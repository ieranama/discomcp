use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tracing::{debug, info, warn};

use crate::artifacts::write_profile_artifacts;
use crate::catalogue::{build_catalogue, fingerprint, retrieve_tool_cards};
use crate::config::{DiscoMcpConfig, ReasoningConfig, ResolvedTargetConfig, TransportKind};
use crate::envelope::unwrap_mcp_envelope;
use crate::error::{DiscoMcpError, Result};
use crate::inference::{infer_capability_profile, infer_workspace_model, operational_model};
use crate::mcp::http::HttpMcpClient;
use crate::mcp::stdio::StdioMcpClient;
use crate::mcp::{McpClient, McpError, MockMcpClient};
use crate::model::{
    ArgumentSource, DocumentationIndex, DocumentationSource, EvidenceClaim, EvidenceRef,
    EvidenceStatus, ExplorationBudgets, NormalizedObservation, ProbeDecision, ProbeRecord,
    ProfileMetadata, ProfileOptions, ProfileResult, QualityDimension, QualityReport, RawDiscovery,
    RiskClass, RuntimeDecision, RuntimeOutcome, TargetProfile, ToolCard, ToolCatalogue,
    Uncertainty,
};
use crate::normalization::normalize_observation;
use crate::policy::{
    backstop_veto, execute_safe_probe, RuntimeBudget, SafeProbeRequest, SafetyPolicy,
};
use crate::reasoning::{
    CommandReasoningBackend, ReasoningBackend, ReasoningError, ReasoningRequest, ReasoningRole,
    ReasoningTask, ScriptedMockReasoningBackend,
};
use crate::redaction::Redactor;

#[async_trait]
pub trait McpClientFactory: Send + Sync {
    async fn connect(&self, target: &ResolvedTargetConfig) -> Result<Box<dyn McpClient>>;
}

/// Everything one probe needs from its caller. The single probe engine shared by
/// the embedded reasoning loop ([`DiscoMcp::profile`]) and the agent-driven
/// session ([`ProfilingSession::execute_probe`]) — they differ only in who picks
/// the decision and what they do with the result.
struct ProbeContext<'a> {
    target_id: &'a str,
    probe_id: String,
    client: &'a dyn McpClient,
    catalogue: &'a ToolCatalogue,
    candidate_tools: Vec<String>,
    observations: &'a [NormalizedObservation],
    budgets: &'a ExplorationBudgets,
    budget: &'a mut RuntimeBudget,
    policy: &'a SafetyPolicy,
    redactor: &'a Redactor,
    dry_run: bool,
}

/// Validates a probe against the full safety runtime, executes it when allowed,
/// and turns any response into a redacted, normalized observation.
async fn run_probe(
    context: ProbeContext<'_>,
    decision: &ProbeDecision,
) -> (ProbeRecord, Option<NormalizedObservation>) {
    let ProbeContext {
        target_id,
        probe_id,
        client,
        catalogue,
        candidate_tools,
        observations,
        budgets,
        budget,
        policy,
        redactor,
        dry_run,
    } = context;
    let execution = execute_safe_probe(SafeProbeRequest {
        client,
        catalogue,
        decision,
        candidate_tools: &candidate_tools,
        observations,
        budgets,
        budget,
        policy,
        dry_run,
    })
    .await;
    let mut record = ProbeRecord {
        id: probe_id.clone(),
        decision: decision.clone(),
        candidate_tools,
        risk: execution.risk,
        runtime_decision: execution.runtime_decision.clone(),
        result_fingerprint: None,
        error: None,
        interpretation: None,
        declared_classification: decision.declared_risk.as_ref().map(|risk| {
            EvidenceClaim::declared(
                format!(
                    "agent classified `{tool}` as {risk:?}",
                    tool = decision.selected_tool.as_deref().unwrap_or_default()
                ),
                "agent:execute_probe",
            )
        }),
    };
    let Some(response) = execution.response else {
        if record.runtime_decision.outcome != RuntimeOutcome::Skipped {
            record.error = Some(record.runtime_decision.reason.clone());
        }
        return (record, None);
    };
    // Unwrap before redacting: inside the envelope the payload is one opaque
    // string, so the redactor would never see its keys or values.
    let payload = unwrap_mcp_envelope(&response);
    let (redacted, report) = redactor.redact(&payload);
    debug!(
        target = target_id,
        probe = probe_id,
        secrets_redacted = report.secrets_redacted,
        pii_redacted = report.pii_redacted,
        "normalizing safe target observation"
    );
    let observation = normalize_observation(
        probe_id,
        decision.selected_tool.clone().unwrap_or_default(),
        decision.arguments.clone(),
        &redacted,
        budgets,
    );
    record.result_fingerprint = Some(observation.fingerprint.clone());
    (record, Some(observation))
}

pub trait ReasoningBackendFactory: Send + Sync {
    fn create(&self, target: &ResolvedTargetConfig) -> Result<Arc<dyn ReasoningBackend>>;
}

#[derive(Default)]
struct DefaultMcpClientFactory;

#[async_trait]
impl McpClientFactory for DefaultMcpClientFactory {
    async fn connect(&self, target: &ResolvedTargetConfig) -> Result<Box<dyn McpClient>> {
        match (&target.transport, target.fixture.as_deref()) {
            (TransportKind::Mock, Some("collection")) => {
                Ok(Box::new(MockMcpClient::collection_fixture()))
            }
            (TransportKind::Mock, Some(fixture)) => Err(DiscoMcpError::Config(format!(
                "target `{}` requests unknown mock fixture `{fixture}`",
                target.id
            ))),
            (TransportKind::Mock, None) => Err(DiscoMcpError::Config(format!(
                "target `{}` uses mock transport without a fixture",
                target.id
            ))),
            (TransportKind::Stdio, _) => {
                let command = target.command.as_deref().ok_or_else(|| {
                    DiscoMcpError::Config(format!(
                        "target `{}` uses stdio transport but does not define `command`",
                        target.id
                    ))
                })?;
                Ok(Box::new(
                    StdioMcpClient::spawn(command, &target.args, &target.env).await?,
                ))
            }
            (TransportKind::StreamableHttp, _) => {
                let url = target.url.as_deref().ok_or_else(|| {
                    DiscoMcpError::Config(format!(
                        "target `{}` uses http transport but does not define `url`",
                        target.id
                    ))
                })?;
                Ok(Box::new(HttpMcpClient::new(url, target.oauth.clone())?))
            }
            (transport, _) => Err(DiscoMcpError::UnsupportedTransport {
                target: target.id.clone(),
                transport: format!("{transport:?}").to_ascii_lowercase(),
            }),
        }
    }
}

#[derive(Clone)]
struct DefaultReasoningBackendFactory {
    config: ReasoningConfig,
}

impl ReasoningBackendFactory for DefaultReasoningBackendFactory {
    fn create(&self, target: &ResolvedTargetConfig) -> Result<Arc<dyn ReasoningBackend>> {
        if target.transport == TransportKind::Mock
            && target.fixture.as_deref() == Some("collection")
        {
            return Ok(Arc::new(ScriptedMockReasoningBackend::collection_fixture()));
        }
        let backend_name = self
            .config
            .everyday_backend
            .as_deref()
            .or(self.config.deep_backend.as_deref())
            .ok_or_else(|| {
                DiscoMcpError::Reasoning(
                    "configure reasoning.everyday_backend for a non-mock target".to_string(),
                )
            })?;
        let backend = self.config.backends.get(backend_name).ok_or_else(|| {
            DiscoMcpError::Reasoning(format!(
                "reasoning backend `{backend_name}` is not defined in configuration"
            ))
        })?;
        if backend.backend_type != "command" {
            return Err(DiscoMcpError::Reasoning(format!(
                "reasoning backend `{backend_name}` uses unsupported type `{}`",
                backend.backend_type
            )));
        }
        if backend.input != "stdin_json" || backend.output != "stdout_json" {
            return Err(DiscoMcpError::Reasoning(format!(
                "reasoning backend `{backend_name}` must use input = \"stdin_json\" and output = \"stdout_json\""
            )));
        }
        let command = backend.command.clone().ok_or_else(|| {
            DiscoMcpError::Reasoning(format!(
                "command reasoning backend `{backend_name}` does not define `command`"
            ))
        })?;
        Ok(Arc::new(CommandReasoningBackend::new(
            command,
            backend.args.clone(),
            backend
                .model
                .clone()
                .unwrap_or_else(|| "default".to_string()),
        )))
    }
}

pub struct DiscoMcp {
    config: DiscoMcpConfig,
    client_factory: Arc<dyn McpClientFactory>,
    reasoning_factory: Arc<dyn ReasoningBackendFactory>,
}

impl DiscoMcp {
    #[must_use]
    pub fn new(config: DiscoMcpConfig) -> Self {
        let reasoning_config = config.reasoning.clone();
        Self {
            config,
            client_factory: Arc::new(DefaultMcpClientFactory),
            reasoning_factory: Arc::new(DefaultReasoningBackendFactory {
                config: reasoning_config,
            }),
        }
    }

    #[must_use]
    pub fn with_dependencies(
        config: DiscoMcpConfig,
        client_factory: Arc<dyn McpClientFactory>,
        reasoning_factory: Arc<dyn ReasoningBackendFactory>,
    ) -> Self {
        Self {
            config,
            client_factory,
            reasoning_factory,
        }
    }

    #[must_use]
    pub fn config(&self) -> &DiscoMcpConfig {
        &self.config
    }

    #[must_use]
    pub fn list_targets(&self) -> Vec<String> {
        self.config.targets.keys().cloned().collect()
    }

    pub async fn inspect(&self, target_id: &str) -> Result<Inspection> {
        let target = self.config.resolve_target(target_id)?;
        let mut client = self.client_factory.connect(&target).await?;
        let discovery = static_discovery(client.as_mut()).await?;
        let catalogue = build_catalogue(
            discovery.tools.clone(),
            discovery.resources.clone(),
            discovery.prompts.clone(),
        );
        info!(
            target = target_id,
            tools = catalogue.tools.len(),
            "static target inspection complete"
        );
        Ok(Inspection {
            target_id: target_id.to_string(),
            server_name: discovery.handshake.server_name,
            tools: catalogue.tools.len(),
            resources: catalogue.resources.len(),
            prompts: catalogue.prompts.len(),
            catalogue_fingerprint: catalogue.fingerprint,
            tool_cards: catalogue.tools.into_iter().map(|tool| tool.card).collect(),
        })
    }

    pub async fn plan(&self, target_id: &str, options: ProfileOptions) -> Result<ProfilePlan> {
        let target = self.config.resolve_target(target_id)?;
        let mut client = self.client_factory.connect(&target).await?;
        let discovery = static_discovery(client.as_mut()).await?;
        let catalogue = build_catalogue(
            discovery.tools.clone(),
            discovery.resources.clone(),
            discovery.prompts.clone(),
        );
        let reasoning = self.reasoning_factory.create(&target)?;
        let _ = analyze_capabilities(&*reasoning, &discovery, &catalogue, &options).await?;
        let candidates = retrieve_cards_for_gap(
            &catalogue,
            "Discover accessible structures, stable identifiers, and safe read paths.",
            &[],
        );
        let budgets = options.effective_budgets();
        let decision = request_probe_decision(
            &*reasoning,
            ProbePlanningContext {
                target_id,
                options: &options,
                cycle: 0,
                open_question:
                    "Discover accessible structures, stable identifiers, and safe read paths.",
                candidates: &candidates,
                observations: &[],
                budgets: &budgets,
            },
        )
        .await?;
        let risk = decision
            .selected_tool
            .as_deref()
            .and_then(|name| catalogue.tools.iter().find(|tool| tool.raw.name == name))
            .map_or(crate::model::RiskClass::Unknown, |tool| {
                tool.card.risk.clone()
            });
        let runtime_decision = if risk.is_allowed_during_onboarding() {
            RuntimeDecision {
                outcome: RuntimeOutcome::Accepted,
                reason: "candidate is an allowed onboarding risk class; schema and provenance are validated at execution time"
                    .to_string(),
            }
        } else {
            RuntimeDecision {
                outcome: RuntimeOutcome::Rejected,
                reason: "candidate risk class is not allowed during onboarding".to_string(),
            }
        };
        Ok(ProfilePlan {
            target_id: target_id.to_string(),
            candidate_tools: candidates,
            decision,
            risk,
            runtime_decision,
            budgets: options.effective_budgets(),
        })
    }

    pub async fn profile(&self, target_id: &str, options: ProfileOptions) -> Result<ProfileResult> {
        let target = self.config.resolve_target(target_id)?;
        let output_dir = options
            .output_dir
            .clone()
            .unwrap_or_else(|| self.config.profile_dir.join(target_id));
        let mut client = self.client_factory.connect(&target).await?;
        let discovery = static_discovery(client.as_mut()).await?;
        let catalogue = build_catalogue(
            discovery.tools.clone(),
            discovery.resources.clone(),
            discovery.prompts.clone(),
        );
        let documentation = collect_documentation(&target, &discovery, &options);
        let reasoning = self.reasoning_factory.create(&target)?;
        let _model_capabilities =
            analyze_capabilities(&*reasoning, &discovery, &catalogue, &options).await?;
        let budgets = options.effective_budgets();
        let redactor = Redactor::new(options.privacy_mode.clone());
        let policy = SafetyPolicy::default();
        let mut runtime_budget = RuntimeBudget::default();
        let mut observations = Vec::new();
        let mut probe_log = Vec::new();
        let mut dynamic_uncertainties = Vec::new();
        let mut open_question = options.goal.clone().unwrap_or_else(|| {
            "Discover accessible workspace structures, stable identifiers, and safe workflows."
                .to_string()
        });

        for cycle in 0..budgets.max_reasoning_cycles {
            let candidates = retrieve_cards_for_gap(&catalogue, &open_question, &observations);
            if candidates.is_empty() {
                dynamic_uncertainties.push(Uncertainty {
                    question: open_question,
                    reason: "No relevant cached tool cards could be retrieved without expanding context."
                        .to_string(),
                    importance: "high".to_string(),
                    evidence: Vec::new(),
                });
                break;
            }
            let decision = match request_probe_decision(
                &*reasoning,
                ProbePlanningContext {
                    target_id,
                    options: &options,
                    cycle,
                    open_question: &open_question,
                    candidates: &candidates,
                    observations: &observations,
                    budgets: &budgets,
                },
            )
            .await
            {
                Ok(decision) => decision,
                Err(error) => {
                    dynamic_uncertainties.push(Uncertainty {
                        question: open_question,
                        reason: format!(
                            "Reasoning output could not produce a valid probe: {error}"
                        ),
                        importance: "high".to_string(),
                        evidence: Vec::new(),
                    });
                    break;
                }
            };
            let probe_id = format!("probe-{:03}", probe_log.len() + 1);
            let candidate_names = candidates
                .iter()
                .map(|candidate| candidate.name.clone())
                .collect::<Vec<_>>();
            if decision.stop {
                probe_log.push(ProbeRecord {
                    id: probe_id,
                    decision: decision.clone(),
                    candidate_tools: candidate_names,
                    risk: crate::model::RiskClass::Unknown,
                    runtime_decision: RuntimeDecision {
                        outcome: RuntimeOutcome::Skipped,
                        reason: decision
                            .stop_reason
                            .clone()
                            .unwrap_or_else(|| "reasoning backend stopped exploration".to_string()),
                    },
                    result_fingerprint: None,
                    error: None,
                    interpretation: None,
                    declared_classification: None,
                });
                break;
            }
            let (mut record, observation) = run_probe(
                ProbeContext {
                    target_id,
                    probe_id: probe_id.clone(),
                    client: client.as_ref(),
                    catalogue: &catalogue,
                    candidate_tools: candidate_names,
                    observations: &observations,
                    budgets: &budgets,
                    budget: &mut runtime_budget,
                    policy: &policy,
                    redactor: &redactor,
                    dry_run: options.dry_run,
                },
                &decision,
            )
            .await;
            if let Some(observation) = observation {
                record.interpretation = Some(interpret_observation(
                    &*reasoning,
                    target_id,
                    &options,
                    &observation,
                    &candidates,
                )
                .await
                .unwrap_or_else(|error| {
                    warn!(target = target_id, probe = probe_id, error = %error, "reasoning interpretation failed");
                    EvidenceClaim::observed(
                        "A safe target response was accepted but model interpretation was unavailable.",
                        format!("observation:{}", observation.id),
                        0.65,
                    )
                }));
                open_question = next_information_gap(&observation, &decision);
                observations.push(observation);
            } else if record.error.is_some() {
                dynamic_uncertainties.push(Uncertainty {
                    question: decision.unresolved_question.clone(),
                    reason: record.runtime_decision.reason.clone(),
                    importance: "medium".to_string(),
                    evidence: vec![EvidenceRef {
                        status: EvidenceStatus::Unknown,
                        source: format!("probe:{probe_id}"),
                        detail: None,
                    }],
                });
                open_question = format!(
                    "Find another safe way to resolve: {}",
                    decision.unresolved_question
                );
            }
            probe_log.push(record);
            if runtime_budget.probes_executed >= budgets.max_mcp_probes {
                break;
            }
        }

        let profile = assemble_profile(
            target_id,
            discovery,
            documentation,
            catalogue,
            observations,
            probe_log,
            dynamic_uncertainties,
            &options,
        );
        write_profile_artifacts(&profile, &output_dir)?;
        info!(
            target = target_id,
            output = %output_dir.display(),
            structures = profile.workspace_model.structures.len(),
            probes = profile.probe_log.len(),
            "target MCP profile generated"
        );
        Ok(ProfileResult {
            profile,
            output_dir,
        })
    }

    pub async fn refresh(&self, target_id: &str, options: ProfileOptions) -> Result<RefreshResult> {
        let output_dir = options
            .output_dir
            .clone()
            .unwrap_or_else(|| self.config.profile_dir.join(target_id));
        let metadata_path = output_dir.join("profile-metadata.json");
        let prior = fs::read(&metadata_path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<ProfileMetadata>(&bytes).ok());
        let inspection = self.inspect(target_id).await?;
        if prior
            .as_ref()
            .is_some_and(|metadata| metadata.target_fingerprint == inspection.catalogue_fingerprint)
        {
            return Ok(RefreshResult {
                changed: false,
                output_dir,
                message: "No declaration change detected; safe probes were not repeated."
                    .to_string(),
            });
        }
        let result = self.profile(target_id, options).await?;
        fs::write(
            result.output_dir.join("profile-diff.md"),
            "# Profile Diff\n\nStatic target declarations changed or no prior profile was available; affected artifacts were regenerated.\n",
        )?;
        Ok(RefreshResult {
            changed: true,
            output_dir: result.output_dir,
            message: "Target declarations changed; the profile was regenerated.".to_string(),
        })
    }

    /// Cheaply checks whether a skill already covers this target's current
    /// declared catalogue, without running any exploration or reasoning.
    pub async fn lookup(&self, target_id: &str) -> Result<LookupResult> {
        let inspection = self.inspect(target_id).await?;
        let existing_skill_dir =
            find_skill_by_fingerprint(&self.config.profile_dir, &inspection.catalogue_fingerprint);
        Ok(LookupResult {
            target_id: target_id.to_string(),
            catalogue_fingerprint: inspection.catalogue_fingerprint,
            existing_skill_dir,
        })
    }

    /// Connects to a target, performs static discovery, and builds the catalogue
    /// and documentation index for an interactive profiling session.
    ///
    /// This path deliberately never constructs a reasoning backend: an external
    /// agent brain drives probe selection through [`ProfilingSession::execute_probe`].
    pub async fn start_session(
        &self,
        target_id: &str,
        options: ProfileOptions,
    ) -> Result<ProfilingSession> {
        let target = self.config.resolve_target(target_id)?;
        let output_dir = options
            .output_dir
            .clone()
            .unwrap_or_else(|| self.config.profile_dir.join(target_id));
        let mut client = self.client_factory.connect(&target).await?;
        let discovery = static_discovery(client.as_mut()).await?;
        let catalogue = build_catalogue(
            discovery.tools.clone(),
            discovery.resources.clone(),
            discovery.prompts.clone(),
        );
        let documentation = collect_documentation(&target, &discovery, &options);
        let budgets = options.effective_budgets();
        let redactor = Redactor::new(options.privacy_mode.clone());
        let open_question = options.goal.clone().unwrap_or_else(|| {
            "Discover accessible workspace structures, stable identifiers, and safe workflows."
                .to_string()
        });
        info!(
            target = target_id,
            tools = catalogue.tools.len(),
            "profiling session started"
        );
        Ok(ProfilingSession {
            target_id: target_id.to_string(),
            output_dir,
            client,
            discovery,
            catalogue,
            documentation,
            options,
            budgets,
            policy: SafetyPolicy::default(),
            redactor,
            runtime_budget: RuntimeBudget::default(),
            observations: Vec::new(),
            probe_log: Vec::new(),
            open_question,
        })
    }
}

/// An in-memory, single-target profiling session driven by an external agent.
///
/// The session owns the connected client and all accumulated safe observations
/// for the life of a served client connection. It applies the identical safety
/// runtime as [`DiscoMcp::profile`] but takes each probe decision from an agent
/// rather than an embedded reasoning backend.
pub struct ProfilingSession {
    target_id: String,
    output_dir: PathBuf,
    client: Box<dyn McpClient>,
    discovery: RawDiscovery,
    catalogue: ToolCatalogue,
    documentation: DocumentationIndex,
    options: ProfileOptions,
    budgets: ExplorationBudgets,
    policy: SafetyPolicy,
    redactor: Redactor,
    runtime_budget: RuntimeBudget,
    observations: Vec<NormalizedObservation>,
    probe_log: Vec<ProbeRecord>,
    open_question: String,
}

/// The result of validating and, when safe, executing one agent-selected probe.
#[derive(Clone, Debug, Serialize)]
pub struct ProbeOutcome {
    pub outcome: RuntimeOutcome,
    pub reason: String,
    pub risk: RiskClass,
    /// The redacted, normalized observation. `Some` only when `outcome` is
    /// [`RuntimeOutcome::Accepted`].
    pub observation: Option<NormalizedObservation>,
    /// A read-only gap report over the whole session, reflecting this probe.
    pub gaps: GapReport,
}

/// A read-only exploration gap report computed purely from accumulated session
/// state. It REPORTS numbers and lists; it never thresholds, gates, or decides.
///
/// `Serialize`-only (backward-safe on the wire, same rationale as
/// [`ProbeOutcome`]) and `Default` so it composes into `ProbeOutcome`.
#[derive(Clone, Debug, Default, Serialize)]
pub struct GapReport {
    pub unsampled_structures: Vec<UnsampledStructure>,
    pub unexecuted_tools: Vec<UnexecutedTool>,
    pub untraversed_identifiers: Vec<UntraversedIdentifier>,
    pub sampling_hints: Vec<SamplingHint>,
    pub depth_signal: DepthSignal,
}

/// A collection an observation listed but no later probe drilled into.
#[derive(Clone, Debug, Default, Serialize)]
pub struct UnsampledStructure {
    /// Observation that listed the collection.
    pub observation_id: String,
    /// Tool that produced it.
    pub tool: String,
    /// Pointer to the array node inside the shape.
    pub json_pointer: String,
    /// Identifiers collected within this observation.
    pub identifiers_inside: usize,
    /// Later accepted probes citing an id from this observation.
    pub downstream_samples: usize,
}

/// An unprobed tool the backstop does not block. The agent judges which of
/// these are read-safe to declare and probe.
#[derive(Clone, Debug, Default, Serialize)]
pub struct UnexecutedTool {
    pub tool: String,
    /// First sentence of the tool's declared description, trimmed to ~140 chars.
    pub why_useful: String,
}

/// An identifier seen in output but never used as a get-by-id argument.
#[derive(Clone, Debug, Default, Serialize)]
pub struct UntraversedIdentifier {
    pub name: String,
    /// Redaction survivor only (never a `[REDACTED…]` value).
    pub value: String,
    /// Cite this as `provenance.observation_id`.
    pub observation_id: String,
    /// Cite this as `provenance.json_pointer`.
    pub json_pointer: String,
    /// Tools whose schema has a matching param (heuristic).
    pub likely_consumer_tools: Vec<String>,
}

/// An unused tool whose schema exposes sampling/ordering params.
#[derive(Clone, Debug, Default, Serialize)]
pub struct SamplingHint {
    pub tool: String,
    /// Matched schema param names, e.g. `["orderBy","pageSize"]`.
    pub params: Vec<String>,
}

/// Pure coverage counts. Never a verdict.
#[derive(Clone, Debug, Default, Serialize)]
pub struct DepthSignal {
    pub structures_observed: usize,
    pub probeable_tools_covered: usize,
    pub probeable_tools_total: usize,
    pub identifiers_traversed: usize,
    pub identifiers_observed: usize,
    /// `runtime_budget.probes_executed`.
    pub probes_executed: u32,
    /// `budgets.max_mcp_probes` (remaining = budget - executed).
    pub probe_budget: u32,
}

impl ProfilingSession {
    /// The declared catalogue the agent reasons over when planning probes.
    #[must_use]
    pub fn catalogue(&self) -> &ToolCatalogue {
        &self.catalogue
    }

    /// The declared server name from the static handshake.
    #[must_use]
    pub fn server_name(&self) -> &str {
        &self.discovery.handshake.server_name
    }

    /// The current open question the session is trying to resolve.
    #[must_use]
    pub fn open_question(&self) -> &str {
        &self.open_question
    }

    /// Validates and, if the full safety runtime permits, executes one probe.
    ///
    /// The agent already saw the entire catalogue via [`Self::catalogue`], so the
    /// candidate subset is the whole catalogue: gating is left to the safety
    /// checks (risk, schema, provenance, sampling, budget, timeout, size).
    pub async fn execute_probe(&mut self, decision: ProbeDecision) -> ProbeOutcome {
        let candidate_names = self
            .catalogue
            .tools
            .iter()
            .map(|tool| tool.raw.name.clone())
            .collect::<Vec<_>>();
        let probe_id = format!("probe-{:03}", self.probe_log.len() + 1);
        let (record, observation) = run_probe(
            ProbeContext {
                target_id: &self.target_id,
                probe_id,
                client: self.client.as_ref(),
                catalogue: &self.catalogue,
                candidate_tools: candidate_names,
                observations: &self.observations,
                budgets: &self.budgets,
                budget: &mut self.runtime_budget,
                policy: &self.policy,
                redactor: &self.redactor,
                dry_run: self.options.dry_run,
            },
            &decision,
        )
        .await;
        let mut outcome = ProbeOutcome {
            outcome: record.runtime_decision.outcome.clone(),
            reason: record.runtime_decision.reason.clone(),
            risk: record.risk.clone(),
            observation: None,
            gaps: GapReport::default(),
        };
        if let Some(observation) = observation {
            self.open_question = next_information_gap(&observation, &decision);
            outcome.observation = Some(observation.clone());
            self.observations.push(observation);
        }
        self.probe_log.push(record);
        outcome.gaps = self.gaps(); // reflects this probe
        outcome
    }

    /// Read-only gap report from current session state. No target calls.
    #[must_use]
    pub fn gaps(&self) -> GapReport {
        compute_gaps(
            &self.catalogue,
            &self.observations,
            &self.probe_log,
            self.budgets.max_mcp_probes,
            self.runtime_budget.probes_executed,
        )
    }

    /// Deterministically assembles and writes the full artifact set from the
    /// session's accumulated safe observations. No reasoning backend is used.
    pub fn finalize(mut self, usage_summary: Option<String>) -> Result<ProfileResult> {
        // Fold the agent's per-probe risk declarations into the catalogue so
        // every downstream consumer of `card.risk` sees annotation-or-agent
        // sourced classes. Last declaration wins; a destructive server
        // annotation outranks any declaration.
        for record in &self.probe_log {
            if record.declared_classification.is_none() {
                continue;
            }
            let Some(tool_name) = record.decision.selected_tool.as_deref() else {
                continue;
            };
            if let Some(tool) = self
                .catalogue
                .tools
                .iter_mut()
                .find(|tool| tool.raw.name == tool_name)
            {
                if tool.card.risk == RiskClass::Destructive
                    && tool.card.risk_evidence == "server_annotation"
                {
                    continue;
                }
                tool.card.risk = record.risk.clone();
                tool.card.risk_evidence = "agent_declared".to_string();
            }
        }
        let mut profile = assemble_profile(
            &self.target_id,
            self.discovery,
            self.documentation,
            self.catalogue,
            self.observations,
            self.probe_log,
            Vec::new(),
            &self.options,
        );
        profile.metadata.usage_summary = usage_summary;
        write_profile_artifacts(&profile, &self.output_dir)?;
        info!(
            target = self.target_id,
            output = %self.output_dir.display(),
            structures = profile.workspace_model.structures.len(),
            probes = profile.probe_log.len(),
            "profiling session finalized"
        );
        Ok(ProfileResult {
            profile,
            output_dir: self.output_dir,
        })
    }
}

/// Schema param names that signal an unused tool can sample smarter (order by
/// recency, page, filter/query) instead of blind first-N. Normalized form.
const SAMPLING_PARAM_HINTS: &[&str] = &[
    "orderby",
    "sort",
    "modifiedtime",
    "updated",
    "pagesize",
    "pagetoken",
    "limit",
    "count",
    "q",
    "query",
    "filter",
];

/// Computes a read-only [`GapReport`] from resident session state. No target
/// calls, no expensive recompute — this only reads what was already gathered.
fn compute_gaps(
    catalogue: &ToolCatalogue,
    observations: &[NormalizedObservation],
    probe_log: &[ProbeRecord],
    probe_budget: u32,
    probes_executed: u32,
) -> GapReport {
    // Tools whose probe was accepted (stop-probes carry `None` — guarded).
    let executed: std::collections::BTreeSet<String> = probe_log
        .iter()
        .filter(|record| record.runtime_decision.outcome == RuntimeOutcome::Accepted)
        .filter_map(|record| record.decision.selected_tool.clone())
        .collect();

    // (observation_id, json_pointer) pairs an accepted probe traversed via
    // `Observed` provenance — the reliable identifier-traversal signal.
    let traversed: std::collections::BTreeSet<(String, String)> = probe_log
        .iter()
        .filter(|record| record.runtime_decision.outcome == RuntimeOutcome::Accepted)
        .flat_map(|record| record.decision.argument_provenance.iter())
        .filter_map(|provenance| match &provenance.source {
            ArgumentSource::Observed {
                observation_id,
                json_pointer,
            } => Some((observation_id.clone(), json_pointer.clone())),
            _ => None,
        })
        .collect();

    // Unprobed tools minus backstop-blocked: everything the agent could still
    // judge read-safe and probe. The backstop is the only hard rejection left,
    // so the report never steers into one.
    let unexecuted_tools: Vec<UnexecutedTool> = catalogue
        .tools
        .iter()
        .filter(|tool| backstop_veto(&tool.raw).is_none())
        .filter(|tool| !executed.contains(&tool.raw.name))
        .map(|tool| UnexecutedTool {
            tool: tool.raw.name.clone(),
            why_useful: first_sentence(&tool.raw.description),
        })
        .collect();
    let probeable_tools_total = catalogue
        .tools
        .iter()
        .filter(|tool| backstop_veto(&tool.raw).is_none())
        .count();

    // Identifiers observed but never used as a get-by-id argument.
    let mut untraversed_identifiers = Vec::new();
    let mut identifiers_observed = 0usize;
    let mut identifiers_traversed = 0usize;
    for observation in observations {
        for identifier in &observation.identifiers {
            identifiers_observed += 1;
            let key = (
                identifier.observation_id.clone(),
                identifier.json_pointer.clone(),
            );
            if traversed.contains(&key) {
                identifiers_traversed += 1;
            } else {
                untraversed_identifiers.push(UntraversedIdentifier {
                    name: identifier.name.clone(),
                    value: identifier.value.clone(),
                    observation_id: identifier.observation_id.clone(),
                    json_pointer: identifier.json_pointer.clone(),
                    likely_consumer_tools: tools_matching_param(catalogue, &identifier.name),
                });
            }
        }
    }

    // Listed collections nobody drilled into.
    let mut unsampled_structures = Vec::new();
    let mut structures_observed = 0usize;
    for observation in observations {
        let mut pointers = Vec::new();
        collect_array_pointers(&observation.shape, "", &mut pointers);
        structures_observed += pointers.len();
        let downstream_samples = probe_log
            .iter()
            .filter(|record| record.runtime_decision.outcome == RuntimeOutcome::Accepted)
            .filter(|record| {
                record
                    .decision
                    .argument_provenance
                    .iter()
                    .any(|provenance| {
                        matches!(
                            &provenance.source,
                            ArgumentSource::Observed { observation_id, .. }
                                if *observation_id == observation.id
                        )
                    })
            })
            .count();
        if downstream_samples == 0 {
            for pointer in pointers {
                unsampled_structures.push(UnsampledStructure {
                    observation_id: observation.id.clone(),
                    tool: observation.tool.clone(),
                    json_pointer: pointer,
                    identifiers_inside: observation.identifiers.len(),
                    downstream_samples,
                });
            }
        }
    }

    // Sampling/ordering params on unused tools.
    let sampling_hints: Vec<SamplingHint> = catalogue
        .tools
        .iter()
        .filter(|tool| backstop_veto(&tool.raw).is_none())
        .filter(|tool| !executed.contains(&tool.raw.name))
        .filter_map(|tool| {
            let params: Vec<String> = schema_property_keys(&tool.raw.input_schema)
                .into_iter()
                .filter(|key| SAMPLING_PARAM_HINTS.contains(&normalize_param(key).as_str()))
                .collect();
            if params.is_empty() {
                None
            } else {
                Some(SamplingHint {
                    tool: tool.raw.name.clone(),
                    params,
                })
            }
        })
        .collect();

    let probeable_tools_covered = probeable_tools_total - unexecuted_tools.len();
    GapReport {
        unsampled_structures,
        unexecuted_tools,
        untraversed_identifiers,
        sampling_hints,
        depth_signal: DepthSignal {
            structures_observed,
            probeable_tools_covered,
            probeable_tools_total,
            identifiers_traversed,
            identifiers_observed,
            probes_executed,
            probe_budget,
        },
    }
}

/// First sentence of a tool description (split on `. ` or newline), trimmed to
/// ~140 chars. A tiny presentation helper for `why_useful`.
fn first_sentence(description: &str) -> String {
    let line = description.trim().split('\n').next().unwrap_or("").trim();
    let sentence = match line.find(". ") {
        Some(index) => &line[..=index], // keep the terminating period
        None => line,
    };
    let sentence = sentence.trim();
    if sentence.chars().count() > 140 {
        sentence
            .chars()
            .take(140)
            .collect::<String>()
            .trim_end()
            .to_string()
    } else {
        sentence.to_string()
    }
}

/// Every property name declared anywhere in a tool's `input_schema`, at any
/// depth. A JSON Schema is a tree, and MCP servers nest real parameters to any
/// depth — some wrap the whole API surface in a generic `params` object, others
/// keep it flat. Walking the tree keeps the hint heuristics working regardless
/// of a server's schema shape instead of assuming a flat top level.
fn schema_property_keys(input_schema: &Value) -> Vec<String> {
    let mut keys = Vec::new();
    collect_schema_property_keys(input_schema, &mut keys);
    keys
}

fn collect_schema_property_keys(schema: &Value, out: &mut Vec<String>) {
    let Value::Object(map) = schema else { return };
    if let Some(properties) = map.get("properties").and_then(Value::as_object) {
        for (name, subschema) in properties {
            out.push(name.clone());
            collect_schema_property_keys(subschema, out);
        }
    }
    // Descend through the structural keywords that carry nested subschemas.
    for keyword in ["items", "additionalProperties"] {
        if let Some(subschema) = map.get(keyword) {
            collect_schema_property_keys(subschema, out);
        }
    }
    for keyword in ["allOf", "anyOf", "oneOf"] {
        if let Some(branches) = map.get(keyword).and_then(Value::as_array) {
            for branch in branches {
                collect_schema_property_keys(branch, out);
            }
        }
    }
}

/// Case- and separator-insensitive normalization: lowercase, drop `_`/`-`.
fn normalize_param(name: &str) -> String {
    name.chars()
        .filter(|character| *character != '_' && *character != '-')
        .flat_map(char::to_lowercase)
        .collect()
}

/// Heuristic: backstop-clear tools whose schema (or, as a fallback, declared
/// arguments) expose a param matching an observed identifier name — a normalized
/// exact match, or a shared non-empty `*id` stem. Restricted to tools the
/// backstop does not block so the hint never steers a probe into the one hard
/// rejection left. Reported as a hint, never a guarantee.
fn tools_matching_param(catalogue: &ToolCatalogue, identifier_name: &str) -> Vec<String> {
    let target = normalize_param(identifier_name);
    let target_stem = target.strip_suffix("id").filter(|stem| !stem.is_empty());
    catalogue
        .tools
        .iter()
        .filter(|tool| backstop_veto(&tool.raw).is_none())
        .filter(|tool| {
            let mut params = schema_property_keys(&tool.raw.input_schema);
            if params.is_empty() {
                params = tool
                    .card
                    .required_arguments
                    .iter()
                    .chain(tool.card.optional_arguments.iter())
                    .cloned()
                    .collect();
            }
            params.iter().any(|param| {
                let normalized = normalize_param(param);
                normalized == target
                    || matches!(
                        (target_stem, normalized.strip_suffix("id")),
                        (Some(a), Some(b)) if !b.is_empty() && a == b
                    )
            })
        })
        .map(|tool| tool.raw.name.clone())
        .collect()
}

/// Walks a normalized `shape` value collecting JSON pointers to every
/// `{"type":"array"}` node.
fn collect_array_pointers(shape: &Value, pointer: &str, out: &mut Vec<String>) {
    if let Value::Object(map) = shape {
        if map.get("type").and_then(Value::as_str) == Some("array") {
            out.push(pointer.to_string());
            if let Some(items) = map.get("items") {
                collect_array_pointers(items, &format!("{pointer}/items"), out);
            }
            return;
        }
        for (key, child) in map {
            collect_array_pointers(child, &format!("{pointer}/{key}"), out);
        }
    }
}

/// Deterministically assembles a [`TargetProfile`] from discovery, catalogue and
/// accumulated observations. Shared by [`DiscoMcp::profile`] and
/// [`ProfilingSession::finalize`].
#[allow(clippy::too_many_arguments)]
fn assemble_profile(
    target_id: &str,
    discovery: RawDiscovery,
    documentation: DocumentationIndex,
    catalogue: ToolCatalogue,
    observations: Vec<NormalizedObservation>,
    probe_log: Vec<ProbeRecord>,
    extra_uncertainties: Vec<Uncertainty>,
    options: &ProfileOptions,
) -> TargetProfile {
    let capability_profile = infer_capability_profile(&catalogue);
    let mut workspace_model =
        infer_workspace_model(target_id, &catalogue, &observations, &probe_log);
    workspace_model.uncertainties.extend(extra_uncertainties);
    for record in &probe_log {
        if let Some(interpretation) = &record.interpretation {
            workspace_model.hypotheses.push(crate::model::Hypothesis {
                claim: interpretation.clone(),
                unresolved_question: record.decision.unresolved_question.clone(),
            });
        }
    }
    let operational_model =
        operational_model(target_id, capability_profile.clone(), &workspace_model);
    let metadata = ProfileMetadata {
        target_id: target_id.to_string(),
        profile_version: env!("CARGO_PKG_VERSION").to_string(),
        generated_at_unix_seconds: now_unix_seconds(),
        target_fingerprint: catalogue.fingerprint.clone(),
        mode: options.mode.clone(),
        goal: options.goal.clone(),
        usage_summary: None,
        static_discovery_complete: true,
    };
    let quality_report = quality_report(&catalogue, &workspace_model);
    TargetProfile {
        metadata,
        raw_discovery: discovery,
        documentation,
        catalogue,
        capability_profile,
        workspace_model,
        operational_model,
        probe_log,
        observations,
        quality_report,
    }
}

/// Scans every profile directory below `profile_dir` for one whose saved
/// `profile-metadata.json` fingerprint matches. Returns the first match.
fn find_skill_by_fingerprint(profile_dir: &std::path::Path, fingerprint: &str) -> Option<PathBuf> {
    let entries = fs::read_dir(profile_dir).ok()?;
    entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .find(|path| {
            fs::read(path.join("profile-metadata.json"))
                .ok()
                .and_then(|bytes| serde_json::from_slice::<ProfileMetadata>(&bytes).ok())
                .is_some_and(|metadata| metadata.target_fingerprint == fingerprint)
        })
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Inspection {
    pub target_id: String,
    pub server_name: String,
    pub tools: usize,
    pub resources: usize,
    pub prompts: usize,
    pub catalogue_fingerprint: String,
    pub tool_cards: Vec<ToolCard>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProfilePlan {
    pub target_id: String,
    pub candidate_tools: Vec<ToolCard>,
    pub decision: ProbeDecision,
    pub risk: crate::model::RiskClass,
    pub runtime_decision: RuntimeDecision,
    pub budgets: ExplorationBudgets,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RefreshResult {
    pub changed: bool,
    pub output_dir: PathBuf,
    pub message: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LookupResult {
    pub target_id: String,
    pub catalogue_fingerprint: String,
    pub existing_skill_dir: Option<PathBuf>,
}

async fn static_discovery(client: &mut dyn McpClient) -> Result<RawDiscovery> {
    let handshake = client.initialize().await?;
    let tools = client.list_tools().await?;
    // Many real MCP servers only implement tools; a missing resources/prompts
    // method means "none declared", not a discovery failure.
    let resources = match client.list_resources().await {
        Ok(resources) => resources,
        Err(McpError::Unsupported(_)) => Vec::new(),
        Err(error) => return Err(error.into()),
    };
    let prompts = match client.list_prompts().await {
        Ok(prompts) => prompts,
        Err(McpError::Unsupported(_)) => Vec::new(),
        Err(error) => return Err(error.into()),
    };
    Ok(RawDiscovery {
        handshake,
        tools,
        resources,
        prompts,
    })
}

async fn analyze_capabilities(
    reasoning: &dyn ReasoningBackend,
    discovery: &RawDiscovery,
    catalogue: &crate::model::ToolCatalogue,
    options: &ProfileOptions,
) -> Result<Value> {
    let candidates = retrieve_cards_for_gap(
        catalogue,
        "understand declared capabilities, safe discovery, and tool risk",
        &[],
    );
    let response = reasoning
        .reason(ReasoningRequest {
            task: ReasoningTask::AnalyzeCapabilities,
            instructions: "Infer a multidimensional capability profile from the bounded tool-card subset. Do not invent tools or claim observation.".to_string(),
            context: json!({
                "server": {
                    "name": discovery.handshake.server_name,
                    "version": discovery.handshake.server_version,
                    "instructions": discovery.handshake.instructions,
                },
                "tool_counts": {"tools": catalogue.tools.len(), "resources": catalogue.resources.len(), "prompts": catalogue.prompts.len()},
                "candidate_tool_cards": candidates,
                "goal": options.goal,
            }),
            output_schema: None,
            role: ReasoningRole::Everyday,
            max_output_tokens: Some(800),
        })
        .await
        .map_err(reasoning_error)?;
    if !response.output.is_object() {
        return Err(DiscoMcpError::Reasoning(
            "capability analysis was not a JSON object".to_string(),
        ));
    }
    Ok(response.output)
}

struct ProbePlanningContext<'a> {
    target_id: &'a str,
    options: &'a ProfileOptions,
    cycle: u32,
    open_question: &'a str,
    candidates: &'a [ToolCard],
    observations: &'a [NormalizedObservation],
    budgets: &'a ExplorationBudgets,
}

async fn request_probe_decision(
    reasoning: &dyn ReasoningBackend,
    context: ProbePlanningContext<'_>,
) -> Result<ProbeDecision> {
    let ProbePlanningContext {
        target_id,
        options,
        cycle,
        open_question,
        candidates,
        observations,
        budgets,
    } = context;
    let latest_observations = observations
        .iter()
        .rev()
        .take(2)
        .cloned()
        .collect::<Vec<_>>();
    let response = reasoning
        .reason(ReasoningRequest {
            task: ReasoningTask::PlanNextProbe,
            instructions: "Return one ProbeDecision. Select only a supplied candidate tool, use only valid JSON arguments, and include provenance for every identifier-like argument. Stop when safe information gain is low.".to_string(),
            context: json!({
                "target_id": target_id,
                "cycle": cycle,
                "goal": options.goal,
                "open_question": open_question,
                "candidate_tool_cards": candidates,
                "latest_observations": latest_observations,
                "remaining_budgets": budgets,
            }),
            output_schema: None,
            role: ReasoningRole::Everyday,
            max_output_tokens: Some(900),
        })
        .await
        .map_err(reasoning_error)?;
    serde_json::from_value(response.output).map_err(|error| {
        DiscoMcpError::Reasoning(format!(
            "ProbeDecision failed structured validation: {error}"
        ))
    })
}

async fn interpret_observation(
    reasoning: &dyn ReasoningBackend,
    target_id: &str,
    options: &ProfileOptions,
    observation: &NormalizedObservation,
    candidates: &[ToolCard],
) -> Result<EvidenceClaim> {
    let response = reasoning
        .reason(ReasoningRequest {
            task: ReasoningTask::InterpretObservation,
            instructions: "Interpret the redacted structural observation. Return an evidence-aware EvidenceClaim and never call tools directly.".to_string(),
            context: json!({
                "target_id": target_id,
                "goal": options.goal,
                "observation": observation,
                "candidate_tool_cards": candidates,
            }),
            output_schema: None,
            role: ReasoningRole::Everyday,
            max_output_tokens: Some(500),
        })
        .await
        .map_err(reasoning_error)?;
    let claim: EvidenceClaim = serde_json::from_value(response.output).map_err(|error| {
        DiscoMcpError::Reasoning(format!(
            "observation interpretation failed validation: {error}"
        ))
    })?;
    if claim.status == EvidenceStatus::Inferred && claim.evidence.is_empty() {
        return Err(DiscoMcpError::Reasoning(
            "inferred observation claim had no evidence references".to_string(),
        ));
    }
    Ok(claim)
}

fn retrieve_cards_for_gap(
    catalogue: &crate::model::ToolCatalogue,
    gap: &str,
    observations: &[NormalizedObservation],
) -> Vec<ToolCard> {
    let dependencies = observations
        .iter()
        .flat_map(|observation| {
            observation
                .identifiers
                .iter()
                .map(|identifier| identifier.name.clone())
        })
        .collect::<Vec<_>>();
    retrieve_tool_cards(catalogue, gap, &dependencies, 12)
}

fn collect_documentation(
    target: &ResolvedTargetConfig,
    discovery: &RawDiscovery,
    options: &ProfileOptions,
) -> DocumentationIndex {
    let mut sources = vec![DocumentationSource {
        id: "mcp-tool-metadata".to_string(),
        location: "MCP tool and parameter descriptions".to_string(),
        status: EvidenceStatus::Declared,
        summary: format!(
            "{} tool description(s) and schemas were cached as declared semantic evidence.",
            discovery.tools.len()
        ),
        fingerprint: fingerprint(&discovery.tools),
    }];
    let redactor = Redactor::new(options.privacy_mode.clone());
    for (index, location) in target.docs.iter().enumerate() {
        let id = format!("configured-doc-{}", index + 1);
        if location.starts_with("https://") || location.starts_with("http://") {
            sources.push(DocumentationSource {
                id,
                location: location.clone(),
                status: EvidenceStatus::Unknown,
                summary: "Configured URL retained as a source reference; network retrieval is intentionally outside this first vertical slice."
                    .to_string(),
                fingerprint: fingerprint(location),
            });
            continue;
        }
        match fs::read_to_string(location) {
            Ok(contents) => {
                let redacted = redactor.redact_text(&contents);
                sources.push(DocumentationSource {
                    id,
                    location: location.clone(),
                    status: EvidenceStatus::Documented,
                    summary: "Configured local documentation was read and indexed without persisting its body."
                        .to_string(),
                    fingerprint: fingerprint(&redacted),
                });
            }
            Err(_) => sources.push(DocumentationSource {
                id,
                location: location.clone(),
                status: EvidenceStatus::Unknown,
                summary:
                    "Configured local documentation could not be read during this profile run."
                        .to_string(),
                fingerprint: fingerprint(location),
            }),
        }
    }
    DocumentationIndex {
        sources,
        extracted_facts: BTreeMap::from([(
            "tool_descriptions".to_string(),
            discovery
                .tools
                .iter()
                .filter(|tool| !tool.description.is_empty())
                .map(|tool| format!("{}: {}", tool.name, tool.description))
                .collect(),
        )]),
    }
}

fn quality_report(
    catalogue: &crate::model::ToolCatalogue,
    workspace: &crate::model::WorkspaceModel,
) -> QualityReport {
    let read_tools = catalogue
        .tools
        .iter()
        .filter(|tool| tool.card.risk.is_allowed_during_onboarding())
        .count();
    let unsafe_tools = catalogue.tools.len().saturating_sub(read_tools);
    let dimensions = vec![
        quality_dimension(
            "discoverability",
            if catalogue.tools.is_empty() {
                "weak"
            } else {
                "available"
            },
            if catalogue.tools.is_empty() { 0.2 } else { 0.9 },
        ),
        quality_dimension(
            "schema_quality",
            if catalogue
                .tools
                .iter()
                .all(|tool| tool.raw.input_schema.is_object())
            {
                "structured"
            } else {
                "partial"
            },
            0.8,
        ),
        quality_dimension(
            "read_safety",
            if read_tools > 0 {
                "safe paths available"
            } else {
                "no safe path confirmed"
            },
            if read_tools > 0 { 0.85 } else { 0.4 },
        ),
        quality_dimension(
            "structure_clarity",
            if workspace.structures.is_empty() {
                "unknown"
            } else {
                "observed"
            },
            if workspace.structures.is_empty() {
                0.3
            } else {
                0.85
            },
        ),
        quality_dimension(
            "relationship_clarity",
            if workspace.relationships.is_empty() {
                "limited"
            } else {
                "inferred"
            },
            if workspace.relationships.is_empty() {
                0.35
            } else {
                0.7
            },
        ),
    ];
    QualityReport {
        dimensions,
        strengths: vec![format!(
            "{read_tools} safe or bounded onboarding tool(s) are available."
        )],
        weaknesses: if workspace.uncertainties.is_empty() {
            Vec::new()
        } else {
            vec![format!(
                "{} unresolved uncertainty record(s) remain.",
                workspace.uncertainties.len()
            )]
        },
        safety_concerns: if unsafe_tools == 0 {
            Vec::new()
        } else {
            vec![format!(
                "{unsafe_tools} tool(s) are documented but blocked from onboarding execution."
            )]
        },
        blockers: Vec::new(),
    }
}

fn quality_dimension(name: &str, assessment: &str, confidence: f32) -> QualityDimension {
    QualityDimension {
        name: name.to_string(),
        assessment: assessment.to_string(),
        confidence,
        evidence: Vec::new(),
    }
}

fn next_information_gap(observation: &NormalizedObservation, decision: &ProbeDecision) -> String {
    if !observation.identifiers.is_empty() {
        return "Use an observed identifier to validate the next safe structural detail or relationship."
            .to_string();
    }
    format!(
        "Resolve remaining question after `{}`: {}",
        decision.selected_tool.as_deref().unwrap_or("unknown"),
        decision.unresolved_question
    )
}

fn reasoning_error(error: ReasoningError) -> DiscoMcpError {
    DiscoMcpError::Reasoning(error.to_string())
}

fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, VecDeque};
    use std::sync::Arc;

    use async_trait::async_trait;
    use serde_json::json;

    use super::*;
    use crate::config::DiscoMcpConfig;
    use crate::mcp::{McpError, MockMcpClient};
    use crate::reasoning::{ReasoningResponse, ScriptedResponse};

    #[derive(Clone)]
    struct FixtureClientFactory {
        client: MockMcpClient,
    }

    #[async_trait]
    impl McpClientFactory for FixtureClientFactory {
        async fn connect(&self, _target: &ResolvedTargetConfig) -> Result<Box<dyn McpClient>> {
            Ok(Box::new(self.client.clone()))
        }
    }

    struct FixtureReasoningFactory {
        backend: Arc<ScriptedMockReasoningBackend>,
    }

    impl ReasoningBackendFactory for FixtureReasoningFactory {
        fn create(&self, _target: &ResolvedTargetConfig) -> Result<Arc<dyn ReasoningBackend>> {
            Ok(self.backend.clone())
        }
    }

    fn fixture_app(client: MockMcpClient, backend: Arc<ScriptedMockReasoningBackend>) -> DiscoMcp {
        DiscoMcp::with_dependencies(
            DiscoMcpConfig::builtin_mock(),
            Arc::new(FixtureClientFactory { client }),
            Arc::new(FixtureReasoningFactory { backend }),
        )
    }

    /// A reasoning factory that panics if used, proving the session path never
    /// constructs or invokes a reasoning backend.
    struct PanicReasoningFactory;

    impl ReasoningBackendFactory for PanicReasoningFactory {
        fn create(&self, _target: &ResolvedTargetConfig) -> Result<Arc<dyn ReasoningBackend>> {
            panic!("the profiling-session path must never construct a reasoning backend");
        }
    }

    fn session_app(client: MockMcpClient) -> DiscoMcp {
        DiscoMcp::with_dependencies(
            DiscoMcpConfig::builtin_mock(),
            Arc::new(FixtureClientFactory { client }),
            Arc::new(PanicReasoningFactory),
        )
    }

    fn session_probe(name: &str, arguments: Value) -> ProbeDecision {
        ProbeDecision {
            selected_tool: Some(name.to_string()),
            arguments,
            confidence: 1.0,
            ..ProbeDecision::default()
        }
    }

    fn session_output(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "discomcp-session-{tag}-{}-{}",
            std::process::id(),
            now_unix_seconds()
        ))
    }

    #[tokio::test]
    async fn start_session_builds_catalogue_without_touching_reasoning() {
        let app = session_app(MockMcpClient::collection_fixture());
        let session = app
            .start_session("mock-collection", ProfileOptions::default())
            .await
            .expect("session should start");
        assert!(!session.catalogue().tools.is_empty());
        assert_eq!(session.server_name(), "generic-collection-fixture");
    }

    #[tokio::test]
    async fn session_executes_a_safe_read_probe() {
        let app = session_app(MockMcpClient::collection_fixture());
        let mut session = app
            .start_session("mock-collection", ProfileOptions::default())
            .await
            .expect("session should start");
        let outcome = session
            .execute_probe(session_probe("list_collections", json!({})))
            .await;
        assert_eq!(outcome.outcome, RuntimeOutcome::Accepted);
        assert!(outcome.observation.is_some());
        assert_eq!(session.runtime_budget.probes_executed, 1);
    }

    #[tokio::test]
    async fn agent_declared_read_is_recorded_and_written_back_at_finalize() {
        let output = session_output("declared");
        let app = session_app(MockMcpClient::collection_fixture());
        let mut session = app
            .start_session(
                "mock-collection",
                ProfileOptions {
                    output_dir: Some(output.clone()),
                    ..ProfileOptions::default()
                },
            )
            .await
            .expect("session should start");
        let mut probe = session_probe("list_collections", json!({}));
        probe.declared_risk = Some(RiskClass::ConstrainedRead);
        let outcome = session.execute_probe(probe).await;
        assert_eq!(outcome.outcome, RuntimeOutcome::Accepted);
        assert_eq!(outcome.risk, RiskClass::ConstrainedRead);
        let claim = session
            .probe_log
            .last()
            .and_then(|record| record.declared_classification.as_ref())
            .expect("declared classification must be recorded as evidence");
        assert_eq!(claim.status, EvidenceStatus::Declared);
        assert!(claim
            .source_references
            .contains(&"agent:execute_probe".to_string()));

        let result = session
            .finalize(Some(
                "This user curates a small set of collections and reads items by id.".to_string(),
            ))
            .expect("finalize should write artifacts");
        let card = result
            .profile
            .catalogue
            .tools
            .iter()
            .find(|tool| tool.raw.name == "list_collections")
            .map(|tool| &tool.card)
            .expect("card");
        assert_eq!(card.risk, RiskClass::ConstrainedRead);
        assert_eq!(card.risk_evidence, "agent_declared");
        let skill = fs::read_to_string(output.join("SKILL.md")).expect("read SKILL.md");
        assert!(skill.contains("- `list_collections`: `agent_declared`"));
        // The agent-authored usage narrative is woven into the skill.
        assert!(skill.contains("## How You Use This MCP"));
        assert!(skill.contains("curates a small set of collections"));
        // Unprobed tools without annotations land in the Unclassified bucket.
        assert!(skill.contains("### Unclassified"));
        assert!(skill.contains("- `create_item`: `unclassified`"));
        let _ = fs::remove_dir_all(output);
    }

    #[tokio::test]
    async fn session_rejects_a_mutation_without_incrementing_budget() {
        let app = session_app(MockMcpClient::collection_fixture());
        let mut session = app
            .start_session("mock-collection", ProfileOptions::default())
            .await
            .expect("session should start");
        let outcome = session
            .execute_probe(session_probe(
                "create_item",
                json!({"collection_id": "projects", "fields": {}}),
            ))
            .await;
        assert_eq!(outcome.outcome, RuntimeOutcome::Rejected);
        assert!(outcome.reason.to_ascii_lowercase().contains("risk"));
        assert!(outcome.observation.is_none());
        assert_eq!(session.runtime_budget.probes_executed, 0);
    }

    #[tokio::test]
    async fn session_rejects_schema_invalid_arguments() {
        let app = session_app(MockMcpClient::collection_fixture());
        let mut session = app
            .start_session("mock-collection", ProfileOptions::default())
            .await
            .expect("session should start");
        let outcome = session
            .execute_probe(session_probe("list_collections", json!({"unexpected": 1})))
            .await;
        assert_eq!(outcome.outcome, RuntimeOutcome::Rejected);
        assert!(outcome.reason.to_ascii_lowercase().contains("schema"));
    }

    #[tokio::test]
    async fn session_rejects_an_identifier_without_provenance() {
        let app = session_app(MockMcpClient::collection_fixture());
        let mut session = app
            .start_session("mock-collection", ProfileOptions::default())
            .await
            .expect("session should start");
        let outcome = session
            .execute_probe(session_probe(
                "describe_collection",
                json!({"collection_id": "projects"}),
            ))
            .await;
        assert_eq!(outcome.outcome, RuntimeOutcome::Rejected);
        assert!(outcome.reason.contains("provenance"));
    }

    #[tokio::test]
    async fn session_rejects_a_probe_when_the_budget_is_exhausted() {
        let mut budgets = ExplorationBudgets::for_mode(&crate::model::ExplorationMode::Quick);
        budgets.max_mcp_probes = 0;
        let app = session_app(MockMcpClient::collection_fixture());
        let mut session = app
            .start_session(
                "mock-collection",
                ProfileOptions {
                    budgets: Some(budgets),
                    ..ProfileOptions::default()
                },
            )
            .await
            .expect("session should start");
        let outcome = session
            .execute_probe(session_probe("list_collections", json!({})))
            .await;
        assert_eq!(outcome.outcome, RuntimeOutcome::Rejected);
        assert!(outcome.reason.to_ascii_lowercase().contains("budget"));
    }

    #[tokio::test]
    async fn session_finalize_writes_artifacts_and_reflects_the_observation() {
        let output = session_output("finalize");
        let app = session_app(MockMcpClient::collection_fixture());
        let mut session = app
            .start_session(
                "mock-collection",
                ProfileOptions {
                    output_dir: Some(output.clone()),
                    ..ProfileOptions::default()
                },
            )
            .await
            .expect("session should start");
        let accepted = session
            .execute_probe(session_probe("list_collections", json!({})))
            .await;
        assert_eq!(accepted.outcome, RuntimeOutcome::Accepted);
        let result = session
            .finalize(None)
            .expect("finalize should write artifacts");
        assert!(output.join("SKILL.md").exists());
        assert!(output.join("workspace-model.json").exists());
        assert!(output.join("operational-model.json").exists());
        assert!(output.join("AGENTS.md").exists());
        assert!(output.join("evals.yml").exists());
        assert_eq!(result.profile.observations.len(), 1);
        assert_eq!(result.profile.observations[0].tool, "list_collections");
        assert!(!result.profile.workspace_model.structures.is_empty());
        let _ = fs::remove_dir_all(output);
    }

    #[tokio::test]
    async fn mock_collection_profile_generates_an_observed_read_path_without_writes() {
        let output =
            std::env::temp_dir().join(format!("discomcp-profile-test-{}", now_unix_seconds()));
        let discomcp = DiscoMcp::new(DiscoMcpConfig::builtin_mock());
        let result = discomcp
            .profile(
                "mock-collection",
                ProfileOptions {
                    output_dir: Some(output.clone()),
                    ..ProfileOptions::default()
                },
            )
            .await
            .expect("profile should complete");
        assert!(output.join("SKILL.md").exists());
        assert!(output.join("workspace-model.json").exists());
        assert!(output.join("operational-model.json").exists());
        assert!(result.profile.probe_log.iter().all(|record| record
            .decision
            .selected_tool
            .as_deref()
            != Some("create_item")));
        assert!(result.profile.probe_log.iter().all(|record| record
            .decision
            .selected_tool
            .as_deref()
            != Some("delete_item")));
        let samples = fs::read_to_string(output.join("samples.redacted.json"))
            .expect("redacted samples should be persisted");
        assert!(!samples.contains("owner@example.test"));
        assert!(!samples.contains("fixture-token-that-must-never-persist"));
        assert!(samples.contains("[REDACTED_EMAIL]"));
        assert!(samples.contains("[REDACTED_SECRET]"));
        let _ = fs::remove_dir_all(output);
    }

    #[tokio::test]
    async fn catalogue_is_loaded_once_per_profile_and_no_change_refresh_skips_probes() {
        let output = std::env::temp_dir().join(format!(
            "discomcp-cache-test-{}-{}",
            std::process::id(),
            now_unix_seconds()
        ));
        let client = MockMcpClient::collection_fixture();
        let calls = client.calls();
        let app = fixture_app(
            client.clone(),
            Arc::new(ScriptedMockReasoningBackend::collection_fixture()),
        );
        let options = ProfileOptions {
            output_dir: Some(output.clone()),
            ..ProfileOptions::default()
        };
        app.profile("mock-collection", options.clone())
            .await
            .expect("initial profile should complete");
        assert_eq!(
            client.static_call_counts(),
            crate::mcp::MockStaticCallCounts {
                initialize: 1,
                list_tools: 1,
                list_resources: 1,
                list_prompts: 1,
            }
        );
        let probe_calls = calls.lock().expect("call log lock").len();
        let refresh = app
            .refresh("mock-collection", options)
            .await
            .expect("no-change refresh should complete");
        assert!(!refresh.changed);
        assert_eq!(calls.lock().expect("call log lock").len(), probe_calls);
        assert_eq!(client.static_call_counts().list_tools, 2);
        assert_eq!(client.static_call_counts().list_resources, 2);
        assert_eq!(client.static_call_counts().list_prompts, 2);
        let _ = fs::remove_dir_all(output);
    }

    #[tokio::test]
    async fn lookup_finds_an_existing_skill_by_fingerprint_without_probing() {
        let parent = std::env::temp_dir().join(format!(
            "discomcp-lookup-test-{}-{}",
            std::process::id(),
            now_unix_seconds()
        ));
        let output = parent.join("mock-collection");
        let client = MockMcpClient::collection_fixture();
        let app = fixture_app(
            client.clone(),
            Arc::new(ScriptedMockReasoningBackend::collection_fixture()),
        );
        app.profile(
            "mock-collection",
            ProfileOptions {
                output_dir: Some(output.clone()),
                ..ProfileOptions::default()
            },
        )
        .await
        .expect("initial profile should complete");

        let mut config = DiscoMcpConfig::builtin_mock();
        config.profile_dir = parent.clone();
        let app = DiscoMcp::with_dependencies(
            config,
            Arc::new(FixtureClientFactory {
                client: client.clone(),
            }),
            Arc::new(FixtureReasoningFactory {
                backend: Arc::new(ScriptedMockReasoningBackend::collection_fixture()),
            }),
        );
        let calls_before_lookup = client.calls().lock().expect("call log lock").len();
        let found = app
            .lookup("mock-collection")
            .await
            .expect("lookup should complete");
        assert_eq!(found.existing_skill_dir, Some(output.clone()));
        assert_eq!(
            client.calls().lock().expect("call log lock").len(),
            calls_before_lookup,
            "lookup must not execute any probe"
        );

        let _ = fs::remove_dir_all(&parent);
    }

    #[tokio::test]
    async fn a_failed_safe_probe_records_uncertainty_and_later_probe_can_succeed() {
        let tools = crate::mcp::collection_fixture_tools();
        let responses = BTreeMap::from([(
            "list_collections".to_string(),
            VecDeque::from([
                Err(McpError::ToolFailure {
                    tool: "list_collections".to_string(),
                    message: "temporary fixture failure".to_string(),
                }),
                Ok(json!({"collections": [{"id": "projects", "name": "Projects"}]})),
            ]),
        )]);
        let client = MockMcpClient::new(
            crate::model::ServerHandshake::default(),
            tools,
            Vec::new(),
            Vec::new(),
            responses,
        );
        let plan = |stop: bool| ProbeDecision {
            objective: "Discover collections".to_string(),
            unresolved_question: "Which collections are available?".to_string(),
            selected_tool: (!stop).then_some("list_collections".to_string()),
            arguments: json!({}),
            expected_information: String::new(),
            expected_information_gain: if stop { 0.0 } else { 0.8 },
            confidence: 0.9,
            alternatives: Vec::new(),
            argument_provenance: Vec::new(),
            declared_risk: None,
            stop,
            stop_reason: stop.then_some("A later safe probe succeeded.".to_string()),
        };
        let backend = Arc::new(ScriptedMockReasoningBackend::new(vec![
            ScriptedResponse {
                task: ReasoningTask::AnalyzeCapabilities,
                response: ReasoningResponse {
                    output: json!({"structure_discovery": true}),
                    warnings: Vec::new(),
                },
            },
            ScriptedResponse {
                task: ReasoningTask::PlanNextProbe,
                response: ReasoningResponse {
                    output: serde_json::to_value(plan(false)).expect("serializable plan"),
                    warnings: Vec::new(),
                },
            },
            ScriptedResponse {
                task: ReasoningTask::PlanNextProbe,
                response: ReasoningResponse {
                    output: serde_json::to_value(plan(false)).expect("serializable plan"),
                    warnings: Vec::new(),
                },
            },
            ScriptedResponse {
                task: ReasoningTask::InterpretObservation,
                response: ReasoningResponse {
                    output: serde_json::to_value(EvidenceClaim::observed(
                        "A later collection response succeeded.",
                        "observation:probe-002",
                        0.9,
                    ))
                    .expect("serializable claim"),
                    warnings: Vec::new(),
                },
            },
            ScriptedResponse {
                task: ReasoningTask::PlanNextProbe,
                response: ReasoningResponse {
                    output: serde_json::to_value(plan(true)).expect("serializable stop plan"),
                    warnings: Vec::new(),
                },
            },
        ]));
        let output = std::env::temp_dir().join(format!(
            "discomcp-failure-test-{}-{}",
            std::process::id(),
            now_unix_seconds()
        ));
        let result = fixture_app(client, backend)
            .profile(
                "mock-collection",
                ProfileOptions {
                    output_dir: Some(output.clone()),
                    ..ProfileOptions::default()
                },
            )
            .await
            .expect("profile should continue after a probe failure");
        assert_eq!(
            result.profile.probe_log[0].runtime_decision.outcome,
            RuntimeOutcome::Failed
        );
        assert!(result
            .profile
            .probe_log
            .iter()
            .any(|record| record.runtime_decision.outcome == RuntimeOutcome::Accepted));
        assert!(!result.profile.workspace_model.uncertainties.is_empty());
        let _ = fs::remove_dir_all(output);
    }

    // ---- Feature A: gap-report unit tests (compute_gaps, no live client) ----

    use crate::model::{ArgumentProvenance, CataloguedTool, ObservedIdentifier, RawTool};

    fn safe_tool(name: &str, desc: &str, schema: Value) -> CataloguedTool {
        CataloguedTool {
            raw: RawTool {
                name: name.to_string(),
                description: desc.to_string(),
                input_schema: schema,
                ..RawTool::default()
            },
            card: ToolCard {
                name: name.to_string(),
                ..ToolCard::default()
            },
        }
    }

    /// A tool the deterministic backstop vetoes (destructive verb in the name).
    fn backstop_blocked_tool(name: &str, schema: Value) -> CataloguedTool {
        assert!(
            crate::policy::backstop_veto(&RawTool {
                name: name.to_string(),
                ..RawTool::default()
            })
            .is_some(),
            "fixture `{name}` must be backstop-blocked"
        );
        safe_tool(name, "", schema)
    }

    fn gap_catalogue(tools: Vec<CataloguedTool>) -> ToolCatalogue {
        ToolCatalogue {
            tools,
            ..ToolCatalogue::default()
        }
    }

    fn ident(
        name: &str,
        value: &str,
        observation_id: &str,
        json_pointer: &str,
    ) -> ObservedIdentifier {
        ObservedIdentifier {
            name: name.to_string(),
            value: value.to_string(),
            observation_id: observation_id.to_string(),
            json_pointer: json_pointer.to_string(),
            ..ObservedIdentifier::default()
        }
    }

    fn obs(
        id: &str,
        tool: &str,
        shape: Value,
        identifiers: Vec<ObservedIdentifier>,
    ) -> NormalizedObservation {
        NormalizedObservation {
            id: id.to_string(),
            tool: tool.to_string(),
            shape,
            identifiers,
            ..NormalizedObservation::default()
        }
    }

    fn observed_prov(observation_id: &str, json_pointer: &str) -> ArgumentProvenance {
        ArgumentProvenance {
            json_pointer: json_pointer.to_string(),
            source: ArgumentSource::Observed {
                observation_id: observation_id.to_string(),
                json_pointer: json_pointer.to_string(),
            },
        }
    }

    fn accepted_probe(tool: &str, provenance: Vec<ArgumentProvenance>) -> ProbeRecord {
        ProbeRecord {
            decision: ProbeDecision {
                selected_tool: Some(tool.to_string()),
                argument_provenance: provenance,
                ..ProbeDecision::default()
            },
            runtime_decision: RuntimeDecision {
                outcome: RuntimeOutcome::Accepted,
                reason: String::new(),
            },
            ..ProbeRecord::default()
        }
    }

    #[test]
    fn gaps_unexecuted_tools_excludes_executed_and_backstop_blocked() {
        let cat = gap_catalogue(vec![
            safe_tool("A", "First tool. More text.", json!({})),
            safe_tool("B", "Bee does things. Ignore this.", json!({})),
            backstop_blocked_tool("delete_m", json!({})),
        ]);
        let probes = vec![accepted_probe("A", vec![])];
        let gaps = compute_gaps(&cat, &[], &probes, 10, 1);
        assert_eq!(gaps.unexecuted_tools.len(), 1);
        assert_eq!(gaps.unexecuted_tools[0].tool, "B");
        assert_eq!(gaps.unexecuted_tools[0].why_useful, "Bee does things.");
    }

    #[test]
    fn gaps_identifier_untraversed_then_traversed() {
        let schema = json!({"type":"object","properties":{"document_id":{"type":"string"}}});
        let cat = gap_catalogue(vec![
            safe_tool("get_doc", "Gets a doc.", schema.clone()),
            // A backstop-blocked tool consuming the same param must never be
            // offered as a likely consumer — following that hint would hit an
            // execute_probe rejection.
            backstop_blocked_tool("delete_doc", schema),
        ]);
        let observations = vec![obs(
            "obs-1",
            "list",
            json!({}),
            vec![ident("document_id", "D1", "obs-1", "/items/0/document_id")],
        )];
        let gaps = compute_gaps(&cat, &observations, &[], 10, 0);
        assert_eq!(gaps.untraversed_identifiers.len(), 1);
        assert_eq!(
            gaps.untraversed_identifiers[0].likely_consumer_tools,
            vec!["get_doc".to_string()]
        );
        assert_eq!(gaps.depth_signal.identifiers_traversed, 0);

        let probes = vec![accepted_probe(
            "get_doc",
            vec![observed_prov("obs-1", "/items/0/document_id")],
        )];
        let gaps = compute_gaps(&cat, &observations, &probes, 10, 1);
        assert!(gaps.untraversed_identifiers.is_empty());
        assert_eq!(gaps.depth_signal.identifiers_traversed, 1);
    }

    #[test]
    fn gaps_unsampled_structure_drops_after_downstream_probe() {
        let shape = json!({"type":"array","items":{"id":"string"}});
        let ids = vec![
            ident("id", "a", "obs-1", "/0/id"),
            ident("id", "b", "obs-1", "/1/id"),
            ident("id", "c", "obs-1", "/2/id"),
        ];
        let observations = vec![obs("obs-1", "list", shape, ids)];
        let cat = gap_catalogue(vec![]);
        let gaps = compute_gaps(&cat, &observations, &[], 10, 0);
        assert_eq!(gaps.unsampled_structures.len(), 1);
        assert_eq!(gaps.unsampled_structures[0].downstream_samples, 0);
        assert_eq!(gaps.unsampled_structures[0].identifiers_inside, 3);

        let probes = vec![accepted_probe("get", vec![observed_prov("obs-1", "/0/id")])];
        let gaps = compute_gaps(&cat, &observations, &probes, 10, 1);
        assert!(gaps.unsampled_structures.is_empty());
    }

    #[test]
    fn gaps_sampling_hints_match_case_and_separator_insensitively() {
        let schema = json!({"type":"object","properties":{"orderBy":{},"pageSize":{},"name":{}}});
        let cat = gap_catalogue(vec![
            safe_tool("list_x", "Lists.", schema.clone()),
            // A backstop-blocked tool exposing a sampling param must never be
            // offered as a sampling hint — probing it would hit an
            // execute_probe rejection.
            backstop_blocked_tool("delete_all", schema),
        ]);
        let gaps = compute_gaps(&cat, &[], &[], 10, 0);
        assert_eq!(gaps.sampling_hints.len(), 1);
        assert_eq!(gaps.sampling_hints[0].tool, "list_x");
        let mut params = gaps.sampling_hints[0].params.clone();
        params.sort();
        assert_eq!(params, vec!["orderBy".to_string(), "pageSize".to_string()]);

        let probes = vec![accepted_probe("list_x", vec![])];
        let gaps = compute_gaps(&cat, &[], &probes, 10, 1);
        assert!(gaps.sampling_hints.is_empty());
    }

    #[test]
    fn gaps_depth_signal_counts_are_exact() {
        let cat = gap_catalogue(vec![
            safe_tool("A", "a", json!({})),
            safe_tool(
                "get",
                "g",
                json!({"type":"object","properties":{"thing_id":{}}}),
            ),
            backstop_blocked_tool("delete_m", json!({})),
        ]);
        let observations = vec![obs(
            "obs-1",
            "list",
            json!({"type":"object"}),
            vec![
                ident("thing_id", "T", "obs-1", "/thing_id"),
                ident("other_id", "O", "obs-1", "/other_id"),
            ],
        )];
        let probes = vec![accepted_probe(
            "A",
            vec![observed_prov("obs-1", "/thing_id")],
        )];
        let ds = compute_gaps(&cat, &observations, &probes, 8, 1).depth_signal;
        assert_eq!(ds.probeable_tools_total, 2);
        assert_eq!(ds.probeable_tools_covered, 1);
        assert_eq!(ds.identifiers_observed, 2);
        assert_eq!(ds.identifiers_traversed, 1);
        assert_eq!(ds.structures_observed, 0);
        assert_eq!(ds.probes_executed, 1);
        assert_eq!(ds.probe_budget, 8);
    }

    #[test]
    fn gaps_stop_probe_is_not_counted_as_executed() {
        let stop = ProbeRecord {
            decision: ProbeDecision {
                selected_tool: None,
                stop: true,
                ..ProbeDecision::default()
            },
            runtime_decision: RuntimeDecision {
                outcome: RuntimeOutcome::Accepted,
                reason: String::new(),
            },
            ..ProbeRecord::default()
        };
        let cat = gap_catalogue(vec![safe_tool("A", "a", json!({}))]);
        let gaps = compute_gaps(&cat, &[], &[stop], 10, 0);
        assert_eq!(gaps.unexecuted_tools.len(), 1);
    }

    #[test]
    fn gaps_shrink_monotonically_as_probes_close_gaps() {
        let schema = json!({"type":"object","properties":{"document_id":{}}});
        let cat = gap_catalogue(vec![
            safe_tool("A", "a", json!({})),
            safe_tool("get_doc", "g", schema),
        ]);
        let observations = vec![obs(
            "obs-1",
            "list",
            json!({}),
            vec![ident("document_id", "D", "obs-1", "/document_id")],
        )];
        let g0 = compute_gaps(&cat, &observations, &[], 10, 0);
        let p1 = vec![accepted_probe("A", vec![])];
        let g1 = compute_gaps(&cat, &observations, &p1, 10, 1);
        let mut p2 = p1.clone();
        p2.push(accepted_probe(
            "get_doc",
            vec![observed_prov("obs-1", "/document_id")],
        ));
        let g2 = compute_gaps(&cat, &observations, &p2, 10, 2);
        assert!(g0.unexecuted_tools.len() >= g1.unexecuted_tools.len());
        assert!(g1.unexecuted_tools.len() >= g2.unexecuted_tools.len());
        assert!(g0.untraversed_identifiers.len() >= g1.untraversed_identifiers.len());
        assert!(g1.untraversed_identifiers.len() >= g2.untraversed_identifiers.len());
    }

    #[test]
    fn gaps_never_leak_sample_or_redacted_payload() {
        let mut observation = obs(
            "obs-1",
            "get",
            json!({"type":"object"}),
            vec![ident("id", "clean-id", "obs-1", "/id")],
        );
        observation.sample = json!({"secret":"[REDACTED:email]","note":"hi"});
        let gaps = compute_gaps(&gap_catalogue(vec![]), &[observation], &[], 10, 0);
        let serialized = serde_json::to_string(&gaps).expect("serialize gaps");
        assert!(!serialized.contains("\"sample\""));
        assert!(!serialized.contains("[REDACTED"));
    }
}
