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
use crate::error::{DiscoMcpError, Result};
use crate::inference::{infer_capability_profile, infer_workspace_model, operational_model};
use crate::mcp::stdio::StdioMcpClient;
use crate::mcp::{McpClient, MockMcpClient};
use crate::model::{
    DocumentationIndex, DocumentationSource, EvidenceClaim, EvidenceRef, EvidenceStatus,
    ExplorationBudgets, NormalizedObservation, ProbeDecision, ProbeRecord, ProfileMetadata,
    ProfileOptions, ProfileResult, QualityDimension, QualityReport, RawDiscovery, RuntimeDecision,
    RuntimeOutcome, TargetProfile, ToolCard, Uncertainty,
};
use crate::normalization::normalize_observation;
use crate::policy::{execute_safe_probe, RuntimeBudget, SafeProbeRequest, SafetyPolicy};
use crate::reasoning::{
    CommandReasoningBackend, ReasoningBackend, ReasoningError, ReasoningRequest, ReasoningRole,
    ReasoningTask, ScriptedMockReasoningBackend,
};
use crate::redaction::Redactor;

#[async_trait]
pub trait McpClientFactory: Send + Sync {
    async fn connect(&self, target: &ResolvedTargetConfig) -> Result<Box<dyn McpClient>>;
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
                });
                break;
            }
            let execution = execute_safe_probe(SafeProbeRequest {
                client: client.as_ref(),
                catalogue: &catalogue,
                decision: &decision,
                candidate_tools: &candidate_names,
                observations: &observations,
                budgets: &budgets,
                budget: &mut runtime_budget,
                policy: &policy,
                dry_run: options.dry_run,
            })
            .await;
            let mut record = ProbeRecord {
                id: probe_id.clone(),
                decision: decision.clone(),
                candidate_tools: candidate_names,
                risk: execution.risk,
                runtime_decision: execution.runtime_decision.clone(),
                result_fingerprint: None,
                error: None,
                interpretation: None,
            };
            if let Some(response) = execution.response {
                let (redacted, report) = redactor.redact(&response);
                debug!(
                    target = target_id,
                    probe = probe_id,
                    secrets_redacted = report.secrets_redacted,
                    pii_redacted = report.pii_redacted,
                    "normalizing safe target observation"
                );
                let observation = normalize_observation(
                    probe_id.clone(),
                    decision.selected_tool.clone().unwrap_or_default(),
                    decision.arguments.clone(),
                    &redacted,
                    &budgets,
                );
                record.result_fingerprint = Some(observation.fingerprint.clone());
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
            } else if record.runtime_decision.outcome != RuntimeOutcome::Skipped {
                record.error = Some(record.runtime_decision.reason.clone());
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

        let capability_profile = infer_capability_profile(&catalogue);
        let mut workspace_model =
            infer_workspace_model(target_id, &catalogue, &observations, &probe_log);
        workspace_model.uncertainties.extend(dynamic_uncertainties);
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
            static_discovery_complete: true,
        };
        let quality_report = quality_report(&catalogue, &workspace_model);
        let profile = TargetProfile {
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
        };
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

async fn static_discovery(client: &mut dyn McpClient) -> Result<RawDiscovery> {
    let handshake = client.initialize().await?;
    let tools = client.list_tools().await?;
    let resources = client.list_resources().await?;
    let prompts = client.list_prompts().await?;
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
}
