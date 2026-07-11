use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Declared,
    Documented,
    Observed,
    Inferred,
    UserDefined,
    #[default]
    Unknown,
    Contradicted,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct EvidenceRef {
    pub status: EvidenceStatus,
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct EvidenceClaim {
    pub claim: String,
    pub status: EvidenceStatus,
    pub confidence: f32,
    #[serde(default)]
    pub evidence: Vec<EvidenceRef>,
    #[serde(default)]
    pub source_references: Vec<String>,
    #[serde(default)]
    pub contradictions: Vec<String>,
}

impl EvidenceClaim {
    #[must_use]
    pub fn declared(claim: impl Into<String>, source: impl Into<String>) -> Self {
        let source = source.into();
        Self {
            claim: claim.into(),
            status: EvidenceStatus::Declared,
            confidence: 1.0,
            evidence: vec![EvidenceRef {
                status: EvidenceStatus::Declared,
                source: source.clone(),
                detail: None,
            }],
            source_references: vec![source],
            contradictions: Vec::new(),
        }
    }

    #[must_use]
    pub fn observed(claim: impl Into<String>, source: impl Into<String>, confidence: f32) -> Self {
        let source = source.into();
        Self {
            claim: claim.into(),
            status: EvidenceStatus::Observed,
            confidence,
            evidence: vec![EvidenceRef {
                status: EvidenceStatus::Observed,
                source: source.clone(),
                detail: None,
            }],
            source_references: vec![source],
            contradictions: Vec::new(),
        }
    }

    #[must_use]
    pub fn inferred(claim: impl Into<String>, sources: Vec<String>, confidence: f32) -> Self {
        Self {
            claim: claim.into(),
            status: EvidenceStatus::Inferred,
            confidence,
            evidence: sources
                .iter()
                .cloned()
                .map(|source| EvidenceRef {
                    status: EvidenceStatus::Inferred,
                    source,
                    detail: None,
                })
                .collect(),
            source_references: sources,
            contradictions: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ServerHandshake {
    pub server_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instructions: Option<String>,
    #[serde(default)]
    pub capabilities: Value,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RawTool {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default = "default_object")]
    pub input_schema: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<Value>,
    #[serde(default)]
    pub annotations: Value,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RawResource {
    pub uri: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    #[serde(default)]
    pub annotations: Value,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct PromptArgument {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub required: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RawPrompt {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub arguments: Vec<PromptArgument>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum RiskClass {
    SafeRead,
    ConstrainedRead,
    SensitiveRead,
    PureComputation,
    Mutation,
    ExternalSideEffect,
    Destructive,
    Administrative,
    ArbitraryExecution,
    #[default]
    Unknown,
}

impl RiskClass {
    #[must_use]
    pub fn is_allowed_during_onboarding(&self) -> bool {
        matches!(
            self,
            Self::SafeRead | Self::ConstrainedRead | Self::PureComputation
        )
    }

    #[must_use]
    pub fn requires_confirmation(&self) -> bool {
        matches!(
            self,
            Self::Mutation
                | Self::ExternalSideEffect
                | Self::Destructive
                | Self::Administrative
                | Self::ArbitraryExecution
        )
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ToolCard {
    pub name: String,
    pub summary: String,
    #[serde(default)]
    pub declared_purposes: Vec<String>,
    pub risk: RiskClass,
    /// Where `risk` came from: `server_annotation`, `agent_declared`, or
    /// `unclassified`.
    #[serde(default)]
    pub risk_evidence: String,
    #[serde(default)]
    pub required_arguments: Vec<String>,
    #[serde(default)]
    pub optional_arguments: Vec<String>,
    #[serde(default)]
    pub identifier_dependencies: BTreeMap<String, String>,
    #[serde(default)]
    pub output_summary: String,
    pub confidence: f32,
    pub fingerprint: String,
    #[serde(default)]
    pub searchable_text: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct CataloguedTool {
    pub raw: RawTool,
    pub card: ToolCard,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ToolCatalogue {
    #[serde(default)]
    pub tools: Vec<CataloguedTool>,
    #[serde(default)]
    pub resources: Vec<RawResource>,
    #[serde(default)]
    pub prompts: Vec<RawPrompt>,
    pub fingerprint: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RawDiscovery {
    pub handshake: ServerHandshake,
    #[serde(default)]
    pub tools: Vec<RawTool>,
    #[serde(default)]
    pub resources: Vec<RawResource>,
    #[serde(default)]
    pub prompts: Vec<RawPrompt>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct DocumentationSource {
    pub id: String,
    pub location: String,
    pub status: EvidenceStatus,
    pub summary: String,
    pub fingerprint: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct DocumentationIndex {
    #[serde(default)]
    pub sources: Vec<DocumentationSource>,
    #[serde(default)]
    pub extracted_facts: BTreeMap<String, Vec<String>>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct CapabilityEvidence {
    pub enabled: bool,
    pub claim: EvidenceClaim,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct CapabilityProfile {
    #[serde(default)]
    pub dimensions: BTreeMap<String, CapabilityEvidence>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StructureKind {
    Object,
    Collection,
    RecordCollection,
    List,
    Table,
    Dataset,
    Folder,
    DocumentCollection,
    FileCollection,
    MessageCollection,
    EventCollection,
    TaskCollection,
    Graph,
    ResourceNamespace,
    Custom,
    #[default]
    Unknown,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct DiscoveredField {
    pub name: String,
    pub type_summary: String,
    #[serde(default)]
    pub enum_values: Vec<String>,
    pub is_identifier: bool,
    pub evidence: EvidenceClaim,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct DiscoveredStructure {
    pub declared_name: String,
    pub normalized_name: String,
    pub possible_semantic_type: StructureKind,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub fields: Vec<DiscoveredField>,
    #[serde(default)]
    pub identifiers: Vec<String>,
    #[serde(default)]
    pub enum_values: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub possible_parents: Vec<String>,
    #[serde(default)]
    pub possible_children: Vec<String>,
    #[serde(default)]
    pub source_tools: Vec<String>,
    #[serde(default)]
    pub source_resources: Vec<String>,
    pub evidence: EvidenceClaim,
    pub freshness: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RelationshipType {
    Contains,
    References,
    ParentChild,
    Membership,
    AttachedTo,
    OwnedBy,
    AssignedTo,
    CreatedBy,
    DerivedFrom,
    TemporalSequence,
    OneToMany,
    ManyToMany,
    #[default]
    Unknown,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct DiscoveredRelationship {
    pub from_structure: String,
    pub to_structure: String,
    pub relationship_type: RelationshipType,
    #[serde(default)]
    pub via_fields: Vec<String>,
    pub evidence: EvidenceClaim,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct DiscoveredOperation {
    pub name: String,
    pub risk: RiskClass,
    pub summary: String,
    pub evidence: EvidenceClaim,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct WorkflowStep {
    pub tool: String,
    pub purpose: String,
    #[serde(default)]
    pub argument_derivation: Vec<String>,
    #[serde(default)]
    pub identifier_source: Option<String>,
    pub confirmation_required: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct OperationalWorkflow {
    pub name: String,
    pub supported_user_intent: String,
    #[serde(default)]
    pub preconditions: Vec<String>,
    #[serde(default)]
    pub ordered_tool_sequence: Vec<WorkflowStep>,
    pub expected_result: String,
    #[serde(default)]
    pub optional_traversal: Vec<String>,
    pub mutation_boundary: String,
    #[serde(default)]
    pub confirmation_requirements: Vec<String>,
    #[serde(default)]
    pub verification_steps: Vec<String>,
    #[serde(default)]
    pub failure_handling: Vec<String>,
    pub evidence: EvidenceClaim,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ObservationRef {
    pub id: String,
    pub tool: String,
    pub fingerprint: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Hypothesis {
    pub claim: EvidenceClaim,
    pub unresolved_question: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Contradiction {
    pub claim: String,
    #[serde(default)]
    pub sources: Vec<String>,
    pub resolution: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Uncertainty {
    pub question: String,
    pub reason: String,
    pub importance: String,
    #[serde(default)]
    pub evidence: Vec<EvidenceRef>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct WorkspaceModel {
    pub target_id: String,
    pub summary: String,
    #[serde(default)]
    pub structures: Vec<DiscoveredStructure>,
    #[serde(default)]
    pub relationships: Vec<DiscoveredRelationship>,
    #[serde(default)]
    pub operations: Vec<DiscoveredOperation>,
    #[serde(default)]
    pub workflows: Vec<OperationalWorkflow>,
    #[serde(default)]
    pub observations: Vec<ObservationRef>,
    #[serde(default)]
    pub hypotheses: Vec<Hypothesis>,
    #[serde(default)]
    pub contradictions: Vec<Contradiction>,
    #[serde(default)]
    pub uncertainties: Vec<Uncertainty>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct OperationalModel {
    pub target_id: String,
    pub summary: String,
    pub capability_profile: CapabilityProfile,
    #[serde(default)]
    pub workflows: Vec<OperationalWorkflow>,
    #[serde(default)]
    pub confirmation_boundaries: Vec<String>,
    #[serde(default)]
    pub known_uncertainties: Vec<Uncertainty>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ObservedIdentifier {
    pub name: String,
    pub value: String,
    pub observation_id: String,
    pub json_pointer: String,
    pub evidence: EvidenceClaim,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct NormalizedObservation {
    pub id: String,
    pub tool: String,
    #[serde(default)]
    pub arguments: Value,
    #[serde(default)]
    pub shape: Value,
    #[serde(default)]
    pub observed_enum_values: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub identifiers: Vec<ObservedIdentifier>,
    #[serde(default)]
    pub sample: Value,
    pub fingerprint: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ArgumentSource {
    Observed {
        observation_id: String,
        json_pointer: String,
    },
    SchemaDefault {
        schema_pointer: String,
    },
    Enum {
        schema_pointer: String,
    },
    UserDefined,
    UserGoal,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ArgumentProvenance {
    pub json_pointer: String,
    pub source: ArgumentSource,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ProbeAlternative {
    pub tool: String,
    pub reason: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ProbeDecision {
    pub objective: String,
    pub unresolved_question: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_tool: Option<String>,
    #[serde(default)]
    pub arguments: Value,
    pub expected_information: String,
    pub expected_information_gain: f32,
    pub confidence: f32,
    #[serde(default)]
    pub alternatives: Vec<ProbeAlternative>,
    #[serde(default)]
    pub argument_provenance: Vec<ArgumentProvenance>,
    /// The agent's own risk classification of the selected tool. DiscoMCP never
    /// infers risk from text; without a read-class declaration (or a server
    /// readOnlyHint) the probe is rejected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared_risk: Option<RiskClass>,
    #[serde(default)]
    pub stop: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop_reason: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeOutcome {
    Accepted,
    #[default]
    Skipped,
    Rejected,
    Failed,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RuntimeDecision {
    pub outcome: RuntimeOutcome,
    pub reason: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ProbeRecord {
    pub id: String,
    pub decision: ProbeDecision,
    #[serde(default)]
    pub candidate_tools: Vec<String>,
    pub risk: RiskClass,
    pub runtime_decision: RuntimeDecision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interpretation: Option<EvidenceClaim>,
    /// Agent-attributed evidence for the risk class the agent declared on this
    /// probe. `None` when the probe carried no declaration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared_classification: Option<EvidenceClaim>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExplorationMode {
    Quick,
    #[default]
    Standard,
    Deep,
    Custom,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExplorationBudgets {
    pub max_reasoning_cycles: u32,
    pub max_mcp_probes: u32,
    /// How many FULL records (objects with many fields) to retain in the sample
    /// for shape inference. Kept LOW to avoid record bloat.
    pub max_samples_per_structure: u32,
    /// How many SHORT scalar items (names/ids/enum values) to keep from an
    /// array in the sample. Kept HIGH so wide lists (datasets, tables, ...) are
    /// captured completely — short strings are cheap. Does not bound the
    /// identifier-collection walk (which is depth-bounded, not count-bounded).
    #[serde(default = "default_identifier_coverage")]
    pub max_identifier_coverage: u32,
    pub max_traversal_depth: u32,
    pub max_response_bytes: usize,
    pub per_call_timeout_ms: u64,
    pub consecutive_low_gain_limit: u32,
}

fn default_identifier_coverage() -> u32 {
    250
}

impl ExplorationBudgets {
    #[must_use]
    pub fn for_mode(mode: &ExplorationMode) -> Self {
        match mode {
            ExplorationMode::Quick => Self {
                max_reasoning_cycles: 2,
                max_mcp_probes: 8,
                max_samples_per_structure: 2,
                max_identifier_coverage: 100,
                max_traversal_depth: 2,
                max_response_bytes: 128 * 1024,
                per_call_timeout_ms: 5_000,
                consecutive_low_gain_limit: 2,
            },
            ExplorationMode::Standard => Self {
                max_reasoning_cycles: 6,
                max_mcp_probes: 30,
                max_samples_per_structure: 5,
                max_identifier_coverage: 250,
                max_traversal_depth: 4,
                max_response_bytes: 256 * 1024,
                per_call_timeout_ms: 8_000,
                consecutive_low_gain_limit: 3,
            },
            ExplorationMode::Deep => Self {
                max_reasoning_cycles: 20,
                max_mcp_probes: 100,
                max_samples_per_structure: 10,
                max_identifier_coverage: 1_000,
                max_traversal_depth: 6,
                max_response_bytes: 512 * 1024,
                per_call_timeout_ms: 12_000,
                consecutive_low_gain_limit: 4,
            },
            ExplorationMode::Custom => Self::for_mode(&ExplorationMode::Standard),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyMode {
    Strict,
    #[default]
    Balanced,
    LocalTrusted,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProfileOptions {
    #[serde(default)]
    pub mode: ExplorationMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub goal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_dir: Option<PathBuf>,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub privacy_mode: PrivacyMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budgets: Option<ExplorationBudgets>,
}

impl Default for ProfileOptions {
    fn default() -> Self {
        Self {
            mode: ExplorationMode::Standard,
            goal: None,
            output_dir: None,
            dry_run: false,
            privacy_mode: PrivacyMode::Balanced,
            budgets: None,
        }
    }
}

impl ProfileOptions {
    #[must_use]
    pub fn effective_budgets(&self) -> ExplorationBudgets {
        self.budgets
            .clone()
            .unwrap_or_else(|| ExplorationBudgets::for_mode(&self.mode))
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ProfileMetadata {
    pub target_id: String,
    pub profile_version: String,
    pub generated_at_unix_seconds: u64,
    pub target_fingerprint: String,
    pub mode: ExplorationMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub goal: Option<String>,
    /// Agent-authored narrative of how the user actually uses this source,
    /// woven into SKILL.md. The runtime captures raw observations; the agent
    /// reasons over them to write this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage_summary: Option<String>,
    pub static_discovery_complete: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct QualityDimension {
    pub name: String,
    pub assessment: String,
    pub confidence: f32,
    #[serde(default)]
    pub evidence: Vec<EvidenceRef>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct QualityReport {
    #[serde(default)]
    pub dimensions: Vec<QualityDimension>,
    #[serde(default)]
    pub strengths: Vec<String>,
    #[serde(default)]
    pub weaknesses: Vec<String>,
    #[serde(default)]
    pub safety_concerns: Vec<String>,
    #[serde(default)]
    pub blockers: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct TargetProfile {
    pub metadata: ProfileMetadata,
    pub raw_discovery: RawDiscovery,
    pub documentation: DocumentationIndex,
    pub catalogue: ToolCatalogue,
    pub capability_profile: CapabilityProfile,
    pub workspace_model: WorkspaceModel,
    pub operational_model: OperationalModel,
    #[serde(default)]
    pub probe_log: Vec<ProbeRecord>,
    #[serde(default)]
    pub observations: Vec<NormalizedObservation>,
    pub quality_report: QualityReport,
}

#[derive(Clone, Debug)]
pub struct ProfileResult {
    pub profile: TargetProfile,
    pub output_dir: PathBuf,
}

#[must_use]
pub fn default_object() -> Value {
    Value::Object(serde_json::Map::new())
}
