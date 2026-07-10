use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::model::{ArgumentProvenance, ArgumentSource, EvidenceClaim, ProbeDecision};

// The public role is declared here rather than tying reasoning to a named model provider.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReasoningRole {
    Everyday,
    Deep,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReasoningTask {
    AnalyzeCapabilities,
    SummarizeDocumentation,
    BuildToolCards,
    ClassifyTools,
    GenerateHypotheses,
    IdentifyInformationGaps,
    PlanNextProbe,
    InterpretObservation,
    InferStructures,
    InferRelationships,
    InferWorkflows,
    GenerateSkill,
    ReviewProfile,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ModelCapabilities {
    pub structured_output: bool,
    pub json_schema: bool,
    pub tool_calling: bool,
    pub streaming: bool,
    pub long_context: bool,
    pub reasoning_control: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReasoningRequest {
    pub task: ReasoningTask,
    pub instructions: String,
    pub context: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<Value>,
    pub role: ReasoningRole,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_output_tokens: Option<u32>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ReasoningResponse {
    #[serde(default)]
    pub output: Value,
    #[serde(default)]
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Error)]
pub enum ReasoningError {
    #[error("reasoning backend returned invalid structured output: {0}")]
    InvalidOutput(String),
    #[error("reasoning backend failed: {0}")]
    Backend(String),
}

#[async_trait]
pub trait ReasoningBackend: Send + Sync {
    async fn reason(&self, request: ReasoningRequest) -> Result<ReasoningResponse, ReasoningError>;
    fn backend_id(&self) -> &str;
    fn model_id(&self) -> &str;
    fn capabilities(&self) -> ModelCapabilities;
}

/// Provider-neutral backend that invokes a configured command for every reasoning request.
///
/// The command receives one UTF-8 JSON-serialized [`ReasoningRequest`] on stdin and must write
/// either a JSON [`ReasoningResponse`] or a raw JSON value usable as its `output` to stdout.
pub struct CommandReasoningBackend {
    command: String,
    args: Vec<String>,
    backend_id: String,
    model_id: String,
    timeout: Duration,
}

impl CommandReasoningBackend {
    #[must_use]
    pub fn new(command: String, args: Vec<String>, model_id: String) -> Self {
        Self {
            backend_id: format!("command:{command}"),
            command,
            args,
            model_id,
            timeout: Duration::from_secs(120),
        }
    }

    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

#[async_trait]
impl ReasoningBackend for CommandReasoningBackend {
    async fn reason(&self, request: ReasoningRequest) -> Result<ReasoningResponse, ReasoningError> {
        let mut process = Command::new(&self.command);
        process
            .args(
                self.args
                    .iter()
                    .map(|argument| argument.replace("{model}", &self.model_id)),
            )
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true);
        let mut child = process.spawn().map_err(|error| {
            ReasoningError::Backend(format!("failed starting reasoning command: {error}"))
        })?;
        let request_json = serde_json::to_vec(&request)
            .map_err(|error| ReasoningError::InvalidOutput(error.to_string()))?;
        let mut stdin = child.stdin.take().ok_or_else(|| {
            ReasoningError::Backend("reasoning command stdin was unavailable".to_string())
        })?;
        stdin.write_all(&request_json).await.map_err(|error| {
            ReasoningError::Backend(format!("failed writing reasoning input: {error}"))
        })?;
        stdin.shutdown().await.map_err(|error| {
            ReasoningError::Backend(format!("failed closing reasoning input: {error}"))
        })?;
        drop(stdin);
        let output = tokio::time::timeout(self.timeout, child.wait_with_output())
            .await
            .map_err(|_| ReasoningError::Backend("reasoning command timed out".to_string()))?
            .map_err(|error| {
                ReasoningError::Backend(format!("reasoning command failed: {error}"))
            })?;
        if !output.status.success() {
            return Err(ReasoningError::Backend(
                "reasoning command exited unsuccessfully; stderr is intentionally not persisted"
                    .to_string(),
            ));
        }
        let value: Value = serde_json::from_slice(&output.stdout).map_err(|error| {
            ReasoningError::InvalidOutput(format!("reasoning command stdout was not JSON: {error}"))
        })?;
        if value.get("output").is_some() {
            return serde_json::from_value(value)
                .map_err(|error| ReasoningError::InvalidOutput(error.to_string()));
        }
        Ok(ReasoningResponse {
            output: value,
            warnings: Vec::new(),
        })
    }

    fn backend_id(&self) -> &str {
        &self.backend_id
    }

    fn model_id(&self) -> &str {
        &self.model_id
    }

    fn capabilities(&self) -> ModelCapabilities {
        ModelCapabilities {
            structured_output: true,
            json_schema: false,
            tool_calling: false,
            streaming: false,
            long_context: false,
            reasoning_control: false,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ScriptedResponse {
    pub task: ReasoningTask,
    pub response: ReasoningResponse,
}

#[derive(Clone, Debug)]
pub struct ScriptedMockReasoningBackend {
    backend_id: String,
    model_id: String,
    responses: Arc<Mutex<VecDeque<ScriptedResponse>>>,
    requests: Arc<Mutex<Vec<ReasoningRequest>>>,
}

impl ScriptedMockReasoningBackend {
    #[must_use]
    pub fn new(responses: Vec<ScriptedResponse>) -> Self {
        Self {
            backend_id: "mock".to_string(),
            model_id: "deterministic".to_string(),
            responses: Arc::new(Mutex::new(VecDeque::from(responses))),
            requests: Arc::new(Mutex::new(Vec::new())),
        }
    }

    #[must_use]
    pub fn requests(&self) -> Arc<Mutex<Vec<ReasoningRequest>>> {
        Arc::clone(&self.requests)
    }

    #[must_use]
    pub fn collection_fixture() -> Self {
        Self::new(vec![
            ScriptedResponse {
                task: ReasoningTask::AnalyzeCapabilities,
                response: ReasoningResponse {
                    output: json!({
                        "persistent_information": true,
                        "structure_discovery": true,
                        "search": false,
                        "record_retrieval": true,
                        "mutation": true,
                        "destructive_actions": true
                    }),
                    warnings: Vec::new(),
                },
            },
            plan_response(
                "Discover accessible workspace structures before selecting a collection.",
                "Which collections are available to this user?",
                "list_collections",
                json!({}),
                Vec::new(),
            ),
            interpretation_response(
                "The target returned two accessible collection descriptors with stable identifiers.",
                "observation:probe-001",
            ),
            plan_response(
                "Sample one observed collection with the minimum useful limit.",
                "What item shape and identifiers occur in an accessible collection?",
                "list_items",
                json!({"collection_id": "projects", "limit": 2}),
                vec![ArgumentProvenance {
                    json_pointer: "/collection_id".to_string(),
                    source: ArgumentSource::Observed {
                        observation_id: "probe-001".to_string(),
                        json_pointer: "/collections/0/id".to_string(),
                    },
                }],
            ),
            interpretation_response(
                "The bounded item sample confirms item identifiers, status values, and an owner reference field.",
                "observation:probe-002",
            ),
            plan_response(
                "Read one observed item to verify the detail shape and collection linkage.",
                "How does an item relate to its collection and nested values?",
                "get_item",
                json!({"collection_id": "projects", "item_id": "project-alpha"}),
                vec![
                    ArgumentProvenance {
                        json_pointer: "/collection_id".to_string(),
                        source: ArgumentSource::Observed {
                            observation_id: "probe-001".to_string(),
                            json_pointer: "/collections/0/id".to_string(),
                        },
                    },
                    ArgumentProvenance {
                        json_pointer: "/item_id".to_string(),
                        source: ArgumentSource::Observed {
                            observation_id: "probe-002".to_string(),
                            json_pointer: "/items/0/id".to_string(),
                        },
                    },
                ],
            ),
            interpretation_response(
                "The detail response confirms an item carries its collection_id and a nested owner object.",
                "observation:probe-003",
            ),
            ScriptedResponse {
                task: ReasoningTask::PlanNextProbe,
                response: ReasoningResponse {
                    output: serde_json::to_value(ProbeDecision {
                        objective: "Stop once the initial read workflow is supported by observed identifiers."
                            .to_string(),
                        unresolved_question: "No further safe probe is required for the initial skill."
                            .to_string(),
                        selected_tool: None,
                        arguments: json!({}),
                        expected_information: String::new(),
                        expected_information_gain: 0.0,
                        confidence: 0.95,
                        alternatives: Vec::new(),
                        argument_provenance: Vec::new(),
                        stop: true,
                        stop_reason: Some("Initial structures and a safe identifier traversal were observed.".to_string()),
                    })
                    .unwrap_or(Value::Null),
                    warnings: Vec::new(),
                },
            },
        ])
    }
}

#[async_trait]
impl ReasoningBackend for ScriptedMockReasoningBackend {
    async fn reason(&self, request: ReasoningRequest) -> Result<ReasoningResponse, ReasoningError> {
        self.requests
            .lock()
            .map_err(|_| ReasoningError::Backend("mock request log lock poisoned".to_string()))?
            .push(request.clone());
        let mut responses = self.responses.lock().map_err(|_| {
            ReasoningError::Backend("mock response queue lock poisoned".to_string())
        })?;
        let Some(scripted) = responses.pop_front() else {
            return Err(ReasoningError::Backend(
                "mock reasoning script was exhausted".to_string(),
            ));
        };
        if scripted.task != request.task {
            return Err(ReasoningError::InvalidOutput(format!(
                "mock script expected task {:?}, received {:?}",
                scripted.task, request.task
            )));
        }
        Ok(scripted.response)
    }

    fn backend_id(&self) -> &str {
        &self.backend_id
    }

    fn model_id(&self) -> &str {
        &self.model_id
    }

    fn capabilities(&self) -> ModelCapabilities {
        ModelCapabilities {
            structured_output: true,
            json_schema: true,
            tool_calling: false,
            streaming: false,
            long_context: false,
            reasoning_control: false,
        }
    }
}

fn plan_response(
    objective: &str,
    unresolved_question: &str,
    tool: &str,
    arguments: Value,
    argument_provenance: Vec<ArgumentProvenance>,
) -> ScriptedResponse {
    ScriptedResponse {
        task: ReasoningTask::PlanNextProbe,
        response: ReasoningResponse {
            output: serde_json::to_value(ProbeDecision {
                objective: objective.to_string(),
                unresolved_question: unresolved_question.to_string(),
                selected_tool: Some(tool.to_string()),
                arguments,
                expected_information:
                    "A bounded structural observation that resolves the stated question."
                        .to_string(),
                expected_information_gain: 0.85,
                confidence: 0.92,
                alternatives: Vec::new(),
                argument_provenance,
                stop: false,
                stop_reason: None,
            })
            .unwrap_or(Value::Null),
            warnings: Vec::new(),
        },
    }
}

fn interpretation_response(claim: &str, source: &str) -> ScriptedResponse {
    ScriptedResponse {
        task: ReasoningTask::InterpretObservation,
        response: ReasoningResponse {
            output: serde_json::to_value(EvidenceClaim::observed(claim, source, 0.95))
                .unwrap_or(Value::Null),
            warnings: Vec::new(),
        },
    }
}
