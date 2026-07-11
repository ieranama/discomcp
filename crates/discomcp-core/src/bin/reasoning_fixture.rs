use std::io::{self, Read};

use discomcp_core::model::{EvidenceClaim, ProbeDecision};
use discomcp_core::reasoning::{ReasoningRequest, ReasoningResponse, ReasoningTask};
use serde_json::{json, Value};

fn main() {
    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .expect("fixture reads stdin");
    let request: ReasoningRequest = serde_json::from_str(&input).expect("fixture receives request");
    let response = match request.task {
        ReasoningTask::AnalyzeCapabilities => ReasoningResponse {
            output: json!({"structure_discovery": true, "record_retrieval": true}),
            warnings: Vec::new(),
        },
        ReasoningTask::PlanNextProbe => plan(&request.context),
        ReasoningTask::InterpretObservation => ReasoningResponse {
            output: serde_json::to_value(EvidenceClaim::observed(
                "The real stdio fixture returned a bounded widget sample.",
                "observation:probe-001",
                0.95,
            ))
            .expect("claim is serializable"),
            warnings: Vec::new(),
        },
        _ => ReasoningResponse {
            output: Value::Object(Default::default()),
            warnings: Vec::new(),
        },
    };
    print!(
        "{}",
        serde_json::to_string(&response).expect("response is serializable")
    );
}

fn plan(context: &Value) -> ReasoningResponse {
    let cycle = context.get("cycle").and_then(Value::as_u64).unwrap_or(0);
    let decision = if cycle == 0 {
        ProbeDecision {
            objective: "Read a bounded widget sample from the real stdio target.".to_string(),
            unresolved_question: "What widget structure is accessible?".to_string(),
            selected_tool: Some("list_widgets".to_string()),
            arguments: json!({"limit": 1}),
            expected_information: "One safe widget sample.".to_string(),
            expected_information_gain: 0.8,
            confidence: 0.9,
            alternatives: Vec::new(),
            argument_provenance: Vec::new(),
            declared_risk: None,
            stop: false,
            stop_reason: None,
        }
    } else {
        ProbeDecision {
            objective: "Stop after the bounded real-target observation.".to_string(),
            unresolved_question: "No additional safe probe is required.".to_string(),
            selected_tool: None,
            arguments: json!({}),
            expected_information: String::new(),
            expected_information_gain: 0.0,
            confidence: 0.9,
            alternatives: Vec::new(),
            argument_provenance: Vec::new(),
            declared_risk: None,
            stop: true,
            stop_reason: Some("The real stdio fixture was profiled safely.".to_string()),
        }
    };
    ReasoningResponse {
        output: serde_json::to_value(decision).expect("decision is serializable"),
        warnings: Vec::new(),
    }
}
