use std::collections::BTreeSet;
use std::time::Duration;

use serde_json::Value;

use crate::mcp::McpClient;
use crate::model::{
    ArgumentSource, CataloguedTool, ExplorationBudgets, NormalizedObservation, ProbeDecision,
    RiskClass, RuntimeDecision, RuntimeOutcome, ToolCatalogue,
};

#[derive(Clone, Debug, Default)]
pub struct RuntimeBudget {
    pub probes_executed: u32,
}

#[derive(Clone, Debug)]
pub struct ProbeExecution {
    pub risk: RiskClass,
    pub runtime_decision: RuntimeDecision,
    pub response: Option<Value>,
}

pub struct SafeProbeRequest<'a> {
    pub client: &'a dyn McpClient,
    pub catalogue: &'a ToolCatalogue,
    pub decision: &'a ProbeDecision,
    pub candidate_tools: &'a [String],
    pub observations: &'a [NormalizedObservation],
    pub budgets: &'a ExplorationBudgets,
    pub budget: &'a mut RuntimeBudget,
    pub policy: &'a SafetyPolicy,
    pub dry_run: bool,
}

#[derive(Clone, Debug, Default)]
pub struct SafetyPolicy {
    pub allow_sensitive_reads: bool,
}

impl SafetyPolicy {
    #[must_use]
    pub fn classify_tool(&self, tool: &crate::model::RawTool) -> RiskClass {
        classify_tool(tool)
    }

    #[must_use]
    pub fn permits(&self, risk: &RiskClass) -> bool {
        risk.is_allowed_during_onboarding()
            || (*risk == RiskClass::SensitiveRead && self.allow_sensitive_reads)
    }
}

#[must_use]
pub fn classify_tool(tool: &crate::model::RawTool) -> RiskClass {
    let annotation = &tool.annotations;
    if annotation
        .get("discomcp.risk")
        .and_then(Value::as_str)
        .and_then(parse_risk)
        .is_some()
    {
        // The checked parse cannot fail after `is_some`.
        return parse_risk(
            annotation
                .get("discomcp.risk")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        )
        .unwrap_or(RiskClass::Unknown);
    }
    if annotation
        .get("destructiveHint")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return RiskClass::Destructive;
    }

    let text = format!(
        "{} {} {} {}",
        tool.name,
        tool.description,
        tool.input_schema,
        tool.output_schema
            .as_ref()
            .map_or_else(String::new, Value::to_string)
    )
    .to_ascii_lowercase();

    if contains_any(
        &text,
        &[
            "arbitrary code",
            "execute code",
            "run code",
            "shell command",
            "command execution",
            "execute sql",
            "sql statement",
        ],
    ) {
        return RiskClass::ArbitraryExecution;
    }
    if contains_any(
        &text,
        &[
            "permanently delete",
            "destructive",
            "delete",
            "destroy",
            "purge",
            "wipe",
        ],
    ) {
        return RiskClass::Destructive;
    }
    if contains_any(
        &text,
        &[
            "admin",
            // A bare "permission" also appears in read-only metadata descriptions
            // ("returns size, permissions, type"), so require an administrative act.
            "permission settings",
            "manage permission",
            "change permission",
            "grant permission",
            "set permission",
            "revoke permission",
            "credential",
            "api key",
            "access control",
            "role assignment",
        ],
    ) {
        return RiskClass::Administrative;
    }
    if contains_any(
        &text,
        &[
            "send message",
            "send email",
            "publish",
            "webhook",
            "external side effect",
            "notify",
        ],
    ) {
        return RiskClass::ExternalSideEffect;
    }
    if contains_any(
        &text,
        &[
            "creates", "create ", "updates", "update ", "modifies", "modify ", "writes", "write ",
            "patch", "rename", "move ", "archive",
        ],
    ) {
        return RiskClass::Mutation;
    }
    if contains_any(
        &text,
        &[
            "calculate",
            "calculation",
            "transform",
            "convert",
            "parse payload",
            "pure computation",
        ],
    ) && contains_any(
        &text,
        &["harmless", "deterministic", "no side effect", "read-only"],
    ) {
        return RiskClass::PureComputation;
    }

    // Real-world MCP tools rarely declare readOnlyHint; a read-verb segment at
    // the start (list_datasets, get_table_info) or end (calendar_events_list,
    // gmail_users_getProfile) is the de-facto convention.
    let name = tool.name.to_ascii_lowercase();
    // Case is load-bearing in the last segment: `getProfile` is a read verb,
    // `getaway` / `listen` / `viewer` are not.
    let last_segment = tool.name.rsplit(['_', '-']).next().unwrap_or_default();
    let read_verb_name = ["list", "get", "read", "describe", "fetch", "show", "view"]
        .iter()
        .any(|verb| {
            name == *verb
                || name.starts_with(&format!("{verb}_"))
                || name.starts_with(&format!("{verb}-"))
                || last_segment.eq_ignore_ascii_case(verb)
                || last_segment.strip_prefix(*verb).is_some_and(|rest| {
                    rest.starts_with(|character: char| character.is_ascii_uppercase())
                })
        });
    let read_only_declared = annotation
        .get("readOnlyHint")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || read_verb_name
        || contains_any(
            &text,
            &[
                "read-only",
                "read only",
                "does not modify",
                "retrieves",
                "returns",
                "lists",
            ],
        );
    if !read_only_declared {
        return RiskClass::Unknown;
    }
    if contains_any(
        &text,
        &[
            "private",
            "sensitive",
            "message content",
            "personal data",
            "email address",
        ],
    ) {
        return RiskClass::SensitiveRead;
    }
    if has_sampling_property(&tool.input_schema)
        || contains_any(&text, &["bounded", "filter", "query", "search"])
    {
        return RiskClass::ConstrainedRead;
    }
    RiskClass::SafeRead
}

fn parse_risk(value: &str) -> Option<RiskClass> {
    match value {
        "safe_read" => Some(RiskClass::SafeRead),
        "constrained_read" => Some(RiskClass::ConstrainedRead),
        "sensitive_read" => Some(RiskClass::SensitiveRead),
        "pure_computation" => Some(RiskClass::PureComputation),
        "mutation" => Some(RiskClass::Mutation),
        "external_side_effect" => Some(RiskClass::ExternalSideEffect),
        "destructive" => Some(RiskClass::Destructive),
        "administrative" => Some(RiskClass::Administrative),
        "arbitrary_execution" => Some(RiskClass::ArbitraryExecution),
        "unknown" => Some(RiskClass::Unknown),
        _ => None,
    }
}

fn contains_any(text: &str, patterns: &[&str]) -> bool {
    patterns.iter().any(|pattern| text.contains(pattern))
}

pub fn validate_json_schema(schema: &Value, value: &Value) -> Result<(), String> {
    validate_schema_at(schema, value, "")
}

fn validate_schema_at(schema: &Value, value: &Value, pointer: &str) -> Result<(), String> {
    if schema.is_null() || schema.as_object().is_none_or(|object| object.is_empty()) {
        return Ok(());
    }
    if let Some(alternatives) = schema.get("oneOf").and_then(Value::as_array) {
        if alternatives
            .iter()
            .any(|candidate| validate_schema_at(candidate, value, pointer).is_ok())
        {
            return Ok(());
        }
        return Err(format!(
            "{pointer}: value does not satisfy any oneOf schema"
        ));
    }
    if let Some(values) = schema.get("enum").and_then(Value::as_array) {
        if !values.iter().any(|candidate| candidate == value) {
            return Err(format!(
                "{pointer}: value is not one of the declared enum values"
            ));
        }
    }
    if let Some(expected_type) = schema.get("type") {
        let matches_type = match expected_type {
            Value::String(kind) => matches_json_type(kind, value),
            Value::Array(kinds) => kinds
                .iter()
                .filter_map(Value::as_str)
                .any(|kind| matches_json_type(kind, value)),
            _ => true,
        };
        if !matches_type {
            return Err(format!(
                "{pointer}: value does not match the declared JSON Schema type"
            ));
        }
    }

    if let Some(object) = value.as_object() {
        if let Some(required) = schema.get("required").and_then(Value::as_array) {
            for key in required.iter().filter_map(Value::as_str) {
                if !object.contains_key(key) {
                    return Err(format!("{pointer}: missing required argument `{key}`"));
                }
            }
        }
        let properties = schema
            .get("properties")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        if schema
            .get("additionalProperties")
            .and_then(Value::as_bool)
            .is_some_and(|allowed| !allowed)
        {
            for key in object.keys() {
                if !properties.contains_key(key) {
                    return Err(format!("{pointer}: unexpected argument `{key}`"));
                }
            }
        }
        for (key, child) in object {
            if let Some(child_schema) = properties.get(key) {
                validate_schema_at(child_schema, child, &format!("{pointer}/{key}"))?;
            }
        }
    }
    if let Some(array) = value.as_array() {
        if let Some(item_schema) = schema.get("items") {
            for (index, child) in array.iter().enumerate() {
                validate_schema_at(item_schema, child, &format!("{pointer}/{index}"))?;
            }
        }
    }
    if let Some(number) = value.as_f64() {
        if let Some(minimum) = schema.get("minimum").and_then(Value::as_f64) {
            if number < minimum {
                return Err(format!("{pointer}: value is below the minimum"));
            }
        }
        if let Some(maximum) = schema.get("maximum").and_then(Value::as_f64) {
            if number > maximum {
                return Err(format!("{pointer}: value is above the maximum"));
            }
        }
    }
    if let Some(string) = value.as_str() {
        if let Some(minimum) = schema.get("minLength").and_then(Value::as_u64) {
            if string.chars().count() < minimum as usize {
                return Err(format!("{pointer}: string is shorter than minLength"));
            }
        }
    }
    Ok(())
}

fn matches_json_type(kind: &str, value: &Value) -> bool {
    match kind {
        "object" => value.is_object(),
        "array" => value.is_array(),
        "string" => value.is_string(),
        "number" => value.is_number(),
        "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
        "boolean" => value.is_boolean(),
        "null" => value.is_null(),
        _ => true,
    }
}

pub async fn execute_safe_probe(request: SafeProbeRequest<'_>) -> ProbeExecution {
    let SafeProbeRequest {
        client,
        catalogue,
        decision,
        candidate_tools,
        observations,
        budgets,
        budget,
        policy,
        dry_run,
    } = request;
    let Some(selected_tool) = decision.selected_tool.as_deref() else {
        return rejected(RiskClass::Unknown, "probe did not select a tool");
    };
    if !candidate_tools
        .iter()
        .any(|candidate| candidate == selected_tool)
    {
        return rejected(
            RiskClass::Unknown,
            "selected tool is outside the retrieved catalogue subset",
        );
    }
    let Some(tool) = catalogue
        .tools
        .iter()
        .find(|candidate| candidate.raw.name == selected_tool)
    else {
        return rejected(
            RiskClass::Unknown,
            "selected tool does not exist in the cached catalogue",
        );
    };
    let risk = tool.card.risk.clone();
    if !policy.permits(&risk) {
        return rejected(risk, "risk policy forbids this tool during onboarding");
    }
    if budget.probes_executed >= budgets.max_mcp_probes {
        return rejected(risk, "MCP probe budget is exhausted");
    }
    if let Err(reason) = validate_json_schema(&tool.raw.input_schema, &decision.arguments) {
        return rejected(
            risk,
            &format!("arguments fail the target input schema: {reason}"),
        );
    }
    if let Err(reason) = validate_identifier_provenance(tool, decision, observations) {
        return rejected(risk, &reason);
    }
    if let Err(reason) = validate_sampling_limits(tool, &decision.arguments, budgets) {
        return rejected(risk, &reason);
    }
    if dry_run {
        return ProbeExecution {
            risk,
            runtime_decision: RuntimeDecision {
                outcome: RuntimeOutcome::Skipped,
                reason: "dry-run: probe passed validation but was not sent to the target MCP"
                    .to_string(),
            },
            response: None,
        };
    }

    budget.probes_executed += 1;
    let call = client.call_tool(selected_tool, decision.arguments.clone());
    let response = match tokio::time::timeout(
        Duration::from_millis(budgets.per_call_timeout_ms),
        call,
    )
    .await
    {
        Err(_) => {
            return ProbeExecution {
                risk,
                runtime_decision: RuntimeDecision {
                    outcome: RuntimeOutcome::Failed,
                    reason: "target MCP call exceeded the configured timeout".to_string(),
                },
                response: None,
            };
        }
        Ok(Err(_error)) => {
            return ProbeExecution {
                risk,
                runtime_decision: RuntimeDecision {
                    outcome: RuntimeOutcome::Failed,
                    reason: "target MCP call failed; raw error is intentionally not persisted"
                        .to_string(),
                },
                response: None,
            };
        }
        Ok(Ok(value)) => value,
    };
    match serde_json::to_vec(&response) {
        Ok(bytes) if bytes.len() <= budgets.max_response_bytes => ProbeExecution {
            risk,
            runtime_decision: RuntimeDecision {
                outcome: RuntimeOutcome::Accepted,
                reason: "probe passed schema, provenance, policy, budget, and response-size checks"
                    .to_string(),
            },
            response: Some(response),
        },
        Ok(_) => ProbeExecution {
            risk,
            runtime_decision: RuntimeDecision {
                outcome: RuntimeOutcome::Failed,
                reason:
                    "target response exceeded the configured response-size limit and was discarded"
                        .to_string(),
            },
            response: None,
        },
        Err(_) => ProbeExecution {
            risk,
            runtime_decision: RuntimeDecision {
                outcome: RuntimeOutcome::Failed,
                reason: "target response could not be serialized safely".to_string(),
            },
            response: None,
        },
    }
}

fn rejected(risk: RiskClass, reason: &str) -> ProbeExecution {
    ProbeExecution {
        risk,
        runtime_decision: RuntimeDecision {
            outcome: RuntimeOutcome::Rejected,
            reason: reason.to_string(),
        },
        response: None,
    }
}

fn validate_identifier_provenance(
    tool: &CataloguedTool,
    decision: &ProbeDecision,
    observations: &[NormalizedObservation],
) -> Result<(), String> {
    let Some(arguments) = decision.arguments.as_object() else {
        return Ok(());
    };
    let available: BTreeSet<(&str, &str, &str)> = observations
        .iter()
        .flat_map(|observation| {
            observation.identifiers.iter().map(|identifier| {
                (
                    observation.id.as_str(),
                    identifier.json_pointer.as_str(),
                    identifier.value.as_str(),
                )
            })
        })
        .collect();

    for (key, value) in arguments {
        if !is_identifier_key(key) || value.as_str().is_none_or(str::is_empty) {
            continue;
        }
        let pointer = format!("/{key}");
        let provenance = decision
            .argument_provenance
            .iter()
            .find(|provenance| provenance.json_pointer == pointer)
            .ok_or_else(|| {
                format!(
                    "identifier argument `{key}` has no provenance; identifiers may not be invented"
                )
            })?;
        match &provenance.source {
            ArgumentSource::Observed {
                observation_id,
                json_pointer,
            } => {
                let value = value.as_str().unwrap_or_default();
                if !available.contains(&(observation_id, json_pointer, value)) {
                    return Err(format!(
                        "identifier argument `{key}` does not match the claimed observed source"
                    ));
                }
            }
            ArgumentSource::UserDefined => {}
            ArgumentSource::Enum { schema_pointer } => {
                let enum_values = tool
                    .raw
                    .input_schema
                    .pointer(schema_pointer)
                    .and_then(|schema| schema.get("enum"))
                    .and_then(Value::as_array)
                    .ok_or_else(|| {
                        format!("identifier argument `{key}` claims a non-enum schema source")
                    })?;
                if !enum_values.iter().any(|candidate| candidate == value) {
                    return Err(format!(
                        "identifier argument `{key}` is not in the declared enum"
                    ));
                }
            }
            ArgumentSource::SchemaDefault { .. } | ArgumentSource::UserGoal => {
                return Err(format!(
                    "identifier argument `{key}` must come from an observation, declared enum, or explicit user input"
                ));
            }
        }
    }
    Ok(())
}

fn validate_sampling_limits(
    tool: &CataloguedTool,
    arguments: &Value,
    budgets: &ExplorationBudgets,
) -> Result<(), String> {
    let Some(arguments) = arguments.as_object() else {
        return Ok(());
    };
    for &key in sampling_keys() {
        if let Some(value) = arguments.get(key) {
            if value
                .as_u64()
                .is_none_or(|number| number > u64::from(budgets.max_samples_per_structure))
            {
                return Err(format!(
                    "sampling argument `{key}` exceeds the configured sample limit of {}",
                    budgets.max_samples_per_structure
                ));
            }
        }
    }
    let is_bounded_reader = matches!(
        tool.card.risk,
        RiskClass::ConstrainedRead | RiskClass::SensitiveRead
    ) && has_sampling_property(&tool.raw.input_schema);
    if is_bounded_reader
        && !sampling_keys()
            .iter()
            .any(|key| arguments.contains_key(*key))
    {
        return Err("bounded read tool requires an explicit sampling argument".to_string());
    }
    Ok(())
}

fn sampling_keys() -> &'static [&'static str] {
    &["limit", "page_size", "pageSize", "count", "first", "take"]
}

fn has_sampling_property(schema: &Value) -> bool {
    schema
        .get("properties")
        .and_then(Value::as_object)
        .is_some_and(|properties| {
            sampling_keys()
                .iter()
                .any(|key| properties.contains_key(*key))
        })
}

/// The provenance rule must cover exactly the keys the normalizer records as
/// observed identifiers, or an agent could invent one the runtime never checks.
fn is_identifier_key(key: &str) -> bool {
    crate::normalization::is_identifier_name(key)
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, VecDeque};
    use std::time::Duration;

    use async_trait::async_trait;
    use serde_json::json;

    use super::*;
    use crate::catalogue::build_catalogue;
    use crate::mcp::{McpClient, McpError, MockMcpClient};
    use crate::model::{
        ArgumentProvenance, EvidenceClaim, NormalizedObservation, ObservedIdentifier, RawPrompt,
        RawResource, RawTool, ServerHandshake,
    };

    fn tool(name: &str, description: &str, schema: serde_json::Value) -> RawTool {
        RawTool {
            name: name.to_string(),
            description: description.to_string(),
            input_schema: schema,
            output_schema: None,
            annotations: json!({}),
        }
    }

    fn decision(name: &str, arguments: serde_json::Value) -> ProbeDecision {
        ProbeDecision {
            objective: "test probe".to_string(),
            unresolved_question: "test".to_string(),
            selected_tool: Some(name.to_string()),
            arguments,
            expected_information: String::new(),
            expected_information_gain: 1.0,
            confidence: 1.0,
            alternatives: Vec::new(),
            argument_provenance: Vec::new(),
            stop: false,
            stop_reason: None,
        }
    }

    fn client_for(raw_tool: RawTool, response: serde_json::Value) -> MockMcpClient {
        let name = raw_tool.name.clone();
        MockMcpClient::new(
            ServerHandshake::default(),
            vec![raw_tool],
            Vec::new(),
            Vec::new(),
            BTreeMap::from([(name, VecDeque::from([Ok(response)]))]),
        )
    }

    async fn execute(
        client: &MockMcpClient,
        catalogue: &ToolCatalogue,
        probe: &ProbeDecision,
        budgets: &ExplorationBudgets,
    ) -> ProbeExecution {
        let mut budget = RuntimeBudget::default();
        let policy = SafetyPolicy::default();
        let candidates = [probe.selected_tool.clone().unwrap_or_default()];
        execute_safe_probe(SafeProbeRequest {
            client,
            catalogue,
            decision: probe,
            candidate_tools: &candidates,
            observations: &[],
            budgets,
            budget: &mut budget,
            policy: &policy,
            dry_run: false,
        })
        .await
    }

    fn fixture_tool() -> RawTool {
        RawTool {
            name: "get_value".to_string(),
            description: "Returns one value by an observed value_id. Read-only.".to_string(),
            input_schema: json!({
                "type": "object",
                "required": ["value_id"],
                "properties": {"value_id": {"type": "string"}},
                "additionalProperties": false
            }),
            output_schema: None,
            annotations: json!({"readOnlyHint": true}),
        }
    }

    #[tokio::test]
    async fn invented_identifier_is_rejected_before_client_call() {
        let tool = fixture_tool();
        let catalogue = build_catalogue(vec![tool.clone()], Vec::new(), Vec::new());
        let client = MockMcpClient::new(
            Default::default(),
            vec![tool],
            Vec::new(),
            Vec::new(),
            BTreeMap::from([("get_value".to_string(), VecDeque::from([Ok(json!({}))]))]),
        );
        let decision = ProbeDecision {
            objective: "read".to_string(),
            unresolved_question: "id".to_string(),
            selected_tool: Some("get_value".to_string()),
            arguments: json!({"value_id": "invented"}),
            expected_information: String::new(),
            expected_information_gain: 1.0,
            confidence: 1.0,
            alternatives: Vec::new(),
            argument_provenance: Vec::new(),
            stop: false,
            stop_reason: None,
        };
        let mut budget = RuntimeBudget::default();
        let budgets = ExplorationBudgets::for_mode(&crate::model::ExplorationMode::Quick);
        let policy = SafetyPolicy::default();
        let candidates = ["get_value".to_string()];
        let result = execute_safe_probe(SafeProbeRequest {
            client: &client,
            catalogue: &catalogue,
            decision: &decision,
            candidate_tools: &candidates,
            observations: &[],
            budgets: &budgets,
            budget: &mut budget,
            policy: &policy,
            dry_run: false,
        })
        .await;
        assert_eq!(result.runtime_decision.outcome, RuntimeOutcome::Rejected);
        assert!(client.calls().lock().expect("lock").is_empty());
    }

    #[tokio::test]
    async fn observed_identifier_is_accepted() {
        let tool = fixture_tool();
        let catalogue = build_catalogue(vec![tool.clone()], Vec::new(), Vec::new());
        let client = MockMcpClient::new(
            Default::default(),
            vec![tool],
            Vec::new(),
            Vec::new(),
            BTreeMap::from([(
                "get_value".to_string(),
                VecDeque::from([Ok(json!({"ok": true}))]),
            )]),
        );
        let observation = NormalizedObservation {
            id: "probe-001".to_string(),
            tool: "list_values".to_string(),
            arguments: json!({}),
            shape: json!({}),
            observed_enum_values: BTreeMap::new(),
            identifiers: vec![ObservedIdentifier {
                name: "value_id".to_string(),
                value: "value-1".to_string(),
                observation_id: "probe-001".to_string(),
                json_pointer: "/values/0/value_id".to_string(),
                evidence: EvidenceClaim::observed("id", "observation:probe-001", 1.0),
            }],
            sample: json!({}),
            fingerprint: String::new(),
        };
        let decision = ProbeDecision {
            objective: "read".to_string(),
            unresolved_question: "id".to_string(),
            selected_tool: Some("get_value".to_string()),
            arguments: json!({"value_id": "value-1"}),
            expected_information: String::new(),
            expected_information_gain: 1.0,
            confidence: 1.0,
            alternatives: Vec::new(),
            argument_provenance: vec![ArgumentProvenance {
                json_pointer: "/value_id".to_string(),
                source: ArgumentSource::Observed {
                    observation_id: "probe-001".to_string(),
                    json_pointer: "/values/0/value_id".to_string(),
                },
            }],
            stop: false,
            stop_reason: None,
        };
        let mut budget = RuntimeBudget::default();
        let budgets = ExplorationBudgets::for_mode(&crate::model::ExplorationMode::Quick);
        let policy = SafetyPolicy::default();
        let candidates = ["get_value".to_string()];
        let observations = [observation];
        let result = execute_safe_probe(SafeProbeRequest {
            client: &client,
            catalogue: &catalogue,
            decision: &decision,
            candidate_tools: &candidates,
            observations: &observations,
            budgets: &budgets,
            budget: &mut budget,
            policy: &policy,
            dry_run: false,
        })
        .await;
        assert_eq!(result.runtime_decision.outcome, RuntimeOutcome::Accepted);
        assert_eq!(client.calls().lock().expect("lock").len(), 1);
    }

    #[tokio::test]
    async fn every_disallowed_risk_class_is_blocked_before_execution() {
        let cases = [
            ("create", "Creates a persistent item.", RiskClass::Mutation),
            (
                "send",
                "Send message to an external recipient.",
                RiskClass::ExternalSideEffect,
            ),
            (
                "delete",
                "Permanently delete an item.",
                RiskClass::Destructive,
            ),
            (
                "roles",
                "Change role permission settings.",
                RiskClass::Administrative,
            ),
            (
                "code",
                "Execute arbitrary code from an input.",
                RiskClass::ArbitraryExecution,
            ),
            (
                "mystery",
                "Processes an opaque payload.",
                RiskClass::Unknown,
            ),
        ];
        for (name, description, expected_risk) in cases {
            let raw_tool = tool(name, description, json!({"type": "object"}));
            let catalogue = build_catalogue(vec![raw_tool.clone()], Vec::new(), Vec::new());
            assert_eq!(catalogue.tools[0].card.risk, expected_risk);
            let client = client_for(raw_tool, json!({"called": true}));
            let result = execute(
                &client,
                &catalogue,
                &decision(name, json!({})),
                &ExplorationBudgets::for_mode(&crate::model::ExplorationMode::Quick),
            )
            .await;
            assert_eq!(result.runtime_decision.outcome, RuntimeOutcome::Rejected);
            assert!(client.calls().lock().expect("lock").is_empty());
        }
    }

    #[tokio::test]
    async fn schema_and_sample_limits_are_rejected_before_execution() {
        let schema_tool = tool(
            "read_value",
            "Returns a value in a read-only operation.",
            json!({
                "type": "object",
                "required": ["query"],
                "properties": {"query": {"type": "string"}},
                "additionalProperties": false
            }),
        );
        let catalogue = build_catalogue(vec![schema_tool.clone()], Vec::new(), Vec::new());
        let client = client_for(schema_tool, json!({"called": true}));
        let result = execute(
            &client,
            &catalogue,
            &decision("read_value", json!({})),
            &ExplorationBudgets::for_mode(&crate::model::ExplorationMode::Quick),
        )
        .await;
        assert_eq!(result.runtime_decision.outcome, RuntimeOutcome::Rejected);
        assert!(client.calls().lock().expect("lock").is_empty());

        let list_tool = tool(
            "list_values",
            "Lists a bounded read-only sample.",
            json!({
                "type": "object",
                "required": ["limit"],
                "properties": {"limit": {"type": "integer", "minimum": 1}},
                "additionalProperties": false
            }),
        );
        let catalogue = build_catalogue(vec![list_tool.clone()], Vec::new(), Vec::new());
        let client = client_for(list_tool, json!({"called": true}));
        let result = execute(
            &client,
            &catalogue,
            &decision("list_values", json!({"limit": 3})),
            &ExplorationBudgets::for_mode(&crate::model::ExplorationMode::Quick),
        )
        .await;
        assert_eq!(result.runtime_decision.outcome, RuntimeOutcome::Rejected);
        assert!(client.calls().lock().expect("lock").is_empty());
    }

    #[tokio::test]
    async fn oversized_response_is_discarded_after_target_execution() {
        let raw_tool = tool(
            "read_value",
            "Returns a read-only value.",
            json!({"type": "object"}),
        );
        let catalogue = build_catalogue(vec![raw_tool.clone()], Vec::new(), Vec::new());
        let client = client_for(
            raw_tool,
            json!({"value": "this response is larger than ten bytes"}),
        );
        let mut budgets = ExplorationBudgets::for_mode(&crate::model::ExplorationMode::Quick);
        budgets.max_response_bytes = 10;
        let result = execute(
            &client,
            &catalogue,
            &decision("read_value", json!({})),
            &budgets,
        )
        .await;
        assert_eq!(result.runtime_decision.outcome, RuntimeOutcome::Failed);
        assert!(result.response.is_none());
        assert_eq!(client.calls().lock().expect("lock").len(), 1);
    }

    struct SlowClient;

    #[async_trait]
    impl McpClient for SlowClient {
        async fn initialize(&mut self) -> Result<ServerHandshake, McpError> {
            Ok(ServerHandshake::default())
        }

        async fn list_tools(&self) -> Result<Vec<RawTool>, McpError> {
            Ok(Vec::new())
        }

        async fn list_resources(&self) -> Result<Vec<RawResource>, McpError> {
            Ok(Vec::new())
        }

        async fn list_prompts(&self) -> Result<Vec<RawPrompt>, McpError> {
            Ok(Vec::new())
        }

        async fn call_tool(
            &self,
            _name: &str,
            _arguments: serde_json::Value,
        ) -> Result<serde_json::Value, McpError> {
            tokio::time::sleep(Duration::from_millis(25)).await;
            Ok(json!({"late": true}))
        }

        async fn read_resource(&self, _uri: &str) -> Result<Option<serde_json::Value>, McpError> {
            Ok(None)
        }

        async fn get_prompt(
            &self,
            _name: &str,
            _arguments: Option<serde_json::Value>,
        ) -> Result<Option<serde_json::Value>, McpError> {
            Ok(None)
        }
    }

    #[tokio::test]
    async fn timeout_is_enforced() {
        let raw_tool = tool(
            "read_value",
            "Returns a read-only value.",
            json!({"type": "object"}),
        );
        let catalogue = build_catalogue(vec![raw_tool], Vec::new(), Vec::new());
        let mut budgets = ExplorationBudgets::for_mode(&crate::model::ExplorationMode::Quick);
        budgets.per_call_timeout_ms = 1;
        let probe = decision("read_value", json!({}));
        let candidates = ["read_value".to_string()];
        let policy = SafetyPolicy::default();
        let mut budget = RuntimeBudget::default();
        let result = execute_safe_probe(SafeProbeRequest {
            client: &SlowClient,
            catalogue: &catalogue,
            decision: &probe,
            candidate_tools: &candidates,
            observations: &[],
            budgets: &budgets,
            budget: &mut budget,
            policy: &policy,
            dry_run: false,
        })
        .await;
        assert_eq!(result.runtime_decision.outcome, RuntimeOutcome::Failed);
    }

    #[test]
    fn terse_real_world_tools_classify_by_name_prefix() {
        let schema = json!({"type": "object"});
        // Google genai-toolbox style: terse descriptions, no annotations.
        let cases = [
            ("list_dataset_ids", "Use this tool to list datasets."),
            ("get_table_info", "Use this tool to get table metadata."),
            ("describe_collection", "Field metadata for one collection."),
            // Google-API style: the verb is the last name segment.
            ("calendar_events_list", "Calendar events."),
            ("gmail_users_getProfile", "Current user's Gmail profile."),
        ];
        for (name, description) in cases {
            let risk = classify_tool(&tool(name, description, schema.clone()));
            assert!(
                matches!(risk, RiskClass::SafeRead | RiskClass::ConstrainedRead),
                "{name} classified as {risk:?}"
            );
        }
        assert_eq!(
            classify_tool(&tool(
                "execute_sql",
                "Use this tool to execute sql statement.",
                schema.clone(),
            )),
            RiskClass::ArbitraryExecution
        );
        // Dangerous keywords still win over a read-verb name prefix.
        assert_eq!(
            classify_tool(&tool(
                "get_credentials",
                "Returns the stored credential for a user.",
                schema.clone(),
            )),
            RiskClass::Administrative
        );
        // ...but merely *returning* permissions is a read, not an administrative act.
        assert_eq!(
            classify_tool(&tool(
                "get_file_info",
                "Retrieve detailed metadata about a file or directory. Returns size, \
                 creation time, last modified time, permissions, and type.",
                schema.clone(),
            )),
            RiskClass::SafeRead
        );
        // A read verb is a whole segment, not any prefix of one.
        for name in ["getaway", "listen", "viewer"] {
            assert_eq!(
                classify_tool(&tool(name, "Processes an opaque payload.", schema.clone())),
                RiskClass::Unknown,
                "{name} must not be read-classified by a prefix match"
            );
        }
    }

    #[tokio::test]
    async fn camel_case_identifier_arguments_require_provenance() {
        let raw_tool = tool(
            "calendar_events_list",
            "Lists calendar events.",
            json!({
                "type": "object",
                "properties": {"calendarId": {"type": "string"}}
            }),
        );
        let catalogue = build_catalogue(vec![raw_tool.clone()], Vec::new(), Vec::new());
        let client = client_for(raw_tool, json!({"called": true}));
        let result = execute(
            &client,
            &catalogue,
            &decision("calendar_events_list", json!({"calendarId": "invented"})),
            &ExplorationBudgets::for_mode(&crate::model::ExplorationMode::Quick),
        )
        .await;
        assert_eq!(result.runtime_decision.outcome, RuntimeOutcome::Rejected);
        assert!(client.calls().lock().expect("lock").is_empty());
    }
}
