use std::collections::BTreeMap;

use serde_json::{Map, Value};

use crate::catalogue::fingerprint;
use crate::model::{EvidenceClaim, ExplorationBudgets, NormalizedObservation, ObservedIdentifier};

#[must_use]
pub fn normalize_observation(
    id: String,
    tool: String,
    arguments: Value,
    redacted_response: &Value,
    budgets: &ExplorationBudgets,
) -> NormalizedObservation {
    let mut enum_values = BTreeMap::new();
    let mut identifiers = Vec::new();
    collect_facts(
        redacted_response,
        "",
        &id,
        0,
        budgets.max_traversal_depth,
        &mut enum_values,
        &mut identifiers,
    );
    let sample = bounded_sample(
        redacted_response,
        budgets.max_samples_per_structure as usize,
        0,
        budgets.max_traversal_depth,
    );
    NormalizedObservation {
        id: id.clone(),
        tool: tool.clone(),
        arguments,
        shape: shape_summary(redacted_response, 0, budgets.max_traversal_depth),
        observed_enum_values: enum_values,
        identifiers,
        sample,
        fingerprint: fingerprint(redacted_response),
    }
}

fn shape_summary(value: &Value, depth: u32, max_depth: u32) -> Value {
    if depth >= max_depth {
        return Value::String("truncated".to_string());
    }
    match value {
        Value::Object(object) => Value::Object(
            object
                .iter()
                .map(|(key, child)| (key.clone(), shape_summary(child, depth + 1, max_depth)))
                .collect(),
        ),
        Value::Array(items) => {
            let item_shape = items.first().map_or_else(
                || Value::String("unknown".to_string()),
                |item| shape_summary(item, depth + 1, max_depth),
            );
            serde_json::json!({"type": "array", "items": item_shape})
        }
        Value::String(_) => Value::String("string".to_string()),
        Value::Number(number) if number.is_i64() || number.is_u64() => {
            Value::String("integer".to_string())
        }
        Value::Number(_) => Value::String("number".to_string()),
        Value::Bool(_) => Value::String("boolean".to_string()),
        Value::Null => Value::String("null".to_string()),
    }
}

fn bounded_sample(value: &Value, limit: usize, depth: u32, max_depth: u32) -> Value {
    match value {
        Value::String(_) | Value::Number(_) | Value::Bool(_) | Value::Null => value.clone(),
        Value::Object(object) => Value::Object(
            object
                .iter()
                .map(|(key, child)| {
                    let child = if depth >= max_depth && (child.is_object() || child.is_array()) {
                        Value::String("[TRAVERSAL_LIMIT]".to_string())
                    } else {
                        bounded_sample(child, limit, depth + 1, max_depth)
                    };
                    (key.clone(), child)
                })
                .collect::<Map<_, _>>(),
        ),
        Value::Array(items) => Value::Array(
            items
                .iter()
                .take(limit)
                .map(|child| {
                    if depth >= max_depth && (child.is_object() || child.is_array()) {
                        Value::String("[TRAVERSAL_LIMIT]".to_string())
                    } else {
                        bounded_sample(child, limit, depth + 1, max_depth)
                    }
                })
                .collect(),
        ),
    }
}

fn collect_facts(
    value: &Value,
    pointer: &str,
    observation_id: &str,
    depth: u32,
    max_depth: u32,
    enum_values: &mut BTreeMap<String, Vec<String>>,
    identifiers: &mut Vec<ObservedIdentifier>,
) {
    if depth > max_depth {
        return;
    }
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                let child_pointer = format!("{pointer}/{}", escape_pointer(key));
                if is_identifier_name(key) {
                    if let Some(string) = scalar_string(child) {
                        if !string.starts_with("[REDACTED") {
                            identifiers.push(ObservedIdentifier {
                                name: key.clone(),
                                value: string,
                                observation_id: observation_id.to_string(),
                                json_pointer: child_pointer.clone(),
                                evidence: EvidenceClaim::observed(
                                    format!("`{key}` was returned by the target MCP"),
                                    format!("observation:{observation_id}{child_pointer}"),
                                    1.0,
                                ),
                            });
                        }
                    }
                }
                if should_collect_enum(key, child) {
                    let values = enum_values.entry(key.clone()).or_default();
                    let candidate = scalar_string(child).unwrap_or_default();
                    if !candidate.is_empty() && !values.contains(&candidate) && values.len() < 10 {
                        values.push(candidate);
                    }
                }
                collect_facts(
                    child,
                    &child_pointer,
                    observation_id,
                    depth + 1,
                    max_depth,
                    enum_values,
                    identifiers,
                );
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                collect_facts(
                    child,
                    &format!("{pointer}/{index}"),
                    observation_id,
                    depth + 1,
                    max_depth,
                    enum_values,
                    identifiers,
                );
            }
        }
        _ => {}
    }
}

fn scalar_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
}

fn should_collect_enum(key: &str, value: &Value) -> bool {
    !is_identifier_name(key)
        && !matches!(
            key.to_ascii_lowercase().as_str(),
            "name" | "title" | "description" | "display_name"
        )
        && matches!(value, Value::String(_) | Value::Number(_) | Value::Bool(_))
}

fn is_identifier_name(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    value == "id"
        || value.ends_with("_id")
        || value.ends_with("-id")
        || value.contains("identifier")
        || value.ends_with("_uri")
}

fn escape_pointer(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::model::ExplorationMode;

    #[test]
    fn normalizer_enforces_array_sample_limit_and_collects_ids() {
        let budgets = ExplorationBudgets::for_mode(&ExplorationMode::Quick);
        let observation = normalize_observation(
            "probe-1".to_string(),
            "list".to_string(),
            json!({}),
            &json!({"items": [{"id": "one"}, {"id": "two"}, {"id": "three"}]}),
            &budgets,
        );
        assert_eq!(
            observation.sample["items"].as_array().expect("array").len(),
            2
        );
        assert_eq!(observation.identifiers.len(), 3);
    }
}
