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
        budgets.max_identifier_coverage as usize,
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

/// Retains a bounded, redacted view of a response for shape inference.
///
/// Two independent caps split what would otherwise be one budget:
/// - `record_limit` (low): how many FULL records (objects) to keep from an
///   array — prevents record bloat while still capturing shape.
/// - `identifier_limit` (high): how many SCALAR items (string/number/bool/null)
///   to keep from an array — lets wide name/id lists be captured completely,
///   since short scalars are cheap.
///
/// The cap for an array is chosen from its element kinds: an array whose every
/// element is a scalar uses `identifier_limit`; any array containing objects or
/// nested arrays (i.e. records) uses `record_limit`.
fn bounded_sample(
    value: &Value,
    record_limit: usize,
    identifier_limit: usize,
    depth: u32,
    max_depth: u32,
) -> Value {
    match value {
        Value::String(_) | Value::Number(_) | Value::Bool(_) | Value::Null => value.clone(),
        Value::Object(object) => Value::Object(
            object
                .iter()
                .map(|(key, child)| {
                    let child = if depth >= max_depth && (child.is_object() || child.is_array()) {
                        Value::String("[TRAVERSAL_LIMIT]".to_string())
                    } else {
                        bounded_sample(child, record_limit, identifier_limit, depth + 1, max_depth)
                    };
                    (key.clone(), child)
                })
                .collect::<Map<_, _>>(),
        ),
        Value::Array(items) => {
            // High coverage only for lists of SHORT scalars (names/ids/enum
            // values). A list of long strings (log lines, message bodies, doc
            // chunks) is treated as records so it stays bounded low — otherwise
            // a wide list of long text would bloat the sample.
            const MAX_SCALAR_LEN: usize = 128;
            let short_scalar_list = items.iter().all(|item| match item {
                Value::String(text) => text.len() <= MAX_SCALAR_LEN,
                Value::Number(_) | Value::Bool(_) | Value::Null => true,
                _ => false,
            });
            let limit = if short_scalar_list {
                identifier_limit
            } else {
                record_limit
            };
            Value::Array(
                items
                    .iter()
                    .take(limit)
                    .map(|child| {
                        if depth >= max_depth && (child.is_object() || child.is_array()) {
                            Value::String("[TRAVERSAL_LIMIT]".to_string())
                        } else {
                            bounded_sample(
                                child,
                                record_limit,
                                identifier_limit,
                                depth + 1,
                                max_depth,
                            )
                        }
                    })
                    .collect(),
            )
        }
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

pub(crate) fn is_identifier_name(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower == "id"
        || lower.ends_with("_id")
        || lower.ends_with("-id")
        || lower.contains("identifier")
        || lower.ends_with("_uri")
        || is_camel_case_id(value)
}

/// `calendarId`, `eventId` — the camelCase spelling of `*_id`.
fn is_camel_case_id(value: &str) -> bool {
    value
        .strip_suffix("Id")
        .is_some_and(|prefix| prefix.ends_with(|character: char| character.is_ascii_alphanumeric()))
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

    #[test]
    fn wide_scalar_array_is_fully_retained_under_identifier_coverage() {
        // Even under Quick (max_samples_per_structure = 2) a wide list of bare
        // scalar names must survive up to the high identifier-coverage budget,
        // not truncate at the low record cap.
        let budgets = ExplorationBudgets::for_mode(&ExplorationMode::Deep);
        let names: Vec<String> = (0..300).map(|i| format!("dataset_{i}")).collect();
        let observation = normalize_observation(
            "probe-scalars".to_string(),
            "list_datasets".to_string(),
            json!({}),
            &json!({ "datasets": names }),
            &budgets,
        );
        let retained = observation.sample["datasets"].as_array().expect("array");
        // Deep coverage is 1000 >= 300, so every name is kept.
        assert_eq!(retained.len(), 300);
        assert_eq!(retained[0], json!("dataset_0"));
        assert_eq!(retained[299], json!("dataset_299"));
    }

    #[test]
    fn scalar_array_truncates_at_identifier_coverage_not_record_cap() {
        // Quick: record cap 2, identifier coverage 100. A 300-item scalar list
        // is bounded by coverage (100), never the record cap (2).
        let budgets = ExplorationBudgets::for_mode(&ExplorationMode::Quick);
        assert_eq!(budgets.max_samples_per_structure, 2);
        assert_eq!(budgets.max_identifier_coverage, 100);
        let names: Vec<String> = (0..300).map(|i| format!("t{i}")).collect();
        let observation = normalize_observation(
            "probe-scalars-quick".to_string(),
            "list_tables".to_string(),
            json!({}),
            &json!({ "tables": names }),
            &budgets,
        );
        assert_eq!(
            observation.sample["tables"]
                .as_array()
                .expect("array")
                .len(),
            100
        );
    }

    #[test]
    fn object_array_still_capped_at_record_limit() {
        // No regression: an array of full-record OBJECTS keeps only the low
        // record cap, regardless of the high identifier-coverage budget.
        let budgets = ExplorationBudgets::for_mode(&ExplorationMode::Standard);
        assert_eq!(budgets.max_samples_per_structure, 5);
        let records: Vec<Value> = (0..40)
            .map(|i| json!({"id": format!("id-{i}"), "name": format!("name-{i}"), "field": i}))
            .collect();
        let observation = normalize_observation(
            "probe-records".to_string(),
            "list".to_string(),
            json!({}),
            &json!({ "results": records }),
            &budgets,
        );
        assert_eq!(
            observation.sample["results"]
                .as_array()
                .expect("array")
                .len(),
            5
        );
        // Every object-keyed id is still collected, unbounded by the sample cap.
        assert_eq!(observation.identifiers.len(), 40);
    }

    #[test]
    fn identifier_coverage_budget_is_honoured_independently() {
        // Config-style override: dropping max_identifier_coverage truncates the
        // scalar list at exactly that value, proving the field is wired through.
        let mut budgets = ExplorationBudgets::for_mode(&ExplorationMode::Standard);
        budgets.max_identifier_coverage = 7;
        let names: Vec<String> = (0..50).map(|i| format!("n{i}")).collect();
        let observation = normalize_observation(
            "probe-override".to_string(),
            "list".to_string(),
            json!({}),
            &json!({ "names": names }),
            &budgets,
        );
        assert_eq!(
            observation.sample["names"].as_array().expect("array").len(),
            7
        );
    }
}
