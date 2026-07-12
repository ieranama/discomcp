use std::collections::BTreeMap;

use serde_json::{Map, Value};

use crate::catalogue::fingerprint;
use crate::model::{EvidenceClaim, ExplorationBudgets, NormalizedObservation, ObservedIdentifier};

/// A scalar short enough to be captured as a citable identifier candidate or an
/// enum value. Long strings (log lines, message bodies, doc chunks) are not.
const MAX_SCALAR_LEN: usize = 128;

/// True for a leaf scalar cheap enough to retain whole: a short string, any
/// number/bool, or null. Shared by the sample walk and the fact walk.
fn is_short_scalar(value: &Value) -> bool {
    match value {
        Value::String(text) => text.len() <= MAX_SCALAR_LEN,
        Value::Number(_) | Value::Bool(_) | Value::Null => true,
        _ => false,
    }
}

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
        &tool,
        budgets.max_identifier_coverage as usize,
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
            let short_scalar_list = items.iter().all(is_short_scalar);
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

/// Walks the whole redacted payload and captures EVERY short leaf scalar, at any
/// depth, as a citable identifier candidate keyed by its JSON pointer. There is
/// no nesting cap (a deep `company.id` inside a saved-search result must be
/// citable); runaway payloads are bounded by `max_coverage` on the identifier
/// vec, not by traversal depth. The agent decides which candidates are true
/// identifiers downstream.
fn collect_facts(
    value: &Value,
    pointer: &str,
    observation_id: &str,
    tool: &str,
    max_coverage: usize,
    enum_values: &mut BTreeMap<String, Vec<String>>,
    identifiers: &mut Vec<ObservedIdentifier>,
) {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                let child_pointer = format!("{pointer}/{}", escape_pointer(key));
                if child.is_object() || child.is_array() {
                    collect_facts(
                        child,
                        &child_pointer,
                        observation_id,
                        tool,
                        max_coverage,
                        enum_values,
                        identifiers,
                    );
                    continue;
                }
                // Leaf scalar: every short, non-redacted one is a candidate.
                if is_short_scalar(child) {
                    if let Some(string) = scalar_string(child) {
                        if !string.starts_with("[REDACTED") && identifiers.len() < max_coverage {
                            identifiers.push(ObservedIdentifier {
                                name: key.clone(),
                                value: string,
                                observation_id: observation_id.to_string(),
                                json_pointer: child_pointer.clone(),
                                from_tool: tool.to_string(),
                                evidence: EvidenceClaim::observed(
                                    format!("`{key}` was returned by the target MCP"),
                                    format!("observation:{observation_id}{child_pointer}"),
                                    1.0,
                                ),
                            });
                        }
                    }
                }
                record_distinct_value(enum_values, &child_pointer, child, max_coverage);
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                let child_pointer = format!("{pointer}/{index}");
                if child.is_object() || child.is_array() {
                    collect_facts(
                        child,
                        &child_pointer,
                        observation_id,
                        tool,
                        max_coverage,
                        enum_values,
                        identifiers,
                    );
                } else if is_short_scalar(child) {
                    if let Some(string) = scalar_string(child) {
                        if !string.starts_with("[REDACTED") && identifiers.len() < max_coverage {
                            identifiers.push(ObservedIdentifier {
                                name: index.to_string(),
                                value: string,
                                observation_id: observation_id.to_string(),
                                json_pointer: child_pointer.clone(),
                                from_tool: tool.to_string(),
                                evidence: EvidenceClaim::observed(
                                    "an array element was returned by the target MCP".to_string(),
                                    format!("observation:{observation_id}{child_pointer}"),
                                    1.0,
                                ),
                            });
                        }
                    }
                    record_distinct_value(enum_values, &child_pointer, child, max_coverage);
                }
            }
        }
        _ => {}
    }
}

/// Accumulates the distinct scalar values a leaf took, keyed by its
/// index-stripped JSON pointer (`/items/0/state` -> `/items/state`). No
/// name blacklist and no magic cap: the agent decides which pointers are enums;
/// the per-pointer value list is bounded only by the coverage budget.
fn record_distinct_value(
    enum_values: &mut BTreeMap<String, Vec<String>>,
    pointer: &str,
    value: &Value,
    max_coverage: usize,
) {
    let Some(candidate) = scalar_string(value) else {
        return;
    };
    if candidate.is_empty() || candidate.starts_with("[REDACTED") {
        return;
    }
    let key = index_stripped_pointer(pointer);
    let values = enum_values.entry(key).or_default();
    if !values.contains(&candidate) && values.len() < max_coverage {
        values.push(candidate);
    }
}

/// Drops numeric (array-index) path segments so values observed across array
/// elements accumulate under one field pointer.
fn index_stripped_pointer(pointer: &str) -> String {
    pointer
        .split('/')
        .filter(|segment| !segment.is_empty() && !segment.bytes().all(|byte| byte.is_ascii_digit()))
        .map(|segment| format!("/{segment}"))
        .collect()
}

fn scalar_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
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
            &json!({"items": [
                {"id": "one", "state": "open"},
                {"id": "two", "state": "closed"},
                {"id": "three", "state": "open"}
            ]}),
            &budgets,
        );
        assert_eq!(
            observation.sample["items"].as_array().expect("array").len(),
            2
        );
        // Every `id` leaf is still captured (superset of the old id-name gate).
        assert_eq!(
            observation
                .identifiers
                .iter()
                .filter(|identifier| identifier.name == "id")
                .count(),
            3
        );
        // A NON-id leaf is now captured too — candidates are keyed by pointer,
        // not by an identifier-name heuristic.
        assert!(
            observation
                .identifiers
                .iter()
                .any(|identifier| identifier.name == "state" && identifier.value == "open"),
            "non-id leaf `state` must be captured: {:?}",
            observation.identifiers
        );
    }

    #[test]
    fn nested_leaf_scalars_are_captured_at_depth() {
        // The founder->company depth blocker: under Quick (depth cap 2) a deep
        // `company.id`/URN inside a list result used to be dropped. It must now
        // be a citable candidate at its exact pointer.
        let budgets = ExplorationBudgets::for_mode(&ExplorationMode::Quick);
        let observation = normalize_observation(
            "probe-deep".to_string(),
            "get_saved_search_results".to_string(),
            json!({}),
            &json!({"company": {"founders": [{"id": "urn:x"}]}}),
            &budgets,
        );
        let identifier = observation
            .identifiers
            .iter()
            .find(|identifier| identifier.json_pointer == "/company/founders/0/id")
            .expect("deep nested id must be captured as a candidate");
        assert_eq!(identifier.value, "urn:x");
        assert_eq!(identifier.from_tool, "get_saved_search_results");
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
        assert_eq!(
            observation
                .identifiers
                .iter()
                .filter(|identifier| identifier.name == "id")
                .count(),
            40
        );
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
