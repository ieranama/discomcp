use std::collections::BTreeSet;

use sha2::{Digest, Sha256};

use crate::model::{
    CataloguedTool, RawPrompt, RawResource, RawTool, RiskClass, ToolCard, ToolCatalogue,
};
use crate::policy::classify_tool;

#[must_use]
pub fn build_catalogue(
    tools: Vec<RawTool>,
    resources: Vec<RawResource>,
    prompts: Vec<RawPrompt>,
) -> ToolCatalogue {
    let tools = tools
        .into_iter()
        .map(|raw| {
            let card = tool_card(&raw);
            CataloguedTool { raw, card }
        })
        .collect::<Vec<_>>();
    let fingerprint = fingerprint(&serde_json::json!({
        "tools": tools,
        "resources": resources,
        "prompts": prompts,
    }));
    ToolCatalogue {
        tools,
        resources,
        prompts,
        fingerprint,
    }
}

#[must_use]
pub fn tool_card(tool: &RawTool) -> ToolCard {
    let properties = tool
        .input_schema
        .get("properties")
        .and_then(serde_json::Value::as_object)
        .cloned()
        .unwrap_or_default();
    let required = tool
        .input_schema
        .get("required")
        .and_then(serde_json::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(ToOwned::to_owned)
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();
    let optional_arguments = properties
        .keys()
        .filter(|key| !required.contains(*key))
        .cloned()
        .collect::<Vec<_>>();
    let identifier_dependencies = properties
        .iter()
        .filter(|(name, _)| is_identifier_name(name))
        .map(|(name, schema)| {
            let description = schema
                .get("description")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("Must be derived from an observed response or explicit user input.");
            (name.clone(), description.to_string())
        })
        .collect();
    let searchable_text = format!(
        "{} {} {} {}",
        tool.name,
        tool.description,
        properties.keys().cloned().collect::<Vec<_>>().join(" "),
        tool.output_schema
            .as_ref()
            .map_or_else(String::new, serde_json::Value::to_string)
    );
    let risk = classify_tool(tool);
    ToolCard {
        name: tool.name.clone(),
        summary: first_sentence(&tool.description),
        declared_purposes: declared_purposes(tool, &risk),
        risk,
        required_arguments: required.into_iter().collect(),
        optional_arguments,
        identifier_dependencies,
        output_summary: output_summary(tool),
        confidence: if tool.description.is_empty() {
            0.45
        } else {
            0.9
        },
        fingerprint: fingerprint(tool),
        searchable_text,
    }
}

#[must_use]
pub fn retrieve_tool_cards(
    catalogue: &ToolCatalogue,
    information_gap: &str,
    prior_dependencies: &[String],
    limit: usize,
) -> Vec<ToolCard> {
    let query = tokenize(&format!(
        "{} {}",
        information_gap,
        prior_dependencies.join(" ")
    ));
    let mut scored = catalogue
        .tools
        .iter()
        .map(|entry| {
            let document = tokenize(&entry.card.searchable_text);
            let overlap = query.intersection(&document).count() as i32;
            let safety_bias = match entry.card.risk {
                RiskClass::SafeRead | RiskClass::ConstrainedRead | RiskClass::PureComputation => 2,
                RiskClass::SensitiveRead => 0,
                _ => -1,
            };
            (overlap * 10 + safety_bias, entry.card.clone())
        })
        .collect::<Vec<_>>();
    scored.sort_by(|(left_score, left), (right_score, right)| {
        right_score
            .cmp(left_score)
            .then_with(|| left.name.cmp(&right.name))
    });
    scored
        .into_iter()
        .filter(|(score, _)| *score > 0)
        .take(limit.clamp(1, 12))
        .map(|(_, card)| card)
        .collect()
}

#[must_use]
pub fn fingerprint<T: serde::Serialize>(value: &T) -> String {
    let encoded = serde_json::to_vec(value).unwrap_or_default();
    let digest = Sha256::digest(encoded);
    format!("sha256:{digest:x}")
}

fn first_sentence(value: &str) -> String {
    value
        .split_terminator('.')
        .next()
        .unwrap_or(value)
        .trim()
        .to_string()
}

fn output_summary(tool: &RawTool) -> String {
    if let Some(schema) = &tool.output_schema {
        if let Some(kind) = schema.get("type").and_then(serde_json::Value::as_str) {
            return format!("Declared output schema type: {kind}");
        }
    }
    "Output schema was not declared.".to_string()
}

fn declared_purposes(tool: &RawTool, risk: &RiskClass) -> Vec<String> {
    let mut purposes = BTreeSet::new();
    match risk {
        RiskClass::SafeRead | RiskClass::ConstrainedRead | RiskClass::SensitiveRead => {
            purposes.insert("read".to_string());
        }
        RiskClass::PureComputation => {
            purposes.insert("computation".to_string());
        }
        RiskClass::Mutation => {
            purposes.insert("mutation".to_string());
        }
        RiskClass::ExternalSideEffect => {
            purposes.insert("external_side_effect".to_string());
        }
        RiskClass::Destructive => {
            purposes.insert("destructive".to_string());
        }
        RiskClass::Administrative => {
            purposes.insert("administrative".to_string());
        }
        RiskClass::ArbitraryExecution => {
            purposes.insert("arbitrary_execution".to_string());
        }
        RiskClass::Unknown => {}
    }
    let text = format!("{} {}", tool.name, tool.description).to_ascii_lowercase();
    if text.contains("search") {
        purposes.insert("search".to_string());
    }
    if text.contains("list") || text.contains("enumerat") {
        purposes.insert("enumeration".to_string());
    }
    purposes.into_iter().collect()
}

fn is_identifier_name(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    value == "id"
        || value.ends_with("_id")
        || value.ends_with("-id")
        || value.contains("identifier")
        || value.ends_with("_uri")
}

fn tokenize(value: &str) -> BTreeSet<String> {
    value
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|token| token.len() > 1)
        .map(|token| token.to_ascii_lowercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn retrieval_selects_relevant_subset_without_full_catalogue() {
        let tools = (0..20)
            .map(|index| RawTool {
                name: format!("tool_{index}"),
                description: if index == 7 {
                    "Lists project records in a read-only bounded response.".to_string()
                } else {
                    format!("Returns unrelated namespace {index} in a read-only response.")
                },
                input_schema: json!({"type": "object"}),
                output_schema: None,
                annotations: json!({"readOnlyHint": true}),
            })
            .collect();
        let catalogue = build_catalogue(tools, Vec::new(), Vec::new());
        let retrieved = retrieve_tool_cards(&catalogue, "find project records", &[], 12);
        assert!(retrieved.len() < catalogue.tools.len());
        assert!(retrieved.len() <= 12);
        assert!(retrieved.iter().any(|card| card.name == "tool_7"));
    }
}
