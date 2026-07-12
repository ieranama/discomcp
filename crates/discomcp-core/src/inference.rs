use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use crate::model::{
    ArgumentSource, CapabilityEvidence, CapabilityProfile, DiscoveredField, DiscoveredOperation,
    DiscoveredRelationship, DiscoveredStructure, EvidenceClaim, EvidenceRef, EvidenceStatus,
    NormalizedObservation, OperationalModel, OperationalWorkflow, ProbeRecord, RelationshipType,
    RiskClass, StructureKind, ToolCatalogue, Uncertainty, WorkflowStep, WorkspaceModel,
};

#[must_use]
pub fn infer_capability_profile(catalogue: &ToolCatalogue) -> CapabilityProfile {
    let cards = catalogue
        .tools
        .iter()
        .map(|tool| &tool.card)
        .collect::<Vec<_>>();
    let mut dimensions = BTreeMap::new();
    // Only risk/confirmation projections survive — pure `card.risk` and catalogue
    // facts. The substring/keyword dimensions (structure_discovery, structured_query,
    // search, metadata_discovery, ...) are gone: the agent authors capability
    // narrative from the raw observations, not from text-matched guesses.
    let checks: [(&str, bool); 9] = [
        (
            "computation",
            cards
                .iter()
                .any(|card| card.risk == RiskClass::PureComputation),
        ),
        (
            "mutation",
            cards.iter().any(|card| card.risk == RiskClass::Mutation),
        ),
        (
            "external_side_effects",
            cards
                .iter()
                .any(|card| card.risk == RiskClass::ExternalSideEffect),
        ),
        (
            "destructive_actions",
            cards.iter().any(|card| card.risk == RiskClass::Destructive),
        ),
        (
            "administration",
            cards
                .iter()
                .any(|card| card.risk == RiskClass::Administrative),
        ),
        ("resource_access", !catalogue.resources.is_empty()),
        ("workflow_prompts", !catalogue.prompts.is_empty()),
        (
            "sensitive_reads",
            cards
                .iter()
                .any(|card| card.risk == RiskClass::SensitiveRead),
        ),
        (
            "arbitrary_execution",
            cards
                .iter()
                .any(|card| card.risk == RiskClass::ArbitraryExecution),
        ),
    ];
    for (name, enabled) in checks {
        let sources = cards
            .iter()
            .filter(|card| capability_related(name, &card.risk))
            .map(|card| format!("tool:{}", card.name))
            .collect::<Vec<_>>();
        let claim = if enabled {
            EvidenceClaim {
                claim: format!("Capability `{name}` is exposed by declared target operations."),
                status: EvidenceStatus::Declared,
                confidence: 0.8,
                evidence: sources
                    .iter()
                    .cloned()
                    .map(|source| EvidenceRef {
                        status: EvidenceStatus::Declared,
                        source,
                        detail: None,
                    })
                    .collect(),
                source_references: sources,
                contradictions: Vec::new(),
            }
        } else {
            EvidenceClaim {
                claim: format!(
                    "Capability `{name}` has not been established from the declared catalogue."
                ),
                status: EvidenceStatus::Unknown,
                confidence: 0.35,
                evidence: Vec::new(),
                source_references: Vec::new(),
                contradictions: Vec::new(),
            }
        };
        dimensions.insert(name.to_string(), CapabilityEvidence { enabled, claim });
    }
    CapabilityProfile { dimensions }
}

#[must_use]
pub fn infer_workspace_model(
    target_id: &str,
    catalogue: &ToolCatalogue,
    observations: &[NormalizedObservation],
    probe_log: &[ProbeRecord],
) -> WorkspaceModel {
    let mut structures = BTreeMap::<String, DiscoveredStructure>::new();
    let mut origins = BTreeMap::<String, Vec<StructureOrigin>>::new();
    for observation in observations {
        let produced = origins.entry(observation.id.clone()).or_default();
        collect_root_structure(observation, &mut structures, produced);
        collect_structures_from_value(
            &observation.sample,
            "",
            observation,
            &mut structures,
            produced,
        );
    }
    let mut structures = structures.into_values().collect::<Vec<_>>();
    structures.sort_by(|left, right| left.normalized_name.cmp(&right.normalized_name));
    let mut relationships = containment_relationships(&structures);
    merge_relationships(
        &mut relationships,
        provenance_relationships(probe_log, &origins),
    );
    let operations = catalogue
        .tools
        .iter()
        .map(|tool| DiscoveredOperation {
            name: tool.raw.name.clone(),
            risk: tool.card.risk.clone(),
            summary: tool.card.summary.clone(),
            evidence: EvidenceClaim::declared(
                format!("`{}` is exposed by the target MCP.", tool.raw.name),
                format!("tool:{}", tool.raw.name),
            ),
        })
        .collect::<Vec<_>>();
    let workflows = infer_workflows(probe_log, observations);
    let uncertainties = initial_uncertainties(catalogue, observations);
    WorkspaceModel {
        target_id: target_id.to_string(),
        summary: workspace_summary(&structures, observations),
        structures,
        relationships,
        operations,
        workflows,
        observations: observations
            .iter()
            .map(|observation| crate::model::ObservationRef {
                id: observation.id.clone(),
                tool: observation.tool.clone(),
                fingerprint: observation.fingerprint.clone(),
            })
            .collect(),
        hypotheses: Vec::new(),
        contradictions: Vec::new(),
        uncertainties,
    }
}

#[must_use]
pub fn operational_model(
    target_id: &str,
    capability_profile: CapabilityProfile,
    workspace: &WorkspaceModel,
) -> OperationalModel {
    let confirmation_boundaries = workspace
        .operations
        .iter()
        .filter(|operation| operation.risk.requires_confirmation())
        .map(|operation| {
            format!(
                "`{}` is classified as `{}` and requires an explicit user confirmation outside onboarding.",
                operation.name,
                serde_json::to_string(&operation.risk)
                    .unwrap_or_else(|_| "unknown".to_string())
                    .trim_matches('"')
            )
        })
        .collect();
    OperationalModel {
        target_id: target_id.to_string(),
        summary:
            "Operational workflows are derived from the cached catalogue and safe observations."
                .to_string(),
        capability_profile,
        workflows: workspace.workflows.clone(),
        confirmation_boundaries,
        known_uncertainties: workspace.uncertainties.clone(),
    }
}

fn capability_related(name: &str, risk: &RiskClass) -> bool {
    match name {
        "mutation" => *risk == RiskClass::Mutation,
        "external_side_effects" => *risk == RiskClass::ExternalSideEffect,
        "destructive_actions" => *risk == RiskClass::Destructive,
        "administration" => *risk == RiskClass::Administrative,
        "arbitrary_execution" => *risk == RiskClass::ArbitraryExecution,
        "computation" => *risk == RiskClass::PureComputation,
        "sensitive_reads" => *risk == RiskClass::SensitiveRead,
        _ => matches!(risk, RiskClass::SafeRead | RiskClass::ConstrainedRead),
    }
}

/// Where a structure was found: its normalized name and the JSON pointer it was
/// observed at. The pointer is what ties an identifier cited as provenance back
/// to the structure that produced it.
#[derive(Clone, Debug)]
struct StructureOrigin {
    normalized_name: String,
    pointer: String,
}

/// The payload root can itself be an object, or a bare list of objects. It has
/// no parent key, so the keyed walk below never reaches it — index it here at
/// the empty pointer.
fn collect_root_structure(
    observation: &NormalizedObservation,
    structures: &mut BTreeMap<String, DiscoveredStructure>,
    produced: &mut Vec<StructureOrigin>,
) {
    let (items, is_collection): (&[Value], bool) = match &observation.sample {
        Value::Array(items) if items.first().is_some_and(Value::is_object) => (items, true),
        Value::Object(_) => (std::slice::from_ref(&observation.sample), false),
        _ => return,
    };
    let structure = make_structure("", items, observation, is_collection);
    record_origin(produced, &structure, "");
    merge_structure(structures, structure);
}

fn record_origin(
    produced: &mut Vec<StructureOrigin>,
    structure: &DiscoveredStructure,
    pointer: &str,
) {
    produced.push(StructureOrigin {
        normalized_name: structure.normalized_name.clone(),
        pointer: pointer.to_string(),
    });
}

/// Indexes EVERY nested object and array-of-objects at its JSON pointer. No
/// entity-naming, record-detection, or wrapper heuristics: the pointer IS the
/// structure key, and the agent authors the human name downstream. Array
/// elements recurse under the array's pointer (index-stripped) so a nested
/// object at `/items/0/owner` is keyed `/items/owner`.
fn collect_structures_from_value(
    value: &Value,
    pointer: &str,
    observation: &NormalizedObservation,
    structures: &mut BTreeMap<String, DiscoveredStructure>,
    produced: &mut Vec<StructureOrigin>,
) {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                let child_pointer = format!("{pointer}/{}", escape_pointer(key));
                match child {
                    Value::Array(items) if items.first().is_some_and(Value::is_object) => {
                        let structure = make_structure(&child_pointer, items, observation, true);
                        record_origin(produced, &structure, &child_pointer);
                        merge_structure(structures, structure);
                        for item in items {
                            collect_structures_from_value(
                                item,
                                &child_pointer,
                                observation,
                                structures,
                                produced,
                            );
                        }
                    }
                    Value::Object(_) => {
                        let structure = make_structure(
                            &child_pointer,
                            std::slice::from_ref(child),
                            observation,
                            false,
                        );
                        record_origin(produced, &structure, &child_pointer);
                        merge_structure(structures, structure);
                        collect_structures_from_value(
                            child,
                            &child_pointer,
                            observation,
                            structures,
                            produced,
                        );
                    }
                    _ => {}
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_structures_from_value(item, pointer, observation, structures, produced);
            }
        }
        _ => {}
    }
}

/// Builds an UNNAMED shape keyed by its pointer: leaf-scalar fields with types
/// and distinct values. `is_collection` is the only mechanical verdict (array
/// of objects vs a single object). No identifier judgement — the agent decides.
fn make_structure(
    pointer: &str,
    items: &[Value],
    observation: &NormalizedObservation,
    is_collection: bool,
) -> DiscoveredStructure {
    let mut fields = BTreeMap::<String, DiscoveredField>::new();
    for item in items {
        if let Some(object) = item.as_object() {
            for (field_name, field_value) in object {
                if field_value.is_object() || field_value.is_array() {
                    continue;
                }
                let field_pointer = format!("{pointer}/{field_name}");
                let field = fields.entry(field_name.clone()).or_insert_with(|| DiscoveredField {
                    name: field_name.clone(),
                    type_summary: value_type(field_value),
                    enum_values: observation
                        .observed_enum_values
                        .get(&field_pointer)
                        .cloned()
                        .unwrap_or_default(),
                    // Vestigial: identifier-ness is the agent's call now. Kept
                    // for wire-compat; always mechanically `false`.
                    is_identifier: false,
                    evidence: EvidenceClaim::observed(
                        format!("Field `{field_name}` appears in an observed sample at `{pointer}`."),
                        format!("observation:{}{field_pointer}", observation.id),
                        0.9,
                    ),
                });
                if field.type_summary != value_type(field_value) {
                    field.type_summary = "mixed".to_string();
                }
            }
        }
    }
    let fields = fields.into_values().collect::<Vec<_>>();
    let enum_values = fields
        .iter()
        .filter(|field| !field.enum_values.is_empty())
        .map(|field| (field.name.clone(), field.enum_values.clone()))
        .collect();
    let kind = if is_collection {
        StructureKind::Collection
    } else {
        StructureKind::Object
    };
    let display_pointer = if pointer.is_empty() { "/" } else { pointer };
    DiscoveredStructure {
        declared_name: pointer.to_string(),
        normalized_name: pointer.to_string(),
        possible_semantic_type: kind,
        description: format!(
            "Observed at pointer `{display_pointer}` in the `{}` response.",
            observation.tool
        ),
        fields,
        identifiers: Vec::new(),
        enum_values,
        possible_parents: Vec::new(),
        possible_children: Vec::new(),
        source_tools: vec![observation.tool.clone()],
        source_resources: Vec::new(),
        evidence: EvidenceClaim::observed(
            format!("An object shape was observed at pointer `{display_pointer}`."),
            format!("observation:{}{pointer}", observation.id),
            0.9,
        ),
        freshness: "current profile run".to_string(),
    }
}

fn merge_structure(
    structures: &mut BTreeMap<String, DiscoveredStructure>,
    structure: DiscoveredStructure,
) {
    let key = structure.normalized_name.clone();
    if let Some(existing) = structures.get_mut(&key) {
        for field in structure.fields {
            if !existing
                .fields
                .iter()
                .any(|candidate| candidate.name == field.name)
            {
                existing.fields.push(field);
            }
        }
        for identifier in structure.identifiers {
            if !existing.identifiers.contains(&identifier) {
                existing.identifiers.push(identifier);
            }
        }
        for tool in structure.source_tools {
            if !existing.source_tools.contains(&tool) {
                existing.source_tools.push(tool);
            }
        }
    } else {
        structures.insert(key, structure);
    }
}

/// Containment is derived purely from the pointer index: a structure at pointer
/// `P` contains the structure at its immediate deeper pointer. The structures
/// are observed, but the containment relationship itself is inferred (labelled
/// as such downstream), never a guessed `*_id` foreign key.
fn containment_relationships(structures: &[DiscoveredStructure]) -> Vec<DiscoveredRelationship> {
    let pointers = structures
        .iter()
        .map(|structure| structure.normalized_name.clone())
        .collect::<BTreeSet<_>>();
    let mut relationships = Vec::new();
    for structure in structures {
        let child = structure.normalized_name.as_str();
        // The parent is the longest OTHER structure pointer that is a strict
        // prefix of this one — the immediate container.
        let parent = pointers
            .iter()
            .filter(|candidate| {
                candidate.as_str() != child
                    && (candidate.is_empty() || child.starts_with(&format!("{candidate}/")))
            })
            .max_by_key(|candidate| candidate.len());
        if let Some(parent) = parent {
            relationships.push(DiscoveredRelationship {
                from_structure: parent.clone(),
                to_structure: child.to_string(),
                relationship_type: RelationshipType::Contains,
                via_fields: Vec::new(),
                evidence: EvidenceClaim::inferred(
                    format!("The structure at `{parent}` contains the structure at `{child}`."),
                    vec![format!("structure:{child}")],
                    0.8,
                ),
            });
        }
    }
    relationships
}

/// The strongest relationship evidence in the system is the traversal the safety
/// runtime already enforced: identifier `X`, observed in probe N, was accepted as
/// argument `calendarId` of probe N+1. That edge is *observed*, not guessed — the
/// structures the consuming probe returned reference the structure that produced
/// the identifier.
fn provenance_relationships(
    probe_log: &[ProbeRecord],
    origins: &BTreeMap<String, Vec<StructureOrigin>>,
) -> Vec<DiscoveredRelationship> {
    let mut relationships = Vec::new();
    for record in probe_log
        .iter()
        .filter(|record| record.runtime_decision.outcome == crate::model::RuntimeOutcome::Accepted)
    {
        // The observation carries the probe's own id, so this is what the probe learned.
        let Some(consuming) = origins.get(&record.id) else {
            continue;
        };
        for provenance in &record.decision.argument_provenance {
            let ArgumentSource::Observed {
                observation_id,
                json_pointer,
            } = &provenance.source
            else {
                continue;
            };
            let field = provenance.json_pointer.trim_start_matches('/');
            if field.is_empty() {
                continue;
            }
            let Some(source) = structure_at(origins.get(observation_id), json_pointer) else {
                continue;
            };
            for target in consuming {
                let target = &target.normalized_name;
                if *target == source {
                    continue;
                }
                relationships.push(DiscoveredRelationship {
                    from_structure: target.clone(),
                    to_structure: source.clone(),
                    relationship_type: RelationshipType::References,
                    via_fields: vec![field.to_string()],
                    evidence: EvidenceClaim::observed(
                        format!(
                            "`{field}` was observed in {observation_id} at `{json_pointer}` and accepted as the identifier that reached `{target}`."
                        ),
                        format!("probe:{}", record.id),
                        0.95,
                    ),
                });
            }
        }
    }
    relationships
}

/// The structure whose pointer is the longest prefix of the identifier's pointer:
/// `/items/0/id` belongs to the structure observed at `/items`.
fn structure_at(origins: Option<&Vec<StructureOrigin>>, json_pointer: &str) -> Option<String> {
    origins?
        .iter()
        .filter(|origin| json_pointer.starts_with(&origin.pointer))
        .max_by_key(|origin| origin.pointer.len())
        .map(|origin| origin.normalized_name.clone())
}

fn merge_relationships(
    relationships: &mut Vec<DiscoveredRelationship>,
    additional: Vec<DiscoveredRelationship>,
) {
    for candidate in additional {
        let duplicate = relationships.iter().any(|existing| {
            existing.from_structure == candidate.from_structure
                && existing.to_structure == candidate.to_structure
                && existing.via_fields == candidate.via_fields
        });
        if !duplicate {
            relationships.push(candidate);
        }
    }
}

fn infer_workflows(
    probe_log: &[ProbeRecord],
    observations: &[NormalizedObservation],
) -> Vec<OperationalWorkflow> {
    let accepted = probe_log
        .iter()
        .filter(|record| record.runtime_decision.outcome == crate::model::RuntimeOutcome::Accepted)
        .filter_map(|record| {
            record
                .decision
                .selected_tool
                .as_ref()
                .map(|tool| (record, tool))
        })
        .collect::<Vec<_>>();
    let mut workflows = Vec::new();
    if !accepted.is_empty() {
        let steps = accepted
            .iter()
            .map(|(record, tool)| WorkflowStep {
                tool: (*tool).clone(),
                purpose: record.decision.objective.clone(),
                argument_derivation: record
                    .decision
                    .argument_provenance
                    .iter()
                    .map(|provenance| {
                        format!("{}: {:?}", provenance.json_pointer, provenance.source)
                    })
                    .collect(),
                identifier_source: record.decision.argument_provenance.iter().find_map(
                    |provenance| match &provenance.source {
                        crate::model::ArgumentSource::Observed { observation_id, .. } => {
                            Some(format!("observed in {observation_id}"))
                        }
                        _ => None,
                    },
                ),
                confirmation_required: false,
            })
            .collect::<Vec<_>>();
        workflows.push(OperationalWorkflow {
            name: "Read a discovered workspace item".to_string(),
            supported_user_intent:
                "Inspect structures reachable through safe, observed identifier traversal.".to_string(),
            preconditions: vec![
                "Use only identifiers returned by a prior successful target MCP response.".to_string(),
                "Keep list or sample parameters within the profile's configured limit.".to_string(),
            ],
            ordered_tool_sequence: steps,
            expected_result: format!(
                "A bounded, redacted result based on {} successful observation(s).",
                observations.len()
            ),
            optional_traversal: vec![
                "Traverse a relationship only when its identifier has been observed and provenance is retained."
                    .to_string(),
            ],
            mutation_boundary: "No mutation tool is executed during onboarding.".to_string(),
            confirmation_requirements: Vec::new(),
            verification_steps: vec!["Check the returned stable identifier and response shape.".to_string()],
            failure_handling: vec![
                "Record the failed probe as an uncertainty and continue with other allowed probes."
                    .to_string(),
            ],
            evidence: EvidenceClaim::observed(
                "The sequence is supported by successful safe probe records.",
                format!("probe:{}", accepted[0].0.id),
                0.92,
            ),
        });
    }
    // The per-tool "Plan X with confirmation" branch is gone: it was 100%
    // templated English generated even with zero probes, and its content — the
    // confirmation boundary for each risky tool — is already surfaced mechanically
    // via `operational_model.confirmation_boundaries`. Only probe-derived
    // workflows remain here.
    workflows
}

fn initial_uncertainties(
    catalogue: &ToolCatalogue,
    observations: &[NormalizedObservation],
) -> Vec<Uncertainty> {
    let mut uncertainties = Vec::new();
    if observations.is_empty() {
        uncertainties.push(Uncertainty {
            question: "Which structures are accessible in this workspace?".to_string(),
            reason: "No safe probe completed successfully.".to_string(),
            importance: "high".to_string(),
            evidence: Vec::new(),
        });
    }
    if catalogue
        .tools
        .iter()
        .any(|tool| tool.card.risk == RiskClass::Unknown)
    {
        uncertainties.push(Uncertainty {
            question: "What are the side effects of the unclassified tools?".to_string(),
            reason: "Neither a server annotation nor an agent declaration classified them during profiling."
                .to_string(),
            importance: "high".to_string(),
            evidence: catalogue
                .tools
                .iter()
                .filter(|tool| tool.card.risk == RiskClass::Unknown)
                .map(|tool| EvidenceRef {
                    status: EvidenceStatus::Unknown,
                    source: format!("tool:{}", tool.raw.name),
                    detail: Some(format!(
                        "the agent did not classify `{}` during profiling",
                        tool.raw.name
                    )),
                })
                .collect(),
        });
    }
    uncertainties
}

fn value_type(value: &Value) -> String {
    match value {
        Value::Object(_) => "object".to_string(),
        Value::Array(_) => "array".to_string(),
        Value::String(_) => "string".to_string(),
        Value::Number(number) if number.is_i64() || number.is_u64() => "integer".to_string(),
        Value::Number(_) => "number".to_string(),
        Value::Bool(_) => "boolean".to_string(),
        Value::Null => "null".to_string(),
    }
}

fn escape_pointer(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

fn workspace_summary(
    structures: &[DiscoveredStructure],
    observations: &[NormalizedObservation],
) -> String {
    if structures.is_empty() {
        return "No workspace structures were confirmed by safe observations.".to_string();
    }
    format!(
        "{} structure(s) were inferred from {} successful safe observation(s).",
        structures.len(),
        observations.len()
    )
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::envelope::unwrap_mcp_envelope;
    use crate::model::{ExplorationBudgets, PrivacyMode};
    use crate::normalization::normalize_observation;
    use crate::redaction::Redactor;

    /// Mirrors the engine: unwrap the envelope, redact the payload, then normalize.
    /// `Balanced` is the default mode; under `Strict` an email-shaped identifier is
    /// redacted too (see `redaction::email_shaped_identifier_survives_outside_strict_mode`).
    fn observe(tool: &str, arguments: Value, response: &Value) -> NormalizedObservation {
        observe_as("probe-001", tool, arguments, response)
    }

    fn observe_as(
        id: &str,
        tool: &str,
        arguments: Value,
        response: &Value,
    ) -> NormalizedObservation {
        let payload = unwrap_mcp_envelope(response);
        let (redacted, _) = Redactor::new(PrivacyMode::Balanced).redact(&payload);
        normalize_observation(
            id.to_string(),
            tool.to_string(),
            arguments,
            &redacted,
            &ExplorationBudgets::for_mode(&crate::model::ExplorationMode::Quick),
        )
    }

    fn calendar_envelope(payload: Value) -> Value {
        json!({
            "content": [{"type": "text", "text": serde_json::to_string(&payload).expect("json")}],
            "isError": false
        })
    }

    #[test]
    fn enveloped_payload_yields_pointer_indexed_structure_and_identifiers() {
        // Naming is the agent's job now: Rust emits an UNNAMED shape keyed by the
        // JSON pointer `/items`, with the real fields and a citable identifier.
        let response = calendar_envelope(json!({
            "kind": "calendar#calendarList",
            "etag": "\"p33vs9nt8hb59a0o\"",
            "items": [{
                "kind": "calendar#calendarListEntry",
                "id": "en.spain#holiday@group.v.calendar.google.com",
                "summary": "Holidays in Spain",
                "timeZone": "Europe/Madrid",
                "accessRole": "reader",
                "selected": true
            }]
        }));
        let observation = observe("calendar_calendarList_list", json!({}), &response);

        // The identifier must be citable as provenance for a later get-by-id probe.
        let identifier = observation
            .identifiers
            .iter()
            .find(|identifier| identifier.json_pointer == "/items/0/id")
            .expect("payload identifier must be recorded at its pointer");
        assert_eq!(
            identifier.value,
            "en.spain#holiday@group.v.calendar.google.com"
        );

        let workspace =
            infer_workspace_model("gws", &ToolCatalogue::default(), &[observation], &[]);
        let structure = workspace
            .structures
            .iter()
            .find(|structure| structure.normalized_name == "/items")
            .expect("structure must be keyed by its JSON pointer");
        // Array-of-objects is flagged mechanically as a Collection, no `kind` parse.
        assert_eq!(structure.possible_semantic_type, StructureKind::Collection);
        for field in ["id", "summary", "timeZone", "accessRole"] {
            assert!(
                structure
                    .fields
                    .iter()
                    .any(|candidate| candidate.name == field),
                "missing real field `{field}`"
            );
        }
    }

    #[test]
    fn non_enveloped_response_still_infers_structures() {
        let observation = observe(
            "list_things",
            json!({"collection_id": "things"}),
            &json!({"items": [{"id": "thing-1", "state": "open"}]}),
        );
        let workspace =
            infer_workspace_model("fixture", &ToolCatalogue::default(), &[observation], &[]);
        let structure = workspace
            .structures
            .iter()
            .find(|structure| structure.normalized_name == "/items")
            .expect("the `items` collection is keyed by its pointer");
        assert!(
            structure.fields.iter().any(|field| field.name == "id"),
            "the `id` leaf must be a field"
        );
    }

    #[test]
    fn enveloped_non_json_text_degrades_gracefully() {
        let response = json!({
            "content": [{"type": "text", "text": "the tool has nothing to report"}],
            "isError": false
        });
        let observation = observe("status_check", json!({}), &response);
        assert_eq!(observation.sample, json!("the tool has nothing to report"));
        let workspace =
            infer_workspace_model("fixture", &ToolCatalogue::default(), &[observation], &[]);
        assert!(workspace.structures.is_empty());
    }

    #[test]
    fn secrets_inside_the_enveloped_payload_are_redacted() {
        let response = calendar_envelope(json!({
            "items": [{
                "id": "cal-1",
                "organizer": "owner@example.test",
                "access_token": "ya29.a0AfB_super_secret_value"
            }]
        }));
        let observation = observe("calendar_calendarList_list", json!({}), &response);
        let persisted = serde_json::to_string(&observation.sample).expect("json");
        assert!(
            !persisted.contains("example.test"),
            "email leaked: {persisted}"
        );
        assert!(
            !persisted.contains("ya29.a0AfB"),
            "secret leaked: {persisted}"
        );
        assert!(
            persisted.contains("cal-1"),
            "payload must survive redaction"
        );
    }

    #[test]
    fn bare_object_payload_emits_a_root_structure_with_its_leaves() {
        // Inverted from the old "name a bare object from the tool" behaviour: a
        // bare object is the root structure (pointer ``), its scalar leaves
        // captured as fields — no tool-name entity guessing.
        let observation = observe(
            "gmail_users_getProfile",
            json!({}),
            &calendar_envelope(
                json!({"emailAddress": "a@b.com", "messagesTotal": 12, "historyId": "9"}),
            ),
        );
        let workspace =
            infer_workspace_model("gws", &ToolCatalogue::default(), &[observation], &[]);
        let root = workspace
            .structures
            .iter()
            .find(|structure| structure.normalized_name.is_empty())
            .expect("the bare object is the root structure");
        assert_eq!(root.possible_semantic_type, StructureKind::Object);
        for field in ["emailAddress", "messagesTotal", "historyId"] {
            assert!(
                root.fields.iter().any(|candidate| candidate.name == field),
                "missing root leaf `{field}`"
            );
        }
    }

    #[test]
    fn sibling_collections_produce_containment_edges_from_the_root() {
        let observation = observe(
            "calendar_events_list",
            json!({}),
            &calendar_envelope(json!({
                "calendars": [{"id": "cal-1", "summary": "Work"}],
                "events": [{"id": "evt-1", "calendarId": "cal-1"}]
            })),
        );
        let workspace =
            infer_workspace_model("gws", &ToolCatalogue::default(), &[observation], &[]);
        // Containment is derived from the pointer index, not a `*_id` name match:
        // the root `` contains both `/calendars` and `/events`.
        for child in ["/calendars", "/events"] {
            assert!(
                workspace.relationships.iter().any(|relationship| {
                    relationship.from_structure.is_empty()
                        && relationship.to_structure == child
                        && relationship.relationship_type == RelationshipType::Contains
                }),
                "expected containment `` -> `{child}`, got {:?}",
                workspace.relationships
            );
        }
    }

    #[test]
    fn accepted_identifier_provenance_becomes_a_relationship() {
        let calendars = observe_as(
            "probe-001",
            "calendar_calendarList_list",
            json!({}),
            &calendar_envelope(json!({
                "kind": "calendar#calendarList",
                "items": [{"kind": "calendar#calendarListEntry", "id": "cal-1", "summary": "Work"}]
            })),
        );
        let events = observe_as(
            "probe-002",
            "calendar_events_list",
            json!({"calendarId": "cal-1"}),
            &calendar_envelope(json!({
                "kind": "calendar#events",
                "items": [{"kind": "calendar#event", "id": "evt-1", "summary": "Standup"}]
            })),
        );
        let record = ProbeRecord {
            id: "probe-002".to_string(),
            decision: crate::model::ProbeDecision {
                objective: "read events of an observed calendar".to_string(),
                unresolved_question: "which events exist".to_string(),
                selected_tool: Some("calendar_events_list".to_string()),
                arguments: json!({"calendarId": "cal-1"}),
                expected_information: String::new(),
                expected_information_gain: 1.0,
                confidence: 1.0,
                alternatives: Vec::new(),
                argument_provenance: vec![crate::model::ArgumentProvenance {
                    json_pointer: "/calendarId".to_string(),
                    source: ArgumentSource::Observed {
                        observation_id: "probe-001".to_string(),
                        json_pointer: "/items/0/id".to_string(),
                    },
                }],
                declared_risk: None,
                stop: false,
                stop_reason: None,
            },
            candidate_tools: vec!["calendar_events_list".to_string()],
            risk: RiskClass::SafeRead,
            runtime_decision: crate::model::RuntimeDecision {
                outcome: crate::model::RuntimeOutcome::Accepted,
                reason: "accepted".to_string(),
            },
            result_fingerprint: None,
            error: None,
            interpretation: None,
            declared_classification: None,
        };
        let workspace = infer_workspace_model(
            "gws",
            &ToolCatalogue::default(),
            &[calendars, events],
            &[record],
        );
        // The provenance traversal is the only foreign-key edge now, keyed by
        // pointer: the consuming observation's root `` references the `/items`
        // structure that produced the accepted identifier.
        assert!(
            workspace.relationships.iter().any(|relationship| {
                relationship.from_structure.is_empty()
                    && relationship.to_structure == "/items"
                    && relationship.via_fields == vec!["calendarId".to_string()]
                    && relationship.relationship_type == RelationshipType::References
            }),
            "the enforced traversal is the relationship, got {:?}",
            workspace.relationships
        );
    }

    #[test]
    fn generic_inference_indexes_collection_by_pointer_with_identifiers() {
        let observation = normalize_observation(
            "probe-1".to_string(),
            "list_things".to_string(),
            json!({"collection_id": "things"}),
            &json!({"items": [{"id": "thing-1", "state": "open"}]}),
            &ExplorationBudgets::for_mode(&crate::model::ExplorationMode::Quick),
        );
        let workspace =
            infer_workspace_model("fixture", &ToolCatalogue::default(), &[observation], &[]);
        let structure = workspace
            .structures
            .iter()
            .find(|structure| structure.normalized_name == "/items")
            .expect("the collection is keyed by its pointer");
        assert!(structure.fields.iter().any(|field| field.name == "id"));
        assert_eq!(structure.possible_semantic_type, StructureKind::Collection);
    }
}
