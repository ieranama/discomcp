use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::error::{DiscoMcpError, Result};
use crate::model::{
    EvidenceStatus, OperationalModel, ProfileMetadata, TargetProfile, ToolCatalogue, WorkspaceModel,
};

pub fn write_profile_artifacts(profile: &TargetProfile, output_dir: &Path) -> Result<()> {
    fs::create_dir_all(output_dir)?;
    write_json(output_dir, "profile-metadata.json", &profile.metadata)?;
    write_json(output_dir, "raw-discovery.json", &profile.raw_discovery)?;
    write_json(
        output_dir,
        "capability-profile.json",
        &profile.capability_profile,
    )?;
    write_json(output_dir, "docs-index.json", &profile.documentation)?;
    write_text(output_dir, "docs-summary.md", &render_docs_summary(profile))?;
    write_json(output_dir, "tool-catalogue.json", &profile.catalogue)?;
    write_json(
        output_dir,
        "tool-cards.json",
        &profile
            .catalogue
            .tools
            .iter()
            .map(|tool| &tool.card)
            .collect::<Vec<_>>(),
    )?;
    write_text(output_dir, "tool-map.md", &render_tool_map(profile))?;
    write_json(
        output_dir,
        "exploration-plan.json",
        &profile
            .probe_log
            .iter()
            .map(|record| &record.decision)
            .collect::<Vec<_>>(),
    )?;
    write_jsonl(output_dir, "probe-log.jsonl", &profile.probe_log)?;
    write_jsonl(output_dir, "observations.jsonl", &profile.observations)?;
    write_json(
        output_dir,
        "hypotheses.json",
        &profile.workspace_model.hypotheses,
    )?;
    write_json(
        output_dir,
        "contradictions.json",
        &profile.workspace_model.contradictions,
    )?;
    write_json(output_dir, "workspace-model.json", &profile.workspace_model)?;
    write_text(
        output_dir,
        "workspace-map.md",
        &render_workspace_map(profile),
    )?;
    write_json(
        output_dir,
        "relationships.json",
        &profile.workspace_model.relationships,
    )?;
    write_text(
        output_dir,
        "relationships.md",
        &render_relationships(profile),
    )?;
    let sample_shapes = profile
        .observations
        .iter()
        .map(|observation| (observation.id.clone(), observation.shape.clone()))
        .collect::<BTreeMap<_, _>>();
    write_json(output_dir, "sample-shapes.json", &sample_shapes)?;
    let samples = profile
        .observations
        .iter()
        .map(|observation| (observation.id.clone(), observation.sample.clone()))
        .collect::<BTreeMap<_, _>>();
    write_json(output_dir, "samples.redacted.json", &samples)?;
    write_json(
        output_dir,
        "operational-model.json",
        &profile.operational_model,
    )?;
    write_text(output_dir, "playbooks.md", &render_playbooks(profile))?;
    write_text(output_dir, "SKILL.md", &render_skill(profile))?;
    write_text(output_dir, "AGENTS.md", &render_agents(profile, output_dir))?;
    write_text(output_dir, "evals.yml", &render_evals(profile)?)?;
    write_json(output_dir, "mcp-quality.json", &profile.quality_report)?;
    write_text(
        output_dir,
        "onboarding-report.md",
        &render_onboarding_report(profile),
    )?;
    Ok(())
}

/// Overwrites SKILL.md with a STUB when a session finished with zero accepted
/// read observations. A catalogue-only run (dead auth, all probes rejected) must
/// not emit a rich-looking profile: no Tool-Safety buckets, no Recommended
/// Sequences, no capability profile rendered as if grounded. It states plainly
/// that nothing was safely observed and how to re-profile.
pub fn write_stub_skill(output_dir: &Path, target_id: &str) -> Result<()> {
    let mut output = String::from("# DiscoMCP Operational Skill\n\n");
    output.push_str("## Insufficient Observations\n\n");
    output.push_str(&format!(
        "`unknown`: Profiling target `{target_id}` produced ZERO accepted read observations. \
         Nothing about this target's structures, identifiers, relationships, or safe workflows \
         was established. This SKILL is a STUB, not a grounded profile — do not treat the cached \
         catalogue as a verified capability map.\n\n"
    ));
    output.push_str("## What To Do Next\n\n");
    output.push_str(
        "`user_defined`: Re-profile in a BACKGROUND subagent so the user is not blocked: run \
         `discomcp serve`, then inspect_target -> execute_probe in a loop driven by each result's \
         `gaps` report -> finalize_profile once coverage is real. If every probe was rejected, \
         the target's auth or connectivity likely failed; verify access before re-profiling. \
         Never run mutation/side-effect/destructive/admin tools during a refresh.\n",
    );
    write_text(output_dir, "SKILL.md", &output)
}

pub fn regenerate_skill(profile_dir: &Path) -> Result<PathBuf> {
    let metadata: ProfileMetadata = read_json(profile_dir, "profile-metadata.json")?;
    let catalogue: ToolCatalogue = read_json(profile_dir, "tool-catalogue.json")?;
    let workspace_model: WorkspaceModel = read_json(profile_dir, "workspace-model.json")?;
    let operational_model: OperationalModel = read_json(profile_dir, "operational-model.json")?;
    let profile = TargetProfile {
        metadata,
        catalogue,
        workspace_model,
        operational_model,
        ..TargetProfile::default()
    };
    write_text(profile_dir, "SKILL.md", &render_skill(&profile))?;
    Ok(profile_dir.join("SKILL.md"))
}

fn write_json<T: Serialize>(directory: &Path, file_name: &str, value: &T) -> Result<()> {
    let contents = serde_json::to_vec_pretty(value)?;
    atomic_write(&directory.join(file_name), &contents)
}

fn write_jsonl<T: Serialize>(directory: &Path, file_name: &str, values: &[T]) -> Result<()> {
    let mut output = String::new();
    for value in values {
        output.push_str(&serde_json::to_string(value)?);
        output.push('\n');
    }
    atomic_write(&directory.join(file_name), output.as_bytes())
}

fn write_text(directory: &Path, file_name: &str, contents: &str) -> Result<()> {
    atomic_write(&directory.join(file_name), contents.as_bytes())
}

fn atomic_write(path: &Path, contents: &[u8]) -> Result<()> {
    let temporary = path.with_extension("tmp");
    fs::write(&temporary, contents).map_err(|source| DiscoMcpError::Artifact {
        path: temporary.clone(),
        source,
    })?;
    fs::rename(&temporary, path).map_err(|source| DiscoMcpError::Artifact {
        path: path.to_path_buf(),
        source,
    })
}

fn read_json<T: serde::de::DeserializeOwned>(directory: &Path, file_name: &str) -> Result<T> {
    let path = directory.join(file_name);
    let contents = fs::read(&path).map_err(|source| DiscoMcpError::Artifact {
        path: path.clone(),
        source,
    })?;
    serde_json::from_slice(&contents).map_err(Into::into)
}

fn render_docs_summary(profile: &TargetProfile) -> String {
    let mut output = String::from("# Documentation Summary\n\n");
    if profile.documentation.sources.is_empty() {
        output.push_str("No configured documentation was captured during this profile run. Tool and parameter descriptions remain declared evidence.\n");
        return output;
    }
    for source in &profile.documentation.sources {
        output.push_str(&format!(
            "- **{}** (`{:?}`): {}\n",
            source.id, source.status, source.summary
        ));
    }
    output
}

fn render_tool_map(profile: &TargetProfile) -> String {
    let mut output = String::from("# Tool Map\n\n");
    for tool in &profile.catalogue.tools {
        output.push_str(&format!(
            "## `{}`\n\n- Risk: `{}`\n- Evidence: `{}`\n- Summary: {}\n",
            tool.raw.name,
            risk_label(&tool.card.risk),
            risk_evidence_label(&tool.card),
            tool.card.summary
        ));
        if !tool.card.required_arguments.is_empty() {
            output.push_str(&format!(
                "- Required arguments: {}\n",
                tool.card
                    .required_arguments
                    .iter()
                    .map(|argument| format!("`{argument}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        if !tool.card.identifier_dependencies.is_empty() {
            output.push_str("- Identifier dependencies:\n");
            for (argument, dependency) in &tool.card.identifier_dependencies {
                output.push_str(&format!("  - `{argument}`: {dependency}\n"));
            }
        }
        output.push('\n');
    }
    output
}

fn render_workspace_map(profile: &TargetProfile) -> String {
    let mut output = String::from("# Workspace Map\n\n");
    output.push_str(&format!("{}\n\n", profile.workspace_model.summary));
    for structure in &profile.workspace_model.structures {
        output.push_str(&format!(
            "## `{}`\n\n- Evidence: `{}` ({:.2})\n- Type: `{}`\n- Sources: {}\n",
            structure.declared_name,
            evidence_label(&structure.evidence.status),
            structure.evidence.confidence,
            serde_json::to_string(&structure.possible_semantic_type)
                .unwrap_or_else(|_| "unknown".to_string())
                .trim_matches('"'),
            structure
                .source_tools
                .iter()
                .map(|tool| format!("`{tool}`"))
                .collect::<Vec<_>>()
                .join(", ")
        ));
        if !structure.fields.is_empty() {
            output.push_str("- Fields:\n");
            for field in &structure.fields {
                output.push_str(&format!(
                    "  - `{}`: `{}`{}\n",
                    field.name,
                    field.type_summary,
                    if field.is_identifier {
                        " (identifier candidate)"
                    } else {
                        ""
                    }
                ));
            }
        }
        output.push('\n');
    }
    output
}

fn render_relationships(profile: &TargetProfile) -> String {
    let mut output = String::from("# Relationships\n\n");
    if profile.workspace_model.relationships.is_empty() {
        output.push_str(
            "No relationships were confirmed or inferred from the bounded observations.\n",
        );
    }
    for relationship in &profile.workspace_model.relationships {
        output.push_str(&format!(
            "- `{}` -> `{}` via {}: `{}` with {:.2} confidence.\n",
            relationship.from_structure,
            relationship.to_structure,
            relationship
                .via_fields
                .iter()
                .map(|field| format!("`{field}`"))
                .collect::<Vec<_>>()
                .join(", "),
            evidence_label(&relationship.evidence.status),
            relationship.evidence.confidence
        ));
    }
    output
}

fn render_playbooks(profile: &TargetProfile) -> String {
    let mut output = String::from("# Operational Playbooks\n\n");
    for workflow in &profile.operational_model.workflows {
        output.push_str(&format!("## {}\n\n", workflow.name));
        for (index, step) in workflow.ordered_tool_sequence.iter().enumerate() {
            output.push_str(&format!(
                "{}. `{}`: {}{}\n",
                index + 1,
                step.tool,
                step.purpose,
                if step.confirmation_required {
                    " (explicit confirmation required)"
                } else {
                    ""
                }
            ));
        }
        output.push('\n');
    }
    output
}

fn render_skill(profile: &TargetProfile) -> String {
    let mut output = String::from("# DiscoMCP Operational Skill\n\n");
    output.push_str("## Purpose\n\n");
    output.push_str(&format!(
        "`declared`: This skill profiles target `{}` and is generated from its cached catalogue plus redacted safe observations.\n\n",
        profile.metadata.target_id
    ));
    if let Some(usage) = &profile.metadata.usage_summary {
        output.push_str("## How You Use This MCP\n\n");
        output.push_str(&format!("`agent_authored`: {usage}\n\n"));
    }
    output.push_str("## When To Use This MCP\n\n");
    output.push_str("Use it for intents supported by the observed structures and declared tools below. Do not assume unavailable structures, fields, identifiers, or relationships.\n\n");
    // Only surface capabilities actually established — "not established" lines are
    // constant filler the agent gains nothing from.
    let established: Vec<_> = profile
        .capability_profile
        .dimensions
        .iter()
        .filter(|(_, capability)| capability.enabled)
        .collect();
    if !established.is_empty() {
        output.push_str("## Functional Capability Profile\n\n");
        for (name, capability) in established {
            output.push_str(&format!(
                "- `{name}`: `{}` - supported by declared evidence\n",
                evidence_label(&capability.claim.status),
            ));
        }
        output.push('\n');
    }
    output.push_str("## Observed Workspace Structures\n\n");
    if profile.workspace_model.structures.is_empty() {
        output.push_str("`unknown`: No workspace structures were safely observed.\n");
    }
    for structure in &profile.workspace_model.structures {
        output.push_str(&format!(
            "- `{}`: `{}` ({:.2})\n",
            structure.declared_name,
            evidence_label(&structure.evidence.status),
            structure.evidence.confidence,
        ));
    }
    // Carry only the identifier fields — the ones that enable a hop. Full field
    // schemas come back live in each tool's own response, so dumping every
    // leaf's type here is redundant weight re-read on every turn. If the profile
    // flagged no identifier fields, omit the section entirely — the hop keys
    // still live in the narrative, the tool sequences, and Confirmed Relationships.
    let identifier_rows: Vec<String> = profile
        .workspace_model
        .structures
        .iter()
        .filter_map(|structure| {
            let ids = structure
                .fields
                .iter()
                .filter(|field| field.is_identifier)
                .map(|field| {
                    format!("`{}` ({})", field.name, evidence_label(&field.evidence.status))
                })
                .collect::<Vec<_>>();
            if ids.is_empty() {
                return None;
            }
            let other = structure.fields.len() - ids.len();
            let suffix = if other > 0 {
                format!(" (+{other} non-identifier field(s), schema live from tool)")
            } else {
                String::new()
            };
            Some(format!(
                "- `{}`: {}{}\n",
                structure.declared_name,
                ids.join(", "),
                suffix
            ))
        })
        .collect();
    if !identifier_rows.is_empty() {
        output.push_str("\n## Identifiers That Enable Hops\n\n");
        output.push_str("`observed`: Read these out of a prior response; never invent them. Full field schemas come live from each tool's own response.\n");
        for row in identifier_rows {
            output.push_str(&row);
        }
    }
    output.push_str("\n## Confirmed Relationships\n\n");
    for relationship in profile
        .workspace_model
        .relationships
        .iter()
        .filter(|relationship| relationship.evidence.status == EvidenceStatus::Observed)
    {
        output.push_str(&format!(
            "- `{}` -> `{}` via {}.\n",
            relationship.from_structure,
            relationship.to_structure,
            relationship.via_fields.join(", ")
        ));
    }
    if !profile
        .workspace_model
        .relationships
        .iter()
        .any(|relationship| relationship.evidence.status == EvidenceStatus::Observed)
    {
        output.push_str("`unknown`: No relationship was directly verified by a traversal probe.\n");
    }
    // Only inferred edges that name a real join field carry information. A blank
    // `via` is just the json-pointer parent/child the agent reconstructs for free.
    let inferred: Vec<_> = profile
        .workspace_model
        .relationships
        .iter()
        .filter(|relationship| relationship.evidence.status == EvidenceStatus::Inferred)
        .filter(|relationship| relationship.via_fields.iter().any(|field| !field.is_empty()))
        .collect();
    if !inferred.is_empty() {
        output.push_str("\n## Inferred Relationships\n\n");
        for relationship in inferred {
            output.push_str(&format!(
                "- `{}` -> `{}` via {}: `inferred` ({:.2}).\n",
                relationship.from_structure,
                relationship.to_structure,
                relationship.via_fields.join(", "),
                relationship.evidence.confidence
            ));
        }
    }
    output.push_str("\n## Tool Safety Classes\n\n");
    for (heading, risks) in [
        ("Safe Read Tools", vec!["safe_read", "constrained_read"]),
        ("Sensitive Read Tools", vec!["sensitive_read"]),
        ("Computational Tools", vec!["pure_computation"]),
        ("Mutation Tools", vec!["mutation"]),
        ("External Side-Effect Tools", vec!["external_side_effect"]),
        (
            "Destructive Or Administrative Tools",
            vec!["destructive", "administrative", "arbitrary_execution"],
        ),
        ("Unclassified", vec!["unknown"]),
    ] {
        let tools = profile
            .catalogue
            .tools
            .iter()
            .filter(|tool| risks.contains(&risk_label(&tool.card.risk)))
            .collect::<Vec<_>>();
        // Omit empty risk classes entirely — a printed "None were established"
        // is constant filler re-read on every turn.
        if tools.is_empty() {
            continue;
        }
        output.push_str(&format!("### {heading}\n\n"));
        for tool in tools {
            output.push_str(&format!(
                "- `{}`: `{}`; {}{}\n",
                tool.raw.name,
                risk_evidence_label(&tool.card),
                tool.card.summary,
                if heading == "Unclassified" {
                    " — not probed or classified during profiling"
                } else {
                    ""
                }
            ));
        }
        output.push('\n');
    }
    let unverified = profile
        .catalogue
        .tools
        .iter()
        .filter(|tool| tool.card.risk_evidence == "agent_declared_unverified")
        .collect::<Vec<_>>();
    if !unverified.is_empty() {
        output.push_str("### Declared But Unverified\n\n");
        for tool in unverified {
            output.push_str(&format!(
                "- `{}`: the agent declared a class but no read probe was accepted — treat as UNVERIFIED, not confirmed safe.\n",
                tool.raw.name
            ));
        }
        output.push('\n');
    }
    output.push_str("## Recommended Tool Sequences\n\n");
    append_workflows(&mut output, &profile.operational_model);
    output.push_str("## User-Specific Workflows\n\n");
    if let Some(goal) = &profile.metadata.goal {
        output.push_str(&format!("`user_defined`: The profile goal was: {goal}\n\n"));
    } else {
        output.push_str("`unknown`: No user goal was supplied; use the observed read workflows conservatively.\n\n");
    }
    output.push_str("## Argument Derivation Conventions\n\n");
    output.push_str("- `observed`: Obtain identifier-like arguments from a successful prior response and retain its probe provenance.\n");
    output
        .push_str("- `declared`: Validate every argument against the cached target JSON Schema.\n");
    output.push_str(
        "- `declared`: Use the smallest useful explicit list limit and never invent IDs.\n\n",
    );
    output.push_str("## Confirmation Boundaries\n\n");
    if profile.operational_model.confirmation_boundaries.is_empty() {
        output.push_str("`declared`: No mutation-capable operation was classified in the current catalogue.\n\n");
    } else {
        for boundary in &profile.operational_model.confirmation_boundaries {
            output.push_str(&format!("- `declared`: {boundary}\n"));
        }
        output.push('\n');
    }
    output.push_str("## Verification Patterns\n\n");
    output.push_str("`declared`: After an explicitly confirmed state-changing operation, use a safe read tool to verify the intended result when one exists.\n\n");
    output.push_str("## Failure And Fallback Behavior\n\n");
    output.push_str("`declared`: If a safe probe fails, retain the uncertainty, do not retry risky tools, and use only another validated safe probe.\n\n");
    if !profile.workspace_model.contradictions.is_empty() {
        output.push_str("## Known Contradictions\n\n");
        for contradiction in &profile.workspace_model.contradictions {
            output.push_str(&format!("- `contradicted`: {}\n", contradiction.claim));
        }
        output.push('\n');
    }
    if !profile.workspace_model.uncertainties.is_empty() {
        output.push_str("## Known Uncertainties\n\n");
        for uncertainty in &profile.workspace_model.uncertainties {
            output.push_str(&format!(
                "- `unknown`: {} ({})\n",
                uncertainty.question, uncertainty.reason
            ));
        }
        output.push('\n');
    }
    output.push_str("## Examples\n\n");
    // Observation-grounded: cite real json_pointers + redacted sample values from
    // an accepted observation, not a restated tool list. When no probe was
    // accepted the profile is a stub (see `write_stub_skill`) and never reaches
    // this renderer.
    let grounded_example = profile.observations.iter().find_map(|observation| {
        observation
            .identifiers
            .first()
            .map(|identifier| (observation, identifier))
    });
    if let Some((observation, identifier)) = grounded_example {
        output.push_str(&format!(
            "`observed`: `{}` returned `{}` = `{}` at pointer `{}`. Cite it as provenance \
             (observation_id `{}`, json_pointer `{}`) to feed a later get-by-id probe — never invent one.\n\n",
            observation.tool,
            identifier.name,
            identifier.value,
            identifier.json_pointer,
            identifier.observation_id,
            identifier.json_pointer,
        ));
    } else {
        output.push_str("`unknown`: No safe end-to-end example was established.\n\n");
    }
    output.push_str("## Refreshing This Skill In The Background\n\n");
    output.push_str(
        "`user_defined`: This skill was built by a DiscoMCP profiling session. If `lookup_target` \
         misses (the catalogue fingerprint below no longer matches the live target) or this profile \
         is stale, re-profile in a BACKGROUND subagent so the user is not blocked: run `discomcp serve`, \
         then inspect_target -> execute_probe in a loop driven by each result's `gaps` report \
         (or session_status) -> stop when unexecuted_tools and untraversed_identifiers are near \
         empty or the probe budget is reached -> finalize_profile, and report the new SKILL.md path. \
         Never run mutation/side-effect/destructive/admin tools during a refresh.\n\n",
    );
    output.push_str("## Profile Freshness\n\n");
    output.push_str(&format!(
        "`observed`: Profile generated at Unix timestamp `{}` from catalogue fingerprint `{}`. Refresh before relying on long-lived assumptions.\n",
        profile.metadata.generated_at_unix_seconds, profile.metadata.target_fingerprint
    ));
    output
}

fn append_workflows(output: &mut String, operational: &OperationalModel) {
    if operational.workflows.is_empty() {
        output.push_str("`unknown`: No workflow reached the evidence threshold.\n\n");
        return;
    }
    for workflow in &operational.workflows {
        output.push_str(&format!("### {}\n\n", workflow.name));
        output.push_str(&format!(
            "`{}`: {}\n",
            evidence_label(&workflow.evidence.status),
            workflow.supported_user_intent
        ));
        for (index, step) in workflow.ordered_tool_sequence.iter().enumerate() {
            output.push_str(&format!(
                "{}. `{}`: {}\n",
                index + 1,
                step.tool,
                step.purpose
            ));
        }
        output.push('\n');
    }
}

fn render_agents(profile: &TargetProfile, output_dir: &Path) -> String {
    format!(
        "# DiscoMCP Target Instructions\n\nTarget: `{}`\nProfile: `{}`\n\nRead `SKILL.md`, `workspace-model.json`, and `operational-model.json` before operating this target.\n\n- Use only cached target tool names from `tool-catalogue.json`.\n- Validate arguments against the target schema and derive IDs from observed output.\n- Never execute mutation, external side-effect, destructive, administrative, arbitrary-execution, or unknown tools during onboarding.\n- Require explicit confirmation before any documented state-changing operation.\n- If stale or `lookup_target` misses, refresh in a BACKGROUND subagent (non-blocking): `discomcp serve`, then inspect_target -> execute_probe gap loop (guided by each result's `gaps` / session_status) -> finalize_profile, and report the new SKILL.md path. Fallback: `discomcp refresh {}`.\n- Run the generated behavioral checks from `evals.yml` after updating the profile.\n\nKnown uncertainties are in `workspace-model.json`.\n",
        profile.metadata.target_id,
        output_dir.display(),
        profile.metadata.target_id
    )
}

fn render_evals(profile: &TargetProfile) -> Result<String> {
    #[derive(Serialize)]
    struct Eval<'a> {
        name: String,
        user_request: String,
        expected_behavior: Vec<String>,
        forbidden_behavior: Vec<String>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        tools: Vec<&'a str>,
    }
    #[derive(Serialize)]
    struct Evals<'a> {
        evals: Vec<Eval<'a>>,
    }
    let evals = profile
        .operational_model
        .workflows
        .iter()
        .map(|workflow| Eval {
            name: workflow
                .name
                .to_ascii_lowercase()
                .chars()
                .map(|character| {
                    if character.is_ascii_alphanumeric() {
                        character
                    } else {
                        '_'
                    }
                })
                .collect(),
            user_request: workflow.supported_user_intent.clone(),
            expected_behavior: workflow
                .ordered_tool_sequence
                .iter()
                .map(|step| format!("select discovered tool `{}`", step.tool))
                .collect(),
            forbidden_behavior: vec![
                "invent a tool".to_string(),
                "invent an identifier".to_string(),
                "execute a mutation during onboarding".to_string(),
            ],
            tools: workflow
                .ordered_tool_sequence
                .iter()
                .map(|step| step.tool.as_str())
                .collect(),
        })
        .collect();
    serde_yaml::to_string(&Evals { evals }).map_err(Into::into)
}

fn render_onboarding_report(profile: &TargetProfile) -> String {
    let executed = profile
        .probe_log
        .iter()
        .filter(|record| record.runtime_decision.outcome == crate::model::RuntimeOutcome::Accepted)
        .count();
    let skipped = profile.probe_log.len().saturating_sub(executed);
    format!(
        "# DiscoMCP Onboarding Report\n\nTarget: `{}`\n\n- Tools discovered: {}\n- Resources discovered: {}\n- Prompts discovered: {}\n- Probes planned: {}\n- Probes executed: {}\n- Probes not executed: {}\n- Structures discovered: {}\n- Relationships inferred: {}\n- Important uncertainties: {}\n\nGenerated canonical artifacts: `workspace-model.json`, `operational-model.json`, and `SKILL.md`.\n",
        profile.metadata.target_id,
        profile.catalogue.tools.len(),
        profile.catalogue.resources.len(),
        profile.catalogue.prompts.len(),
        profile.probe_log.len(),
        executed,
        skipped,
        profile.workspace_model.structures.len(),
        profile.workspace_model.relationships.len(),
        profile.workspace_model.uncertainties.len()
    )
}

fn evidence_label(status: &EvidenceStatus) -> &'static str {
    match status {
        EvidenceStatus::Declared => "declared",
        EvidenceStatus::Documented => "documented",
        EvidenceStatus::Observed => "observed",
        EvidenceStatus::Inferred => "inferred",
        EvidenceStatus::UserDefined => "user_defined",
        EvidenceStatus::Unknown => "unknown",
        EvidenceStatus::Contradicted => "contradicted",
    }
}

/// Falls back for catalogues persisted before `risk_evidence` existed.
fn risk_evidence_label(card: &crate::model::ToolCard) -> &str {
    if card.risk_evidence.is_empty() {
        "unclassified"
    } else {
        &card.risk_evidence
    }
}

fn risk_label(risk: &crate::model::RiskClass) -> &'static str {
    match risk {
        crate::model::RiskClass::SafeRead => "safe_read",
        crate::model::RiskClass::ConstrainedRead => "constrained_read",
        crate::model::RiskClass::SensitiveRead => "sensitive_read",
        crate::model::RiskClass::PureComputation => "pure_computation",
        crate::model::RiskClass::Mutation => "mutation",
        crate::model::RiskClass::ExternalSideEffect => "external_side_effect",
        crate::model::RiskClass::Destructive => "destructive",
        crate::model::RiskClass::Administrative => "administrative",
        crate::model::RiskClass::ArbitraryExecution => "arbitrary_execution",
        crate::model::RiskClass::Unknown => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::render_skill;
    use crate::model::TargetProfile;

    /// The background-refresh section is static text, independent of the probe
    /// log / observations that `regenerate_skill` rebuilds as `default()`. So it
    /// must render identically from a default profile — the regenerate invariant.
    #[test]
    fn skill_contains_the_background_refresh_section() {
        let skill = render_skill(&TargetProfile::default());
        assert!(skill.contains("## Refreshing This Skill In The Background"));
        assert!(skill.contains("BACKGROUND subagent"));
    }
}
