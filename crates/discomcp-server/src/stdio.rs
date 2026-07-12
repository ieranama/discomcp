//! Newline-delimited JSON-RPC stdio server for DiscoMCP.
//!
//! DiscoMCP acts as the safety runtime; an external agent is the brain. The
//! served surface is deliberately small (six tools) and every tool is backed by
//! a real core method. Target catalogues are never forwarded as tools; instead
//! `inspect_target` returns tool cards the agent reasons over, and
//! `execute_probe` enforces the full safety runtime on each agent-chosen call.

use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::path::Path;

use discomcp_core::artifacts::regenerate_skill;
use discomcp_core::model::{ArgumentProvenance, ProbeDecision, RiskClass};
use discomcp_core::policy::backstop_veto;
use discomcp_core::{DiscoMcp, ProfileOptions, ProfilingSession, Result};
use serde_json::{json, Value};
use tokio::runtime::Handle;

const PROTOCOL_VERSION: &str = "2025-06-18";

const INSTRUCTIONS: &str = "DiscoMCP is a safety runtime for profiling an unknown target MCP; \
you are the reasoning brain. Run profiling in a BACKGROUND SUBAGENT so the user's foreground work \
is never blocked. Workflow: (1) list_targets to see configured targets; (2) lookup_target — if it \
returns no existing_skill_dir (a MISS), dispatch a non-blocking background subagent to build the \
skill and continue the user's task meanwhile; (3) inspect_target to connect and start a session — \
returns tool_cards (name, description, input_schema, raw annotations, backstop_blocked), plus \
server_instructions (the MCP's own usage guidance) and documentation_urls. BEFORE probing, READ \
the docs so you explore grounded, not blind: read server_instructions, fetch any documentation_urls, \
and if the target has public official docs (e.g. the vendor's docs site), fetch and read those too \
with your own web tools. Then YOU classify each tool's risk from its card; DiscoMCP does not guess. (4) execute_probe in a loop, \
declaring your `classification` on every probe as ADVISORY evidence (it is recorded in the profile \
but never authorizes execution). DiscoMCP applies a DEFAULT-DENY read gate: a probe runs ONLY IF it is \
provably read-only — the tool name's first or last segment is a read verb \
(list/get/read/search/describe/fetch/show/view/lookup/find/count/export/download/preview/check/stat/head/query), \
OR the server annotates readOnlyHint=true, OR the tool is a query-executor whose sql/query argument is a \
read-only statement (SELECT/WITH/SHOW/DESCRIBE/EXPLAIN/PRAGMA with no write or DDL keywords). Any write-verb \
tool name or the destructive backstop rejects the probe regardless of what you declare. Each result carries a `gaps` report \
(unsampled_structures, unexecuted_tools, untraversed_identifiers, sampling_hints, depth_signal) — \
let the gaps drive the next probe: traverse an untraversed_identifier with its cited provenance, \
run an unexecuted_tool you judge read-safe, or use a sampling_hint param (orderBy/pageSize/q/filter) \
to sample smartly instead of blind first-N. For file/document/record stores (Drive, SharePoint, \
CRMs) DEFAULT TO THE MOST RECENT items — a sampling_hint's recency_params (modifiedTime/updated/ \
orderBy desc) reveal what the user is actively working on; a store can hold thousands of items, so \
profile the active surface, not the archive. Call session_status anytime for the same report \
without spending a probe. DiscoMCP enforces only a deterministic backstop (server destructiveHint, \
destructive-verb tool names, never executing a tool you did not explicitly submit) plus JSON-schema \
validation, identifier provenance, sampling limits, response-size caps, secret redaction, and the \
probe budget. Risk judgement is yours; your declarations are recorded as agent-attributed evidence \
in the profile. STOP when the gaps are sufficiently closed (unexecuted_tools and \
untraversed_identifiers near empty, or depth_signal.probes_executed approaching probe_budget) — \
DiscoMCP reports, you decide; the only hard stop is the \"MCP probe budget is exhausted\" rejection. \
(5) finalize_profile to synthesize and write the workspace model, operational model and SKILL.md, \
then report the returned skill_path back to the user. generate_skill regenerates SKILL.md from an \
existing profile directory.";

/// Runs the blocking JSON-RPC loop until stdin EOF.
pub fn run(core: DiscoMcp) -> Result<()> {
    let handle = Handle::current();
    let stdin = std::io::stdin();
    let mut out = std::io::stdout();
    let mut sessions: HashMap<String, ProfilingSession> = HashMap::new();
    for line in stdin.lock().lines() {
        let line = line?;
        let Ok(request) = serde_json::from_str::<Value>(line.trim_end()) else {
            continue; // Skip unparseable lines (stdio fixture parity).
        };
        let Some(id) = request.get("id").cloned() else {
            continue; // No id -> notification (e.g. notifications/initialized) -> ignore.
        };
        let response = dispatch(&request, id, &core, &mut sessions, &handle);
        writeln!(out, "{}", serde_json::to_string(&response)?)?;
        out.flush()?;
    }
    Ok(())
}

fn dispatch(
    request: &Value,
    id: Value,
    core: &DiscoMcp,
    sessions: &mut HashMap<String, ProfilingSession>,
    handle: &Handle,
) -> Value {
    let method = request
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default();
    match method {
        "initialize" => ok(
            id,
            json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "discomcp", "version": env!("CARGO_PKG_VERSION")},
                "instructions": INSTRUCTIONS,
            }),
        ),
        "ping" => ok(id, json!({})),
        "tools/list" => ok(id, json!({"tools": tool_definitions()})),
        "tools/call" => {
            let params = request.get("params").cloned().unwrap_or_else(|| json!({}));
            let Some(name) = params.get("name").and_then(Value::as_str) else {
                return err(id, -32602, "Invalid params: missing tool name");
            };
            let arguments = params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            match call_tool(name, &arguments, core, sessions, handle) {
                Some(result) => ok(id, result),
                None => err(id, -32602, "Invalid params: unknown tool"),
            }
        }
        _ => err(id, -32601, "Method not found"),
    }
}

fn call_tool(
    name: &str,
    arguments: &Value,
    core: &DiscoMcp,
    sessions: &mut HashMap<String, ProfilingSession>,
    handle: &Handle,
) -> Option<Value> {
    let result = match name {
        "list_targets" => tool_ok(json!({"targets": core.list_targets()})),
        "lookup_target" => handle_lookup(arguments, core, handle),
        "inspect_target" => handle_inspect(arguments, core, sessions, handle),
        "execute_probe" => handle_execute_probe(arguments, sessions, handle),
        "finalize_profile" => handle_finalize(arguments, sessions),
        "session_status" => handle_session_status(arguments, sessions),
        "generate_skill" => handle_generate_skill(arguments),
        _ => return None,
    };
    Some(result)
}

fn handle_lookup(arguments: &Value, core: &DiscoMcp, handle: &Handle) -> Value {
    let Some(target) = string_arg(arguments, "target") else {
        return tool_err("missing required `target` argument");
    };
    match handle.block_on(core.lookup(&target)) {
        Ok(result) => tool_ok(json!({
            "target_id": result.target_id,
            "catalogue_fingerprint": result.catalogue_fingerprint,
            "existing_skill_dir": result.existing_skill_dir,
        })),
        Err(error) => tool_err(&error.to_string()),
    }
}

fn handle_inspect(
    arguments: &Value,
    core: &DiscoMcp,
    sessions: &mut HashMap<String, ProfilingSession>,
    handle: &Handle,
) -> Value {
    let Some(target) = string_arg(arguments, "target") else {
        return tool_err("missing required `target` argument");
    };
    let mut options = ProfileOptions {
        goal: string_arg(arguments, "goal"),
        privacy_mode: core.config().profiles.privacy_mode.clone(),
        ..ProfileOptions::default()
    };
    let record_cap = core.config().profiles.max_samples_per_structure;
    let identifier_cap = core.config().profiles.max_identifier_coverage;
    if record_cap.is_some() || identifier_cap.is_some() {
        let mut budgets = options.effective_budgets();
        if let Some(cap) = record_cap {
            budgets.max_samples_per_structure = cap;
        }
        if let Some(cap) = identifier_cap {
            budgets.max_identifier_coverage = cap;
        }
        options.budgets = Some(budgets);
    }
    let session = match handle.block_on(core.start_session(&target, options)) {
        Ok(session) => session,
        Err(error) => return tool_err(&error.to_string()),
    };
    let catalogue = session.catalogue();
    let tool_cards = catalogue
        .tools
        .iter()
        .map(|tool| {
            json!({
                "name": tool.raw.name,
                "description": tool.raw.description,
                "input_schema": tool.raw.input_schema,
                "annotations": tool.raw.annotations,           // readOnlyHint/destructiveHint raw
                "backstop_blocked": backstop_veto(&tool.raw).is_some(), // advisory only
            })
        })
        .collect::<Vec<_>>();
    let structured = json!({
        "server_name": session.server_name(),
        "tools": catalogue
            .tools
            .iter()
            .map(|tool| tool.raw.name.clone())
            .collect::<Vec<_>>(),
        "resources": catalogue
            .resources
            .iter()
            .map(|resource| resource.name.clone())
            .collect::<Vec<_>>(),
        "prompts": catalogue
            .prompts
            .iter()
            .map(|prompt| prompt.name.clone())
            .collect::<Vec<_>>(),
        "catalogue_fingerprint": catalogue.fingerprint,
        "tool_cards": tool_cards,
        "server_instructions": session.server_instructions(),
        "documentation_urls": session.documentation_locations(),
    });
    sessions.insert(target, session);
    tool_ok(structured)
}

fn handle_execute_probe(
    arguments: &Value,
    sessions: &mut HashMap<String, ProfilingSession>,
    handle: &Handle,
) -> Value {
    let Some(target) = string_arg(arguments, "target") else {
        return tool_err("missing required `target` argument");
    };
    let Some(tool) = string_arg(arguments, "tool") else {
        return tool_err("missing required `tool` argument");
    };
    let Some(session) = sessions.get_mut(&target) else {
        return tool_err("no active session; call inspect_target first");
    };
    let probe_arguments = arguments
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let argument_provenance = arguments
        .get("provenance")
        .cloned()
        .and_then(|value| serde_json::from_value::<Vec<ArgumentProvenance>>(value).ok())
        .unwrap_or_default();
    let decision = ProbeDecision {
        selected_tool: Some(tool),
        arguments: probe_arguments,
        argument_provenance,
        objective: string_arg(arguments, "objective").unwrap_or_default(),
        declared_risk: string_arg(arguments, "classification")
            .and_then(|value| serde_json::from_value::<RiskClass>(json!(value)).ok()),
        confidence: 1.0,
        ..ProbeDecision::default()
    };
    let outcome = handle.block_on(session.execute_probe(decision));
    // Rejected/Failed are valid, expected outcomes the agent must learn from,
    // so this is never a transport error.
    tool_ok(serde_json::to_value(outcome).unwrap_or_else(|_| json!({})))
}

fn handle_finalize(arguments: &Value, sessions: &mut HashMap<String, ProfilingSession>) -> Value {
    let Some(target) = string_arg(arguments, "target") else {
        return tool_err("missing required `target` argument");
    };
    let Some(session) = sessions.remove(&target) else {
        return tool_err("no active session; call inspect_target first");
    };
    match session.finalize(string_arg(arguments, "usage_summary")) {
        Ok(result) => {
            let skill_path = result.output_dir.join("SKILL.md");
            tool_ok(json!({
                "output_dir": result.output_dir,
                "skill_path": skill_path,
                "structures": result.profile.workspace_model.structures.len(),
                "probes": result.profile.probe_log.len(),
                "observations": result.profile.observations.len(),
            }))
        }
        Err(error) => tool_err(&error.to_string()),
    }
}

fn handle_session_status(arguments: &Value, sessions: &HashMap<String, ProfilingSession>) -> Value {
    let Some(target) = string_arg(arguments, "target") else {
        return tool_err("missing required `target` argument");
    };
    let Some(session) = sessions.get(&target) else {
        return tool_err("no active session; call inspect_target first");
    };
    tool_ok(serde_json::to_value(session.gaps()).unwrap_or_else(|_| json!({})))
}

fn handle_generate_skill(arguments: &Value) -> Value {
    let Some(profile_dir) = string_arg(arguments, "profile_dir") else {
        return tool_err("missing required `profile_dir` argument");
    };
    match regenerate_skill(Path::new(&profile_dir)) {
        Ok(skill_path) => tool_ok(json!({"skill_path": skill_path})),
        Err(error) => tool_err(&error.to_string()),
    }
}

fn string_arg(arguments: &Value, key: &str) -> Option<String> {
    arguments
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn ok(id: Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn err(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

fn tool_ok(structured: Value) -> Value {
    let text = serde_json::to_string(&structured).unwrap_or_default();
    json!({
        "content": [{"type": "text", "text": text}],
        "structuredContent": structured,
        "isError": false,
    })
}

fn tool_err(message: &str) -> Value {
    json!({
        "content": [{"type": "text", "text": message}],
        "isError": true,
    })
}

fn tool_definitions() -> Value {
    json!([
        {
            "name": "list_targets",
            "description": "List target MCP ids configured in this DiscoMCP server.",
            "inputSchema": {"type": "object", "properties": {}}
        },
        {
            "name": "lookup_target",
            "description": "Check whether a DiscoMCP skill already covers this target's current declared catalogue, without probing. A MISS (no existing_skill_dir) means dispatch a BACKGROUND subagent to profile the target (inspect_target -> execute_probe gap loop -> finalize_profile) and keep working the user's task while it runs.",
            "inputSchema": {
                "type": "object",
                "required": ["target"],
                "properties": {"target": {"type": "string"}}
            }
        },
        {
            "name": "inspect_target",
            "description": "Connect to the target MCP, list its declared tools/resources/prompts, and start a profiling session. Returns tool cards (name, description, input schema, raw server annotations, backstop_blocked advisory) as raw material — YOU classify each tool's risk; DiscoMCP never keyword-guesses.",
            "inputSchema": {
                "type": "object",
                "required": ["target"],
                "properties": {
                    "target": {"type": "string"},
                    "goal": {"type": "string", "description": "Optional objective to focus exploration."}
                }
            }
        },
        {
            "name": "execute_probe",
            "description": "Validate and, if permitted, execute ONE tool call against the target. DEFAULT-DENY: a probe runs ONLY IF it is provably read-only — a read-verb tool name (list/get/read/search/...), a server readOnlyHint, or a query-executor whose sql/query argument is a read-only statement (SELECT/WITH/SHOW/DESCRIBE/EXPLAIN/PRAGMA). A write-verb tool name or the destructive backstop (server destructiveHint or destructive-verb name) rejects regardless of your declaration. Your `classification` is REQUIRED but ADVISORY — recorded as evidence, it never authorizes execution. Also enforces JSON-schema validation, identifier provenance (identifiers may not be invented — cite the observation), sampling limits, and the probe budget. Returns a redacted observation or the rejection reason. Every result includes a `gaps` report (unsampled_structures, unexecuted_tools, untraversed_identifiers, sampling_hints, depth_signal).",
            "inputSchema": {
                "type": "object",
                "required": ["target", "tool", "arguments", "classification"],
                "properties": {
                    "target": {"type": "string"},
                    "tool": {"type": "string", "description": "A tool name from inspect_target's tool_cards."},
                    "arguments": {"type": "object", "description": "Arguments for the target tool call."},
                    "classification": {"type": "string",
                        "enum": ["safe_read","constrained_read","sensitive_read","pure_computation","mutation","external_side_effect","destructive","administrative","arbitrary_execution"],
                        "description": "YOUR risk classification of this tool, judged from its name, description, input_schema and annotations. ADVISORY evidence only: recorded as agent-attributed evidence in the profile, it does NOT authorize execution. DiscoMCP runs a probe only when it is provably read-only (read-verb tool name, server readOnlyHint, or a query-executor with a read-only sql/query argument); write-verb names and the destructive backstop are rejected regardless of what you declare."},
                    "provenance": {
                        "type": "array",
                        "description": "Origin of each argument. REQUIRED for any identifier argument (id, *_id, *-id, *Id, *_uri, contains 'identifier'). Use kind \"observed\" citing the probe the identifier came from. Use \"user_defined\" ONLY for an identifier the human user explicitly supplied — never for values you invented; it is recorded as user-attributed evidence.",
                        "items": {
                            "type": "object",
                            "required": ["json_pointer", "source"],
                            "properties": {
                                "json_pointer": {"type": "string", "description": "Pointer to the argument, e.g. \"/collection_id\"."},
                                "source": {
                                    "type": "object",
                                    "required": ["kind"],
                                    "properties": {
                                        "kind": {"type": "string", "enum": ["observed", "schema_default", "enum", "user_defined", "user_goal"]},
                                        "observation_id": {"type": "string", "description": "Required when kind is \"observed\": the probe id, e.g. \"probe-001\"."},
                                        "json_pointer": {"type": "string", "description": "Required when kind is \"observed\": where in that observation the value appears."},
                                        "schema_pointer": {"type": "string", "description": "Required when kind is \"schema_default\" or \"enum\"."}
                                    }
                                }
                            }
                        }
                    },
                    "objective": {"type": "string", "description": "Optional note on what this probe is trying to learn."}
                }
            }
        },
        {
            "name": "finalize_profile",
            "description": "Synthesize the workspace model, operational model, capability profile, quality report and SKILL.md from this session's accumulated safe observations, and write the full artifact set to disk. Pass `usage_summary`: YOUR narrative of how THIS user actually uses this source, reasoned from what you observed (their saved searches, folders, tracked entities, recurring queries) — not a generic capability list. This becomes the skill's 'How You Use This MCP' section and is the whole point: the skill must let an agent exploit the MCP the way this user does. Returns skill_path to report back to the user.",
            "inputSchema": {
                "type": "object",
                "required": ["target"],
                "properties": {
                    "target": {"type": "string"},
                    "usage_summary": {"type": "string", "description": "Agent-authored: how this specific user uses this source, inferred from the observations (concrete: what they track, which tools serve their real workflow, in what order)."}
                }
            }
        },
        {
            "name": "generate_skill",
            "description": "Regenerate SKILL.md from an existing profile directory (profile-metadata.json + tool-catalogue.json + workspace-model.json + operational-model.json).",
            "inputSchema": {
                "type": "object",
                "required": ["profile_dir"],
                "properties": {"profile_dir": {"type": "string"}}
            }
        },
        {
            "name": "session_status",
            "description": "Return the current GAP REPORT for an active session, computed only from state already gathered — no target calls, no probe consumed. Reports (does not decide): unsampled_structures (collections listed but never drilled into), unexecuted_tools (unprobed tools minus backstop-blocked; you judge which are read-safe, with why_useful), untraversed_identifiers (ids seen in output but never used as a get-by-id argument, with likely_consumer_tools), sampling_hints (schema params like orderBy/pageSize/q/filter on unused tools for smart sampling), and depth_signal (raw coverage counts + probe budget). The same report rides every execute_probe result under `gaps`. You decide when coverage is enough.",
            "inputSchema": {
                "type": "object",
                "required": ["target"],
                "properties": {"target": {"type": "string"}}
            }
        }
    ])
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use discomcp_core::{DiscoMcp, DiscoMcpConfig};
    use serde_json::{json, Value};
    use tokio::runtime::Runtime;

    use super::{dispatch, ProfilingSession};

    fn dispatch_for(request: &Value) -> Value {
        let runtime = Runtime::new().expect("tokio runtime");
        let handle = runtime.handle().clone();
        let core = DiscoMcp::new(DiscoMcpConfig::builtin_mock());
        let mut sessions: HashMap<String, ProfilingSession> = HashMap::new();
        let id = request.get("id").cloned().unwrap_or(Value::Null);
        dispatch(request, id, &core, &mut sessions, &handle)
    }

    #[test]
    fn initialize_reports_server_identity_and_capabilities() {
        let response = dispatch_for(&json!({"jsonrpc": "2.0", "id": 1, "method": "initialize"}));
        assert_eq!(response["result"]["serverInfo"]["name"], "discomcp");
        assert_eq!(response["result"]["protocolVersion"], "2025-06-18");
        assert!(response["result"]["capabilities"]["tools"].is_object());
    }

    #[test]
    fn tools_list_exposes_the_backed_tools() {
        let response = dispatch_for(&json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}));
        let tools = response["result"]["tools"].as_array().expect("tools array");
        let names = tools
            .iter()
            .map(|tool| tool["name"].as_str().unwrap_or_default())
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            vec![
                "list_targets",
                "lookup_target",
                "inspect_target",
                "execute_probe",
                "finalize_profile",
                "generate_skill",
                "session_status",
            ]
        );
        assert!(tools.iter().all(|tool| tool["inputSchema"].is_object()));
    }

    #[test]
    fn unknown_method_returns_method_not_found() {
        let response =
            dispatch_for(&json!({"jsonrpc": "2.0", "id": 3, "method": "does/not/exist"}));
        assert_eq!(response["error"]["code"], -32601);
    }

    #[test]
    fn ping_returns_an_empty_result() {
        let response = dispatch_for(&json!({"jsonrpc": "2.0", "id": 4, "method": "ping"}));
        assert_eq!(response["result"], json!({}));
    }

    /// A stateful harness so a sequence of tool calls shares one session map.
    struct Harness {
        runtime: Runtime,
        core: DiscoMcp,
        sessions: HashMap<String, ProfilingSession>,
    }

    impl Harness {
        fn new() -> Self {
            Self {
                runtime: Runtime::new().expect("tokio runtime"),
                core: DiscoMcp::new(DiscoMcpConfig::builtin_mock()),
                sessions: HashMap::new(),
            }
        }

        fn call(&mut self, request: &Value) -> Value {
            let handle = self.runtime.handle().clone();
            let id = request.get("id").cloned().unwrap_or(Value::Null);
            dispatch(request, id, &self.core, &mut self.sessions, &handle)
        }

        fn tool(&mut self, id: i64, name: &str, arguments: Value) -> Value {
            self.call(&json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            }))
        }
    }

    #[test]
    fn gaps_ride_the_wire_and_traversal_shrinks_them() {
        let mut harness = Harness::new();
        harness.call(&json!({"jsonrpc": "2.0", "id": 1, "method": "initialize"}));
        let inspect = harness.tool(2, "inspect_target", json!({"target": "mock-collection"}));
        assert_eq!(inspect["result"]["isError"], false);

        // First safe read: list the collections.
        let probe = harness.tool(
            3,
            "execute_probe",
            json!({"target": "mock-collection", "tool": "list_collections", "arguments": {}}),
        );
        let gaps = probe["result"]["structuredContent"]["gaps"].clone();
        assert!(!gaps["unexecuted_tools"]
            .as_array()
            .expect("unexecuted array")
            .is_empty());
        assert!(!gaps["untraversed_identifiers"]
            .as_array()
            .expect("untraversed array")
            .is_empty());
        assert!(
            gaps["depth_signal"]["probe_budget"]
                .as_u64()
                .expect("budget")
                > 0
        );

        // session_status is a pure read: identical report, no probe consumed.
        let status = harness.tool(4, "session_status", json!({"target": "mock-collection"}));
        assert_eq!(status["result"]["isError"], false);
        assert_eq!(status["result"]["structuredContent"], gaps);

        let unexecuted_before = gaps["unexecuted_tools"].as_array().unwrap().len();
        let traversed_before = gaps["depth_signal"]["identifiers_traversed"]
            .as_u64()
            .unwrap();

        // Traverse one listed identifier via observed provenance (get-by-id).
        let traverse = harness.tool(
            5,
            "execute_probe",
            json!({
                "target": "mock-collection",
                "tool": "describe_collection",
                "arguments": {"collection_id": "projects"},
                "classification": "safe_read",
                "provenance": [{
                    "json_pointer": "/collection_id",
                    "source": {
                        "kind": "observed",
                        "observation_id": "probe-001",
                        "json_pointer": "/collections/0/id"
                    }
                }]
            }),
        );
        let after = traverse["result"]["structuredContent"]["gaps"].clone();
        assert_eq!(
            traverse["result"]["structuredContent"]["outcome"], "accepted",
            "the traversal probe must be accepted"
        );
        // Running a new safe read shrinks the unexecuted set...
        assert!(after["unexecuted_tools"].as_array().unwrap().len() < unexecuted_before);
        // ...and traversing an identifier is recorded (the shrinking proof).
        assert_eq!(
            after["depth_signal"]["identifiers_traversed"]
                .as_u64()
                .unwrap(),
            traversed_before + 1
        );
    }

    #[test]
    fn session_status_without_a_session_is_an_error() {
        let mut harness = Harness::new();
        harness.call(&json!({"jsonrpc": "2.0", "id": 1, "method": "initialize"}));
        let status = harness.tool(2, "session_status", json!({"target": "mock-collection"}));
        assert_eq!(status["result"]["isError"], true);
        let text = status["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_default();
        assert!(text.contains("no active session"));
    }

    #[test]
    fn unknown_tool_call_is_invalid_params() {
        let response = dispatch_for(&json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {"name": "no_such_tool", "arguments": {}}
        }));
        assert_eq!(response["error"]["code"], -32602);
    }
}
