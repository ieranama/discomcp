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
use discomcp_core::model::{ArgumentProvenance, ProbeDecision};
use discomcp_core::{DiscoMcp, ProfileOptions, ProfilingSession, Result};
use serde_json::{json, Value};
use tokio::runtime::Handle;

const PROTOCOL_VERSION: &str = "2025-06-18";

const INSTRUCTIONS: &str = "DiscoMCP is a safety runtime for profiling an unknown target MCP; \
you are the reasoning brain. Workflow: (1) list_targets to see configured targets; \
(2) optionally lookup_target to check for an existing skill; (3) inspect_target to connect, \
classify each tool's risk, and start a session (returns tool_cards); (4) execute_probe repeatedly \
to safely read the target — DiscoMCP enforces risk class, JSON-schema validation, identifier \
provenance, sampling limits, and the probe budget, returning a redacted observation or a rejection \
reason to learn from; (5) finalize_profile to synthesize and write the workspace model, operational \
model and SKILL.md. generate_skill regenerates SKILL.md from an existing profile directory.";

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
    let options = ProfileOptions {
        goal: string_arg(arguments, "goal"),
        privacy_mode: core.config().profiles.privacy_mode.clone(),
        ..ProfileOptions::default()
    };
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
                "risk": tool.card.risk,
                "input_schema": tool.raw.input_schema,
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
        unresolved_question: String::new(),
        expected_information: String::new(),
        expected_information_gain: 0.0,
        confidence: 1.0,
        alternatives: Vec::new(),
        stop: false,
        stop_reason: None,
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
    match session.finalize() {
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
            "description": "Check whether a DiscoMCP skill already covers this target's current declared catalogue, without probing.",
            "inputSchema": {
                "type": "object",
                "required": ["target"],
                "properties": {"target": {"type": "string"}}
            }
        },
        {
            "name": "inspect_target",
            "description": "Connect to the target MCP, list its declared tools/resources/prompts, classify each tool's risk, and start a profiling session. Returns tool cards (name, description, risk, input schema) for planning safe probes.",
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
            "description": "Validate and, if safe, execute ONE tool call against the target. DiscoMCP enforces risk class (only safe reads run), JSON-schema validation, identifier provenance (identifiers may not be invented — cite the observation they came from), sampling limits, and the probe budget. Returns a redacted observation (shape, sample, identifiers, enum values) on acceptance, or the reason it was rejected.",
            "inputSchema": {
                "type": "object",
                "required": ["target", "tool", "arguments"],
                "properties": {
                    "target": {"type": "string"},
                    "tool": {"type": "string", "description": "A tool name from inspect_target's tool_cards."},
                    "arguments": {"type": "object", "description": "Arguments for the target tool call."},
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
            "description": "Synthesize the workspace model, operational model, capability profile, quality report and SKILL.md from this session's accumulated safe observations, and write the full artifact set to disk. Deterministic — no reasoning backend needed.",
            "inputSchema": {
                "type": "object",
                "required": ["target"],
                "properties": {"target": {"type": "string"}}
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
    fn tools_list_exposes_the_six_backed_tools() {
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
