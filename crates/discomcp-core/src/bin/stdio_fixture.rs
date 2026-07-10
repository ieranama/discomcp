use std::io::{self, BufRead, Write};

use serde_json::{json, Value};

fn main() {
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    for line in stdin.lock().lines() {
        let Ok(line) = line else {
            break;
        };
        if line.trim().is_empty() {
            continue;
        }
        let request: Value = match serde_json::from_str(&line) {
            Ok(request) => request,
            Err(_) => continue,
        };
        let Some(id) = request.get("id").cloned() else {
            continue;
        };
        let response = match request.get("method").and_then(Value::as_str) {
            Some("initialize") => success(
                id,
                json!({
                    "protocolVersion": "2025-06-18",
                    "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
                    "serverInfo": {"name": "local-stdio-fixture", "version": "1.0.0"},
                    "instructions": "Use list_widgets for a bounded read-only widget sample."
                }),
            ),
            Some("tools/list") => success(
                id,
                json!({
                    "tools": [
                        {
                            "name": "list_widgets",
                            "description": "Lists a bounded read-only widget sample.",
                            "inputSchema": {
                                "type": "object",
                                "required": ["limit"],
                                "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 10}},
                                "additionalProperties": false
                            },
                            "annotations": {"readOnlyHint": true}
                        },
                        {
                            "name": "update_widget",
                            "description": "Updates a widget and changes persistent state.",
                            "inputSchema": {
                                "type": "object",
                                "required": ["widget_id", "status"],
                                "properties": {"widget_id": {"type": "string"}, "status": {"type": "string"}}
                            }
                        }
                    ]
                }),
            ),
            Some("resources/list") => success(
                id,
                json!({
                    "resources": [{
                        "uri": "docs://overview",
                        "name": "Workspace overview",
                        "description": "Fixture workspace documentation.",
                        "mimeType": "text/markdown"
                    }]
                }),
            ),
            Some("prompts/list") => success(
                id,
                json!({
                    "prompts": [{
                        "name": "explain_widget",
                        "description": "Explains an observed widget.",
                        "arguments": [{"name": "widget_id", "description": "Observed widget identifier", "required": true}]
                    }]
                }),
            ),
            Some("tools/call") => success(
                id,
                json!({
                    "content": [{"type": "text", "text": "Widget sample returned."}],
                    "structuredContent": {"widgets": [{"id": "widget-1", "status": "active"}]}
                }),
            ),
            Some("resources/read") => success(
                id,
                json!({"contents": [{"uri": "docs://overview", "text": "Widget workspace overview."}]}),
            ),
            Some("prompts/get") => success(
                id,
                json!({"messages": [{"role": "user", "content": {"type": "text", "text": "Explain widget."}}]}),
            ),
            _ => error(id, -32601, "Method not found"),
        };
        let encoded = serde_json::to_string(&response).expect("fixture response is JSON");
        writeln!(stdout, "{encoded}").expect("fixture stdout is writable");
        stdout.flush().expect("fixture stdout flushes");
    }
}

fn success(id: Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn error(id: Value, code: i32, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}
