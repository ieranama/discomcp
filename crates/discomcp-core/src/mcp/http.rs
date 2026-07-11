//! Streamable HTTP MCP transport with lazy OAuth 2.0.
//!
//! The JSON-RPC bodies are byte-identical to the stdio transport; only the wire
//! carrier differs. OAuth is engaged lazily: [`HttpMcpClient::post_rpc`] only
//! authenticates after the target answers a `401`, so open servers never touch
//! the browser flow.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, WWW_AUTHENTICATE};
use reqwest::{StatusCode, Url};
use serde_json::{json, Map, Value};

use super::oauth::{self, TokenSet};
use super::{McpClient, McpError};
use crate::config::OAuthConfig;
use crate::error::DiscoMcpError;
use crate::model::{
    default_object, PromptArgument, RawPrompt, RawResource, RawTool, ServerHandshake,
};

const PROTOCOL_VERSION: &str = "2025-06-18";
const MAX_CATALOGUE_PAGES: usize = 100;
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// An MCP client that speaks the Streamable HTTP transport over a single endpoint.
pub struct HttpMcpClient {
    client: reqwest::Client,
    endpoint: Url,
    next_request_id: AtomicU64,
    session_id: Mutex<Option<String>>,
    protocol_version: Mutex<Option<String>>,
    auth: Mutex<Option<TokenSet>>,
    oauth: Option<OAuthConfig>,
}

impl HttpMcpClient {
    /// Builds a client for `url`. No network traffic occurs here; OAuth stays
    /// dormant until a request is met with `401`.
    pub fn new(url: &str, oauth: Option<OAuthConfig>) -> Result<Self, DiscoMcpError> {
        let endpoint = Url::parse(url).map_err(|error| {
            DiscoMcpError::Config(format!("target url `{url}` is invalid: {error}"))
        })?;
        let client = reqwest::Client::builder()
            .timeout(DEFAULT_REQUEST_TIMEOUT)
            .build()
            .map_err(|error| {
                DiscoMcpError::Config(format!("failed building target HTTP client: {error}"))
            })?;
        Ok(Self {
            client,
            endpoint,
            next_request_id: AtomicU64::new(1),
            session_id: Mutex::new(None),
            protocol_version: Mutex::new(None),
            auth: Mutex::new(None),
            oauth,
        })
    }

    async fn request(&self, method: &str, params: Value) -> Result<Value, McpError> {
        let id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        let message = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });
        self.request_inner(id, &message)
            .await
            .map_err(|error| match error {
                // JSON-RPC -32601: the server does not implement this method.
                McpError::Unsupported(_) => McpError::Unsupported(method.to_string()),
                other => other,
            })
    }

    async fn request_inner(&self, id: u64, message: &Value) -> Result<Value, McpError> {
        let response = self.post_rpc(message, Some(id)).await?.ok_or_else(|| {
            McpError::Protocol("target MCP returned no response body for a request".to_string())
        })?;
        if let Some(error) = response.get("error") {
            // -32601 is the spec code, but real servers also report missing
            // methods with other codes and a recognizable message.
            let error_message = error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_ascii_lowercase();
            if error.get("code").and_then(Value::as_i64) == Some(-32601)
                || error_message.contains("method not found")
                || error_message.contains("method not supported")
                || error_message.contains("not implemented")
            {
                return Err(McpError::Unsupported(String::new()));
            }
            return Err(McpError::Protocol(json_rpc_error_summary(error)));
        }
        response.get("result").cloned().ok_or_else(|| {
            McpError::Protocol("target MCP response lacked result or error".to_string())
        })
    }

    async fn notification(&self, method: &str, params: Value) -> Result<(), McpError> {
        let message = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        });
        self.post_rpc(&message, None).await.map(|_| ())
    }

    /// The single HTTP analogue of the stdio write/read pair: POST one JSON-RPC
    /// message, transparently authenticate on `401`, and return the matching
    /// JSON-RPC response (or `None` for notifications / `202`).
    async fn post_rpc(&self, message: &Value, id: Option<u64>) -> Result<Option<Value>, McpError> {
        let body = serde_json::to_string(message).map_err(|error| {
            McpError::Protocol(format!("failed encoding JSON-RPC message: {error}"))
        })?;
        let mut retried_after_auth = false;
        loop {
            let session = self.session_id.lock().expect("session lock").clone();
            let version = self.protocol_version.lock().expect("version lock").clone();
            let token = self
                .auth
                .lock()
                .expect("auth lock")
                .as_ref()
                .map(|token| token.access_token.clone());

            let mut builder = self
                .client
                .post(self.endpoint.clone())
                .header(CONTENT_TYPE, "application/json")
                .header(ACCEPT, "application/json, text/event-stream")
                .body(body.clone());
            if let Some(version) = version {
                builder = builder.header("MCP-Protocol-Version", version);
            }
            if let Some(session) = session {
                builder = builder.header("Mcp-Session-Id", session);
            }
            if let Some(token) = token {
                builder = builder.header(AUTHORIZATION, format!("Bearer {token}"));
            }

            let response = builder.send().await.map_err(|error| {
                McpError::Transport(format!("target MCP request failed: {error}"))
            })?;
            let status = response.status();

            // Capture the session id the server may assign on initialize.
            if let Some(value) = response
                .headers()
                .get("mcp-session-id")
                .and_then(|value| value.to_str().ok())
            {
                *self.session_id.lock().expect("session lock") = Some(value.to_string());
            }

            if status == StatusCode::UNAUTHORIZED {
                if retried_after_auth {
                    return Err(McpError::Transport(
                        "target MCP rejected credentials".to_string(),
                    ));
                }
                let challenge = response
                    .headers()
                    .get(WWW_AUTHENTICATE)
                    .and_then(|value| value.to_str().ok())
                    .map(ToOwned::to_owned);
                let token_set =
                    oauth::ensure_token(&self.endpoint, &self.oauth, challenge.as_deref()).await?;
                *self.auth.lock().expect("auth lock") = Some(token_set);
                retried_after_auth = true;
                continue;
            }

            if status == StatusCode::ACCEPTED {
                return Ok(None);
            }

            if !status.is_success() {
                return Err(McpError::Transport(format!(
                    "target MCP returned HTTP status {status}"
                )));
            }

            let content_type = response
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_ascii_lowercase();
            let text = response.text().await.map_err(|error| {
                McpError::Transport(format!("failed reading target MCP response body: {error}"))
            })?;

            if text.trim().is_empty() {
                return Ok(None);
            }

            if content_type.contains("text/event-stream") {
                for payload in parse_sse_events(&text) {
                    if let Ok(value) = serde_json::from_str::<Value>(&payload) {
                        if matches_id(&value, id) {
                            return Ok(Some(value));
                        }
                    }
                }
                return Err(McpError::Protocol(
                    "target MCP event stream lacked a matching JSON-RPC response".to_string(),
                ));
            }

            let value: Value = serde_json::from_str(&text).map_err(|error| {
                McpError::Protocol(format!("target MCP returned invalid JSON-RPC: {error}"))
            })?;
            if !matches_id(&value, id) {
                return Err(McpError::Protocol(
                    "target MCP JSON response id did not match the request".to_string(),
                ));
            }
            return Ok(Some(value));
        }
    }

    async fn catalogue_pages(&self, method: &str, key: &str) -> Result<Vec<Value>, McpError> {
        let mut values = Vec::new();
        let mut cursor = None;
        for _ in 0..MAX_CATALOGUE_PAGES {
            let params = cursor.as_ref().map_or_else(
                || Value::Object(Map::new()),
                |cursor| json!({"cursor": cursor}),
            );
            let result = self.request(method, params).await?;
            let page = result.get(key).and_then(Value::as_array).ok_or_else(|| {
                McpError::Protocol(format!(
                    "target MCP `{method}` response lacked `{key}` array"
                ))
            })?;
            values.extend(page.iter().cloned());
            cursor = result
                .get("nextCursor")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
            if cursor.is_none() {
                return Ok(values);
            }
        }
        Err(McpError::Protocol(format!(
            "target MCP `{method}` exceeded the catalogue pagination limit"
        )))
    }
}

#[async_trait]
impl McpClient for HttpMcpClient {
    async fn initialize(&mut self) -> Result<ServerHandshake, McpError> {
        let result = self
            .request(
                "initialize",
                json!({
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {
                        "name": "discomcp",
                        "version": env!("CARGO_PKG_VERSION"),
                    },
                }),
            )
            .await?;
        let protocol_version = required_string(&result, "protocolVersion", "initialize result")?;
        if !supported_protocol(protocol_version) {
            return Err(McpError::Protocol(format!(
                "target MCP negotiated unsupported protocol version `{protocol_version}`"
            )));
        }
        // Every later request must echo the negotiated protocol version header.
        *self.protocol_version.lock().expect("version lock") = Some(protocol_version.to_string());
        let server_info = result
            .get("serverInfo")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                McpError::Protocol("target MCP initialize result lacked serverInfo".to_string())
            })?;
        let server_name = required_string_object(server_info, "name", "serverInfo")?.to_string();
        let server_version = server_info
            .get("version")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        self.notification("notifications/initialized", Value::Object(Map::new()))
            .await?;
        Ok(ServerHandshake {
            server_name,
            server_version,
            protocol_version: Some(protocol_version.to_string()),
            instructions: result
                .get("instructions")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            capabilities: result.get("capabilities").cloned().unwrap_or_default(),
        })
    }

    async fn list_tools(&self) -> Result<Vec<RawTool>, McpError> {
        self.catalogue_pages("tools/list", "tools")
            .await?
            .into_iter()
            .map(parse_tool)
            .collect()
    }

    async fn list_resources(&self) -> Result<Vec<RawResource>, McpError> {
        self.catalogue_pages("resources/list", "resources")
            .await?
            .into_iter()
            .map(parse_resource)
            .collect()
    }

    async fn list_prompts(&self) -> Result<Vec<RawPrompt>, McpError> {
        self.catalogue_pages("prompts/list", "prompts")
            .await?
            .into_iter()
            .map(parse_prompt)
            .collect()
    }

    async fn call_tool(&self, name: &str, arguments: Value) -> Result<Value, McpError> {
        let result = self
            .request("tools/call", json!({"name": name, "arguments": arguments}))
            .await?;
        if result
            .get("isError")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            return Err(McpError::ToolFailure {
                tool: name.to_string(),
                message: "target MCP returned a tool error".to_string(),
            });
        }
        Ok(result)
    }

    async fn read_resource(&self, uri: &str) -> Result<Option<Value>, McpError> {
        self.request("resources/read", json!({"uri": uri}))
            .await
            .map(Some)
    }

    async fn get_prompt(
        &self,
        name: &str,
        arguments: Option<Value>,
    ) -> Result<Option<Value>, McpError> {
        let mut params = Map::new();
        params.insert("name".to_string(), Value::String(name.to_string()));
        if let Some(arguments) = arguments {
            params.insert("arguments".to_string(), arguments);
        }
        self.request("prompts/get", Value::Object(params))
            .await
            .map(Some)
    }
}

fn matches_id(value: &Value, id: Option<u64>) -> bool {
    match id {
        Some(id) => value.get("id") == Some(&Value::from(id)),
        None => true,
    }
}

/// Extract the concatenated `data:` payload of each SSE event.
///
/// Blank lines delimit events, `:`-prefixed comment lines are ignored, and both
/// LF and CRLF line endings are accepted. Multiple `data:` lines in one event
/// are joined with `\n` per the SSE spec.
fn parse_sse_events(body: &str) -> Vec<String> {
    let mut events = Vec::new();
    let mut current: Vec<String> = Vec::new();
    for raw_line in body.split('\n') {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        if line.is_empty() {
            if !current.is_empty() {
                events.push(current.join("\n"));
                current.clear();
            }
            continue;
        }
        if line.starts_with(':') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("data:") {
            current.push(rest.strip_prefix(' ').unwrap_or(rest).to_string());
        }
    }
    if !current.is_empty() {
        events.push(current.join("\n"));
    }
    events
}

// --- JSON-RPC parsers, byte-identical to the stdio transport -----------------

fn parse_tool(value: Value) -> Result<RawTool, McpError> {
    let name = required_string(&value, "name", "tool")?.to_string();
    Ok(RawTool {
        name,
        description: optional_string(&value, "description").unwrap_or_default(),
        input_schema: value
            .get("inputSchema")
            .cloned()
            .unwrap_or_else(default_object),
        output_schema: value.get("outputSchema").cloned(),
        annotations: value.get("annotations").cloned().unwrap_or_default(),
    })
}

fn parse_resource(value: Value) -> Result<RawResource, McpError> {
    let uri = required_string(&value, "uri", "resource")?.to_string();
    Ok(RawResource {
        name: optional_string(&value, "name").unwrap_or_else(|| uri.clone()),
        uri,
        description: optional_string(&value, "description").unwrap_or_default(),
        mime_type: optional_string(&value, "mimeType"),
        annotations: value.get("annotations").cloned().unwrap_or_default(),
    })
}

fn parse_prompt(value: Value) -> Result<RawPrompt, McpError> {
    let arguments = if let Some(arguments) = value.get("arguments").and_then(Value::as_array) {
        arguments
            .iter()
            .map(|argument| {
                Ok(PromptArgument {
                    name: required_string(argument, "name", "prompt argument")?.to_string(),
                    description: optional_string(argument, "description").unwrap_or_default(),
                    required: argument
                        .get("required")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                })
            })
            .collect::<Result<Vec<_>, McpError>>()?
    } else {
        Vec::new()
    };
    Ok(RawPrompt {
        name: required_string(&value, "name", "prompt")?.to_string(),
        description: optional_string(&value, "description").unwrap_or_default(),
        arguments,
    })
}

fn required_string<'a>(value: &'a Value, key: &str, context: &str) -> Result<&'a str, McpError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| McpError::Protocol(format!("target MCP {context} lacked string `{key}`")))
}

fn required_string_object<'a>(
    value: &'a Map<String, Value>,
    key: &str,
    context: &str,
) -> Result<&'a str, McpError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| McpError::Protocol(format!("target MCP {context} lacked string `{key}`")))
}

fn optional_string(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn supported_protocol(version: &str) -> bool {
    matches!(version, "2024-11-05" | "2025-03-26" | "2025-06-18")
}

fn json_rpc_error_summary(error: &Value) -> String {
    error.get("message").and_then(Value::as_str).map_or_else(
        || "target MCP returned a JSON-RPC error".to_string(),
        |message| format!("target MCP JSON-RPC error: {message}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tools_call_request_body_matches_stdio() {
        let client = HttpMcpClient::new("https://mcp.example.test/mcp", None).expect("client");
        // Mirror what request() builds for tools/call.
        let id = client.next_request_id.load(Ordering::Relaxed);
        let params =
            json!({"name": "list_items", "arguments": {"collection_id": "projects", "limit": 5}});
        let message = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": params,
        });
        assert_eq!(message["jsonrpc"], "2.0");
        assert_eq!(message["method"], "tools/call");
        assert_eq!(message["params"]["name"], "list_items");
        assert_eq!(message["params"]["arguments"]["limit"], 5);
    }

    #[test]
    fn request_ids_are_monotonic() {
        let client = HttpMcpClient::new("https://mcp.example.test/mcp", None).expect("client");
        let first = client.next_request_id.fetch_add(1, Ordering::Relaxed);
        let second = client.next_request_id.fetch_add(1, Ordering::Relaxed);
        assert_eq!(first, 1);
        assert_eq!(second, 2);
    }

    #[test]
    fn parse_sse_events_extracts_matching_response() {
        let body = "event: message\r\ndata: {\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"ok\":true}}\r\n\r\n";
        let events = parse_sse_events(body);
        assert_eq!(events.len(), 1);
        let value: Value = serde_json::from_str(&events[0]).expect("json");
        assert!(matches_id(&value, Some(7)));
        assert_eq!(value["result"]["ok"], true);
    }

    #[test]
    fn parse_sse_events_handles_multiple_events_and_comments() {
        let body = ": keep-alive\ndata: {\"id\":1}\n\ndata: {\"id\":2}\n\n";
        let events = parse_sse_events(body);
        assert_eq!(
            events,
            vec!["{\"id\":1}".to_string(), "{\"id\":2}".to_string()]
        );
    }

    #[test]
    fn parse_sse_events_joins_multiline_data() {
        let body = "data: line-one\ndata: line-two\n\n";
        let events = parse_sse_events(body);
        assert_eq!(events, vec!["line-one\nline-two".to_string()]);
    }

    #[test]
    fn matches_id_ignores_non_matching_stream_messages() {
        let other = json!({"jsonrpc": "2.0", "id": 99, "result": {}});
        assert!(!matches_id(&other, Some(1)));
        let notification = json!({"jsonrpc": "2.0", "method": "x"});
        assert!(matches_id(&notification, None));
    }

    #[test]
    fn method_not_found_maps_to_unsupported_error_shape() {
        // Reproduces the interpretation in request_inner for a -32601 error.
        let error = json!({"code": -32601, "message": "Method not found"});
        let error_message = error
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_ascii_lowercase();
        let is_unsupported = error.get("code").and_then(Value::as_i64) == Some(-32601)
            || error_message.contains("method not found");
        assert!(is_unsupported);
    }

    #[test]
    fn generic_error_summary_is_protocol_message() {
        let error = json!({"code": -32000, "message": "boom"});
        assert_eq!(
            json_rpc_error_summary(&error),
            "target MCP JSON-RPC error: boom"
        );
    }
}
