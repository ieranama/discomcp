use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{json, Map, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::Mutex;

use super::{McpClient, McpError};
use crate::model::{
    default_object, PromptArgument, RawPrompt, RawResource, RawTool, ServerHandshake,
};

const PROTOCOL_VERSION: &str = "2025-06-18";
const MAX_CATALOGUE_PAGES: usize = 100;
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// An MCP client that launches and communicates with a newline-delimited stdio server.
pub struct StdioMcpClient {
    child: Mutex<Child>,
    stdin: Mutex<ChildStdin>,
    stdout: Mutex<BufReader<ChildStdout>>,
    request_lock: Mutex<()>,
    next_request_id: AtomicU64,
    request_timeout: Duration,
}

impl StdioMcpClient {
    /// Launches a configured stdio MCP server without exposing its environment values in errors.
    pub async fn spawn(
        command: &str,
        args: &[String],
        environment: &BTreeMap<String, String>,
    ) -> Result<Self, McpError> {
        let mut process = Command::new(command);
        process
            .args(args)
            .envs(environment)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true);
        let mut child = process.spawn().map_err(|error| {
            McpError::Transport(format!("failed to start target MCP process: {error}"))
        })?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| McpError::Transport("target MCP stdin was unavailable".to_string()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| McpError::Transport("target MCP stdout was unavailable".to_string()))?;
        Ok(Self {
            child: Mutex::new(child),
            stdin: Mutex::new(stdin),
            stdout: Mutex::new(BufReader::new(stdout)),
            request_lock: Mutex::new(()),
            next_request_id: AtomicU64::new(1),
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
        })
    }

    #[must_use]
    pub fn with_request_timeout(mut self, request_timeout: Duration) -> Self {
        self.request_timeout = request_timeout;
        self
    }

    async fn request(&self, method: &str, params: Value) -> Result<Value, McpError> {
        let id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        let message = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });
        tokio::time::timeout(self.request_timeout, self.request_inner(id, message))
            .await
            .map_err(|_| McpError::Transport(format!("target MCP request `{method}` timed out")))?
    }

    async fn request_inner(&self, id: u64, message: Value) -> Result<Value, McpError> {
        let _request_guard = self.request_lock.lock().await;
        self.write_message(&message).await?;
        let mut stdout = self.stdout.lock().await;
        loop {
            let mut line = String::new();
            let bytes = stdout.read_line(&mut line).await.map_err(|error| {
                McpError::Transport(format!("failed reading target MCP stdout: {error}"))
            })?;
            if bytes == 0 {
                return Err(McpError::Transport(
                    "target MCP process exited before responding".to_string(),
                ));
            }
            let message: Value = serde_json::from_str(line.trim_end()).map_err(|error| {
                McpError::Protocol(format!(
                    "target MCP wrote invalid JSON-RPC to stdout: {error}"
                ))
            })?;
            if message.get("id") != Some(&Value::from(id)) {
                continue;
            }
            if let Some(error) = message.get("error") {
                return Err(McpError::Protocol(json_rpc_error_summary(error)));
            }
            return message.get("result").cloned().ok_or_else(|| {
                McpError::Protocol("target MCP response lacked result or error".to_string())
            });
        }
    }

    async fn notification(&self, method: &str, params: Value) -> Result<(), McpError> {
        let _request_guard = self.request_lock.lock().await;
        self.write_message(&json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        }))
        .await
    }

    async fn write_message(&self, message: &Value) -> Result<(), McpError> {
        let encoded = serde_json::to_string(message).map_err(|error| {
            McpError::Protocol(format!("failed encoding JSON-RPC message: {error}"))
        })?;
        let mut stdin = self.stdin.lock().await;
        stdin.write_all(encoded.as_bytes()).await.map_err(|error| {
            McpError::Transport(format!("failed writing target MCP stdin: {error}"))
        })?;
        stdin.write_all(b"\n").await.map_err(|error| {
            McpError::Transport(format!("failed framing target MCP request: {error}"))
        })?;
        stdin.flush().await.map_err(|error| {
            McpError::Transport(format!("failed flushing target MCP stdin: {error}"))
        })
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

impl Drop for StdioMcpClient {
    fn drop(&mut self) {
        if let Ok(mut child) = self.child.try_lock() {
            let _ = child.start_kill();
        }
    }
}

#[async_trait]
impl McpClient for StdioMcpClient {
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
