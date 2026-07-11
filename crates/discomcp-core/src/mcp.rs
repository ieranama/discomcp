use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde_json::{json, Value};
use thiserror::Error;

use crate::model::{RawPrompt, RawResource, RawTool, ServerHandshake};

pub mod stdio;

type MockResponses = BTreeMap<String, VecDeque<Result<Value, McpError>>>;

#[derive(Clone, Debug, Error)]
pub enum McpError {
    #[error("target MCP transport error: {0}")]
    Transport(String),
    #[error("target MCP protocol error: {0}")]
    Protocol(String),
    #[error("target MCP does not support `{0}`")]
    Unsupported(String),
    #[error("target MCP does not expose tool `{0}`")]
    ToolNotFound(String),
    #[error("target MCP tool `{tool}` failed: {message}")]
    ToolFailure { tool: String, message: String },
}

#[async_trait]
pub trait McpClient: Send + Sync {
    async fn initialize(&mut self) -> Result<ServerHandshake, McpError>;
    async fn list_tools(&self) -> Result<Vec<RawTool>, McpError>;
    async fn list_resources(&self) -> Result<Vec<RawResource>, McpError>;
    async fn list_prompts(&self) -> Result<Vec<RawPrompt>, McpError>;
    async fn call_tool(&self, name: &str, arguments: Value) -> Result<Value, McpError>;
    async fn read_resource(&self, uri: &str) -> Result<Option<Value>, McpError>;
    async fn get_prompt(
        &self,
        name: &str,
        arguments: Option<Value>,
    ) -> Result<Option<Value>, McpError>;
}

#[derive(Clone, Debug, Default)]
pub struct MockCall {
    pub name: String,
    pub arguments: Value,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MockStaticCallCounts {
    pub initialize: usize,
    pub list_tools: usize,
    pub list_resources: usize,
    pub list_prompts: usize,
}

#[derive(Clone, Debug)]
pub struct MockMcpClient {
    handshake: ServerHandshake,
    tools: Vec<RawTool>,
    resources: Vec<RawResource>,
    prompts: Vec<RawPrompt>,
    responses: Arc<Mutex<MockResponses>>,
    calls: Arc<Mutex<Vec<MockCall>>>,
    initialize_calls: Arc<AtomicUsize>,
    list_tools_calls: Arc<AtomicUsize>,
    list_resources_calls: Arc<AtomicUsize>,
    list_prompts_calls: Arc<AtomicUsize>,
}

impl MockMcpClient {
    #[must_use]
    pub fn new(
        handshake: ServerHandshake,
        tools: Vec<RawTool>,
        resources: Vec<RawResource>,
        prompts: Vec<RawPrompt>,
        responses: MockResponses,
    ) -> Self {
        Self {
            handshake,
            tools,
            resources,
            prompts,
            responses: Arc::new(Mutex::new(responses)),
            calls: Arc::new(Mutex::new(Vec::new())),
            initialize_calls: Arc::new(AtomicUsize::new(0)),
            list_tools_calls: Arc::new(AtomicUsize::new(0)),
            list_resources_calls: Arc::new(AtomicUsize::new(0)),
            list_prompts_calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    #[must_use]
    pub fn calls(&self) -> Arc<Mutex<Vec<MockCall>>> {
        Arc::clone(&self.calls)
    }

    #[must_use]
    pub fn static_call_counts(&self) -> MockStaticCallCounts {
        MockStaticCallCounts {
            initialize: self.initialize_calls.load(Ordering::Relaxed),
            list_tools: self.list_tools_calls.load(Ordering::Relaxed),
            list_resources: self.list_resources_calls.load(Ordering::Relaxed),
            list_prompts: self.list_prompts_calls.load(Ordering::Relaxed),
        }
    }

    #[must_use]
    pub fn collection_fixture() -> Self {
        let tools = collection_fixture_tools();
        let mut responses = BTreeMap::new();
        responses.insert(
            "list_collections".to_string(),
            VecDeque::from([Ok(json!({
                "collections": [
                    {"id": "projects", "name": "Projects", "description": "Long-lived work initiatives"},
                    {"id": "tickets", "name": "Tickets", "description": "Trackable units of work"}
                ]
            }))]),
        );
        responses.insert(
            "describe_collection".to_string(),
            VecDeque::from([Ok(json!({
                "collection": {
                    "id": "projects",
                    "display_name": "Projects",
                    "fields": [
                        {"name": "id", "type": "string", "identifier": true},
                        {"name": "name", "type": "string"},
                        {"name": "status", "type": "enum", "values": ["active", "archived"]},
                        {"name": "owner_id", "type": "string"}
                    ]
                }
            }))]),
        );
        responses.insert(
            "list_items".to_string(),
            VecDeque::from([Ok(json!({
                "items": [
                    {"id": "project-alpha", "name": "Alpha", "status": "active", "owner_id": "member-1"},
                    {"id": "project-beta", "name": "Beta", "status": "archived", "owner_id": "member-2"}
                ],
                "next_cursor": null
            }))]),
        );
        responses.insert(
            "get_item".to_string(),
            VecDeque::from([Ok(json!({
                "item": {
                    "id": "project-alpha",
                    "name": "Alpha",
                    "status": "active",
                    "collection_id": "projects",
                    "owner": {
                        "id": "member-1",
                        "display_name": "Owner One",
                        "email": "owner@example.test",
                        "access_token": "fixture-token-that-must-never-persist"
                    }
                }
            }))]),
        );
        Self::new(
            ServerHandshake {
                server_name: "generic-collection-fixture".to_string(),
                server_version: Some("1.0.0".to_string()),
                protocol_version: Some("2025-06-18".to_string()),
                instructions: Some(
                    "This server exposes collections and collection items. Use small limits when listing items."
                        .to_string(),
                ),
                capabilities: json!({"tools": true, "resources": false, "prompts": false}),
            },
            tools,
            Vec::new(),
            Vec::new(),
            responses,
        )
    }
}

#[async_trait]
impl McpClient for MockMcpClient {
    async fn initialize(&mut self) -> Result<ServerHandshake, McpError> {
        self.initialize_calls.fetch_add(1, Ordering::Relaxed);
        Ok(self.handshake.clone())
    }

    async fn list_tools(&self) -> Result<Vec<RawTool>, McpError> {
        self.list_tools_calls.fetch_add(1, Ordering::Relaxed);
        Ok(self.tools.clone())
    }

    async fn list_resources(&self) -> Result<Vec<RawResource>, McpError> {
        self.list_resources_calls.fetch_add(1, Ordering::Relaxed);
        Ok(self.resources.clone())
    }

    async fn list_prompts(&self) -> Result<Vec<RawPrompt>, McpError> {
        self.list_prompts_calls.fetch_add(1, Ordering::Relaxed);
        Ok(self.prompts.clone())
    }

    async fn call_tool(&self, name: &str, arguments: Value) -> Result<Value, McpError> {
        self.calls
            .lock()
            .map_err(|_| McpError::Transport("mock call log lock poisoned".to_string()))?
            .push(MockCall {
                name: name.to_string(),
                arguments,
            });
        let mut responses = self
            .responses
            .lock()
            .map_err(|_| McpError::Transport("mock response lock poisoned".to_string()))?;
        let queue = responses
            .get_mut(name)
            .ok_or_else(|| McpError::ToolNotFound(name.to_string()))?;
        queue.pop_front().unwrap_or_else(|| {
            Err(McpError::ToolFailure {
                tool: name.to_string(),
                message: "fixture has no remaining response".to_string(),
            })
        })
    }

    async fn read_resource(&self, _uri: &str) -> Result<Option<Value>, McpError> {
        Ok(None)
    }

    async fn get_prompt(
        &self,
        _name: &str,
        _arguments: Option<Value>,
    ) -> Result<Option<Value>, McpError> {
        Ok(None)
    }
}

#[must_use]
pub fn collection_fixture_tools() -> Vec<RawTool> {
    vec![
        RawTool {
            name: "list_collections".to_string(),
            description: "Lists accessible collections and their stable collection identifiers. This is read-only metadata discovery."
                .to_string(),
            input_schema: json!({"type": "object", "additionalProperties": false}),
            output_schema: Some(json!({"type": "object", "properties": {"collections": {"type": "array"}}})),
            annotations: json!({"readOnlyHint": true}),
        },
        RawTool {
            name: "describe_collection".to_string(),
            description: "Returns field metadata for one collection selected by an observed collection_id. Read-only."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "required": ["collection_id"],
                "properties": {"collection_id": {"type": "string", "description": "A collection identifier returned by list_collections."}},
                "additionalProperties": false
            }),
            output_schema: Some(json!({"type": "object"})),
            annotations: json!({"readOnlyHint": true}),
        },
        RawTool {
            name: "list_items".to_string(),
            description: "Lists a bounded sample of items in one collection. Use an observed collection_id and a small limit. Read-only."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "required": ["collection_id", "limit"],
                "properties": {
                    "collection_id": {"type": "string", "description": "A collection identifier returned by list_collections."},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 100, "description": "Maximum number of items returned."},
                    "cursor": {"type": "string", "description": "Cursor from a previous list_items response."}
                },
                "additionalProperties": false
            }),
            output_schema: Some(json!({"type": "object"})),
            annotations: json!({"readOnlyHint": true}),
        },
        RawTool {
            name: "get_item".to_string(),
            description: "Gets one item by an observed stable item_id. Read-only."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "required": ["collection_id", "item_id"],
                "properties": {
                    "collection_id": {"type": "string", "description": "An observed collection identifier."},
                    "item_id": {"type": "string", "description": "An item identifier returned by list_items."}
                },
                "additionalProperties": false
            }),
            output_schema: Some(json!({"type": "object"})),
            annotations: json!({"readOnlyHint": true}),
        },
        RawTool {
            name: "create_item".to_string(),
            description: "Creates a new item in a collection and changes persistent workspace state."
                .to_string(),
            input_schema: json!({"type": "object", "required": ["collection_id", "fields"], "properties": {"collection_id": {"type": "string"}, "fields": {"type": "object"}}}),
            output_schema: None,
            annotations: json!({}),
        },
        RawTool {
            name: "delete_item".to_string(),
            description: "Permanently deletes an item from a collection. This action is destructive."
                .to_string(),
            input_schema: json!({"type": "object", "required": ["collection_id", "item_id"], "properties": {"collection_id": {"type": "string"}, "item_id": {"type": "string"}}}),
            output_schema: None,
            annotations: json!({}),
        },
    ]
}
