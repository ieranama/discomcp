use std::path::PathBuf;

use thiserror::Error;

use crate::mcp::McpError;

#[derive(Debug, Error)]
pub enum DiscoMcpError {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("target `{0}` was not found in the DiscoMCP registry")]
    UnknownTarget(String),
    #[error("target `{target}` uses unsupported transport `{transport}`")]
    UnsupportedTransport { target: String, transport: String },
    #[error("MCP error: {0}")]
    Mcp(#[from] McpError),
    #[error("reasoning backend error: {0}")]
    Reasoning(String),
    #[error("probe rejected: {0}")]
    ProbeRejected(String),
    #[error("schema validation failed: {0}")]
    SchemaValidation(String),
    #[error("artifact error at `{path}`: {source}")]
    Artifact {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("TOML error: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("YAML error: {0}")]
    Yaml(#[from] serde_yaml::Error),
}

pub type Result<T, E = DiscoMcpError> = std::result::Result<T, E>;
