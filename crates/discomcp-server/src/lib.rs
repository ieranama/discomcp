//! Newline-delimited JSON-RPC stdio MCP server for DiscoMCP.
//!
//! This crate defines the small interface an external agent sees. It does not
//! expose a profiled target's catalogue or forward target tools.

use discomcp_core::{DiscoMcp, DiscoMcpConfig, DiscoMcpError};

mod stdio;

/// Runs the newline-delimited JSON-RPC stdio MCP server until stdin reaches
/// EOF. The blocking read loop runs on a dedicated blocking thread and bridges
/// to the async core through the current Tokio runtime handle.
pub async fn serve_stdio(config: DiscoMcpConfig) -> discomcp_core::Result<()> {
    let core = DiscoMcp::new(config);
    tokio::task::spawn_blocking(move || stdio::run(core))
        .await
        .map_err(|error| {
            DiscoMcpError::Config(format!("stdio server task failed to join: {error}"))
        })?
}
