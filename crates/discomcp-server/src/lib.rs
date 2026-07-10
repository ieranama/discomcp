//! Stable public MCP-server surface for DiscoMCP.
//!
//! This crate deliberately defines the small interface an external agent sees.
//! It does not expose a profiled target's catalogue or forward target tools. An
//! MCP transport adapter will bind these definitions to protocol handlers in a
//! later milestone.

use discomcp_core::{DiscoMcp, DiscoMcpConfig};
use serde::{Deserialize, Serialize};

/// The stable MCP tools exposed by DiscoMCP to an external agent.
///
/// Target MCP tools remain internal. Additions to this enum are intentionally
/// non-exhaustive so external integrations can remain forward compatible.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum PublicTool {
    /// Lists target MCPs configured in DiscoMCP's independent registry.
    ListTargetMcps,
    /// Returns static discovery information for a configured target MCP.
    InspectTargetMcp,
    /// Plans a safety-validated target profiling run without executing probes.
    PlanTargetMcpProfile,
    /// Starts or completes a target MCP profiling run.
    ProfileTargetMcp,
    /// Continues a persisted target MCP profiling run.
    ContinueTargetMcpProfile,
    /// Reads a completed or in-progress target MCP profile.
    GetTargetMcpProfile,
    /// Reads the canonical workspace model for a target MCP profile.
    GetTargetWorkspaceModel,
    /// Reads the generated operational SKILL.md for a target MCP profile.
    GetGeneratedSkill,
    /// Refreshes a target MCP profile incrementally.
    RefreshTargetMcpProfile,
    /// Reads the most recent incremental profile diff.
    GetProfileDiff,
}

impl PublicTool {
    /// All public tools in stable presentation order.
    pub const ALL: [Self; 10] = [
        Self::ListTargetMcps,
        Self::InspectTargetMcp,
        Self::PlanTargetMcpProfile,
        Self::ProfileTargetMcp,
        Self::ContinueTargetMcpProfile,
        Self::GetTargetMcpProfile,
        Self::GetTargetWorkspaceModel,
        Self::GetGeneratedSkill,
        Self::RefreshTargetMcpProfile,
        Self::GetProfileDiff,
    ];

    /// The MCP-compatible tool name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ListTargetMcps => "list_target_mcps",
            Self::InspectTargetMcp => "inspect_target_mcp",
            Self::PlanTargetMcpProfile => "plan_target_mcp_profile",
            Self::ProfileTargetMcp => "profile_target_mcp",
            Self::ContinueTargetMcpProfile => "continue_target_mcp_profile",
            Self::GetTargetMcpProfile => "get_target_mcp_profile",
            Self::GetTargetWorkspaceModel => "get_target_workspace_model",
            Self::GetGeneratedSkill => "get_generated_skill",
            Self::RefreshTargetMcpProfile => "refresh_target_mcp_profile",
            Self::GetProfileDiff => "get_profile_diff",
        }
    }

    /// Finds a stable public tool by its MCP-compatible name.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|tool| tool.name() == name)
    }

    /// Metadata used by a future MCP transport implementation.
    #[must_use]
    pub const fn metadata(self) -> PublicToolMetadata {
        match self {
            Self::ListTargetMcps => PublicToolMetadata::new(
                self,
                "List configured target MCPs without exposing their internal tools.",
            ),
            Self::InspectTargetMcp => PublicToolMetadata::new(
                self,
                "Inspect cached server metadata, capabilities, and catalogue summary for a target.",
            ),
            Self::PlanTargetMcpProfile => PublicToolMetadata::new(
                self,
                "Plan a bounded, safety-validated profiling run without executing target probes.",
            ),
            Self::ProfileTargetMcp => PublicToolMetadata::new(
                self,
                "Profile a target MCP through DiscoMCP's guarded discovery and exploration runtime.",
            ),
            Self::ContinueTargetMcpProfile => PublicToolMetadata::new(
                self,
                "Continue a persisted target profiling run using its remaining budget and state.",
            ),
            Self::GetTargetMcpProfile => PublicToolMetadata::new(
                self,
                "Retrieve a target's redacted, machine-readable DiscoMCP profile.",
            ),
            Self::GetTargetWorkspaceModel => PublicToolMetadata::new(
                self,
                "Retrieve the redacted workspace model inferred for a target MCP.",
            ),
            Self::GetGeneratedSkill => PublicToolMetadata::new(
                self,
                "Retrieve the generated workspace-aware operational skill for a target MCP.",
            ),
            Self::RefreshTargetMcpProfile => PublicToolMetadata::new(
                self,
                "Refresh a target profile and regenerate only artifacts affected by detected changes.",
            ),
            Self::GetProfileDiff => PublicToolMetadata::new(
                self,
                "Retrieve the changes detected between the two most recent target profiles.",
            ),
        }
    }
}

/// Stable descriptive metadata for one externally visible DiscoMCP tool.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct PublicToolMetadata {
    /// Typed identifier for programmatic consumers.
    pub tool: PublicTool,
    /// MCP tool name.
    pub name: &'static str,
    /// Concise description suitable for an MCP tool catalogue.
    pub description: &'static str,
    /// Target catalogues are always kept private from external agents.
    pub exposes_target_catalogue: bool,
}

impl PublicToolMetadata {
    const fn new(tool: PublicTool, description: &'static str) -> Self {
        Self {
            name: tool.name(),
            tool,
            description,
            exposes_target_catalogue: false,
        }
    }
}

/// Presentation-layer metadata for the DiscoMCP MCP server.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct ToolSurfaceMetadata {
    /// Protocol-facing server name.
    pub server_name: &'static str,
    /// Package version used by the server implementation.
    pub version: &'static str,
    /// Public tools available through this presentation surface.
    pub tools: &'static [PublicToolMetadata],
}

/// A thin wrapper that reserves DiscoMCP's public MCP-server boundary.
///
/// The wrapper owns the core runtime but does not implement protocol transport,
/// request dispatch, or target-tool forwarding yet.
pub struct DiscoMcpServer {
    core: DiscoMcp,
}

impl DiscoMcpServer {
    /// Creates the server wrapper from DiscoMCP configuration.
    #[must_use]
    pub fn new(config: DiscoMcpConfig) -> Self {
        Self {
            core: DiscoMcp::new(config),
        }
    }

    /// Wraps an already configured DiscoMCP core runtime.
    #[must_use]
    pub fn from_core(core: DiscoMcp) -> Self {
        Self { core }
    }

    /// Returns the core runtime for server-side request handlers.
    #[must_use]
    pub fn core(&self) -> &DiscoMcp {
        &self.core
    }

    /// Consumes the wrapper and returns the core runtime.
    #[must_use]
    pub fn into_core(self) -> DiscoMcp {
        self.core
    }

    /// Returns stable metadata for the public tool surface.
    #[must_use]
    pub fn tool_surface() -> ToolSurfaceMetadata {
        ToolSurfaceMetadata {
            server_name: "discomcp",
            version: env!("CARGO_PKG_VERSION"),
            tools: &PUBLIC_TOOL_METADATA,
        }
    }
}

/// Stable metadata for every public DiscoMCP MCP tool.
pub static PUBLIC_TOOL_METADATA: [PublicToolMetadata; 10] = [
    PublicTool::ListTargetMcps.metadata(),
    PublicTool::InspectTargetMcp.metadata(),
    PublicTool::PlanTargetMcpProfile.metadata(),
    PublicTool::ProfileTargetMcp.metadata(),
    PublicTool::ContinueTargetMcpProfile.metadata(),
    PublicTool::GetTargetMcpProfile.metadata(),
    PublicTool::GetTargetWorkspaceModel.metadata(),
    PublicTool::GetGeneratedSkill.metadata(),
    PublicTool::RefreshTargetMcpProfile.metadata(),
    PublicTool::GetProfileDiff.metadata(),
];

#[cfg(test)]
mod tests {
    use super::{PublicTool, PUBLIC_TOOL_METADATA};

    #[test]
    fn public_surface_matches_the_stable_tool_names() {
        let names: Vec<_> = PUBLIC_TOOL_METADATA.iter().map(|tool| tool.name).collect();

        assert_eq!(names.len(), 10);
        assert_eq!(names[0], "list_target_mcps");
        assert_eq!(names[9], "get_profile_diff");
        assert!(names.iter().all(|name| !name.is_empty()));
        assert!(PUBLIC_TOOL_METADATA
            .iter()
            .all(|tool| !tool.exposes_target_catalogue));
    }

    #[test]
    fn tools_round_trip_by_name() {
        for tool in PublicTool::ALL {
            assert_eq!(PublicTool::from_name(tool.name()), Some(tool));
        }
        assert_eq!(PublicTool::from_name("target_tool"), None);
    }
}
