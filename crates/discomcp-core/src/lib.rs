//! DiscoMCP's provider-neutral, safety-first profiling core.

pub mod artifacts;
pub mod catalogue;
pub mod config;
pub mod engine;
pub mod envelope;
pub mod error;
pub mod inference;
pub mod mcp;
pub mod model;
pub mod normalization;
pub mod policy;
pub mod reasoning;
pub mod redaction;

pub use config::DiscoMcpConfig;
pub use engine::{
    DepthSignal, DiscoMcp, GapReport, ProbeOutcome, ProfilingSession, SamplingHint, UnexecutedTool,
    UnsampledStructure, UntraversedIdentifier,
};
pub use error::{DiscoMcpError, Result};
pub use model::{ProfileOptions, ProfileResult};
