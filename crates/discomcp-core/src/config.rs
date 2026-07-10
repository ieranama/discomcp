use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{DiscoMcpError, Result};
use crate::model::PrivacyMode;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct DiscoMcpConfig {
    #[serde(default)]
    pub targets: BTreeMap<String, TargetConfig>,
    #[serde(default)]
    pub reasoning: ReasoningConfig,
    #[serde(default)]
    pub profiles: ProfileConfig,
    #[serde(default = "default_profile_dir")]
    pub profile_dir: PathBuf,
}

impl DiscoMcpConfig {
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let contents = fs::read_to_string(path)?;
        let mut config: Self = toml::from_str(&contents)?;
        if config.profile_dir.as_os_str().is_empty() {
            config.profile_dir = default_profile_dir();
        }
        Ok(config)
    }

    #[must_use]
    pub fn builtin_mock() -> Self {
        let mut targets = BTreeMap::new();
        targets.insert(
            "mock-collection".to_string(),
            TargetConfig {
                transport: TransportKind::Mock,
                fixture: Some("collection".to_string()),
                command: None,
                args: Vec::new(),
                docs: Vec::new(),
                env: BTreeMap::new(),
            },
        );
        Self {
            targets,
            reasoning: ReasoningConfig::mock(),
            profiles: ProfileConfig::default(),
            profile_dir: default_profile_dir(),
        }
    }

    pub fn resolve_target(&self, target_id: &str) -> Result<ResolvedTargetConfig> {
        let target = self
            .targets
            .get(target_id)
            .ok_or_else(|| DiscoMcpError::UnknownTarget(target_id.to_string()))?;
        let mut resolved_env = BTreeMap::new();
        for (key, template) in &target.env {
            resolved_env.insert(key.clone(), interpolate_environment(template, target_id)?);
        }
        Ok(ResolvedTargetConfig {
            id: target_id.to_string(),
            transport: target.transport.clone(),
            fixture: target.fixture.clone(),
            command: target.command.clone(),
            args: target
                .args
                .iter()
                .map(|value| interpolate_environment(value, target_id))
                .collect::<Result<Vec<_>>>()?,
            docs: target
                .docs
                .iter()
                .map(|value| interpolate_environment(value, target_id))
                .collect::<Result<Vec<_>>>()?,
            env: resolved_env,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ReasoningConfig {
    #[serde(default = "default_routing")]
    pub routing: String,
    #[serde(default)]
    pub everyday_backend: Option<String>,
    #[serde(default)]
    pub deep_backend: Option<String>,
    #[serde(default)]
    pub backends: BTreeMap<String, ReasoningBackendConfig>,
}

impl ReasoningConfig {
    #[must_use]
    pub fn mock() -> Self {
        let mut backends = BTreeMap::new();
        backends.insert(
            "mock".to_string(),
            ReasoningBackendConfig {
                backend_type: "mock".to_string(),
                model: Some("deterministic".to_string()),
                command: None,
                args: Vec::new(),
                input: default_reasoning_input(),
                output: default_reasoning_output(),
            },
        );
        Self {
            routing: "single".to_string(),
            everyday_backend: Some("mock".to_string()),
            deep_backend: Some("mock".to_string()),
            backends,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ReasoningBackendConfig {
    #[serde(rename = "type", default)]
    pub backend_type: String,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default = "default_reasoning_input")]
    pub input: String,
    #[serde(default = "default_reasoning_output")]
    pub output: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProfileConfig {
    #[serde(default)]
    pub privacy_mode: PrivacyMode,
}

impl Default for ProfileConfig {
    fn default() -> Self {
        Self {
            privacy_mode: PrivacyMode::Balanced,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TargetConfig {
    #[serde(default)]
    pub transport: TransportKind,
    #[serde(default)]
    pub fixture: Option<String>,
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub docs: Vec<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransportKind {
    Mock,
    #[default]
    Stdio,
    StreamableHttp,
    Sse,
}

#[derive(Clone)]
pub struct ResolvedTargetConfig {
    pub id: String,
    pub transport: TransportKind,
    pub fixture: Option<String>,
    pub command: Option<String>,
    pub args: Vec<String>,
    pub docs: Vec<String>,
    // Deliberately omit Debug so a diagnostic cannot accidentally include values.
    pub env: BTreeMap<String, String>,
}

impl std::fmt::Debug for ResolvedTargetConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ResolvedTargetConfig")
            .field("id", &self.id)
            .field("transport", &self.transport)
            .field("fixture", &self.fixture)
            .field("command", &self.command)
            .field("args", &self.args)
            .field("docs", &self.docs)
            .field("env", &"[REDACTED]")
            .finish()
    }
}

fn default_profile_dir() -> PathBuf {
    PathBuf::from(".discomcp/profiles")
}

fn default_routing() -> String {
    "single".to_string()
}

fn default_reasoning_input() -> String {
    "stdin_json".to_string()
}

fn default_reasoning_output() -> String {
    "stdout_json".to_string()
}

fn interpolate_environment(value: &str, target_id: &str) -> Result<String> {
    let mut output = String::new();
    let mut remaining = value;
    while let Some(start) = remaining.find("${") {
        output.push_str(&remaining[..start]);
        let after_start = &remaining[start + 2..];
        let Some(end) = after_start.find('}') else {
            return Err(DiscoMcpError::Config(format!(
                "target `{target_id}` has an unterminated environment placeholder"
            )));
        };
        let variable = &after_start[..end];
        if variable.is_empty() {
            return Err(DiscoMcpError::Config(format!(
                "target `{target_id}` has an empty environment placeholder"
            )));
        }
        let resolved = std::env::var(variable).map_err(|_| {
            DiscoMcpError::Config(format!(
                "Missing environment variable {variable} required by target `{target_id}`."
            ))
        })?;
        output.push_str(&resolved);
        remaining = &after_start[end + 1..];
    }
    output.push_str(remaining);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_environment_variable_never_echoes_template_value() {
        let error = interpolate_environment("prefix-${DISCOMCP_MISSING_SECRET}-suffix", "test")
            .expect_err("missing variable should fail");
        let text = error.to_string();
        assert!(text.contains("DISCOMCP_MISSING_SECRET"));
        assert!(!text.contains("prefix-"));
        assert!(!text.contains("suffix"));
    }
}
