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
                url: None,
                oauth: None,
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
        let url = target
            .url
            .as_deref()
            .map(|value| interpolate_environment(value, target_id))
            .transpose()?;
        let oauth = target
            .oauth
            .as_ref()
            .map(|oauth| resolve_oauth(oauth, target_id))
            .transpose()?;
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
            url,
            oauth,
        })
    }
}

fn resolve_oauth(oauth: &OAuthConfig, target_id: &str) -> Result<OAuthConfig> {
    let map_opt = |value: &Option<String>| -> Result<Option<String>> {
        value
            .as_deref()
            .map(|value| interpolate_environment(value, target_id))
            .transpose()
    };
    Ok(OAuthConfig {
        client_id: map_opt(&oauth.client_id)?,
        client_secret: map_opt(&oauth.client_secret)?,
        issuer: map_opt(&oauth.issuer)?,
        authorization_endpoint: map_opt(&oauth.authorization_endpoint)?,
        token_endpoint: map_opt(&oauth.token_endpoint)?,
        registration_endpoint: map_opt(&oauth.registration_endpoint)?,
        scopes: oauth
            .scopes
            .iter()
            .map(|value| interpolate_environment(value, target_id))
            .collect::<Result<Vec<_>>>()?,
        redirect_port: oauth.redirect_port,
    })
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
    /// Override the per-structure array sample cap for FULL records (objects).
    /// Kept low by default to avoid record bloat; raising it retains more full
    /// records per structure for shape inference.
    #[serde(default)]
    pub max_samples_per_structure: Option<u32>,
    /// Override the identifier/name-coverage cap. Raise it to map wide scalar
    /// collections completely (e.g. every dataset/table name in a warehouse);
    /// the mode default (250 in standard) already keeps most lists intact.
    #[serde(default)]
    pub max_identifier_coverage: Option<u32>,
}

impl Default for ProfileConfig {
    fn default() -> Self {
        Self {
            privacy_mode: PrivacyMode::Balanced,
            max_samples_per_structure: None,
            max_identifier_coverage: None,
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
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub oauth: Option<OAuthConfig>,
}

/// OAuth 2.0 client configuration for an HTTP MCP target.
///
/// Every field is optional: with none set, DiscoMCP performs full RFC 9728 /
/// RFC 8414 discovery and RFC 7591 dynamic client registration on demand. Any
/// field that is set short-circuits the corresponding discovery step.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct OAuthConfig {
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
    /// Skip protected-resource discovery when set.
    #[serde(default)]
    pub issuer: Option<String>,
    /// Skip authorization-server metadata discovery when set.
    #[serde(default)]
    pub authorization_endpoint: Option<String>,
    #[serde(default)]
    pub token_endpoint: Option<String>,
    #[serde(default)]
    pub registration_endpoint: Option<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Pin the loopback redirect port when the authorization server requires it.
    #[serde(default)]
    pub redirect_port: Option<u16>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransportKind {
    Mock,
    #[default]
    Stdio,
    #[serde(alias = "http")]
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
    pub url: Option<String>,
    // Deliberately redacted in Debug: may carry client_secret / bearer material.
    pub oauth: Option<OAuthConfig>,
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
            .field("url", &self.url)
            .field("oauth", &self.oauth.as_ref().map(|_| "[REDACTED]"))
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

    #[test]
    fn http_and_streamable_http_deserialize_to_same_variant() {
        let http: TargetConfig = toml::from_str("transport = \"http\"").expect("http parses");
        let streamable: TargetConfig =
            toml::from_str("transport = \"streamable_http\"").expect("streamable_http parses");
        assert_eq!(http.transport, TransportKind::StreamableHttp);
        assert_eq!(streamable.transport, TransportKind::StreamableHttp);
    }

    #[test]
    fn resolve_target_interpolates_url_and_oauth_fields() {
        std::env::set_var("DISCOMCP_TEST_URL", "https://mcp.example.test/mcp");
        std::env::set_var("DISCOMCP_TEST_CLIENT", "client-123");
        std::env::set_var("DISCOMCP_TEST_SCOPE", "read");
        let toml = r#"
[targets.remote]
transport = "http"
url = "${DISCOMCP_TEST_URL}"

[targets.remote.oauth]
client_id = "${DISCOMCP_TEST_CLIENT}"
scopes = ["${DISCOMCP_TEST_SCOPE}", "offline_access"]
"#;
        let config: DiscoMcpConfig = toml::from_str(toml).expect("config parses");
        let resolved = config.resolve_target("remote").expect("resolves");
        assert_eq!(
            resolved.url.as_deref(),
            Some("https://mcp.example.test/mcp")
        );
        let oauth = resolved.oauth.expect("oauth present");
        assert_eq!(oauth.client_id.as_deref(), Some("client-123"));
        assert_eq!(
            oauth.scopes,
            vec!["read".to_string(), "offline_access".to_string()]
        );
    }

    #[test]
    fn debug_redacts_oauth_secrets() {
        let resolved = ResolvedTargetConfig {
            id: "remote".to_string(),
            transport: TransportKind::StreamableHttp,
            fixture: None,
            command: None,
            args: Vec::new(),
            docs: Vec::new(),
            env: BTreeMap::new(),
            url: Some("https://mcp.example.test/mcp".to_string()),
            oauth: Some(OAuthConfig {
                client_secret: Some("super-secret-value".to_string()),
                ..Default::default()
            }),
        };
        let rendered = format!("{resolved:?}");
        assert!(rendered.contains("https://mcp.example.test/mcp"));
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains("super-secret-value"));
    }
}
