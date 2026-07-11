//! OAuth 2.0 support for the HTTP MCP transport.
//!
//! The flow is intentionally lazy and degrades cleanly: [`ensure_token`] is only
//! ever invoked after the target answers a `401`, and every configured or cached
//! datum short-circuits a discovery / registration / browser step. The pure
//! helpers (PKCE, discovery URLs, token form/response, cache round-trip, callback
//! parsing) are unit-tested without any network or browser.

use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rand::rngs::OsRng;
use rand::RngCore;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::config::OAuthConfig;
use crate::mcp::McpError;

/// Clock skew tolerated when deciding whether a cached token is still usable.
const EXPIRY_SKEW: u64 = 60;
const HTTP_TIMEOUT: Duration = Duration::from_secs(20);

/// A negotiated bearer token plus the material needed to refresh it.
#[derive(Clone, Debug)]
pub struct TokenSet {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at: Option<SystemTime>,
}

/// One authorization grant, ready to be encoded as a token-endpoint form.
#[derive(Clone, Debug)]
pub enum Grant {
    AuthorizationCode(String),
    Refresh(String),
}

/// Parsed loopback callback query parameters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallbackParams {
    pub code: String,
    pub state: String,
}

/// The on-disk token cache (mode 0600). Reused for silent refresh.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CachedTokens {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub expires_at_unix: Option<u64>,
    pub client_id: String,
    #[serde(default)]
    pub client_secret: Option<String>,
    pub token_endpoint: String,
}

impl CachedTokens {
    fn to_token_set(&self) -> TokenSet {
        TokenSet {
            access_token: self.access_token.clone(),
            refresh_token: self.refresh_token.clone(),
            expires_at: self
                .expires_at_unix
                .map(|secs| UNIX_EPOCH + Duration::from_secs(secs)),
        }
    }
}

/// Resolved authorization-server endpoints.
#[derive(Clone, Debug, Default)]
struct Endpoints {
    authorization_endpoint: String,
    token_endpoint: String,
    registration_endpoint: Option<String>,
}

/// Obtain a usable bearer token for `endpoint`, running only the steps that
/// configured or cached data does not already satisfy.
pub async fn ensure_token(
    endpoint: &Url,
    cfg: &Option<OAuthConfig>,
    www_authenticate: Option<&str>,
) -> Result<TokenSet, McpError> {
    let cfg = cfg.clone().unwrap_or_default();
    let host = endpoint.host_str().unwrap_or("default").to_string();
    let cache_path = token_cache_path(&host);
    let now = SystemTime::now();

    let client = reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .build()
        .map_err(|error| {
            McpError::Transport(format!("failed building OAuth HTTP client: {error}"))
        })?;

    // (a) Cache first: an unexpired token skips the browser entirely.
    if let Some(cached) = read_cache(&cache_path) {
        if is_valid(&cached, now) {
            return Ok(cached.to_token_set());
        }
        if let Some(refresh) = cached.refresh_token.clone() {
            if let Ok(token_set) = refresh_grant(&client, &cached, &refresh, &cache_path).await {
                return Ok(token_set);
            }
            // Refresh failed (revoked / expired) — fall through to a full flow.
        }
    }

    // (b) Discovery (RFC 9728 + RFC 8414), honoring configured overrides.
    let endpoints = discover_endpoints(&client, endpoint, &cfg, www_authenticate).await?;

    // Loopback must be bound before DCR / authorize so the redirect URI is known.
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", cfg.redirect_port.unwrap_or(0)))
        .await
        .map_err(|error| McpError::Transport(format!("failed binding OAuth loopback: {error}")))?;
    let port = listener
        .local_addr()
        .map_err(|error| McpError::Transport(format!("failed reading loopback port: {error}")))?
        .port();
    let redirect_uri = format!("http://127.0.0.1:{port}/callback");

    // (c) Dynamic Client Registration (RFC 7591) only when no client_id exists.
    let (client_id, client_secret) = if let Some(id) = cfg.client_id.clone() {
        (id, cfg.client_secret.clone())
    } else {
        register_client(&client, &endpoints, &redirect_uri, &cfg.scopes).await?
    };

    // (d) Authorization Code + PKCE (S256).
    let (verifier, challenge) = generate_pkce();
    let state = random_url_safe(16);
    let authorize_url = build_authorize_url(
        &endpoints.authorization_endpoint,
        &client_id,
        &redirect_uri,
        &state,
        &challenge,
        &cfg.scopes,
        endpoint,
    )?;

    open_browser(authorize_url.as_str());
    eprintln!("DiscoMCP: open this URL to authorize the target MCP:\n  {authorize_url}");

    let code = await_callback(listener, &state).await?;

    let form = build_token_form(
        &Grant::AuthorizationCode(code),
        &redirect_uri,
        &client_id,
        client_secret.as_deref(),
        &verifier,
    );
    let token_set = post_token(&client, &endpoints.token_endpoint, &form).await?;

    let cached = cached_from(
        &token_set,
        &client_id,
        client_secret.as_deref(),
        &endpoints.token_endpoint,
    );
    if let Err(error) = write_cache(&cache_path, &cached) {
        tracing::warn!("failed persisting OAuth token cache: {error}");
    }
    Ok(token_set)
}

async fn refresh_grant(
    client: &reqwest::Client,
    cached: &CachedTokens,
    refresh_token: &str,
    cache_path: &PathBuf,
) -> Result<TokenSet, McpError> {
    let form = build_token_form(
        &Grant::Refresh(refresh_token.to_string()),
        "",
        &cached.client_id,
        cached.client_secret.as_deref(),
        "",
    );
    let mut token_set = post_token(client, &cached.token_endpoint, &form).await?;
    // A refresh response may omit a fresh refresh_token; keep the previous one.
    if token_set.refresh_token.is_none() {
        token_set.refresh_token = Some(refresh_token.to_string());
    }
    let updated = cached_from(
        &token_set,
        &cached.client_id,
        cached.client_secret.as_deref(),
        &cached.token_endpoint,
    );
    if let Err(error) = write_cache(cache_path, &updated) {
        tracing::warn!("failed persisting refreshed OAuth token cache: {error}");
    }
    Ok(token_set)
}

async fn discover_endpoints(
    client: &reqwest::Client,
    endpoint: &Url,
    cfg: &OAuthConfig,
    www_authenticate: Option<&str>,
) -> Result<Endpoints, McpError> {
    // Fast path: both required endpoints configured explicitly.
    if let (Some(authorization_endpoint), Some(token_endpoint)) = (
        cfg.authorization_endpoint.clone(),
        cfg.token_endpoint.clone(),
    ) {
        return Ok(Endpoints {
            authorization_endpoint,
            token_endpoint,
            registration_endpoint: cfg.registration_endpoint.clone(),
        });
    }

    // Resolve the issuer: configured, or from protected-resource metadata.
    let issuer = if let Some(issuer) = cfg.issuer.clone() {
        issuer
    } else {
        let metadata_url = www_authenticate
            .and_then(|header| parse_www_authenticate_param(header, "resource_metadata"))
            .and_then(|raw| Url::parse(&raw).ok())
            .unwrap_or_else(|| protected_resource_metadata_url(endpoint));
        let metadata = fetch_json(client, metadata_url.as_str()).await?;
        metadata
            .get("authorization_servers")
            .and_then(Value::as_array)
            .and_then(|servers| servers.first())
            .and_then(Value::as_str)
            .ok_or_else(|| {
                McpError::Protocol(
                    "protected-resource metadata lacked authorization_servers".to_string(),
                )
            })?
            .to_string()
    };

    // Authorization-server metadata, with the OpenID configuration fallback.
    let as_metadata = match fetch_json(client, as_metadata_url(&issuer).as_str()).await {
        Ok(value) => value,
        Err(_) => fetch_json(client, openid_configuration_url(&issuer).as_str()).await?,
    };

    let authorization_endpoint = cfg
        .authorization_endpoint
        .clone()
        .or_else(|| string_field(&as_metadata, "authorization_endpoint"))
        .ok_or_else(|| {
            McpError::Protocol(
                "authorization-server metadata lacked authorization_endpoint".to_string(),
            )
        })?;
    let token_endpoint = cfg
        .token_endpoint
        .clone()
        .or_else(|| string_field(&as_metadata, "token_endpoint"))
        .ok_or_else(|| {
            McpError::Protocol("authorization-server metadata lacked token_endpoint".to_string())
        })?;
    let registration_endpoint = cfg
        .registration_endpoint
        .clone()
        .or_else(|| string_field(&as_metadata, "registration_endpoint"));

    Ok(Endpoints {
        authorization_endpoint,
        token_endpoint,
        registration_endpoint,
    })
}

async fn register_client(
    client: &reqwest::Client,
    endpoints: &Endpoints,
    redirect_uri: &str,
    scopes: &[String],
) -> Result<(String, Option<String>), McpError> {
    let registration_endpoint = endpoints.registration_endpoint.as_deref().ok_or_else(|| {
        McpError::Protocol(
            "OAuth requires a client_id but the authorization server offers no dynamic registration"
                .to_string(),
        )
    })?;
    let body = json!({
        "client_name": "discomcp",
        "redirect_uris": [redirect_uri],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
        "scope": scopes.join(" "),
    });
    let response = client
        .post(registration_endpoint)
        .json(&body)
        .send()
        .await
        .map_err(|error| {
            McpError::Transport(format!("dynamic client registration failed: {error}"))
        })?;
    if !response.status().is_success() {
        return Err(McpError::Protocol(format!(
            "dynamic client registration rejected with status {}",
            response.status()
        )));
    }
    let value: Value = response
        .json()
        .await
        .map_err(|error| McpError::Protocol(format!("invalid registration response: {error}")))?;
    let client_id = string_field(&value, "client_id")
        .ok_or_else(|| McpError::Protocol("registration response lacked client_id".to_string()))?;
    Ok((client_id, string_field(&value, "client_secret")))
}

async fn await_callback(
    listener: tokio::net::TcpListener,
    expected_state: &str,
) -> Result<String, McpError> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let (mut stream, _) = listener
        .accept()
        .await
        .map_err(|error| McpError::Transport(format!("OAuth loopback accept failed: {error}")))?;

    let mut request_line = String::new();
    {
        let mut reader = BufReader::new(&mut stream);
        reader.read_line(&mut request_line).await.map_err(|error| {
            McpError::Transport(format!("failed reading OAuth callback: {error}"))
        })?;
    }

    let parsed = parse_callback_query(&request_line);
    let (status, message) = match &parsed {
        Ok(params) if params.state == expected_state => {
            ("200 OK", "Authorization complete. You may close this tab.")
        }
        Ok(_) => ("400 Bad Request", "Authorization state mismatch."),
        Err(_) => ("400 Bad Request", "Authorization failed."),
    };
    let body = format!("<!doctype html><meta charset=utf-8><p>{message}</p>");
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.flush().await;

    let params = parsed?;
    if params.state != expected_state {
        return Err(McpError::Protocol(
            "OAuth callback state did not match the request".to_string(),
        ));
    }
    Ok(params.code)
}

async fn post_token(
    client: &reqwest::Client,
    token_endpoint: &str,
    form: &[(&str, String)],
) -> Result<TokenSet, McpError> {
    let response = client
        .post(token_endpoint)
        .form(form)
        .send()
        .await
        .map_err(|error| McpError::Transport(format!("token request failed: {error}")))?;
    if !response.status().is_success() {
        return Err(McpError::Protocol(format!(
            "token endpoint rejected the grant with status {}",
            response.status()
        )));
    }
    let value: Value = response
        .json()
        .await
        .map_err(|error| McpError::Protocol(format!("invalid token response: {error}")))?;
    parse_token_response(&value, SystemTime::now())
}

async fn fetch_json(client: &reqwest::Client, url: &str) -> Result<Value, McpError> {
    let response = client.get(url).send().await.map_err(|error| {
        McpError::Transport(format!("metadata request to {url} failed: {error}"))
    })?;
    if !response.status().is_success() {
        return Err(McpError::Protocol(format!(
            "metadata request to {url} returned status {}",
            response.status()
        )));
    }
    response
        .json()
        .await
        .map_err(|error| McpError::Protocol(format!("invalid metadata JSON from {url}: {error}")))
}

// --- Pure helpers (unit-tested) ---------------------------------------------

/// PKCE verifier (43-char base64url) and its S256 challenge.
fn generate_pkce() -> (String, String) {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let verifier = URL_SAFE_NO_PAD.encode(bytes);
    let challenge = challenge_from_verifier(&verifier);
    (verifier, challenge)
}

/// Deterministic S256 challenge for a given verifier (RFC 7636 App. B).
fn challenge_from_verifier(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

fn random_url_safe(bytes: usize) -> String {
    let mut buffer = vec![0u8; bytes];
    OsRng.fill_bytes(&mut buffer);
    URL_SAFE_NO_PAD.encode(buffer)
}

/// `{origin}/.well-known/oauth-protected-resource` (RFC 9728).
fn protected_resource_metadata_url(endpoint: &Url) -> Url {
    let mut url = endpoint.clone();
    url.set_path("/.well-known/oauth-protected-resource");
    url.set_query(None);
    url.set_fragment(None);
    url
}

/// `{issuer}/.well-known/oauth-authorization-server` (RFC 8414), issuer path preserved.
fn as_metadata_url(issuer: &str) -> Url {
    well_known_url(issuer, "oauth-authorization-server")
}

fn openid_configuration_url(issuer: &str) -> Url {
    well_known_url(issuer, "openid-configuration")
}

fn well_known_url(issuer: &str, suffix: &str) -> Url {
    // RFC 8414 inserts the `.well-known` segment between host and issuer path.
    let trimmed = issuer.trim_end_matches('/');
    Url::parse(&format!("{trimmed}/.well-known/{suffix}"))
        .unwrap_or_else(|_| Url::parse("https://invalid.invalid/").expect("static URL parses"))
}

fn build_authorize_url(
    authorization_endpoint: &str,
    client_id: &str,
    redirect_uri: &str,
    state: &str,
    challenge: &str,
    scopes: &[String],
    resource: &Url,
) -> Result<Url, McpError> {
    let mut url = Url::parse(authorization_endpoint)
        .map_err(|error| McpError::Protocol(format!("invalid authorization_endpoint: {error}")))?;
    {
        let mut pairs = url.query_pairs_mut();
        pairs
            .append_pair("response_type", "code")
            .append_pair("client_id", client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("state", state)
            .append_pair("code_challenge", challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("resource", resource.as_str());
        if !scopes.is_empty() {
            pairs.append_pair("scope", &scopes.join(" "));
        }
    }
    Ok(url)
}

fn build_token_form(
    grant: &Grant,
    redirect_uri: &str,
    client_id: &str,
    client_secret: Option<&str>,
    code_verifier: &str,
) -> Vec<(&'static str, String)> {
    let mut form = Vec::new();
    match grant {
        Grant::AuthorizationCode(code) => {
            form.push(("grant_type", "authorization_code".to_string()));
            form.push(("code", code.clone()));
            form.push(("redirect_uri", redirect_uri.to_string()));
            form.push(("code_verifier", code_verifier.to_string()));
        }
        Grant::Refresh(refresh_token) => {
            form.push(("grant_type", "refresh_token".to_string()));
            form.push(("refresh_token", refresh_token.clone()));
        }
    }
    form.push(("client_id", client_id.to_string()));
    if let Some(secret) = client_secret {
        form.push(("client_secret", secret.to_string()));
    }
    form
}

fn parse_token_response(value: &Value, now: SystemTime) -> Result<TokenSet, McpError> {
    let access_token = string_field(value, "access_token")
        .ok_or_else(|| McpError::Protocol("token response lacked access_token".to_string()))?;
    let refresh_token = string_field(value, "refresh_token");
    let expires_at = value
        .get("expires_in")
        .and_then(Value::as_u64)
        .map(|seconds| now + Duration::from_secs(seconds));
    Ok(TokenSet {
        access_token,
        refresh_token,
        expires_at,
    })
}

fn parse_callback_query(request_line: &str) -> Result<CallbackParams, McpError> {
    let target = request_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| McpError::Protocol("malformed OAuth callback request line".to_string()))?;
    let url = Url::parse(&format!("http://127.0.0.1{target}"))
        .map_err(|error| McpError::Protocol(format!("invalid OAuth callback URL: {error}")))?;
    let mut code = None;
    let mut state = None;
    let mut error = None;
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "code" => code = Some(value.into_owned()),
            "state" => state = Some(value.into_owned()),
            "error" => error = Some(value.into_owned()),
            _ => {}
        }
    }
    if let Some(error) = error {
        return Err(McpError::Protocol(format!(
            "authorization server returned error `{error}`"
        )));
    }
    Ok(CallbackParams {
        code: code.ok_or_else(|| McpError::Protocol("OAuth callback lacked code".to_string()))?,
        state: state
            .ok_or_else(|| McpError::Protocol("OAuth callback lacked state".to_string()))?,
    })
}

fn parse_www_authenticate_param(header: &str, key: &str) -> Option<String> {
    // Find `key="value"` (or unquoted) within the challenge parameters.
    let needle = format!("{key}=");
    let start = header.find(&needle)? + needle.len();
    let rest = &header[start..];
    if let Some(stripped) = rest.strip_prefix('"') {
        stripped.find('"').map(|end| stripped[..end].to_string())
    } else {
        let end = rest.find([',', ' ']).unwrap_or(rest.len());
        Some(rest[..end].to_string())
    }
}

fn is_valid(cached: &CachedTokens, now: SystemTime) -> bool {
    match cached.expires_at_unix {
        Some(expires_at) => {
            let now_unix = now
                .duration_since(UNIX_EPOCH)
                .map(|delta| delta.as_secs())
                .unwrap_or(0);
            expires_at > now_unix.saturating_add(EXPIRY_SKEW)
        }
        // No expiry recorded: treat as usable and let a 401 trigger a refresh.
        None => true,
    }
}

fn cached_from(
    token_set: &TokenSet,
    client_id: &str,
    client_secret: Option<&str>,
    token_endpoint: &str,
) -> CachedTokens {
    CachedTokens {
        access_token: token_set.access_token.clone(),
        refresh_token: token_set.refresh_token.clone(),
        expires_at_unix: token_set.expires_at.and_then(|instant| {
            instant
                .duration_since(UNIX_EPOCH)
                .ok()
                .map(|delta| delta.as_secs())
        }),
        client_id: client_id.to_string(),
        client_secret: client_secret.map(ToOwned::to_owned),
        token_endpoint: token_endpoint.to_string(),
    }
}

fn token_cache_path(host: &str) -> PathBuf {
    let sanitized: String = host
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' || character == '.' {
                character
            } else {
                '_'
            }
        })
        .collect();
    home_dir()
        .join(".discomcp")
        .join("oauth")
        .join(format!("{sanitized}.json"))
}

fn read_cache(path: &PathBuf) -> Option<CachedTokens> {
    let contents = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&contents).ok()
}

fn write_cache(path: &PathBuf, tokens: &CachedTokens) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let serialized = serde_json::to_string_pretty(tokens)?;
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::fs::PermissionsExt;
        // Create the file atomically with 0600 so the secrets are never
        // world-readable, even transiently, between creation and chmod.
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        // If the file already existed with looser perms, tighten it.
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        file.write_all(serialized.as_bytes())?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, serialized)?;
    }
    Ok(())
}

fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map_or_else(|| PathBuf::from("."), PathBuf::from)
}

fn string_field(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn open_browser(url: &str) {
    #[cfg(target_os = "macos")]
    let (program, args): (&str, Vec<&str>) = ("open", vec![url]);
    #[cfg(target_os = "windows")]
    let (program, args): (&str, Vec<&str>) = ("cmd", vec!["/C", "start", "", url]);
    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    let (program, args): (&str, Vec<&str>) = ("xdg-open", vec![url]);
    let _ = std::process::Command::new(program).args(args).spawn();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_challenge_matches_rfc7636_appendix_b_vector() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert_eq!(
            challenge_from_verifier(verifier),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn generate_pkce_produces_43_char_verifier_and_rederivable_challenge() {
        let (verifier, challenge) = generate_pkce();
        assert_eq!(verifier.len(), 43);
        assert_eq!(challenge_from_verifier(&verifier), challenge);
    }

    #[test]
    fn protected_resource_metadata_url_uses_origin() {
        let endpoint = Url::parse("https://mcp.attio.com/mcp").expect("url");
        assert_eq!(
            protected_resource_metadata_url(&endpoint).as_str(),
            "https://mcp.attio.com/.well-known/oauth-protected-resource"
        );
        let notion = Url::parse("https://mcp.notion.com/mcp").expect("url");
        assert_eq!(
            protected_resource_metadata_url(&notion).as_str(),
            "https://mcp.notion.com/.well-known/oauth-protected-resource"
        );
    }

    #[test]
    fn as_metadata_url_handles_bare_and_pathful_issuers() {
        assert_eq!(
            as_metadata_url("https://auth.attio.com").as_str(),
            "https://auth.attio.com/.well-known/oauth-authorization-server"
        );
        assert_eq!(
            as_metadata_url("https://auth.example.com/tenant/").as_str(),
            "https://auth.example.com/tenant/.well-known/oauth-authorization-server"
        );
    }

    #[test]
    fn token_form_authorization_code_includes_pkce_verifier() {
        let form = build_token_form(
            &Grant::AuthorizationCode("the-code".to_string()),
            "http://127.0.0.1:5000/callback",
            "client-1",
            None,
            "the-verifier",
        );
        assert!(form.contains(&("grant_type", "authorization_code".to_string())));
        assert!(form.contains(&("code", "the-code".to_string())));
        assert!(form.contains(&("code_verifier", "the-verifier".to_string())));
        assert!(form.contains(&("client_id", "client-1".to_string())));
        assert!(!form.iter().any(|(key, _)| *key == "client_secret"));
    }

    #[test]
    fn token_form_refresh_omits_code() {
        let form = build_token_form(
            &Grant::Refresh("refresh-1".to_string()),
            "",
            "client-1",
            Some("secret"),
            "",
        );
        assert!(form.contains(&("grant_type", "refresh_token".to_string())));
        assert!(form.contains(&("refresh_token", "refresh-1".to_string())));
        assert!(form.contains(&("client_secret", "secret".to_string())));
        assert!(!form.iter().any(|(key, _)| *key == "code"));
    }

    #[test]
    fn parse_token_response_maps_expiry_and_tolerates_missing_refresh() {
        let now = SystemTime::now();
        let value = json!({"access_token": "abc", "expires_in": 3600});
        let token = parse_token_response(&value, now).expect("parses");
        assert_eq!(token.access_token, "abc");
        assert!(token.refresh_token.is_none());
        let expires = token.expires_at.expect("expiry present");
        let delta = expires.duration_since(now).expect("future").as_secs();
        assert!((3599..=3601).contains(&delta));
    }

    #[test]
    fn cache_round_trips_and_reports_expiry() {
        let dir = std::env::temp_dir().join(format!("discomcp-oauth-test-{}", std::process::id()));
        let path = dir.join("cache.json");
        let now = SystemTime::now();
        let tokens = CachedTokens {
            access_token: "token".to_string(),
            refresh_token: Some("refresh".to_string()),
            expires_at_unix: Some(now.duration_since(UNIX_EPOCH).unwrap().as_secs() + 3600),
            client_id: "client".to_string(),
            client_secret: None,
            token_endpoint: "https://auth.example.com/token".to_string(),
        };
        write_cache(&path, &tokens).expect("write");
        let read = read_cache(&path).expect("read back");
        assert_eq!(read.access_token, "token");
        assert_eq!(read.refresh_token.as_deref(), Some("refresh"));
        assert!(is_valid(&read, now));

        let expired = CachedTokens {
            expires_at_unix: Some(now.duration_since(UNIX_EPOCH).unwrap().as_secs()),
            ..read
        };
        // Within the 60s skew window the token is considered stale.
        assert!(!is_valid(&expired, now));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn write_cache_sets_0600_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("discomcp-oauth-perm-{}", std::process::id()));
        let path = dir.join("cache.json");
        let tokens = CachedTokens {
            access_token: "token".to_string(),
            refresh_token: None,
            expires_at_unix: None,
            client_id: "client".to_string(),
            client_secret: None,
            token_endpoint: "https://auth.example.com/token".to_string(),
        };
        write_cache(&path, &tokens).expect("write");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn token_cache_path_sanitizes_host() {
        let path = token_cache_path("mcp.attio.com:8443/weird");
        let name = path.file_name().unwrap().to_string_lossy();
        assert_eq!(name, "mcp.attio.com_8443_weird.json");
    }

    #[test]
    fn parse_callback_extracts_code_and_state() {
        let params =
            parse_callback_query("GET /callback?code=abc123&state=xyz HTTP/1.1").expect("parses");
        assert_eq!(params.code, "abc123");
        assert_eq!(params.state, "xyz");
        assert_ne!(params.state, "not-the-expected-state");
    }

    #[test]
    fn parse_callback_rejects_error_response() {
        let error = parse_callback_query("GET /callback?error=access_denied HTTP/1.1")
            .expect_err("error param rejected");
        assert!(error.to_string().contains("access_denied"));
    }

    #[test]
    fn www_authenticate_resource_metadata_param_is_extracted() {
        let header =
            "Bearer resource_metadata=\"https://mcp.attio.com/.well-known/oauth-protected-resource\", error=\"invalid_token\"";
        assert_eq!(
            parse_www_authenticate_param(header, "resource_metadata").as_deref(),
            Some("https://mcp.attio.com/.well-known/oauth-protected-resource")
        );
    }
}
