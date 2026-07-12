use std::collections::BTreeMap;

use discomcp_core::config::{ReasoningBackendConfig, ReasoningConfig, TargetConfig, TransportKind};
use discomcp_core::mcp::stdio::StdioMcpClient;
use discomcp_core::mcp::McpClient;
use discomcp_core::{DiscoMcp, DiscoMcpConfig, ProfileOptions};
use serde_json::json;

#[tokio::test]
async fn stdio_client_completes_lifecycle_and_standard_operations() {
    let command = env!("CARGO_BIN_EXE_stdio_fixture").to_string();
    let mut client = StdioMcpClient::spawn(&command, &[], &BTreeMap::new())
        .await
        .expect("fixture should start");
    let handshake = client.initialize().await.expect("initialize succeeds");
    assert_eq!(handshake.server_name, "local-stdio-fixture");
    assert_eq!(handshake.protocol_version.as_deref(), Some("2025-06-18"));

    let tools = client.list_tools().await.expect("tools list succeeds");
    assert_eq!(tools.len(), 2);
    assert_eq!(tools[0].name, "list_widgets");
    let resources = client
        .list_resources()
        .await
        .expect("resources list succeeds");
    assert_eq!(resources[0].uri, "docs://overview");
    let prompts = client.list_prompts().await.expect("prompts list succeeds");
    assert_eq!(prompts[0].name, "explain_widget");

    let result = client
        .call_tool("list_widgets", json!({"limit": 1}))
        .await
        .expect("tool call succeeds");
    assert_eq!(result["structuredContent"]["widgets"][0]["id"], "widget-1");
    assert!(client
        .read_resource("docs://overview")
        .await
        .expect("resource read succeeds")
        .is_some());
    assert!(client
        .get_prompt("explain_widget", Some(json!({"widget_id": "widget-1"})))
        .await
        .expect("prompt get succeeds")
        .is_some());
}

#[tokio::test]
async fn configured_stdio_target_uses_the_real_transport_for_inspection() {
    let mut config = DiscoMcpConfig::default();
    config.targets.insert(
        "local".to_string(),
        TargetConfig {
            transport: TransportKind::Stdio,
            fixture: None,
            command: Some(env!("CARGO_BIN_EXE_stdio_fixture").to_string()),
            args: Vec::new(),
            docs: Vec::new(),
            env: BTreeMap::new(),
            url: None,
            oauth: None,
        },
    );
    let inspection = DiscoMcp::new(config)
        .inspect("local")
        .await
        .expect("configured stdio inspection succeeds");
    assert_eq!(inspection.server_name, "local-stdio-fixture");
    assert_eq!(inspection.tools, 2);
    assert_eq!(inspection.resources, 1);
    assert_eq!(inspection.prompts, 1);
}

#[tokio::test]
async fn configured_stdio_target_profiles_with_a_command_reasoning_backend() {
    let mut config = DiscoMcpConfig::default();
    config.targets.insert(
        "local".to_string(),
        TargetConfig {
            transport: TransportKind::Stdio,
            fixture: None,
            command: Some(env!("CARGO_BIN_EXE_stdio_fixture").to_string()),
            args: Vec::new(),
            docs: Vec::new(),
            env: BTreeMap::new(),
            url: None,
            oauth: None,
        },
    );
    config.reasoning = ReasoningConfig {
        routing: "single".to_string(),
        everyday_backend: Some("fixture".to_string()),
        deep_backend: None,
        backends: BTreeMap::from([(
            "fixture".to_string(),
            ReasoningBackendConfig {
                backend_type: "command".to_string(),
                model: Some("fixture".to_string()),
                command: Some(env!("CARGO_BIN_EXE_reasoning_fixture").to_string()),
                args: Vec::new(),
                input: "stdin_json".to_string(),
                output: "stdout_json".to_string(),
            },
        )]),
    };
    let output = std::env::temp_dir().join(format!(
        "discomcp-real-stdio-profile-{}",
        std::process::id()
    ));
    let result = DiscoMcp::new(config)
        .profile(
            "local",
            ProfileOptions {
                output_dir: Some(output.clone()),
                ..ProfileOptions::default()
            },
        )
        .await
        .expect("configured real stdio profile succeeds");
    assert!(output.join("SKILL.md").exists());
    assert!(result
        .profile
        .probe_log
        .iter()
        .any(|probe| probe.runtime_decision.outcome
            == discomcp_core::model::RuntimeOutcome::Accepted));
    assert!(result
        .profile
        .workspace_model
        .structures
        .iter()
        .any(|structure| structure.normalized_name.ends_with("widgets")));
    let _ = std::fs::remove_dir_all(output);
}
