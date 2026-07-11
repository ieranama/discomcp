//! End-to-end test: drive the built `discomcp serve` binary as a scripted MCP
//! client over newline-delimited JSON-RPC on stdio, against the credential-free
//! builtin mock target.

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

use serde_json::{json, Value};

/// Locates the sibling `discomcp` binary next to this test executable, building
/// it on demand. `cargo test --all` does not itself produce the CLI executable
/// artifact (an integration test in another crate does not depend on it), so we
/// build it explicitly when it is absent.
fn discomcp_binary() -> PathBuf {
    let mut dir = std::env::current_exe().expect("current test executable path");
    dir.pop(); // drop the test binary file name
    if dir.ends_with("deps") {
        dir.pop(); // step out of the deps directory
    }
    let binary = dir.join(if cfg!(windows) {
        "discomcp.exe"
    } else {
        "discomcp"
    });
    if !binary.exists() {
        let status = Command::new(env!("CARGO"))
            .args(["build", "-p", "discomcp"])
            .status()
            .expect("run cargo build -p discomcp");
        assert!(status.success(), "cargo build -p discomcp failed");
    }
    binary
}

fn send(stdin: &mut impl Write, message: &Value) {
    let line = serde_json::to_string(message).expect("serialize request");
    writeln!(stdin, "{line}").expect("write request line");
    stdin.flush().expect("flush request");
}

fn recv_matching_id(reader: &mut impl BufRead, id: i64) -> Value {
    loop {
        let mut line = String::new();
        let read = reader.read_line(&mut line).expect("read response line");
        assert!(read != 0, "server closed before responding to id {id}");
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let value: Value = serde_json::from_str(trimmed).expect("parse response JSON");
        if value.get("id").and_then(Value::as_i64) == Some(id) {
            return value;
        }
    }
}

fn call(name: &str, arguments: Value, id: i64) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments}
    })
}

#[test]
fn serve_stdio_drives_a_full_profiling_session() {
    let temp = std::env::temp_dir().join(format!(
        "discomcp-serve-stdio-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default()
    ));
    std::fs::create_dir_all(&temp).expect("create temp dir");
    let profile_dir = temp.join("profiles");
    let config_path = temp.join("config.toml");
    std::fs::write(
        &config_path,
        format!(
            "profile_dir = {:?}\n\n[targets.mock]\ntransport = \"mock\"\nfixture = \"collection\"\n",
            profile_dir
        ),
    )
    .expect("write config");

    let mut child = Command::new(discomcp_binary())
        .arg("serve")
        .arg("--config")
        .arg(&config_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn `discomcp serve`");
    let mut stdin = child.stdin.take().expect("child stdin");
    let mut reader = BufReader::new(child.stdout.take().expect("child stdout"));

    // 1. initialize
    send(
        &mut stdin,
        &json!({"jsonrpc": "2.0", "id": 1, "method": "initialize"}),
    );
    let init = recv_matching_id(&mut reader, 1);
    assert_eq!(init["result"]["serverInfo"]["name"], "discomcp");

    // 2. a notification is ignored (no response), while a following ping is answered.
    send(
        &mut stdin,
        &json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    );
    send(
        &mut stdin,
        &json!({"jsonrpc": "2.0", "id": 2, "method": "ping"}),
    );
    let pong = recv_matching_id(&mut reader, 2);
    assert_eq!(pong["result"], json!({}));

    // 3. tools/list contains the core profiling tools.
    send(
        &mut stdin,
        &json!({"jsonrpc": "2.0", "id": 3, "method": "tools/list"}),
    );
    let list = recv_matching_id(&mut reader, 3);
    let names = list["result"]["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .map(|tool| tool["name"].as_str().unwrap_or_default().to_string())
        .collect::<Vec<_>>();
    for expected in ["inspect_target", "execute_probe", "finalize_profile"] {
        assert!(
            names.iter().any(|name| name == expected),
            "missing {expected}"
        );
    }

    // 4. list_targets surfaces the configured mock target.
    let targets = recv_after(&mut stdin, &mut reader, call("list_targets", json!({}), 4));
    let target_ids = targets["result"]["structuredContent"]["targets"]
        .as_array()
        .expect("targets array");
    assert!(target_ids.iter().any(|target| target == "mock"));

    // 5. inspect_target starts a session and returns tool cards.
    let inspect = recv_after(
        &mut stdin,
        &mut reader,
        call("inspect_target", json!({"target": "mock"}), 5),
    );
    let cards = inspect["result"]["structuredContent"]["tool_cards"]
        .as_array()
        .expect("tool_cards array");
    assert!(!cards.is_empty());
    // Cards are raw material for the agent's own classification: annotations
    // and a backstop advisory, never a Rust-guessed risk.
    for card in cards {
        assert!(card.get("risk").is_none(), "risk must not ride the wire");
        assert!(card.get("annotations").is_some());
        assert!(card["backstop_blocked"].is_boolean());
    }

    // 6. an agent-declared read probe is accepted and returns a redacted observation.
    let probe = recv_after(
        &mut stdin,
        &mut reader,
        call(
            "execute_probe",
            json!({"target": "mock", "tool": "list_collections", "arguments": {}, "classification": "safe_read", "provenance": []}),
            6,
        ),
    );
    let observed = &probe["result"]["structuredContent"];
    assert_eq!(observed["outcome"], "accepted");
    assert!(observed["observation"].is_object());
    assert!(observed["observation"]["shape"].is_object());
    assert!(observed["observation"].get("sample").is_some());

    // 7. an undeclared mutating probe is rejected by the safety runtime.
    let mutating = recv_after(
        &mut stdin,
        &mut reader,
        call(
            "execute_probe",
            json!({
                "target": "mock",
                "tool": "create_item",
                "arguments": {"collection_id": "projects", "fields": {}},
                "provenance": []
            }),
            7,
        ),
    );
    let rejected = &mutating["result"]["structuredContent"];
    assert_eq!(rejected["outcome"], "rejected");
    assert!(rejected["reason"]
        .as_str()
        .expect("reason string")
        .to_ascii_lowercase()
        .contains("risk"));

    // 8. a destructive-named tool is backstopped even when the agent falsely
    // declares it a read.
    let backstopped = recv_after(
        &mut stdin,
        &mut reader,
        call(
            "execute_probe",
            json!({
                "target": "mock",
                "tool": "delete_item",
                "arguments": {"collection_id": "projects", "item_id": "x"},
                "classification": "safe_read",
                "provenance": []
            }),
            8,
        ),
    );
    let vetoed = &backstopped["result"]["structuredContent"];
    assert_eq!(vetoed["outcome"], "rejected");
    assert!(vetoed["reason"]
        .as_str()
        .expect("reason string")
        .contains("backstop"));

    // 9. finalize writes the artifact set to disk.
    let finalized = recv_after(
        &mut stdin,
        &mut reader,
        call("finalize_profile", json!({"target": "mock"}), 9),
    );
    let output_dir = finalized["result"]["structuredContent"]["output_dir"]
        .as_str()
        .expect("output_dir string");
    assert!(std::path::Path::new(output_dir).join("SKILL.md").exists());

    // 10. closing stdin lets the server reach EOF and exit cleanly.
    drop(stdin);
    let status = child.wait().expect("await child exit");
    assert!(status.success(), "server should exit cleanly on stdin EOF");

    let _ = std::fs::remove_dir_all(&temp);
}

fn recv_after(stdin: &mut impl Write, reader: &mut impl BufRead, request: Value) -> Value {
    let id = request["id"].as_i64().expect("request id");
    send(stdin, &request);
    recv_matching_id(reader, id)
}
