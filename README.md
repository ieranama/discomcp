<div align="center">

# 🪩 DiscoMCP

**Turn an unknown MCP server into a reusable, read-only skill your agent can actually use.**

[![CI](https://github.com/ieranama/discomcp/actions/workflows/ci.yml/badge.svg)](https://github.com/ieranama/discomcp/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/ieranama/discomcp?label=release)](https://github.com/ieranama/discomcp/releases)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Follow-0A66C2?logo=linkedin&logoColor=white)](http://linkedin.com/in/inigo-erana/)

</div>

A tool catalogue tells an agent *what* an MCP server exposes, not *how* to use it — which tools matter, which id in one response is the key to the next call, or which sequence answers a real question. So agents guess.

DiscoMCP points your agent at an MCP server, lets it explore safely, and writes a `SKILL.md` that captures how that server is actually used — grounded in what it observed, with provenance. **Exploring is read-only by construction: it never modifies anything.**

## How it works

| Step | What happens |
| --- | --- |
| **1. Inspect** | Read the server's declared tools, schemas, and docs. Nothing is called yet. |
| **2. Explore** | Run only *provably-read* probes, following identifiers from one response into the next. |
| **3. Record** | Every observation is stored with provenance — what was seen, and by which call. |
| **4. Generate** | Write `SKILL.md`: the usage playbook, the identifier hops, and each tool's safety class. |

The result is a skill your agent loads instead of walking in blind.

## Read-only, guaranteed

Exploration runs on a **default-deny gate**: a probe executes only when it is *provably* a read — the tool name is a read verb, the server marks it read-only, or (for a query tool) its argument parses as read-only SQL. A `SELECT` runs; a `DROP` on the *same* tool is rejected by inspecting the statement, not the name. A tool that merely *declares* itself safe never executes.

The runtime always rejects tools classified as mutation, external side effect, destructive, administrative, arbitrary execution, or unknown risk. Secrets are redacted before logs, artifacts, and any reasoning-provider request.

## Quick Start

Run with no install — `npx` fetches the right prebuilt binary for your platform:

```bash
npx @ieranama/discomcp --help
```

Or install the binary once (no Rust toolchain required):

```bash
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/ieranama/discomcp/releases/latest/download/discomcp-installer.sh | sh
```

Point a config at any MCP server — this is the whole file:

```toml
[targets.example]
transport = "stdio"
command = "npx"
args = ["-y", "some-mcp-server"]

[profiles]
privacy_mode = "balanced"
```

Then add DiscoMCP to your agent as a regular MCP server and let it drive:

```bash
discomcp serve --config ./discomcp.toml
```

The agent profiles through a handful of tools — `list_targets`, `lookup_target`, `inspect_target`, `execute_probe`, `finalize_profile`, `generate_skill` — and the runtime validates every probe (risk class, argument schema, identifier provenance, budgets, redaction) before anything touches the target. `lookup_target` reports whether a fresh skill already exists, so exploration only runs when the catalogue actually changed.

Profiles are written under `.discomcp/profiles/<target-id>/`; `SKILL.md` is the generated skill.

## Evidence

Every claim in a profile carries a status, so an agent never mistakes a guess for a fact:

| Status | Meaning |
| --- | --- |
| `declared` | Exposed directly through MCP metadata, schemas, or annotations. |
| `documented` | Found in configured or MCP-exposed documentation. |
| `observed` | Confirmed by a successful, permitted MCP call. |
| `inferred` | Reasoned from declarations, docs, and observations (carries confidence). |
| `user_defined` | Explicitly supplied by the user. |
| `unknown` | Insufficient evidence. |
| `contradicted` | Sources disagree. |

## Configuration

Targets are owned by DiscoMCP; it does not inherit servers from another agent host. `stdio` launches a local MCP subprocess; `http` connects to a hosted server over Streamable HTTP (with OAuth handled for you):

```toml
[targets.local]
transport = "stdio"
command = "npx"
args = ["-y", "some-mcp-server"]

[targets.local.env]
SOME_API_KEY = "${SOME_API_KEY}"

[targets.remote]
transport = "http"
url = "https://your-mcp-server.example/mcp"

[targets.remote.oauth]
scopes = ["read"]
```

Environment interpolation fails clearly when a variable is missing and never prints the resolved secret. Do not commit credentials or profile output containing sensitive workspace material.

See [examples/config.toml](examples/config.toml) for a full example, including an optional reasoning backend for running DiscoMCP standalone without an agent host.

## Development

Build from source to contribute or run an unreleased change. Prerequisites: Rust stable with `rustfmt` and `clippy`.

```bash
git clone https://github.com/ieranama/discomcp.git
cd discomcp
cargo test --all
```

Run the local quality gate before opening a pull request:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Extension guide](docs/EXTENDING.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT License](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in DiscoMCP by you, as defined in the Apache-2.0 license, shall be dual-licensed as above, without any additional terms or conditions.
