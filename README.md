<div align="center">

# 🪩 DiscoMCP

**Turn an unknown MCP into a reusable, workspace-aware operational skill for AI agents.**

[![CI](https://github.com/ieranama/discomcp/actions/workflows/ci.yml/badge.svg)](https://github.com/ieranama/discomcp/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/ieranama/discomcp?label=release)](https://github.com/ieranama/discomcp/releases)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Follow-0A66C2?logo=linkedin&logoColor=white)](http://linkedin.com/in/inigo-erana/)

</div>

No agent should walk onto the dance floor blind — DiscoMCP checks the room, learns the moves, and only then cuts in.

DiscoMCP turns an unknown Model Context Protocol (MCP) connection into a reusable, workspace-aware operational skill for AI agents.

It connects to a target MCP, collects its declared capabilities and configured documentation, safely explores only permitted read or harmless computation paths, and produces a profile with a workspace-specific `SKILL.md`.

> DiscoMCP makes your agent be the one in the room you would like to dance with — not the one who shows up, starts flailing at every button on the mixing desk, and calls it improvisation. It learns the playlist first, asks before it touches the decks, and never, ever pulls the fire alarm to see what happens.

## Why DiscoMCP

An MCP tool catalogue alone does not explain how a particular user's accessible workspace is organized or which tool sequence solves a real task. DiscoMCP keeps the target catalogue internal, records evidence for every important claim, and generates an operational model that agents can use without guessing.

The result answers questions such as:

- What does this MCP expose, and what platform or data source does it represent?
- Which tools are safe to call during discovery, and which require explicit confirmation later?
- Which structures, fields, identifiers, and relationships were actually observed?
- What workflow should an agent follow to answer a user request safely?
- What remains uncertain?

## Safety Contract

DiscoMCP separates model reasoning from deterministic runtime control. A reasoning backend may propose a probe, but the runtime validates the target tool, JSON arguments, identifier provenance, policy, budgets, response limits, and redaction before any call is made.

During profiling, the runtime never automatically executes tools classified as:

- mutation
- external side effect
- destructive
- administrative
- arbitrary execution
- unknown risk

Sensitive reads are additionally constrained by the configured privacy policy. Secrets are redacted before logs, persistence, generated artifacts, and reasoning-provider requests.

## Quick Start

Prerequisites:

- Rust stable with `rustfmt` and `clippy`
- `cargo-audit` for the full local quality gate
- An MCP server you can already run locally over stdio (any newline-delimited JSON-RPC MCP server works)

Copy [examples/config.toml](examples/config.toml), point `[targets.example]` at your MCP server's command and args, then run:

```bash
git clone https://github.com/ieranama/discomcp.git
cd discomcp
cargo run -p discomcp -- profile example \
  --config ./examples/config.toml \
  --mode standard \
  --goal "Understand this MCP, safely explore my accessible workspace, and generate an operational skill"
```

For an installed binary, the equivalent command is:

```bash
discomcp profile example \
  --config ./examples/config.toml \
  --mode standard \
  --goal "Understand this MCP, safely explore my accessible workspace, and generate an operational skill"
```

Profiles are written below `.discomcp/profiles/<target-id>/`. The canonical outputs are:

- `capability-profile.json`
- `workspace-model.json`
- `operational-model.json`

`SKILL.md` and `AGENTS.md` are generated exports of that canonical state.

## Configuration

Start with [examples/config.toml](examples/config.toml). Targets are owned by DiscoMCP; it does not inherit servers from another agent host automatically. `stdio` launches a real MCP subprocess and communicates using newline-delimited JSON-RPC.

```toml
[targets.example]
transport = "stdio"
command = "npx"
args = ["-y", "example-mcp"]
docs = ["./docs/example-mcp.md"]

[targets.example.env]
EXAMPLE_API_KEY = "${EXAMPLE_API_KEY}"

[reasoning]
routing = "single"
everyday_backend = "primary"

[reasoning.backends.primary]
type = "command"
command = "some-agent-cli"
args = ["exec", "--model", "{model}"]
model = "your-configured-model"
input = "stdin_json"
output = "stdout_json"
```

The command receives one serialized `ReasoningRequest` on stdin and must emit either a `ReasoningResponse` JSON object or the raw JSON value for its `output` on stdout. No target credentials or unredacted MCP response are interpolated into the command line.

Environment interpolation fails clearly when a required variable is missing and never prints the resolved secret. Do not commit credentials, profile output containing sensitive workspace material, or `.env` files.

## Evidence

Every material claim in a generated profile carries one of these statuses:

| Status | Meaning |
| --- | --- |
| `declared` | Exposed directly through MCP metadata, schemas, or annotations. |
| `documented` | Found in configured or MCP-exposed documentation. |
| `observed` | Confirmed by a successful permitted MCP call. |
| `inferred` | Reasoned from declarations, documentation, and observations. |
| `user_defined` | Explicitly supplied by the user. |
| `unknown` | Insufficient evidence. |
| `contradicted` | Relevant sources disagree. |

Inferences include their confidence, supporting evidence, source references, and contradictions. DiscoMCP does not present an inferred relationship as an observed fact.

## Development

Run the local quality gate before opening a pull request:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
cargo audit
```

Install the audit tool once if needed:

```bash
cargo install cargo-audit --locked
```

The repository includes a generic collection-oriented mock MCP fixture so tests do not require credentials or external services.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Extension guide](docs/EXTENDING.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). By participating, you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## License

Licensed under either of

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT License](LICENSE-MIT)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in DiscoMCP by you, as defined in the Apache-2.0 license, shall be dual-licensed as above, without any additional terms or conditions.
