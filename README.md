<div align="center">

# 🪩 DiscoMCP

**Your agent, meet your tools.**

Give any AI agent a real, safe understanding of the tools it connects to — in one command.

[![CI](https://github.com/ieranama/discomcp/actions/workflows/ci.yml/badge.svg)](https://github.com/ieranama/discomcp/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/ieranama/discomcp?label=release)](https://github.com/ieranama/discomcp/releases)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Follow-0A66C2?logo=linkedin&logoColor=white)](http://linkedin.com/in/inigo-erana/)

</div>

Agents are great at code. They get lost inside your tools — they don't know which of a hundred actions matter, how your data connects, or what's safe to touch. So they guess, or they freeze.

DiscoMCP fixes that. Point it at any MCP server and it hands your agent a ready-made skill: what the server does, how it's actually used, and exactly what's safe — learned by looking, and **without ever changing a thing**.

## Why teams use it

| | |
| --- | --- |
| 🧭 **Agents that know their way around** | Your agent gets a map of the tool instead of guessing — the sequences that answer real questions, and how one result leads to the next. |
| 🔒 **Read-only, guaranteed** | Exploring can never write. It runs a step only when it can *prove* that step is a read. Nothing is deleted or modified while it learns. |
| ⚡ **One command, zero setup** | A single 8 MB binary. No runtime, no toolchain — `npx` and you're running. |
| 🧩 **Works with any MCP server** | Local or hosted. The same tool profiles your CRM, your data warehouse, or any API behind MCP. |

## Read-only, guaranteed

This is the part that lets you actually turn an agent loose on a real system.

DiscoMCP explores behind a **default-deny gate**: it runs an action only when it can prove that action is a read. A safe lookup runs. Anything that could write, change, or delete — even if a tool *claims* it's harmless — is refused. Secrets are stripped from everything it saves.

So your agent can learn your production tools without you holding your breath.

## Does it help?

Same question, same server, same model — with and without the generated skill. Read-only, against a genuinely wide, unfamiliar server. `n=2` per row.

| Task | Cold (no skill) | With skill | Tokens |
| --- | --- | --- | --- |
| Targeted lookup | ~12 round-trips | ~5 | **−28%** |
| Cross-dataset reasoning | ~10 round-trips | ~6 | **−44%** |
| Full pipeline trace | ~10–13 round-trips | ~3 | **−57%** |

The harder and less familiar the task, the more it helps: the skill front-loads the map a cold agent has to rediscover by trial. Both reach correct answers — the skill reaches them in far fewer round-trips.

_Small sample, directional — not a guarantee. On a trivial task or a narrow server the skill's own prompt cost can wash out what it saves; the durable win is fewer round-trips and steadier behavior on complex servers. Full method in [benchmarks/METRICS.md](benchmarks/METRICS.md)._

## Get started

**1. Run it** — no install needed:

```bash
npx @ieranama/discomcp --help
```

**2. Point it at a server** — the whole config is a few lines:

```toml
[targets.example]
transport = "stdio"
command = "npx"
args = ["-y", "some-mcp-server"]
```

**3. Hand it to your agent** and let it explore:

```bash
discomcp serve --config ./discomcp.toml
```

Your agent does the exploring; DiscoMCP keeps it safe and writes the skill. The result lands in `.discomcp/profiles/<server>/SKILL.md` — ready to drop into your agent.

## Under the hood

Built in Rust: the model does the thinking, a small deterministic core enforces every safety check. Every claim in a generated skill is tagged with how it was known — declared, documented, observed, or inferred — so an agent never mistakes a guess for a fact.

- [Architecture](docs/ARCHITECTURE.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Extension guide](docs/EXTENDING.md)
- [Configuration example](examples/config.toml)
- [Contributing](CONTRIBUTING.md) · [Security policy](SECURITY.md)

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT License](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in DiscoMCP by you, as defined in the Apache-2.0 license, shall be dual-licensed as above, without any additional terms or conditions.
