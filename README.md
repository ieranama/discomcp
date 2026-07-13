<div align="center">

# 🪩 DiscoMCP

**Your agent, meet your tools and context.**

Teach any AI agent how *you* use the tools it connects to — safely, in one command.

[![CI](https://github.com/ieranama/discomcp/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/ieranama/discomcp/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/ieranama/discomcp?label=release&cacheSeconds=300)](https://github.com/ieranama/discomcp/releases)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)

</div>

Agents are great at code. They get lost inside your tools — they don't know which of a hundred actions matter, how your data connects, or what's safe to touch. So they guess, or they freeze.

DiscoMCP fixes that. Point it at any MCP server and it hands your agent a skill for how **you** use it — not a generic tool list, but *your* workflows on *your* data: the views, tables and records you actually work with, the sequences that answer your real questions, and how one result leads into the next. Learned by looking at your own workspace, and **without ever changing a thing**.

A tool catalogue tells an agent the server has 90 actions. DiscoMCP tells it the five you actually use, in the order you use them, against the data that's really there.

## Why teams use it

| | |
| --- | --- |
| 🎯 **Tailored to how you work** | Not a generic capability dump — a profile of *your* usage: your workflows, your conventions, the parts of your workspace that matter, grounded in what's really in your data. |
| 🧭 **Agents that know their way around** | Your agent follows the sequences that answer real questions and chains one result into the next, instead of guessing across a hundred tools. |
| 🔒 **Read-only, guaranteed** | Exploring can never write. It runs a step only when it can *prove* that step is a read. Nothing is deleted or modified while it learns. |
| ⚡ **One command, zero setup** | A single 8 MB binary. No runtime, no toolchain — `npx` and you're running. |

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
