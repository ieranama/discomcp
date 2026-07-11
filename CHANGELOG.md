# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] - 2026-07-11

### Added

- Adaptive exploration: every `execute_probe` result and a new `session_status` tool carry a `gaps` report so the agent can decide how deep to explore. The report is computed purely from in-session state (no extra target calls) and lists unsampled structures, unexecuted safe-read tools, untraversed identifiers (with the tools likely to consume them), sampling hints (schema params like `orderBy`/`pageSize`/`q`/`filter` that enable most-recent/most-relevant sampling), and a pure-count `depth_signal`. DiscoMCP reports; the agent decides when to stop. Hint lists only surface onboarding-allowed tools, so following a gap never leads into a rejected probe.
- Background-subagent profiling guidance: the MCP `instructions` and the generated `SKILL.md`/`AGENTS.md` now tell a host agent to profile (and refresh) in a non-blocking background subagent, driven by the gap report, so the user's foreground work is never blocked.

## [0.3.0] - 2026-07-11

### Added

- `discomcp serve` now runs a real newline-delimited JSON-RPC stdio MCP server, so any MCP client agent can drive profiling directly: `list_targets`, `lookup_target`, `inspect_target`, `execute_probe`, `finalize_profile`, and `generate_skill`. The agent proposes probes; the runtime enforces risk class, argument schema, identifier provenance, budgets, and redaction. No reasoning backend is needed in serve mode.
- `discomcp lookup <target>` and `DiscoMcp::lookup` gate exploration by catalogue fingerprint: they report an existing matching skill without executing any probe.
- `ProfilingSession` in `discomcp-core` for step-wise, agent-driven profiling sessions.

### Changed

- Tool results are unwrapped from the MCP content envelope before redaction, normalization and inference, so the workspace model describes the target's real payload instead of the `content`/`text` wrapper. A payload carried as JSON inside a string — including the `structuredContent: {"content": "<json>"}` shape emitted by servers that declare the MCP TypeScript SDK's default `outputSchema` — is parsed too.
- Relationships are now also derived from accepted identifier provenance: an identifier observed in one probe and accepted as an argument of the next is recorded as an observed relationship between the structures involved.
- Redaction: values under identifier keys (`id`, `*_id`, `*Id`, `*_uri`, ...) keep their exact value under `local_trusted` and `balanced`, because a redacted primary key is uncitable and kills list -> get traversal (a Google calendar id literally is an email address). They are still redacted when they look like a secret, under every mode, and `strict` redacts email/phone-shaped identifiers as well — choosing privacy over traversal.
- Static discovery now treats a target's missing `resources/list` or `prompts/list` method (JSON-RPC -32601) as "none declared" instead of failing, matching real-world tools-only MCP servers.
- Risk classification recognizes read-verb tool names (`calendar_events_list`, `gmail_users_getProfile`) as whole segments, and no longer classifies a metadata read as `administrative` merely because it returns a `permissions` field.

### Removed

- The speculative `PublicTool` metadata surface in `discomcp-server`; the served tool list is now the single source of truth.

## [0.2.0] - 2026-07-10

### Changed

- `examples/config.toml` and the Quick Start now configure a real stdio MCP target instead of the deterministic mock fixture; the mock transport remains internal to the test suite only.

### Removed

- Checked-in `examples/profiles/mock-collection` example profile output (generated artifact, not source).

## [0.1.0] - 2026-07-10

### Added

- Initial open-source project scaffold and dual licensing.
- Generic DiscoMCP core with provider-neutral MCP and reasoning contracts.
- Deterministic mock collection target, safe probe runtime, redaction, workspace inference, and profile artifact exporters.
- `discomcp` CLI commands for inspect, plan, profile, refresh, generate-skill, and public server-surface inspection.
- Checked-in redacted example profile, safety tests, CI, threat model, and extension guide.
- Newline-delimited stdio JSON-RPC MCP transport and local real-process integration coverage.
- Generic command reasoning backend using a documented stdin/stdout JSON contract.
