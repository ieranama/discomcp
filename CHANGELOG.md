# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
