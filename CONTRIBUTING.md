# Contributing to DiscoMCP

Thanks for contributing. DiscoMCP is safety-sensitive software: an implementation must preserve the distinction between reasoning proposals and runtime-enforced execution.

## Development Setup

Install Rust stable with the repository toolchain, then run:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
```

Install and run the dependency audit before changes that affect dependencies or releases:

```bash
cargo install cargo-audit --locked
cargo audit
```

## Pull Requests

Keep changes focused and explain their behavioral impact. A pull request should include:

- a clear problem statement and implementation summary;
- tests appropriate to the affected runtime boundary;
- documentation updates when behavior, configuration, or generated artifacts change;
- explicit notes about privacy, safety, compatibility, and migration effects.

Do not include credentials, unredacted target responses, private documentation, generated profiles containing user data, or `.env` files.

## Safety Requirements

Changes must not allow a reasoning backend to bypass runtime validation. In particular:

- onboarding must not execute mutation, external-side-effect, destructive, administrative, arbitrary-execution, or unknown-risk tools;
- tool existence, argument schema, identifier provenance, budgets, and risk policy must be checked before a target call;
- secrets must be redacted before logging, persistence, and reasoning-provider requests;
- failed safe probes should become evidence or uncertainty rather than terminate a profile unnecessarily;
- generated skills may only reference discovered target tools and evidence-backed structures.

Add or update tests for every altered safety boundary.

## Fixtures and Documentation

Use generic fixtures. Do not add branded adapters or proprietary workspace data to the core test suite. Fixture outputs should make evidence status, identifier derivation, and expected safety decisions testable.

Document externally visible configuration, profile artifacts, and extension contracts. Keep the README accurate about the currently implemented surface; do not document planned behavior as available behavior.

## Reporting Vulnerabilities

Do not file public issues for vulnerabilities. Follow [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions are licensed under the repository's dual license: MIT or Apache-2.0, at the recipient's option.
