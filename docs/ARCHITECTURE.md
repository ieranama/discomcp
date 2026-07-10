# Architecture

DiscoMCP is a generic MCP profiler. It treats every target MCP as unknown and produces evidence-backed operational guidance without exposing every target tool to the external agent.

## Surfaces

The project has three presentation surfaces built on one core:

1. **Library:** application code profiles a named target through `DiscoMcp`.
2. **CLI:** commands inspect, plan, profile, refresh, and export generated artifacts.
3. **MCP server boundary:** a small stable public tool surface is defined for another agent to request profiles and artifacts. Protocol request dispatch is the next presentation milestone.

The future MCP server will be an MCP host/client for its own target registry. It will not automatically inherit target connections from another host.

## Core Flow

```text
target MCP
  -> transport client
  -> static discovery and cached catalogue
  -> compact tool cards and retrieval
  -> reasoning proposal
  -> deterministic runtime validation
  -> permitted probe execution
  -> normalization and redaction
  -> evidence-backed workspace and operational models
  -> SKILL.md and AGENTS.md exporters
```

Static discovery records server identity, tools, resources, prompts, schemas, and configured documentation. The implementation supports both a deterministic mock transport and real newline-delimited stdio MCP subprocesses; `McpClient` remains the extension boundary for HTTP transports. The complete catalogue remains canonical local state. Reasoning calls receive a compact current objective, selected tool cards, schema fragments, relevant observations, open questions, and remaining budgets rather than the entire catalogue or raw history.

## Responsibility Boundary

The reasoning backend interprets documentation and observations, proposes safe probes, identifies gaps, forms hypotheses, infers structures and relationships, and drafts workflows.

The runtime owns stdio process lifecycle, JSON-RPC initialization, catalogue and tool calls, schema validation, tool existence checks, identifier provenance, risk classification enforcement, budgets, timeouts, response limits, redaction, persistence, and declaration fingerprints. HTTP transports, transport retries, and structured audit-log sinks remain future work. Model output is untrusted input until the runtime validates it.

## Canonical State

Profiles are stored under `.discomcp/profiles/<target-id>/`. The canonical machine-readable artifacts are:

- `capability-profile.json`
- `workspace-model.json`
- `operational-model.json`

Supporting artifacts include the full tool catalogue, compact tool cards, documentation index and summary, probes, observations, hypotheses, contradictions, redacted sample shapes, evals, a quality report, and human-readable maps. `SKILL.md` is an exporter, not the only source of truth.

Every material claim retains evidence status, confidence, provenance, and contradictions. The system uses `declared`, `documented`, `observed`, `inferred`, `user_defined`, `unknown`, and `contradicted`; an inference is never rendered as an observation.

## Safety Model

During onboarding, the runtime blocks mutation, external-side-effect, destructive, administrative, arbitrary-execution, and unknown-risk tools. It accepts constrained reads and harmless pure computation only after validating arguments, constraints, and limits. Mutation workflows may be documented but are not executed during profiling.

The redaction layer runs before model calls, logs, persistence, and generated artifacts. It preserves shape and non-sensitive identifiers where permitted while removing secrets and minimizing sensitive personal data according to the configured privacy mode.

## Extensibility

`McpClient` keeps transports independent from discovery and inference. `ReasoningBackend` keeps reasoning independent from model providers. New transports and backends must preserve the validation and redaction boundary described in [EXTENDING.md](EXTENDING.md).
