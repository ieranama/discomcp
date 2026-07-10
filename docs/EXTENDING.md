# Extension Guide

DiscoMCP is designed to add transports and reasoning systems without coupling the core to a provider or weakening runtime safety.

## Reasoning Backends

Implement the provider-neutral `ReasoningBackend` contract. A backend receives a structured request containing a logical task, instructions, compact JSON context, optional output schema, role, and output budget. It returns structured content or a typed error along with stable backend, model, and capability identifiers.

Backends must:

- use logical roles such as `everyday` and `deep`, not provider names in core behavior;
- advertise capabilities honestly, including structured output and JSON Schema support;
- return only the requested structured response or a clear error;
- avoid logging request content that may contain redacted workspace data;
- treat all response content as untrusted until core validation succeeds.

When native JSON Schema output is unavailable, the core should request delimited JSON, parse it, validate it, and perform bounded repair attempts. Native tool calling is optional; a backend can return a validated `ProbeDecision` instead.

### Command Backends

The generic command backend is intentionally simple. It passes one documented JSON request on standard input and expects one JSON response on standard output. Commands, fixed arguments, model selection, headers, and environment references come only from trusted configuration. Do not interpolate target documentation, tool output, user text, or secrets into a shell command.

## MCP Transports

Implement the transport-independent `McpClient` contract for initialization, catalogue listing, tool calls, resource reads, and prompt retrieval. A transport implementation should isolate protocol framing and lifecycle details from discovery, policy, and inference.

Every transport must:

- apply connection and request timeouts;
- surface typed actionable errors without secrets;
- preserve raw protocol data only long enough for normalization and redaction;
- support bounded request and response handling;
- avoid retries for an operation whose side effects cannot be ruled out;
- expose server identity and capabilities needed for catalogue fingerprints.

Stdio is the initial real transport. Future HTTP and SSE transports must obey the same safety and redaction contracts.

## Retrieval and Inference Extensions

The MVP uses deterministic lexical retrieval over compact tool cards. A semantic retriever may be added only behind the same interface and must preserve selective retrieval: do not send a complete target catalogue or complete documentation on every reasoning cycle.

Inference extensions must keep evidence status, confidence, source references, and contradictions. They may improve semantic interpretation but cannot invent structures, fields, relationships, or workflows that lack supporting evidence.

## Required Tests for Extensions

Add fixture-driven tests that demonstrate:

- only selected tools reach the reasoning request;
- invalid structured output is rejected or repaired within a bounded policy;
- unknown or prohibited tool calls cannot cross the runtime boundary;
- secrets do not appear in logs, persisted state, or backend context;
- no invented identifiers are accepted;
- transport failures leave useful uncertainty instead of corrupting profile state.

## Compatibility

Avoid provider- or application-specific behavior in the core. Branded integrations belong in optional adapters that use the public extension contracts. Changes to persisted profile schemas should include a migration or an explicit versioned incompatibility note.
