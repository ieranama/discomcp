# Threat Model

DiscoMCP connects an agent workflow to unknown MCP servers and optional reasoning providers. Its primary security goal is to learn safely without allowing untrusted target content or model output to cause unapproved actions or disclose secrets.

## Assets to Protect

- Target credentials, authorization headers, cookies, private keys, and environment variables.
- Sensitive workspace content, including personal data, documents, messages, and identifiers.
- The integrity of the target workspace and external systems reachable through target tools.
- The integrity of generated profiles and skills consumed by later agents.
- Local process execution and filesystem boundaries.

## Trust Boundaries

| Boundary | Untrusted input or risk | Required control |
| --- | --- | --- |
| Target MCP | Handshake metadata, schemas, docs, tool output, errors | Normalize, size-limit, redact, treat claims as evidence rather than authority. |
| Reasoning backend | Probe decisions, structured output, explanations | Validate tool existence, schema, identifier provenance, policy, and budgets before execution. |
| Config and environment | Commands, arguments, URLs, secret interpolation | Fail closed for missing variables, never print resolved secrets, redact diagnostics. |
| Generated artifacts | Future-agent instructions and summaries | Render only discovered tools and evidence-backed claims; retain uncertainty and freshness. |
| Local persistence | Logs, profiles, sample data | Store redacted bounded data only; keep raw output transient where possible. |

## Principal Threats and Mitigations

### Prompt Injection and Misleading Documentation

Target descriptions, resources, prompts, errors, and samples can attempt to change the profiler's behavior. They are data, not instructions. The reasoning layer may interpret them, but runtime policy is deterministic and cannot be overridden by a target response or a model instruction.

### Unsafe Tool Execution

Names and descriptions can be incomplete or deceptive. Risk classification draws on declarations, schemas, docs, observations, and conservative defaults. During onboarding, mutation, external-side-effect, destructive, administrative, arbitrary-execution, and unknown-risk tools are blocked. A database query is permitted only when read-only behavior is documented or mechanically enforceable.

### Invented Tools, Identifiers, and Arguments

The runtime verifies the selected tool against the cached catalogue, validates arguments against its JSON Schema, and requires identifiers to originate from observations, declarations, configuration, or explicit user input. It rejects invented prerequisites and unresolved required arguments.

### Secret and Sensitive-Data Disclosure

Secrets are recursively redacted before logging, persistence, artifacts, and reasoning requests. Balanced mode also minimizes personally identifiable information; strict mode removes it before any model call. Configuration interpolation must not expose values in command diagnostics or errors.

### Resource Exhaustion

Unknown target responses and documentation can be large or cyclic. The runtime applies timeouts, call budgets, traversal-depth limits, sample limits, response-size limits, retries, and stop conditions. A failed probe becomes a bounded observation and uncertainty when safe to continue.

### Malicious Local Commands or Reasoning Backends

Command backends are explicitly configured and receive a documented JSON contract. They must not be constructed from untrusted target content. Their output is parsed and validated as untrusted structured data; native provider tool calling is optional and does not bypass the runtime.

### Stale or Misleading Profiles

Profiles retain fingerprints and freshness metadata for server metadata, catalogue declarations, documentation, structures, shapes, and relationships. Refresh compares fingerprints, invalidates affected observations, and records a diff rather than presenting old observations as current facts.

## Residual Risk

No generic profiler can prove every read is harmless or every server declaration is truthful. DiscoMCP therefore prefers safe partial understanding over broad exploration, marks uncertainty explicitly, and requires users to confirm mutations outside onboarding. Operators remain responsible for target access scopes, configured reasoning backends, and review of generated guidance before high-impact use.

## Security Testing Expectations

Automated tests must cover prohibited-tool blocking, unknown-tool rejection, argument validation, identifier provenance, response and timeout limits, redaction, absence of raw sensitive sample persistence, selected-tool context limits, cache behavior, and no-change refresh behavior.
