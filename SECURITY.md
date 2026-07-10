# Security Policy

## Reporting a Vulnerability

Do not report suspected vulnerabilities in a public issue, discussion, or pull request.

Use GitHub's private vulnerability reporting feature for this repository when it is enabled. Include a concise reproduction, affected versions or commit, impact, and any proposed mitigation. Avoid attaching credentials, production exports, access tokens, or unredacted private target data.

Before the first public release, maintainers must enable private vulnerability reporting in the repository settings and publish a monitored alternate reporting channel in this document.

We will acknowledge a valid report as soon as practical, investigate privately, and coordinate disclosure after a fix or mitigation is available.

## Supported Versions

Until the first tagged release, security fixes are applied to the default branch. After releases begin, the currently supported release line and its security support window will be listed here.

## Security Scope

DiscoMCP handles credentials and untrusted inputs from target MCP servers, documentation, reasoning backends, and generated artifacts. Reports are especially valuable for issues involving:

- execution of prohibited target tools during onboarding;
- secret or sensitive-data disclosure through logs, artifacts, errors, or reasoning context;
- command injection through configuration or a reasoning backend;
- bypass of argument validation, identifier provenance, budgets, or risk policy;
- resource exhaustion from malicious MCP responses or documentation;
- unsafe handling of profile refreshes or generated skills.

The design and mitigations are described in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
