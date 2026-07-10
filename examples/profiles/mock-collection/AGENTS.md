# DiscoMCP Target Instructions

Target: `mock-collection`
Profile: `examples/profiles/mock-collection`

Read `SKILL.md`, `workspace-model.json`, and `operational-model.json` before operating this target.

- Use only cached target tool names from `tool-catalogue.json`.
- Validate arguments against the target schema and derive IDs from observed output.
- Never execute mutation, external side-effect, destructive, administrative, arbitrary-execution, or unknown tools during onboarding.
- Require explicit confirmation before any documented state-changing operation.
- Refresh this profile with `discomcp refresh mock-collection` before relying on stale workspace assumptions.
- Run the generated behavioral checks from `evals.yml` after updating the profile.

Known uncertainties are in `workspace-model.json`.
