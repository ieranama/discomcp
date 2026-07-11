# Benchmark: DiscoMCP skill vs cold discovery

Same question, same MCP, same model (Haiku 4.5). Two arms:
- **cold** — agent gets only the raw tool list; must discover structure by trial.
- **skill** — agent also gets the DiscoMCP-generated `SKILL.md` up front.

Read-only enforced (metadata tools only; no query execution). Tokens = input
(incl. cache) + output, from the `claude` CLI's own usage reporting. Target: a
real wide-schema data warehouse (18 datasets, hundreds of tables). n=2 per cell.

| Task complexity | cold turns | skill turns | tokens saved |
|-----------------|-----------:|------------:|-------------:|
| Low  (single targeted lookup)      | ~12 | ~5 | **−28%** |
| Mid  (cross-dataset join reasoning) | ~10 | ~6 | **−44%** |
| High (trace a full multi-stage pipeline) | ~10 | ~3 | **−57%** |

**Trend: the more complex the task, the more the skill saves.** Cold discovery
cost scales with how much of the schema the agent must uncover; the skill front-
loads that map, so its advantage grows with task complexity. Both arms reached
correct, specific answers — the skill reached them in far fewer round-trips
(e.g. 3 turns vs 10–13 on the hardest task).

Caveat: the win appears on targeted questions against a genuinely wide/unfamiliar
MCP. On a trivial task or a narrow MCP the skill's own prompt cost can wash out
the discovery it saves; the value is fewer round-trips and more consistent
behavior when the MCP is complex, not a flat token discount everywhere.
