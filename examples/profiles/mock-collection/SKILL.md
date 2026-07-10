# DiscoMCP Operational Skill

## Purpose

`declared`: This skill profiles target `mock-collection` and is generated from its cached catalogue plus redacted safe observations.

## When To Use This MCP

Use it for intents supported by the observed structures and declared tools below. Do not assume unavailable structures, fields, identifiers, or relationships.

## What The MCP Exposes

`declared`: 6 tool(s), 0 resource(s), and 0 prompt(s) were cached during static discovery.

## Functional Capability Profile


## Observed Workspace Structures

- `collections`: `observed` (0.90) from `list_collections`.
- `item`: `observed` (0.90) from `get_item`.
- `owner`: `observed` (0.90) from `get_item`.
- `projects`: `observed` (0.90) from `list_items`.

## Important Fields And Identifiers

- `collections`: `description` (string), `id` (identifier candidate, observed), `name` (string)
- `item`: `collection_id` (identifier candidate, observed), `id` (identifier candidate, observed), `name` (string), `owner` (object), `status` (string)
- `owner`: `access_token` (string), `display_name` (string), `email` (string), `id` (identifier candidate, observed)
- `projects`: `id` (identifier candidate, observed), `name` (string), `owner_id` (identifier candidate, observed), `status` (string)

## Confirmed Relationships

`unknown`: No relationship was directly verified by a traversal probe.

## Inferred Relationships

- `item` -> `collections` via collection_id: `inferred` (0.70).
- `projects` -> `owner` via owner_id: `inferred` (0.70).

## Tool Safety Classes

### Safe Read Tools

- `list_collections`: `declared`; Lists accessible collections and their stable collection identifiers
- `describe_collection`: `declared`; Returns field metadata for one collection selected by an observed collection_id
- `list_items`: `declared`; Lists a bounded sample of items in one collection
- `get_item`: `declared`; Gets one item by an observed stable item_id

### Sensitive Read Tools

`unknown`: None were established from the current catalogue.

### Computational Tools

`unknown`: None were established from the current catalogue.

### Mutation Tools

- `create_item`: `declared`; Creates a new item in a collection and changes persistent workspace state

### External Side-Effect Tools

`unknown`: None were established from the current catalogue.

### Destructive Or Administrative Tools

- `delete_item`: `declared`; Permanently deletes an item from a collection

## Recommended Tool Sequences

### Read a discovered workspace item

`observed`: Inspect structures reachable through safe, observed identifier traversal.
1. `list_collections`: Discover accessible workspace structures before selecting a collection.
2. `list_items`: Sample one observed collection with the minimum useful limit.
3. `get_item`: Read one observed item to verify the detail shape and collection linkage.

### Plan `create_item` with explicit confirmation

`declared`: Prepare, but do not automatically execute, the `create_item` operation.
1. `create_item`: Execute only after the user has reviewed exact arguments and confirmed.

### Plan `delete_item` with explicit confirmation

`declared`: Prepare, but do not automatically execute, the `delete_item` operation.
1. `delete_item`: Execute only after the user has reviewed exact arguments and confirmed.

## User-Specific Workflows

`user_defined`: The profile goal was: Understand the collection-oriented fixture and generate an operational skill

## Argument Derivation Conventions

- `observed`: Obtain identifier-like arguments from a successful prior response and retain its probe provenance.
- `declared`: Validate every argument against the cached target JSON Schema.
- `declared`: Use the smallest useful explicit list limit and never invent IDs.

## Confirmation Boundaries

- `declared`: `create_item` is classified as `mutation` and requires an explicit user confirmation outside onboarding.
- `declared`: `delete_item` is classified as `destructive` and requires an explicit user confirmation outside onboarding.

## Verification Patterns

`declared`: After an explicitly confirmed state-changing operation, use a safe read tool to verify the intended result when one exists.

## Failure And Fallback Behavior

`declared`: If a safe probe fails, retain the uncertainty, do not retry risky tools, and use only another validated safe probe.

## Known Contradictions

`unknown`: No contradictions were recorded in this profile run.

## Known Uncertainties

`unknown`: No material uncertainty was recorded.

## Examples

`observed`: To follow **Read a discovered workspace item**:
1. Call `list_collections` only with validated arguments.
2. Call `list_items` only with validated arguments.
3. Call `get_item` only with validated arguments.

## Questions That Improve The Skill

- `user_defined`: Which observed structure is the source of truth for your workflow?
- `user_defined`: Which planned actions should always require confirmation?

## Profile Freshness

`observed`: Profile generated at Unix timestamp `1783671787` from catalogue fingerprint `sha256:3e3733e33c492caae85635144c64e43394335c02dc4fcc57c909ef5aba82c43e`. Refresh before relying on long-lived assumptions.
