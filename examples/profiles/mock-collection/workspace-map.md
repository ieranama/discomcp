# Workspace Map

4 structure(s) were inferred from 3 successful safe observation(s).

## `collections`

- Evidence: `observed` (0.90)
- Type: `record_collection`
- Sources: `list_collections`
- Fields:
  - `description`: `string`
  - `id`: `string` (identifier candidate)
  - `name`: `string`

## `item`

- Evidence: `observed` (0.90)
- Type: `record_collection`
- Sources: `get_item`
- Fields:
  - `collection_id`: `string` (identifier candidate)
  - `id`: `string` (identifier candidate)
  - `name`: `string`
  - `owner`: `object`
  - `status`: `string`

## `owner`

- Evidence: `observed` (0.90)
- Type: `record_collection`
- Sources: `get_item`
- Fields:
  - `access_token`: `string`
  - `display_name`: `string`
  - `email`: `string`
  - `id`: `string` (identifier candidate)

## `projects`

- Evidence: `observed` (0.90)
- Type: `record_collection`
- Sources: `list_items`
- Fields:
  - `id`: `string` (identifier candidate)
  - `name`: `string`
  - `owner_id`: `string` (identifier candidate)
  - `status`: `string`

