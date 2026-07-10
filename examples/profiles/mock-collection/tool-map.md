# Tool Map

## `list_collections`

- Risk: `safe_read`
- Evidence: `declared`
- Summary: Lists accessible collections and their stable collection identifiers

## `describe_collection`

- Risk: `safe_read`
- Evidence: `declared`
- Summary: Returns field metadata for one collection selected by an observed collection_id
- Required arguments: `collection_id`
- Identifier dependencies:
  - `collection_id`: A collection identifier returned by list_collections.

## `list_items`

- Risk: `constrained_read`
- Evidence: `declared`
- Summary: Lists a bounded sample of items in one collection
- Required arguments: `collection_id`, `limit`
- Identifier dependencies:
  - `collection_id`: A collection identifier returned by list_collections.

## `get_item`

- Risk: `safe_read`
- Evidence: `declared`
- Summary: Gets one item by an observed stable item_id
- Required arguments: `collection_id`, `item_id`
- Identifier dependencies:
  - `collection_id`: An observed collection identifier.
  - `item_id`: An item identifier returned by list_items.

## `create_item`

- Risk: `mutation`
- Evidence: `declared`
- Summary: Creates a new item in a collection and changes persistent workspace state
- Required arguments: `collection_id`, `fields`
- Identifier dependencies:
  - `collection_id`: Must be derived from an observed response or explicit user input.

## `delete_item`

- Risk: `destructive`
- Evidence: `declared`
- Summary: Permanently deletes an item from a collection
- Required arguments: `collection_id`, `item_id`
- Identifier dependencies:
  - `collection_id`: Must be derived from an observed response or explicit user input.
  - `item_id`: Must be derived from an observed response or explicit user input.

