//! Unwrapping of the MCP `tools/call` result envelope.
//!
//! A target's real payload is what DiscoMCP must learn from, but MCP wraps it in
//! `{"content": [{"type": "text", "text": "<json>"}], "isError": false}`. Left
//! wrapped, every downstream walk (redaction, normalization, inference) sees the
//! envelope and nothing else: the payload is one opaque string.

use std::borrow::Cow;

use serde_json::Value;

/// Returns the real payload carried by an MCP tool result, or `value` itself
/// when it is not an envelope (simple servers that return plain JSON).
///
/// Prefers `structuredContent` (the spec's typed payload). Otherwise parses the
/// `text` content blocks as JSON: one block yields its payload, several yield an
/// array. Text that is not JSON is kept as a string rather than discarded.
///
/// The result is then unwrapped once more: a server that declares
/// `outputSchema: {content: string}` (the MCP TypeScript SDK default) ships its
/// real payload as JSON *inside a string*, so `structuredContent` is
/// `{"content": "<json>"}` — a second envelope, not the payload.
#[must_use]
pub fn unwrap_mcp_envelope(value: &Value) -> Cow<'_, Value> {
    let Some(object) = value.as_object() else {
        return Cow::Borrowed(value);
    };
    if let Some(structured) = object.get("structuredContent") {
        return match parse_embedded_json(structured) {
            Some(payload) => Cow::Owned(payload),
            None => Cow::Borrowed(structured),
        };
    }
    let Some(content) = object.get("content").and_then(Value::as_array) else {
        return Cow::Borrowed(value);
    };
    let mut payloads = content
        .iter()
        .filter(|block| block.get("type").and_then(Value::as_str) == Some("text"))
        .filter_map(|block| block.get("text").and_then(Value::as_str))
        .map(|text| {
            serde_json::from_str::<Value>(text).unwrap_or_else(|_| Value::String(text.to_string()))
        })
        .collect::<Vec<_>>();
    match payloads.len() {
        0 => Cow::Borrowed(value),
        1 => {
            let payload = payloads.remove(0);
            Cow::Owned(parse_embedded_json(&payload).unwrap_or(payload))
        }
        _ => Cow::Owned(Value::Array(payloads)),
    }
}

/// A JSON document carried inside a string — either the string itself or an
/// object whose single field holds it. Only a structural result (object/array)
/// is accepted, so `{"count": "12"}` is not silently turned into the number 12.
fn parse_embedded_json(value: &Value) -> Option<Value> {
    let text = match value {
        Value::String(text) => text.as_str(),
        Value::Object(object) if object.len() == 1 => {
            object.values().next().and_then(Value::as_str)?
        }
        _ => return None,
    };
    let parsed = serde_json::from_str::<Value>(text).ok()?;
    (parsed.is_object() || parsed.is_array()).then_some(parsed)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn unwraps_text_content_payload() {
        let envelope = json!({
            "content": [{"type": "text", "text": "{\"id\": \"cal-1\", \"summary\": \"Work\"}"}],
            "isError": false
        });
        assert_eq!(
            *unwrap_mcp_envelope(&envelope),
            json!({"id": "cal-1", "summary": "Work"})
        );
    }

    #[test]
    fn prefers_structured_content() {
        let envelope = json!({
            "content": [{"type": "text", "text": "ignored"}],
            "structuredContent": {"id": "cal-1"}
        });
        assert_eq!(*unwrap_mcp_envelope(&envelope), json!({"id": "cal-1"}));
    }

    #[test]
    fn unwraps_the_typescript_sdk_content_string_wrapper() {
        // A server declaring `outputSchema: {content: string}` (the MCP TS SDK
        // default, e.g. the filesystem server) puts the real payload in a string.
        let envelope = json!({
            "content": [{"type": "text", "text": "{\"entries\": [{\"name\": \"a\"}]}"}],
            "structuredContent": {"content": "{\"entries\": [{\"name\": \"a\"}]}"}
        });
        assert_eq!(
            *unwrap_mcp_envelope(&envelope),
            json!({"entries": [{"name": "a"}]})
        );
    }

    #[test]
    fn keeps_single_string_field_objects_that_are_not_json() {
        let envelope = json!({"structuredContent": {"content": "[FILE] notes.txt"}});
        assert_eq!(
            *unwrap_mcp_envelope(&envelope),
            json!({"content": "[FILE] notes.txt"})
        );
        // A scalar-looking string field is not a payload either.
        let scalar = json!({"structuredContent": {"count": "12"}});
        assert_eq!(*unwrap_mcp_envelope(&scalar), json!({"count": "12"}));
    }

    #[test]
    fn joins_multiple_text_blocks() {
        let envelope = json!({"content": [
            {"type": "text", "text": "{\"id\": \"a\"}"},
            {"type": "text", "text": "{\"id\": \"b\"}"}
        ]});
        assert_eq!(
            *unwrap_mcp_envelope(&envelope),
            json!([{"id": "a"}, {"id": "b"}])
        );
    }

    #[test]
    fn keeps_non_json_text_as_string() {
        let envelope = json!({"content": [{"type": "text", "text": "plain prose"}]});
        assert_eq!(*unwrap_mcp_envelope(&envelope), json!("plain prose"));
    }

    #[test]
    fn passes_through_unenveloped_and_blockless_responses() {
        let plain = json!({"items": [{"id": "one"}]});
        assert_eq!(*unwrap_mcp_envelope(&plain), plain);
        let image_only = json!({"content": [{"type": "image", "data": "..."}]});
        assert_eq!(*unwrap_mcp_envelope(&image_only), image_only);
    }
}
