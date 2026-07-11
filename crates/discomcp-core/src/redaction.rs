use serde_json::{Map, Value};

use crate::model::PrivacyMode;
use crate::normalization::is_identifier_name;

#[derive(Clone, Debug, Default)]
pub struct RedactionReport {
    pub secrets_redacted: usize,
    pub pii_redacted: usize,
}

#[derive(Clone, Debug)]
pub struct Redactor {
    mode: PrivacyMode,
}

impl Redactor {
    #[must_use]
    pub fn new(mode: PrivacyMode) -> Self {
        Self { mode }
    }

    #[must_use]
    pub fn redact(&self, value: &Value) -> (Value, RedactionReport) {
        let mut report = RedactionReport::default();
        let redacted = self.redact_at(value, None, &mut report);
        (redacted, report)
    }

    #[must_use]
    pub fn redact_text(&self, value: &str) -> String {
        if looks_like_secret(value) {
            "[REDACTED_SECRET]".to_string()
        } else if self.mode != PrivacyMode::LocalTrusted && looks_like_email(value) {
            "[REDACTED_EMAIL]".to_string()
        } else {
            value.to_string()
        }
    }

    fn redact_at(&self, value: &Value, key: Option<&str>, report: &mut RedactionReport) -> Value {
        if let Some(key) = key {
            if is_secret_key(key) {
                report.secrets_redacted += 1;
                return Value::String("[REDACTED_SECRET]".to_string());
            }
            if self.mode != PrivacyMode::LocalTrusted && is_pii_key(key) {
                report.pii_redacted += 1;
                return Value::String(pii_marker(key).to_string());
            }
        }
        match value {
            Value::Object(object) => Value::Object(
                object
                    .iter()
                    .map(|(key, child)| (key.clone(), self.redact_at(child, Some(key), report)))
                    .collect::<Map<_, _>>(),
            ),
            Value::Array(items) => Value::Array(
                items
                    .iter()
                    .map(|child| self.redact_at(child, key, report))
                    .collect(),
            ),
            Value::String(string) => {
                // A secret is a secret wherever it appears: a signed URL under
                // `download_uri` is still a credential. This check never yields.
                if looks_like_secret(string) {
                    report.secrets_redacted += 1;
                    return Value::String("[REDACTED_SECRET]".to_string());
                }
                // A primary key is not free-text PII, and redacting it would make
                // the record uncitable — no observed identifier, so no traversal
                // (a Google calendar id literally *is* an email address). Outside
                // `Strict`, values under identifier keys therefore skip the
                // email/phone *shape* heuristics. `Strict` chooses privacy over
                // traversal and redacts them like any other value. Name-based rules
                // (`access_token`, `email`, ...) still apply under every mode.
                if self.mode != PrivacyMode::Strict && key.is_some_and(is_identifier_name) {
                    return Value::String(string.clone());
                }
                if self.mode != PrivacyMode::LocalTrusted && looks_like_email(string) {
                    report.pii_redacted += 1;
                    Value::String("[REDACTED_EMAIL]".to_string())
                } else if self.mode == PrivacyMode::Strict && looks_like_phone(string) {
                    report.pii_redacted += 1;
                    Value::String("[REDACTED_PHONE]".to_string())
                } else {
                    Value::String(string.clone())
                }
            }
            _ => value.clone(),
        }
    }
}

fn is_secret_key(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase();
    [
        "api_key",
        "apikey",
        "access_token",
        "refresh_token",
        "authorization",
        "cookie",
        "password",
        "private_key",
        "client_secret",
        "secret",
        "credential",
    ]
    .iter()
    .any(|needle| normalized.contains(needle))
}

fn is_pii_key(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase();
    [
        "email",
        "phone",
        "address",
        "ssn",
        "social_security",
        "birthdate",
    ]
    .iter()
    .any(|needle| normalized.contains(needle))
}

fn pii_marker(key: &str) -> &'static str {
    let normalized = key.to_ascii_lowercase();
    if normalized.contains("email") {
        "[REDACTED_EMAIL]"
    } else if normalized.contains("phone") {
        "[REDACTED_PHONE]"
    } else if normalized.contains("address") {
        "[REDACTED_ADDRESS]"
    } else {
        "[REDACTED_PII]"
    }
}

fn looks_like_email(value: &str) -> bool {
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !value.contains(char::is_whitespace)
}

fn looks_like_phone(value: &str) -> bool {
    let digits = value.chars().filter(char::is_ascii_digit).count();
    (7..=15).contains(&digits) && value.len() <= 24
}

fn looks_like_secret(value: &str) -> bool {
    let compact = value.trim();
    if compact.starts_with("sk-") || compact.starts_with("Bearer ") || compact.starts_with("ghp_") {
        return true;
    }
    let has_lower = compact
        .chars()
        .any(|character| character.is_ascii_lowercase());
    let has_upper = compact
        .chars()
        .any(|character| character.is_ascii_uppercase());
    let has_digit = compact.chars().any(|character| character.is_ascii_digit());
    let has_separator = compact
        .chars()
        .any(|character| matches!(character, '_' | '-' | '/' | '+' | '='));
    compact.len() >= 32
        && has_lower
        && has_upper
        && has_digit
        && has_separator
        && !compact.contains(' ')
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn redacts_secrets_and_balanced_pii_without_losing_structure() {
        let input = json!({
            "id": "item_123",
            "email": "person@example.test",
            "access_token": "sk-super-secret",
            "nested": {"status": "active"}
        });
        let (redacted, report) = Redactor::new(PrivacyMode::Balanced).redact(&input);
        assert_eq!(redacted["id"], "item_123");
        assert_eq!(redacted["email"], "[REDACTED_EMAIL]");
        assert_eq!(redacted["access_token"], "[REDACTED_SECRET]");
        assert_eq!(redacted["nested"]["status"], "active");
        assert_eq!(report.secrets_redacted, 1);
        assert_eq!(report.pii_redacted, 1);
    }

    #[test]
    fn identifier_keys_never_exempt_secret_shaped_values() {
        let input = json!({
            "id": "cal-1",
            "download_uri": "https://storage.googleapis.com/b/f.pdf?X-Goog-Signature=4d7e2fA9bC0123456789abcdefABCDEF"
        });
        for mode in [
            PrivacyMode::LocalTrusted,
            PrivacyMode::Balanced,
            PrivacyMode::Strict,
        ] {
            let (redacted, report) = Redactor::new(mode).redact(&input);
            assert_eq!(redacted["download_uri"], "[REDACTED_SECRET]");
            assert_eq!(report.secrets_redacted, 1);
        }
    }

    #[test]
    fn email_shaped_identifier_survives_outside_strict_mode() {
        let input = json!({"id": "person@example.test"});
        let (balanced, _) = Redactor::new(PrivacyMode::Balanced).redact(&input);
        assert_eq!(balanced["id"], "person@example.test");
        // `strict` is an explicit request for privacy over traversal.
        let (strict, report) = Redactor::new(PrivacyMode::Strict).redact(&input);
        assert_eq!(strict["id"], "[REDACTED_EMAIL]");
        assert_eq!(report.pii_redacted, 1);
    }
}
