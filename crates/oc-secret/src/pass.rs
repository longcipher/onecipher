//! `pass`-compatible text secret model (pass/ripasso interop).
//!
//! Unified parser for the file format used by `pass` (password-store) and
//! ripasso:
//! - the first line is always the secret value, never a `key: value` field,
//! - subsequent `key: value` lines require exactly `": "` as separator and a key containing no
//!   whitespace,
//! - `otp()` checks `otpauth` / `otp` / `totp` in order, else falls back to the first line,
//! - `Debug` is redacted (never prints secret material).
//!
//! [`oc_core::SecretPayload`] keeps `secret: String` for JSON compatibility;
//! the exemption window is documented on that type (Drop-zeroized, hardened
//! at use-site via `secret_hardened()`). This parser converts to/from that
//! payload without widening the window.

use std::collections::BTreeMap;

/// Parsed `pass`-style text secret.
#[derive(Clone, PartialEq, Eq)]
pub struct PassEntry {
    /// First line (the secret value).
    password: String,
    /// Subsequent `key: value` fields.
    fields: BTreeMap<String, String>,
}

impl PassEntry {
    /// Parse `pass`-style text.
    ///
    /// Empty input yields an empty password with no fields. Only lines after
    /// the first are considered for `key: value` extraction.
    pub fn parse(text: &str) -> Self {
        let mut lines = text.lines();
        let password = lines.next().unwrap_or("").to_string();
        let mut fields = BTreeMap::new();
        for line in lines {
            // Require ": " separator; key must be non-empty with no whitespace.
            let Some(idx) = line.find(": ") else {
                continue;
            };
            let (key, rest) = line.split_at(idx);
            let value = &rest[2..];
            if key.is_empty() || key.chars().any(char::is_whitespace) {
                continue;
            }
            fields.insert(key.to_string(), value.to_string());
        }
        Self { password, fields }
    }

    /// The secret value (first line).
    pub fn password(&self) -> &str {
        &self.password
    }

    /// Borrow parsed fields.
    pub fn fields(&self) -> &BTreeMap<String, String> {
        &self.fields
    }

    /// OTP URI or code: `otpauth` > `otp` > `totp`, else the first line.
    pub fn otp(&self) -> &str {
        self.fields
            .get("otpauth")
            .or_else(|| self.fields.get("otp"))
            .or_else(|| self.fields.get("totp"))
            .map_or(&self.password, String::as_str)
    }

    /// Field lookup.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.fields.get(key).map(String::as_str)
    }

    /// Convert into a storage payload (secret = first line, notes = rest).
    pub fn into_payload(self) -> oc_core::SecretPayload {
        let notes = if self.fields.is_empty() {
            None
        } else {
            Some(
                self.fields.iter().map(|(k, v)| format!("{k}: {v}")).collect::<Vec<_>>().join("\n"),
            )
        };
        oc_core::SecretPayload { secret: self.password, notes, extra: None }
    }

    /// Render back to `pass`-style text (password line + sorted fields).
    pub fn render(&self) -> String {
        let mut out = self.password.clone();
        out.push('\n');
        for (k, v) in &self.fields {
            out.push_str(k);
            out.push_str(": ");
            out.push_str(v);
            out.push('\n');
        }
        out
    }
}

// Redacted Debug: never print secret material.
impl std::fmt::Debug for PassEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PassEntry")
            .field("password", &"<redacted>")
            .field("fields", &self.fields.keys().collect::<Vec<_>>())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_line_is_value_even_if_it_looks_like_a_field() {
        let e = PassEntry::parse("user: hunter2\nother: x");
        assert_eq!(e.password(), "user: hunter2");
        assert_eq!(e.get("other"), Some("x"));
        assert!(e.get("user").is_none());
    }

    #[test]
    fn field_requires_colon_space_and_clean_key() {
        let e = PassEntry::parse("pw\nkey:value\nbad key: v\nok: v\nempty:\n");
        assert!(e.get("key").is_none(), "missing space after colon");
        assert!(e.get("bad key").is_none(), "key with whitespace rejected");
        assert_eq!(e.get("ok"), Some("v"));
        assert!(e.get("empty").is_none());
    }

    #[test]
    fn otp_priority_then_fallback_to_first_line() {
        let e = PassEntry::parse("fallback\notp: O1\ntotp: T1\notpauth: U1");
        assert_eq!(e.otp(), "U1");
        let e = PassEntry::parse("fallback\notp: O1\ntotp: T1");
        assert_eq!(e.otp(), "O1");
        let e = PassEntry::parse("fallback\nuser: bob");
        assert_eq!(e.otp(), "fallback");
    }

    #[test]
    fn debug_never_leaks_secret() {
        let e = PassEntry::parse("s3cr3t\notp: 123");
        let d = format!("{e:?}");
        assert!(!d.contains("s3cr3t"));
        assert!(!d.contains("123"));
    }

    #[test]
    fn render_round_trips_through_parse() {
        let e = PassEntry::parse("pw\nb: 2\na: 1");
        let back = PassEntry::parse(&e.render());
        assert_eq!(back.password(), "pw");
        assert_eq!(back.get("a"), Some("1"));
    }
}
