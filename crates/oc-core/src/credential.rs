//! Dual-track credential model for wallet/agent authentication.
//!
//! Replaces scattered `starts_with("oc_key_")` string-prefix checks with a
//! single [`Credential::parse`] entry point.
//!
//! - [`Credential::Passphrase`] — owner mode, raw passphrase bytes.
//! - [`Credential::ApiToken`] — agent mode, `oc_key_` prefixed token.
//!
//! Token generation uses 256 bits of entropy (`oc_key_` + 64 hex chars) and
//! only the SHA-256 hash is persisted. Lookup compares hashes with a
//! constant-time equality helper so key-file scans do not short-circuit on
//! the first differing byte.

use serde::{Deserialize, Serialize};

/// Prefix identifying agent API tokens.
pub const TOKEN_PREFIX: &str = "oc_key_";

/// Owner passphrase vs agent API token.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Credential {
    /// Owner passphrase (may be empty for unencrypted wallets).
    Passphrase(String),
    /// Agent API token (`oc_key_...`).
    ApiToken(String),
}

impl Credential {
    /// Classify a raw credential string by the `oc_key_` prefix.
    pub fn parse(raw: &str) -> Self {
        if raw.starts_with(TOKEN_PREFIX) {
            Self::ApiToken(raw.to_string())
        } else {
            Self::Passphrase(raw.to_string())
        }
    }

    /// True for agent API tokens.
    pub const fn is_token(&self) -> bool {
        matches!(self, Self::ApiToken(_))
    }

    /// Borrow the raw credential value.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Passphrase(s) | Self::ApiToken(s) => s,
        }
    }
}

impl std::fmt::Display for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // Never render secret material; show only the kind.
            Self::Passphrase(_) => write!(f, "<passphrase>"),
            Self::ApiToken(_) => write!(f, "<api-token>"),
        }
    }
}

/// Constant-time equality for hex hash strings.
///
/// Compares every byte and folds differences with `|` so the timing does not
/// reveal the first differing position. Length mismatch fails closed.
pub fn ct_eq(a: &str, b: &str) -> bool {
    let ab = a.as_bytes();
    let bb = b.as_bytes();
    if ab.len() != bb.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in ab.iter().zip(bb.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_routes_by_prefix() {
        assert!(matches!(Credential::parse("oc_key_abc"), Credential::ApiToken(_)));
        assert!(matches!(Credential::parse("hunter2"), Credential::Passphrase(_)));
        assert!(matches!(Credential::parse(""), Credential::Passphrase(_)));
    }

    #[test]
    fn display_never_leaks_secret() {
        assert_eq!(Credential::parse("oc_key_abc").to_string(), "<api-token>");
        assert_eq!(Credential::parse("secret").to_string(), "<passphrase>");
    }

    #[test]
    fn ct_eq_matches_equal_rejects_different() {
        assert!(ct_eq("abc", "abc"));
        assert!(!ct_eq("abc", "abd"));
        assert!(!ct_eq("abc", "abcd"));
        assert!(!ct_eq("", "x"));
    }
}
