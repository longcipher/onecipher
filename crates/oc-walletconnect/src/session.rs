//! WC v2 session state machine + topic-indexed table.
//!
//! Lifecycle: Propose → Settle (Active) → Expired | Closed
//! Each session has: topic, symKey, expiry, approved CAIP-2 namespaces,
//! approved JSON-RPC methods, and optional dApp origin metadata.
//!
//! The `sym_key` is the **session** symmetric key. For a pairing (Propose
//! state) it is the pairing key from the URI; once a session is settled it is
//! the X25519+HKDF-derived session key (per the official client's
//! `deriveSymKey`).

use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

use crate::error::{WcError, WcResult};

/// Wrapper for WC symmetric keys that zeroizes on drop and redacts in Debug.
/// Note: uses String internally for serde compatibility but zeroizes on drop.
#[derive(Clone, Serialize, Deserialize)]
pub struct WcSymKeyHex(String);

impl WcSymKeyHex {
    pub fn new(hex_key: String) -> Self {
        Self(hex_key)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn decode_bytes(&self) -> Option<Vec<u8>> {
        hex::decode(&self.0).ok()
    }

    /// Parse into a [`crate::crypto::WcSymKey`] if the hex decodes to 32 bytes.
    pub fn to_sym_key(&self) -> Option<crate::crypto::WcSymKey> {
        let bytes = self.decode_bytes()?;
        if bytes.len() != 32 {
            return None;
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Some(crate::crypto::WcSymKey::from_bytes(arr))
    }
}

impl std::fmt::Debug for WcSymKeyHex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WcSymKeyHex([REDACTED])")
    }
}

impl Drop for WcSymKeyHex {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.0.zeroize();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WcSessionState {
    Propose,
    Active,
    Expired,
    Closed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WcSession {
    pub topic: String,
    pub sym_key: WcSymKeyHex,
    pub state: WcSessionState,
    pub expiry_unix: u64,
    pub namespaces: Vec<String>,
    pub methods: Vec<String>,
    pub dapp_origin: Option<String>,
    pub dapp_name: Option<String>,
    pub created_at_unix: u64,
}

impl WcSession {
    pub fn new_pairing(topic: String, sym_key: String, expiry_unix: u64) -> Self {
        Self {
            topic,
            sym_key: WcSymKeyHex::new(sym_key),
            state: WcSessionState::Propose,
            expiry_unix,
            namespaces: Vec::new(),
            methods: Vec::new(),
            dapp_origin: None,
            dapp_name: None,
            created_at_unix: now_unix(),
        }
    }

    pub fn settle(&mut self, topic: String, namespaces: Vec<String>, methods: Vec<String>) {
        self.topic = topic;
        self.namespaces = namespaces;
        self.methods = methods;
        self.state = WcSessionState::Active;
    }

    pub fn expire(&mut self) {
        self.state = WcSessionState::Expired;
    }

    pub fn close(&mut self) {
        self.state = WcSessionState::Closed;
    }

    pub fn is_active(&self) -> bool {
        self.state == WcSessionState::Active && now_unix() < self.expiry_unix
    }

    /// Whether the session still needs an active relay subscription.
    ///
    /// Pairing sessions sit in `Propose` state until the dApp's
    /// `wc_sessionPropose` settles them; they must be subscribed *before* that
    /// message arrives, which is why a non-`Active` pairing is included here.
    /// Expired/closed sessions no longer need the relay.
    pub fn needs_relay(&self) -> bool {
        now_unix() < self.expiry_unix &&
            (self.state == WcSessionState::Propose || self.state == WcSessionState::Active)
    }

    pub fn is_method_allowed(&self, method: &str) -> bool {
        self.methods.iter().any(|m| m == method)
    }

    /// Whether `caip2` is covered by the session's approved namespaces.
    ///
    /// Entries match exactly; an entry ending in `*` (e.g. `eip155:*`) acts as
    /// a family wildcard covering any chain id in that namespace (`eip155:1`,
    /// `eip155:137`, ...). Wildcards are produced when a session proposal
    /// declares a namespace without an explicit `chains` array.
    pub fn is_chain_allowed(&self, caip2: &str) -> bool {
        self.namespaces.iter().any(|n| match n.strip_suffix('*') {
            Some(family) => caip2.starts_with(family),
            None => n == caip2,
        })
    }

    pub fn ensure_active(&self) -> WcResult<()> {
        if !self.is_active() {
            return Err(WcError::SessionExpired(self.topic.clone()));
        }
        Ok(())
    }
}

impl From<crate::crypto::WcSymKey> for WcSymKeyHex {
    fn from(k: crate::crypto::WcSymKey) -> Self {
        Self::new(k.to_hex())
    }
}

#[derive(Debug, Default)]
pub struct WcSessionTable {
    sessions: HashMap<String, WcSession>,
}

impl WcSessionTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, session: WcSession) {
        self.sessions.insert(session.topic.clone(), session);
    }

    pub fn get(&self, topic: &str) -> Option<&WcSession> {
        self.sessions.get(topic)
    }

    pub fn get_mut(&mut self, topic: &str) -> Option<&mut WcSession> {
        self.sessions.get_mut(topic)
    }

    pub fn remove(&mut self, topic: &str) -> Option<WcSession> {
        self.sessions.remove(topic)
    }

    pub fn iter(&self) -> impl Iterator<Item = &WcSession> {
        self.sessions.values()
    }

    pub fn purge_expired(&mut self) {
        let now = now_unix();
        self.sessions.retain(|_, s| s.expiry_unix > now);
    }
}

/// Lowest Unix timestamp considered plausible (2001-09-09). Readings below
/// this are treated as a corrupted clock rather than trusted.
pub const MIN_PLAUSIBLE_UNIX_SECS: u64 = 1_000_000_000;

/// Map a raw seconds reading to the fail-closed clock value (L-08).
///
/// A corrupted system clock previously yielded `0`, which made every expired
/// session look active (`0 < expiry_unix`) and defeated `purge_expired`.
/// Instead, implausible readings map to `u64::MAX`: every time comparison
/// (`is_active`, `needs_relay`, `purge_expired`) then treats sessions as
/// EXPIRED until the clock reports a sane value again.
fn sanitize_unix_secs(raw: u64) -> u64 {
    if raw >= MIN_PLAUSIBLE_UNIX_SECS { raw } else { u64::MAX }
}

/// Current Unix timestamp in seconds, fail-closed on clock errors.
///
/// Mirrors the Net-Agent router's fail-closed `now_unix_secs`
/// (`oc-netagent::wc_method_router`); that helper returns a `Result` keyed to
/// JSON-RPC error types and cannot be reused here because
/// `oc-walletconnect` must not depend on `oc-netagent`.
pub fn now_unix() -> u64 {
    sanitize_unix_secs(SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs()))
}

/// Current UTC time as an RFC 3339 string (used for EIP-4361 `Issued At`).
///
/// Falls back to the Unix epoch string if the system clock is before the
/// epoch (a corrupted clock should not panic the builder).
pub fn now_rfc3339() -> String {
    let secs = now_unix() as i64;
    let (secs, nanos) = if secs < 0 {
        (secs, 0u32)
    } else {
        let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
        (secs, d.subsec_nanos())
    };
    // Manual RFC 3339 UTC formatting (no chrono/time dependency): compute the
    // civil date from the Unix timestamp via Howard Hinnant's algorithm.
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    let (hh, mm, ss) =
        (secs.rem_euclid(86_400) / 3600, secs.rem_euclid(3600) / 60, secs.rem_euclid(60));
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}.{nanos:09}Z")
}

/// Convert days since the Unix epoch to a `(year, month, day)` civil date
/// (Howard Hinnant's `civil_from_days` algorithm).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn now_unix_fails_closed_on_implausible_clock() {
        assert_eq!(sanitize_unix_secs(0), u64::MAX);
        assert_eq!(sanitize_unix_secs(999_999_999), u64::MAX);
        assert_eq!(sanitize_unix_secs(MIN_PLAUSIBLE_UNIX_SECS), MIN_PLAUSIBLE_UNIX_SECS);
        assert_eq!(sanitize_unix_secs(1_700_000_000), 1_700_000_000);
        // The live clock is sane in the test environment.
        assert!(now_unix() >= MIN_PLAUSIBLE_UNIX_SECS);
        assert_ne!(now_unix(), u64::MAX);
    }

    #[test]
    fn fail_closed_clock_reading_treats_sessions_as_expired() {
        // A pre-epoch reading maps to u64::MAX, so every expiry lands in the
        // "past" under the same `<` comparison used by is_active/needs_relay.
        let broken_now = sanitize_unix_secs(0);
        let expiry = u64::MAX - 60;
        assert!(broken_now >= expiry);
        // The identical session is active under a sane reading.
        let sane_now = sanitize_unix_secs(1_700_000_000);
        assert!(sane_now < expiry);
    }

    #[test]
    fn chain_allowlist_supports_exact_and_wildcard_entries() {
        let mut s = WcSession::new_pairing("t".into(), "ab".repeat(32), u64::MAX);
        s.settle("t".into(), vec!["eip155:1".into(), "solana:*".into()], vec![]);
        assert!(s.is_chain_allowed("eip155:1"));
        assert!(!s.is_chain_allowed("eip155:137"));
        assert!(s.is_chain_allowed("solana:mainnet"));
        assert!(s.is_chain_allowed("solana:devnet"));
        assert!(!s.is_chain_allowed("bitcoin:mainnet"));
    }
}
