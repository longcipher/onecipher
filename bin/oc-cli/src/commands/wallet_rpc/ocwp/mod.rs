//! OCWP — OneCipher Wallet Protocol: the JSON-RPC surface shared by the
//! browser extension (and future remote ends) with the OneCipher daemon.
//!
//! See `docs/extension-wallet-design.md` for the normative specification.
//! This module holds the shared [`AppState`] and connection validation; the
//! individual concerns live in submodules:
//!
//! - [`errors`] — OCWP error codes and policy-reason mapping.
//! - [`session`] — unlocked sessions (TTL/idle, `Zeroizing` passphrase).
//! - [`registries`] — authorized sites + chain registry (persisted 0600).
//! - [`policy_gate`] — policy evaluation for OCWP signing (D8).
//! - [`rpc_proxy`] — read-only JSON-RPC proxy + broadcast.
//! - [`handlers`] — the `oc_*` method implementations.

mod errors;
pub(crate) mod handlers;
mod policy_gate;
mod registries;
mod rpc_proxy;
mod session;
#[cfg(test)]
mod vectors;

use std::{path::Path, sync::Arc};

use axum::http::HeaderMap;
pub(crate) use errors::OcwpError;
pub(crate) use session::{SessionSettings, SessionStore};

use crate::commands::wallet_rpc::state::SignerState;

/// OCWP server settings (CLI flags / daemon env).
#[derive(Debug, Clone, Default)]
pub(crate) struct OcwpSettings {
    /// Allowed browser extension IDs (Origin allowlist). Empty = deny all.
    pub extension_ids: Vec<String>,
    /// Session absolute TTL seconds (default 900).
    pub session_ttl_secs: Option<u64>,
    /// Session idle TTL seconds (default 300).
    pub session_idle_secs: Option<u64>,
    /// Require passkey step-up for EIP-7702 authorization signing.
    pub require_passkey_eip7702: bool,
}

/// One outstanding passkey step-up challenge.
#[derive(Debug, Clone)]
pub(crate) struct StepUpBinding {
    /// Session that requested the challenge.
    pub session_id: String,
    /// Credential the challenge was minted for.
    pub credential_id: String,
    /// Unix seconds after which the binding is dead.
    pub expires_at: u64,
}

/// Short-lived, single-use bindings between an `oc_passkey_challenge` response
/// and the `passkey` object of the request that consumes it.
///
/// The keyagent already refuses to verify a challenge twice, but on its own it
/// has no notion of *which session* a challenge belongs to — any client with
/// access to the same wallet could satisfy another's step-up. Binding here
/// closes that: a challenge authorizes exactly one retry of exactly one
/// session, and only for `STEP_UP_TTL_SECS`.
#[derive(Debug)]
pub(crate) struct StepUpStore {
    bindings: dashmap::DashMap<String, StepUpBinding>,
}

/// How long a minted step-up challenge stays redeemable (design §3.5: a step-up
/// is a fresh confirmation, not a bearer token).
pub(crate) const STEP_UP_TTL_SECS: u64 = 120;

impl StepUpStore {
    pub(crate) fn new() -> Self {
        Self { bindings: dashmap::DashMap::new() }
    }

    /// Record a challenge for a session.
    pub(crate) fn issue(&self, challenge_hex: String, session_id: &str, credential_id: &str) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        // Opportunistic sweep: challenges are short-lived and the map only ever
        // holds one entry per in-flight step-up.
        self.bindings.retain(|_, binding| binding.expires_at > now);
        self.bindings.insert(
            challenge_hex,
            StepUpBinding {
                session_id: session_id.to_string(),
                credential_id: credential_id.to_string(),
                expires_at: now.saturating_add(STEP_UP_TTL_SECS),
            },
        );
    }

    /// Redeem a challenge: it must exist, be unexpired, and belong to
    /// `session_id`. Consumption is unconditional for the *rightful* owner —
    /// a redeemed challenge can never be replayed, even if the signature it
    /// carried fails to verify.
    ///
    /// A mismatched session does **not** consume the binding: otherwise any
    /// other allowlisted extension could invalidate a pending step-up simply by
    /// guessing its challenge, turning a replay defence into a denial of
    /// service. `remove_if` evaluates under the shard lock, so concurrent
    /// redemptions of the same challenge cannot both win.
    pub(crate) fn consume(&self, challenge_hex: &str, session_id: &str) -> Option<StepUpBinding> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut taken: Option<StepUpBinding> = None;
        self.bindings.remove_if(challenge_hex, |_, binding| {
            if binding.expires_at <= now || binding.session_id != session_id {
                return false;
            }
            taken = Some(binding.clone());
            true
        });
        taken
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.bindings.len()
    }
}

impl Default for StepUpStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Shared state for every wallet-rpc handler (ledgerflow + OCWP).
#[derive(Clone)]
pub(crate) struct AppState {
    /// The ledgerflow-compatible signer (wallet/index/passphrase at startup).
    pub signer: SignerState,
    /// OCWP unlocked sessions.
    pub sessions: Arc<SessionStore>,
    /// Outstanding passkey step-up challenges.
    pub step_up: Arc<StepUpStore>,
    /// Authorized dApp origins (`sites.json`).
    pub sites: Arc<registries::SiteStore>,
    /// Built-in + custom chains (`chains.json`).
    pub chains: Arc<registries::ChainRegistry>,
    /// Allowed browser extension IDs (Origin allowlist).
    pub extension_ids: Arc<Vec<String>>,
    /// User config (RPC endpoints).
    pub config: oc_core::Config,
    /// dApp-facing RPC proxy rate limiter.
    pub rate_limiter: Arc<rpc_proxy::RpcRateLimiter>,
    /// EIP-7702 step-up requirement.
    pub require_passkey_eip7702: bool,
}

impl AppState {
    /// Production constructor: registries live in `~/.onecipher`.
    pub(crate) fn new(signer: SignerState, settings: OcwpSettings) -> Result<Self, String> {
        let state_dir = oc_core::paths::state_dir().map_err(|e| e.to_string())?;
        Self::with_state_dir(signer, settings, &state_dir)
    }

    /// Constructor with an explicit state dir (tests / embedded use).
    pub(crate) fn with_state_dir(
        signer: SignerState,
        settings: OcwpSettings,
        state_dir: &Path,
    ) -> Result<Self, String> {
        let session_settings = SessionSettings {
            ttl_secs: settings.session_ttl_secs.unwrap_or(900),
            idle_secs: settings.session_idle_secs.unwrap_or(300),
        };
        Ok(Self {
            signer,
            sessions: Arc::new(SessionStore::new(session_settings)),
            step_up: Arc::new(StepUpStore::new()),
            sites: Arc::new(registries::SiteStore::open(state_dir)?),
            chains: Arc::new(registries::ChainRegistry::open(state_dir)),
            extension_ids: Arc::new(settings.extension_ids),
            config: oc_core::Config::load_or_default(),
            rate_limiter: Arc::new(rpc_proxy::RpcRateLimiter::new(30.0, 60.0)),
            require_passkey_eip7702: settings.require_passkey_eip7702,
        })
    }

    /// Validate an OCWP request's connection headers (design §3.4 / INV-9):
    /// loopback `Host` (anti DNS-rebinding) + allowlisted extension `Origin`.
    ///
    /// Returns the validated `chrome-extension://<id>` origin so the caller can
    /// bind sessions to it (see [`SessionStore::touch_for_origin`]).
    pub(crate) fn validate_connection(&self, headers: &HeaderMap) -> Result<String, OcwpError> {
        check_host(headers)?;
        let origin = headers
            .get(axum::http::header::ORIGIN)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| OcwpError::unauthorized("missing Origin header"))?;
        let id = origin
            .strip_prefix("chrome-extension://")
            .filter(|id| !id.is_empty() && !id.contains('/'))
            .ok_or_else(|| {
                OcwpError::unauthorized("Origin must be a chrome-extension:// origin")
            })?;
        if !self.extension_ids.iter().any(|allowed| allowed == id) {
            return Err(OcwpError::unauthorized("extension id is not allowed"));
        }
        Ok(format!("chrome-extension://{id}"))
    }
}

/// Daemon OCWP settings from environment variables.
///
/// - `OC_WALLET_RPC_EXTENSION_IDS` — comma-separated extension ID allowlist.
/// - `OC_WALLET_RPC_SESSION_TTL_SECS` / `OC_WALLET_RPC_SESSION_IDLE_SECS`.
/// - `OC_WALLET_RPC_REQUIRE_PASSKEY_EIP7702` — `1`/`true` enables step-up.
pub(crate) fn settings_from_env() -> OcwpSettings {
    let extension_ids = std::env::var("OC_WALLET_RPC_EXTENSION_IDS").map_or_default(|v| {
        v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
    });
    OcwpSettings {
        extension_ids,
        session_ttl_secs: std::env::var("OC_WALLET_RPC_SESSION_TTL_SECS")
            .ok()
            .and_then(|v| v.parse().ok()),
        session_idle_secs: std::env::var("OC_WALLET_RPC_SESSION_IDLE_SECS")
            .ok()
            .and_then(|v| v.parse().ok()),
        require_passkey_eip7702: std::env::var("OC_WALLET_RPC_REQUIRE_PASSKEY_EIP7702")
            .map_or(true, |v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes")),
    }
}

/// Validate only the `Host` header (loopback, anti DNS-rebinding). Applies to
/// every wallet-rpc method, including the ledgerflow aliases.
pub(crate) fn check_host(headers: &HeaderMap) -> Result<(), OcwpError> {
    let host =
        headers.get(axum::http::header::HOST).and_then(|v| v.to_str().ok()).unwrap_or_default();
    let host_name = host.rsplit_once(':').map_or(host, |(h, _)| h);
    let host_name = host_name.trim_start_matches('[').trim_end_matches(']');
    if !matches!(host_name, "127.0.0.1" | "localhost" | "::1") {
        return Err(OcwpError::unauthorized("invalid Host header"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (k, v) in pairs {
            map.insert(
                axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                axum::http::HeaderValue::from_str(v).unwrap(),
            );
        }
        map
    }

    fn test_state(extension_ids: Vec<String>) -> AppState {
        let dir = tempfile::tempdir().unwrap().keep();
        let signer = SignerState::new("default", 0);
        AppState::with_state_dir(
            signer,
            OcwpSettings { extension_ids, ..OcwpSettings::default() },
            &dir,
        )
        .expect("state")
    }

    const EXT_ORIGIN: &str = "chrome-extension://abcdefghijklmnopabcdefghijklmnop";

    #[test]
    fn valid_loopback_connection_passes() {
        let state = test_state(vec!["abcdefghijklmnopabcdefghijklmnop".into()]);
        assert!(
            state
                .validate_connection(&headers(&[
                    ("host", "127.0.0.1:18080"),
                    ("origin", EXT_ORIGIN),
                ]))
                .is_ok()
        );
        assert!(
            state
                .validate_connection(&headers(&[
                    ("host", "localhost:18080"),
                    ("origin", EXT_ORIGIN),
                ]))
                .is_ok()
        );
    }

    #[test]
    fn non_allowlisted_extension_id_is_rejected() {
        let state = test_state(vec!["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into()]);
        let err = state
            .validate_connection(&headers(&[("host", "127.0.0.1:18080"), ("origin", EXT_ORIGIN)]))
            .expect_err("unknown extension id must be rejected");
        assert_eq!(err.code, errors::CODE_UNAUTHORIZED);
    }

    #[test]
    fn empty_allowlist_denies_all() {
        let state = test_state(Vec::new());
        assert!(
            state
                .validate_connection(&headers(&[
                    ("host", "127.0.0.1:18080"),
                    ("origin", EXT_ORIGIN),
                ]))
                .is_err()
        );
    }

    #[test]
    fn dns_rebinding_host_is_rejected() {
        let state = test_state(vec!["abcdefghijklmnopabcdefghijklmnop".into()]);
        let err = state
            .validate_connection(&headers(&[("host", "evil.example.com"), ("origin", EXT_ORIGIN)]))
            .expect_err("non-loopback Host must be rejected");
        assert_eq!(err.code, errors::CODE_UNAUTHORIZED);
    }

    #[test]
    fn web_origin_and_missing_origin_are_rejected() {
        let state = test_state(vec!["abcdefghijklmnopabcdefghijklmnop".into()]);
        assert!(
            state
                .validate_connection(&headers(&[
                    ("host", "127.0.0.1:18080"),
                    ("origin", "https://dapp.example"),
                ]))
                .is_err()
        );
        assert!(state.validate_connection(&headers(&[("host", "127.0.0.1:18080")])).is_err());
    }

    #[test]
    fn default_settings_shape() {
        let settings = OcwpSettings::default();
        assert_eq!(settings.extension_ids, [] as [std::string::String; 0]);
    }

    #[test]
    fn validate_connection_returns_the_pinned_origin() {
        let state = test_state(vec!["abcdefghijklmnopabcdefghijklmnop".into()]);
        let origin = state
            .validate_connection(&headers(&[("host", "127.0.0.1:18080"), ("origin", EXT_ORIGIN)]))
            .expect("allowlisted origin");
        assert_eq!(origin, EXT_ORIGIN, "session binding needs the exact origin");
    }

    // -- step-up challenge bindings ------------------------------------------

    #[test]
    fn step_up_binding_is_single_use_and_session_scoped() {
        let store = StepUpStore::new();
        store.issue("aa".into(), "session-1", "cred-1");
        assert_eq!(store.len(), 1);
        // Another session cannot redeem it.
        assert!(store.consume("aa", "session-2").is_none());
        // The issuing session can, exactly once.
        let binding = store.consume("aa", "session-1").expect("issuing session redeems");
        assert_eq!(binding.credential_id, "cred-1");
        assert!(store.consume("aa", "session-1").is_none(), "replay must fail");
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn step_up_binding_expires() {
        let store = StepUpStore::new();
        // A binding whose deadline is already in the past (the `expires_at = 0`
        // sentinel used by the sweep) must not be redeemable.
        store.bindings.insert(
            "bb".into(),
            StepUpBinding { session_id: "s".into(), credential_id: "c".into(), expires_at: 0 },
        );
        assert!(store.consume("bb", "s").is_none(), "expired challenge must fail");
        // A failed redemption never consumes anything — only the `issue` sweep
        // evicts dead entries, so expiry cannot be abused to deny service.
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn step_up_foreign_redemption_does_not_destroy_the_binding() {
        let store = StepUpStore::new();
        store.issue("cc".into(), "owner", "cred");
        assert!(store.consume("cc", "intruder").is_none());
        // The rightful owner is unaffected by the intruder's attempt.
        assert_eq!(store.consume("cc", "owner").map(|b| b.credential_id), Some("cred".into()));
    }

    #[test]
    fn step_up_issue_sweeps_expired_bindings() {
        let store = StepUpStore::new();
        store.bindings.insert(
            "stale".into(),
            StepUpBinding { session_id: "s".into(), credential_id: "c".into(), expires_at: 0 },
        );
        store.issue("fresh".into(), "s", "c");
        assert_eq!(store.len(), 1, "expired bindings must not accumulate");
        assert!(store.consume("stale", "s").is_none());
    }
}
