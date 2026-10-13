//! OCWP (OneCipher Wallet Protocol) error codes and JSON-RPC error mapping.
//!
//! The wire codes follow the extension design document
//! (`docs/extension-wallet-design.md` §5.3): EIP-1193 user/authorization codes,
//! a policy-denial range, and the standard JSON-RPC codes.

use serde_json::{Value, json};

/// User rejected the request (also approval-window expiry). Emitted
/// client-side; part of the documented wire protocol.
#[allow(dead_code)]
pub(super) const CODE_USER_REJECTED: i32 = 4001;
/// Unauthorized: locked, session expired, origin not allowed, step-up required.
pub(super) const CODE_UNAUTHORIZED: i32 = 4100;
/// Unsupported method / protocol version mismatch.
pub(super) const CODE_UNSUPPORTED: i32 = 4200;
/// Policy denied (generic).
pub(super) const CODE_POLICY_DENIED: i32 = 4300;
/// Policy denied: budget exceeded.
pub(super) const CODE_BUDGET_EXCEEDED: i32 = 4301;
/// Policy denied: rate limit.
pub(super) const CODE_RATE_LIMITED: i32 = 4302;
/// Policy denied: destination not whitelisted.
pub(super) const CODE_NOT_WHITELISTED: i32 = 4303;
/// Policy denied: expired policy/session key.
pub(super) const CODE_EXPIRED: i32 = 4304;
/// Policy denied: required policy set is empty/missing.
pub(super) const CODE_POLICY_MISSING: i32 = 4305;
/// Policy denied: cooldown active.
pub(super) const CODE_COOLDOWN: i32 = 4306;
/// Daemon unreachable (client-side mapping; part of the wire protocol).
#[allow(dead_code)]
pub(super) const CODE_DISCONNECTED: i32 = 4900;
/// Chain not connected for this site (part of the wire protocol).
#[allow(dead_code)]
pub(super) const CODE_CHAIN_NOT_CONNECTED: i32 = 4901;

/// An OCWP error: JSON-RPC code + message + optional structured data.
#[derive(Debug, Clone)]
pub(crate) struct OcwpError {
    pub code: i32,
    pub message: String,
    pub data: Option<Value>,
}

impl OcwpError {
    pub(crate) fn new(code: i32, message: impl Into<String>) -> Self {
        Self { code, message: message.into(), data: None }
    }

    pub(crate) fn with_data(code: i32, message: impl Into<String>, data: Value) -> Self {
        Self { code, message: message.into(), data: Some(data) }
    }

    /// `-32602` invalid params.
    pub(crate) fn invalid_params(message: impl Into<String>) -> Self {
        Self::new(-32602, message)
    }

    /// `-32603` internal error. L-07: callers pass a static, detail-free
    /// message; anything sensitive is logged, never returned.
    pub(crate) fn internal(message: &'static str) -> Self {
        Self::new(-32603, message)
    }

    /// `4100` unauthorized (locked / expired / not allowed).
    pub(crate) fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(CODE_UNAUTHORIZED, message)
    }

    /// `4100` with `data.require_passkey = true` — the client must run the
    /// passkey step-up and retry the request with a `passkey` object.
    pub(crate) fn require_passkey() -> Self {
        Self::with_data(
            CODE_UNAUTHORIZED,
            "passkey confirmation required",
            json!({ "require_passkey": true }),
        )
    }

    /// `4200` unsupported method / protocol version mismatch.
    pub(crate) fn unsupported(message: impl Into<String>) -> Self {
        Self::new(CODE_UNSUPPORTED, message)
    }

    /// Map a policy denial reason to the most specific error code, keeping the
    /// reason and policy id in `data` for the consent UI.
    pub(crate) fn from_policy_reason(reason: &str, policy_id: Option<&str>) -> Self {
        let lowered = reason.to_ascii_lowercase();
        let code = if lowered.contains("budget") {
            CODE_BUDGET_EXCEEDED
        } else if lowered.contains("rate limit") {
            CODE_RATE_LIMITED
        } else if lowered.contains("whitelist") || lowered.contains("allowlist") {
            CODE_NOT_WHITELISTED
        } else if lowered.contains("expired") {
            CODE_EXPIRED
        } else if lowered.contains("cooldown") {
            CODE_COOLDOWN
        } else if lowered.contains("no polic") || lowered.contains("missing") {
            CODE_POLICY_MISSING
        } else {
            CODE_POLICY_DENIED
        };
        let mut data = serde_json::Map::new();
        data.insert("reason".into(), json!(reason));
        if let Some(id) = policy_id {
            data.insert("policy_id".into(), json!(id));
        }
        Self::with_data(code, "policy denied", Value::Object(data))
    }
}

impl std::fmt::Display for OcwpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.message, self.code)
    }
}

impl From<OcwpError> for crate::commands::wallet_rpc::state::RpcError {
    fn from(e: OcwpError) -> Self {
        match e.data {
            Some(data) => Self::with_data(e.code, e.message, data),
            None => Self::new(e.code, e.message),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_reason_maps_to_specific_codes() {
        assert_eq!(
            OcwpError::from_policy_reason("budget exceeded", None).code,
            CODE_BUDGET_EXCEEDED
        );
        assert_eq!(OcwpError::from_policy_reason("rate limit hit", None).code, CODE_RATE_LIMITED);
        assert_eq!(
            OcwpError::from_policy_reason("address not in whitelist", None).code,
            CODE_NOT_WHITELISTED
        );
        assert_eq!(OcwpError::from_policy_reason("policy expired", None).code, CODE_EXPIRED);
        assert_eq!(OcwpError::from_policy_reason("cooldown active", None).code, CODE_COOLDOWN);
        assert_eq!(
            OcwpError::from_policy_reason("no policy matched", None).code,
            CODE_POLICY_MISSING
        );
        assert_eq!(OcwpError::from_policy_reason("denied", None).code, CODE_POLICY_DENIED);
    }

    #[test]
    fn require_passkey_carries_data_flag() {
        let err = OcwpError::require_passkey();
        assert_eq!(err.code, CODE_UNAUTHORIZED);
        assert_eq!(err.data.as_ref().and_then(|d| d.get("require_passkey")), Some(&json!(true)));
    }

    #[test]
    fn into_rpc_error_preserves_code_and_data() {
        let rpc: crate::commands::wallet_rpc::state::RpcError = OcwpError::require_passkey().into();
        assert_eq!(rpc.code(), CODE_UNAUTHORIZED);
    }
}
