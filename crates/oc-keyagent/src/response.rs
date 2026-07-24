//! `KeyAgentResponse` — the response enum for Key-Agent IPC.
//!
//! Encoded as a prost `oneof` with three variants: `Ok` (opaque prost payload),
//! `Deny` (policy rejection with a [`DenyReason`]), `Error` (internal error
//! string). The caller knows the expected response type from the request
//! variant and decodes the `Ok` payload accordingly.

use crate::proto::DenyReason;

/// A response from the Key-Agent to the Network-Agent over UDS.
#[derive(Clone, PartialEq, prost::Message)]
pub struct KeyAgentResponse {
    /// The response status (exactly one variant set).
    #[prost(oneof = "KeyAgentResponseKind", tags = "1, 2, 3")]
    pub kind: Option<KeyAgentResponseKind>,
}

/// The `oneof` payload of [`KeyAgentResponse`].
#[derive(Clone, PartialEq, Eq, prost::Oneof)]
pub enum KeyAgentResponseKind {
    /// Success — opaque prost-encoded response payload. The caller decodes
    /// this into the specific response type matching the request variant
    /// (e.g. `PayX402Response` for a `PayX402` request).
    #[prost(bytes, tag = "1")]
    Ok(Vec<u8>),
    /// Policy DENY — the request was rejected by the Policy Engine. Carries
    /// the [`DenyReason`] for the Network-Agent to surface to the user.
    #[prost(message, tag = "2")]
    Deny(DenyReasonPayload),
    /// Internal error — the request failed for a non-policy reason (decode
    /// failure, not-yet-implemented, I/O error, etc.).
    #[prost(string, tag = "3")]
    Error(String),
}

/// Wrapper to encode `DenyReason` as a proto message.
///
/// `prost` cannot place an `enumeration` directly as a `oneof` variant, so we
/// wrap it in a one-field message. The wire format is tag=1, varint value.
#[derive(Clone, Copy, PartialEq, Eq, prost::Message)]
pub struct DenyReasonPayload {
    #[prost(enumeration = "DenyReason", tag = "1")]
    pub reason: i32,
}

impl KeyAgentResponse {
    /// Build a successful response carrying an opaque prost-encoded payload.
    pub const fn ok(payload: Vec<u8>) -> Self {
        Self { kind: Some(KeyAgentResponseKind::Ok(payload)) }
    }

    /// Build a policy-deny response carrying the reason.
    pub const fn deny(reason: DenyReason) -> Self {
        Self { kind: Some(KeyAgentResponseKind::Deny(DenyReasonPayload { reason: reason as i32 })) }
    }

    /// Build an internal-error response.
    pub fn error(msg: impl Into<String>) -> Self {
        Self { kind: Some(KeyAgentResponseKind::Error(msg.into())) }
    }

    /// Build a "not yet implemented" error response (used by T11 stubs).
    pub fn not_implemented(feature: &str) -> Self {
        Self::error(format!("not yet implemented: {feature}"))
    }

    /// Returns `true` if this response is the `Error` variant.
    pub const fn is_error(&self) -> bool {
        matches!(self.kind, Some(KeyAgentResponseKind::Error(_)))
    }

    /// Returns `true` if this response is the `Deny` variant.
    pub const fn is_deny(&self) -> bool {
        matches!(self.kind, Some(KeyAgentResponseKind::Deny(_)))
    }
}

#[cfg(test)]
mod tests {
    use prost::Message;

    use super::*;

    #[test]
    fn test_ok_round_trip() {
        let resp = KeyAgentResponse::ok(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let bytes = resp.encode_to_vec();
        let decoded = KeyAgentResponse::decode(bytes.as_slice()).unwrap();
        assert_eq!(resp, decoded);
    }

    #[test]
    fn test_error_round_trip() {
        let resp = KeyAgentResponse::error("not yet implemented: PayX402 (T16/T13)");
        let bytes = resp.encode_to_vec();
        let decoded = KeyAgentResponse::decode(bytes.as_slice()).unwrap();
        assert_eq!(resp, decoded);
        assert!(decoded.is_error());
    }

    #[test]
    fn test_deny_round_trip() {
        let resp = KeyAgentResponse::deny(DenyReason::BudgetExceeded);
        let bytes = resp.encode_to_vec();
        let decoded = KeyAgentResponse::decode(bytes.as_slice()).unwrap();
        assert_eq!(resp, decoded);
        assert!(decoded.is_deny());
        match decoded.kind {
            Some(KeyAgentResponseKind::Deny(payload)) => {
                assert_eq!(payload.reason, DenyReason::BudgetExceeded as i32);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn test_empty_response_round_trip() {
        let resp = KeyAgentResponse { kind: None };
        let bytes = resp.encode_to_vec();
        let decoded = KeyAgentResponse::decode(bytes.as_slice()).unwrap();
        assert_eq!(resp, decoded);
    }

    #[test]
    fn test_all_deny_reasons_round_trip() {
        // All 9 R80 DenyReason variants must round-trip.
        let all = [
            DenyReason::RateLimitMinute,
            DenyReason::RateLimitHour,
            DenyReason::BudgetExceeded,
            DenyReason::Whitelist,
            DenyReason::Expired,
            DenyReason::PasskeyForged,
            DenyReason::PolicyMissing,
            DenyReason::Cooldown,
            DenyReason::Unknown,
        ];
        for reason in all {
            let resp = KeyAgentResponse::deny(reason);
            let bytes = resp.encode_to_vec();
            let decoded = KeyAgentResponse::decode(bytes.as_slice()).unwrap();
            assert_eq!(resp, decoded, "round-trip failed for {reason:?}");
        }
    }
}
