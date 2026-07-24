//! `KeyAgentRequest` — the request enum for Key-Agent IPC.
//!
//! Each variant wraps a prost wire-type message defined in [`crate::proto`].
//! The on-wire frame format is: 4-byte big-endian length prefix +
//! prost-encoded `KeyAgentRequest`. `KeyAgentRequest` itself is a prost
//! `oneof` (encoded as tag + nested message).
//!
//! The set of variants covers every Key-Agent operation; the former
//! `PayMPP` (bidirectional stream, never implemented) and `ListSessionKeys`
//! (folded into `ListWallets` since both use `Empty`) RPCs are omitted.

use crate::proto::{
    CreateSessionKeyRequest, GenerateChallengeRequest, GenerateTotpRequest, GetBalanceRequest,
    GetPaymentHistoryRequest, GetSecretRequest, ListSecretsRequest, PayX402Request,
    RegisterPasskeyRequest, RevokeSessionKeyRequest, SignMessageRequest, SignTransactionRequest,
    SignTypedDataRequest, SignUserOpRequest, UnlockVaultRequest,
};

/// A request sent from the Network-Agent to the Key-Agent over UDS.
///
/// Encoded as a prost `oneof`. The Network-Agent constructs the appropriate
/// variant, encodes it via `prost::Message::encode_to_vec`, and sends it as
/// a length-prefixed frame (see [`crate::frame::write_frame`]). The Key-Agent
/// decodes via `prost::Message::decode`, dispatches via
/// [`crate::handler::dispatch`], and responds with a
/// [`crate::response::KeyAgentResponse`].
#[derive(Clone, PartialEq, prost::Message)]
pub struct KeyAgentRequest {
    /// The request payload (exactly one variant set).
    #[prost(
        oneof = "KeyAgentRequestKind",
        tags = "1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17"
    )]
    pub kind: Option<KeyAgentRequestKind>,
}

/// The `oneof` payload of [`KeyAgentRequest`].
///
/// Tag numbers MUST match the wire format expected by the Network-Agent and
/// MUST NOT be reordered (wire compatibility).
// `large_enum_variant` is a known prost oneof pattern: each variant wraps a
// prost-generated request message, and the largest (`CreateSessionKeyRequest`,
// ~256 bytes with nested `Policy`/`BudgetAllocation`/`PasskeyAuthorization`)
// dominates the enum size. Boxing every variant would complicate the wire
// code (prost 0.13 needs `#[prost(message, boxed, ..)]`) for zero practical
// gain — the enum is constructed exactly once per request at the frame
// boundary and dropped at end of dispatch. The 256-byte stack copy is
// negligible vs. the IPC round-trip.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, PartialEq, prost::Oneof)]
pub enum KeyAgentRequestKind {
    /// `AgentService.CreateSessionKey` — requires PasskeyAuthorization (T15).
    #[prost(message, tag = "1")]
    CreateSessionKey(CreateSessionKeyRequest),
    /// `AgentService.RevokeSessionKey` — requires PasskeyAuthorization (T15).
    #[prost(message, tag = "2")]
    RevokeSessionKey(RevokeSessionKeyRequest),
    /// `AgentService.PayX402` — x402 payment (T16 policy + T13 signing).
    #[prost(message, tag = "3")]
    PayX402(PayX402Request),
    /// `AgentService.SignTransaction` — generic chain tx signing (T13).
    #[prost(message, tag = "4")]
    SignTransaction(SignTransactionRequest),
    /// `AgentService.SignUserOp` — EIP-4337 UserOp signing (T13).
    #[prost(message, tag = "5")]
    SignUserOp(SignUserOpRequest),
    /// `AgentService.SignMessage` — raw message signing (T13).
    #[prost(message, tag = "6")]
    SignMessage(SignMessageRequest),
    /// `AgentService.SignTypedData` — EIP-712 typed data signing (T13).
    #[prost(message, tag = "7")]
    SignTypedData(SignTypedDataRequest),
    /// `AgentService.GetPaymentHistory` — read-only (T18).
    #[prost(message, tag = "8")]
    GetPaymentHistory(GetPaymentHistoryRequest),
    /// `AgentService.GetBalance` — read-only (T18).
    #[prost(message, tag = "9")]
    GetBalance(GetBalanceRequest),
    /// `AgentService.ListWallets` — read-only (T18). Uses `Empty`.
    #[prost(message, tag = "10")]
    ListWallets(crate::proto::Empty),
    /// `AgentService.LockVault` — clears key cache, audit LOCK_VAULT.
    #[prost(message, tag = "11")]
    LockVault(crate::proto::Empty),
    /// `AgentService.UnlockVault` — verify Passkey, issue UnlockToken (Stage 0).
    #[prost(message, tag = "12")]
    UnlockVault(UnlockVaultRequest),
    /// `AgentService.RegisterPasskey` — store Passkey pubkey at wallet creation (Stage 0).
    #[prost(message, tag = "13")]
    RegisterPasskey(RegisterPasskeyRequest),
    /// `AgentService.GenerateChallenge` — issue a fresh Passkey challenge nonce (P0-2).
    /// Clients MUST call this before any Passkey-gated signing RPC so the
    /// Key-Agent can match the challenge against its pending_challenges set.
    #[prost(message, tag = "14")]
    GenerateChallenge(GenerateChallengeRequest),
    /// `AgentService.GetSecret` — read a secret by name (Phase 6).
    /// R56: Key-Agent returns "not implemented"; the CLI / Net-Agent handles
    /// the actual SecretStore operation (oc-keyagent cannot depend on oc-secret).
    #[prost(message, tag = "15")]
    GetSecret(GetSecretRequest),
    /// `AgentService.ListSecrets` — list secret index entries (Phase 6).
    /// R56: same as GetSecret — Key-Agent returns "not implemented".
    #[prost(message, tag = "16")]
    ListSecrets(ListSecretsRequest),
    /// `AgentService.GenerateTotp` — generate a TOTP code from a stored secret (Phase 6).
    /// R56: same as GetSecret — Key-Agent returns "not implemented".
    #[prost(message, tag = "17")]
    GenerateTotp(GenerateTotpRequest),
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use prost::Message;

    use super::*;

    #[test]
    fn test_empty_request_round_trip() {
        // A request with no kind set encodes to 0 bytes and decodes back to None.
        let req = KeyAgentRequest { kind: None };
        let bytes = req.encode_to_vec();
        assert!(bytes.is_empty());
        let decoded = KeyAgentRequest::decode(bytes.as_slice()).unwrap();
        assert_eq!(req, decoded);
        assert!(decoded.kind.is_none());
    }

    #[test]
    fn test_list_wallets_round_trip() {
        let req = KeyAgentRequest {
            kind: Some(KeyAgentRequestKind::ListWallets(crate::proto::Empty {})),
        };
        let bytes = req.encode_to_vec();
        let decoded = KeyAgentRequest::decode(bytes.as_slice()).unwrap();
        assert_eq!(req, decoded);
    }

    #[test]
    fn test_get_secret_round_trip() {
        let req = KeyAgentRequest {
            kind: Some(KeyAgentRequestKind::GetSecret(crate::proto::GetSecretRequest {
                name: "github/token".to_string(),
                api_token: "oc_key_abc123".to_string(),
            })),
        };
        let bytes = req.encode_to_vec();
        let decoded = KeyAgentRequest::decode(bytes.as_slice()).unwrap();
        assert_eq!(req, decoded);
    }

    #[test]
    fn test_list_secrets_round_trip() {
        let req = KeyAgentRequest {
            kind: Some(KeyAgentRequestKind::ListSecrets(crate::proto::ListSecretsRequest {
                api_token: "oc_key_xyz".to_string(),
            })),
        };
        let bytes = req.encode_to_vec();
        let decoded = KeyAgentRequest::decode(bytes.as_slice()).unwrap();
        assert_eq!(req, decoded);
    }

    #[test]
    fn test_generate_totp_round_trip() {
        let req = KeyAgentRequest {
            kind: Some(KeyAgentRequestKind::GenerateTotp(crate::proto::GenerateTotpRequest {
                name: "totp/github".to_string(),
                api_token: "oc_key_def".to_string(),
            })),
        };
        let bytes = req.encode_to_vec();
        let decoded = KeyAgentRequest::decode(bytes.as_slice()).unwrap();
        assert_eq!(req, decoded);
    }

    #[test]
    fn test_pay_x402_round_trip() {
        let mut headers = std::collections::HashMap::new();
        headers.insert("X-Idempotency-Key".to_string(), "abc-123".to_string());
        let req = KeyAgentRequest {
            kind: Some(KeyAgentRequestKind::PayX402(PayX402Request {
                session_key_id: "sk-test".to_string(),
                url: "https://example.com".to_string(),
                method: "GET".to_string(),
                body: vec![0xDE, 0xAD],
                headers,
                ..Default::default()
            })),
        };
        let bytes = req.encode_to_vec();
        let decoded = KeyAgentRequest::decode(bytes.as_slice()).unwrap();
        assert_eq!(req, decoded);
    }

    #[test]
    fn test_decode_garbage_no_panic() {
        // Garbage bytes must return Err, not panic.
        let garbage = vec![0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x01, 0x02];
        let _ = KeyAgentRequest::decode(garbage.as_slice());
    }

    proptest! {
        #[test]
        fn test_pay_x402_fuzz_round_trip(
            session_key_id in "[a-z0-9-]{1,32}",
            url in "https?://[a-z]{1,16}.[a-z]{1,8}",
            method in "(GET|POST|PUT|DELETE)",
            body in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..256),
        ) {
            let req = KeyAgentRequest {
                kind: Some(KeyAgentRequestKind::PayX402(PayX402Request {
                    session_key_id,
                    url,
                    method,
                    body,
                    headers: std::collections::HashMap::new(),
                    ..Default::default()
                })),
            };
            let bytes = req.encode_to_vec();
            let decoded = KeyAgentRequest::decode(bytes.as_slice()).unwrap();
            prop_assert_eq!(req, decoded);
        }
    }
}
