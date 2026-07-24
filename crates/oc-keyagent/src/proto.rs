//! Prost wire types for Key-Agent ↔ Network-Agent IPC.
//!
//! Replaces the former `oc-proto` crate (deleted in the v0.5 simplification).
//! The ConnectRPC/tonic `service AgentService` definition was dead code — the
//! actual transport is UDS + length-prefixed prost frames (see [`crate::frame`]).
//! Only the message/enum types actually exercised by the IPC dispatch are
//! retained; the dead RPC stubs (PayMPP stream, Phase 6 secret responses)
//! were dropped.
//!
//! Field tag numbers mirror the original `proto/agent.proto` for defensive
//! wire compatibility (frames are not persisted in practice — they are
//! request/response scoped over a single UDS connection).
//!
//! ## R56 compliance
//!
//! `prost` is a pure codec crate (no I/O, no async runtime) — R56-safe for
//! `oc-keyagent`.

#![allow(clippy::derivable_impls)]

// ===========================================================================
// Common
// ===========================================================================

/// Local replacement for `google.protobuf.Empty` — avoids well-known-types
/// vendoring (ponytail ladder — minimum dep).
#[derive(Clone, PartialEq, Eq, Hash, prost::Message)]
pub struct Empty {}

/// Passkey challenge-response authorization. Required on all high-risk RPCs
/// (signing, session-key management, vault unlock).
#[derive(Clone, PartialEq, prost::Message)]
pub struct PasskeyAuthorization {
    /// Key-Agent-generated random nonce (32 bytes, single-use).
    #[prost(bytes, tag = "1")]
    pub challenge: Vec<u8>,
    /// UI process signs `challenge || credential_id` with the Passkey private key.
    #[prost(bytes, tag = "2")]
    pub signature: Vec<u8>,
    /// Passkey credential ID string.
    #[prost(string, tag = "3")]
    pub credential_id: String,
}

// ===========================================================================
// Challenge issuance (P0-2)
// ===========================================================================

/// `GenerateChallenge` request — issues a fresh 32-byte nonce for `credential_id`.
#[derive(Clone, PartialEq, prost::Message)]
pub struct GenerateChallengeRequest {
    /// Registered Passkey credential ID.
    #[prost(string, tag = "1")]
    pub credential_id: String,
}

/// `GenerateChallenge` response — single-use nonce, consumed on next verify.
#[derive(Clone, PartialEq, prost::Message)]
pub struct GenerateChallengeResponse {
    /// 32-byte random nonce.
    #[prost(bytes, tag = "1")]
    pub challenge: Vec<u8>,
}

// ===========================================================================
// Policy (mirrors oc_policy::v2 types — kept as proto wire types because
// proto messages are a separate type system from Rust domain types)
// ===========================================================================

/// Policy envelope attached to a session key.
#[derive(Clone, PartialEq, prost::Message)]
pub struct Policy {
    #[prost(uint32, tag = "1")]
    pub version: u32,
    #[prost(string, tag = "2")]
    pub session_key_id: String,
    #[prost(string, tag = "3")]
    pub device_id: String,
    #[prost(message, optional, tag = "4")]
    pub rules: Option<PolicyRulesV2>,
    #[prost(message, optional, tag = "5")]
    pub budget_allocation: Option<BudgetAllocation>,
}

/// Policy rules (rate limits, whitelists, expiry).
#[derive(Clone, PartialEq, prost::Message)]
pub struct PolicyRulesV2 {
    #[prost(double, tag = "1")]
    pub max_single_amount_usd: f64,
    #[prost(double, tag = "2")]
    pub max_daily_amount_usd: f64,
    #[prost(double, tag = "3")]
    pub max_monthly_amount_usd: f64,
    #[prost(uint64, tag = "4")]
    pub expiry_unix: u64,
    #[prost(uint32, tag = "5")]
    pub rate_limit_per_minute: u32,
    #[prost(uint32, tag = "6")]
    pub rate_limit_per_hour: u32,
    #[prost(uint64, tag = "7")]
    pub cooldown_after_denial_sec: u64,
    #[prost(string, repeated, tag = "8")]
    pub asset_whitelist: Vec<String>,
    #[prost(string, repeated, tag = "9")]
    pub chain_whitelist: Vec<String>,
    #[prost(string, repeated, tag = "10")]
    pub contract_whitelist: Vec<String>,
    #[prost(string, repeated, tag = "11")]
    pub payment_protocols: Vec<String>,
}

/// Budget allocation for a session key (sub-allocation of a parent budget).
#[derive(Clone, PartialEq, prost::Message)]
pub struct BudgetAllocation {
    #[prost(double, tag = "1")]
    pub allocated_usd: f64,
    #[prost(uint64, tag = "2")]
    pub allocated_at_unix: u64,
    #[prost(double, tag = "3")]
    pub parent_total_usd: f64,
    #[prost(string, tag = "4")]
    pub parent_session_id: String,
}

// ===========================================================================
// Session Key management
// ===========================================================================

#[derive(Clone, PartialEq, prost::Message)]
pub struct CreateSessionKeyRequest {
    #[prost(string, tag = "1")]
    pub label: String,
    #[prost(message, optional, tag = "2")]
    pub rules: Option<Policy>,
    #[prost(message, optional, tag = "3")]
    pub budget: Option<BudgetAllocation>,
    /// Required: proof of human presence.
    #[prost(message, optional, tag = "4")]
    pub auth: Option<PasskeyAuthorization>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct CreateSessionKeyResponse {
    #[prost(string, tag = "1")]
    pub session_key_id: String,
    #[prost(uint64, tag = "2")]
    pub created_at_unix: u64,
    #[prost(message, optional, tag = "3")]
    pub policy: Option<Policy>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct RevokeSessionKeyRequest {
    #[prost(string, tag = "1")]
    pub session_key_id: String,
    /// Required: proof of human presence.
    #[prost(message, optional, tag = "2")]
    pub auth: Option<PasskeyAuthorization>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct RevokeSessionKeyResponse {
    #[prost(uint64, tag = "1")]
    pub revoked_at_unix: u64,
}

/// `ListSessionKeys` response — sent by the Key-Agent in reply to the
/// `ListWallets` slot (the daemon folds list-session-keys into ListWallets per
/// `request.rs` deviation note; the CLI still consumes this type as the
/// canonical session-key listing).
#[derive(Clone, PartialEq, prost::Message)]
pub struct ListSessionKeysResponse {
    #[prost(message, repeated, tag = "1")]
    pub keys: Vec<SessionKeyInfo>,
}

/// Session key metadata entry.
#[derive(Clone, PartialEq, prost::Message)]
pub struct SessionKeyInfo {
    #[prost(string, tag = "1")]
    pub session_key_id: String,
    #[prost(string, tag = "2")]
    pub label: String,
    #[prost(uint64, tag = "3")]
    pub created_at_unix: u64,
    #[prost(uint64, tag = "4")]
    pub expires_at_unix: u64,
    #[prost(message, optional, tag = "5")]
    pub policy: Option<Policy>,
    #[prost(enumeration = "SessionKeyStatus", tag = "6")]
    pub status: i32,
}

// ===========================================================================
// Wallet management
// ===========================================================================

#[derive(Clone, PartialEq, prost::Message)]
pub struct ListWalletsResponse {
    #[prost(message, repeated, tag = "1")]
    pub wallets: Vec<WalletInfo>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct WalletInfo {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    pub name: String,
    #[prost(string, tag = "3")]
    pub key_type: String,
    #[prost(uint64, tag = "4")]
    pub created_at: u64,
    #[prost(message, repeated, tag = "5")]
    pub accounts: Vec<WalletAccount>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct WalletAccount {
    #[prost(string, tag = "1")]
    pub account_id: String,
    #[prost(string, tag = "2")]
    pub address: String,
    #[prost(string, tag = "3")]
    pub chain_id: String,
    #[prost(string, tag = "4")]
    pub derivation_path: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct GetBalanceRequest {
    #[prost(string, tag = "1")]
    pub wallet_id: String,
    #[prost(string, tag = "2")]
    pub chain_id: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct BalanceResponse {
    #[prost(string, tag = "1")]
    pub wallet_id: String,
    #[prost(string, tag = "2")]
    pub chain_id: String,
    #[prost(string, tag = "3")]
    pub balance: String,
    #[prost(uint32, tag = "4")]
    pub decimals: u32,
    #[prost(string, tag = "5")]
    pub symbol: String,
}

// ===========================================================================
// Signing
// ===========================================================================

#[derive(Clone, PartialEq, prost::Message)]
pub struct SignTransactionRequest {
    #[prost(string, tag = "1")]
    pub session_key_id: String,
    #[prost(string, tag = "2")]
    pub wallet_id: String,
    #[prost(string, tag = "3")]
    pub chain_id: String,
    #[prost(string, tag = "4")]
    pub raw_tx_hex: String,
    /// Required Passkey gate before signing (P0-2).
    #[prost(message, optional, tag = "5")]
    pub auth: Option<PasskeyAuthorization>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct SignTransactionResponse {
    #[prost(bytes, tag = "1")]
    pub signature: Vec<u8>,
    #[prost(string, tag = "2")]
    pub signed_tx_hex: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct SignUserOpRequest {
    #[prost(string, tag = "1")]
    pub session_key_id: String,
    #[prost(string, tag = "2")]
    pub wallet_id: String,
    #[prost(string, tag = "3")]
    pub chain_id: String,
    #[prost(string, tag = "4")]
    pub user_op_hex: String,
    /// Required Passkey gate before signing (P0-2).
    #[prost(message, optional, tag = "5")]
    pub auth: Option<PasskeyAuthorization>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct SignUserOpResponse {
    #[prost(bytes, tag = "1")]
    pub signature: Vec<u8>,
    #[prost(string, tag = "2")]
    pub signed_user_op_hex: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct SignMessageRequest {
    #[prost(string, tag = "1")]
    pub session_key_id: String,
    #[prost(string, tag = "2")]
    pub wallet_id: String,
    #[prost(bytes, tag = "3")]
    pub message: Vec<u8>,
    /// Required Passkey gate before signing (P0-2).
    #[prost(message, optional, tag = "4")]
    pub auth: Option<PasskeyAuthorization>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct SignMessageResponse {
    #[prost(bytes, tag = "1")]
    pub signature: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct SignTypedDataRequest {
    #[prost(string, tag = "1")]
    pub session_key_id: String,
    #[prost(string, tag = "2")]
    pub wallet_id: String,
    #[prost(string, tag = "3")]
    pub typed_data_json: String,
    /// Required Passkey gate before signing (P0-2).
    #[prost(message, optional, tag = "4")]
    pub auth: Option<PasskeyAuthorization>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct SignTypedDataResponse {
    #[prost(bytes, tag = "1")]
    pub signature: Vec<u8>,
}

// ===========================================================================
// Payments (x402)
// ===========================================================================

#[derive(Clone, PartialEq, prost::Message)]
pub struct PayX402Request {
    #[prost(string, tag = "1")]
    pub session_key_id: String,
    #[prost(string, tag = "2")]
    pub url: String,
    #[prost(string, tag = "3")]
    pub method: String,
    #[prost(bytes, tag = "4")]
    pub body: Vec<u8>,
    #[prost(map = "string, string", tag = "5")]
    pub headers: std::collections::HashMap<String, String>,
    /// Stage 0 additions — payment requirement fields.
    #[prost(double, tag = "6")]
    pub amount_usd: f64,
    /// CAIP-19 asset identifier.
    #[prost(string, tag = "7")]
    pub asset: String,
    /// CAIP-2 chain identifier.
    #[prost(string, tag = "8")]
    pub chain_id: String,
    /// Contract address or empty.
    #[prost(string, tag = "9")]
    pub recipient: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct PayX402Response {
    #[prost(enumeration = "PaymentStatus", tag = "1")]
    pub status: i32,
    #[prost(bytes, tag = "2")]
    pub receipt: Vec<u8>,
    #[prost(string, tag = "3")]
    pub retry_authorization: String,
    /// Populated on DENY (RATE_LIMIT / BUDGET_EXCEEDED / WHITELIST / etc.).
    #[prost(string, tag = "4")]
    pub deny_reason: String,
    #[prost(string, tag = "5")]
    pub error: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct GetPaymentHistoryRequest {
    #[prost(string, tag = "1")]
    pub session_key_id: String,
    #[prost(uint64, tag = "2")]
    pub since_unix: u64,
    #[prost(uint32, tag = "3")]
    pub limit: u32,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct PaymentHistoryResponse {
    #[prost(message, repeated, tag = "1")]
    pub records: Vec<PaymentRecord>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct PaymentRecord {
    #[prost(uint64, tag = "1")]
    pub timestamp_unix: u64,
    #[prost(string, tag = "2")]
    pub session_key_id: String,
    #[prost(double, tag = "3")]
    pub amount_usd: f64,
    #[prost(string, tag = "4")]
    pub asset: String,
    #[prost(string, tag = "5")]
    pub chain_id: String,
    #[prost(string, tag = "6")]
    pub recipient: String,
    #[prost(enumeration = "PaymentStatus", tag = "7")]
    pub status: i32,
    #[prost(bytes, tag = "8")]
    pub receipt: Vec<u8>,
    #[prost(string, tag = "9")]
    pub deny_reason: String,
}

// ===========================================================================
// Vault
// ===========================================================================

#[derive(Clone, PartialEq, prost::Message)]
pub struct LockVaultResponse {
    #[prost(bool, tag = "1")]
    pub locked: bool,
}

/// `UnlockVault` request — verify Passkey, issue an `UnlockToken` (32 bytes).
#[derive(Clone, PartialEq, prost::Message)]
pub struct UnlockVaultRequest {
    #[prost(string, tag = "1")]
    pub wallet_id: String,
    #[prost(message, optional, tag = "2")]
    pub auth: Option<PasskeyAuthorization>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct UnlockVaultResponse {
    /// 32-byte token.
    #[prost(bytes, tag = "1")]
    pub unlock_token: Vec<u8>,
    /// Token expiry timestamp.
    #[prost(uint64, tag = "2")]
    pub expires_at_unix: u64,
}

// ===========================================================================
// Passkey registration (Stage 0)
// ===========================================================================

#[derive(Clone, PartialEq, prost::Message)]
pub struct RegisterPasskeyRequest {
    #[prost(string, tag = "1")]
    pub wallet_id: String,
    #[prost(string, tag = "2")]
    pub credential_id: String,
    /// "p256" or "ed25519".
    #[prost(string, tag = "3")]
    pub algorithm: String,
    /// Raw public key bytes.
    #[prost(bytes, tag = "4")]
    pub public_key: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct RegisterPasskeyResponse {
    #[prost(bool, tag = "1")]
    pub registered: bool,
}

// ===========================================================================
// Secret vault (Phase 6 — request types only; Key-Agent returns
// "not implemented" for these. Response types are omitted as dead code.)
// ===========================================================================

#[derive(Clone, PartialEq, prost::Message)]
pub struct GetSecretRequest {
    /// Secret name (glob-checked against read_patterns).
    #[prost(string, tag = "1")]
    pub name: String,
    /// `oc_key_...` token for authorization.
    #[prost(string, tag = "2")]
    pub api_token: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct ListSecretsRequest {
    #[prost(string, tag = "1")]
    pub api_token: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct GenerateTotpRequest {
    /// Name of the TOTP secret entry.
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(string, tag = "2")]
    pub api_token: String,
}

// ===========================================================================
// Enums
// ===========================================================================

/// Payment status (mirrors `oc_policy` payment outcomes).
///
/// `#[derive(prost::Enumeration)]` generates `is_valid`, `from_i32`,
/// `Default`, `From<Self> for i32`, and `TryFrom<i32> for Self`.
/// The `as_str_name` / `from_str_name` helpers below are inherent methods
/// (prost 0.14 dropped the `Enumeration` trait — only the derive remains).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, prost::Enumeration)]
#[repr(i32)]
pub enum PaymentStatus {
    Ok = 0,
    Deny = 1,
    Error = 2,
}

impl PaymentStatus {
    /// Stable string name for audit logs and JSON serialization.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Self::Ok => "PAYMENT_STATUS_OK",
            Self::Deny => "PAYMENT_STATUS_DENY",
            Self::Error => "PAYMENT_STATUS_ERROR",
        }
    }

    /// Inverse of [`as_str_name`].
    pub fn from_str_name(name: &str) -> Option<Self> {
        match name {
            "PAYMENT_STATUS_OK" => Some(Self::Ok),
            "PAYMENT_STATUS_DENY" => Some(Self::Deny),
            "PAYMENT_STATUS_ERROR" => Some(Self::Error),
            _ => None,
        }
    }
}

/// Policy denial reason (mirrors `oc_policy::v2::DenyReason` — R80: exactly 9 variants).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, prost::Enumeration)]
#[repr(i32)]
pub enum DenyReason {
    RateLimitMinute = 0,
    RateLimitHour = 1,
    BudgetExceeded = 2,
    Whitelist = 3,
    Expired = 4,
    PasskeyForged = 5,
    PolicyMissing = 6,
    Cooldown = 7,
    Unknown = 8,
}

impl DenyReason {
    /// Stable string name for audit logs and JSON serialization.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Self::RateLimitMinute => "DENY_REASON_RATE_LIMIT_MINUTE",
            Self::RateLimitHour => "DENY_REASON_RATE_LIMIT_HOUR",
            Self::BudgetExceeded => "DENY_REASON_BUDGET_EXCEEDED",
            Self::Whitelist => "DENY_REASON_WHITELIST",
            Self::Expired => "DENY_REASON_EXPIRED",
            Self::PasskeyForged => "DENY_REASON_PASSKEY_FORGED",
            Self::PolicyMissing => "DENY_REASON_POLICY_MISSING",
            Self::Cooldown => "DENY_REASON_COOLDOWN",
            Self::Unknown => "DENY_REASON_UNKNOWN",
        }
    }

    /// Inverse of [`as_str_name`].
    pub fn from_str_name(name: &str) -> Option<Self> {
        match name {
            "DENY_REASON_RATE_LIMIT_MINUTE" => Some(Self::RateLimitMinute),
            "DENY_REASON_RATE_LIMIT_HOUR" => Some(Self::RateLimitHour),
            "DENY_REASON_BUDGET_EXCEEDED" => Some(Self::BudgetExceeded),
            "DENY_REASON_WHITELIST" => Some(Self::Whitelist),
            "DENY_REASON_EXPIRED" => Some(Self::Expired),
            "DENY_REASON_PASSKEY_FORGED" => Some(Self::PasskeyForged),
            "DENY_REASON_POLICY_MISSING" => Some(Self::PolicyMissing),
            "DENY_REASON_COOLDOWN" => Some(Self::Cooldown),
            "DENY_REASON_UNKNOWN" => Some(Self::Unknown),
            _ => None,
        }
    }
}

/// Session key lifecycle status.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, prost::Enumeration)]
#[repr(i32)]
pub enum SessionKeyStatus {
    Active = 0,
    Revoked = 1,
    Expired = 2,
}

impl SessionKeyStatus {
    /// Stable string name for audit logs and JSON serialization.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Self::Active => "SESSION_KEY_STATUS_ACTIVE",
            Self::Revoked => "SESSION_KEY_STATUS_REVOKED",
            Self::Expired => "SESSION_KEY_STATUS_EXPIRED",
        }
    }

    /// Inverse of [`as_str_name`].
    pub fn from_str_name(name: &str) -> Option<Self> {
        match name {
            "SESSION_KEY_STATUS_ACTIVE" => Some(Self::Active),
            "SESSION_KEY_STATUS_REVOKED" => Some(Self::Revoked),
            "SESSION_KEY_STATUS_EXPIRED" => Some(Self::Expired),
            _ => None,
        }
    }
}

// ===========================================================================
// Tests — round-trip coverage for the migrated types
// ===========================================================================

#[cfg(test)]
mod tests {
    use prost::Message;

    use super::*;

    fn roundtrip<M>(msg: &M) -> M
    where
        M: Message + Clone + PartialEq + std::fmt::Debug + Default,
    {
        let buf = msg.encode_to_vec();
        Message::decode(buf.as_slice()).expect("decode must succeed for a validly-encoded message")
    }

    #[test]
    fn empty_encodes_to_zero_bytes() {
        let empty = Empty {};
        assert!(empty.encode_to_vec().is_empty());
        let decoded: Empty = Message::decode(&[][..]).unwrap();
        assert_eq!(empty, decoded);
    }

    #[test]
    fn passkey_authorization_roundtrip() {
        let original = PasskeyAuthorization {
            challenge: vec![0xDE, 0xAD, 0xBE, 0xEF],
            signature: vec![0x01, 0x02, 0x03, 0x04, 0x05],
            credential_id: "cred-12345".to_string(),
        };
        assert_eq!(original, roundtrip(&original));
    }

    #[test]
    fn payx402_request_roundtrip_with_headers() {
        let mut headers = std::collections::HashMap::new();
        headers.insert("X-Idempotency-Key".to_string(), "abc-123".to_string());
        headers.insert("Authorization".to_string(), "Bearer token".to_string());
        let original = PayX402Request {
            session_key_id: "sk-7f3a".to_string(),
            url: "https://pay.example/x402".to_string(),
            method: "POST".to_string(),
            body: b"{\"amount\":100}".to_vec(),
            headers,
            amount_usd: 1.5,
            asset: "eip155:1/erc20:0xabc".to_string(),
            chain_id: "eip155:1".to_string(),
            recipient: "0xrecipient".to_string(),
        };
        let decoded = roundtrip(&original);
        assert_eq!(original, decoded);
        assert_eq!(decoded.headers.len(), 2);
        assert_eq!(decoded.headers.get("X-Idempotency-Key"), Some(&"abc-123".to_string()));
    }

    #[test]
    fn payx402_response_roundtrip_with_deny_reason() {
        let original = PayX402Response {
            status: PaymentStatus::Deny as i32,
            receipt: vec![0xAA, 0xBB],
            retry_authorization: "retry-after-60s".to_string(),
            deny_reason: "RATE_LIMIT_MINUTE".to_string(),
            error: String::new(),
        };
        assert_eq!(original, roundtrip(&original));
    }

    #[test]
    fn create_session_key_request_roundtrip_with_auth() {
        let auth = PasskeyAuthorization {
            challenge: vec![0x10; 32],
            signature: vec![0x20; 64],
            credential_id: "cred-abc".to_string(),
        };
        let original = CreateSessionKeyRequest {
            label: "test-session".to_string(),
            rules: None,
            budget: None,
            auth: Some(auth),
        };
        let decoded = roundtrip(&original);
        assert_eq!(original, decoded);
        assert!(decoded.auth.is_some(), "auth must round-trip");
    }

    #[test]
    fn payment_status_enum_values_and_names() {
        assert_eq!(PaymentStatus::Ok as i32, 0);
        assert_eq!(PaymentStatus::Deny as i32, 1);
        assert_eq!(PaymentStatus::Error as i32, 2);
        assert_eq!(PaymentStatus::default(), PaymentStatus::Ok);
        for v in [PaymentStatus::Ok, PaymentStatus::Deny, PaymentStatus::Error] {
            let name = v.as_str_name();
            assert_eq!(PaymentStatus::from_str_name(name), Some(v));
        }
        assert_eq!(PaymentStatus::from_str_name("UNKNOWN"), None);
    }

    #[test]
    fn deny_reason_enum_values_and_names() {
        assert_eq!(DenyReason::RateLimitMinute as i32, 0);
        assert_eq!(DenyReason::Unknown as i32, 8);
        assert_eq!(DenyReason::default(), DenyReason::RateLimitMinute);
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
        for v in all {
            let name = v.as_str_name();
            assert_eq!(DenyReason::from_str_name(name), Some(v));
        }
        assert_eq!(DenyReason::from_str_name("UNKNOWN"), None);
    }

    #[test]
    fn deny_reason_try_from_i32_round_trip() {
        for v in [DenyReason::RateLimitMinute, DenyReason::BudgetExceeded, DenyReason::Unknown] {
            let recovered =
                DenyReason::try_from(v as i32).expect("try_from must succeed for valid value");
            assert_eq!(recovered, v);
        }
        assert!(DenyReason::try_from(999).is_err(), "out-of-range i32 must error");
    }

    #[test]
    fn decode_malformed_bytes_does_not_panic() {
        let garbage: Vec<u8> = vec![0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x01, 0x02];
        let _ = PayX402Request::decode(garbage.as_slice());
    }

    #[test]
    fn wallet_info_with_accounts_roundtrip() {
        let original = ListWalletsResponse {
            wallets: vec![WalletInfo {
                id: "w1".to_string(),
                name: "primary".to_string(),
                key_type: "mnemonic".to_string(),
                created_at: 1_700_000_000,
                accounts: vec![WalletAccount {
                    account_id: "acc-1".to_string(),
                    address: "0xabc".to_string(),
                    chain_id: "eip155:1".to_string(),
                    derivation_path: "m/44'/60'/0'/0/0".to_string(),
                }],
            }],
        };
        assert_eq!(original, roundtrip(&original));
    }

    #[test]
    fn policy_with_rules_roundtrip() {
        let original = Policy {
            version: 2,
            session_key_id: "sk-1".to_string(),
            device_id: "dev-1".to_string(),
            rules: Some(PolicyRulesV2 {
                max_single_amount_usd: 100.0,
                max_daily_amount_usd: 1000.0,
                max_monthly_amount_usd: 10_000.0,
                expiry_unix: 1_800_000_000,
                rate_limit_per_minute: 10,
                rate_limit_per_hour: 100,
                cooldown_after_denial_sec: 60,
                asset_whitelist: vec!["eip155:1/erc20:0xabc".to_string()],
                chain_whitelist: vec!["eip155:1".to_string()],
                contract_whitelist: vec![],
                payment_protocols: vec!["x402".to_string()],
            }),
            budget_allocation: Some(BudgetAllocation {
                allocated_usd: 500.0,
                allocated_at_unix: 1_700_000_000,
                parent_total_usd: 5000.0,
                parent_session_id: "sk-parent".to_string(),
            }),
        };
        assert_eq!(original, roundtrip(&original));
    }

    #[test]
    fn unlock_vault_response_roundtrip() {
        let original =
            UnlockVaultResponse { unlock_token: vec![0x42; 32], expires_at_unix: 1_800_000_000 };
        assert_eq!(original, roundtrip(&original));
    }

    #[test]
    fn generate_challenge_response_roundtrip() {
        let original = GenerateChallengeResponse { challenge: vec![0xAB; 32] };
        assert_eq!(original, roundtrip(&original));
    }

    #[test]
    fn session_key_status_enum_roundtrip() {
        assert_eq!(SessionKeyStatus::Active as i32, 0);
        assert_eq!(SessionKeyStatus::Revoked as i32, 1);
        assert_eq!(SessionKeyStatus::Expired as i32, 2);
        assert_eq!(SessionKeyStatus::default(), SessionKeyStatus::Active);
        for v in [SessionKeyStatus::Active, SessionKeyStatus::Revoked, SessionKeyStatus::Expired] {
            let name = v.as_str_name();
            assert_eq!(SessionKeyStatus::from_str_name(name), Some(v));
        }
        assert_eq!(SessionKeyStatus::from_str_name("UNKNOWN"), None);
    }

    #[test]
    fn list_session_keys_response_roundtrip() {
        let original = ListSessionKeysResponse {
            keys: vec![SessionKeyInfo {
                session_key_id: "sk-1".to_string(),
                label: "alpha".to_string(),
                created_at_unix: 1_700_000_000,
                expires_at_unix: 1_800_000_000,
                policy: None,
                status: SessionKeyStatus::Active as i32,
            }],
        };
        assert_eq!(original, roundtrip(&original));
    }
}
