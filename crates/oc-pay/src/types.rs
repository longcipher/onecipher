//! Domain types for `oc-pay`.
//!
//! Per R36, [`PaymentSettler`] operates over [`SessionKey`] (the payer),
//! [`Caip19Asset`] (the asset being spent), [`PaymentScheme`] (the x402
//! scheme), [`PaymentReceipt`] (the result of a settlement), and
//! [`ChannelId`] (the MPP channel handle).
//!
//! # Phase 1 MVP scope
//!
//! Phase 1 defines minimal newtypes here — full CAIP-19 parsing, on-chain
//! receipt decoding, and channel-state introspection are T19 / T20's job.

use std::{fmt, str::FromStr};

use oc_session_key::{KeyScheme, PublicKey};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};

/// CAIP-19 asset identifier newtype.
///
/// CAIP-19 strings look like `"eip155:8453/slip44:60"` (Base native asset) or
/// `"eip155:1/erc20:0x6B175474E89094C44Da98b954EedeAC495271d0F"` (Dai on
/// Ethereum mainnet). Phase 1 wraps the string in a newtype so the
/// [`PaymentSettler`](crate::PaymentSettler) signature is self-documenting;
/// full CAIP-19 parse / validate logic lives in `oc-netagent` (Phase D).
///
/// `oc-core` currently defines only CAIP-2 ([`oc_core::ChainId`]); we define
/// CAIP-19 here rather than touching `oc-core` to keep T18 self-contained.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Caip19Asset(String);

impl Caip19Asset {
    /// Construct a new `Caip19Asset` from a validated CAIP-19 string.
    ///
    /// Performs only minimal structural validation (non-empty, contains `/`).
    /// Full validation is delegated to the consumer (Phase D).
    pub fn new(s: impl Into<String>) -> Result<Self, crate::PayError> {
        let s = s.into();
        if s.is_empty() {
            return Err(crate::PayError::InvalidRecipient("CAIP-19 asset id is empty".to_string()));
        }
        if !s.contains('/') {
            return Err(crate::PayError::InvalidRecipient(format!(
                "CAIP-19 asset id missing '/': {s}"
            )));
        }
        Ok(Self(s))
    }

    /// Construct a `Caip19Asset` without validation (for tests / known-good
    /// constants).
    pub fn unchecked(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// The raw CAIP-19 string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Caip19Asset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Caip19Asset {
    type Err = crate::PayError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

/// x402 payment scheme.
///
/// Per R8, the Phase 1 MVP supports two x402 schemes:
/// - [`PaymentScheme::Exact`] — single-shot exact payment (facilitator settles one tx; no on-chain
///   account abstraction).
/// - [`PaymentScheme::ExactPlusUserOp`] — exact payment sponsored through an EIP-4337 UserOp
///   (Paymaster sponsors gas; SCA verifies ERC-7715 session key).
///
/// Future schemes (`upto`, `aggr_deferred`) are out of scope for Phase 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentScheme {
    /// Single-shot exact payment (no UserOp).
    Exact,
    /// Exact payment via EIP-4337 UserOp (Paymaster-sponsored gas).
    #[serde(rename = "exact+userop")]
    ExactPlusUserOp,
}

impl PaymentScheme {
    /// Lowercase scheme id as it appears on the wire (`"exact"`,
    /// `"exact+userop"`).
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::ExactPlusUserOp => "exact+userop",
        }
    }
}

impl fmt::Display for PaymentScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for PaymentScheme {
    type Err = crate::PayError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "exact" => Ok(Self::Exact),
            "exact+userop" => Ok(Self::ExactPlusUserOp),
            other => {
                Err(crate::PayError::InvalidRecipient(format!("unknown payment scheme: {other}")))
            }
        }
    }
}

/// Receipt returned by [`PaymentSettler::pay_exact`](crate::PaymentSettler) and
/// [`PaymentSettler::close_channel`](crate::PaymentSettler).
///
/// Phase 1 carries the chain-specific on-chain identifier (tx hash / Solana
/// signature / Tempo channel-close tx) plus enough metadata for downstream
/// auditing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentReceipt {
    /// CAIP-2 chain id on which the payment settled.
    pub chain_id: String,
    /// Scheme used to settle.
    pub scheme: PaymentScheme,
    /// On-chain settlement identifier:
    /// - EVM: `0x`-prefixed tx hash returned by the Bundler.
    /// - Solana: base58 transaction signature.
    /// - Tempo: channel-close tx hash (EVM or Solana, depending on chain).
    pub tx_hash: String,
    /// Amount settled, in the smallest on-chain unit recorded by the receipt.
    /// (For x402 `exact`, this equals the requested amount; for MPP
    /// `close_channel`, this is the channel's total streamed amount.)
    pub amount: Decimal,
    /// CAIP-19 asset that was spent.
    pub asset: Caip19Asset,
    /// Recipient identifier (CAIP-10 address, base58 pubkey, or Tempo peer id).
    pub recipient: String,
    /// Optional free-form metadata returned by the settler (e.g. Paymaster
    /// sponsorship id, Tempo channel id, Bundler userOp hash).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

impl PaymentReceipt {
    /// Construct a minimal receipt with the required fields and no metadata.
    pub fn new(
        chain_id: impl Into<String>,
        scheme: PaymentScheme,
        tx_hash: impl Into<String>,
        amount: Decimal,
        asset: Caip19Asset,
        recipient: impl Into<String>,
    ) -> Self {
        Self {
            chain_id: chain_id.into(),
            scheme,
            tx_hash: tx_hash.into(),
            amount,
            asset,
            recipient: recipient.into(),
            metadata: None,
        }
    }
}

/// MPP channel identifier.
///
/// Tempo channels are addressed by a 32-byte id (the channel's on-chain
/// account / object id). Phase 1 stores the raw bytes plus a hex
/// representation for easy logging. Future phases may add a typed wrapper that
/// distinguishes EVM-channel ids from Solana-channel ids.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChannelId {
    /// Raw 32-byte channel id.
    pub bytes: [u8; 32],
    /// Hex representation (`0x`-prefixed) — convenience field for logging /
    /// display. Derived from `bytes`.
    pub hex: String,
}

impl ChannelId {
    /// Construct a `ChannelId` from raw 32 bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        let hex = format!("0x{}", hex::encode(bytes));
        Self { bytes, hex }
    }

    /// Construct a `ChannelId` from a `0x`-prefixed hex string (64 hex chars
    /// after the prefix).
    pub fn from_hex(s: &str) -> Result<Self, crate::PayError> {
        let stripped = s.strip_prefix("0x").unwrap_or(s);
        let decoded = hex::decode(stripped)
            .map_err(|e| crate::PayError::TempoError(format!("invalid channel id hex: {e}")))?;
        if decoded.len() != 32 {
            return Err(crate::PayError::TempoError(format!(
                "channel id must be 32 bytes, got {}",
                decoded.len()
            )));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&decoded);
        Ok(Self::from_bytes(bytes))
    }

    /// Construct a deterministic test-only `ChannelId` from a u64. The high
    /// bytes are zero; the low 8 bytes carry the value (big-endian).
    #[doc(hidden)]
    pub fn for_test(value: u64) -> Self {
        let mut bytes = [0u8; 32];
        bytes[24..].copy_from_slice(&value.to_be_bytes());
        Self::from_bytes(bytes)
    }
}

impl fmt::Display for ChannelId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.hex)
    }
}

/// MPP channel lifecycle state.
///
/// Phase 1 tracks only the three states the [`TempoSettler`](crate::TempoSettler)
/// cares about; real Tempo exposes more granular states (pending-open,
/// settling, dispute-window) which T19 will wire up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelState {
    /// Channel is open and can stream payments.
    Open,
    /// Channel has been closed and the final settlement tx has been mined.
    Closed,
}

/// The "payer" type passed to [`PaymentSettler::pay_exact`](crate::PaymentSettler).
///
/// # Why we define this here (deviation note)
/// The T18 spec says `payer: &SessionKey` and "re-export from `oc-session-key`
/// (read its lib.rs to find the exact type name; it might be `SessionKey` or
/// `SessionKeyInfo` or similar — match the actual API)". `oc-session-key` does
/// not define a `SessionKey` type — it defines `OwnerKey`, `PublicKey`,
/// `SessionPrivateKey`, and `GrantReceipt`. The "session key" concept is split
/// across the public key (on-chain identity) and the private key (held by the
/// Key-Agent, used to sign).
///
/// For T18's payer concept we need both: the public identity (so the settler
/// can build the UserOp / Solana tx and the SCA can verify ERC-7715) and a
/// reference to the private key for the Key-Agent to sign with. Phase 1
/// defines a minimal `SessionKey` newtype here wrapping a `PublicKey` plus a
/// `key_id` (the Key-Agent's handle to the private key) and a `chain_id`.
/// Future phases may promote this into `oc-session-key`.
#[derive(Debug, Clone)]
pub struct SessionKey {
    /// On-chain public key (33-byte compressed secp256k1 for EVM, 32-byte
    /// ed25519 for Solana).
    pub public: PublicKey,
    /// CAIP-2 chain id this session key is valid on.
    pub chain_id: String,
    /// Key-Agent's opaque identifier for the session private key. The settler
    /// never sees the raw private key — it asks the Key-Agent to sign via this
    /// id (real Key-Agent integration is T19's job; Phase 1 settlers sign
    /// locally with a mock signer).
    pub key_id: String,
}

impl SessionKey {
    /// Construct a new `SessionKey`.
    pub fn new(public: PublicKey, chain_id: impl Into<String>, key_id: impl Into<String>) -> Self {
        Self { public, chain_id: chain_id.into(), key_id: key_id.into() }
    }

    /// Signature scheme used by this session key.
    pub const fn scheme(&self) -> KeyScheme {
        self.public.scheme
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_pubkey() -> PublicKey {
        PublicKey { bytes: vec![0u8; 33], scheme: KeyScheme::Secp256k1Evm }
    }

    #[test]
    fn test_caip19_new_valid() {
        let a = Caip19Asset::new("eip155:8453/slip44:60").unwrap();
        assert_eq!(a.as_str(), "eip155:8453/slip44:60");
        assert_eq!(a.to_string(), "eip155:8453/slip44:60");
    }

    #[test]
    fn test_caip19_new_rejects_empty() {
        assert!(Caip19Asset::new("").is_err());
    }

    #[test]
    fn test_caip19_new_rejects_no_slash() {
        assert!(Caip19Asset::new("eip1558453").is_err());
    }

    #[test]
    fn test_caip19_from_str_roundtrip() {
        let a: Caip19Asset = "eip155:1/erc20:0xabc".parse().unwrap();
        let json = serde_json::to_string(&a).unwrap();
        assert_eq!(json, "\"eip155:1/erc20:0xabc\"");
        let a2: Caip19Asset = serde_json::from_str(&json).unwrap();
        assert_eq!(a, a2);
    }

    #[test]
    fn test_payment_scheme_as_str() {
        assert_eq!(PaymentScheme::Exact.as_str(), "exact");
        assert_eq!(PaymentScheme::ExactPlusUserOp.as_str(), "exact+userop");
        assert_eq!(PaymentScheme::Exact.to_string(), "exact");
        assert_eq!(PaymentScheme::ExactPlusUserOp.to_string(), "exact+userop");
    }

    #[test]
    fn test_payment_scheme_from_str() {
        assert_eq!("exact".parse::<PaymentScheme>().unwrap(), PaymentScheme::Exact);
        assert_eq!(
            "exact+userop".parse::<PaymentScheme>().unwrap(),
            PaymentScheme::ExactPlusUserOp
        );
        assert!("bogus".parse::<PaymentScheme>().is_err());
    }

    #[test]
    fn test_payment_scheme_serde() {
        let s = serde_json::to_string(&PaymentScheme::ExactPlusUserOp).unwrap();
        assert_eq!(s, "\"exact+userop\"");
        let p: PaymentScheme = serde_json::from_str(&s).unwrap();
        assert_eq!(p, PaymentScheme::ExactPlusUserOp);
    }

    #[test]
    fn test_payment_receipt_serde_roundtrip() {
        let r = PaymentReceipt::new(
            "eip155:8453",
            PaymentScheme::ExactPlusUserOp,
            "0xabc",
            Decimal::from(1),
            Caip19Asset::unchecked("eip155:8453/slip44:60"),
            "0xrecipient",
        );
        let json = serde_json::to_string(&r).unwrap();
        let r2: PaymentReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(r, r2);
    }

    #[test]
    fn test_channel_id_from_bytes_roundtrip() {
        let bytes = [42u8; 32];
        let id = ChannelId::from_bytes(bytes);
        assert_eq!(id.hex, "0x".to_string() + &"2a".repeat(32));
        let id2 = ChannelId::from_hex(&id.hex).unwrap();
        assert_eq!(id, id2);
    }

    #[test]
    fn test_channel_id_for_test() {
        let id = ChannelId::for_test(1);
        assert_eq!(id.bytes[24..], 1u64.to_be_bytes());
        assert!(id.hex.starts_with("0x"));
    }

    #[test]
    fn test_channel_id_from_hex_rejects_bad_length() {
        assert!(ChannelId::from_hex("0xdeadbeef").is_err());
        assert!(ChannelId::from_hex("0x").is_err());
    }

    #[test]
    fn test_session_key_new() {
        let sk = SessionKey::new(dummy_pubkey(), "eip155:8453", "key-1");
        assert_eq!(sk.chain_id, "eip155:8453");
        assert_eq!(sk.key_id, "key-1");
        assert_eq!(sk.scheme(), KeyScheme::Secp256k1Evm);
    }

    #[test]
    fn test_channel_state_serde() {
        let s = serde_json::to_string(&ChannelState::Open).unwrap();
        assert_eq!(s, "\"open\"");
        let s2 = serde_json::to_string(&ChannelState::Closed).unwrap();
        assert_eq!(s2, "\"closed\"");
    }
}
