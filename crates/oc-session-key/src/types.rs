//! Domain types for `oc-session-key`.
//!
//! Per the design (§5.1), these are Rust-specific wire/domain types — they live
//! here rather than in `oc-keyagent::proto` because they wrap `HardenedBytes`
//! (R51/R52) and reference `oc-policy` types. The prost wire-format layer in
//! `oc_keyagent::proto` defines the UDS IPC codec separately.

use oc_crypto::HardenedBytes;
use serde::{Deserialize, Serialize};

/// Owner's signing key (Layer 1 master key, derived from mnemonic).
///
/// Wrapped in `HardenedBytes` for memory protection (R51/R52). Not serializable
/// — owners never persist their raw key material through this type.
pub struct OwnerKey {
    /// 32 bytes for secp256k1 (EVM) or ed25519 (Solana).
    pub raw: HardenedBytes,
    /// CAIP-2 chain id, e.g. `"eip155:8453"` or `"solana:mainnet"`.
    pub chain_id: String,
}

/// Session key's public key (the half that goes on-chain in `grant()`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKey {
    /// 33 bytes compressed (EVM secp256k1) or 32 bytes (Solana ed25519).
    pub bytes: Vec<u8>,
    /// Signature scheme used by this key.
    pub scheme: KeyScheme,
}

/// Signature scheme used by a session key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyScheme {
    /// EVM secp256k1 (33-byte compressed pubkey).
    Secp256k1Evm,
    /// Solana ed25519 (32-byte pubkey).
    Ed25519Solana,
}

/// Session key's private key (used in `sign_with`). Wrapped in `HardenedBytes`.
pub struct SessionPrivateKey {
    /// 32 bytes.
    pub raw: HardenedBytes,
    /// Signature scheme used by this key.
    pub scheme: KeyScheme,
}

/// What to sign — abstracts over tx / UserOp / message / typed data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignPayload {
    /// Raw EVM transaction (RLP-encoded hex without `0x` prefix).
    Transaction {
        /// EIP-155 chain id (e.g. `8453` for Base).
        chain_id: u64,
        /// RLP-encoded unsigned tx, hex-encoded (no `0x` prefix).
        raw_hex: String,
    },
    /// EIP-4337 UserOp (hex-encoded).
    UserOp {
        /// EIP-155 chain id.
        chain_id: u64,
        /// Hex-encoded UserOp bytes (no `0x` prefix).
        user_op_hex: String,
    },
    /// Arbitrary message (raw bytes).
    Message { bytes: Vec<u8> },
    /// EIP-712 typed data (JSON).
    TypedData { json: String },
}

/// A `0x`-prefixed hex-encoded byte string (e.g. transaction hash, Merkle root).
///
/// Newtype enforcing the `0x` prefix and valid hex encoding at construction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HexBytes(pub String);

impl HexBytes {
    /// Create a new `HexBytes` from a `0x`-prefixed hex string.
    ///
    /// Returns `None` if the string does not start with `0x` or contains
    /// non-hex characters.
    pub fn new(s: &str) -> Option<Self> {
        if !s.starts_with("0x") {
            return None;
        }
        let hex_part = &s[2..];
        if hex_part.is_empty() || !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        Some(Self(s.to_string()))
    }

    /// Create a new `HexBytes` from raw bytes (encodes as `0x`-prefixed hex).
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(format!("0x{}", hex::encode(bytes)))
    }

    /// Get the raw bytes (decodes from hex).
    pub fn to_bytes(&self) -> Option<Vec<u8>> {
        hex::decode(&self.0[2..]).ok()
    }

    /// Get the `0x`-prefixed hex string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Get the length of the hex string (including `0x` prefix).
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if the hex string is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Check if the hex string starts with the given prefix.
    pub fn starts_with(&self, prefix: &str) -> bool {
        self.0.starts_with(prefix)
    }
}

impl std::fmt::Display for HexBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl PartialEq for HexBytes {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl PartialEq<str> for HexBytes {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for HexBytes {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl AsRef<str> for HexBytes {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// An EVM transaction hash (`0x`-prefixed, 32 bytes).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxHash(pub String);

impl TxHash {
    /// Create a new `TxHash` from a `0x`-prefixed hex string.
    ///
    /// Returns `None` if the string is not a valid 32-byte hex string.
    pub fn new(s: &str) -> Option<Self> {
        let hb = HexBytes::new(s)?;
        hb.to_bytes().is_some_and(|b| b.len() == 32).then_some(Self(hb.0))
    }

    /// Get the `0x`-prefixed hex string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Get the length of the hex string (including `0x` prefix).
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if the hex string is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Check if the hex string starts with the given prefix.
    pub fn starts_with(&self, prefix: &str) -> bool {
        self.0.starts_with(prefix)
    }
}

impl std::fmt::Display for TxHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl PartialEq for TxHash {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl PartialEq<str> for TxHash {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for TxHash {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl AsRef<str> for TxHash {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// An EVM address (`0x`-prefixed, 20 bytes).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvmAddress(pub String);

impl EvmAddress {
    /// Create a new `EvmAddress` from a `0x`-prefixed hex string.
    ///
    /// Returns `None` if the string is not a valid 20-byte hex string.
    pub fn new(s: &str) -> Option<Self> {
        let hb = HexBytes::new(s)?;
        hb.to_bytes().is_some_and(|b| b.len() == 20).then_some(Self(hb.0))
    }

    /// Get the `0x`-prefixed hex string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Get the length of the hex string (including `0x` prefix).
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if the hex string is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Check if the hex string starts with the given prefix.
    pub fn starts_with(&self, prefix: &str) -> bool {
        self.0.starts_with(prefix)
    }
}

impl std::fmt::Display for EvmAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl PartialEq for EvmAddress {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl PartialEq<str> for EvmAddress {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for EvmAddress {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl AsRef<str> for EvmAddress {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// A Solana public key (base58-encoded, 32 bytes).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolanaPubkey(pub String);

impl SolanaPubkey {
    /// Create a new `SolanaPubkey` from a base58-encoded string.
    ///
    /// Returns `None` if the string is not a valid 32-byte base58 string.
    pub fn new(s: &str) -> Option<Self> {
        let bytes = bs58::decode(s).into_vec().ok()?;
        (bytes.len() == 32).then(|| Self(s.to_string()))
    }

    /// Get the base58-encoded string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Get the length of the base58-encoded string.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if the string is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Check if the string starts with the given prefix.
    pub fn starts_with(&self, prefix: &str) -> bool {
        self.0.starts_with(prefix)
    }
}

impl std::fmt::Display for SolanaPubkey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl PartialEq for SolanaPubkey {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl PartialEq<str> for SolanaPubkey {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for SolanaPubkey {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl AsRef<str> for SolanaPubkey {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Receipt returned by `grant()` — proves the session key was registered on-chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GrantReceipt {
    /// EVM: transaction hash + Merkle root of the permission set (ERC-7715).
    Evm {
        /// `0x`-prefixed transaction hash.
        tx_hash: TxHash,
        /// `0x`-prefixed hex (32 bytes) — Merkle root of the permission set.
        merkle_root: HexBytes,
        /// ERC-7579 SCA address (`0x`-prefixed).
        sca_address: EvmAddress,
    },
    /// Solana: Session Tokens program account address.
    Solana {
        /// Session Tokens account address (base58).
        session_tokens_account: String,
        /// Session Tokens program id (base58).
        program_id: SolanaPubkey,
        /// Slot at which the account was created.
        slot: u64,
    },
}

/// Signature output (chain-specific format).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Signature {
    /// EVM: 65 bytes (`r || s || v`), hex-encoded with `0x` prefix.
    Evm { hex: String },
    /// Solana: 64-byte ed25519 signature, base58-encoded.
    Solana { base58: String },
}

/// A minimal Solana instruction (mock encoding for Phase 1; real borsh encoding
/// lives in `oc-netagent`).
#[derive(Debug, Clone)]
pub struct SolanaInstruction {
    /// Program id (base58).
    pub program_id: String,
    /// Account addresses referenced by the instruction (base58).
    pub accounts: Vec<String>,
    /// Instruction data (raw bytes).
    pub data: Vec<u8>,
}
