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

/// Receipt returned by `grant()` — proves the session key was registered on-chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GrantReceipt {
    /// EVM: transaction hash + Merkle root of the permission set (ERC-7715).
    Evm {
        // TODO(M10): change to a HexBytes / TxHash newtype
        /// `0x`-prefixed transaction hash.
        tx_hash: String,
        // TODO(M10): change to a HexBytes / MerkleRoot newtype
        /// `0x`-prefixed hex (32 bytes) — Merkle root of the permission set.
        merkle_root: String,
        // TODO(M10): change to an EvmAddress newtype
        /// ERC-7579 SCA address (`0x`-prefixed).
        sca_address: String,
    },
    /// Solana: Session Tokens program account address.
    Solana {
        /// Session Tokens account address (base58).
        session_tokens_account: String,
        // TODO(M10): change to a SolanaPubkey newtype
        /// Session Tokens program id (base58).
        program_id: String,
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
