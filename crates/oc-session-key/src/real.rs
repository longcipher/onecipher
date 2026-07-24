//! Real ERC-7579 EVM + Solana Session Tokens providers (Phase 2).
//!
//! This module sits alongside the Phase 1 mock-based providers in
//! [`crate::evm`] and [`crate::solana`]. Phase 1 used a single
//! [`crate::rpc::RpcClient`] trait that bundled EVM + Solana calls behind one
//! mock. Phase 2 splits the abstractions into chain-specific, injectable
//! traits so a real `oc-netagent` implementation can wire up alloy /
//! solana-client behind them without touching the provider logic.
//!
//! # Layout
//! - [`derive_session_key_id`] — deterministic `sk-{namespace}-0x{hash}` IDs.
//! - [`EvmRpcClient`] / [`EvmBundlerClient`] — EVM RPC + ERC-4337 bundler traits.
//! - [`SolanaRpcClient`] — Solana RPC trait.
//! - [`EvmSessionKeyProvider`] — real ERC-7579 install/verify/revoke impl.
//! - [`SolanaSessionKeyProvider`] — real Session Tokens program impl.
//! - [`MockEvmRpcClient`] / [`MockEvmBundlerClient`] / [`MockSolanaRpcClient`] — test doubles with
//!   call counters.
//!
//! # R56 compliance
//! This crate still MUST NOT depend on tokio / reqwest / tungstenite / hyper /
//! async-std / smol. The traits here are `#[async_trait]` but produce
//! runtime-agnostic futures; the Net-Agent supplies the executor.

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use async_trait::async_trait;
use oc_policy::PolicyV2;
use oc_signer::{
    chains::{EvmSigner, SolanaSigner},
    traits::ChainSigner,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    SessionKeyProvider,
    error::SessionKeyError,
    types::{
        GrantReceipt, OwnerKey, PublicKey, SessionPrivateKey, SignPayload, Signature,
        SolanaInstruction,
    },
};

// ---------------------------------------------------------------------------
// Session key ID derivation
// ---------------------------------------------------------------------------

/// Derive a deterministic session key ID.
///
/// Format: `sk-{chain_namespace}-0x{8-byte hash}` where `chain_namespace` is
/// the first CAIP-2 component (e.g. `eip155` from `eip155:8453`, `solana` from
/// `solana:mainnet`). The hash is the first 8 bytes of
/// `SHA-256("onecipher-session-key" || session_pubkey || chain_id)`.
///
/// This replaces the Phase 1 `sk-{u64}` format with a value that is
/// deterministic from the session pubkey + chain, so the same key material
/// always yields the same ID on-chain (verifiable without a registry).
///
/// **Deviation note:** `docs/design.md` §6.2 specifies keccak256 for the hash.
/// Phase 2 keeps SHA-256 for parity with [`crate::evm::EvmSessionKeyProvider`]
/// (Phase 1 deviation, R74 YAGNI) — keccak256 lives in `oc-netagent` where the
/// alloy dependency is available.
pub fn derive_session_key_id(session_pubkey: &[u8], chain_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"onecipher-session-key");
    hasher.update(session_pubkey);
    hasher.update(chain_id.as_bytes());
    let hash = hasher.finalize();
    format!(
        "sk-{}-0x{}",
        // split(':').next() always yields at least one element; unwrap_or is
        // lint-safe and documents the fallback for malformed chain ids.
        chain_id.split(':').next().unwrap_or("unknown"),
        hex::encode(&hash[..8])
    )
}

// ---------------------------------------------------------------------------
// EVM RPC + bundler traits
// ---------------------------------------------------------------------------

/// ERC-4337 bundler client abstraction.
///
/// Real implementations (alloy / ethers-rs against Pimlico / Stackup) live in
/// `oc-netagent`. The trait is `#[async_trait]` but runtime-agnostic (R56).
#[async_trait]
pub trait EvmBundlerClient: Send + Sync {
    /// Submit a serialized ERC-4337 UserOp and return its hash.
    async fn send_user_operation(&self, user_op: &[u8]) -> Result<String, SessionKeyError>;
    /// Fetch the receipt for a previously submitted UserOp hash.
    async fn get_user_operation_receipt(&self, hash: &str) -> Result<Value, SessionKeyError>;
}

/// EVM RPC client abstraction (eth_call / send_raw_transaction / estimateGas).
///
/// Real implementations live in `oc-netagent`.
#[async_trait]
pub trait EvmRpcClient: Send + Sync {
    /// `eth_call` to `to` with `data`; returns the raw return bytes.
    async fn eth_call(&self, to: &str, data: &[u8]) -> Result<Vec<u8>, SessionKeyError>;
    /// `eth_sendRawTransaction` with a pre-signed transaction; returns the tx hash.
    async fn send_transaction(&self, tx: &[u8]) -> Result<String, SessionKeyError>;
    /// `eth_estimateGas` for `to` + `data`; returns the gas estimate.
    async fn estimate_gas(&self, to: &str, data: &[u8]) -> Result<u64, SessionKeyError>;
}

// ---------------------------------------------------------------------------
// Solana RPC trait
// ---------------------------------------------------------------------------

/// Solana RPC client abstraction.
///
/// Real implementations (solana-client / solana-rpc-client) live in
/// `oc-netagent`. Runtime-agnostic per R56.
#[async_trait]
pub trait SolanaRpcClient: Send + Sync {
    /// Send a transaction containing `instructions` and return the signature.
    async fn send_transaction(
        &self,
        instructions: Vec<SolanaInstruction>,
    ) -> Result<String, SessionKeyError>;
    /// Fetch an account's data (returns `None` if the account does not exist).
    async fn get_account(&self, address: &str) -> Result<Option<Vec<u8>>, SessionKeyError>;
    /// Fetch the current slot (used for receipt slot in `grant`).
    async fn get_slot(&self) -> Result<u64, SessionKeyError>;
}

// ---------------------------------------------------------------------------
// Real EVM SessionKeyProvider (ERC-7579 + ERC-4337)
// ---------------------------------------------------------------------------

/// Real EVM session-key provider — ERC-7579 `installSessionKey` submitted via
/// an ERC-4337 bundler, with `isSessionKeyActive` view checks and
/// `revokeSessionKey` owner-signed transactions.
///
/// This is the Phase 2 replacement for the Phase 1 mock-based
/// [`crate::evm::EvmSessionKeyProvider`]. It uses split
/// [`EvmRpcClient`] + [`EvmBundlerClient`] traits so the real alloy-backed
/// implementations can be injected by `oc-netagent` without touching provider
/// logic.
///
/// **Deviation note (R74 YAGNI):** the SCA address is derived from the owner
/// key via [`EvmSigner::derive_address`] (the owner's EOA). Real ERC-7579
/// counterfactual SCA derivation (`CREATE2` from a factory + salt) lives in
/// `oc-netagent`. The EOA-as-SCA-target stand-in is structurally faithful for
/// the injectable-RPC path: the same calldata is sent, just to a different
/// `to` address.
pub struct EvmSessionKeyProvider {
    rpc: Arc<dyn EvmRpcClient>,
    bundler: Arc<dyn EvmBundlerClient>,
    chain_id: String,
    /// Optional ERC-7579 SCA address. If empty, methods derive a stand-in
    /// from the owner key (see deviation note). Set via [`Self::with_sca_address`].
    sca_address: String,
}

impl EvmSessionKeyProvider {
    /// Construct a new real EVM session-key provider.
    pub fn new(
        rpc: Arc<dyn EvmRpcClient>,
        bundler: Arc<dyn EvmBundlerClient>,
        chain_id: impl Into<String>,
    ) -> Self {
        Self { rpc, bundler, chain_id: chain_id.into(), sca_address: String::new() }
    }

    /// Set the ERC-7579 SCA address. When set, all `eth_call` /
    /// `send_transaction` targets use this address instead of the
    /// owner-derived stand-in.
    pub fn with_sca_address(mut self, sca_address: impl Into<String>) -> Self {
        self.sca_address = sca_address.into();
        self
    }

    /// Resolve the SCA target address. Uses the configured `sca_address` if
    /// set; otherwise derives a stand-in from the owner key (deviation note).
    fn resolve_sca(&self, owner_key: &OwnerKey) -> Result<String, SessionKeyError> {
        if !self.sca_address.is_empty() {
            return Ok(self.sca_address.clone());
        }
        let signer = EvmSigner;
        signer
            .derive_address(owner_key.raw.expose())
            .map_err(|e| SessionKeyError::InvalidPayload(e.to_string()))
    }

    /// Compute the ERC-7715 permission Merkle root from a `PolicyV2`.
    ///
    /// **Deviation note:** SHA-256 of the serialized policy, parity with
    /// Phase 1. Real keccak256 + Merkle tree lives in `oc-netagent`.
    pub(crate) fn compute_merkle_root(policy: &PolicyV2) -> Result<String, SessionKeyError> {
        let json = serde_json::to_string(policy)
            .map_err(|e| SessionKeyError::MerkleFailed(e.to_string()))?;
        let hash = Sha256::digest(json.as_bytes());
        Ok(format!("0x{}", hex::encode(hash)))
    }

    /// Encode the ERC-7579 `installSessionKey(bytes32,bytes32,uint64)` calldata.
    ///
    /// **Deviation note:** mock 4-byte selector. Real selector derivation
    /// from the keccak256 of the canonical signature lives in `oc-netagent`.
    fn encode_install_session_key(
        session_pubkey: &[u8],
        merkle_root: &str,
        expiry_unix: u64,
    ) -> Vec<u8> {
        const SELECTOR: [u8; 4] = [0x7a, 0x8b, 0x9c, 0x0d];
        crate::abi::encode_grant_permission(SELECTOR, session_pubkey, merkle_root, expiry_unix)
    }

    /// Encode `isSessionKeyActive(bytes32)` view calldata (mock selector).
    fn encode_is_session_key_active(session_key_id: &str) -> Vec<u8> {
        const SELECTOR: [u8; 4] = [0x8b, 0x9c, 0x0d, 0x1e];
        crate::abi::encode_is_permission_granted(SELECTOR, session_key_id)
    }

    /// Encode `revokeSessionKey(bytes32)` calldata (mock selector).
    fn encode_revoke_session_key(session_key_id: &str) -> Vec<u8> {
        const SELECTOR: [u8; 4] = [0x9c, 0x0d, 0x1e, 0x2f];
        crate::abi::encode_revoke_permission(SELECTOR, session_key_id)
    }

    /// Build a simplified ERC-4337 UserOp blob from the SCA address + calldata.
    ///
    /// **Deviation note:** this is NOT a real serialized UserOp — it is a
    /// length-prefixed `(sca_address, calldata)` envelope sufficient for the
    /// mock bundler. Real UserOp assembly (alloy `UserOperationBuilder`) lives
    /// in `oc-netagent`.
    fn build_user_op(sca_address: &str, calldata: &[u8]) -> Vec<u8> {
        let mut user_op = Vec::with_capacity(2 + sca_address.len() + 4 + calldata.len());
        user_op.extend_from_slice(&(sca_address.len() as u16).to_be_bytes());
        user_op.extend_from_slice(sca_address.as_bytes());
        user_op.extend_from_slice(&(calldata.len() as u32).to_be_bytes());
        user_op.extend_from_slice(calldata);
        user_op
    }

    /// Decode a bool return from an `eth_call` (ABI: last byte ≠ 0 ⇒ true).
    fn decode_bool_return(returndata: &[u8]) -> bool {
        !returndata.is_empty() && returndata[returndata.len() - 1] != 0
    }
}

#[async_trait]
impl SessionKeyProvider for EvmSessionKeyProvider {
    fn chain_id(&self) -> &str {
        &self.chain_id
    }

    async fn grant(
        &self,
        owner_key: &OwnerKey,
        session_pubkey: &PublicKey,
        policy: &PolicyV2,
    ) -> Result<GrantReceipt, SessionKeyError> {
        if owner_key.chain_id != self.chain_id {
            return Err(SessionKeyError::ChainMismatch {
                expected: self.chain_id.clone(),
                actual: owner_key.chain_id.clone(),
            });
        }
        let sca = self.resolve_sca(owner_key)?;
        let merkle_root = Self::compute_merkle_root(policy)?;
        let calldata = Self::encode_install_session_key(
            session_pubkey.bytes.as_slice(),
            &merkle_root,
            policy.rules.expiry_unix,
        );
        let user_op = Self::build_user_op(&sca, &calldata);
        let tx_hash = self.bundler.send_user_operation(&user_op).await?;
        Ok(GrantReceipt::Evm { tx_hash, merkle_root, sca_address: sca })
    }

    async fn verify_active(&self, session_key_id: &str) -> Result<bool, SessionKeyError> {
        // verify_active has no owner_key, so derive the SCA target from the
        // session_key_id when sca_address is unset. This is a mock derivation;
        // real verify_active requires the SCA address (set via with_sca_address
        // in production).
        let sca = if self.sca_address.is_empty() {
            let hash = Sha256::digest(session_key_id.as_bytes());
            format!("0x{}", hex::encode(&hash[..20]))
        } else {
            self.sca_address.clone()
        };
        let calldata = Self::encode_is_session_key_active(session_key_id);
        let result = self.rpc.eth_call(&sca, &calldata).await?;
        Ok(Self::decode_bool_return(&result))
    }

    async fn revoke(
        &self,
        owner_key: &OwnerKey,
        session_key_id: &str,
    ) -> Result<(), SessionKeyError> {
        if owner_key.chain_id != self.chain_id {
            return Err(SessionKeyError::ChainMismatch {
                expected: self.chain_id.clone(),
                actual: owner_key.chain_id.clone(),
            });
        }
        let sca = self.resolve_sca(owner_key)?;
        let calldata = Self::encode_revoke_session_key(session_key_id);
        // Owner-signed revoke: in production the tx is signed by the owner key
        // and submitted via send_transaction. Here we pass the calldata envelope
        // to the RPC client; real signing lives in oc-netagent.
        let mut tx = Vec::with_capacity(2 + sca.len() + 4 + calldata.len());
        tx.extend_from_slice(&(sca.len() as u16).to_be_bytes());
        tx.extend_from_slice(sca.as_bytes());
        tx.extend_from_slice(&(calldata.len() as u32).to_be_bytes());
        tx.extend_from_slice(&calldata);
        let _ = self.rpc.send_transaction(&tx).await?;
        Ok(())
    }

    async fn sign_with(
        &self,
        session_priv: &SessionPrivateKey,
        payload: &SignPayload,
    ) -> Result<Signature, SessionKeyError> {
        // Signing is local (no RPC); the SCA validates the signature on-chain.
        // Delegate to oc-signer's EvmSigner (reuse, don't re-roll).
        let signer = EvmSigner;
        let priv_bytes = session_priv.raw.expose();
        let sig_bytes = match payload {
            SignPayload::Transaction { raw_hex, .. } => {
                let raw = hex::decode(raw_hex.trim_start_matches("0x"))
                    .map_err(|e| SessionKeyError::InvalidPayload(e.to_string()))?;
                signer
                    .sign_transaction(priv_bytes, &raw)
                    .map_err(|e| SessionKeyError::SigningFailed(e.to_string()))?
            }
            SignPayload::UserOp { user_op_hex, .. } => {
                let raw = hex::decode(user_op_hex.trim_start_matches("0x"))
                    .map_err(|e| SessionKeyError::InvalidPayload(e.to_string()))?;
                signer
                    .sign_transaction(priv_bytes, &raw)
                    .map_err(|e| SessionKeyError::SigningFailed(e.to_string()))?
            }
            SignPayload::Message { bytes } => signer
                .sign_message(priv_bytes, bytes)
                .map_err(|e| SessionKeyError::SigningFailed(e.to_string()))?,
            SignPayload::TypedData { json } => signer
                .sign_typed_data(priv_bytes, json)
                .map_err(|e| SessionKeyError::SigningFailed(e.to_string()))?,
        };
        Ok(Signature::Evm { hex: format!("0x{}", hex::encode(&sig_bytes.signature)) })
    }
}

// ---------------------------------------------------------------------------
// Real Solana SessionKeyProvider (Session Tokens program)
// ---------------------------------------------------------------------------

/// Real Solana session-key provider — Session Tokens program.
///
/// Phase 2 replacement for the Phase 1 mock-based
/// [`crate::solana::SolanaSessionKeyProvider`]. Uses an injectable
/// [`SolanaRpcClient`] trait so the real solana-rpc-client implementation can
/// be wired up by `oc-netagent`.
pub struct SolanaSessionKeyProvider {
    rpc: Arc<dyn SolanaRpcClient>,
    chain_id: String,
    /// Session Tokens program id (base58), config value per A3.
    program_id: String,
}

impl SolanaSessionKeyProvider {
    /// Construct a new real Solana session-key provider.
    pub fn new(
        rpc: Arc<dyn SolanaRpcClient>,
        chain_id: impl Into<String>,
        program_id: impl Into<String>,
    ) -> Self {
        Self { rpc, chain_id: chain_id.into(), program_id: program_id.into() }
    }

    /// Encode the `CreateSessionToken` instruction.
    ///
    /// **Deviation note:** simplified mock encoding (1-byte discriminator +
    /// raw pubkey + length-prefixed JSON policy). Real borsh encoding lives in
    /// `oc-netagent`.
    fn encode_create_session_token_ix(
        program_id: &str,
        session_pubkey: &[u8],
        policy: &PolicyV2,
    ) -> SolanaInstruction {
        let mut data = Vec::new();
        // Instruction discriminator: CreateSessionToken = 1.
        data.push(1);
        data.extend_from_slice(session_pubkey);
        let policy_json = serde_json::to_vec(policy).unwrap_or_default();
        data.extend_from_slice(&(policy_json.len() as u32).to_le_bytes());
        data.extend_from_slice(&policy_json);
        SolanaInstruction { program_id: program_id.to_string(), accounts: vec![], data }
    }

    /// Encode the `RevokeSessionToken` instruction (discriminator = 2).
    fn encode_revoke_session_token_ix(program_id: &str, session_key_id: &str) -> SolanaInstruction {
        SolanaInstruction {
            program_id: program_id.to_string(),
            accounts: vec![session_key_id.to_string()],
            data: vec![2],
        }
    }
}

#[async_trait]
impl SessionKeyProvider for SolanaSessionKeyProvider {
    fn chain_id(&self) -> &str {
        &self.chain_id
    }

    async fn grant(
        &self,
        owner_key: &OwnerKey,
        session_pubkey: &PublicKey,
        policy: &PolicyV2,
    ) -> Result<GrantReceipt, SessionKeyError> {
        if owner_key.chain_id != self.chain_id {
            return Err(SessionKeyError::ChainMismatch {
                expected: self.chain_id.clone(),
                actual: owner_key.chain_id.clone(),
            });
        }
        let ix =
            Self::encode_create_session_token_ix(&self.program_id, &session_pubkey.bytes, policy);
        let sig = self.rpc.send_transaction(vec![ix]).await?;
        let slot = self.rpc.get_slot().await.unwrap_or(0);
        Ok(GrantReceipt::Solana {
            session_tokens_account: sig,
            program_id: self.program_id.clone(),
            slot,
        })
    }

    async fn verify_active(&self, session_key_id: &str) -> Result<bool, SessionKeyError> {
        let account = self.rpc.get_account(session_key_id).await?;
        Ok(account.is_some())
    }

    async fn revoke(
        &self,
        owner_key: &OwnerKey,
        session_key_id: &str,
    ) -> Result<(), SessionKeyError> {
        if owner_key.chain_id != self.chain_id {
            return Err(SessionKeyError::ChainMismatch {
                expected: self.chain_id.clone(),
                actual: owner_key.chain_id.clone(),
            });
        }
        let ix = Self::encode_revoke_session_token_ix(&self.program_id, session_key_id);
        let _ = self.rpc.send_transaction(vec![ix]).await?;
        Ok(())
    }

    async fn sign_with(
        &self,
        session_priv: &SessionPrivateKey,
        payload: &SignPayload,
    ) -> Result<Signature, SessionKeyError> {
        // Solana uses ed25519 signing. Delegate to oc-signer's SolanaSigner.
        match payload {
            SignPayload::Message { bytes } => {
                let signer = SolanaSigner;
                let sig = signer
                    .sign_message(session_priv.raw.expose(), bytes)
                    .map_err(|e| SessionKeyError::SigningFailed(e.to_string()))?;
                Ok(Signature::Solana { base58: bs58::encode(&sig.signature).into_string() })
            }
            _ => Err(SessionKeyError::InvalidPayload(
                "Solana supports only Message payload in Phase 2".to_string(),
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// Mock EVM RPC + bundler clients (for tests)
// ---------------------------------------------------------------------------

/// Shared call counters for [`MockEvmRpcClient`] and [`MockEvmBundlerClient`].
#[derive(Default)]
pub struct MockEvmCounters {
    /// `eth_call` invocations.
    pub eth_call_calls: AtomicUsize,
    /// `send_transaction` invocations.
    pub send_transaction_calls: AtomicUsize,
    /// `estimate_gas` invocations.
    pub estimate_gas_calls: AtomicUsize,
    /// `send_user_operation` invocations.
    pub send_user_op_calls: AtomicUsize,
    /// `get_user_operation_receipt` invocations.
    pub get_user_op_receipt_calls: AtomicUsize,
}

impl MockEvmCounters {
    /// Number of `eth_call` calls.
    pub fn eth_call(&self) -> usize {
        self.eth_call_calls.load(Ordering::Relaxed)
    }
    /// Number of `send_transaction` calls.
    pub fn send_transaction(&self) -> usize {
        self.send_transaction_calls.load(Ordering::Relaxed)
    }
    /// Number of `send_user_operation` calls.
    pub fn send_user_op(&self) -> usize {
        self.send_user_op_calls.load(Ordering::Relaxed)
    }
}

/// Mock EVM RPC client for tests.
pub struct MockEvmRpcClient {
    /// Response returned by `eth_call`.
    pub eth_call_response: Result<Vec<u8>, SessionKeyError>,
    /// Response returned by `send_transaction`.
    pub send_transaction_response: Result<String, SessionKeyError>,
    /// Response returned by `estimate_gas`.
    pub estimate_gas_response: Result<u64, SessionKeyError>,
    /// Shared call counters.
    pub counters: Arc<MockEvmCounters>,
}

impl MockEvmRpcClient {
    /// Build a mock that returns successful responses for every call.
    pub fn ok() -> Self {
        Self {
            eth_call_response: Ok(vec![0x01]),
            send_transaction_response: Ok("0xdeadbeef".to_string()),
            estimate_gas_response: Ok(21000),
            counters: Arc::new(MockEvmCounters::default()),
        }
    }

    /// Returns a cloneable handle to the call counters.
    pub fn counters(&self) -> Arc<MockEvmCounters> {
        Arc::clone(&self.counters)
    }
}

#[async_trait]
impl EvmRpcClient for MockEvmRpcClient {
    async fn eth_call(&self, _to: &str, _data: &[u8]) -> Result<Vec<u8>, SessionKeyError> {
        self.counters.eth_call_calls.fetch_add(1, Ordering::Relaxed);
        self.eth_call_response.clone()
    }

    async fn send_transaction(&self, _tx: &[u8]) -> Result<String, SessionKeyError> {
        self.counters.send_transaction_calls.fetch_add(1, Ordering::Relaxed);
        self.send_transaction_response.clone()
    }

    async fn estimate_gas(&self, _to: &str, _data: &[u8]) -> Result<u64, SessionKeyError> {
        self.counters.estimate_gas_calls.fetch_add(1, Ordering::Relaxed);
        self.estimate_gas_response.clone()
    }
}

/// Mock ERC-4337 bundler client for tests.
pub struct MockEvmBundlerClient {
    /// Response returned by `send_user_operation`.
    pub send_user_op_response: Result<String, SessionKeyError>,
    /// Response returned by `get_user_operation_receipt`.
    pub get_user_op_receipt_response: Result<Value, SessionKeyError>,
    /// Shared call counters.
    pub counters: Arc<MockEvmCounters>,
}

impl MockEvmBundlerClient {
    /// Build a mock that returns successful responses for every call.
    pub fn ok() -> Self {
        Self {
            send_user_op_response: Ok("0xbundler_hash_123".to_string()),
            get_user_op_receipt_response: Ok(serde_json::json!({
                "userOpHash": "0xbundler_hash_123",
                "success": true,
                "transactionHash": "0xtxhash_456"
            })),
            counters: Arc::new(MockEvmCounters::default()),
        }
    }

    /// Returns a cloneable handle to the call counters.
    pub fn counters(&self) -> Arc<MockEvmCounters> {
        Arc::clone(&self.counters)
    }
}

#[async_trait]
impl EvmBundlerClient for MockEvmBundlerClient {
    async fn send_user_operation(&self, _user_op: &[u8]) -> Result<String, SessionKeyError> {
        self.counters.send_user_op_calls.fetch_add(1, Ordering::Relaxed);
        self.send_user_op_response.clone()
    }

    async fn get_user_operation_receipt(&self, _hash: &str) -> Result<Value, SessionKeyError> {
        self.counters.get_user_op_receipt_calls.fetch_add(1, Ordering::Relaxed);
        self.get_user_op_receipt_response.clone()
    }
}

// ---------------------------------------------------------------------------
// Mock Solana RPC client (for tests)
// ---------------------------------------------------------------------------

/// Shared call counters for [`MockSolanaRpcClient`].
#[derive(Default)]
pub struct MockSolanaCounters {
    /// `send_transaction` invocations.
    pub send_transaction_calls: AtomicUsize,
    /// `get_account` invocations.
    pub get_account_calls: AtomicUsize,
    /// `get_slot` invocations.
    pub get_slot_calls: AtomicUsize,
}

impl MockSolanaCounters {
    /// Number of `send_transaction` calls.
    pub fn send_transaction(&self) -> usize {
        self.send_transaction_calls.load(Ordering::Relaxed)
    }
    /// Number of `get_account` calls.
    pub fn get_account(&self) -> usize {
        self.get_account_calls.load(Ordering::Relaxed)
    }
}

/// Mock Solana RPC client for tests.
pub struct MockSolanaRpcClient {
    /// Response returned by `send_transaction`.
    pub send_transaction_response: Result<String, SessionKeyError>,
    /// Response returned by `get_account`.
    pub get_account_response: Result<Option<Vec<u8>>, SessionKeyError>,
    /// Response returned by `get_slot`.
    pub get_slot_response: Result<u64, SessionKeyError>,
    /// Shared call counters.
    pub counters: Arc<MockSolanaCounters>,
}

impl MockSolanaRpcClient {
    /// Build a mock that returns successful responses for every call.
    pub fn ok() -> Self {
        Self {
            send_transaction_response: Ok("sol_sig_mock_real".to_string()),
            get_account_response: Ok(Some(vec![0x01])),
            get_slot_response: Ok(123_456),
            counters: Arc::new(MockSolanaCounters::default()),
        }
    }

    /// Returns a cloneable handle to the call counters.
    pub fn counters(&self) -> Arc<MockSolanaCounters> {
        Arc::clone(&self.counters)
    }
}

#[async_trait]
impl SolanaRpcClient for MockSolanaRpcClient {
    async fn send_transaction(
        &self,
        _instructions: Vec<SolanaInstruction>,
    ) -> Result<String, SessionKeyError> {
        self.counters.send_transaction_calls.fetch_add(1, Ordering::Relaxed);
        self.send_transaction_response.clone()
    }

    async fn get_account(&self, _address: &str) -> Result<Option<Vec<u8>>, SessionKeyError> {
        self.counters.get_account_calls.fetch_add(1, Ordering::Relaxed);
        self.get_account_response.clone()
    }

    async fn get_slot(&self) -> Result<u64, SessionKeyError> {
        self.counters.get_slot_calls.fetch_add(1, Ordering::Relaxed);
        self.get_slot_response.clone()
    }
}
