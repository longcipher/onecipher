//! [`SignerState`] (signing-key lifecycle) and the JSON-RPC 2.0 wire types for
//! the loopback WalletSigner server.

use std::{path::PathBuf, sync::Arc};

use oc_core::ChainType;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroizing;

/// Shared signer configuration. The wallet + index select the HD key; the
/// passphrase decrypts the wallet vault. Captured once at startup. This is the
/// only place that touches key-material decryption, isolating that sensitive
/// lifecycle from the request dispatch and handler logic.
#[derive(Clone)]
pub(crate) struct SignerState {
    wallet: String,
    index: u32,
    passphrase: Arc<Zeroizing<String>>,
    /// Optional override for the vault location (used by tests).
    vault_path: Option<Arc<PathBuf>>,
}

impl SignerState {
    pub(crate) fn new(wallet: &str, index: u32) -> Self {
        Self::with_vault(wallet, index, None)
    }

    fn with_vault(wallet: &str, index: u32, vault_path: Option<PathBuf>) -> Self {
        let passphrase = super::super::peek_passphrase()
            .map_or_else(|| Zeroizing::new(String::new()), zeroize::Zeroizing::new);
        Self {
            wallet: wallet.to_string(),
            index,
            passphrase: Arc::new(passphrase),
            vault_path: vault_path.map(Arc::new),
        }
    }

    /// Decrypt the secret key for the given chain type.
    ///
    /// L-07: the detailed error may embed filesystem paths, so it is logged
    /// via `tracing` and replaced with a generic message before it can reach
    /// a JSON-RPC client.
    pub(crate) fn secret_key(
        &self,
        chain_type: ChainType,
    ) -> Result<oc_signer::SecretBytes, String> {
        oc_wallet::decrypt_signing_key(
            &self.wallet,
            chain_type,
            self.passphrase.as_bytes(),
            Some(self.index),
            self.vault_path.as_ref().map(|p| p.as_path()),
        )
        .map_err(|e| {
            tracing::warn!(error = %e, "wallet-rpc: failed to decrypt signing key");
            "internal error".to_string()
        })
    }

    /// Hex-encoded owner passphrase for enclave pipe requests.
    ///
    /// The loopback server holds the owner passphrase (not a device key), so
    /// wallet-rpc signing uses passphrase-mode enclave requests; the child
    /// zeroizes the decoded bytes on drop.
    pub(crate) fn passphrase_credential_hex(&self) -> String {
        hex::encode(self.passphrase.as_bytes())
    }

    /// Resolve the configured wallet name/id to the canonical wallet ID.
    ///
    /// L-07: see [`SignerState::secret_key`] — details stay in the log.
    pub(crate) fn configured_wallet_id(&self) -> Result<String, String> {
        oc_vault::load_wallet_by_name_or_id(
            &self.wallet,
            self.vault_path.as_ref().map(|p| p.as_path()),
        )
        .map(|wallet| wallet.id)
        .map_err(|e| {
            tracing::warn!(error = %e, "wallet-rpc: failed to resolve configured wallet");
            "internal error".to_string()
        })
    }

    /// Derive the compressed secp256k1 public key (33 bytes) for a secret key.
    pub(crate) fn secp256k1_public_key(secret: &[u8]) -> Result<Vec<u8>, String> {
        let k = k256::ecdsa::SigningKey::from_slice(secret)
            .map_err(|e| format!("invalid secp256k1 key: {e}"))?;
        Ok(k.verifying_key().to_sec1_point(true).as_bytes().to_vec())
    }

    /// Derive the ed25519 public key (32 bytes) for a secret key.
    pub(crate) fn ed25519_public_key(secret: &[u8]) -> Result<Vec<u8>, String> {
        let bytes: [u8; 32] =
            secret.try_into().map_err(|_| "invalid ed25519 key length".to_string())?;
        let pair = ed25519_dalek::SigningKey::from_bytes(&bytes);
        Ok(pair.verifying_key().to_bytes().to_vec())
    }

    /// secp256k1 public key for the default EVM account.
    pub(crate) fn secp256k1_pubkey(&self) -> Result<Vec<u8>, String> {
        let secret = self.secret_key(ChainType::Evm)?;
        Self::secp256k1_public_key(secret.expose())
    }

    /// ed25519 public key for the default non-EVM account.
    pub(crate) fn ed25519_pubkey(&self) -> Result<Vec<u8>, String> {
        let secret = self.secret_key(ChainType::Solana)?;
        Self::ed25519_public_key(secret.expose())
    }

    /// Borrow the configured wallet name/id (for diagnostics only).
    pub(crate) fn wallet(&self) -> &str {
        &self.wallet
    }

    /// Borrow the configured HD key index (for diagnostics only).
    pub(crate) fn index(&self) -> u32 {
        self.index
    }

    /// Construct a `SignerState` from explicit parts. Used by tests that
    /// provision a throwaway wallet in a temporary vault.
    #[cfg(test)]
    pub(crate) fn from_parts(
        wallet: String,
        index: u32,
        passphrase: zeroize::Zeroizing<String>,
        vault_path: Option<std::sync::Arc<std::path::PathBuf>>,
    ) -> Self {
        Self { wallet, index, passphrase: std::sync::Arc::new(passphrase), vault_path }
    }
}

/// JSON-RPC 2.0 request envelope.
#[derive(Debug, Deserialize)]
pub(crate) struct RpcRequest {
    #[serde(rename = "jsonrpc")]
    jsonrpc: String,
    id: Value,
    method: String,
    #[serde(default)]
    params: Option<Value>,
}

impl RpcRequest {
    /// Borrow the JSON-RPC version string.
    pub(crate) fn jsonrpc(&self) -> &str {
        &self.jsonrpc
    }

    /// Borrow the request id (echoed back in the response).
    pub(crate) fn id(&self) -> &Value {
        &self.id
    }

    /// Borrow the method name.
    pub(crate) fn method(&self) -> &str {
        &self.method
    }

    /// Borrow the optional params object.
    pub(crate) fn params(&self) -> &Option<Value> {
        &self.params
    }
}

/// A JSON-RPC error payload.
#[derive(Debug, Serialize)]
pub(crate) struct RpcError {
    code: i32,
    message: String,
}

impl RpcError {
    pub(crate) fn new(code: i32, message: impl Into<String>) -> Self {
        Self { code, message: message.into() }
    }

    /// JSON-RPC error code.
    #[cfg(test)]
    pub(crate) fn code(&self) -> i32 {
        self.code
    }

    /// Human-readable error message.
    #[cfg(test)]
    pub(crate) fn message(&self) -> &str {
        &self.message
    }
}

/// `ledgerflow_keys` result item.
#[derive(Debug, Serialize)]
pub(crate) struct KeyInfo {
    alg: &'static str,
    public_key: String,
    key_id: Option<String>,
}

impl KeyInfo {
    pub(crate) fn new(alg: &'static str, public_key: String, key_id: Option<String>) -> Self {
        Self { alg, public_key, key_id }
    }
}

/// `ledgerflow_sign_payment` request params. The wire `asset` field is
/// accepted (unknown fields are ignored) but not required for signing.
#[derive(Debug, Deserialize)]
pub(crate) struct SignPaymentParams {
    chain_id: String,
    #[serde(default)]
    amount: Option<String>,
    #[serde(default)]
    payee: Option<String>,
    #[serde(default)]
    nonce: Option<String>,
}

impl SignPaymentParams {
    pub(crate) fn chain_id(&self) -> &str {
        &self.chain_id
    }
    pub(crate) fn amount(&self) -> Option<&str> {
        self.amount.as_deref()
    }
    pub(crate) fn payee(&self) -> Option<&str> {
        self.payee.as_deref()
    }
    pub(crate) fn nonce(&self) -> Option<&str> {
        self.nonce.as_deref()
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct GenerateChallengeParams {
    credential_id: String,
}

impl GenerateChallengeParams {
    pub(crate) fn credential_id(&self) -> &str {
        &self.credential_id
    }
}
