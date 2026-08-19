//! Loopback JSON-RPC 2.0 WalletSigner server.
//!
//! OneCipher acts as the signing backend ("WalletSigner") for the sister
//! project `ledgerflow`. This server exposes a challenge method plus the
//! signing methods that
//! [`ledgerflow`](https://github.com/longcipher/ledgerflow)'s
//! `LocalRpcSigner` client calls over HTTP POST to `http://127.0.0.1:18080`:
//!
//! - `ledgerflow_generate_challenge` — mint a fresh passkey challenge for the configured wallet
//!   binding.
//! - `ledgerflow_keys` — list the signer's public keys.
//! - `ledgerflow_sign` — sign an arbitrary message (base64 raw bytes).
//! - `ledgerflow_sign_payment` — sign an EVM payment, returning a raw (RLP-encoded, signed)
//!   transaction.
//!
//! The transport is a single JSON-RPC 2.0 request per POST; binary fields are
//! base64 STANDARD encoded. Every stateful call must carry an `auth`
//! object derived from `ledgerflow_generate_challenge`. The server binds to
//! loopback only (R12c).

use std::{path::PathBuf, sync::Arc};

use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
};
use base64::Engine;
// Bring `ed25519_dalek::Signer` (the `sign` method) into scope.
use ed25519_dalek::Signer as _;
use oc_core::ChainType;
use oc_keyagent::{passkey::PasskeyPubkeyStore, proto::PasskeyAuthorization};
use oc_signer::{ChainSigner, chains::EvmSigner};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::CliError;

// ---------------------------------------------------------------------------
// Shared server state
// ---------------------------------------------------------------------------

/// Shared signer configuration. The wallet + index select the HD key; the
/// passphrase decrypts the wallet vault. Captured once at startup.
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
        let passphrase = super::peek_passphrase()
            .map_or_else(|| Zeroizing::new(String::new()), zeroize::Zeroizing::new);
        Self {
            wallet: wallet.to_string(),
            index,
            passphrase: Arc::new(passphrase),
            vault_path: vault_path.map(Arc::new),
        }
    }

    /// Decrypt the secret key for the given chain type.
    fn secret_key(&self, chain_type: ChainType) -> Result<oc_signer::SecretBytes, String> {
        oc_wallet::decrypt_signing_key(
            &self.wallet,
            chain_type,
            self.passphrase.as_bytes(),
            Some(self.index),
            self.vault_path.as_ref().map(|p| p.as_path()),
        )
        .map_err(|e| format!("failed to decrypt signing key: {e}"))
    }

    /// Resolve the configured wallet name/id to the canonical wallet ID.
    fn configured_wallet_id(&self) -> Result<String, String> {
        oc_vault::load_wallet_by_name_or_id(
            &self.wallet,
            self.vault_path.as_ref().map(|p| p.as_path()),
        )
        .map(|wallet| wallet.id)
        .map_err(|e| format!("failed to resolve configured wallet: {e}"))
    }

    /// Derive the compressed secp256k1 public key (33 bytes) for a secret key.
    fn secp256k1_public_key(secret: &[u8]) -> Result<Vec<u8>, String> {
        let k = k256::ecdsa::SigningKey::from_slice(secret)
            .map_err(|e| format!("invalid secp256k1 key: {e}"))?;
        Ok(k.verifying_key().to_sec1_point(true).as_bytes().to_vec())
    }

    /// Derive the ed25519 public key (32 bytes) for a secret key.
    fn ed25519_public_key(secret: &[u8]) -> Result<Vec<u8>, String> {
        let bytes: [u8; 32] =
            secret.try_into().map_err(|_| "invalid ed25519 key length".to_string())?;
        let pair = ed25519_dalek::SigningKey::from_bytes(&bytes);
        Ok(pair.verifying_key().to_bytes().to_vec())
    }

    /// secp256k1 public key for the default EVM account.
    fn secp256k1_pubkey(&self) -> Result<Vec<u8>, String> {
        let secret = self.secret_key(ChainType::Evm)?;
        Self::secp256k1_public_key(secret.expose())
    }

    /// ed25519 public key for the default non-EVM account.
    fn ed25519_pubkey(&self) -> Result<Vec<u8>, String> {
        let secret = self.secret_key(ChainType::Solana)?;
        Self::ed25519_public_key(secret.expose())
    }
}

// ---------------------------------------------------------------------------
// JSON-RPC 2.0 wire types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct RpcRequest {
    #[serde(rename = "jsonrpc")]
    jsonrpc: String,
    id: Value,
    method: String,
    #[serde(default)]
    params: Option<Value>,
}

/// A JSON-RPC error payload.
#[derive(Debug, Serialize)]
struct RpcError {
    code: i32,
    message: String,
}

impl RpcError {
    fn new(code: i32, message: impl Into<String>) -> Self {
        Self { code, message: message.into() }
    }
}

// ---------------------------------------------------------------------------
// Wire parameter/result structures
// ---------------------------------------------------------------------------

/// `ledgerflow_keys` result item.
#[derive(Debug, Serialize)]
struct KeyInfo {
    alg: &'static str,
    public_key: String,
    key_id: Option<String>,
}

/// `ledgerflow_sign_payment` request params. The wire `asset` field is
/// accepted (unknown fields are ignored) but not required for signing.
#[derive(Debug, Deserialize)]
struct SignPaymentParams {
    chain_id: String,
    #[serde(default)]
    amount: Option<String>,
    #[serde(default)]
    payee: Option<String>,
    #[serde(default)]
    nonce: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GenerateChallengeParams {
    credential_id: String,
}

// ---------------------------------------------------------------------------
// Handler dispatch
// ---------------------------------------------------------------------------

/// Single entry point: POST body is a JSON-RPC 2.0 request. Dispatches to the
/// three `ledgerflow_*` methods.
async fn rpc(State(state): State<SignerState>, Json(req): Json<RpcRequest>) -> Response {
    if req.jsonrpc != "2.0" {
        return error_response(&req.id, RpcError::new(-32600, "invalid JSON-RPC version"));
    }
    let id = req.id;
    let result = match req.method.as_str() {
        "ledgerflow_generate_challenge" => match validate_params(&req.params) {
            Ok(p) => handle_generate_challenge(&p),
            Err(e) => Err(e),
        },
        "ledgerflow_keys" => match validate_params(&req.params) {
            Ok(p) => match require_authorization(&state, &p) {
                Ok(()) => handle_keys(&state),
                Err(e) => Err(e),
            },
            Err(e) => Err(e),
        },
        "ledgerflow_sign" => match validate_params(&req.params) {
            Ok(p) => match require_authorization(&state, &p) {
                Ok(()) => handle_sign(&state, &p),
                Err(e) => Err(e),
            },
            Err(e) => Err(e),
        },
        "ledgerflow_sign_payment" => match validate_params(&req.params) {
            Ok(p) => match require_authorization(&state, &p) {
                Ok(()) => handle_sign_payment(&state, &p),
                Err(e) => Err(e),
            },
            Err(e) => Err(e),
        },
        other => Err(RpcError::new(-32601, format!("method not found: {other}"))),
    };

    match result {
        Ok(value) => success_response(&id, value),
        Err(e) => error_response(&id, e),
    }
}

fn validate_params(params: &Option<Value>) -> Result<Value, RpcError> {
    params.clone().ok_or_else(|| RpcError::new(-32602, "missing params"))
}

fn parse_auth(params: &Value) -> Result<PasskeyAuthorization, RpcError> {
    let auth_obj = params
        .get("auth")
        .and_then(Value::as_object)
        .ok_or_else(|| RpcError::new(-32602, "missing auth"))?;
    let challenge_hex = auth_obj
        .get("challenge_hex")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::new(-32602, "missing auth.challenge_hex"))?;
    let signature_hex = auth_obj
        .get("signature_hex")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::new(-32602, "missing auth.signature_hex"))?;
    let credential_id = auth_obj
        .get("credential_id")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::new(-32602, "missing auth.credential_id"))?;
    let challenge = hex::decode(challenge_hex)
        .map_err(|e| RpcError::new(-32602, format!("invalid auth.challenge_hex: {e}")))?;
    let signature = hex::decode(signature_hex)
        .map_err(|e| RpcError::new(-32602, format!("invalid auth.signature_hex: {e}")))?;
    Ok(PasskeyAuthorization { challenge, signature, credential_id: credential_id.to_string() })
}

fn require_authorization(state: &SignerState, params: &Value) -> Result<(), RpcError> {
    let auth = parse_auth(params)?;
    oc_keyagent::handler::authorize_passkey(&auth)
        .map_err(|e| RpcError::new(-32602, format!("passkey authorization failed: {e}")))?;
    let configured_wallet_id =
        state.configured_wallet_id().map_err(|e| RpcError::new(-32603, e))?;
    let store = PasskeyPubkeyStore::open_default()
        .map_err(|e| RpcError::new(-32603, format!("passkey store: {e}")))?;
    let stored = store
        .get(&auth.credential_id)
        .ok_or_else(|| RpcError::new(-32602, "passkey not registered"))?;
    if stored.wallet_id != configured_wallet_id {
        return Err(RpcError::new(-32602, "passkey is not bound to configured wallet"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Method implementations
// ---------------------------------------------------------------------------

/// `ledgerflow_keys` → `[{"alg":"ed25519","public_key":"<b64>"}, ...]`.
fn handle_keys(state: &SignerState) -> Result<Value, RpcError> {
    let mut keys = Vec::new();
    match state.ed25519_pubkey() {
        Ok(pubkey) => keys.push(KeyInfo {
            alg: "ed25519",
            public_key: base64::engine::general_purpose::STANDARD.encode(&pubkey),
            key_id: None,
        }),
        Err(e) => return Err(RpcError::new(-32603, e)),
    }
    match state.secp256k1_pubkey() {
        Ok(pubkey) => keys.push(KeyInfo {
            alg: "secp256k1",
            public_key: base64::engine::general_purpose::STANDARD.encode(&pubkey),
            key_id: None,
        }),
        Err(e) => return Err(RpcError::new(-32603, e)),
    }
    serde_json::to_value(keys).map_err(|e| RpcError::new(-32603, e.to_string()))
}

/// `ledgerflow_generate_challenge` → `{"challenge_hex":"..."}`.
fn handle_generate_challenge(params: &Value) -> Result<Value, RpcError> {
    let request = serde_json::from_value::<GenerateChallengeParams>(params.clone())
        .map_err(|e| RpcError::new(-32602, format!("invalid challenge params: {e}")))?;
    let challenge = oc_keyagent::handler::generate_passkey_challenge(&request.credential_id)
        .map_err(|e| RpcError::new(-32603, e))?;
    Ok(json!({ "challenge_hex": hex::encode(challenge) }))
}

/// `ledgerflow_sign` — sign a base64 message with the selected key.
fn handle_sign(state: &SignerState, params: &Value) -> Result<Value, RpcError> {
    // Ignore `domain` for actual signing — it only labels what is being signed.
    let msg_b64 = params
        .get("message")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::new(-32602, "missing 'message' (base64)"))?;
    let message = base64::engine::general_purpose::STANDARD
        .decode(msg_b64)
        .map_err(|e| RpcError::new(-32602, format!("invalid base64 message: {e}")))?;

    // Select the curve.
    let key = params.get("key");
    let alg = key
        .and_then(|k| k.get("alg"))
        .and_then(Value::as_str)
        .unwrap_or("ed25519")
        .to_ascii_lowercase();

    let (signature, pubkey) = match alg.as_str() {
        "ed25519" => {
            let secret =
                state.secret_key(ChainType::Solana).map_err(|e| RpcError::new(-32603, e))?;
            let bytes: [u8; 32] = secret
                .expose()
                .try_into()
                .map_err(|_| RpcError::new(-32603, "invalid ed25519 key length"))?;
            let pair = ed25519_dalek::SigningKey::from_bytes(&bytes);
            let sig = pair.sign(&message);
            let pubkey = pair.verifying_key().to_bytes().to_vec();
            (sig.to_bytes().to_vec(), pubkey)
        }
        "secp256k1" => {
            let secret = state.secret_key(ChainType::Evm).map_err(|e| RpcError::new(-32603, e))?;
            let signer = EvmSigner;
            let output = signer
                .sign_message(secret.expose(), &message)
                .map_err(|e| RpcError::new(-32603, format!("signing failed: {e}")))?;
            // 65-byte r||s||v signature (EIP-191 style: v = 27|28).
            let pubkey = SignerState::secp256k1_public_key(secret.expose())
                .map_err(|e| RpcError::new(-32603, e))?;
            (output.signature, pubkey)
        }
        other => return Err(RpcError::new(-32602, format!("unsupported alg: {other}"))),
    };

    serde_json::to_value(json!({
        "signer": {
            "alg": alg,
            "public_key": base64::engine::general_purpose::STANDARD.encode(pubkey),
            "key_id": null,
        },
        "signature": {
            "value": base64::engine::general_purpose::STANDARD.encode(&signature),
            "alg": alg,
        },
    }))
    .map_err(|e| RpcError::new(-32603, e.to_string()))
}

/// `ledgerflow_sign_payment` — build and sign an EIP-1559 EVM payment.
fn handle_sign_payment(state: &SignerState, params: &Value) -> Result<Value, RpcError> {
    let p = serde_json::from_value::<SignPaymentParams>(params.clone())
        .map_err(|e| RpcError::new(-32602, format!("invalid payment params: {e}")))?;

    // Chain ID must be eip155:<n>.
    let chain_ref = p
        .chain_id
        .strip_prefix("eip155:")
        .ok_or_else(|| RpcError::new(-32602, "chain_id must be eip155:<n>"))?;
    let chain_id = chain_ref
        .parse::<u128>()
        .map_err(|_| RpcError::new(-32602, format!("invalid chain id: {}", p.chain_id)))?;

    // Amount in wei (u128 decimal string).
    let amount = p
        .amount
        .as_deref()
        .ok_or_else(|| RpcError::new(-32602, "missing 'amount' (wei, decimal string)"))?
        .parse::<u128>()
        .map_err(|e| RpcError::new(-32602, format!("invalid amount: {e}")))?;

    // Payee (0x + 20 bytes).
    let payee = p.payee.as_deref().ok_or_else(|| RpcError::new(-32602, "missing 'payee'"))?;
    let payee_bytes = hex::decode(payee.strip_prefix("0x").unwrap_or(payee))
        .map_err(|e| RpcError::new(-32602, format!("invalid payee hex: {e}")))?;
    if payee_bytes.len() != 20 {
        return Err(RpcError::new(-32602, "payee must be a 20-byte address"));
    }

    // Nonce (default 0).
    let nonce = match p.nonce.as_deref() {
        Some(n) => {
            n.parse::<u128>().map_err(|e| RpcError::new(-32602, format!("invalid nonce: {e}")))?
        }
        None => 0,
    };

    // Decrypt the signing key.
    let secret = state.secret_key(ChainType::Evm).map_err(|e| RpcError::new(-32603, e))?;
    let signer = EvmSigner;

    // Build an unsigned EIP-1559 transaction:
    // RLP([chain_id, nonce, max_priority_fee, max_fee, gas_limit, to, value, data, access_list])
    let items: Vec<u8> = [
        rlp_u128(chain_id),
        rlp_u128(nonce),
        rlp_u128(0),             // maxPriorityFeePerGas
        rlp_u128(1_000_000_000), // maxFeePerGas = 1 gwei
        rlp_u128(52_000),        // gasLimit (self-transfer + margin)
        oc_signer::rlp::encode_bytes(&payee_bytes),
        rlp_u128(amount),
        oc_signer::rlp::encode_bytes(&[]), // data = empty
        oc_signer::rlp::encode_list(&[]),  // accessList = empty
    ]
    .concat();

    let mut unsigned_tx = vec![0x02u8];
    unsigned_tx.extend_from_slice(&oc_signer::rlp::encode_list(&items));

    let output = signer
        .sign_transaction(secret.expose(), &unsigned_tx)
        .map_err(|e| RpcError::new(-32603, format!("signing failed: {e}")))?;
    let signed = signer
        .encode_signed_transaction(&unsigned_tx, &output)
        .map_err(|e| RpcError::new(-32603, format!("tx encoding failed: {e}")))?;

    let raw_transaction = format!("0x{}", hex::encode(&signed));
    serde_json::to_value(json!({ "raw_transaction": raw_transaction, "tx_hash": null }))
        .map_err(|e| RpcError::new(-32603, e.to_string()))
}

/// RLP-encode a u128 as a minimal big-endian integer.
fn rlp_u128(v: u128) -> Vec<u8> {
    if v == 0 {
        return oc_signer::rlp::encode_bytes(&[]);
    }
    let bytes = v.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    oc_signer::rlp::encode_bytes(&bytes[start..])
}

// ---------------------------------------------------------------------------
// Response helpers
// ---------------------------------------------------------------------------

fn success_response(id: &Value, result: Value) -> Response {
    (StatusCode::OK, Json(json!({ "jsonrpc": "2.0", "id": id, "result": result }))).into_response()
}

fn error_response(id: &Value, err: RpcError) -> Response {
    (StatusCode::OK, Json(json!({ "jsonrpc": "2.0", "id": id, "error": err }))).into_response()
}

/// Daemon-resident WalletSigner server settings.
///
/// Disabled by default. When `OC_WALLET_RPC_LISTEN` is set to a loopback
/// address, the daemon exposes the WalletSigner server there for wallet
/// `default`, index 0 unless overridden with `OC_WALLET_RPC_WALLET` /
/// `OC_WALLET_RPC_INDEX`.
pub(crate) fn daemon_config() -> (String, String, u32) {
    let listen = std::env::var("OC_WALLET_RPC_LISTEN").unwrap_or_else(|_| "off".into());
    let wallet = std::env::var("OC_WALLET_RPC_WALLET").unwrap_or_else(|_| "default".to_string());
    let index = std::env::var("OC_WALLET_RPC_INDEX").ok().and_then(|v| v.parse().ok()).unwrap_or(0);
    (listen, wallet, index)
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Start the loopback WalletSigner JSON-RPC server and block until it exits.
///
/// CLI entry point: validates the loopback bind address, builds the signer
/// state, then drives the serving future on the shared runtime.
pub(crate) fn serve(listen: &str, wallet: &str, index: u32) -> Result<(), CliError> {
    let parsed = parse_loopback(listen)?;
    let state = SignerState::new(wallet, index);
    crate::shared_runtime().block_on(serve_async(state, parsed))
}

/// Parse and validate a loopback-only bind address (R12c/R12e).
pub(crate) fn parse_loopback(listen: &str) -> Result<std::net::SocketAddr, CliError> {
    let parsed: std::net::SocketAddr = listen
        .parse()
        .map_err(|e| CliError::InvalidArgs(format!("invalid listen address '{listen}': {e}")))?;
    // R12c/R12e: loopback only.
    if !parsed.ip().is_loopback() {
        return Err(CliError::InvalidArgs(format!(
            "WalletSigner MUST bind to loopback (127.0.0.1) only, got {parsed}"
        )));
    }
    Ok(parsed)
}

/// Serve the WalletSigner JSON-RPC 2.0 endpoint on `parsed` until cancelled.
///
/// This is the daemon-reusable core: it binds the loopback socket and serves
/// the axum router without driving its own runtime, so callers (the CLI
/// `serve` command or the daemon's async task loop) can control its lifetime.
pub(crate) async fn serve_async(
    state: SignerState,
    parsed: std::net::SocketAddr,
) -> Result<(), CliError> {
    let app = axum::Router::new().route("/", post(rpc)).with_state(state.clone());

    let listener = tokio::net::TcpListener::bind(parsed).await.map_err(CliError::Io)?;
    eprintln!(
        "WalletSigner JSON-RPC server listening on http://{} (wallet '{}', index {})",
        listener.local_addr().map_err(CliError::Io)?,
        state.wallet,
        state.index
    );
    axum::serve(listener, app).await.map_err(CliError::Io)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::MutexGuard;

    use oc_keyagent::passkey::{PasskeyPubkeyStore, StoredPasskeyPubkey};

    use super::*;

    const TEST_PASSPHRASE: &str = "test-passphrase";
    static HOME_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct HomeGuard {
        _lock: MutexGuard<'static, ()>,
        _dir: tempfile::TempDir,
        old_home: Option<String>,
    }

    impl HomeGuard {
        fn new() -> Self {
            let lock = HOME_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let dir = tempfile::tempdir().expect("tempdir");
            let old_home = std::env::var("HOME").ok();
            // SAFETY: tests in this module are serialized by HOME_LOCK.
            unsafe { std::env::set_var("HOME", dir.path()) };
            Self { _lock: lock, _dir: dir, old_home }
        }
    }

    impl Drop for HomeGuard {
        fn drop(&mut self) {
            match &self.old_home {
                Some(old) => {
                    // SAFETY: tests in this module are serialized by HOME_LOCK.
                    unsafe { std::env::set_var("HOME", old) };
                }
                None => {
                    // SAFETY: tests in this module are serialized by HOME_LOCK.
                    unsafe { std::env::remove_var("HOME") };
                }
            }
        }
    }

    /// Create a fresh wallet in a temporary vault and return a `SignerState`
    /// pointed at it, so the wire handlers run against real key material.
    fn test_state() -> SignerState {
        let vault = tempfile::tempdir().expect("tempdir");
        oc_wallet::create_wallet("test", Some(12), Some(TEST_PASSPHRASE), Some(vault.path()))
            .expect("create wallet");
        SignerState {
            wallet: "test".to_string(),
            index: 0,
            passphrase: Arc::new(Zeroizing::new(TEST_PASSPHRASE.to_string())),
            vault_path: Some(Arc::new(vault.keep())),
        }
    }

    fn keys_json() -> Value {
        handle_keys(&test_state()).expect("keys should succeed")
    }

    #[test]
    fn keys_returns_both_algs() {
        let v = keys_json();
        let arr = v.as_array().expect("result must be an array");
        assert_eq!(arr.len(), 2, "expected ed25519 + secp256k1 keys");
        let algs: Vec<&str> = arr.iter().map(|k| k["alg"].as_str().unwrap_or("")).collect();
        assert!(algs.contains(&"ed25519"));
        assert!(algs.contains(&"secp256k1"));
        for k in arr {
            let pk = k["public_key"].as_str().expect("public_key must be a string");
            let bytes = base64::engine::general_purpose::STANDARD.decode(pk).expect("valid base64");
            assert!(!bytes.is_empty());
        }
    }

    #[test]
    fn sign_ed25519_returns_valid_signature() {
        let params = json!({
            "domain": "warrant",
            "message": base64::engine::general_purpose::STANDARD.encode(b"hello ledgerflow"),
        });
        let out = handle_sign(&test_state(), &params).expect("sign should succeed");
        assert_eq!(out["signer"]["alg"], "ed25519");
        assert_eq!(out["signature"]["alg"], "ed25519");
        let sig = base64::engine::general_purpose::STANDARD
            .decode(out["signature"]["value"].as_str().unwrap())
            .expect("valid base64 sig");
        assert_eq!(sig.len(), 64, "ed25519 signature must be 64 bytes");
    }

    #[test]
    fn sign_secp256k1_returns_valid_signature() {
        let params = json!({
            "message": base64::engine::general_purpose::STANDARD.encode(b"hello"),
            "key": { "alg": "Secp256k1" },
        });
        let out = handle_sign(&test_state(), &params).expect("sign should succeed");
        assert_eq!(out["signer"]["alg"], "secp256k1");
        let sig = base64::engine::general_purpose::STANDARD
            .decode(out["signature"]["value"].as_str().unwrap())
            .expect("valid base64 sig");
        assert_eq!(sig.len(), 65, "secp256k1 EIP-191 signature must be 65 bytes");
    }

    #[test]
    fn sign_rejects_missing_message() {
        let params = json!({ "domain": "proof" });
        let err = handle_sign(&test_state(), &params).unwrap_err();
        assert_eq!(err.code, -32602);
    }

    #[test]
    fn sign_payment_builds_eip1559_raw_transaction() {
        let params = json!({
            "chain_id": "eip155:8453",
            "asset": "eip155:8453/slip44:60",
            "amount": "1000000000000000",
            "payee": "0x1111111111111111111111111111111111111111",
            "nonce": "0",
        });
        let out =
            handle_sign_payment(&test_state(), &params).expect("payment signing should succeed");
        let raw = out["raw_transaction"].as_str().expect("raw_transaction must be a string");
        assert!(raw.starts_with("0x02"), "must be an EIP-1559 (type 0x02) transaction, got {raw}");
        let bytes = hex::decode(raw.strip_prefix("0x").unwrap()).expect("valid hex");
        assert!(bytes.len() > 90, "signed tx should be non-trivial in size");
    }

    #[test]
    fn sign_payment_rejects_bad_chain() {
        let params = json!({
            "chain_id": "solana:mainnet",
            "payee": "0x1111111111111111111111111111111111111111",
        });
        let err = handle_sign_payment(&test_state(), &params).unwrap_err();
        assert_eq!(err.code, -32602);
    }

    #[test]
    fn rlp_u128_encoding() {
        assert_eq!(rlp_u128(0), oc_signer::rlp::encode_bytes(&[]));
        assert_eq!(rlp_u128(1), oc_signer::rlp::encode_bytes(&[1]));
        // 0x010203
        assert_eq!(rlp_u128(0x010203), oc_signer::rlp::encode_bytes(&[1, 2, 3]));
    }

    fn auth_params_for_wallet(binding_wallet_id: &str, credential_id: &str) -> Value {
        let mut store = PasskeyPubkeyStore::open_default().expect("open passkey store");
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rng());
        let public_key = signing_key.verifying_key().to_bytes().to_vec();
        store
            .register(
                credential_id,
                StoredPasskeyPubkey {
                    algorithm: "ed25519".to_string(),
                    public_key,
                    wallet_id: binding_wallet_id.to_string(),
                    registered_at: 0,
                },
            )
            .expect("register passkey");

        let challenge = oc_keyagent::handler::generate_passkey_challenge(credential_id)
            .expect("generate challenge");
        let mut message = challenge.clone();
        message.extend_from_slice(credential_id.as_bytes());
        let signature: ed25519_dalek::Signature = signing_key.sign(&message);
        json!({
            "auth": {
                "challenge_hex": hex::encode(challenge),
                "signature_hex": hex::encode(signature.to_bytes()),
                "credential_id": credential_id,
            }
        })
    }

    #[test]
    fn authorization_accepts_passkey_bound_to_configured_wallet() {
        let _home = HomeGuard::new();
        let state = test_state();
        let wallet_id = state.configured_wallet_id().expect("resolve wallet id");
        let params = auth_params_for_wallet(&wallet_id, "cred-wallet-rpc-ok");
        require_authorization(&state, &params).expect("bound passkey must authorize");
    }

    #[test]
    fn authorization_rejects_passkey_bound_to_different_wallet() {
        let _home = HomeGuard::new();
        let state = test_state();
        let params = auth_params_for_wallet("other-wallet-id", "cred-wallet-rpc-mismatch");
        let err =
            require_authorization(&state, &params).expect_err("foreign wallet binding must fail");
        assert_eq!(err.code, -32602);
        assert!(err.message.contains("configured wallet"));
    }
}
