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
//!
//! # Module layout
//!
//! This previously-lived in a single 640-line file. It is now split to honour
//! the single-responsibility boundary:
//! - [`state`] — [`SignerState`] (key material lifecycle) + JSON-RPC wire types.
//! - [`auth`] — passkey challenge minting + per-request authorization.
//! - [`handlers`] — the concrete `ledgerflow_*` method implementations.
//! - this `mod` — the axum router, response helpers, and daemon/CLI entry points.

mod auth;
mod handlers;
mod state;

use std::net::SocketAddr;

use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
};
// `ChainSigner` trait must be in scope for `EvmSigner::sign_transaction` /
// `encode_signed_transaction` (trait methods, not inherent).
use oc_signer::ChainSigner as _;
use serde_json::{Value, json};
pub(crate) use state::SignerState;

use crate::CliError;

/// Run a synchronous handler on tokio's blocking thread pool (H-06).
///
/// The `ledgerflow_*` handlers perform age scrypt KDF work and vault/passkey
/// file I/O; running them inline on an async worker would stall the reactor.
/// A cancelled or panicked blocking task maps to a generic -32603 (L-07: no
/// internal detail leaks to the client).
async fn run_blocking<T, F>(f: F) -> Result<T, state::RpcError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, state::RpcError> + Send + 'static,
{
    match tokio::task::spawn_blocking(f).await {
        Ok(result) => result,
        Err(_) => Err(state::RpcError::new(-32603, "internal error")),
    }
}

/// H-06: [`auth::require_authorization`] off the async path.
async fn authorize_async(state: &SignerState, params: &Value) -> Result<(), state::RpcError> {
    let state = state.clone();
    let params = params.clone();
    run_blocking(move || auth::require_authorization(&state, &params)).await
}

/// H-06: [`handlers::handle_keys`] off the async path.
async fn keys_async(state: SignerState) -> Result<Value, state::RpcError> {
    run_blocking(move || handlers::handle_keys(&state)).await
}

/// H-06: [`handlers::handle_sign`] off the async path.
async fn sign_async(state: SignerState, params: Value) -> Result<Value, state::RpcError> {
    run_blocking(move || handlers::handle_sign(&state, &params)).await
}

/// H-06: [`handlers::handle_sign_payment`] off the async path.
async fn sign_payment_async(state: SignerState, params: Value) -> Result<Value, state::RpcError> {
    run_blocking(move || handlers::handle_sign_payment(&state, &params)).await
}

/// Intent pre-flight on the wallet-rpc hot path (read-only, no auth).
///
/// Shares `oc_netagent::intent::hot_path` with the WC/HTTP-RPC surfaces:
/// `simulate_for_hot_path` over a real RPC endpoint (fail-closed without
/// `rpc_url` / `OC_RPC_URL`). `CrossChainTransfer` stays fail-closed.
async fn intent_simulate_async(params: Value) -> Result<Value, state::RpcError> {
    run_blocking(move || {
        let chain_id = params
            .get("chain_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| state::RpcError::new(-32602, "missing 'chain_id'"))?;
        let session_key_id = params
            .get("session_key_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| state::RpcError::new(-32602, "missing 'session_key_id'"))?;
        let kind_value =
            params.get("kind").ok_or_else(|| state::RpcError::new(-32602, "missing 'kind'"))?;
        let kind: oc_netagent::intent::IntentKind = serde_json::from_value(kind_value.clone())
            .map_err(|e| state::RpcError::new(-32602, format!("invalid kind: {e}")))?;
        let intent = oc_netagent::intent::Intent::new(
            kind,
            chain_id.to_string(),
            session_key_id.to_string(),
        );
        let rpc_url = params.get("rpc_url").and_then(serde_json::Value::as_str).map(String::from);
        let cfg = oc_netagent::intent::HotPathConfig::new(rpc_url);
        let rpc = oc_netagent::intent::select_rpc_client(&intent.chain_id, &cfg)
            .map_err(|e| state::RpcError::new(-32603, format!("intent RPC unavailable: {e}")))?;
        let summary = crate::shared_runtime()
            .block_on(oc_netagent::intent::simulate_for_hot_path(&intent, &*rpc))
            .map_err(|e| state::RpcError::new(-32603, format!("intent simulate: {e}")))?;
        serde_json::to_value(&summary)
            .map_err(|e| state::RpcError::new(-32603, format!("summary encode: {e}")))
    })
    .await
}

/// Intent execution on the wallet-rpc hot path (auth-gated, local signing).
///
/// C13 trait boundary: the intent code sees opaque bytes; the `IntentSigner`
/// impl below decrypts the EVM vault key and signs locally (loopback trust
/// model — unlike the WC daemon, which forwards to the Key-Agent over UDS).
async fn intent_execute_async(state: SignerState, params: Value) -> Result<Value, state::RpcError> {
    run_blocking(move || {
        let chain_id = params
            .get("chain_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| state::RpcError::new(-32602, "missing 'chain_id'"))?;
        let session_key_id = params
            .get("session_key_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| state::RpcError::new(-32602, "missing 'session_key_id'"))?;
        let kind_value =
            params.get("kind").ok_or_else(|| state::RpcError::new(-32602, "missing 'kind'"))?;
        let kind: oc_netagent::intent::IntentKind = serde_json::from_value(kind_value.clone())
            .map_err(|e| state::RpcError::new(-32602, format!("invalid kind: {e}")))?;
        let from_address = params
            .get("from_address")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| state::RpcError::new(-32602, "missing 'from_address'"))?
            .to_string();
        let intent = oc_netagent::intent::Intent::new(
            kind,
            chain_id.to_string(),
            session_key_id.to_string(),
        );
        let rpc_url = params.get("rpc_url").and_then(serde_json::Value::as_str).map(String::from);
        let cfg = oc_netagent::intent::HotPathConfig::new(rpc_url);
        let rpc = oc_netagent::intent::select_rpc_client(&intent.chain_id, &cfg)
            .map_err(|e| state::RpcError::new(-32603, format!("intent RPC unavailable: {e}")))?;
        // Local C13 signer: the EVM vault key signs the unsigned bytes, then
        // the signature is encoded into a full signed RLP transaction for
        // broadcast. Per-request enclave (default): decrypt→sign→wipe runs in
        // a subprocess; the in-process fallback below is tests /
        // `OC_ENCLAVE=off` only.
        let signer = |_key: &oc_netagent::intent::SigningKeyRef,
                      unsigned_tx: &[u8]|
         -> Result<Vec<u8>, oc_netagent::intent::IntentError> {
            if crate::enclave_spawn::signing_enclave_enabled() {
                let wallet_id = state
                    .configured_wallet_id()
                    .map_err(oc_netagent::intent::IntentError::Execution)?;
                let mut req = crate::enclave_spawn::fresh_request(
                    oc_keyagent::enclave::OP_SIGN_TRANSACTION,
                    &wallet_id,
                    "eip155:1",
                );
                req.payload_hex = hex::encode(unsigned_tx);
                req.index = state.index();
                req.credential_hex = Some(state.passphrase_credential_hex());
                let resp = crate::enclave_spawn::spawn_enclave(&req)
                    .map_err(oc_netagent::intent::IntentError::Execution)?;
                return crate::enclave_spawn::response_hex(resp.signed_tx_hex.as_ref(), "signed tx")
                    .map_err(oc_netagent::intent::IntentError::Execution);
            }
            let secret = state
                .secret_key(oc_core::ChainType::Evm)
                .map_err(oc_netagent::intent::IntentError::Execution)?;
            let evm = oc_signer::chains::EvmSigner;
            let sig = evm
                .sign_transaction(secret.expose(), unsigned_tx)
                .map_err(|e| oc_netagent::intent::IntentError::Execution(e.to_string()))?;
            evm.encode_signed_transaction(unsigned_tx, &sig)
                .map_err(|e| oc_netagent::intent::IntentError::Execution(e.to_string()))
        };
        let result = crate::shared_runtime()
            .block_on(oc_netagent::intent::execute_for_hot_path(
                &intent,
                &*rpc,
                &from_address,
                &signer,
            ))
            .map_err(|e| state::RpcError::new(-32603, format!("intent execute: {e}")))?;
        serde_json::to_value(&result)
            .map_err(|e| state::RpcError::new(-32603, format!("result encode: {e}")))
    })
    .await
}

/// H-06: [`auth::handle_generate_challenge`] off the async path.
async fn generate_challenge_async(params: Value) -> Result<Value, state::RpcError> {
    run_blocking(move || auth::handle_generate_challenge(&params)).await
}

/// Single entry point: POST body is a JSON-RPC 2.0 request. Dispatches to the
/// `ledgerflow_*` methods in [`handlers`], gating the stateful ones behind
/// [`auth::require_authorization`].
async fn rpc(State(state): State<SignerState>, Json(req): Json<state::RpcRequest>) -> Response {
    if req.jsonrpc() != "2.0" {
        return error_response(req.id(), state::RpcError::new(-32600, "invalid JSON-RPC version"));
    }
    let id = req.id().clone();
    let result = match req.method() {
        "ledgerflow_generate_challenge" => match auth::validate_params(req.params()) {
            Ok(p) => generate_challenge_async(p).await,
            Err(e) => Err(e),
        },
        "ledgerflow_keys" => match auth::validate_params(req.params()) {
            Ok(p) => match authorize_async(&state, &p).await {
                Ok(()) => keys_async(state.clone()).await,
                Err(e) => Err(e),
            },
            Err(e) => Err(e),
        },
        "ledgerflow_sign" => match auth::validate_params(req.params()) {
            Ok(p) => match authorize_async(&state, &p).await {
                Ok(()) => sign_async(state.clone(), p).await,
                Err(e) => Err(e),
            },
            Err(e) => Err(e),
        },
        "ledgerflow_sign_payment" => match auth::validate_params(req.params()) {
            Ok(p) => match authorize_async(&state, &p).await {
                Ok(()) => sign_payment_async(state.clone(), p).await,
                Err(e) => Err(e),
            },
            Err(e) => Err(e),
        },
        // Intent hot path (read-only pre-flight, no auth — same adapter as
        // WC/HTTP-RPC; fail-closed without an RPC endpoint).
        "ledgerflow_intentSimulate" => match auth::validate_params(req.params()) {
            Ok(p) => intent_simulate_async(p).await,
            Err(e) => Err(e),
        },
        // Intent execution (auth-gated, local loopback signing via the C13
        // `IntentSigner` boundary).
        "ledgerflow_intentExecute" => match auth::validate_params(req.params()) {
            Ok(p) => match authorize_async(&state, &p).await {
                Ok(()) => intent_execute_async(state.clone(), p).await,
                Err(e) => Err(e),
            },
            Err(e) => Err(e),
        },
        other => Err(state::RpcError::new(-32601, format!("method not found: {other}"))),
    };

    match result {
        Ok(value) => success_response(&id, value),
        Err(e) => error_response(&id, e),
    }
}

// ---------------------------------------------------------------------------
// Response helpers
// ---------------------------------------------------------------------------

fn success_response(id: &Value, result: Value) -> Response {
    (StatusCode::OK, Json(json!({ "jsonrpc": "2.0", "id": id, "result": result }))).into_response()
}

fn error_response(id: &Value, err: state::RpcError) -> Response {
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
pub(crate) fn parse_loopback(listen: &str) -> Result<SocketAddr, CliError> {
    let parsed: SocketAddr = listen
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
pub(crate) async fn serve_async(state: SignerState, parsed: SocketAddr) -> Result<(), CliError> {
    let app = axum::Router::new().route("/", post(rpc)).with_state(state.clone());

    let listener = tokio::net::TcpListener::bind(parsed).await.map_err(CliError::Io)?;
    eprintln!(
        "WalletSigner JSON-RPC server listening on http://{} (wallet '{}', index {})",
        listener.local_addr().map_err(CliError::Io)?,
        state.wallet(),
        state.index()
    );
    axum::serve(listener, app).await.map_err(CliError::Io)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use base64::Engine;

    use super::*;
    use crate::commands::wallet_rpc::{
        auth::{auth_params_for_wallet, require_authorization},
        handlers::{handle_keys, handle_sign, handle_sign_payment},
    };
    // Shared `HomeGuard`/`HOME_LOCK` from `crate::test_util` — the single lock
    // that serializes ALL HOME-mutating tests in the crate (this module AND
    // `tests.rs`), so they cannot race on the process-global `HOME` env var.
    use crate::test_util::HomeGuard;

    const TEST_PASSPHRASE: &str = "test-passphrase";

    /// Create a fresh wallet in a temporary vault and return a `SignerState`
    /// pointed at it, so the wire handlers run against real key material.
    fn test_state() -> SignerState {
        let vault = tempfile::tempdir().expect("tempdir");
        oc_wallet::create_wallet("test", Some(12), Some(TEST_PASSPHRASE), Some(vault.path()))
            .expect("create wallet");
        SignerState::from_parts(
            "test".to_string(),
            0,
            zeroize::Zeroizing::new(TEST_PASSPHRASE.to_string()),
            Some(std::sync::Arc::new(vault.keep())),
        )
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
            assert_ne!(bytes.len(), 0);
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
        assert_eq!(err.code(), -32602);
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
        assert_eq!(err.code(), -32602);
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
        assert_eq!(err.code(), -32602);
        assert!(err.message().contains("configured wallet"));
    }
}
