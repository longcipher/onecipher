//! Integration tests for the `SignAuth` request (auth-class signing, no
//! passkey gate).
//!
//! The wallet is created device-bound: its encryption passphrase is the
//! unlock token derived from the process device key (the same derivation the
//! Key-Agent's `handle_sign_auth` performs). This mirrors how passkey-gated
//! signing works (`UnlockToken::new(wallet_id, auth.signature)`), with the
//! device key standing in for the passkey signature.
//!
//! Per R56 these tests are synchronous (no tokio / reqwest / hyper).

use std::sync::MutexGuard;

use oc_core::{EncryptedWallet, KeyType};
use oc_keyagent::{
    KeyAgentRequest, KeyAgentRequestKind, KeyAgentResponseKind,
    audit::DeviceKeyStore,
    proto::{SignAuthRequest, SignAuthResponse},
};
use prost::Message;

/// The canonical BIP-39 test vector mnemonic (derives to EVM address
/// `0x9858EfFD232B4033E47d90003D41EC34EcaEda94` at m/44'/60'/0'/0/0).
const ABANDON_PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// Serializes HOME-mutating tests (the device key + vault live under HOME).
static HOME_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// RAII guard that redirects `HOME` to a fresh temp dir and restores the
/// original value on drop.
struct HomeGuard {
    _lock: MutexGuard<'static, ()>,
    _dir: tempfile::TempDir,
}

impl HomeGuard {
    fn new() -> Self {
        let lock = HOME_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = tempfile::tempdir().expect("create temp HOME dir");
        let path = dir.path().to_path_buf();
        let home = path.to_string_lossy().into_owned();
        // SAFETY: tests are serialized via HOME_LOCK; no other thread reads
        // HOME concurrently within this crate's test binary.
        unsafe { std::env::set_var("HOME", &home) };
        Self { _lock: lock, _dir: dir }
    }
}

/// Create a device-bound wallet in the isolated HOME: encrypted with the
/// unlock-token passphrase the Key-Agent derives from the device key.
fn create_device_bound_wallet(wallet_id: &str) -> Vec<u8> {
    let store = DeviceKeyStore::open_default().expect("open device key store");
    let device_key = store.load_or_generate().expect("load device key");
    let token = oc_core::UnlockToken::new(wallet_id.to_string(), &device_key.to_bytes())
        .expect("derive unlock token");
    let passphrase = token.to_passphrase().expect("derive passphrase");

    let envelope = oc_signer::encrypt(ABANDON_PHRASE.as_bytes(), passphrase.as_bytes()).unwrap();
    let wallet = EncryptedWallet::new(
        wallet_id.to_string(),
        "auth-wallet".to_string(),
        vec![],
        serde_json::to_value(&envelope).unwrap(),
        KeyType::Mnemonic,
    );
    oc_vault::save_encrypted_wallet(&wallet, None).expect("save wallet");
    device_key.to_bytes().to_vec()
}

/// Dispatch a `SignAuth` request and decode the response payload.
fn dispatch_sign_auth(wallet_id: &str, message: &[u8]) -> SignAuthResponse {
    let agent_token = vec![0xAB; 32];
    oc_keyagent::handler::set_sign_auth_internal_token(Some(agent_token.clone()));
    let req = KeyAgentRequest {
        kind: Some(KeyAgentRequestKind::SignAuth(SignAuthRequest {
            wallet_id: wallet_id.to_string(),
            chain_id: "eip155:1".to_string(),
            message: message.to_vec(),
            auth: None,
            agent_token,
        })),
    };
    let resp = oc_keyagent::handler::dispatch(&req).expect("dispatch must not fail");
    match &resp.kind {
        Some(KeyAgentResponseKind::Ok(bytes)) => {
            SignAuthResponse::decode(bytes.as_slice()).expect("decode SignAuthResponse")
        }
        other => panic!("expected Ok(SignAuthResponse), got {other:?}"),
    }
}

#[test]
fn sign_auth_eip191_signature_recovers_the_derived_address() {
    let _home = HomeGuard::new();
    let wallet_id = "w-auth-eip191";
    // Creating the wallet also (re)generates the device key the handler will
    // read — the wallet passphrase is derived from that same key, so the
    // handler's unlock must succeed.
    create_device_bound_wallet(wallet_id);

    let message = b"onecipher auth sign-in message";
    let out = dispatch_sign_auth(wallet_id, message);

    // Known vector: the abandon mnemonic derives to this EIP-55 address.
    assert_eq!(
        out.address, "0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
        "address must match the abandon-mnemonic test vector"
    );
    assert_eq!(out.chain_id, "eip155:1");
    assert_eq!(out.signature.len(), 65, "EVM EIP-191 signatures are r||s||v (65 bytes)");

    // EIP-191 recovery: ecrecover(keccak256("\x19Ethereum Signed Message:\n" +
    // len + msg), v, r, s) must yield the derived address.
    let signer = oc_signer::signer_for_chain(oc_core::ChainType::Evm);
    let valid = signer
        .verify_message(&out.address, message, &out.signature)
        .expect("verify_message must not error");
    assert!(valid, "signature must recover the expected address");

    // Compressed secp256k1 public key (33 bytes, 0x02/0x03 prefix).
    assert_eq!(out.public_key.len(), 33);
    assert!(out.public_key[0] == 0x02 || out.public_key[0] == 0x03);
}

#[test]
fn sign_auth_accepts_daemon_internal_token_without_passkey() {
    let _home = HomeGuard::new();
    let wallet_id = "w-auth-nopasskey";
    create_device_bound_wallet(wallet_id);

    // WalletConnect-originated auth signing uses a daemon-internal capability
    // token instead of a user-provided PasskeyAuthorization.
    let out = dispatch_sign_auth(wallet_id, b"no passkey needed");
    assert_eq!(out.address, "0x9858EfFD232B4033E47d90003D41EC34EcaEda94");
    assert_eq!(out.signature.len(), 65);
}

#[test]
fn sign_auth_missing_wallet_id_returns_error() {
    let _home = HomeGuard::new();
    let req = KeyAgentRequest {
        kind: Some(KeyAgentRequestKind::SignAuth(SignAuthRequest {
            wallet_id: String::new(),
            chain_id: "eip155:1".to_string(),
            message: b"x".to_vec(),
            auth: None,
            agent_token: vec![0xAB; 32],
        })),
    };
    let resp = oc_keyagent::handler::dispatch(&req).expect("dispatch must not fail");
    assert!(resp.is_error(), "empty wallet_id must be rejected");
}

#[test]
fn sign_auth_unknown_wallet_returns_error() {
    let _home = HomeGuard::new();
    let req = KeyAgentRequest {
        kind: Some(KeyAgentRequestKind::SignAuth(SignAuthRequest {
            wallet_id: "does-not-exist".to_string(),
            chain_id: "eip155:1".to_string(),
            message: b"x".to_vec(),
            auth: None,
            agent_token: vec![0xAB; 32],
        })),
    };
    let resp = oc_keyagent::handler::dispatch(&req).expect("dispatch must not fail");
    assert!(resp.is_error(), "unknown wallet must be rejected");
}
