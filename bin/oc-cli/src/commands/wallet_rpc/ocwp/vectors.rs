//! OCWP conformance vectors — Rust side (design §9.4).
//!
//! The JSON fixtures in `extension/vectors/ocwp-v1/` are executed against a
//! real [`AppState`] here and against the TypeScript client tests in
//! `extension/tests/`, so the two implementations cannot drift apart.
//! `$SESSION`-style indirection is expressed via the `"session"` field:
//! `"none"` passes params through; `"valid"` injects a freshly unlocked
//! session id.

use serde_json::Value;

use super::{AppState, OcwpSettings, errors::OcwpError};
use crate::{commands::wallet_rpc::state::SignerState, test_util::HomeGuard};

const TEST_PASSPHRASE: &str = "test-passphrase";
const EXTENSION_ID: &str = "abcdefghijklmnopabcdefghijklmnop";
/// The pinned origin every vector is dispatched from (INV-9 origin binding).
const EXT_ORIGIN: &str = "chrome-extension://abcdefghijklmnopabcdefghijklmnop";
/// A second, *also allowlisted* extension — used to prove origin pinning.
const OTHER_ORIGIN: &str = "chrome-extension://ffffffffffffffffffffffffffffffff";

fn vectors_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../extension/vectors/ocwp-v1")
}

/// Build an app state with a throwaway vault containing wallet "test".
fn test_app(home: &HomeGuard) -> (AppState, std::path::PathBuf) {
    let vault = tempfile::tempdir().expect("tempdir");
    oc_wallet::create_wallet("test", Some(12), Some(TEST_PASSPHRASE), Some(vault.path()))
        .expect("create wallet");
    let state_dir = home.path().join(".onecipher");
    let signer = SignerState::from_parts(
        "test".to_string(),
        0,
        zeroize::Zeroizing::new(TEST_PASSPHRASE.to_string()),
        Some(std::sync::Arc::new(vault.keep())),
    );
    let app = AppState::with_state_dir(
        signer,
        OcwpSettings {
            extension_ids: vec![
                EXTENSION_ID.to_string(),
                OTHER_ORIGIN.trim_start_matches("chrome-extension://").to_string(),
            ],
            require_passkey_eip7702: true,
            ..OcwpSettings::default()
        },
        &state_dir,
    )
    .expect("app state");
    (app, state_dir)
}

fn load_vectors(name: &str) -> Value {
    let path = vectors_dir().join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("corrupt {}: {e}", path.display()))
}

#[test]
fn error_vectors_fail_with_the_documented_codes() {
    let _home = HomeGuard::new();
    let (app, _state_dir) = test_app(&_home);
    // A valid session for the `"session": "valid"` vectors.
    let unlock = super::handlers::handle_unlock(
        &app,
        &serde_json::json!({ "wallet": "test", "passphrase": TEST_PASSPHRASE }),
        EXT_ORIGIN,
    )
    .expect("unlock with the correct passphrase must succeed");
    let session_id = unlock["session_id"].as_str().expect("session_id").to_string();

    let vectors = load_vectors("errors.json");
    let vectors = vectors.as_array().expect("errors.json must be an array");
    assert!(vectors.len() >= 10, "expected a substantial vector set");

    for vector in vectors {
        let name = vector["name"].as_str().expect("vector name");
        let method = vector["method"].as_str().expect("vector method");
        let mut params = vector["params"].clone();
        if vector["session"].as_str() == Some("valid") {
            params["session_id"] = Value::String(session_id.clone());
        }
        let result = super::handlers::dispatch(&app, method, &params, EXT_ORIGIN);
        let expected = vector["expected_error_code"].as_i64().expect("expected code");
        let err: OcwpError = result.expect_err(&format!("vector '{name}' must fail"));
        assert_eq!(i64::from(err.code), expected, "vector '{name}': {}", err.message);
        if let Some(expected_data) = vector.get("expected_error_data") {
            let data = err.data.unwrap_or_else(|| panic!("vector '{name}' must carry data"));
            for (key, value) in expected_data.as_object().expect("expected_data object") {
                assert_eq!(&data[key], value, "vector '{name}' data.{key}");
            }
        }
    }
}

#[test]
fn hello_vector_matches_shape() {
    let _home = HomeGuard::new();
    let (app, _state_dir) = test_app(&_home);
    let vector = load_vectors("hello.json");
    let result = super::handlers::handle_hello(&app).expect("hello must succeed");
    for key in vector["expected_result_keys"].as_array().expect("keys") {
        let key = key.as_str().expect("key string");
        assert!(result.get(key).is_some(), "hello result missing '{key}'");
    }
    assert_eq!(
        result["protocol_version"], vector["expected_protocol_version"],
        "protocol_version must match the vector"
    );
    let features: Vec<&str> =
        result["features"].as_array().expect("features").iter().filter_map(Value::as_str).collect();
    for feature in vector["expected_features"].as_array().expect("features") {
        assert!(
            features.contains(&feature.as_str().expect("feature string")),
            "hello features missing {feature}"
        );
    }
}

#[test]
fn unlock_success_vector_shape() {
    let _home = HomeGuard::new();
    let (app, _state_dir) = test_app(&_home);
    let result = super::handlers::handle_unlock(
        &app,
        &serde_json::json!({ "wallet": "test", "passphrase": TEST_PASSPHRASE }),
        EXT_ORIGIN,
    )
    .expect("unlock must succeed");
    for key in ["session_id", "wallet_id", "expires_at_unix", "accounts", "origin"] {
        assert!(result.get(key).is_some(), "unlock result missing '{key}'");
    }
    let session_id = result["session_id"].as_str().expect("session id");
    assert_eq!(session_id.len(), 64, "session id must be 32 bytes hex");
    assert_eq!(result["origin"], EXT_ORIGIN, "unlock must echo its pinned origin");
    // Accounts list every chain family with an address.
    let accounts = result["accounts"].as_array().expect("accounts");
    assert!(!accounts.is_empty(), "wallet must expose accounts");
    for account in accounts {
        assert!(account["address"].as_str().is_some());
        assert!(account["chain_id"].as_str().is_some());
    }
}

/// INV-9: a session unlocked by extension A is unusable by extension B, even
/// though B is on the same allowlist and on the same loopback socket.
#[test]
fn sessions_are_bound_to_the_unlocking_origin() {
    let _home = HomeGuard::new();
    let (app, _state_dir) = test_app(&_home);
    let unlock = super::handlers::handle_unlock(
        &app,
        &serde_json::json!({ "wallet": "test", "passphrase": TEST_PASSPHRASE }),
        EXT_ORIGIN,
    )
    .expect("unlock");
    let session_id = unlock["session_id"].as_str().expect("session id").to_string();
    let params = serde_json::json!({ "session_id": session_id });

    // The owning origin works.
    super::handlers::dispatch(&app, "oc_accounts", &params, EXT_ORIGIN)
        .expect("owning origin may use its session");
    // A foreign allowlisted origin is refused.
    let err = super::handlers::dispatch(&app, "oc_accounts", &params, OTHER_ORIGIN)
        .expect_err("foreign origin must not drive the session");
    assert_eq!(err.code, super::errors::CODE_UNAUTHORIZED);
    // A web origin never gets that far (connection validation rejects it
    // first), so the session handler is only reachable via the allowlist.
    let err = super::handlers::dispatch(&app, "oc_session_status", &params, OTHER_ORIGIN)
        .expect("session_status reports foreign sessions as locked, not an error");
    assert_eq!(err["unlocked"], false, "a foreign session must read as locked");
}

/// INV-4/§4.9: the policy preview must project the *same* transaction fields
/// the signing path enforces. A preview that read an empty request would show
/// a green badge for a transaction policy denies.
#[test]
fn policy_preview_projects_the_transaction_it_is_given() {
    let _home = HomeGuard::new();
    let (app, _state_dir) = test_app(&_home);
    let unlock = super::handlers::handle_unlock(
        &app,
        &serde_json::json!({ "wallet": "test", "passphrase": TEST_PASSPHRASE }),
        EXT_ORIGIN,
    )
    .expect("unlock");
    let session_id = unlock["session_id"].as_str().expect("session id").to_string();

    // No policies are configured in the throwaway vault, so the decision is
    // `allow` — but the *projection* is what is under test: it must echo the
    // transaction it was handed rather than an empty one.
    let transaction = serde_json::json!({
        "to": "0x1111111111111111111111111111111111111111",
        "value": "1000",
        "data": "0xa9059cbb",
        "maxFeePerGas": "0x10",
    });
    let preview = super::handlers::dispatch(
        &app,
        "oc_policy_preview",
        &serde_json::json!({
            "session_id": session_id,
            "chain_id": "eip155:1",
            "transaction": transaction,
        }),
        EXT_ORIGIN,
    )
    .expect("preview must succeed");
    assert_eq!(
        preview["to"], "0x1111111111111111111111111111111111111111",
        "preview must project `to`, not drop it"
    );
    assert_eq!(preview["value"], "1000");
    assert_eq!(preview["data"], "0xa9059cbb");
    assert_eq!(preview["tx_type"], "0x02 (EIP-1559)");
    assert_eq!(preview["decision"], "allow");

    // The documented flat shape must keep working for third-party clients.
    let flat = super::handlers::dispatch(
        &app,
        "oc_policy_preview",
        &serde_json::json!({
            "session_id": session_id,
            "chain_id": "eip155:1",
            "to": "0x2222222222222222222222222222222222222222",
            "value": "7",
        }),
        EXT_ORIGIN,
    )
    .expect("flat preview must succeed");
    assert_eq!(flat["to"], "0x2222222222222222222222222222222222222222");
    assert_eq!(flat["value"], "7");
}

/// §5.2: `oc_passkey_challenge` records a session binding, so a challenge
/// minted for one session cannot authorize another's request.
#[test]
fn step_up_challenges_are_bound_to_their_session() {
    let _home = HomeGuard::new();
    let (app, _state_dir) = test_app(&_home);
    let first = super::handlers::handle_unlock(
        &app,
        &serde_json::json!({ "wallet": "test", "passphrase": TEST_PASSPHRASE }),
        EXT_ORIGIN,
    )
    .expect("unlock a");
    let second = super::handlers::handle_unlock(
        &app,
        &serde_json::json!({ "wallet": "test", "passphrase": TEST_PASSPHRASE }),
        EXT_ORIGIN,
    )
    .expect("unlock b");
    let session_a = first["session_id"].as_str().expect("session a").to_string();
    let session_b = second["session_id"].as_str().expect("session b").to_string();

    // Minting requires a registered credential, so drive the store directly
    // through the public passkey-registration path. The key below is the P-256
    // generator point G, the canonical valid uncompressed SEC1 encoding.
    let credential_id = "cred-ocwp-origin-binding";
    super::handlers::dispatch(
        &app,
        "oc_passkey_register",
        &serde_json::json!({
            "session_id": session_a,
            "credential_id": credential_id,
            "algorithm": "p256",
            "public_key": base64_std(&[
                0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63,
                0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39,
                0x45, 0xd8, 0x98, 0xc2, 0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e,
                0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e,
                0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
            ]),
        }),
        EXT_ORIGIN,
    )
    .expect("passkey registration");

    let challenge = super::handlers::dispatch(
        &app,
        "oc_passkey_challenge",
        &serde_json::json!({ "session_id": session_a, "credential_id": credential_id }),
        EXT_ORIGIN,
    )
    .expect("challenge");
    let challenge_hex = challenge["challenge_hex"].as_str().expect("challenge hex").to_string();

    // Session B cannot redeem session A's challenge.
    assert!(
        app.step_up.consume(&challenge_hex, &session_b).is_none(),
        "a challenge must not cross sessions"
    );
    // Session A can — exactly once.
    assert!(app.step_up.consume(&challenge_hex, &session_a).is_some());
    assert!(
        app.step_up.consume(&challenge_hex, &session_a).is_none(),
        "a challenge must be single-use"
    );
}

fn base64_std(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}
