//! Passkey challenge minting and per-request authorization for the loopback
//! WalletSigner server.

use oc_keyagent::{passkey::PasskeyPubkeyStore, proto::PasskeyAuthorization};
use serde_json::Value;

use super::state::{GenerateChallengeParams, RpcError, SignerState};

/// Validate that params are present (non-null). Returns the cloned params
/// object for downstream typed extraction.
pub(crate) fn validate_params(params: &Option<Value>) -> Result<Value, RpcError> {
    params.clone().ok_or_else(|| RpcError::new(-32602, "missing params"))
}

/// Extract and decode a [`PasskeyAuthorization`] from the `auth` object of a
/// params value.
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

/// Authorize a stateful request: verify the passkey signature and that the
/// bound passkey belongs to the configured wallet.
pub(crate) fn require_authorization(state: &SignerState, params: &Value) -> Result<(), RpcError> {
    let auth = parse_auth(params)?;
    oc_keyagent::handler::authorize_passkey(&auth)
        .map_err(|e| RpcError::new(-32602, format!("passkey authorization failed: {e}")))?;
    let configured_wallet_id =
        state.configured_wallet_id().map_err(|e| RpcError::new(-32603, e))?;
    // L-07: store open/read failures may embed filesystem paths — log the
    // detail and return a generic message to the client.
    let store = PasskeyPubkeyStore::open_default().map_err(|e| {
        tracing::warn!(error = %e, "wallet-rpc: failed to open passkey store");
        RpcError::new(-32603, "internal error")
    })?;
    let stored = store
        .get(&auth.credential_id)
        .map_err(|e| {
            tracing::warn!(error = %e, "wallet-rpc: failed to read passkey store");
            RpcError::new(-32603, "internal error")
        })?
        .ok_or_else(|| RpcError::new(-32602, "passkey not registered"))?;
    if stored.wallet_id != configured_wallet_id {
        return Err(RpcError::new(-32602, "passkey is not bound to configured wallet"));
    }
    Ok(())
}

/// `ledgerflow_generate_challenge` → `{"challenge_hex":"..."}`.
pub(crate) fn handle_generate_challenge(params: &Value) -> Result<Value, RpcError> {
    let request = serde_json::from_value::<GenerateChallengeParams>(params.clone())
        .map_err(|e| RpcError::new(-32602, format!("invalid challenge params: {e}")))?;
    let challenge = oc_keyagent::handler::generate_passkey_challenge(request.credential_id())
        .map_err(|e| RpcError::new(-32603, e))?;
    Ok(serde_json::json!({ "challenge_hex": hex::encode(challenge) }))
}

/// Build a valid `auth` params object for a passkey bound to `binding_wallet_id`.
///
/// Test-only helper: registers a fresh passkey, mints a challenge, and signs it
/// so `require_authorization` accepts the resulting params.
#[cfg(test)]
pub(crate) fn auth_params_for_wallet(binding_wallet_id: &str, credential_id: &str) -> Value {
    use ed25519_dalek::Signer as _;
    let mut store = PasskeyPubkeyStore::open_default().expect("open passkey store");
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rng());
    let public_key = signing_key.verifying_key().to_bytes().to_vec();
    store
        .register(
            credential_id,
            oc_keyagent::passkey::StoredPasskeyPubkey {
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
    serde_json::json!({
        "auth": {
            "challenge_hex": hex::encode(challenge),
            "signature_hex": hex::encode(signature.to_bytes()),
            "credential_id": credential_id,
        }
    })
}
