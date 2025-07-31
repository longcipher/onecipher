//! Session key CLI (R21-R27). Dispatches via `NetAgentClient`.
//!
//! Each subcommand constructs the appropriate proto `Request`, hands it to the
//! `NetAgentClient` trait, and prints the response. Hex-decoding of Passkey
//! challenge/signature happens here (UI-process concern), not in the proto layer.

use oc_proto::{CreateSessionKeyRequest, PasskeyAuthorization, RevokeSessionKeyRequest};

use crate::{CliError, netagent::NetAgentClient};

/// `onecipher session-key create --label ... --challenge <hex> --signature <hex> --credential-id
/// ...`
///
/// RPC: `CreateSessionKey(CreateSessionKeyRequest) → CreateSessionKeyResponse`
pub(crate) fn create(
    label: &str,
    challenge_hex: &str,
    signature_hex: &str,
    credential_id: &str,
    client: &dyn NetAgentClient,
) -> Result<(), CliError> {
    let challenge = hex::decode(challenge_hex)
        .map_err(|e| CliError::InvalidArgs(format!("invalid challenge hex: {e}")))?;
    let signature = hex::decode(signature_hex)
        .map_err(|e| CliError::InvalidArgs(format!("invalid signature hex: {e}")))?;
    let req = CreateSessionKeyRequest {
        label: label.to_string(),
        rules: None,
        budget: None,
        auth: Some(PasskeyAuthorization {
            challenge,
            signature,
            credential_id: credential_id.to_string(),
        }),
    };
    let resp = client.create_session_key(req)?;
    println!("session key created: {}", resp.session_key_id);
    Ok(())
}

/// `onecipher session-key revoke <session_key_id> --challenge <hex> --signature <hex>
/// --credential-id ...`
///
/// RPC: `RevokeSessionKey(RevokeSessionKeyRequest) → RevokeSessionKeyResponse`
pub(crate) fn revoke(
    session_key_id: &str,
    challenge_hex: &str,
    signature_hex: &str,
    credential_id: &str,
    client: &dyn NetAgentClient,
) -> Result<(), CliError> {
    let challenge = hex::decode(challenge_hex)
        .map_err(|e| CliError::InvalidArgs(format!("invalid challenge hex: {e}")))?;
    let signature = hex::decode(signature_hex)
        .map_err(|e| CliError::InvalidArgs(format!("invalid signature hex: {e}")))?;
    let req = RevokeSessionKeyRequest {
        session_key_id: session_key_id.to_string(),
        auth: Some(PasskeyAuthorization {
            challenge,
            signature,
            credential_id: credential_id.to_string(),
        }),
    };
    client.revoke_session_key(req)?;
    println!("session key revoked: {session_key_id}");
    Ok(())
}

/// `onecipher session-key list`
///
/// RPC: `ListSessionKeys(Empty) → ListSessionKeysResponse`
pub(crate) fn list(client: &dyn NetAgentClient) -> Result<(), CliError> {
    let resp = client.list_session_keys()?;
    if resp.keys.is_empty() {
        println!("(no session keys)");
    } else {
        for sk in &resp.keys {
            let status_str = session_key_status_name(sk.status);
            println!("{}: {} ({})", sk.session_key_id, sk.label, status_str);
        }
    }
    Ok(())
}

/// Map `SessionKeyInfo.status` (i32 enum) to a human-readable name.
/// Falls back to the raw integer for unknown values (forward compat).
const fn session_key_status_name(status: i32) -> &'static str {
    match status {
        0 => "ACTIVE",
        1 => "REVOKED",
        2 => "EXPIRED",
        _ => "UNKNOWN",
    }
}
