//! Handler dispatch for [`KeyAgentRequest`].
//!
//! Real implementations replacing the T11 stubs. All handlers are synchronous
//! (R55 — no async runtime in Key-Agent). Sensitive key material lives inside
//! `HardenedBytes` and is zeroized on drop.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock},
};

use prost::Message;
use tracing::warn;

use crate::{
    audit::{AuditLog, DeviceKeyStore, EventType},
    error::KeyAgentError,
    global_key_cache,
    passkey::{PasskeyPubkeyStore, PasskeyVerifier, StoredPasskeyPubkey},
    request::{KeyAgentRequest, KeyAgentRequestKind},
    response::KeyAgentResponse,
};

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

/// Process-wide audit log. Initialized lazily on first use.
/// Stage 0: device key is persisted via DeviceKeyStore (survives restarts).
static GLOBAL_AUDIT_LOG: OnceLock<Arc<Mutex<AuditLog>>> = OnceLock::new();

fn global_audit_log() -> Result<Arc<Mutex<AuditLog>>, KeyAgentError> {
    if let Some(log) = GLOBAL_AUDIT_LOG.get() {
        return Ok(log.clone());
    }
    // L3 fix: HOME must be set — refuse to fall back to /tmp (world-readable,
    // survives reboot, leaks audit trail to a shared location).
    let path = oc_core::paths::state_path("logs/audit.jsonl")
        .map_err(|e| KeyAgentError::Internal(e.to_string()))?;
    let device_id = "keyagent".to_string();
    // Stage 0: persistent device key instead of per-process random key.
    let store = DeviceKeyStore::open_default()
        .map_err(|e| KeyAgentError::Internal(format!("failed to open device key store: {e}")))?;
    let device_key = store
        .load_or_generate()
        .map_err(|e| KeyAgentError::Internal(format!("failed to load/generate device key: {e}")))?;
    let log = AuditLog::open(&path, &device_id, device_key)
        .map_err(|e| KeyAgentError::Internal(format!("failed to open audit log: {e}")))?;
    let arc = Arc::new(Mutex::new(log));
    // set may fail on race — another thread won. Return the winner's arc.
    match GLOBAL_AUDIT_LOG.set(arc.clone()) {
        Ok(()) => Ok(arc),
        Err(winner) => Ok(winner),
    }
}

/// P0-2: Process-wide shared Passkey verifier table, keyed by `credential_id`.
///
/// Per the challenge lifecycle fix: a fresh [`PasskeyVerifier`] was being
/// created per `verify_passkey()` call, leaving `pending_challenges` always
/// empty and causing every verify to return `Replay`. This shared map is
/// populated lazily — [`handle_generate_challenge`] inserts a verifier on
/// first challenge issuance for a credential_id, and [`verify_passkey`]
/// reuses the same instance so the challenge is found in
/// `pending_challenges`.
///
/// Each [`PasskeyVerifier`] is bound to one credential_id (and its stored
/// public key), so a `HashMap<credential_id, PasskeyVerifier>` is needed to
/// support multiple registered Passkeys concurrently.
static GLOBAL_PASSKEY_VERIFIERS: OnceLock<Arc<Mutex<HashMap<String, PasskeyVerifier>>>> =
    OnceLock::new();

fn global_passkey_verifiers() -> Arc<Mutex<HashMap<String, PasskeyVerifier>>> {
    GLOBAL_PASSKEY_VERIFIERS.get_or_init(|| Arc::new(Mutex::new(HashMap::new()))).clone()
}

/// Daemon-internal capability token used to authorize WalletConnect-originated
/// auth-class signing after origin/approval checks have already completed.
static SIGN_AUTH_INTERNAL_TOKEN: OnceLock<Arc<Mutex<Option<Vec<u8>>>>> = OnceLock::new();

fn sign_auth_internal_token() -> Arc<Mutex<Option<Vec<u8>>>> {
    SIGN_AUTH_INTERNAL_TOKEN.get_or_init(|| Arc::new(Mutex::new(None))).clone()
}

/// Default vault path (`None` = use `~/.onecipher`).
fn vault_path() -> Option<&'static std::path::Path> {
    None
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Load a wallet from the vault, decrypt it, and derive the chain signing key.
/// Returns `(key, signer)`. Key is zeroized on drop.
///
/// `unlock_token` carries Passkey-derived key material. The token's passphrase
/// is derived (validating the token) and used to decrypt the wallet. A valid
/// unlock token is REQUIRED — the empty-passphrase backward-compat path was
/// removed (C1 fix) because it allowed signing without a freshly-verified
/// Passkey.
fn load_chain_key(
    wallet_id: &str,
    chain_id: &str,
    unlock_token: &oc_core::UnlockToken,
) -> Result<(oc_signer::SecretBytes, Box<dyn oc_signer::ChainSigner>), String> {
    let chain = oc_core::parse_chain(chain_id).map_err(|e| format!("invalid chain: {e}"))?;

    let pp = unlock_token.to_passphrase().map_err(|e| format!("passphrase derivation: {e}"))?;
    let pp_bytes: &[u8] = pp.as_bytes();

    let key = oc_wallet::ops::decrypt_signing_key(
        wallet_id,
        chain.chain_type,
        pp_bytes,
        None,
        vault_path(),
    )
    .map_err(|e| format!("wallet decrypt failed: {e}"))?;
    // NOTE: the legacy "empty-passphrase" fallback was intentionally removed
    // (C1 fix). Pre-device-bound vaults must be migrated with
    // `onecipher wallet migrate` before they can be unlocked; silently
    // retrying with `b""` reintroduced a signing-without-passphrase path.
    let signer = oc_signer::signer_for_chain(chain.chain_type);
    Ok((key, signer))
}

/// Append an audit entry. Silently logs on failure (audit must not break ops).
fn audit(event_type: EventType, session_key_id: Option<&str>, payload: serde_json::Value) {
    let audit_log = match global_audit_log() {
        Ok(log) => log,
        Err(e) => {
            warn!(target: "oc-keyagent::audit", "audit log unavailable: {e}");
            return;
        }
    };
    if let Ok(mut log) = audit_log.lock() {
        if let Err(e) = log.append(event_type, session_key_id.map(String::from), payload) {
            warn!(target: "oc-keyagent::audit", "audit append failed: {e}");
        }
    }
}

/// Current unix timestamp in seconds.
fn now_unix() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()
}

/// Verify a [`PasskeyAuthorization`] against the stored public key.
///
/// Returns `Ok(StoredPasskeyPubkey)` on success — the caller may inspect
/// `wallet_id` for binding checks (e.g. `UnlockVault`). Returns
/// `Err(KeyAgentResponse)` on any failure (store error, unknown credential,
/// forged signature) so the caller can propagate it via `Ok(resp)`.
///
/// P0-2 lifecycle fix: the verifier is now looked up from the process-wide
/// [`GLOBAL_PASSKEY_VERIFIERS`] map (keyed by `credential_id`) so that
/// challenges generated by [`handle_generate_challenge`] are visible here.
/// If no verifier exists yet for this `credential_id`, one is lazily created
/// — but its `pending_challenges` set will be empty, so the client MUST have
/// called `GenerateChallenge` first or `verify()` will return `Replay`.
fn verify_passkey(
    auth: &crate::proto::PasskeyAuthorization,
) -> Result<StoredPasskeyPubkey, KeyAgentResponse> {
    let store = match PasskeyPubkeyStore::open_default() {
        Ok(s) => s,
        Err(e) => return Err(KeyAgentResponse::error(format!("passkey store: {e}"))),
    };
    let stored = match store.get(&auth.credential_id) {
        Some(s) => s,
        None => return Err(KeyAgentResponse::error("passkey not registered")),
    };

    let verifiers_map = global_passkey_verifiers();
    let mut verifiers = match verifiers_map.lock() {
        Ok(v) => v,
        Err(_) => return Err(KeyAgentResponse::error("passkey verifiers mutex poisoned")),
    };

    // Lazy-init: if GenerateChallenge was never called for this credential_id,
    // create the verifier on first verify. The pending_challenges set will be
    // empty, so verify() will return Replay — clients MUST call GenerateChallenge
    // first to obtain a valid challenge nonce.
    if !verifiers.contains_key(&auth.credential_id) {
        let pubkey = match PasskeyPubkeyStore::to_passkey_pubkey(&stored) {
            Ok(k) => k,
            Err(e) => return Err(KeyAgentResponse::error(format!("passkey pubkey: {e}"))),
        };
        verifiers.insert(
            auth.credential_id.clone(),
            PasskeyVerifier::new(pubkey, auth.credential_id.as_bytes().to_vec()),
        );
    }
    let verifier = verifiers
        .get_mut(&auth.credential_id)
        .ok_or_else(|| KeyAgentResponse::error("passkey verifier evicted"))?;

    if let Err(e) = verifier.verify(auth) {
        audit(
            EventType::PasskeyForged,
            None,
            serde_json::json!({"credential_id": auth.credential_id, "error": e.to_string()}),
        );
        return Err(KeyAgentResponse::deny(crate::proto::DenyReason::PasskeyForged));
    }
    Ok(stored)
}

/// Issue a fresh passkey challenge for `credential_id` using the process-wide
/// verifier table.
pub fn generate_passkey_challenge(credential_id: &str) -> Result<Vec<u8>, String> {
    let req = crate::proto::GenerateChallengeRequest { credential_id: credential_id.to_string() };
    let resp = handle_generate_challenge(&req).map_err(|e| e.to_string())?;
    let bytes = match resp.kind {
        Some(crate::response::KeyAgentResponseKind::Ok(bytes)) => bytes,
        Some(crate::response::KeyAgentResponseKind::Error(message)) => return Err(message),
        Some(crate::response::KeyAgentResponseKind::Deny(reason)) => {
            return Err(format!("denied: {reason:?}"));
        }
        None => return Err("missing challenge response".to_string()),
    };
    let decoded = crate::proto::GenerateChallengeResponse::decode(bytes.as_slice())
        .map_err(|e| format!("decode generate challenge: {e}"))?;
    Ok(decoded.challenge)
}

/// Verify a passkey proof against the process-wide verifier table.
pub fn authorize_passkey(auth: &crate::proto::PasskeyAuthorization) -> Result<(), String> {
    verify_passkey(auth).map(|_| ()).map_err(|resp| match resp.kind {
        Some(crate::response::KeyAgentResponseKind::Error(message)) => message,
        Some(crate::response::KeyAgentResponseKind::Deny(reason)) => format!("denied: {reason:?}"),
        Some(crate::response::KeyAgentResponseKind::Ok(_)) => {
            "unexpected success payload".to_string()
        }
        None => "missing authorization response".to_string(),
    })
}

/// Install or clear the daemon-internal capability token used by SignAuth.
pub fn set_sign_auth_internal_token(token: Option<Vec<u8>>) {
    if let Ok(mut slot) = sign_auth_internal_token().lock() {
        *slot = token;
    }
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

/// Dispatch a request to the appropriate handler.
///
/// Returns `Ok(response)` for any successfully-processed request,
/// and `Err(KeyAgentError)` only for unrecoverable dispatcher-level failures
/// (e.g. an empty request with no `kind` set). Handler-internal errors are
/// converted to `KeyAgentResponse::error(...)` and returned via `Ok` so the
/// connection loop can continue serving subsequent requests on the same
/// connection.
pub fn dispatch(req: &KeyAgentRequest) -> Result<KeyAgentResponse, KeyAgentError> {
    match &req.kind {
        Some(KeyAgentRequestKind::ListWallets(_)) => handle_list_wallets(),
        Some(KeyAgentRequestKind::SignTransaction(req)) => handle_sign_transaction(req),
        Some(KeyAgentRequestKind::SignMessage(req)) => handle_sign_message(req),
        Some(KeyAgentRequestKind::SignAuth(req)) => handle_sign_auth(req),
        Some(KeyAgentRequestKind::SignTypedData(req)) => handle_sign_typed_data(req),
        Some(KeyAgentRequestKind::SignUserOp(req)) => handle_sign_user_op(req),
        Some(KeyAgentRequestKind::CreateSessionKey(req)) => handle_create_session_key(req),
        Some(KeyAgentRequestKind::RevokeSessionKey(req)) => handle_revoke_session_key(req),
        Some(KeyAgentRequestKind::GetBalance(_)) => {
            // R56: Key-Agent cannot do network I/O. Net-Agent handles balance queries.
            Ok(KeyAgentResponse::not_implemented(
                "GetBalance — Net-Agent handles balance queries (R56: no network I/O in Key-Agent)",
            ))
        }
        Some(KeyAgentRequestKind::LockVault(_)) => handle_lock_vault(),
        Some(KeyAgentRequestKind::UnlockVault(req)) => handle_unlock_vault(req),
        Some(KeyAgentRequestKind::RegisterPasskey(req)) => handle_register_passkey(req),
        Some(KeyAgentRequestKind::GenerateChallenge(req)) => handle_generate_challenge(req),
        Some(KeyAgentRequestKind::GetSecret(_)) => {
            // R56: Key-Agent cannot depend on oc-secret (age dependency chain).
            // The CLI handles secret reads locally via oc-secret; the Net-Agent
            // may handle them in the future. Returning "not implemented" keeps
            // the wire format forward-compatible.
            Ok(KeyAgentResponse::not_implemented(
                "GetSecret — secret operations handled locally by CLI (R56: no oc-secret dep in Key-Agent)",
            ))
        }
        Some(KeyAgentRequestKind::ListSecrets(_)) => Ok(KeyAgentResponse::not_implemented(
            "ListSecrets — secret operations handled locally by CLI (R56: no oc-secret dep in Key-Agent)",
        )),
        Some(KeyAgentRequestKind::GenerateTotp(_)) => Ok(KeyAgentResponse::not_implemented(
            "GenerateTotp — secret operations handled locally by CLI (R56: no oc-secret dep in Key-Agent)",
        )),
        Some(KeyAgentRequestKind::DrainTelemetry(req)) => handle_drain_telemetry(*req),
        None => {
            Err(KeyAgentError::InvalidRequest("request kind is None (empty request)".to_string()))
        }
    }
}

// ---------------------------------------------------------------------------
// Individual handlers
// ---------------------------------------------------------------------------

fn handle_list_wallets() -> Result<KeyAgentResponse, KeyAgentError> {
    let wallets = oc_vault::vault::list_encrypted_wallets(vault_path())
        .map_err(|e| KeyAgentError::Internal(format!("vault list failed: {e}")))?;

    let proto_wallets: Vec<crate::proto::WalletInfo> = wallets
        .iter()
        .map(|w| {
            let key_type = match w.key_type {
                oc_core::wallet_file::KeyType::Mnemonic => "mnemonic",
                oc_core::wallet_file::KeyType::PrivateKey => "private_key",
            };
            let created_at = w
                .created_at
                .parse::<jiff::Timestamp>()
                .map_or(0, |ts| ts.as_second().max(0) as u64);
            crate::proto::WalletInfo {
                id: w.id.clone(),
                name: w.name.clone(),
                key_type: key_type.to_string(),
                created_at,
                accounts: w
                    .accounts
                    .iter()
                    .map(|a| crate::proto::WalletAccount {
                        account_id: a.account_id.clone(),
                        address: a.address.clone(),
                        chain_id: a.chain_id.clone(),
                        derivation_path: a.derivation_path.clone(),
                    })
                    .collect(),
            }
        })
        .collect();

    let resp = crate::proto::ListWalletsResponse { wallets: proto_wallets };
    Ok(KeyAgentResponse::ok(resp.encode_to_vec()))
}

fn handle_sign_transaction(
    req: &crate::proto::SignTransactionRequest,
) -> Result<KeyAgentResponse, KeyAgentError> {
    // P0-2: Passkey gate — verify authentication before signing.
    let auth = match req.auth.as_ref() {
        Some(a) => a,
        None => return Ok(KeyAgentResponse::error("missing passkey authorization")),
    };
    if let Err(resp) = verify_passkey(auth) {
        return Ok(resp);
    }

    // C1 fix: derive an UnlockToken from the freshly-verified Passkey signature.
    // The empty-passphrase backward-compat path was removed; a valid token is
    // required to decrypt the wallet signing key.
    let unlock_token = match oc_core::UnlockToken::new(req.wallet_id.clone(), &auth.signature) {
        Ok(t) => t,
        Err(e) => return Ok(KeyAgentResponse::error(format!("token derivation: {e}"))),
    };
    let (key, signer) = match load_chain_key(&req.wallet_id, &req.chain_id, &unlock_token) {
        Ok(v) => v,
        Err(e) => return Ok(KeyAgentResponse::error(e)),
    };

    let tx_bytes = match hex::decode(&req.raw_tx_hex) {
        Ok(b) => b,
        Err(e) => return Ok(KeyAgentResponse::error(format!("invalid tx hex: {e}"))),
    };

    let signable = match signer.extract_signable_bytes(&tx_bytes) {
        Ok(b) => b.to_vec(),
        Err(e) => return Ok(KeyAgentResponse::error(format!("extract signable failed: {e}"))),
    };
    let output = match signer.sign_transaction(key.expose(), &signable) {
        Ok(o) => o,
        Err(e) => return Ok(KeyAgentResponse::error(format!("signing failed: {e}"))),
    };
    let signed_tx = match signer.encode_signed_transaction(&tx_bytes, &output) {
        Ok(s) => s,
        Err(e) => return Ok(KeyAgentResponse::error(format!("encode signed tx failed: {e}"))),
    };

    audit(
        EventType::SignUserOp,
        Some(&req.session_key_id),
        serde_json::json!({"action": "sign_transaction", "chain_id": req.chain_id}),
    );

    let resp = crate::proto::SignTransactionResponse {
        signature: output.signature,
        signed_tx_hex: hex::encode(&signed_tx),
    };
    Ok(KeyAgentResponse::ok(resp.encode_to_vec()))
}

fn handle_sign_message(
    req: &crate::proto::SignMessageRequest,
) -> Result<KeyAgentResponse, KeyAgentError> {
    // P0-2: Passkey gate — verify authentication before signing.
    let auth = match req.auth.as_ref() {
        Some(a) => a,
        None => return Ok(KeyAgentResponse::error("missing passkey authorization")),
    };
    if let Err(resp) = verify_passkey(auth) {
        return Ok(resp);
    }

    // C1 fix: derive an UnlockToken from the freshly-verified Passkey signature.
    let unlock_token = match oc_core::UnlockToken::new(req.wallet_id.clone(), &auth.signature) {
        Ok(t) => t,
        Err(e) => return Ok(KeyAgentResponse::error(format!("token derivation: {e}"))),
    };

    // SignMessage has no chain_id; default to EVM (ponytail: most common).
    let (signature, _address, _public_key) =
        match sign_message_core(&req.wallet_id, "eip155:1", &unlock_token, &req.message) {
            Ok(v) => v,
            Err(e) => return Ok(KeyAgentResponse::error(e)),
        };

    let resp = crate::proto::SignMessageResponse { signature };
    Ok(KeyAgentResponse::ok(resp.encode_to_vec()))
}

/// Shared message-signing core used by the passkey-gated `SignMessage` and
/// the approval-gated `SignAuth` paths.
///
/// Loads the chain key for `wallet_id`/`chain_id`, signs the raw `message`
/// bytes with the chain's message-signing convention (`signer.sign_message`:
/// EVM EIP-191 personal_sign, Solana raw bytes ed25519, …), and derives the
/// chain-standard account address. Returns `(signature, address, public_key)`.
///
/// This is the single signing path for message signing — callers MUST NOT
/// duplicate it. Authorization (passkey vs. network-layer) is decided by the
/// caller before the unlock token is produced.
fn sign_message_core(
    wallet_id: &str,
    chain_id: &str,
    unlock_token: &oc_core::UnlockToken,
    message: &[u8],
) -> Result<(Vec<u8>, String, Vec<u8>), String> {
    let (key, signer) = load_chain_key(wallet_id, chain_id, unlock_token)?;
    let output =
        signer.sign_message(key.expose(), message).map_err(|e| format!("signing failed: {e}"))?;
    let address =
        signer.derive_address(key.expose()).map_err(|e| format!("address derivation: {e}"))?;
    let public_key = output
        .public_key
        .clone()
        .unwrap_or_else(|| derive_public_key(signer.curve(), key.expose()).unwrap_or_default());
    Ok((output.signature, address, public_key))
}

/// Derive raw public key bytes from a private key when the signer did not
/// populate `SignOutput::public_key` (EVM-family chains).
///
/// Returns 33-byte compressed secp256k1 keys and 32-byte ed25519 keys, or
/// `None` if the private key cannot be parsed.
fn derive_public_key(curve: oc_signer::Curve, private_key: &[u8]) -> Option<Vec<u8>> {
    match curve {
        oc_signer::Curve::Secp256k1 => {
            let sk = k256::ecdsa::SigningKey::from_slice(private_key).ok()?;
            Some(sk.verifying_key().to_sec1_point(true).as_bytes().to_vec())
        }
        oc_signer::Curve::Ed25519 => {
            let bytes: [u8; 32] = private_key.get(..32)?.try_into().ok()?;
            let sk = ed25519_dalek::SigningKey::from_bytes(&bytes);
            Some(sk.verifying_key().to_bytes().to_vec())
        }
    }
}

/// Handle `SignAuth` — auth-class message signing with explicit authorization.
fn handle_sign_auth(
    req: &crate::proto::SignAuthRequest,
) -> Result<KeyAgentResponse, KeyAgentError> {
    if req.wallet_id.is_empty() {
        return Ok(KeyAgentResponse::error("missing wallet_id"));
    }
    if req.chain_id.is_empty() {
        return Ok(KeyAgentResponse::error("missing chain_id"));
    }

    let unlock_token = if let Some(auth) = &req.auth {
        if !req.agent_token.is_empty() {
            return Ok(KeyAgentResponse::error(
                "sign_auth request must carry either auth or agent_token, not both",
            ));
        }
        let stored = match verify_passkey(auth) {
            Ok(stored) => stored,
            Err(resp) => return Ok(resp),
        };
        if !stored.wallet_id.is_empty() && stored.wallet_id != req.wallet_id {
            return Ok(KeyAgentResponse::error("passkey is not registered for this wallet"));
        }
        match oc_core::UnlockToken::new(req.wallet_id.clone(), &auth.signature) {
            Ok(token) => token,
            Err(e) => return Ok(KeyAgentResponse::error(format!("token derivation: {e}"))),
        }
    } else {
        let configured = match sign_auth_internal_token().lock() {
            Ok(guard) => guard.clone(),
            Err(_) => return Ok(KeyAgentResponse::error("sign_auth internal token mutex poisoned")),
        };
        let Some(expected) = configured else {
            return Ok(KeyAgentResponse::error("sign_auth internal token not configured"));
        };
        if req.agent_token.is_empty() {
            return Ok(KeyAgentResponse::deny(crate::proto::DenyReason::PasskeyForged));
        }
        if req.agent_token != expected {
            audit(
                EventType::PasskeyForged,
                None,
                serde_json::json!({"action": "sign_auth_internal_token_mismatch", "wallet_id": req.wallet_id}),
            );
            return Ok(KeyAgentResponse::deny(crate::proto::DenyReason::PasskeyForged));
        }
        let store = DeviceKeyStore::open_default()
            .map_err(|e| KeyAgentError::Internal(format!("device key store: {e}")))?;
        let device_key = store
            .load_or_generate()
            .map_err(|e| KeyAgentError::Internal(format!("device key: {e}")))?;
        match oc_core::UnlockToken::new(req.wallet_id.clone(), &device_key.to_bytes()) {
            Ok(token) => token,
            Err(e) => return Ok(KeyAgentResponse::error(format!("token derivation: {e}"))),
        }
    };

    let (signature, address, public_key) =
        match sign_message_core(&req.wallet_id, &req.chain_id, &unlock_token, &req.message) {
            Ok(v) => v,
            Err(e) => return Ok(KeyAgentResponse::error(e)),
        };

    audit(
        EventType::SignUserOp, // closest existing variant — auth-class signing
        None,
        serde_json::json!({
            "action": "sign_auth",
            "chain_id": req.chain_id,
            "wallet_id": req.wallet_id,
            "mode": if req.auth.is_some() { "passkey" } else { "internal_token" }
        }),
    );

    let resp = crate::proto::SignAuthResponse {
        signature,
        address,
        chain_id: req.chain_id.clone(),
        public_key,
    };
    Ok(KeyAgentResponse::ok(resp.encode_to_vec()))
}

fn handle_sign_typed_data(
    req: &crate::proto::SignTypedDataRequest,
) -> Result<KeyAgentResponse, KeyAgentError> {
    // P0-2: Passkey gate — verify authentication before signing.
    let auth = match req.auth.as_ref() {
        Some(a) => a,
        None => return Ok(KeyAgentResponse::error("missing passkey authorization")),
    };
    if let Err(resp) = verify_passkey(auth) {
        return Ok(resp);
    }

    // C1 fix: derive an UnlockToken from the freshly-verified Passkey signature.
    let unlock_token = match oc_core::UnlockToken::new(req.wallet_id.clone(), &auth.signature) {
        Ok(t) => t,
        Err(e) => return Ok(KeyAgentResponse::error(format!("token derivation: {e}"))),
    };

    // EIP-712 typed data is EVM-only.
    let (key, _) = match load_chain_key(&req.wallet_id, "eip155:1", &unlock_token) {
        Ok(v) => v,
        Err(e) => return Ok(KeyAgentResponse::error(e)),
    };

    let evm_signer = oc_signer::chains::EvmSigner;
    let output = match evm_signer.sign_typed_data(key.expose(), &req.typed_data_json) {
        Ok(o) => o,
        Err(e) => return Ok(KeyAgentResponse::error(format!("signing failed: {e}"))),
    };

    let resp = crate::proto::SignTypedDataResponse { signature: output.signature };
    Ok(KeyAgentResponse::ok(resp.encode_to_vec()))
}

fn handle_sign_user_op(
    req: &crate::proto::SignUserOpRequest,
) -> Result<KeyAgentResponse, KeyAgentError> {
    // P0-2: Passkey gate — verify authentication before signing.
    let auth = match req.auth.as_ref() {
        Some(a) => a,
        None => return Ok(KeyAgentResponse::error("missing passkey authorization")),
    };
    if let Err(resp) = verify_passkey(auth) {
        return Ok(resp);
    }

    // C1 fix: derive an UnlockToken from the freshly-verified Passkey signature.
    let unlock_token = match oc_core::UnlockToken::new(req.wallet_id.clone(), &auth.signature) {
        Ok(t) => t,
        Err(e) => return Ok(KeyAgentResponse::error(format!("token derivation: {e}"))),
    };
    let (key, signer) = match load_chain_key(&req.wallet_id, &req.chain_id, &unlock_token) {
        Ok(v) => v,
        Err(e) => return Ok(KeyAgentResponse::error(e)),
    };

    let user_op_bytes = match hex::decode(&req.user_op_hex) {
        Ok(b) => b,
        Err(e) => return Ok(KeyAgentResponse::error(format!("invalid user op hex: {e}"))),
    };

    let signable = match signer.extract_signable_bytes(&user_op_bytes) {
        Ok(b) => b.to_vec(),
        Err(e) => return Ok(KeyAgentResponse::error(format!("extract signable failed: {e}"))),
    };
    let output = match signer.sign_transaction(key.expose(), &signable) {
        Ok(o) => o,
        Err(e) => return Ok(KeyAgentResponse::error(format!("signing failed: {e}"))),
    };
    let signed_user_op = match signer.encode_signed_transaction(&user_op_bytes, &output) {
        Ok(s) => s,
        Err(e) => return Ok(KeyAgentResponse::error(format!("encode failed: {e}"))),
    };

    audit(
        EventType::SignUserOp,
        Some(&req.session_key_id),
        serde_json::json!({"action": "sign_user_op", "chain_id": req.chain_id}),
    );

    let resp = crate::proto::SignUserOpResponse {
        signature: output.signature,
        signed_user_op_hex: hex::encode(&signed_user_op),
    };
    Ok(KeyAgentResponse::ok(resp.encode_to_vec()))
}

fn handle_create_session_key(
    req: &crate::proto::CreateSessionKeyRequest,
) -> Result<KeyAgentResponse, KeyAgentError> {
    // Stage 0: verify PasskeyAuthorization (R30/R31/C-05).
    let auth = match req.auth.as_ref() {
        Some(a) => a,
        None => return Ok(KeyAgentResponse::error("missing passkey authorization")),
    };
    if let Err(resp) = verify_passkey(auth) {
        return Ok(resp);
    }

    let session_key_id = format!("sk-{}", rand::random::<u64>());
    let created_at = now_unix();

    let proto_policy = req.rules.clone().unwrap_or_else(|| crate::proto::Policy {
        version: 2,
        session_key_id: session_key_id.clone(),
        device_id: "keyagent".to_string(),
        rules: None,
        budget_allocation: None,
    });

    audit(
        EventType::CreateSessionKey,
        Some(&session_key_id),
        serde_json::json!({"label": req.label, "status": "ALLOWED"}),
    );

    let resp = crate::proto::CreateSessionKeyResponse {
        session_key_id,
        created_at_unix: created_at,
        policy: Some(proto_policy),
    };
    Ok(KeyAgentResponse::ok(resp.encode_to_vec()))
}

fn handle_revoke_session_key(
    req: &crate::proto::RevokeSessionKeyRequest,
) -> Result<KeyAgentResponse, KeyAgentError> {
    // Stage 0: verify PasskeyAuthorization (R30/R31/C-05).
    let auth = match req.auth.as_ref() {
        Some(a) => a,
        None => return Ok(KeyAgentResponse::error("missing passkey authorization")),
    };
    if let Err(resp) = verify_passkey(auth) {
        return Ok(resp);
    }

    let revoked_at = now_unix();

    audit(
        EventType::RevokeSessionKey,
        Some(&req.session_key_id),
        serde_json::json!({"status": "ALLOWED", "revoked_at_unix": revoked_at}),
    );

    let resp = crate::proto::RevokeSessionKeyResponse { revoked_at_unix: revoked_at };
    Ok(KeyAgentResponse::ok(resp.encode_to_vec()))
}

fn handle_lock_vault() -> Result<KeyAgentResponse, KeyAgentError> {
    global_key_cache().clear();
    // Also drop any in-flight Passkey challenge state so a lock cannot be
    // followed by a replay of a previously-issued challenge (L1 fix).
    global_passkey_verifiers()
        .lock()
        .map_err(|_| KeyAgentError::Internal("passkey verifiers mutex poisoned".into()))?
        .clear();

    audit(
        EventType::BudgetReclaim, // ponytail: closest existing variant; add LOCK_VAULT if needed
        None,
        serde_json::json!({"action": "lock_vault", "cache_cleared": true}),
    );

    let resp = crate::proto::LockVaultResponse { locked: true };
    Ok(KeyAgentResponse::ok(resp.encode_to_vec()))
}

fn handle_unlock_vault(
    req: &crate::proto::UnlockVaultRequest,
) -> Result<KeyAgentResponse, KeyAgentError> {
    // 1. Verify Passkey.
    let auth = match req.auth.as_ref() {
        Some(a) => a,
        None => return Ok(KeyAgentResponse::error("missing passkey authorization")),
    };

    let stored = match verify_passkey(auth) {
        Ok(s) => s,
        Err(resp) => return Ok(resp),
    };

    // 2. Verify passkey is bound to the requested wallet.
    if stored.wallet_id != req.wallet_id {
        return Ok(KeyAgentResponse::error("passkey not bound to this wallet"));
    }

    // 3. Issue UnlockToken (30-second TTL, derived from Passkey signature).
    let token = match oc_core::UnlockToken::new(req.wallet_id.clone(), &auth.signature) {
        Ok(t) => t,
        Err(e) => return Ok(KeyAgentResponse::error(format!("token generation: {e}"))),
    };

    let expires_at = now_unix() + oc_core::UnlockToken::DEFAULT_TTL.as_secs();

    let resp = crate::proto::UnlockVaultResponse {
        unlock_token: token.key_bytes().to_vec(),
        expires_at_unix: expires_at,
    };
    Ok(KeyAgentResponse::ok(resp.encode_to_vec()))
}

fn handle_register_passkey(
    req: &crate::proto::RegisterPasskeyRequest,
) -> Result<KeyAgentResponse, KeyAgentError> {
    let mut store = match PasskeyPubkeyStore::open_default() {
        Ok(s) => s,
        Err(e) => return Ok(KeyAgentResponse::error(format!("passkey store: {e}"))),
    };

    let stored = StoredPasskeyPubkey {
        algorithm: req.algorithm.clone(),
        public_key: req.public_key.clone(),
        wallet_id: req.wallet_id.clone(),
        registered_at: now_unix(),
    };

    if let Err(e) = store.register(&req.credential_id, stored) {
        return Ok(KeyAgentResponse::error(format!("register passkey: {e}")));
    }

    let resp = crate::proto::RegisterPasskeyResponse { registered: true };
    Ok(KeyAgentResponse::ok(resp.encode_to_vec()))
}

/// P0-2: Issue a fresh 32-byte Passkey challenge nonce for the given
/// `credential_id`.
///
/// The nonce is stored in the process-wide [`GLOBAL_PASSKEY_VERIFIERS`] map
/// (inside the `PasskeyVerifier` bound to this `credential_id`). The client
/// MUST sign `challenge || credential_id` with the Passkey private key and
/// return the resulting `PasskeyAuthorization` in the subsequent signing
/// RPC. [`verify_passkey`] consumes the challenge from the same shared
/// verifier, providing single-use replay protection.
fn handle_generate_challenge(
    req: &crate::proto::GenerateChallengeRequest,
) -> Result<KeyAgentResponse, KeyAgentError> {
    if req.credential_id.is_empty() {
        return Ok(KeyAgentResponse::error("missing credential_id"));
    }

    let store = match PasskeyPubkeyStore::open_default() {
        Ok(s) => s,
        Err(e) => return Ok(KeyAgentResponse::error(format!("passkey store: {e}"))),
    };
    let stored = match store.get(&req.credential_id) {
        Some(s) => s,
        None => return Ok(KeyAgentResponse::error("passkey not registered")),
    };

    let verifiers_map = global_passkey_verifiers();
    let mut verifiers = match verifiers_map.lock() {
        Ok(v) => v,
        Err(_) => return Ok(KeyAgentResponse::error("passkey verifiers mutex poisoned")),
    };

    // Lazily create the verifier bound to this credential_id on first
    // challenge issuance. Subsequent GenerateChallenge / verify_passkey calls
    // reuse the same instance so pending_challenges is shared.
    if !verifiers.contains_key(&req.credential_id) {
        let pubkey = match PasskeyPubkeyStore::to_passkey_pubkey(&stored) {
            Ok(k) => k,
            Err(e) => return Ok(KeyAgentResponse::error(format!("passkey pubkey: {e}"))),
        };
        verifiers.insert(
            req.credential_id.clone(),
            PasskeyVerifier::new(pubkey, req.credential_id.as_bytes().to_vec()),
        );
    }
    let verifier = verifiers
        .get_mut(&req.credential_id)
        .ok_or_else(|| KeyAgentError::Unauthorized("passkey verifier evicted".into()))?;

    let challenge = verifier.generate_challenge();

    audit(
        EventType::PasskeyForged, // closest existing variant — records challenge issuance
        None,
        serde_json::json!({"action": "generate_challenge", "credential_id": req.credential_id}),
    );

    let resp = crate::proto::GenerateChallengeResponse { challenge: challenge.to_vec() };
    Ok(KeyAgentResponse::ok(resp.encode_to_vec()))
}

/// Default number of telemetry records returned when the caller passes `0`.
///
/// Sized so a full batch stays comfortably inside
/// [`crate::frame::MAX_FRAME_SIZE`] (4 MiB): a record with the maximum number
/// of allowlisted fields serializes to well under 4 KiB, so 512 records is
/// ~2 MiB worst case.
const DEFAULT_TELEMETRY_DRAIN: u32 = 512;

/// Upper bound on a single drain, regardless of what the caller asks for.
const MAX_TELEMETRY_DRAIN: u32 = 1024;

/// P1 3.1: Hand the Network-Agent a batch of buffered telemetry records.
///
/// The Key-Agent is deliberately export-blind — it has no tokio, no HTTP
/// client and no OTLP exporter (R56), and its seccomp/Seatbelt profile denies
/// every non-UDS socket (R12). So instead of pushing spans out, it buffers
/// them in a bounded ring ([`crate::telemetry`]) and lets the Network-Agent —
/// which already holds this UDS connection and may link an exporter — pull
/// them.
///
/// Field values are redacted at *record* time, not here: only names in
/// `telemetry::SAFE_FIELDS` keep their value, everything else is stored as
/// `<redacted>`. That makes this RPC safe to serve without Passkey
/// authorization.
fn handle_drain_telemetry(
    req: crate::proto::DrainTelemetryRequest,
) -> Result<KeyAgentResponse, KeyAgentError> {
    let max = match req.max_records {
        0 => DEFAULT_TELEMETRY_DRAIN,
        n => n.min(MAX_TELEMETRY_DRAIN),
    };

    let batch = crate::telemetry::drain(max as usize);
    let record_count = u32::try_from(batch.records.len()).unwrap_or(u32::MAX);
    let dropped = batch.dropped;

    let batch_json = match serde_json::to_string(&batch) {
        Ok(j) => j,
        Err(e) => return Ok(KeyAgentResponse::error(format!("telemetry encode: {e}"))),
    };

    let resp = crate::proto::DrainTelemetryResponse { batch_json, record_count, dropped };
    Ok(KeyAgentResponse::ok(resp.encode_to_vec()))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        proto::Empty,
        request::{KeyAgentRequest, KeyAgentRequestKind},
        response::KeyAgentResponseKind,
    };

    fn dispatch_req(req_kind: KeyAgentRequestKind) -> KeyAgentResponse {
        let req = KeyAgentRequest { kind: Some(req_kind) };
        dispatch(&req).expect("dispatch should return Ok(...)")
    }

    #[test]
    fn test_list_wallets_returns_ok() {
        let resp = dispatch_req(KeyAgentRequestKind::ListWallets(Empty {}));
        match &resp.kind {
            Some(KeyAgentResponseKind::Ok(bytes)) => {
                let decoded: crate::proto::ListWalletsResponse =
                    prost::Message::decode(bytes.as_slice()).unwrap();
                let _ = decoded.wallets.len();
            }
            Some(KeyAgentResponseKind::Error(_)) => {
                // Acceptable: vault dir doesn't exist in test env.
            }
            _ => panic!("unexpected response: {resp:?}"),
        }
    }

    #[test]
    fn test_sign_transaction_missing_wallet_returns_error() {
        let resp = dispatch_req(KeyAgentRequestKind::SignTransaction(
            crate::proto::SignTransactionRequest {
                session_key_id: "sk-1".to_string(),
                wallet_id: "nonexistent-wallet".to_string(),
                chain_id: "eip155:1".to_string(),
                raw_tx_hex: "deadbeef".to_string(),
                auth: None,
            },
        ));
        // P0-2: with auth=None, the Passkey gate rejects before reaching
        // load_chain_key. Either error path satisfies this smoke test.
        assert!(resp.is_error(), "expected error for missing auth / wallet");
    }

    #[test]
    fn test_sign_message_missing_wallet_returns_error() {
        let resp =
            dispatch_req(KeyAgentRequestKind::SignMessage(crate::proto::SignMessageRequest {
                session_key_id: "sk-1".to_string(),
                wallet_id: "nonexistent-wallet".to_string(),
                message: b"hello".to_vec(),
                auth: None,
            }));
        assert!(resp.is_error(), "expected error for missing auth / wallet");
    }

    #[test]
    fn test_sign_auth_missing_wallet_returns_error() {
        // SignAuth has NO passkey gate — the error must come from the
        // wallet/chain validation (empty wallet_id short-circuits first).
        let resp = dispatch_req(KeyAgentRequestKind::SignAuth(crate::proto::SignAuthRequest {
            wallet_id: String::new(),
            chain_id: "eip155:1".to_string(),
            message: b"sign in".to_vec(),
            auth: None,
            agent_token: Vec::new(),
        }));
        assert!(resp.is_error(), "expected error for missing wallet_id");
        match &resp.kind {
            Some(KeyAgentResponseKind::Error(msg)) => assert!(msg.contains("wallet_id")),
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn test_sign_typed_data_missing_wallet_returns_error() {
        let resp =
            dispatch_req(KeyAgentRequestKind::SignTypedData(crate::proto::SignTypedDataRequest {
                session_key_id: "sk-1".to_string(),
                wallet_id: "nonexistent-wallet".to_string(),
                typed_data_json: "{}".to_string(),
                auth: None,
            }));
        assert!(resp.is_error(), "expected error for missing auth / wallet");
    }

    #[test]
    fn test_sign_user_op_missing_wallet_returns_error() {
        let resp = dispatch_req(KeyAgentRequestKind::SignUserOp(crate::proto::SignUserOpRequest {
            session_key_id: "sk-1".to_string(),
            wallet_id: "nonexistent-wallet".to_string(),
            chain_id: "eip155:1".to_string(),
            user_op_hex: "deadbeef".to_string(),
            auth: None,
        }));
        assert!(resp.is_error(), "expected error for missing auth / wallet");
    }

    #[test]
    fn test_create_session_key_missing_auth_returns_error() {
        // Stage 0: auth is now required — missing auth must be rejected.
        let resp = dispatch_req(KeyAgentRequestKind::CreateSessionKey(
            crate::proto::CreateSessionKeyRequest {
                label: "test-key".to_string(),
                rules: None,
                budget: None,
                auth: None,
            },
        ));
        assert!(resp.is_error(), "CreateSessionKey without auth should be rejected");
    }

    #[test]
    fn test_revoke_session_key_missing_auth_returns_error() {
        // Stage 0: auth is now required — missing auth must be rejected.
        let resp = dispatch_req(KeyAgentRequestKind::RevokeSessionKey(
            crate::proto::RevokeSessionKeyRequest {
                session_key_id: "sk-test".to_string(),
                auth: None,
            },
        ));
        assert!(resp.is_error(), "RevokeSessionKey without auth should be rejected");
    }

    #[test]
    fn test_get_balance_returns_not_implemented() {
        let resp = dispatch_req(KeyAgentRequestKind::GetBalance(crate::proto::GetBalanceRequest {
            wallet_id: "w1".to_string(),
            chain_id: "eip155:1".to_string(),
        }));
        assert!(resp.is_error());
    }

    #[test]
    fn test_lock_vault_returns_ok() {
        let resp = dispatch_req(KeyAgentRequestKind::LockVault(Empty {}));
        assert!(!resp.is_error(), "LockVault should succeed");
        match &resp.kind {
            Some(KeyAgentResponseKind::Ok(bytes)) => {
                let decoded: crate::proto::LockVaultResponse =
                    prost::Message::decode(bytes.as_slice()).unwrap();
                assert!(decoded.locked);
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[test]
    fn test_empty_request_returns_error() {
        let req = KeyAgentRequest { kind: None };
        let result = dispatch(&req);
        assert!(matches!(result, Err(KeyAgentError::InvalidRequest(_))));
    }

    #[test]
    fn test_all_variants_dispatch_without_panic() {
        let cases: Vec<KeyAgentRequestKind> = vec![
            KeyAgentRequestKind::CreateSessionKey(crate::proto::CreateSessionKeyRequest {
                label: "x".to_string(),
                rules: None,
                budget: None,
                auth: None,
            }),
            KeyAgentRequestKind::RevokeSessionKey(crate::proto::RevokeSessionKeyRequest {
                session_key_id: "x".to_string(),
                auth: None,
            }),
            KeyAgentRequestKind::SignTransaction(crate::proto::SignTransactionRequest {
                session_key_id: "x".to_string(),
                wallet_id: "x".to_string(),
                chain_id: "x".to_string(),
                raw_tx_hex: "x".to_string(),
                auth: None,
            }),
            KeyAgentRequestKind::SignUserOp(crate::proto::SignUserOpRequest {
                session_key_id: "x".to_string(),
                wallet_id: "x".to_string(),
                chain_id: "x".to_string(),
                user_op_hex: "x".to_string(),
                auth: None,
            }),
            KeyAgentRequestKind::SignMessage(crate::proto::SignMessageRequest {
                session_key_id: "x".to_string(),
                wallet_id: "x".to_string(),
                message: vec![],
                auth: None,
            }),
            KeyAgentRequestKind::SignAuth(crate::proto::SignAuthRequest {
                wallet_id: "x".to_string(),
                chain_id: "x".to_string(),
                message: vec![],
                auth: None,
                agent_token: Vec::new(),
            }),
            KeyAgentRequestKind::SignTypedData(crate::proto::SignTypedDataRequest {
                session_key_id: "x".to_string(),
                wallet_id: "x".to_string(),
                typed_data_json: "x".to_string(),
                auth: None,
            }),
            KeyAgentRequestKind::GetBalance(crate::proto::GetBalanceRequest {
                wallet_id: "x".to_string(),
                chain_id: "x".to_string(),
            }),
            KeyAgentRequestKind::ListWallets(Empty {}),
            KeyAgentRequestKind::LockVault(Empty {}),
            // Stage 0 variant (Fix 7): UnlockVault.
            // auth=None short-circuits to an error response (no I/O, no panic).
            // RegisterPasskey is intentionally excluded — its handler writes to
            // the real ~/.onecipher/passkeys.json store, which would pollute
            // the user's passkey registry. It needs an isolated test with a
            // temp-dir store (out of scope for this dispatch smoke test).
            KeyAgentRequestKind::UnlockVault(crate::proto::UnlockVaultRequest {
                wallet_id: "x".to_string(),
                auth: None,
            }),
            // Phase 6 secret variants — R56 returns "not implemented" (no panic).
            KeyAgentRequestKind::GetSecret(crate::proto::GetSecretRequest {
                name: "x".to_string(),
                api_token: "x".to_string(),
            }),
            KeyAgentRequestKind::ListSecrets(crate::proto::ListSecretsRequest {
                api_token: "x".to_string(),
            }),
            KeyAgentRequestKind::GenerateTotp(crate::proto::GenerateTotpRequest {
                name: "x".to_string(),
                api_token: "x".to_string(),
            }),
        ];
        for (i, kind) in cases.into_iter().enumerate() {
            let req = KeyAgentRequest { kind: Some(kind) };
            let resp = dispatch(&req).unwrap_or_else(|e| panic!("dispatch[{i}] err: {e:?}"));
            let _ = resp;
        }
    }

    // -----------------------------------------------------------------------
    // P1 3.1 — DrainTelemetry
    // -----------------------------------------------------------------------

    /// Run `body` with exclusive access to the global telemetry buffer, left
    /// enabled and empty on entry and restored on exit.
    ///
    /// The ring is a process-wide singleton, so these tests share it with
    /// `telemetry`'s own tests — hence the crate-wide lock.
    fn with_exclusive_telemetry<T>(
        body: impl FnOnce(&'static crate::telemetry::TelemetryBuffer) -> T,
    ) -> T {
        let guard = crate::telemetry::TELEMETRY_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let buffer = crate::telemetry::global_buffer();
        let was_enabled = buffer.is_enabled();
        buffer.set_enabled(true);
        // Discard anything an earlier test left behind.
        let _ = crate::telemetry::drain(usize::MAX);

        let out = body(buffer);

        let _ = crate::telemetry::drain(usize::MAX);
        buffer.set_enabled(was_enabled);
        drop(guard);
        out
    }

    fn test_record(seq: u64, name: &str) -> crate::telemetry::TelemetryRecord {
        crate::telemetry::TelemetryRecord {
            seq,
            timestamp_ms: 1_700_000_000_000,
            level: crate::telemetry::TelemetryLevel::Info,
            kind: crate::telemetry::RecordKind::Event,
            target: "oc-keyagent::handler".to_string(),
            name: name.to_string(),
            span_id: None,
            parent_span_id: None,
            duration_ms: None,
            fields: vec![],
        }
    }

    fn drain_via_dispatch(max_records: u32) -> crate::proto::DrainTelemetryResponse {
        let resp = dispatch_req(KeyAgentRequestKind::DrainTelemetry(
            crate::proto::DrainTelemetryRequest { max_records },
        ));
        match &resp.kind {
            Some(KeyAgentResponseKind::Ok(bytes)) => {
                prost::Message::decode(bytes.as_slice()).expect("decode DrainTelemetryResponse")
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[test]
    fn drain_telemetry_dispatches_without_panic() {
        // The counterpart of `test_all_variants_dispatch_without_panic` for
        // the DrainTelemetry variant, kept here so it runs under the
        // telemetry lock instead of stealing records from the other tests.
        with_exclusive_telemetry(|_| {
            let req = KeyAgentRequest {
                kind: Some(KeyAgentRequestKind::DrainTelemetry(
                    crate::proto::DrainTelemetryRequest { max_records: 1 },
                )),
            };
            let resp = dispatch(&req).expect("DrainTelemetry must not error");
            assert!(!resp.is_error());
            assert!(!resp.is_deny());
        });
    }

    #[test]
    fn drain_telemetry_on_an_empty_buffer_is_an_empty_batch() {
        with_exclusive_telemetry(|_| {
            let resp = drain_via_dispatch(16);
            assert_eq!(resp.record_count, 0);
            assert_eq!(resp.dropped, 0);
            let batch: crate::telemetry::TelemetryBatch =
                serde_json::from_str(&resp.batch_json).expect("batch_json is valid JSON");
            assert!(batch.is_empty());
        });
    }

    #[test]
    fn drain_telemetry_returns_buffered_records_and_empties_the_ring() {
        with_exclusive_telemetry(|buffer| {
            for seq in 0..3u64 {
                buffer.push(test_record(seq, "drain_test"));
            }

            let resp = drain_via_dispatch(16);
            assert_eq!(resp.record_count, 3);
            let batch: crate::telemetry::TelemetryBatch =
                serde_json::from_str(&resp.batch_json).expect("batch_json is valid JSON");
            assert_eq!(batch.records.len(), 3);

            // Second drain sees an empty ring — the first call consumed it.
            assert_eq!(drain_via_dispatch(16).record_count, 0);
        });
    }

    #[test]
    fn drain_telemetry_caps_an_oversized_request() {
        with_exclusive_telemetry(|buffer| {
            buffer.push(test_record(0, "cap_test"));
            // Ask for far more than MAX_TELEMETRY_DRAIN: the cap must not
            // panic or overflow, and the buffered record still comes back.
            let resp = drain_via_dispatch(u32::MAX);
            assert_eq!(resp.record_count, 1);
        });
    }

    #[test]
    fn zero_max_records_means_server_default_not_drain_nothing() {
        with_exclusive_telemetry(|buffer| {
            buffer.push(test_record(0, "default_cap"));
            // An un-set proto field decodes to 0; that must NOT be read as
            // "return nothing", otherwise every default-constructed request
            // would silently no-op.
            let resp = drain_via_dispatch(0);
            assert_eq!(resp.record_count, 1);
        });
    }
}
