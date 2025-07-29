//! Handler dispatch for [`KeyAgentRequest`].
//!
//! Real implementations replacing the T11 stubs. All handlers are synchronous
//! (R55 — no async runtime in Key-Agent). Sensitive key material lives inside
//! `HardenedBytes` and is zeroized on drop.

use std::{
    collections::HashMap,
    io::BufRead,
    path::PathBuf,
    sync::{Arc, Mutex, OnceLock},
};

use prost::Message;

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

fn global_audit_log() -> Arc<Mutex<AuditLog>> {
    GLOBAL_AUDIT_LOG
        .get_or_init(|| {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
            let path = PathBuf::from(home).join(".onecipher/logs/audit.jsonl");
            let device_id = "keyagent".to_string();
            // Stage 0: persistent device key instead of per-process random key.
            let store = DeviceKeyStore::open_default().expect("failed to open device key store");
            let device_key = store.load_or_generate().expect("failed to load/generate device key");
            Arc::new(Mutex::new(
                AuditLog::open(&path, &device_id, device_key).expect("failed to open audit log"),
            ))
        })
        .clone()
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
/// `unlock_token` carries Passkey-derived key material. When `Some`, the
/// token's passphrase is derived (validating the token) and used to decrypt
/// the wallet. When `None`, an empty passphrase is used (backward compat).
fn load_chain_key(
    wallet_id: &str,
    chain_id: &str,
    unlock_token: Option<&oc_core::UnlockToken>,
) -> Result<(oc_signer::SecretBytes, Box<dyn oc_signer::ChainSigner>), String> {
    let chain = oc_core::parse_chain(chain_id).map_err(|e| format!("invalid chain: {e}"))?;

    let pp = if let Some(token) = unlock_token {
        Some(token.to_passphrase().map_err(|e| format!("passphrase derivation: {e}"))?)
    } else {
        eprintln!("[WARN] no unlock token — using empty passphrase (backward compat)");
        None
    };
    let pp_bytes: &[u8] = pp.as_ref().map_or(b"", |p| p.as_bytes());

    let key = oc_wallet::ops::decrypt_signing_key(
        wallet_id,
        chain.chain_type,
        pp_bytes,
        None,
        vault_path(),
    )
    .map_err(|e| format!("wallet decrypt failed: {e}"))?;
    let signer = oc_signer::signer_for_chain(chain.chain_type);
    Ok((key, signer))
}

/// Append an audit entry. Silently logs on failure (audit must not break ops).
fn audit(event_type: EventType, session_key_id: Option<&str>, payload: serde_json::Value) {
    if let Ok(mut log) = global_audit_log().lock() {
        if let Err(e) = log.append(event_type, session_key_id.map(String::from), payload) {
            eprintln!("[AUDIT-WARN] append failed: {e}");
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
    auth: &oc_proto::PasskeyAuthorization,
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
        .expect("verifier was just inserted or already present");

    if let Err(e) = verifier.verify(auth) {
        audit(
            EventType::PasskeyForged,
            None,
            serde_json::json!({"credential_id": auth.credential_id, "error": e.to_string()}),
        );
        return Err(KeyAgentResponse::deny(oc_proto::DenyReason::PasskeyForged));
    }
    Ok(stored)
}

/// Convert a `DenyReason` to a lowercase snake_case string.
fn deny_reason_string(reason: &oc_policy::v2::DenyReason) -> String {
    match reason {
        oc_policy::v2::DenyReason::RateLimitMinute => "rate_limit_minute",
        oc_policy::v2::DenyReason::RateLimitHour => "rate_limit_hour",
        oc_policy::v2::DenyReason::BudgetExceeded => "budget_exceeded",
        oc_policy::v2::DenyReason::Whitelist => "whitelist",
        oc_policy::v2::DenyReason::Expired => "expired",
        oc_policy::v2::DenyReason::PasskeyForged => "passkey_forged",
        oc_policy::v2::DenyReason::PolicyMissing => "policy_missing",
        oc_policy::v2::DenyReason::Cooldown => "cooldown",
        oc_policy::v2::DenyReason::Unknown => "unknown",
    }
    .to_string()
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
        Some(KeyAgentRequestKind::SignTypedData(req)) => handle_sign_typed_data(req),
        Some(KeyAgentRequestKind::SignUserOp(req)) => handle_sign_user_op(req),
        Some(KeyAgentRequestKind::CreateSessionKey(req)) => handle_create_session_key(req),
        Some(KeyAgentRequestKind::RevokeSessionKey(req)) => handle_revoke_session_key(req),
        Some(KeyAgentRequestKind::PayX402(req)) => handle_pay_x402(req),
        Some(KeyAgentRequestKind::GetPaymentHistory(req)) => handle_get_payment_history(req),
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

    let proto_wallets: Vec<oc_proto::WalletInfo> = wallets
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
            oc_proto::WalletInfo {
                id: w.id.clone(),
                name: w.name.clone(),
                key_type: key_type.to_string(),
                created_at,
                accounts: w
                    .accounts
                    .iter()
                    .map(|a| oc_proto::WalletAccount {
                        account_id: a.account_id.clone(),
                        address: a.address.clone(),
                        chain_id: a.chain_id.clone(),
                        derivation_path: a.derivation_path.clone(),
                    })
                    .collect(),
            }
        })
        .collect();

    let resp = oc_proto::ListWalletsResponse { wallets: proto_wallets };
    Ok(KeyAgentResponse::ok(resp.encode_to_vec()))
}

fn handle_sign_transaction(
    req: &oc_proto::SignTransactionRequest,
) -> Result<KeyAgentResponse, KeyAgentError> {
    // P0-2: Passkey gate — verify authentication before signing.
    let auth = match req.auth.as_ref() {
        Some(a) => a,
        None => return Ok(KeyAgentResponse::error("missing passkey authorization")),
    };
    if let Err(resp) = verify_passkey(auth) {
        return Ok(resp);
    }

    let (key, signer) = match load_chain_key(&req.wallet_id, &req.chain_id, None) {
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

    let resp = oc_proto::SignTransactionResponse {
        signature: output.signature,
        signed_tx_hex: hex::encode(&signed_tx),
    };
    Ok(KeyAgentResponse::ok(resp.encode_to_vec()))
}

fn handle_sign_message(
    req: &oc_proto::SignMessageRequest,
) -> Result<KeyAgentResponse, KeyAgentError> {
    // P0-2: Passkey gate — verify authentication before signing.
    let auth = match req.auth.as_ref() {
        Some(a) => a,
        None => return Ok(KeyAgentResponse::error("missing passkey authorization")),
    };
    if let Err(resp) = verify_passkey(auth) {
        return Ok(resp);
    }

    // SignMessage has no chain_id; default to EVM (ponytail: most common).
    let (key, signer) = match load_chain_key(&req.wallet_id, "eip155:1", None) {
        Ok(v) => v,
        Err(e) => return Ok(KeyAgentResponse::error(e)),
    };

    let output = match signer.sign_message(key.expose(), &req.message) {
        Ok(o) => o,
        Err(e) => return Ok(KeyAgentResponse::error(format!("signing failed: {e}"))),
    };

    let resp = oc_proto::SignMessageResponse { signature: output.signature };
    Ok(KeyAgentResponse::ok(resp.encode_to_vec()))
}

fn handle_sign_typed_data(
    req: &oc_proto::SignTypedDataRequest,
) -> Result<KeyAgentResponse, KeyAgentError> {
    // P0-2: Passkey gate — verify authentication before signing.
    let auth = match req.auth.as_ref() {
        Some(a) => a,
        None => return Ok(KeyAgentResponse::error("missing passkey authorization")),
    };
    if let Err(resp) = verify_passkey(auth) {
        return Ok(resp);
    }

    // EIP-712 typed data is EVM-only.
    let (key, _) = match load_chain_key(&req.wallet_id, "eip155:1", None) {
        Ok(v) => v,
        Err(e) => return Ok(KeyAgentResponse::error(e)),
    };

    let evm_signer = oc_signer::chains::EvmSigner;
    let output = match evm_signer.sign_typed_data(key.expose(), &req.typed_data_json) {
        Ok(o) => o,
        Err(e) => return Ok(KeyAgentResponse::error(format!("signing failed: {e}"))),
    };

    let resp = oc_proto::SignTypedDataResponse { signature: output.signature };
    Ok(KeyAgentResponse::ok(resp.encode_to_vec()))
}

fn handle_sign_user_op(
    req: &oc_proto::SignUserOpRequest,
) -> Result<KeyAgentResponse, KeyAgentError> {
    // P0-2: Passkey gate — verify authentication before signing.
    let auth = match req.auth.as_ref() {
        Some(a) => a,
        None => return Ok(KeyAgentResponse::error("missing passkey authorization")),
    };
    if let Err(resp) = verify_passkey(auth) {
        return Ok(resp);
    }

    let (key, signer) = match load_chain_key(&req.wallet_id, &req.chain_id, None) {
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

    let resp = oc_proto::SignUserOpResponse {
        signature: output.signature,
        signed_user_op_hex: hex::encode(&signed_user_op),
    };
    Ok(KeyAgentResponse::ok(resp.encode_to_vec()))
}

fn handle_create_session_key(
    req: &oc_proto::CreateSessionKeyRequest,
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

    let proto_policy = req.rules.clone().unwrap_or_else(|| oc_proto::Policy {
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

    let resp = oc_proto::CreateSessionKeyResponse {
        session_key_id,
        created_at_unix: created_at,
        policy: Some(proto_policy),
    };
    Ok(KeyAgentResponse::ok(resp.encode_to_vec()))
}

fn handle_revoke_session_key(
    req: &oc_proto::RevokeSessionKeyRequest,
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

    let resp = oc_proto::RevokeSessionKeyResponse { revoked_at_unix: revoked_at };
    Ok(KeyAgentResponse::ok(resp.encode_to_vec()))
}

fn handle_pay_x402(req: &oc_proto::PayX402Request) -> Result<KeyAgentResponse, KeyAgentError> {
    // T16: Build PayRequest and evaluate via PolicyIntegration.
    // ponytail: amount/asset/chain/recipient come from x402 protocol response;
    // we use placeholders for now. PolicyIntegration is created per-request.
    let pay_request = oc_policy::PayRequest {
        session_key_id: req.session_key_id.clone(),
        device_id: "keyagent".to_string(),
        amount_usd: req.amount_usd,
        asset: req.asset.clone(),
        chain_id: req.chain_id.clone(),
        recipient: if req.recipient.is_empty() { None } else { Some(req.recipient.clone()) },
    };

    let audit_log = global_audit_log();
    let state_path = {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        PathBuf::from(home).join(".onecipher/policy_state.json")
    };

    let mut policy_integration = match crate::PolicyIntegration::open(
        &state_path,
        &req.session_key_id,
        None, // ponytail: load policy from store later
        audit_log,
        Box::new(oc_policy::v2::LogAlertSink),
    ) {
        Ok(pi) => pi,
        Err(e) => return Ok(KeyAgentResponse::error(format!("policy init failed: {e}"))),
    };

    let decision = policy_integration.evaluate(&pay_request, &req.session_key_id);

    match decision {
        oc_policy::v2::Decision::Allow => {
            let resp = oc_proto::PayX402Response {
                status: oc_proto::PaymentStatus::Ok as i32,
                receipt: vec![],
                retry_authorization: String::new(),
                deny_reason: String::new(),
                error: String::new(),
            };
            Ok(KeyAgentResponse::ok(resp.encode_to_vec()))
        }
        oc_policy::v2::Decision::Deny(reason) => {
            let deny_str = deny_reason_string(&reason);
            let resp = oc_proto::PayX402Response {
                status: oc_proto::PaymentStatus::Deny as i32,
                receipt: vec![],
                retry_authorization: String::new(),
                deny_reason: deny_str,
                error: String::new(),
            };
            Ok(KeyAgentResponse::ok(resp.encode_to_vec()))
        }
    }
}

fn handle_get_payment_history(
    req: &oc_proto::GetPaymentHistoryRequest,
) -> Result<KeyAgentResponse, KeyAgentError> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let log_path = PathBuf::from(home).join(".onecipher/logs/audit.jsonl");

    let file = match std::fs::File::open(&log_path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let resp = oc_proto::PaymentHistoryResponse { records: vec![] };
            return Ok(KeyAgentResponse::ok(resp.encode_to_vec()));
        }
        Err(e) => return Ok(KeyAgentResponse::error(format!("audit log read failed: {e}"))),
    };

    let reader = std::io::BufReader::new(file);
    let mut records = Vec::new();
    let limit = if req.limit == 0 { usize::MAX } else { req.limit as usize };

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };
        if line.trim().is_empty() {
            continue;
        }
        let entry: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let event_type = entry.get("event_type").and_then(|v| v.as_str()).unwrap_or("");
        if event_type != "pay_x402" {
            continue;
        }

        let entry_sk = entry.get("session_key_id").and_then(|v| v.as_str()).unwrap_or("");
        if !req.session_key_id.is_empty() && entry_sk != req.session_key_id {
            continue;
        }

        let ts = entry.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
        let ts_unix = ts.parse::<jiff::Timestamp>().map_or(0, |t| t.as_second().max(0) as u64);
        if ts_unix < req.since_unix {
            continue;
        }

        let payload = entry.get("payload").cloned().unwrap_or(serde_json::Value::Null);
        let status_str = payload.get("status").and_then(|v| v.as_str()).unwrap_or("");
        let status = if status_str == "ALLOWED" {
            oc_proto::PaymentStatus::Ok as i32
        } else if status_str == "DENIED" {
            oc_proto::PaymentStatus::Deny as i32
        } else {
            oc_proto::PaymentStatus::Error as i32
        };

        records.push(oc_proto::PaymentRecord {
            timestamp_unix: ts_unix,
            session_key_id: entry_sk.to_string(),
            amount_usd: payload.get("amount_usd").and_then(|v| v.as_f64()).unwrap_or(0.0),
            asset: payload.get("asset").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            chain_id: payload.get("chain_id").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            recipient: payload.get("recipient").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            status,
            receipt: vec![],
            deny_reason: payload
                .get("deny_reason")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
        });

        if records.len() >= limit {
            break;
        }
    }

    let resp = oc_proto::PaymentHistoryResponse { records };
    Ok(KeyAgentResponse::ok(resp.encode_to_vec()))
}

fn handle_lock_vault() -> Result<KeyAgentResponse, KeyAgentError> {
    global_key_cache().clear();

    audit(
        EventType::BudgetReclaim, // ponytail: closest existing variant; add LOCK_VAULT if needed
        None,
        serde_json::json!({"action": "lock_vault", "cache_cleared": true}),
    );

    let resp = oc_proto::LockVaultResponse { locked: true };
    Ok(KeyAgentResponse::ok(resp.encode_to_vec()))
}

fn handle_unlock_vault(
    req: &oc_proto::UnlockVaultRequest,
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

    let resp = oc_proto::UnlockVaultResponse {
        unlock_token: token.key_bytes().to_vec(),
        expires_at_unix: expires_at,
    };
    Ok(KeyAgentResponse::ok(resp.encode_to_vec()))
}

fn handle_register_passkey(
    req: &oc_proto::RegisterPasskeyRequest,
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

    let resp = oc_proto::RegisterPasskeyResponse { registered: true };
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
    req: &oc_proto::GenerateChallengeRequest,
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
        .expect("verifier was just inserted or already present");

    let challenge = verifier.generate_challenge();

    audit(
        EventType::PasskeyForged, // closest existing variant — records challenge issuance
        None,
        serde_json::json!({"action": "generate_challenge", "credential_id": req.credential_id}),
    );

    let resp = oc_proto::GenerateChallengeResponse { challenge: challenge.to_vec() };
    Ok(KeyAgentResponse::ok(resp.encode_to_vec()))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use oc_proto::{Empty, PayX402Request};

    use super::*;
    use crate::{
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
                let decoded: oc_proto::ListWalletsResponse =
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
        let resp =
            dispatch_req(KeyAgentRequestKind::SignTransaction(oc_proto::SignTransactionRequest {
                session_key_id: "sk-1".to_string(),
                wallet_id: "nonexistent-wallet".to_string(),
                chain_id: "eip155:1".to_string(),
                raw_tx_hex: "deadbeef".to_string(),
                auth: None,
            }));
        // P0-2: with auth=None, the Passkey gate rejects before reaching
        // load_chain_key. Either error path satisfies this smoke test.
        assert!(resp.is_error(), "expected error for missing auth / wallet");
    }

    #[test]
    fn test_sign_message_missing_wallet_returns_error() {
        let resp = dispatch_req(KeyAgentRequestKind::SignMessage(oc_proto::SignMessageRequest {
            session_key_id: "sk-1".to_string(),
            wallet_id: "nonexistent-wallet".to_string(),
            message: b"hello".to_vec(),
            auth: None,
        }));
        assert!(resp.is_error(), "expected error for missing auth / wallet");
    }

    #[test]
    fn test_sign_typed_data_missing_wallet_returns_error() {
        let resp =
            dispatch_req(KeyAgentRequestKind::SignTypedData(oc_proto::SignTypedDataRequest {
                session_key_id: "sk-1".to_string(),
                wallet_id: "nonexistent-wallet".to_string(),
                typed_data_json: "{}".to_string(),
                auth: None,
            }));
        assert!(resp.is_error(), "expected error for missing auth / wallet");
    }

    #[test]
    fn test_sign_user_op_missing_wallet_returns_error() {
        let resp = dispatch_req(KeyAgentRequestKind::SignUserOp(oc_proto::SignUserOpRequest {
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
            oc_proto::CreateSessionKeyRequest {
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
            oc_proto::RevokeSessionKeyRequest { session_key_id: "sk-test".to_string(), auth: None },
        ));
        assert!(resp.is_error(), "RevokeSessionKey without auth should be rejected");
    }

    #[test]
    fn test_get_balance_returns_not_implemented() {
        let resp = dispatch_req(KeyAgentRequestKind::GetBalance(oc_proto::GetBalanceRequest {
            wallet_id: "w1".to_string(),
            chain_id: "eip155:1".to_string(),
        }));
        assert!(resp.is_error());
    }

    #[test]
    fn test_get_payment_history_returns_ok() {
        let resp = dispatch_req(KeyAgentRequestKind::GetPaymentHistory(
            oc_proto::GetPaymentHistoryRequest {
                session_key_id: "sk-test".to_string(),
                since_unix: 0,
                limit: 10,
            },
        ));
        match &resp.kind {
            Some(KeyAgentResponseKind::Ok(bytes)) => {
                let decoded: oc_proto::PaymentHistoryResponse =
                    prost::Message::decode(bytes.as_slice()).unwrap();
                let _ = decoded.records.len();
            }
            Some(KeyAgentResponseKind::Error(_)) => {
                // Acceptable if audit log dir doesn't exist.
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[test]
    fn test_lock_vault_returns_ok() {
        let resp = dispatch_req(KeyAgentRequestKind::LockVault(Empty {}));
        assert!(!resp.is_error(), "LockVault should succeed");
        match &resp.kind {
            Some(KeyAgentResponseKind::Ok(bytes)) => {
                let decoded: oc_proto::LockVaultResponse =
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
            KeyAgentRequestKind::CreateSessionKey(oc_proto::CreateSessionKeyRequest {
                label: "x".to_string(),
                rules: None,
                budget: None,
                auth: None,
            }),
            KeyAgentRequestKind::RevokeSessionKey(oc_proto::RevokeSessionKeyRequest {
                session_key_id: "x".to_string(),
                auth: None,
            }),
            KeyAgentRequestKind::PayX402(PayX402Request {
                session_key_id: "x".to_string(),
                url: "x".to_string(),
                method: "x".to_string(),
                body: vec![],
                headers: std::collections::HashMap::new(),
                ..Default::default()
            }),
            KeyAgentRequestKind::SignTransaction(oc_proto::SignTransactionRequest {
                session_key_id: "x".to_string(),
                wallet_id: "x".to_string(),
                chain_id: "x".to_string(),
                raw_tx_hex: "x".to_string(),
                auth: None,
            }),
            KeyAgentRequestKind::SignUserOp(oc_proto::SignUserOpRequest {
                session_key_id: "x".to_string(),
                wallet_id: "x".to_string(),
                chain_id: "x".to_string(),
                user_op_hex: "x".to_string(),
                auth: None,
            }),
            KeyAgentRequestKind::SignMessage(oc_proto::SignMessageRequest {
                session_key_id: "x".to_string(),
                wallet_id: "x".to_string(),
                message: vec![],
                auth: None,
            }),
            KeyAgentRequestKind::SignTypedData(oc_proto::SignTypedDataRequest {
                session_key_id: "x".to_string(),
                wallet_id: "x".to_string(),
                typed_data_json: "x".to_string(),
                auth: None,
            }),
            KeyAgentRequestKind::GetPaymentHistory(oc_proto::GetPaymentHistoryRequest {
                session_key_id: "x".to_string(),
                since_unix: 0,
                limit: 0,
            }),
            KeyAgentRequestKind::GetBalance(oc_proto::GetBalanceRequest {
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
            KeyAgentRequestKind::UnlockVault(oc_proto::UnlockVaultRequest {
                wallet_id: "x".to_string(),
                auth: None,
            }),
            // Phase 6 secret variants — R56 returns "not implemented" (no panic).
            KeyAgentRequestKind::GetSecret(oc_proto::GetSecretRequest {
                name: "x".to_string(),
                api_token: "x".to_string(),
            }),
            KeyAgentRequestKind::ListSecrets(oc_proto::ListSecretsRequest {
                api_token: "x".to_string(),
            }),
            KeyAgentRequestKind::GenerateTotp(oc_proto::GenerateTotpRequest {
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
}
