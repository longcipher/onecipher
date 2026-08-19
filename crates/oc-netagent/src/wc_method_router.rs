//! JSON-RPC method → KeyAgentRequest translation.
//!
//! Implements `WalletMethodHandler` so the `WcWalletServer` can dispatch
//! inbound WC requests. Each JSON-RPC method is mapped to a `KeyAgentRequest`
//! variant, forwarded to the Key-Agent via UDS, and the response is translated
//! back to a JSON value (or a JSON-RPC error code).

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use oc_core::{ChainIdExt, TxSimulation, approval_log::ApprovalLog};
use oc_keyagent::{
    KeyAgentRequest, KeyAgentRequestKind, KeyAgentResponse, KeyAgentResponseKind,
    proto::{
        GenerateChallengeRequest, GetBalanceRequest, ListWalletsResponse, PasskeyAuthorization,
        SignAuthRequest, SignAuthResponse, SignMessageRequest, SignTransactionRequest,
        SignTypedDataRequest, SignUserOpRequest,
    },
};
use oc_walletconnect::{
    WalletMethodHandler, jsonrpc::JsonRpcErrorCode, wallet_server::HandlerResult,
};
use prost::Message;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{
    approval::{
        ApprovalChannel, ApprovalDecision, PendingApproval, RiskLevel, RiskReason, RiskSource,
    },
    key_agent_client::KeyAgentClient,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignAuthMode {
    RequirePasskey,
    InternalToken(Vec<u8>),
}

/// Common parameters extracted from WC method params.
#[allow(clippy::struct_field_names)]
struct CommonParams {
    wallet_id: String,
    chain_id: String,
    session_key_id: Option<String>,
}

pub struct WcMethodRouter {
    key_agent: KeyAgentClient,
    /// Optional approval channel for Web UI flow.
    approval: Option<ApprovalChannel>,
    /// Whether approval mode is active (signing requests require Web UI approval).
    pub approval_mode: Arc<AtomicBool>,
    /// Timeout for waiting on user decision.
    approval_timeout: Duration,
    /// Optional persistent log for approvals.
    approval_log: Option<Arc<ApprovalLog>>,
    /// Loaded policy for pre-signing risk evaluation (W2.1).
    policy: Option<oc_policy::PolicyV2>,
    /// Shared WC session table (when wired by the daemon) — used to resolve
    /// the dApp name/origin for the approval gate when the wallet server did
    /// not attach them (e.g. pairing-topic requests).
    sessions: Option<Arc<tokio::sync::Mutex<oc_walletconnect::WcSessionTable>>>,
    /// How auth-class signing requests are authorized.
    sign_auth_mode: SignAuthMode,
}

impl WcMethodRouter {
    pub fn new(key_agent: KeyAgentClient) -> Self {
        Self {
            key_agent,
            approval: None,
            approval_mode: Arc::new(AtomicBool::new(false)),
            approval_timeout: Duration::from_secs(300),
            approval_log: None,
            policy: None,
            sessions: None,
            sign_auth_mode: SignAuthMode::RequirePasskey,
        }
    }

    /// Create a router with approval channel and configuration.
    pub fn with_approval(
        key_agent: KeyAgentClient,
        approval: ApprovalChannel,
        approval_mode: Arc<AtomicBool>,
        approval_timeout: Duration,
        approval_log: Option<Arc<ApprovalLog>>,
    ) -> Self {
        Self {
            key_agent,
            approval: Some(approval),
            approval_mode,
            approval_timeout,
            approval_log,
            policy: None,
            sessions: None,
            sign_auth_mode: SignAuthMode::RequirePasskey,
        }
    }

    /// Attach a loaded `PolicyV2` for pre-signing risk evaluation (W2.1).
    pub fn with_policy(mut self, policy: oc_policy::PolicyV2) -> Self {
        self.policy = Some(policy);
        self
    }

    /// Share the WC session table with the wallet server so the approval gate
    /// can resolve the dApp name/origin for the request's session topic.
    pub fn with_sessions(
        mut self,
        sessions: Arc<tokio::sync::Mutex<oc_walletconnect::WcSessionTable>>,
    ) -> Self {
        self.sessions = Some(sessions);
        self
    }

    pub fn with_sign_auth_mode(mut self, mode: SignAuthMode) -> Self {
        self.sign_auth_mode = mode;
        self
    }

    #[cfg(test)]
    pub(crate) fn has_approval_channel(&self) -> bool {
        self.approval.is_some()
    }

    /// Resolve the dApp name/origin for an approval decision.
    ///
    /// Prefers the metadata the wallet server attached to the request; falls
    /// back to the shared session table (keyed by `session_topic`) when the
    /// caller passed empty strings — this is the case for pairing-topic
    /// requests (e.g. `wc_authRequest`), where the session may carry the
    /// proposer metadata.
    fn resolve_dapp_metadata(
        &self,
        session_topic: &str,
        dapp_name: &str,
        dapp_origin: &str,
    ) -> (String, String) {
        if !dapp_name.is_empty() || !dapp_origin.is_empty() {
            return (dapp_name.to_string(), dapp_origin.to_string());
        }
        let Some(sessions) = &self.sessions else {
            return (String::new(), String::new());
        };
        let Ok(t) = sessions.try_lock() else {
            return (String::new(), String::new());
        };
        match t.get(session_topic) {
            Some(s) => {
                (s.dapp_name.clone().unwrap_or_default(), s.dapp_origin.clone().unwrap_or_default())
            }
            None => (String::new(), String::new()),
        }
    }

    /// Resolve the default (first) wallet and its chain address.
    ///
    /// Used by `onecipher_signAuth` (when `wallet_id` is omitted) and by
    /// `wc_authRequest` (which never carries a wallet id). The default wallet
    /// must expose an account for the requested chain; mismatches fail closed
    /// instead of silently signing with some other account.
    async fn default_wallet_for_chain(
        &self,
        chain_id: &str,
    ) -> Result<(String, String), (JsonRpcErrorCode, String)> {
        if chain_id.is_empty() {
            return Err((
                JsonRpcErrorCode::UnsupportedMethod,
                "chain_id is required when resolving a default wallet".into(),
            ));
        }
        let bytes =
            self.forward(KeyAgentRequestKind::ListWallets(oc_keyagent::proto::Empty {})).await?;
        let resp: ListWalletsResponse = Message::decode(bytes.as_slice())
            .map_err(|e| (JsonRpcErrorCode::Internal, format!("decode: {e}")))?;
        let wallet = resp.wallets.first().ok_or_else(|| {
            (JsonRpcErrorCode::Internal, "no wallet available for auth request".into())
        })?;
        let address = wallet
            .accounts
            .iter()
            .find(|a| a.chain_id == chain_id)
            .map(|a| a.address.clone())
            .ok_or_else(|| {
                (
                    JsonRpcErrorCode::UnsupportedMethod,
                    format!("default wallet has no account for requested chain {chain_id}"),
                )
            })?;
        Ok((wallet.id.clone(), address))
    }

    /// Check if a signing request should be gated by the approval flow.
    ///
    /// Returns `Ok(true)` if the caller should proceed to `forward()` directly.
    /// Returns `Ok(false)` if the request was rejected by the user.
    /// Returns `Err(...)` if there was a timeout or the request was rejected with
    /// a JSON-RPC error.
    #[allow(clippy::too_many_arguments)]
    async fn maybe_gate_approval(
        &self,
        method: &str,
        params: &Value,
        dapp_name: &str,
        dapp_origin: &str,
        chain_id: &str,
        risk: RiskLevel,
        risk_reasons: Vec<RiskReason>,
        simulation: Option<TxSimulation>,
    ) -> Result<bool, (JsonRpcErrorCode, String)> {
        // If approval mode is off, always proceed
        if !self.approval_mode.load(Ordering::Relaxed) {
            return Ok(true);
        }

        // If no approval channel configured, proceed (graceful degradation)
        let approval_channel = match &self.approval {
            Some(ch) => ch,
            None => return Ok(true),
        };

        let now_secs = Self::now_unix_secs()?;

        let pending = PendingApproval {
            id: uuid::Uuid::new_v4(),
            method: method.to_string(),
            params: params.clone(),
            dapp_name: dapp_name.to_string(),
            dapp_origin: dapp_origin.to_string(),
            chain_id: chain_id.to_string(),
            risk,
            risk_reasons,
            simulation,
            created_at_unix: now_secs,
            expires_at_unix: now_secs + self.approval_timeout.as_secs(),
        };

        // Log pending (sync fs append — run on the blocking pool to avoid
        // stalling the async runtime on disk I/O).
        if let Some(log) = &self.approval_log {
            let log = log.clone();
            let pending = pending.clone();
            if let Err(e) = tokio::task::spawn_blocking(move || log.append_pending(&pending))
                .await
                .unwrap_or_else(|e| Err(std::io::Error::other(e.to_string())))
            {
                tracing::warn!(error = %e, "failed to log pending approval");
            }
        }

        let id = pending.id;
        let decision = approval_channel.request(pending, self.approval_timeout).await;

        // Log resolved (sync fs append — run on the blocking pool).
        if let Some(log) = &self.approval_log {
            let (decision_str, reason) = match &decision {
                ApprovalDecision::Approve => ("approved", String::new()),
                ApprovalDecision::Reject { reason } => ("rejected", reason.clone()),
                ApprovalDecision::Timeout => ("timeout", String::new()),
            };
            let log = log.clone();
            if let Err(e) =
                tokio::task::spawn_blocking(move || log.append_resolved(id, decision_str, &reason))
                    .await
                    .unwrap_or_else(|e| Err(std::io::Error::other(e.to_string())))
            {
                tracing::warn!(error = %e, "failed to log resolved approval");
            }
        }

        match decision {
            ApprovalDecision::Approve => Ok(true),
            ApprovalDecision::Reject { reason } => {
                Err((JsonRpcErrorCode::UserRejected, format!("user rejected: {reason}")))
            }
            ApprovalDecision::Timeout => {
                Err((JsonRpcErrorCode::UserRejected, "approval timeout".into()))
            }
        }
    }

    /// Current Unix timestamp in seconds, fail-closed on clock errors.
    ///
    /// A corrupted system clock (e.g. set before the Unix epoch) would make
    /// `duration_since(UNIX_EPOCH).unwrap_or_default()` silently yield `0`,
    /// which would defeat every time-based policy check (expiry, cooldown,
    /// approval TTL). Instead we surface the error so the caller rejects the
    /// request rather than blindly trusting a bogus `now == 0`.
    fn now_unix_secs() -> Result<u64, (JsonRpcErrorCode, String)> {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|e| {
                (
                    JsonRpcErrorCode::Internal,
                    format!("system clock error (refusing to evaluate time-based policy): {e}"),
                )
            })
    }

    /// P0-2: Extract a [`PasskeyAuthorization`] from the WC JSON params `auth`
    /// sub-object.
    ///
    /// The `auth` object must contain:
    /// - `challenge_hex`: hex-encoded 32-byte challenge (from `GenerateChallenge`)
    /// - `signature_hex`: hex-encoded Passkey signature over `challenge || credential_id`
    /// - `credential_id`: Passkey credential ID string
    ///
    /// Returns `Ok(None)` when no `auth` field is present (callers decide
    /// whether to treat that as an error — signing RPCs require it, while
    /// read-only RPCs do not).
    fn extract_passkey_auth(
        params: &Value,
    ) -> Result<Option<PasskeyAuthorization>, (JsonRpcErrorCode, String)> {
        let auth_obj = match params.get("auth") {
            Some(v) if !v.is_null() => v,
            _ => return Ok(None),
        };
        let challenge_hex = auth_obj
            .get("challenge_hex")
            .and_then(Value::as_str)
            .ok_or_else(|| (JsonRpcErrorCode::Unauthorized, "missing auth.challenge_hex".into()))?;
        let signature_hex = auth_obj
            .get("signature_hex")
            .and_then(Value::as_str)
            .ok_or_else(|| (JsonRpcErrorCode::Unauthorized, "missing auth.signature_hex".into()))?;
        let credential_id = auth_obj
            .get("credential_id")
            .and_then(Value::as_str)
            .ok_or_else(|| (JsonRpcErrorCode::Unauthorized, "missing auth.credential_id".into()))?;
        let challenge = hex::decode(challenge_hex).map_err(|e| {
            (JsonRpcErrorCode::Unauthorized, format!("invalid auth.challenge_hex: {e}"))
        })?;
        let signature = hex::decode(signature_hex).map_err(|e| {
            (JsonRpcErrorCode::Unauthorized, format!("invalid auth.signature_hex: {e}"))
        })?;
        Ok(Some(PasskeyAuthorization {
            challenge,
            signature,
            credential_id: credential_id.to_string(),
        }))
    }

    /// Common parameters extracted from WC method params.
    fn extract_common_params(params: &Value) -> Result<CommonParams, (JsonRpcErrorCode, String)> {
        let wallet_id = params
            .get("wallet_id")
            .and_then(Value::as_str)
            .ok_or_else(|| (JsonRpcErrorCode::UnsupportedMethod, "missing wallet_id".into()))?
            .to_string();
        let chain_id = params
            .get("chain_id")
            .and_then(Value::as_str)
            .ok_or_else(|| (JsonRpcErrorCode::UnsupportedMethod, "missing chain_id".into()))?
            .to_string();
        let session_key_id = params.get("session_key_id").and_then(Value::as_str).map(String::from);
        Ok(CommonParams { wallet_id, chain_id, session_key_id })
    }

    /// Pre-signing policy evaluation (W2.1).
    ///
    /// Evaluates the signing request against the loaded `PolicyV2` rules.
    /// Returns `Err(...)` for an immediate JSON-RPC reject (Deny), or
    /// `Ok((risk, reasons))` for Warn/Allow.
    fn policy_evaluate_signing(
        &self,
        method: &str,
        params: &Value,
        chain_id: &str,
    ) -> Result<(RiskLevel, Vec<RiskReason>), (JsonRpcErrorCode, String)> {
        let policy = match &self.policy {
            Some(p) => p,
            None => return Ok((RiskLevel::Safe, vec![])),
        };

        let mut reasons: Vec<RiskReason> = vec![];

        // Chain whitelist check → Deny
        if !policy.rules.chain_whitelist.is_empty() &&
            !chain_id.is_empty() &&
            !policy.rules.chain_whitelist.iter().any(|c| c == chain_id)
        {
            tracing::warn!(method, chain_id, "policy deny: chain not whitelisted");
            return Err((
                JsonRpcErrorCode::PolicyChainNotWhitelisted,
                format!("chain {chain_id} not in policy whitelist"),
            ));
        }

        // Expiry check → Deny
        let now = Self::now_unix_secs()?;
        if now > policy.rules.expiry_unix {
            tracing::warn!(method, "policy deny: policy expired");
            return Err((JsonRpcErrorCode::PolicyExpired, "policy has expired".into()));
        }

        // Warn checks (non-blocking)
        if let Some(to) = params.get("to").and_then(Value::as_str) {
            if !policy.rules.contract_whitelist.is_empty() &&
                !policy.rules.contract_whitelist.iter().any(|c| c.eq_ignore_ascii_case(to))
            {
                reasons.push(RiskReason {
                    code: "policy_warn_new_contract".into(),
                    level: RiskLevel::Warning,
                    message: format!("contract {to} is not in the whitelist"),
                    source: RiskSource::Policy,
                    detail: Some(serde_json::json!({"address": to})),
                });
            }
        }

        // ponytail: dApp origin warning removed — no verified-dApp list exists yet.
        // Add back when PolicyRulesV2 gains a `dapp_origins` allowlist field.

        if reasons.is_empty() {
            Ok((RiskLevel::Safe, vec![]))
        } else {
            Ok((RiskLevel::Warning, reasons))
        }
    }

    /// Process simulation result into (simulation, risk_delta, risk_reasons_delta).
    ///
    /// - Success: pass through, no risk change.
    /// - Revert (sim.success == false): bump risk to Danger, add reason.
    /// - Error: return None simulation, warn (do NOT block signing).
    fn apply_simulation_result(
        result: Result<TxSimulation, crate::sim::SimError>,
    ) -> (Option<TxSimulation>, RiskLevel, Vec<RiskReason>) {
        match result {
            Ok(sim) if sim.success => (Some(sim), RiskLevel::Safe, vec![]),
            Ok(sim) => {
                let reason = RiskReason {
                    code: "sim_revert".into(),
                    level: RiskLevel::Danger,
                    message: format!(
                        "simulation indicates revert: {}",
                        sim.error.as_deref().unwrap_or("execution failed")
                    ),
                    source: RiskSource::Simulation,
                    detail: Some(serde_json::json!({"gas_used": sim.gas_used})),
                };
                (Some(sim), RiskLevel::Danger, vec![reason])
            }
            Err(e) => {
                tracing::warn!(error = %e, "tx simulation failed, degrading gracefully");
                let reason = RiskReason {
                    code: "sim_unavailable".into(),
                    level: RiskLevel::Warning,
                    message: "transaction simulation was not available".into(),
                    source: RiskSource::Simulation,
                    detail: Some(serde_json::json!({"error": e.to_string()})),
                };
                (None, RiskLevel::Warning, vec![reason])
            }
        }
    }

    async fn forward(
        &self,
        kind: KeyAgentRequestKind,
    ) -> Result<Vec<u8>, (JsonRpcErrorCode, String)> {
        let req = KeyAgentRequest { kind: Some(kind) };
        let resp: KeyAgentResponse = self
            .key_agent
            .send(&req)
            .await
            .map_err(|e| (JsonRpcErrorCode::Internal, format!("key-agent wire: {e}")))?;
        match resp.kind {
            Some(KeyAgentResponseKind::Ok(b)) => Ok(b),
            Some(KeyAgentResponseKind::Deny(d)) => {
                let code = deny_reason_to_rpc_code_from_proto(d.reason);
                Err((code, "policy denied".into()))
            }
            Some(KeyAgentResponseKind::Error(msg)) => Err((JsonRpcErrorCode::Signer, msg)),
            None => Err((JsonRpcErrorCode::Internal, "empty key-agent response".into())),
        }
    }
}

/// Convert a proto `DenyReason` integer to a `JsonRpcErrorCode`.
fn deny_reason_to_rpc_code_from_proto(reason: i32) -> JsonRpcErrorCode {
    use oc_keyagent::proto::DenyReason as ProtoDenyReason;
    match ProtoDenyReason::try_from(reason) {
        Ok(ProtoDenyReason::RateLimitMinute) => JsonRpcErrorCode::PolicyRateLimit,
        Ok(ProtoDenyReason::RateLimitHour) => JsonRpcErrorCode::PolicyRateLimit,
        Ok(ProtoDenyReason::BudgetExceeded) => JsonRpcErrorCode::PolicyBudgetExceeded,
        Ok(ProtoDenyReason::Whitelist) => JsonRpcErrorCode::PolicyWhitelist,
        Ok(ProtoDenyReason::Expired) => JsonRpcErrorCode::PolicyExpired,
        Ok(ProtoDenyReason::PasskeyForged) => JsonRpcErrorCode::Unauthorized,
        Ok(ProtoDenyReason::PolicyMissing) => JsonRpcErrorCode::PolicyMissing,
        Ok(ProtoDenyReason::Cooldown) => JsonRpcErrorCode::PolicyCooldown,
        Ok(ProtoDenyReason::Unknown) | Err(_) => JsonRpcErrorCode::Internal,
    }
}

impl WalletMethodHandler for WcMethodRouter {
    fn handle<'a>(
        &'a self,
        method: &str,
        params: Value,
        session_topic: &str,
        dapp_name: Option<&str>,
        dapp_origin: Option<&str>,
    ) -> HandlerResult<'a> {
        let method = method.to_string();
        // Own the dApp metadata so the future outlives the call's borrows.
        let dapp_name = dapp_name.unwrap_or("").to_string();
        let dapp_origin = dapp_origin.unwrap_or("").to_string();
        let session_topic = session_topic.to_string();
        Box::pin(async move {
            // Resolve dApp metadata from the shared session table when the
            // wallet server did not attach it (pairing-topic requests).
            let (resolved_name, resolved_origin) =
                self.resolve_dapp_metadata(&session_topic, &dapp_name, &dapp_origin);
            let dapp_name = resolved_name.as_str();
            let dapp_origin = resolved_origin.as_str();
            match method.as_str() {
                "onecipher_listWallets" => {
                    let bytes = self
                        .forward(KeyAgentRequestKind::ListWallets(oc_keyagent::proto::Empty {}))
                        .await?;
                    let resp: ListWalletsResponse = Message::decode(bytes.as_slice())
                        .map_err(|e| (JsonRpcErrorCode::Internal, format!("decode: {e}")))?;
                    let wallets: Vec<Value> = resp.wallets.iter().map(|w| {
                    let accounts: Vec<Value> = w.accounts.iter().map(|a| {
                        json!({"account_id": a.account_id, "address": a.address, "chain_id": a.chain_id, "derivation_path": a.derivation_path})
                    }).collect();
                    json!({"id": w.id, "name": w.name, "key_type": w.key_type, "created_at": w.created_at, "accounts": accounts})
                }).collect();
                    Ok(json!({"wallets": wallets}))
                }

                "eth_sendTransaction" |
                "eth_signTransaction" |
                "solana_signTransaction" |
                "cosmos_signDirect" |
                "cosmos_signAmino" |
                "onecipher_signTransaction" => {
                    // P0-2: Passkey gate — signing RPCs require auth.
                    let auth = Self::extract_passkey_auth(&params)?.ok_or_else(|| {
                        (JsonRpcErrorCode::Unauthorized, "missing passkey authorization".into())
                    })?;
                    let CommonParams { wallet_id, chain_id, session_key_id } =
                        Self::extract_common_params(&params)?;
                    let session_key_id = session_key_id.unwrap_or_default();
                    let raw_tx_hex = params
                        .get("raw_tx_hex")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            (JsonRpcErrorCode::UnsupportedMethod, "missing raw_tx_hex".into())
                        })?
                        .to_string();

                    // W2.1: Pre-signing policy evaluation
                    let (mut risk, mut risk_reasons) =
                        self.policy_evaluate_signing(&method, &params, &chain_id)?;

                    // W3.3: Simulate EVM transactions before approval
                    let simulation = {
                        let cid: Option<oc_core::ChainId> = chain_id.parse().ok();
                        if cid.as_ref().map_or(false, |c| c.is_evm()) {
                            let sim_result =
                                crate::sim::simulate_evm_tx(&raw_tx_hex, &chain_id).await;
                            let (sim, sim_risk, sim_reasons) =
                                Self::apply_simulation_result(sim_result);
                            risk = std::cmp::max(risk, sim_risk);
                            risk_reasons.extend(sim_reasons);
                            sim
                        } else {
                            None
                        }
                    };

                    // Web UI approval gate (W1.3)
                    self.maybe_gate_approval(
                        &method,
                        &params,
                        dapp_name,
                        dapp_origin,
                        &chain_id,
                        risk,
                        risk_reasons,
                        simulation,
                    )
                    .await?;

                    let req = SignTransactionRequest {
                        session_key_id,
                        wallet_id,
                        chain_id,
                        raw_tx_hex,
                        auth: Some(auth),
                    };
                    let bytes = self.forward(KeyAgentRequestKind::SignTransaction(req)).await?;
                    let resp: oc_keyagent::proto::SignTransactionResponse =
                        Message::decode(bytes.as_slice())
                            .map_err(|e| (JsonRpcErrorCode::Internal, format!("decode: {e}")))?;
                    Ok(json!({"signature": resp.signature, "signed_tx_hex": resp.signed_tx_hex}))
                }

                "personal_sign" | "eth_sign" | "solana_signMessage" | "onecipher_signMessage" => {
                    // P0-2: Passkey gate — signing RPCs require auth.
                    let auth = Self::extract_passkey_auth(&params)?.ok_or_else(|| {
                        (JsonRpcErrorCode::Unauthorized, "missing passkey authorization".into())
                    })?;
                    let CommonParams { wallet_id, session_key_id, .. } =
                        Self::extract_common_params(&params)?;
                    let session_key_id = session_key_id.unwrap_or_default();
                    let message = params
                        .get("message")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            (JsonRpcErrorCode::UnsupportedMethod, "missing message".into())
                        })?
                        .as_bytes()
                        .to_vec();

                    // W2.1: Pre-signing policy evaluation
                    let (risk, risk_reasons) =
                        self.policy_evaluate_signing(&method, &params, "")?;

                    // Web UI approval gate (W1.3)
                    self.maybe_gate_approval(
                        &method,
                        &params,
                        dapp_name,
                        dapp_origin,
                        "",
                        risk,
                        risk_reasons,
                        None,
                    )
                    .await?;

                    let req =
                        SignMessageRequest { session_key_id, wallet_id, message, auth: Some(auth) };
                    let bytes = self.forward(KeyAgentRequestKind::SignMessage(req)).await?;
                    let resp: oc_keyagent::proto::SignMessageResponse =
                        Message::decode(bytes.as_slice())
                            .map_err(|e| (JsonRpcErrorCode::Internal, format!("decode: {e}")))?;
                    Ok(json!({"signature": resp.signature}))
                }

                // Auth-class message signing (`onecipher_signAuth`).
                //
                // Local/direct callers must provide a Passkey proof; the
                // WalletConnect daemon path injects a daemon-internal token
                // instead. The Key-Agent signs the raw `message` bytes with
                // the chain's message-signing convention (EVM: EIP-191;
                // Solana: raw ed25519; …) and returns the signature, the
                // derived account address and the public key.
                "onecipher_signAuth" => {
                    let chain_id = params
                        .get("chain_id")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            (JsonRpcErrorCode::UnsupportedMethod, "missing chain_id".into())
                        })?
                        .to_string();
                    // wallet_id is optional, but the default wallet must have
                    // an account for the requested chain.
                    let wallet_id = match params.get("wallet_id").and_then(Value::as_str) {
                        Some(w) => w.to_string(),
                        None => self.default_wallet_for_chain(&chain_id).await?.0,
                    };
                    let message = params
                        .get("message")
                        .and_then(Value::as_str)
                        .map(|m| m.as_bytes().to_vec())
                        .ok_or_else(|| {
                            (JsonRpcErrorCode::UnsupportedMethod, "missing message".into())
                        })?;
                    let auth = match &self.sign_auth_mode {
                        SignAuthMode::RequirePasskey => {
                            Some(Self::extract_passkey_auth(&params)?.ok_or_else(|| {
                                (
                                    JsonRpcErrorCode::Unauthorized,
                                    "missing auth for onecipher_signAuth".into(),
                                )
                            })?)
                        }
                        SignAuthMode::InternalToken(_) => None,
                    };

                    // W2.1: Pre-signing policy evaluation (chain whitelist etc.)
                    let (risk, risk_reasons) =
                        self.policy_evaluate_signing(&method, &params, &chain_id)?;

                    // Web UI approval gate (W1.3) — NO passkey involved.
                    self.maybe_gate_approval(
                        &method,
                        &params,
                        dapp_name,
                        dapp_origin,
                        &chain_id,
                        risk,
                        risk_reasons,
                        None,
                    )
                    .await?;

                    let req = match &self.sign_auth_mode {
                        SignAuthMode::RequirePasskey => SignAuthRequest {
                            wallet_id,
                            chain_id: chain_id.clone(),
                            message,
                            auth,
                            agent_token: Vec::new(),
                        },
                        SignAuthMode::InternalToken(token) => SignAuthRequest {
                            wallet_id,
                            chain_id: chain_id.clone(),
                            message,
                            auth: None,
                            agent_token: token.clone(),
                        },
                    };
                    let bytes = self.forward(KeyAgentRequestKind::SignAuth(req)).await?;
                    let resp: SignAuthResponse = Message::decode(bytes.as_slice())
                        .map_err(|e| (JsonRpcErrorCode::Internal, format!("decode: {e}")))?;
                    Ok(json!({
                        "signature": format!("0x{}", hex::encode(&resp.signature)),
                        "address": resp.address,
                        "chain_id": resp.chain_id,
                        "public_key": format!("0x{}", hex::encode(&resp.public_key)),
                    }))
                }

                // WalletConnect v2 Auth protocol (`wc_authRequest`) — one-time
                // sign-in on a pairing topic, no session needed. The router
                // builds the EIP-4361 (SIWE) message from the dApp's params,
                // signs it via the Key-Agent's SignAuth path, and returns the
                // signature + message hash + the original payload.
                "wc_authRequest" => {
                    use oc_walletconnect::{
                        AuthRequestParams, AuthType, build_siwe_message, eip4361_hash,
                    };

                    let auth_params: AuthRequestParams = serde_json::from_value(params.clone())
                        .map_err(|e| {
                            (JsonRpcErrorCode::Internal, format!("bad wc_authRequest params: {e}"))
                        })?;
                    auth_params.validate().map_err(|e| {
                        (JsonRpcErrorCode::Internal, format!("invalid wc_authRequest: {e}"))
                    })?;

                    // Only EVM chains are supported by the Auth protocol for
                    // now — non-EVM chains should use `onecipher_signAuth`.
                    let is_evm = auth_params
                        .chain_id
                        .parse::<oc_core::ChainId>()
                        .map_or(false, |c| c.is_evm());
                    if !is_evm {
                        return Err((
                            JsonRpcErrorCode::UnsupportedMethod,
                            format!(
                                "wc_authRequest not supported for non-EVM chain {}",
                                auth_params.chain_id
                            ),
                        ));
                    }

                    // Resolve the default wallet + its address for the chain.
                    let (wallet_id, address) =
                        self.default_wallet_for_chain(&auth_params.chain_id).await?;

                    let (message, hash): (Vec<u8>, Vec<u8>) = match auth_params.r#type {
                        AuthType::Eip4361 => {
                            let text = build_siwe_message(&address, &auth_params).map_err(|e| {
                                (JsonRpcErrorCode::Internal, format!("siwe build: {e}"))
                            })?;
                            let hash = eip4361_hash(&text).to_vec();
                            (text.into_bytes(), hash)
                        }
                        AuthType::Eip191 => {
                            // Keep it simple: sign `aud || "\n" || nonce`, or
                            // the raw `message` field when the dApp supplied one.
                            let raw = match params.get("message").and_then(Value::as_str) {
                                Some(m) => m.as_bytes().to_vec(),
                                None => format!("{}\n{}", auth_params.aud, auth_params.nonce)
                                    .into_bytes(),
                            };
                            let hash = Sha256::digest(&raw).to_vec();
                            (raw, hash)
                        }
                    };

                    // W2.1: policy evaluation (chain whitelist).
                    let (risk, risk_reasons) =
                        self.policy_evaluate_signing(&method, &params, &auth_params.chain_id)?;

                    // Approval gate (W1.3).
                    self.maybe_gate_approval(
                        &method,
                        &params,
                        dapp_name,
                        dapp_origin,
                        &auth_params.chain_id,
                        risk,
                        risk_reasons,
                        None,
                    )
                    .await?;

                    let req = match &self.sign_auth_mode {
                        SignAuthMode::RequirePasskey => {
                            return Err((
                                JsonRpcErrorCode::Unauthorized,
                                "wc_authRequest requires WalletConnect daemon internal authorization"
                                    .into(),
                            ));
                        }
                        SignAuthMode::InternalToken(token) => SignAuthRequest {
                            wallet_id,
                            chain_id: auth_params.chain_id.clone(),
                            message,
                            auth: None,
                            agent_token: token.clone(),
                        },
                    };
                    let bytes = self.forward(KeyAgentRequestKind::SignAuth(req)).await?;
                    let resp: SignAuthResponse = Message::decode(bytes.as_slice())
                        .map_err(|e| (JsonRpcErrorCode::Internal, format!("decode: {e}")))?;
                    Ok(json!({
                        "signature": format!("0x{}", hex::encode(&resp.signature)),
                        "hash": format!("0x{}", hex::encode(&hash)),
                        "payload": params,
                    }))
                }

                "eth_signTypedData_v4" | "onecipher_signTypedData" => {
                    // P0-2: Passkey gate — signing RPCs require auth.
                    let auth = Self::extract_passkey_auth(&params)?.ok_or_else(|| {
                        (JsonRpcErrorCode::Unauthorized, "missing passkey authorization".into())
                    })?;
                    let CommonParams { wallet_id, session_key_id, .. } =
                        Self::extract_common_params(&params)?;
                    let session_key_id = session_key_id.unwrap_or_default();
                    let typed_data_json = params
                        .get("typed_data_json")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            (JsonRpcErrorCode::UnsupportedMethod, "missing typed_data_json".into())
                        })?
                        .to_string();

                    // W2.1: Pre-signing policy evaluation
                    let (risk, risk_reasons) =
                        self.policy_evaluate_signing(&method, &params, "")?;

                    // Web UI approval gate (W1.3)
                    self.maybe_gate_approval(
                        &method,
                        &params,
                        dapp_name,
                        dapp_origin,
                        "",
                        risk,
                        risk_reasons,
                        None,
                    )
                    .await?;

                    let req = SignTypedDataRequest {
                        session_key_id,
                        wallet_id,
                        typed_data_json,
                        auth: Some(auth),
                    };
                    let bytes = self.forward(KeyAgentRequestKind::SignTypedData(req)).await?;
                    let resp: oc_keyagent::proto::SignTypedDataResponse =
                        Message::decode(bytes.as_slice())
                            .map_err(|e| (JsonRpcErrorCode::Internal, format!("decode: {e}")))?;
                    Ok(json!({"signature": resp.signature}))
                }

                "onecipher_signUserOp" => {
                    // P0-2: Passkey gate — signing RPCs require auth.
                    let auth = Self::extract_passkey_auth(&params)?.ok_or_else(|| {
                        (JsonRpcErrorCode::Unauthorized, "missing passkey authorization".into())
                    })?;
                    let CommonParams { wallet_id, chain_id, session_key_id } =
                        Self::extract_common_params(&params)?;
                    let session_key_id = session_key_id.unwrap_or_default();
                    let user_op_hex = params
                        .get("user_op_hex")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            (JsonRpcErrorCode::UnsupportedMethod, "missing user_op_hex".into())
                        })?
                        .to_string();

                    // W2.1: Pre-signing policy evaluation
                    let (risk, risk_reasons) =
                        self.policy_evaluate_signing(&method, &params, &chain_id)?;

                    // Web UI approval gate (W1.3)
                    self.maybe_gate_approval(
                        &method,
                        &params,
                        dapp_name,
                        dapp_origin,
                        &chain_id,
                        risk,
                        risk_reasons,
                        None,
                    )
                    .await?;

                    let req = SignUserOpRequest {
                        session_key_id,
                        wallet_id,
                        chain_id,
                        user_op_hex,
                        auth: Some(auth),
                    };
                    let bytes = self.forward(KeyAgentRequestKind::SignUserOp(req)).await?;
                    let resp: oc_keyagent::proto::SignUserOpResponse =
                        Message::decode(bytes.as_slice())
                            .map_err(|e| (JsonRpcErrorCode::Internal, format!("decode: {e}")))?;
                    Ok(
                        json!({"signature": resp.signature, "signed_user_op_hex": resp.signed_user_op_hex}),
                    )
                }

                // P0-2: Challenge issuance RPC. Clients MUST call this before any
                // Passkey-gated signing RPC to obtain a fresh 32-byte nonce that the
                // Key-Agent stores in its pending_challenges set.
                "onecipher_generateChallenge" => {
                    let credential_id = params
                        .get("credential_id")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            (JsonRpcErrorCode::UnsupportedMethod, "missing credential_id".into())
                        })?
                        .to_string();
                    let req = GenerateChallengeRequest { credential_id };
                    let bytes = self.forward(KeyAgentRequestKind::GenerateChallenge(req)).await?;
                    let resp: oc_keyagent::proto::GenerateChallengeResponse =
                        Message::decode(bytes.as_slice())
                            .map_err(|e| (JsonRpcErrorCode::Internal, format!("decode: {e}")))?;
                    Ok(json!({"challenge_hex": hex::encode(&resp.challenge)}))
                }

                "onecipher_getBalance" => {
                    let CommonParams { wallet_id, chain_id, .. } =
                        Self::extract_common_params(&params)?;
                    let req = GetBalanceRequest { wallet_id, chain_id };
                    let bytes = self.forward(KeyAgentRequestKind::GetBalance(req)).await?;
                    let resp: oc_keyagent::proto::BalanceResponse =
                        Message::decode(bytes.as_slice())
                            .map_err(|e| (JsonRpcErrorCode::Internal, format!("decode: {e}")))?;
                    Ok(
                        json!({"wallet_id": resp.wallet_id, "chain_id": resp.chain_id, "balance": resp.balance, "decimals": resp.decimals, "symbol": resp.symbol}),
                    )
                }

                _ => {
                    Err((JsonRpcErrorCode::UnsupportedMethod, format!("unknown method: {method}")))
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn test_policy() -> oc_policy::PolicyV2 {
        oc_policy::PolicyV2 {
            version: 2,
            session_key_id: "sk-test".into(),
            device_id: "dev-test".into(),
            rules: oc_policy::PolicyRulesV2 {
                max_single_amount_usd: 10.0,
                max_daily_amount_usd: 100.0,
                max_monthly_amount_usd: 1000.0,
                expiry_unix: 999_999_999_999,
                rate_limit_per_minute: 10,
                rate_limit_per_hour: 100,
                cooldown_after_denial_sec: 0,
                asset_whitelist: vec![],
                chain_whitelist: vec!["eip155:1".into()],
                contract_whitelist: vec!["0xabc".into()],
                payment_protocols: vec![],
            },
            budget_allocation: oc_policy::BudgetAllocation {
                allocated_usd: 50.0,
                allocated_at_unix: 0,
                parent_total_usd: 1000.0,
                parent_session_id: "parent".into(),
            },
        }
    }

    #[tokio::test]
    async fn approval_mode_off_bypasses_channel() {
        let key_agent = KeyAgentClient::new("/tmp/nonexistent.sock");
        let (channel, mut rx) = ApprovalChannel::new(16);
        let mode = Arc::new(AtomicBool::new(false));
        let router =
            WcMethodRouter::with_approval(key_agent, channel, mode, Duration::from_secs(300), None);

        let result = router
            .maybe_gate_approval(
                "eth_sendTransaction",
                &json!({}),
                "dapp",
                "https://x.com",
                "eip155:1",
                RiskLevel::Safe,
                vec![],
                None,
            )
            .await;
        assert_eq!(result, Ok(true));
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn approval_mode_on_sends_to_channel_and_approve() {
        let key_agent = KeyAgentClient::new("/tmp/nonexistent.sock");
        let (channel, mut rx) = ApprovalChannel::new(16);
        let mode = Arc::new(AtomicBool::new(true));
        let router =
            WcMethodRouter::with_approval(key_agent, channel, mode, Duration::from_secs(5), None);

        let handle = tokio::spawn(async move {
            router
                .maybe_gate_approval(
                    "personal_sign",
                    &json!({}),
                    "Uniswap",
                    "https://app.uniswap.org",
                    "eip155:1",
                    RiskLevel::Safe,
                    vec![],
                    None,
                )
                .await
        });

        let (pending, resp_tx) = rx.recv().await.unwrap();
        assert_eq!(pending.method, "personal_sign");
        assert_eq!(pending.dapp_name, "Uniswap");
        resp_tx.send(ApprovalDecision::Approve).unwrap();

        let result = handle.await.unwrap();
        assert_eq!(result, Ok(true));
    }

    #[tokio::test]
    async fn approval_mode_on_reject_returns_error() {
        let key_agent = KeyAgentClient::new("/tmp/nonexistent.sock");
        let (channel, mut rx) = ApprovalChannel::new(16);
        let mode = Arc::new(AtomicBool::new(true));
        let router =
            WcMethodRouter::with_approval(key_agent, channel, mode, Duration::from_secs(5), None);

        let handle = tokio::spawn(async move {
            router
                .maybe_gate_approval(
                    "eth_sendTransaction",
                    &json!({}),
                    "evil",
                    "https://evil.com",
                    "eip155:1",
                    RiskLevel::Safe,
                    vec![],
                    None,
                )
                .await
        });

        let (_pending, resp_tx) = rx.recv().await.unwrap();
        resp_tx.send(ApprovalDecision::Reject { reason: "suspicious".into() }).unwrap();

        let result = handle.await.unwrap();
        assert!(result.is_err());
        let (code, msg) = result.unwrap_err();
        assert_eq!(code, JsonRpcErrorCode::UserRejected);
        assert!(msg.contains("rejected"));
    }

    #[tokio::test]
    async fn approval_channel_receives_risk_and_reasons() {
        let key_agent = KeyAgentClient::new("/tmp/nonexistent.sock");
        let (channel, mut rx) = ApprovalChannel::new(16);
        let mode = Arc::new(AtomicBool::new(true));
        let router =
            WcMethodRouter::with_approval(key_agent, channel, mode, Duration::from_secs(5), None);

        let reasons = vec![RiskReason {
            code: "policy_warn_unverified_dapp".into(),
            level: RiskLevel::Warning,
            message: "dApp not verified".into(),
            source: RiskSource::Policy,
            detail: None,
        }];

        let handle = tokio::spawn(async move {
            router
                .maybe_gate_approval(
                    "personal_sign",
                    &json!({}),
                    "dapp",
                    "https://unknown.com",
                    "eip155:1",
                    RiskLevel::Warning,
                    reasons,
                    None,
                )
                .await
        });

        let (pending, resp_tx) = rx.recv().await.unwrap();
        assert_eq!(pending.risk, RiskLevel::Warning);
        assert_eq!(pending.risk_reasons.len(), 1);
        assert_eq!(pending.risk_reasons[0].code, "policy_warn_unverified_dapp");
        resp_tx.send(ApprovalDecision::Approve).unwrap();
        assert!(handle.await.unwrap().is_ok());
    }

    // --- W2.1: policy_evaluate_signing tests ---

    #[test]
    fn policy_evaluate_allow_when_no_policy() {
        let key_agent = KeyAgentClient::new("/tmp/nonexistent.sock");
        let router = WcMethodRouter::new(key_agent)
            .with_sign_auth_mode(SignAuthMode::InternalToken(vec![7; 32]));
        let (risk, reasons) =
            router.policy_evaluate_signing("personal_sign", &json!({}), "eip155:1").unwrap();
        assert_eq!(risk, RiskLevel::Safe);
        assert!(reasons.is_empty());
    }

    #[test]
    fn policy_evaluate_deny_chain_not_whitelisted() {
        let key_agent = KeyAgentClient::new("/tmp/nonexistent.sock");
        let router = WcMethodRouter::new(key_agent).with_policy(test_policy());
        let err =
            router.policy_evaluate_signing("personal_sign", &json!({}), "eip155:137").unwrap_err();
        assert_eq!(err.0, JsonRpcErrorCode::PolicyChainNotWhitelisted);
        assert!(err.1.contains("eip155:137"));
    }

    #[test]
    fn policy_evaluate_deny_expired_policy() {
        let key_agent = KeyAgentClient::new("/tmp/nonexistent.sock");
        let mut policy = test_policy();
        policy.rules.expiry_unix = 1; // already expired
        let router = WcMethodRouter::new(key_agent).with_policy(policy);
        let err =
            router.policy_evaluate_signing("personal_sign", &json!({}), "eip155:1").unwrap_err();
        assert_eq!(err.0, JsonRpcErrorCode::PolicyExpired);
    }

    #[test]
    fn policy_evaluate_dapp_origin_no_verified_list() {
        let key_agent = KeyAgentClient::new("/tmp/nonexistent.sock");
        let router = WcMethodRouter::new(key_agent).with_policy(test_policy());
        let params = json!({"dapp_origin": "https://unknown.com"});
        let (risk, reasons) =
            router.policy_evaluate_signing("personal_sign", &params, "eip155:1").unwrap();
        // No verified-dApp list exists yet, so dapp_origin is ignored.
        assert_eq!(risk, RiskLevel::Safe);
        assert!(reasons.is_empty());
    }

    #[test]
    fn policy_evaluate_warn_new_contract() {
        let key_agent = KeyAgentClient::new("/tmp/nonexistent.sock");
        let router = WcMethodRouter::new(key_agent).with_policy(test_policy());
        let params = json!({"to": "0xdeadbeef"});
        let (risk, reasons) =
            router.policy_evaluate_signing("eth_sendTransaction", &params, "eip155:1").unwrap();
        assert_eq!(risk, RiskLevel::Warning);
        assert!(reasons.iter().any(|r| r.code == "policy_warn_new_contract"));
    }

    #[test]
    fn policy_evaluate_allow_clean() {
        let key_agent = KeyAgentClient::new("/tmp/nonexistent.sock");
        let router = WcMethodRouter::new(key_agent).with_policy(test_policy());
        let params = json!({"to": "0xabc"});
        let (risk, reasons) =
            router.policy_evaluate_signing("eth_sendTransaction", &params, "eip155:1").unwrap();
        assert_eq!(risk, RiskLevel::Safe);
        assert!(reasons.is_empty());
    }

    #[test]
    fn policy_evaluate_deny_maps_to_forbidden() {
        let key_agent = KeyAgentClient::new("/tmp/nonexistent.sock");
        let router = WcMethodRouter::new(key_agent).with_policy(test_policy());
        // Chain not whitelisted → Deny → should produce error, not risk
        let result = router.policy_evaluate_signing("personal_sign", &json!({}), "solana:mainnet");
        assert!(result.is_err());
        let (code, _) = result.unwrap_err();
        assert_eq!(code, JsonRpcErrorCode::PolicyChainNotWhitelisted);
    }

    #[test]
    fn deny_reason_to_rpc_code_mapping() {
        use oc_keyagent::proto::DenyReason as ProtoDenyReason;
        assert_eq!(
            deny_reason_to_rpc_code_from_proto(ProtoDenyReason::RateLimitMinute as i32),
            JsonRpcErrorCode::PolicyRateLimit
        );
        assert_eq!(
            deny_reason_to_rpc_code_from_proto(ProtoDenyReason::BudgetExceeded as i32),
            JsonRpcErrorCode::PolicyBudgetExceeded
        );
        assert_eq!(
            deny_reason_to_rpc_code_from_proto(ProtoDenyReason::Whitelist as i32),
            JsonRpcErrorCode::PolicyWhitelist
        );
        assert_eq!(
            deny_reason_to_rpc_code_from_proto(ProtoDenyReason::Expired as i32),
            JsonRpcErrorCode::PolicyExpired
        );
        assert_eq!(
            deny_reason_to_rpc_code_from_proto(ProtoDenyReason::Cooldown as i32),
            JsonRpcErrorCode::PolicyCooldown
        );
        assert_eq!(
            deny_reason_to_rpc_code_from_proto(ProtoDenyReason::PolicyMissing as i32),
            JsonRpcErrorCode::PolicyMissing
        );
        assert_eq!(
            deny_reason_to_rpc_code_from_proto(ProtoDenyReason::PasskeyForged as i32),
            JsonRpcErrorCode::Unauthorized
        );
        assert_eq!(
            deny_reason_to_rpc_code_from_proto(ProtoDenyReason::Unknown as i32),
            JsonRpcErrorCode::Internal
        );
    }

    #[test]
    fn extract_passkey_auth_returns_none_when_no_auth() {
        let params = json!({"wallet_id": "w1"});
        let result = WcMethodRouter::extract_passkey_auth(&params).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn extract_passkey_auth_returns_none_when_auth_is_null() {
        let params = json!({"wallet_id": "w1", "auth": null});
        let result = WcMethodRouter::extract_passkey_auth(&params).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn extract_passkey_auth_parses_valid_auth() {
        let params = json!({
            "auth": {
                "challenge_hex": "aabb",
                "signature_hex": "ccdd",
                "credential_id": "cred-1"
            }
        });
        let result = WcMethodRouter::extract_passkey_auth(&params).unwrap().unwrap();
        assert_eq!(result.challenge, vec![0xaa, 0xbb]);
        assert_eq!(result.signature, vec![0xcc, 0xdd]);
        assert_eq!(result.credential_id, "cred-1");
    }

    #[test]
    fn extract_passkey_auth_rejects_missing_challenge_hex() {
        let params = json!({
            "auth": {
                "signature_hex": "ccdd",
                "credential_id": "cred-1"
            }
        });
        let err = WcMethodRouter::extract_passkey_auth(&params).unwrap_err();
        assert_eq!(err.0, JsonRpcErrorCode::Unauthorized);
        assert!(err.1.contains("challenge_hex"));
    }

    #[test]
    fn extract_passkey_auth_rejects_missing_signature_hex() {
        let params = json!({
            "auth": {
                "challenge_hex": "aabb",
                "credential_id": "cred-1"
            }
        });
        let err = WcMethodRouter::extract_passkey_auth(&params).unwrap_err();
        assert_eq!(err.0, JsonRpcErrorCode::Unauthorized);
        assert!(err.1.contains("signature_hex"));
    }

    #[test]
    fn extract_passkey_auth_rejects_missing_credential_id() {
        let params = json!({
            "auth": {
                "challenge_hex": "aabb",
                "signature_hex": "ccdd"
            }
        });
        let err = WcMethodRouter::extract_passkey_auth(&params).unwrap_err();
        assert_eq!(err.0, JsonRpcErrorCode::Unauthorized);
        assert!(err.1.contains("credential_id"));
    }

    #[test]
    fn extract_passkey_auth_rejects_invalid_hex_challenge() {
        let params = json!({
            "auth": {
                "challenge_hex": "zzzz",
                "signature_hex": "ccdd",
                "credential_id": "cred-1"
            }
        });
        let err = WcMethodRouter::extract_passkey_auth(&params).unwrap_err();
        assert_eq!(err.0, JsonRpcErrorCode::Unauthorized);
        assert!(err.1.contains("challenge_hex"));
    }

    #[test]
    fn extract_passkey_auth_rejects_invalid_hex_signature() {
        let params = json!({
            "auth": {
                "challenge_hex": "aabb",
                "signature_hex": "not-hex",
                "credential_id": "cred-1"
            }
        });
        let err = WcMethodRouter::extract_passkey_auth(&params).unwrap_err();
        assert_eq!(err.0, JsonRpcErrorCode::Unauthorized);
        assert!(err.1.contains("signature_hex"));
    }

    #[test]
    fn extract_passkey_auth_rejects_non_string_challenge() {
        let params = json!({
            "auth": {
                "challenge_hex": 123,
                "signature_hex": "ccdd",
                "credential_id": "cred-1"
            }
        });
        let err = WcMethodRouter::extract_passkey_auth(&params).unwrap_err();
        assert_eq!(err.0, JsonRpcErrorCode::Unauthorized);
    }

    #[test]
    fn extract_passkey_auth_empty_challenge_hex_is_valid() {
        let params = json!({
            "auth": {
                "challenge_hex": "",
                "signature_hex": "ccdd",
                "credential_id": "cred-1"
            }
        });
        let result = WcMethodRouter::extract_passkey_auth(&params).unwrap().unwrap();
        assert!(result.challenge.is_empty());
    }

    // -----------------------------------------------------------------------
    // Session-metadata resolution (approval gate dApp name/origin)
    // -----------------------------------------------------------------------

    #[test]
    fn resolve_dapp_metadata_prefers_attached_values() {
        let key_agent = KeyAgentClient::new("/tmp/nonexistent.sock");
        let router = WcMethodRouter::new(key_agent)
            .with_sign_auth_mode(SignAuthMode::InternalToken(vec![7; 32]));
        let (name, origin) =
            router.resolve_dapp_metadata("topic-1", "Uniswap", "https://uniswap.org");
        assert_eq!(name, "Uniswap");
        assert_eq!(origin, "https://uniswap.org");
    }

    #[tokio::test]
    async fn resolve_dapp_metadata_falls_back_to_session_table() {
        let key_agent = KeyAgentClient::new("/tmp/nonexistent.sock");
        let sessions = Arc::new(tokio::sync::Mutex::new(oc_walletconnect::WcSessionTable::new()));
        let router = WcMethodRouter::new(key_agent).with_sessions(Arc::clone(&sessions));

        let mut session = oc_walletconnect::WcSession::new_pairing(
            "topic-auth".into(),
            "ab".repeat(32),
            u64::MAX,
        );
        session.dapp_name = Some("AuthDApp".into());
        session.dapp_origin = Some("https://iam.example.com".into());
        sessions.lock().await.insert(session);

        // Empty attached metadata → resolved from the shared table.
        let (name, origin) = router.resolve_dapp_metadata("topic-auth", "", "");
        assert_eq!(name, "AuthDApp");
        assert_eq!(origin, "https://iam.example.com");

        // Unknown topic → empty strings.
        let (name, origin) = router.resolve_dapp_metadata("unknown", "", "");
        assert_eq!(name, "");
        assert_eq!(origin, "");
    }

    // -----------------------------------------------------------------------
    // Mock Key-Agent over UDS: serves a canned response per request kind.
    // -----------------------------------------------------------------------

    /// Spawn a mock Key-Agent that answers `ListWallets` with a single-wallet
    /// listing and every other request with `canned`. Each accepted connection
    /// serves multiple requests (the client pools its connection, like the
    /// real Key-Agent's per-connection request loop).
    async fn spawn_mock_keyagent(
        sock_path: String,
        wallets: ListWalletsResponse,
        canned: Vec<u8>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let listener = tokio::net::UnixListener::bind(&sock_path).expect("bind mock keyagent");
            for _ in 0..3 {
                let (mut stream, _) = listener.accept().await.expect("accept mock keyagent");
                loop {
                    // Read one request frame.
                    let mut len_buf = [0u8; 4];
                    if stream.read_exact(&mut len_buf).await.is_err() {
                        break; // client closed the connection
                    }
                    let len = u32::from_be_bytes(len_buf);
                    let mut req_buf = vec![0u8; len as usize];
                    if stream.read_exact(&mut req_buf).await.is_err() {
                        break;
                    }
                    // Decode the request kind to pick the response payload.
                    let payload = match oc_keyagent::KeyAgentRequest::decode(req_buf.as_slice()) {
                        Ok(req)
                            if matches!(
                                req.kind,
                                Some(oc_keyagent::KeyAgentRequestKind::ListWallets(_))
                            ) =>
                        {
                            wallets.encode_to_vec()
                        }
                        _ => canned.clone(),
                    };
                    let resp = oc_keyagent::KeyAgentResponse::ok(payload);
                    let resp_bytes = resp.encode_to_vec();
                    if stream.write_all(&(resp_bytes.len() as u32).to_be_bytes()).await.is_err() {
                        break;
                    }
                    if stream.write_all(&resp_bytes).await.is_err() {
                        break;
                    }
                    if stream.flush().await.is_err() {
                        break;
                    }
                }
            }
        })
    }

    fn sample_list_wallets() -> ListWalletsResponse {
        ListWalletsResponse {
            wallets: vec![oc_keyagent::proto::WalletInfo {
                id: "w1".into(),
                name: "primary".into(),
                key_type: "mnemonic".into(),
                created_at: 0,
                accounts: vec![oc_keyagent::proto::WalletAccount {
                    account_id: "acc-1".into(),
                    address: "0x9858EfFD232B4033E47d90003D41EC34EcaEda94".into(),
                    chain_id: "eip155:1".into(),
                    derivation_path: "m/44'/60'/0'/0/0".into(),
                }],
            }],
        }
    }

    fn sample_sign_auth_response() -> oc_keyagent::proto::SignAuthResponse {
        oc_keyagent::proto::SignAuthResponse {
            signature: vec![0xAA; 65],
            address: "0x9858EfFD232B4033E47d90003D41EC34EcaEda94".into(),
            chain_id: "eip155:1".into(),
            public_key: vec![0x02; 33],
        }
    }

    #[tokio::test]
    async fn sign_auth_internal_token_mode_returns_expected_shape() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("ka.sock").to_string_lossy().to_string();
        let canned = sample_sign_auth_response().encode_to_vec();
        let _mock = spawn_mock_keyagent(sock.clone(), sample_list_wallets(), canned).await;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let key_agent = KeyAgentClient::new(&sock);
        let router = WcMethodRouter::new(key_agent)
            .with_sign_auth_mode(SignAuthMode::InternalToken(vec![7; 32]));
        // Approval mode is off by default → the gate passes through.
        let params = json!({
            "wallet_id": "w1",
            "chain_id": "eip155:1",
            "message": "Sign in to example service"
            // NOTE: daemon-internal mode injects an agent token instead of requiring auth.
        });
        let result = router.handle("onecipher_signAuth", params, "topic-1", None, None).await;
        let value = result.expect("signAuth must succeed in internal token mode");
        assert_eq!(value["address"], "0x9858EfFD232B4033E47d90003D41EC34EcaEda94");
        assert_eq!(value["chain_id"], "eip155:1");
        assert_eq!(value["signature"], format!("0x{}", hex::encode(vec![0xAA; 65])));
        assert_eq!(value["public_key"], format!("0x{}", hex::encode(vec![0x02; 33])));
    }

    #[tokio::test]
    async fn sign_auth_defaults_wallet_from_list_wallets() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("ka2.sock").to_string_lossy().to_string();
        let canned = sample_sign_auth_response().encode_to_vec();
        let _mock = spawn_mock_keyagent(sock.clone(), sample_list_wallets(), canned).await;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let key_agent = KeyAgentClient::new(&sock);
        let router = WcMethodRouter::new(key_agent)
            .with_sign_auth_mode(SignAuthMode::InternalToken(vec![7; 32]));
        // wallet_id omitted → resolved via ListWallets (first wallet).
        let params = json!({
            "chain_id": "eip155:1",
            "message": "hello"
        });
        let result = router.handle("onecipher_signAuth", params, "topic-2", None, None).await;
        assert!(result.is_ok(), "signAuth without wallet_id must succeed: {:?}", result.err());
        assert_eq!(result.unwrap()["address"], "0x9858EfFD232B4033E47d90003D41EC34EcaEda94");
    }

    #[tokio::test]
    async fn sign_auth_default_wallet_rejects_chain_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("ka-mismatch.sock").to_string_lossy().to_string();
        let canned = sample_sign_auth_response().encode_to_vec();
        let _mock = spawn_mock_keyagent(sock.clone(), sample_list_wallets(), canned).await;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let key_agent = KeyAgentClient::new(&sock);
        let router = WcMethodRouter::new(key_agent)
            .with_sign_auth_mode(SignAuthMode::InternalToken(vec![7; 32]));
        let params = json!({
            "chain_id": "solana:mainnet",
            "message": "hello"
        });
        let result =
            router.handle("onecipher_signAuth", params, "topic-mismatch", None, None).await;
        let (code, msg) = result.expect_err("chain mismatch must fail closed");
        assert_eq!(code, JsonRpcErrorCode::UnsupportedMethod);
        assert!(msg.contains("requested chain"));
    }

    #[tokio::test]
    async fn sign_auth_missing_message_is_rejected() {
        let key_agent = KeyAgentClient::new("/tmp/nonexistent.sock");
        let router = WcMethodRouter::new(key_agent);
        let params = json!({ "wallet_id": "w1", "chain_id": "eip155:1" });
        let result = router.handle("onecipher_signAuth", params, "t", None, None).await;
        assert!(result.is_err());
        let (code, msg) = result.unwrap_err();
        assert_eq!(code, JsonRpcErrorCode::UnsupportedMethod);
        assert!(msg.contains("message"));
    }

    // -----------------------------------------------------------------------
    // WC v2 Auth protocol (`wc_authRequest`) router tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn wc_auth_request_eip4361_builds_siwe_and_signs() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("ka3.sock").to_string_lossy().to_string();
        let canned = sample_sign_auth_response().encode_to_vec();
        let _mock = spawn_mock_keyagent(sock.clone(), sample_list_wallets(), canned).await;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let key_agent = KeyAgentClient::new(&sock);
        let router = WcMethodRouter::new(key_agent)
            .with_sign_auth_mode(SignAuthMode::InternalToken(vec![7; 32]));
        let params = json!({
            "type": "eip4361",
            "chainId": "eip155:1",
            "aud": "https://iam.example.com/login",
            "domain": "iam.example.com",
            "nonce": "a1b2c3d4e5f6g7h8",
            "statement": "Sign in with your wallet",
            "resources": ["https://iam.example.com/terms"]
        });
        let result =
            router.handle("wc_authRequest", params.clone(), "pairing-topic", None, None).await;
        let value = result.expect("wc_authRequest must succeed");
        // The signature is 0x-prefixed hex of the 65-byte canned signature.
        assert_eq!(value["signature"], format!("0x{}", hex::encode(vec![0xAA; 65])));
        // hash = keccak256 of the SIWE message for eip4361.
        let hash_hex = value["hash"].as_str().unwrap();
        assert!(hash_hex.starts_with("0x"));
        assert_eq!(hash_hex.len(), 2 + 64);
        // The original payload is echoed back verbatim.
        assert_eq!(value["payload"], params);
    }

    #[tokio::test]
    async fn wc_auth_request_eip191_signs_aud_nonce() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("ka4.sock").to_string_lossy().to_string();
        let canned = sample_sign_auth_response().encode_to_vec();
        let _mock = spawn_mock_keyagent(sock.clone(), sample_list_wallets(), canned).await;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let key_agent = KeyAgentClient::new(&sock);
        let router = WcMethodRouter::new(key_agent)
            .with_sign_auth_mode(SignAuthMode::InternalToken(vec![7; 32]));
        let params = json!({
            "type": "eip191",
            "chainId": "eip155:1",
            "aud": "https://iam.example.com",
            "domain": "iam.example.com",
            "nonce": "abcdefgh12345678"
        });
        let result =
            router.handle("wc_authRequest", params.clone(), "pairing-topic", None, None).await;
        let value = result.expect("eip191 auth must succeed");
        assert!(value["signature"].as_str().unwrap().starts_with("0x"));
        // sha256 fallback hash.
        let hash_hex = value["hash"].as_str().unwrap();
        assert_eq!(hash_hex.len(), 2 + 64);
        assert_eq!(value["payload"], params);
    }

    #[tokio::test]
    async fn wc_auth_request_non_evm_chain_is_method_not_supported() {
        let key_agent = KeyAgentClient::new("/tmp/nonexistent.sock");
        let router = WcMethodRouter::new(key_agent);
        let params = json!({
            "type": "eip4361",
            "chainId": "solana:mainnet",
            "aud": "https://iam.example.com",
            "domain": "iam.example.com",
            "nonce": "abcdefgh12345678"
        });
        let result = router.handle("wc_authRequest", params, "pairing-topic", None, None).await;
        let (code, msg) = result.unwrap_err();
        assert_eq!(code, JsonRpcErrorCode::UnsupportedMethod);
        assert!(msg.contains("non-EVM"));
    }

    #[tokio::test]
    async fn wc_auth_request_missing_required_fields_is_rejected() {
        let key_agent = KeyAgentClient::new("/tmp/nonexistent.sock");
        let router = WcMethodRouter::new(key_agent);
        // Missing nonce → validation error.
        let params = json!({
            "type": "eip4361",
            "chainId": "eip155:1",
            "aud": "https://iam.example.com",
            "domain": "iam.example.com"
        });
        let result = router.handle("wc_authRequest", params, "pairing-topic", None, None).await;
        assert!(result.is_err());
    }
}

#[cfg(test)]
mod sim_integration {
    use oc_core::{TokenDelta, TokenDirection, TxSimulation};

    use super::*;

    fn successful_sim() -> TxSimulation {
        TxSimulation {
            success: true,
            gas_used: 21000,
            balance_change: vec![TokenDelta {
                token: "ETH".into(),
                direction: TokenDirection::Send,
                amount: "0.1".into(),
            }],
            decoded_action: None,
            error: None,
        }
    }

    fn revert_sim() -> TxSimulation {
        TxSimulation {
            success: false,
            gas_used: 50000,
            balance_change: vec![],
            decoded_action: None,
            error: Some("execution reverted: insufficient balance".into()),
        }
    }

    #[test]
    fn success_path_populates_simulation_no_risk_bump() {
        let (sim, risk, reasons) = WcMethodRouter::apply_simulation_result(Ok(successful_sim()));
        assert!(sim.is_some());
        assert!(sim.unwrap().success);
        assert_eq!(risk, RiskLevel::Safe);
        assert!(reasons.is_empty());
    }

    #[test]
    fn revert_path_bumps_risk_to_danger() {
        let (sim, risk, reasons) = WcMethodRouter::apply_simulation_result(Ok(revert_sim()));
        assert!(sim.is_some());
        assert!(!sim.unwrap().success);
        assert_eq!(risk, RiskLevel::Danger);
        assert_eq!(reasons.len(), 1);
        assert_eq!(reasons[0].code, "sim_revert");
        assert_eq!(reasons[0].level, RiskLevel::Danger);
        assert_eq!(reasons[0].source, RiskSource::Simulation);
        assert!(reasons[0].message.contains("revert"));
    }

    #[test]
    fn failure_degrade_returns_none_simulation_with_warning() {
        let (sim, risk, reasons) = WcMethodRouter::apply_simulation_result(Err(
            crate::sim::SimError::NotAvailable("stub".into()),
        ));
        assert!(sim.is_none());
        assert_eq!(risk, RiskLevel::Warning);
        assert_eq!(reasons.len(), 1);
        assert_eq!(reasons[0].code, "sim_unavailable");
        assert_eq!(reasons[0].level, RiskLevel::Warning);
        assert_eq!(reasons[0].source, RiskSource::Simulation);
    }

    #[tokio::test]
    async fn approval_channel_receives_simulation_data() {
        let key_agent = KeyAgentClient::new("/tmp/nonexistent.sock");
        let (channel, mut rx) = ApprovalChannel::new(16);
        let mode = Arc::new(AtomicBool::new(true));
        let router =
            WcMethodRouter::with_approval(key_agent, channel, mode, Duration::from_secs(5), None);

        let sim = successful_sim();
        let handle = tokio::spawn(async move {
            router
                .maybe_gate_approval(
                    "eth_sendTransaction",
                    &json!({}),
                    "dapp",
                    "https://x.com",
                    "eip155:1",
                    RiskLevel::Safe,
                    vec![],
                    Some(sim),
                )
                .await
        });

        let (pending, resp_tx) = rx.recv().await.unwrap();
        assert!(pending.simulation.is_some());
        assert!(pending.simulation.unwrap().success);
        resp_tx.send(ApprovalDecision::Approve).unwrap();
        assert!(handle.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn danger_risk_from_revert_flows_to_approval() {
        let key_agent = KeyAgentClient::new("/tmp/nonexistent.sock");
        let (channel, mut rx) = ApprovalChannel::new(16);
        let mode = Arc::new(AtomicBool::new(true));
        let router =
            WcMethodRouter::with_approval(key_agent, channel, mode, Duration::from_secs(5), None);

        let sim = revert_sim();
        let reasons = vec![RiskReason {
            code: "sim_revert".into(),
            level: RiskLevel::Danger,
            message: "simulation indicates revert".into(),
            source: RiskSource::Simulation,
            detail: None,
        }];
        let handle = tokio::spawn(async move {
            router
                .maybe_gate_approval(
                    "eth_sendTransaction",
                    &json!({}),
                    "dapp",
                    "https://x.com",
                    "eip155:1",
                    RiskLevel::Danger,
                    reasons,
                    Some(sim),
                )
                .await
        });

        let (pending, resp_tx) = rx.recv().await.unwrap();
        assert_eq!(pending.risk, RiskLevel::Danger);
        assert_eq!(pending.risk_reasons.len(), 1);
        assert_eq!(pending.risk_reasons[0].code, "sim_revert");
        assert!(pending.simulation.is_some());
        assert!(!pending.simulation.unwrap().success);
        resp_tx.send(ApprovalDecision::Approve).unwrap();
        assert!(handle.await.unwrap().is_ok());
    }
}
