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

use oc_core::{ChainIdExt, TxSimulation};
use oc_keyagent::{
    KeyAgentRequest, KeyAgentRequestKind, KeyAgentResponse, KeyAgentResponseKind,
    proto::{
        GenerateChallengeRequest, GetBalanceRequest, ListWalletsResponse, PasskeyAuthorization,
        PayX402Request, SignMessageRequest, SignTransactionRequest, SignTypedDataRequest,
        SignUserOpRequest,
    },
};
use oc_walletconnect::{
    WalletMethodHandler, jsonrpc::JsonRpcErrorCode, wallet_server::HandlerResult,
};
use prost::Message;
use serde_json::{Value, json};

use crate::{
    approval::{
        ApprovalChannel, ApprovalDecision, PendingApproval, RiskLevel, RiskReason, RiskSource,
    },
    approval_log::ApprovalLog,
    key_agent_client::KeyAgentClient,
};

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
        }
    }

    /// Attach a loaded `PolicyV2` for pre-signing risk evaluation (W2.1).
    pub fn with_policy(mut self, policy: oc_policy::PolicyV2) -> Self {
        self.policy = Some(policy);
        self
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

        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

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

        // Log pending
        if let Some(log) = &self.approval_log {
            if let Err(e) = log.append_pending(&pending).await {
                tracing::warn!(error = %e, "failed to log pending approval");
            }
        }

        let id = pending.id;
        let decision = approval_channel.request(pending, self.approval_timeout).await;

        // Log resolved
        if let Some(log) = &self.approval_log {
            let (decision_str, reason) = match &decision {
                ApprovalDecision::Approve => ("approved", String::new()),
                ApprovalDecision::Reject { reason } => ("rejected", reason.clone()),
                ApprovalDecision::Timeout => ("timeout", String::new()),
            };
            if let Err(e) = log.append_resolved(id, decision_str, &reason).await {
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
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
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

    #[allow(dead_code)] // ponytail: used by tests and future integration
    fn deny_reason_to_rpc_code(reason: &oc_policy::DenyReason) -> JsonRpcErrorCode {
        match reason {
            oc_policy::DenyReason::RateLimitMinute | oc_policy::DenyReason::RateLimitHour => {
                JsonRpcErrorCode::PolicyRateLimit
            }
            oc_policy::DenyReason::BudgetExceeded => JsonRpcErrorCode::PolicyBudgetExceeded,
            oc_policy::DenyReason::Whitelist => JsonRpcErrorCode::PolicyWhitelist,
            oc_policy::DenyReason::Expired => JsonRpcErrorCode::PolicyExpired,
            oc_policy::DenyReason::PasskeyForged => JsonRpcErrorCode::Unauthorized,
            oc_policy::DenyReason::PolicyMissing => JsonRpcErrorCode::PolicyMissing,
            oc_policy::DenyReason::Cooldown => JsonRpcErrorCode::PolicyCooldown,
            oc_policy::DenyReason::Unknown => JsonRpcErrorCode::Internal,
        }
    }

    /// Process simulation result into (simulation, risk_delta, risk_reasons_delta).
    ///
    /// - Success: pass through, no risk change.
    /// - Revert (sim.success == false): bump risk to Danger, add reason.
    /// - Error: return None simulation, warn (do NOT block signing).
    fn apply_simulation_result(
        result: Result<TxSimulation, oc_sim::SimError>,
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
                let code = match oc_keyagent::proto::DenyReason::try_from(d.reason)
                    .unwrap_or(oc_keyagent::proto::DenyReason::Unknown)
                {
                    oc_keyagent::proto::DenyReason::RateLimitMinute => {
                        JsonRpcErrorCode::PolicyRateLimit
                    }
                    oc_keyagent::proto::DenyReason::RateLimitHour => {
                        JsonRpcErrorCode::PolicyRateLimit
                    }
                    oc_keyagent::proto::DenyReason::BudgetExceeded => {
                        JsonRpcErrorCode::PolicyBudgetExceeded
                    }
                    oc_keyagent::proto::DenyReason::Whitelist => JsonRpcErrorCode::PolicyWhitelist,
                    oc_keyagent::proto::DenyReason::Expired => JsonRpcErrorCode::PolicyExpired,
                    oc_keyagent::proto::DenyReason::PasskeyForged => JsonRpcErrorCode::Unauthorized,
                    oc_keyagent::proto::DenyReason::PolicyMissing => {
                        JsonRpcErrorCode::PolicyMissing
                    }
                    oc_keyagent::proto::DenyReason::Cooldown => JsonRpcErrorCode::PolicyCooldown,
                    oc_keyagent::proto::DenyReason::Unknown => JsonRpcErrorCode::Internal,
                };
                Err((code, "policy denied".into()))
            }
            Some(KeyAgentResponseKind::Error(msg)) => Err((JsonRpcErrorCode::Signer, msg)),
            None => Err((JsonRpcErrorCode::Internal, "empty key-agent response".into())),
        }
    }
}

impl WalletMethodHandler for WcMethodRouter {
    fn handle<'a>(
        &'a self,
        method: &str,
        params: Value,
        _session_topic: &str,
    ) -> HandlerResult<'a> {
        let method = method.to_string();
        Box::pin(async move {
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
                    let wallet_id = params
                        .get("wallet_id")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            (JsonRpcErrorCode::UnsupportedMethod, "missing wallet_id".into())
                        })?
                        .to_string();
                    let chain_id = params
                        .get("chain_id")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            (JsonRpcErrorCode::UnsupportedMethod, "missing chain_id".into())
                        })?
                        .to_string();
                    let raw_tx_hex = params
                        .get("raw_tx_hex")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            (JsonRpcErrorCode::UnsupportedMethod, "missing raw_tx_hex".into())
                        })?
                        .to_string();
                    let session_key_id = params
                        .get("session_key_id")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();

                    // W2.1: Pre-signing policy evaluation
                    let (mut risk, mut risk_reasons) =
                        self.policy_evaluate_signing(&method, &params, &chain_id)?;

                    // W3.3: Simulate EVM transactions before approval
                    let simulation = {
                        let cid: Option<oc_core::ChainId> = chain_id.parse().ok();
                        if cid.as_ref().map_or(false, |c| c.is_evm()) {
                            let sim_result = oc_sim::simulate_evm_tx(&raw_tx_hex, &chain_id).await;
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
                        "",
                        "",
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
                    let wallet_id = params
                        .get("wallet_id")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            (JsonRpcErrorCode::UnsupportedMethod, "missing wallet_id".into())
                        })?
                        .to_string();
                    let message = params
                        .get("message")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            (JsonRpcErrorCode::UnsupportedMethod, "missing message".into())
                        })?
                        .as_bytes()
                        .to_vec();
                    let session_key_id = params
                        .get("session_key_id")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();

                    // W2.1: Pre-signing policy evaluation
                    let (risk, risk_reasons) =
                        self.policy_evaluate_signing(&method, &params, "")?;

                    // Web UI approval gate (W1.3)
                    self.maybe_gate_approval(
                        &method,
                        &params,
                        "",
                        "",
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

                "eth_signTypedData_v4" | "onecipher_signTypedData" => {
                    // P0-2: Passkey gate — signing RPCs require auth.
                    let auth = Self::extract_passkey_auth(&params)?.ok_or_else(|| {
                        (JsonRpcErrorCode::Unauthorized, "missing passkey authorization".into())
                    })?;
                    let wallet_id = params
                        .get("wallet_id")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            (JsonRpcErrorCode::UnsupportedMethod, "missing wallet_id".into())
                        })?
                        .to_string();
                    let typed_data_json = params
                        .get("typed_data_json")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            (JsonRpcErrorCode::UnsupportedMethod, "missing typed_data_json".into())
                        })?
                        .to_string();
                    let session_key_id = params
                        .get("session_key_id")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();

                    // W2.1: Pre-signing policy evaluation
                    let (risk, risk_reasons) =
                        self.policy_evaluate_signing(&method, &params, "")?;

                    // Web UI approval gate (W1.3)
                    self.maybe_gate_approval(
                        &method,
                        &params,
                        "",
                        "",
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
                    let wallet_id = params
                        .get("wallet_id")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            (JsonRpcErrorCode::UnsupportedMethod, "missing wallet_id".into())
                        })?
                        .to_string();
                    let chain_id = params
                        .get("chain_id")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            (JsonRpcErrorCode::UnsupportedMethod, "missing chain_id".into())
                        })?
                        .to_string();
                    let user_op_hex = params
                        .get("user_op_hex")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            (JsonRpcErrorCode::UnsupportedMethod, "missing user_op_hex".into())
                        })?
                        .to_string();
                    let session_key_id = params
                        .get("session_key_id")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();

                    // W2.1: Pre-signing policy evaluation
                    let (risk, risk_reasons) =
                        self.policy_evaluate_signing(&method, &params, &chain_id)?;

                    // Web UI approval gate (W1.3)
                    self.maybe_gate_approval(
                        &method,
                        &params,
                        "",
                        "",
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
                    let wallet_id = params
                        .get("wallet_id")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            (JsonRpcErrorCode::UnsupportedMethod, "missing wallet_id".into())
                        })?
                        .to_string();
                    let chain_id = params
                        .get("chain_id")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            (JsonRpcErrorCode::UnsupportedMethod, "missing chain_id".into())
                        })?
                        .to_string();
                    let req = GetBalanceRequest { wallet_id, chain_id };
                    let bytes = self.forward(KeyAgentRequestKind::GetBalance(req)).await?;
                    let resp: oc_keyagent::proto::BalanceResponse =
                        Message::decode(bytes.as_slice())
                            .map_err(|e| (JsonRpcErrorCode::Internal, format!("decode: {e}")))?;
                    Ok(
                        json!({"wallet_id": resp.wallet_id, "chain_id": resp.chain_id, "balance": resp.balance, "decimals": resp.decimals, "symbol": resp.symbol}),
                    )
                }

                "onecipher_payX402" => {
                    let session_key_id = params
                        .get("session_key_id")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            (JsonRpcErrorCode::UnsupportedMethod, "missing session_key_id".into())
                        })?
                        .to_string();
                    let url = params
                        .get("url")
                        .and_then(Value::as_str)
                        .ok_or_else(|| (JsonRpcErrorCode::UnsupportedMethod, "missing url".into()))?
                        .to_string();
                    let method =
                        params.get("method").and_then(Value::as_str).unwrap_or("GET").to_string();
                    let body = params
                        .get("body")
                        .and_then(Value::as_str)
                        .map(|b| b.as_bytes().to_vec())
                        .unwrap_or_default();
                    let headers = params
                        .get("headers")
                        .and_then(|v| serde_json::from_value(v.clone()).ok())
                        .unwrap_or_default();
                    let req = PayX402Request {
                        session_key_id,
                        url,
                        method,
                        body,
                        headers,
                        ..Default::default()
                    };
                    let bytes = self.forward(KeyAgentRequestKind::PayX402(req)).await?;
                    let resp: oc_keyagent::proto::PayX402Response =
                        Message::decode(bytes.as_slice())
                            .map_err(|e| (JsonRpcErrorCode::Internal, format!("decode: {e}")))?;
                    Ok(
                        json!({"status": resp.status, "receipt": resp.receipt, "retry_authorization": resp.retry_authorization, "deny_reason": resp.deny_reason, "error": resp.error}),
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
        let router = WcMethodRouter::new(key_agent);
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
        assert_eq!(
            WcMethodRouter::deny_reason_to_rpc_code(&oc_policy::DenyReason::RateLimitMinute),
            JsonRpcErrorCode::PolicyRateLimit
        );
        assert_eq!(
            WcMethodRouter::deny_reason_to_rpc_code(&oc_policy::DenyReason::BudgetExceeded),
            JsonRpcErrorCode::PolicyBudgetExceeded
        );
        assert_eq!(
            WcMethodRouter::deny_reason_to_rpc_code(&oc_policy::DenyReason::Whitelist),
            JsonRpcErrorCode::PolicyWhitelist
        );
        assert_eq!(
            WcMethodRouter::deny_reason_to_rpc_code(&oc_policy::DenyReason::Expired),
            JsonRpcErrorCode::PolicyExpired
        );
        assert_eq!(
            WcMethodRouter::deny_reason_to_rpc_code(&oc_policy::DenyReason::Cooldown),
            JsonRpcErrorCode::PolicyCooldown
        );
        assert_eq!(
            WcMethodRouter::deny_reason_to_rpc_code(&oc_policy::DenyReason::PolicyMissing),
            JsonRpcErrorCode::PolicyMissing
        );
        assert_eq!(
            WcMethodRouter::deny_reason_to_rpc_code(&oc_policy::DenyReason::PasskeyForged),
            JsonRpcErrorCode::Unauthorized
        );
        assert_eq!(
            WcMethodRouter::deny_reason_to_rpc_code(&oc_policy::DenyReason::Unknown),
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
            oc_sim::SimError::NotAvailable("stub".into()),
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
