//! Policy Engine integration for the Key-Agent.
//!
//! Per R29 / AD-04: every `PayX402` / `SignUserOp` / `PayMPP` request MUST
//! pass through `oc_policy::evaluate_11_step` before signing. The
//! `PolicyState` is persisted (fsync + atomic rename, mode 0600) after
//! every decision — counters survive a process restart. On 3 consecutive
//! DENYs (R78), the in-process `AlertSink` is fired by
//! `oc_policy::PolicyState::record_deny` AND a `HUMAN_ALERT` audit entry
//! is appended here so the alert is durable in the append-only log (R76).
//!
//! Per R56 / R77: synchronous std only, NO tokio / reqwest / async.
//! `#![deny(unsafe_code)]` is preserved at the crate root — this module
//! uses zero `unsafe` blocks.
//!
//! Ponytail ladder: this module is step 4 (wrap existing dep `oc-policy`).
//! No new policy logic is introduced; we add only the integration glue
//! (load → evaluate → persist → audit → alert-on-3-DENYs) that the
//! Key-Agent runtime requires.

use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use oc_policy::{AlertSink, Decision, PayRequest, PolicyState, evaluate_11_step};

use crate::{
    audit::{AuditLog, EventType},
    error::KeyAgentError,
};

/// Policy integration wrapper. Owns the `PolicyState`, shares the
/// `AuditLog` via `Arc<Mutex<...>>`, and appends:
///  - one `PayX402` audit entry per ALLOW/DENY decision (R76)
///  - one `HumanAlert` audit entry when 3 consecutive DENYs fire the alert (R78)
///
/// Every `evaluate` call:
/// 1. Captures `prior_counter` + `prior_deny_reasons` so we can detect when the alert fires inside
///    `evaluate_11_step` (record_deny clears them on alert, so we must capture BEFORE the call).
/// 2. Runs `evaluate_11_step(&req, session_key_id, &mut self.state)`. `record_deny` inside this
///    function increments the counter and, when the counter hits 3, fires `AlertSink` and resets
///    the counter to 0.
/// 3. Persists `PolicyState` to `state_path` (fsync + atomic rename, mode 0600) — counters survive
///    a restart (R29 / AD-04 / C-09).
/// 4. Appends a `PayX402` audit entry with status `ALLOWED` / `DENIED`
///    + reason (R76 / C-07).
/// 5. If a 3rd-consecutive DENY fired the alert (detected via `prior_counter == 2 &&
///    current_counter == 0`), appends a `HumanAlert` audit entry carrying the 3 deny reasons (R78 /
///    C-10).
pub struct PolicyIntegration {
    state: PolicyState,
    state_path: PathBuf,
    audit: Arc<Mutex<AuditLog>>,
}

impl PolicyIntegration {
    /// Open the policy integration: load `PolicyState` from disk (or
    /// create a fresh state if the file does not exist), install the
    /// `AlertSink`, optionally attach a `PolicyV2`.
    ///
    /// The caller is responsible for loading `PolicyV2` from the policy
    /// store and passing it in (ponytail step 4 — no new policy logic
    /// here). If `policy` is `None`, step 2 of the 11-step flow returns
    /// `Deny(PolicyMissing)` for every request (R29 CL1 / C-08).
    ///
    /// The `state_path` file is created with mode 0600 on the first
    /// `persist` call (which happens inside `evaluate`). If the file
    /// already exists with a wrong mode, `PolicyState::load` warns and
    /// `PolicyState::persist` rewrites it with 0600.
    pub fn open(
        state_path: &Path,
        session_key_id: &str,
        policy: Option<oc_policy::PolicyV2>,
        audit: Arc<Mutex<AuditLog>>,
        alert_sink: Box<dyn AlertSink>,
    ) -> Result<Self, KeyAgentError> {
        let mut state = PolicyState::load(state_path, session_key_id.to_string())
            .map_err(|e| KeyAgentError::Internal(format!("policy state load failed: {e}")))?;
        // `PolicyState::load` deserializes alert_sink as the default
        // `LogAlertSink` (it is `#[serde(skip)]`). Replace it with the
        // caller-provided sink (which may be a `MockAlertSink` in tests
        // or a custom sink in production).
        state.alert_sink = alert_sink;
        if policy.is_some() {
            state.policy = policy;
        }
        Ok(Self { state, state_path: state_path.to_path_buf(), audit })
    }

    /// Evaluate a `PayRequest` against the policy. Persists state,
    /// writes an audit entry, and (on 3 consecutive DENYs) writes a
    /// `HUMAN_ALERT` audit entry. Returns the `Decision`.
    ///
    /// Per R29 / AD-04 / R76 / R78. Persistence + audit errors are
    /// logged to stderr but do NOT change the returned decision — the
    /// decision is the result of the policy evaluation, regardless of
    /// I/O outcomes. This matches the design contract: the caller
    /// receives the decision as evaluated, even if the audit log write
    /// failed (the next evaluate will retry the append-only write).
    pub fn evaluate(&mut self, req: &PayRequest, session_key_id: &str) -> Decision {
        // 1. Capture prior counter + reasons to detect alert firing. `record_deny` inside
        //    `evaluate_11_step` clears `last_deny_reasons` when it fires the alert, so we must
        //    snapshot them BEFORE the call.
        let prior_counter = self.state.consecutive_deny_counter;
        let prior_deny_reasons = self.state.last_deny_reasons.clone();

        // 2. Run the 11-step evaluation. `record_deny` inside this function fires `alert_sink` +
        //    resets the counter when the counter hits 3 (R78 / C-10).
        let decision = evaluate_11_step(req, session_key_id, &mut self.state);

        // 3. Persist PolicyState to disk (fsync + atomic rename, mode 0600). Errors are logged but
        //    do not change the decision.
        if let Err(e) = self.state.persist(&self.state_path) {
            eprintln!("[POLICY-WARN] state persist failed: {e}");
        }

        // 4. Write ALLOW/DENY audit entry (R76 / C-07).
        let mut audit_guard = self.audit.lock().expect("audit mutex poisoned");
        let status = match &decision {
            Decision::Allow | Decision::Warn(_) => "ALLOWED",
            Decision::Deny(_) => "DENIED",
        };
        let deny_reason_value = match &decision {
            Decision::Allow | Decision::Warn(_) => serde_json::Value::Null,
            Decision::Deny(r) => serde_json::to_value(r).unwrap_or(serde_json::Value::Null),
        };
        let payload = serde_json::json!({
            "session_key_id": session_key_id,
            "amount_usd": req.amount_usd,
            "asset": req.asset,
            "chain_id": req.chain_id,
            "recipient": req.recipient,
            "status": status,
            "deny_reason": deny_reason_value,
            "consecutive_deny_counter": self.state.consecutive_deny_counter,
        });
        if let Err(e) =
            audit_guard.append(EventType::PayX402, Some(session_key_id.to_string()), payload)
        {
            eprintln!("[POLICY-WARN] audit append failed: {e}");
        }

        // 5. Detect alert firing: prior counter was 2, this DENY brought it to 3, which
        //    `record_deny` detected and reset to 0. The 3 deny reasons are the prior 2 + the
        //    current one. Write a HUMAN_ALERT audit entry (R78) so the alert is durable.
        if let Decision::Deny(current_reason) = &decision {
            if prior_counter == 2 && self.state.consecutive_deny_counter == 0 {
                let mut all_reasons = prior_deny_reasons;
                all_reasons.push(current_reason.clone());
                let reasons_json: Vec<serde_json::Value> = all_reasons
                    .iter()
                    .map(|r| serde_json::to_value(r).unwrap_or(serde_json::Value::Null))
                    .collect();
                let alert_payload = serde_json::json!({
                    "session_key_id": session_key_id,
                    "device_id": req.device_id,
                    "deny_reasons": reasons_json,
                    "reason": "3 consecutive DENYs (R78)",
                });
                if let Err(e) = audit_guard.append(
                    EventType::HumanAlert,
                    Some(session_key_id.to_string()),
                    alert_payload,
                ) {
                    eprintln!("[POLICY-WARN] human_alert audit append failed: {e}");
                }
            }
        }

        decision
    }

    /// Current consecutive deny counter (for testing / observability).
    pub const fn consecutive_deny_counter(&self) -> u32 {
        self.state.consecutive_deny_counter
    }

    /// Borrow the underlying `PolicyState` mutably. Useful for setting
    /// `now_override` for deterministic tests, or for inspecting
    /// `local_spent_usd` after a restart in state-persistence tests.
    pub const fn state_mut(&mut self) -> &mut PolicyState {
        &mut self.state
    }
}
