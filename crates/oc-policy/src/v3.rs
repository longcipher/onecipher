//! Policy Engine v3 — Cedar-like attribute-based rules (§6.4).
//!
//! Extends v2 with a simplified Cedar-like rule evaluator. The full
//! `cedar-policy` crate is intentionally NOT used — it is heavy and would
//! risk violating R56 (`oc-policy` must stay free of async / network /
//! heavyweight dependencies). Instead, a small rule tree supports the key
//! Cedar patterns:
//! - `permit` / `forbid` effects
//! - `when`-style conditions (attribute comparisons, membership, AND/OR/NOT)
//! - `in` operator for whitelist membership
//!
//! Evaluation order: the v2 11-step flow runs first. If it denies, v3 rules
//! are skipped. If it allows, v3 rules are evaluated — any matching `Forbid`
//! rule overrides to `Deny`. If any `Permit` rules exist, at least one must
//! match for the decision to remain `Allow`.
//!
//! **Deviation note:** R80 caps `DenyReason` at exactly 9 variants, so a
//! dedicated `CedarRule` deny reason is not available; v3 rule denies reuse
//! `DenyReason::Unknown`.

use serde::{Deserialize, Serialize};

use crate::{
    v2::{Decision, DenyReason, PayRequest, PolicyState},
    wasm::{NoHostFacts, RegistryOutcome, StrategyRegistry, WasmEvalRequest, WasmHostCalls},
};

// ---------------------------------------------------------------------------
// Rule types
// ---------------------------------------------------------------------------

/// A Cedar-like policy rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub id: String,
    pub effect: RuleEffect,
    pub condition: RuleCondition,
    pub description: Option<String>,
}

/// Rule effect — `permit` or `forbid` in Cedar syntax.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RuleEffect {
    Permit,
    Forbid,
}

/// A simplified condition tree (Cedar-like `when` clause).
///
/// Tagged with `op` so it serializes to/from JSON as
/// `{"op": "Comparison", "field": ..., "operator": "==", "value": ...}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op")]
pub enum RuleCondition {
    /// `field op value` — e.g. `amount_usd <= 100`.
    Comparison { field: String, operator: ComparisonOp, value: serde_json::Value },
    /// `field in list` — e.g. `recipient in ["0xABC", "0xDEF"]`.
    Membership { field: String, values: Vec<serde_json::Value> },
    /// All conditions must be true (AND).
    All { conditions: Vec<Self> },
    /// Any condition must be true (OR).
    Any { conditions: Vec<Self> },
    /// Negation (NOT).
    Not { condition: Box<Self> },
    /// Constant `true` / `false`.
    Always { value: bool },
}

/// Comparison operators for [`RuleCondition::Comparison`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ComparisonOp {
    #[serde(rename = "==")]
    Eq,
    #[serde(rename = "!=")]
    Ne,
    #[serde(rename = "<")]
    Lt,
    #[serde(rename = "<=")]
    Le,
    #[serde(rename = ">")]
    Gt,
    #[serde(rename = ">=")]
    Ge,
}

// ---------------------------------------------------------------------------
// PolicyV3
// ---------------------------------------------------------------------------

/// Policy v3 — extends v2 with Cedar-like rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyV3 {
    /// The embedded v2 policy (run first).
    pub v2: crate::v2::PolicyV2,
    /// v3 Cedar-like rules. Evaluated after v2 allows.
    pub rules: Vec<PolicyRule>,
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

/// Evaluate a request against a v3 policy.
///
/// The v2 11-step evaluation runs first. If v2 denies, that decision is
/// returned immediately. If v2 allows, v3 rules are evaluated:
/// - Any matching `Forbid` rule overrides the decision to `Deny(Unknown)`.
/// - If any `Permit` rules exist, at least one must match for the decision to remain `Allow`;
///   otherwise the decision is `Deny(Unknown)`.
///
/// # Side effects
///
/// To run the v2 flow, the v2 portion of `policy` is temporarily injected
/// into `state.policy` for the duration of the v2 evaluation and restored
/// afterwards. Counter mutations performed by the v2 flow (e.g. `record_allow`)
/// persist in `state`. v3-level denies are NOT recorded as state transitions.
pub fn evaluate_v3(policy: &PolicyV3, request: &PayRequest, state: &mut PolicyState) -> Decision {
    // Inject the v2 policy so evaluate_11_step can find it, then restore the
    // previous value so the caller's state is not unexpectedly mutated.
    let prev_policy = state.policy.clone();
    state.policy = Some(policy.v2.clone());
    let v2_decision = crate::v2::evaluate_11_step(request, &policy.v2.session_key_id, state);
    state.policy = prev_policy;

    // If v2 denies, return immediately.
    if let Decision::Deny(reason) = &v2_decision {
        return Decision::Deny(reason.clone());
    }

    // Any matching Forbid rule overrides to Deny.
    for rule in &policy.rules {
        if rule.effect == RuleEffect::Forbid && evaluate_condition(&rule.condition, request) {
            // R80 caps `DenyReason` at exactly 9 variants, so a dedicated
            // Cedar-rule deny reason is unavailable. Preserve the rule
            // identity in the structured log before returning Unknown.
            tracing::warn!(
                target: "oc-policy::v3",
                rule_id = %rule.id,
                "Cedar Forbid rule matched; overriding decision to Deny"
            );
            return Decision::Deny(DenyReason::Unknown);
        }
    }

    // If there are Permit rules, at least one must match for Allow.
    let has_permit_rules = policy.rules.iter().any(|r| r.effect == RuleEffect::Permit);
    if has_permit_rules {
        let any_permit_matched = policy
            .rules
            .iter()
            .filter(|r| r.effect == RuleEffect::Permit)
            .any(|r| evaluate_condition(&r.condition, request));
        if !any_permit_matched {
            // No Permit rule matched. R80 has no Cedar-specific deny reason,
            // so log the context before returning Unknown.
            let permit_rule_ids: Vec<&str> = policy
                .rules
                .iter()
                .filter(|r| r.effect == RuleEffect::Permit)
                .map(|r| r.id.as_str())
                .collect();
            tracing::warn!(
                target: "oc-policy::v3",
                permit_rule_ids = ?permit_rule_ids,
                "No matching Cedar Permit rule; denying (R80 cap)"
            );
            return Decision::Deny(DenyReason::Unknown);
        }
    }

    // v2 allowed and no v3 forbid matched (and permit requirements met).
    v2_decision
}

/// Evaluate a condition tree against a request.
fn evaluate_condition(condition: &RuleCondition, request: &PayRequest) -> bool {
    match condition {
        RuleCondition::Always { value } => *value,
        RuleCondition::Comparison { field, operator, value } => {
            let field_value = get_field(request, field);
            compare_values(&field_value, operator, value)
        }
        RuleCondition::Membership { field, values } => {
            let field_value = get_field(request, field);
            values.iter().any(|v| v == &field_value)
        }
        RuleCondition::All { conditions } => {
            conditions.iter().all(|c| evaluate_condition(c, request))
        }
        RuleCondition::Any { conditions } => {
            conditions.iter().any(|c| evaluate_condition(c, request))
        }
        RuleCondition::Not { condition } => !evaluate_condition(condition, request),
    }
}

/// Get a field value from a `PayRequest` as a JSON value.
///
/// Supported fields: `amount_usd`, `asset`, `chain_id`, `session_key_id`,
/// `device_id`, `recipient`. Unknown fields resolve to `Null`.
fn get_field(request: &PayRequest, field: &str) -> serde_json::Value {
    match field {
        "amount_usd" => serde_json::json!(request.amount_usd),
        "asset" => serde_json::json!(request.asset),
        "chain_id" => serde_json::json!(request.chain_id),
        "session_key_id" => serde_json::json!(request.session_key_id),
        "device_id" => serde_json::json!(request.device_id),
        "recipient" => {
            request.recipient.as_ref().map_or(serde_json::Value::Null, |r| serde_json::json!(r))
        }
        _ => serde_json::Value::Null,
    }
}

/// Compare two JSON values with the given operator.
///
/// Numeric comparisons use `f64`. String comparisons support `==` / `!=`
/// only; ordering operators on strings return `false`. Mismatched types
/// return `false`.
fn compare_values(
    actual: &serde_json::Value,
    op: &ComparisonOp,
    expected: &serde_json::Value,
) -> bool {
    match (actual, expected) {
        (serde_json::Value::Number(a), serde_json::Value::Number(e)) => {
            let a = a.as_f64().unwrap_or(0.0);
            let e = e.as_f64().unwrap_or(0.0);
            match op {
                ComparisonOp::Eq => (a - e).abs() < f64::EPSILON,
                ComparisonOp::Ne => (a - e).abs() >= f64::EPSILON,
                ComparisonOp::Lt => a < e,
                ComparisonOp::Le => a <= e,
                ComparisonOp::Gt => a > e,
                ComparisonOp::Ge => a >= e,
            }
        }
        (serde_json::Value::String(a), serde_json::Value::String(e)) => match op {
            ComparisonOp::Eq => a == e,
            ComparisonOp::Ne => a != e,
            ComparisonOp::Lt | ComparisonOp::Le | ComparisonOp::Gt | ComparisonOp::Ge => false,
        },
        _ => false,
    }
}

/// Parse a Cedar-like v3 policy from JSON.
///
/// # Errors
///
/// Returns `serde_json::Error` if `json` is not a valid `PolicyV3`.
pub fn parse_policy_v3(json: &str) -> Result<PolicyV3, serde_json::Error> {
    serde_json::from_str(json)
}

// ---------------------------------------------------------------------------
// Wasm strategy plugin integration
// ---------------------------------------------------------------------------

/// The result of a v3 evaluation that also consulted the Wasm strategy
/// registry.
///
/// `Decision` alone cannot represent a strategy warning: [`crate::WarnReason`]
/// is a closed enum (R80 keeps it stable across the wire protocol) with no
/// free-form variant. Rather than widen it — which would ripple into the
/// x402 deny-reason wire mapping — strategy warnings are surfaced alongside
/// the decision in this struct. Callers that only care about allow/deny can
/// use [`StrategyDecision::decision`] and ignore the rest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrategyDecision {
    /// The final decision, after both the built-in pipeline and the plugins.
    pub decision: Decision,
    /// The plugin that blocked the request, as `(plugin, reason, message)`.
    pub denied_by: Option<(String, String, String)>,
    /// Non-blocking `(plugin, message)` warnings raised by plugins.
    pub warnings: Vec<(String, String)>,
    /// `(plugin, error)` pairs for plugins that failed to evaluate.
    ///
    /// A plugin failure is deliberately **not** a deny: a corrupt or
    /// mis-compiled strategy file must never brick the wallet. Failures are
    /// reported so the caller can write them to the audit log.
    pub errors: Vec<(String, String)>,
}

impl StrategyDecision {
    /// Whether the request was blocked, by any layer.
    pub fn is_denied(&self) -> bool {
        matches!(self.decision, Decision::Deny(_))
    }

    /// A decision produced without consulting any plugin.
    fn passthrough(decision: Decision) -> Self {
        Self { decision, denied_by: None, warnings: Vec::new(), errors: Vec::new() }
    }
}

/// Build the Wasm-facing request from a [`PayRequest`].
///
/// `method` is supplied by the caller because `PayRequest` is payment-shaped
/// and does not carry the originating JSON-RPC method.
pub fn wasm_request_from_pay(req: &PayRequest, method: &str) -> WasmEvalRequest {
    WasmEvalRequest {
        method: method.to_string(),
        chain_id: req.chain_id.clone(),
        amount_usd: req.amount_usd,
        asset: req.asset.clone(),
        recipient: req.recipient.clone().unwrap_or_default(),
        session_key_id: req.session_key_id.clone(),
        host_facts: serde_json::Value::Object(serde_json::Map::new()),
    }
}

/// Evaluate a request against a v3 policy **and** the Wasm strategy registry.
///
/// Ordering is deliberate and is the whole point of the design:
///
/// 1. The built-in v2 11-step pipeline and the v3 Cedar rules run first, via [`evaluate_v3`].
/// 2. **If they already deny, the plugins are not run at all.** An untrusted guest never observes a
///    request the core has already rejected, and a plugin can never *upgrade* a deny into an allow.
/// 3. Only on allow/warn are plugins consulted, deny-wins.
///
/// This makes the plugin layer strictly *additive* authority-wise: it can
/// tighten policy but never loosen it.
///
/// A plugin deny maps to [`DenyReason::Unknown`], for the same R80 reason that
/// v3 Cedar denies do; the plugin identity and reason string are preserved in
/// [`StrategyDecision::denied_by`] and in the structured log.
pub fn evaluate_v3_with_strategies(
    policy: &PolicyV3,
    request: &PayRequest,
    state: &mut PolicyState,
    registry: &StrategyRegistry,
    method: &str,
    host: &dyn WasmHostCalls,
) -> StrategyDecision {
    // Captured BEFORE evaluation: step 10 clears the deny streak on allow, and
    // we must restore it if a plugin later overturns that allow.
    let prior_counter = state.consecutive_deny_counter;
    let prior_reasons = state.last_deny_reasons.clone();

    let decision = evaluate_v3(policy, request, state);

    // Fail-closed short-circuit: never hand a already-denied request to a
    // guest, and never let a guest overturn a core deny.
    if matches!(decision, Decision::Deny(_)) || registry.is_empty() {
        return StrategyDecision::passthrough(decision);
    }

    let wasm_req = wasm_request_from_pay(request, method);
    let RegistryOutcome { denied_by, warnings, errors } = registry.evaluate(&wasm_req, host);

    for (plugin, message) in &warnings {
        tracing::warn!(
            target: "oc-policy::wasm",
            plugin = %plugin,
            message = %message,
            "strategy plugin raised a warning"
        );
    }
    for (plugin, error) in &errors {
        tracing::warn!(
            target: "oc-policy::wasm",
            plugin = %plugin,
            error = %error,
            "strategy plugin failed to evaluate; treated as non-blocking"
        );
    }

    let decision = if let Some((plugin, reason, message)) = &denied_by {
        tracing::warn!(
            target: "oc-policy::wasm",
            plugin = %plugin,
            reason = %reason,
            message = %message,
            "strategy plugin denied the request"
        );
        // The 11-step flow already committed an allow (spend + rate-limit
        // slots). Undo it, then record the deny so the R78 consecutive-deny
        // alert still fires — otherwise a plugin-denied burst would both
        // consume budget and never trip the alarm.
        let now_ms = state.now_ms();
        state.rollback_allow(request, now_ms, prior_counter, prior_reasons);
        state.record_deny(DenyReason::Unknown, &request.session_key_id, now_ms);
        Decision::Deny(DenyReason::Unknown)
    } else {
        decision
    };

    StrategyDecision { decision, denied_by, warnings, errors }
}

/// [`evaluate_v3_with_strategies`] with no host facts supplied to the guest.
pub fn evaluate_v3_with_registry(
    policy: &PolicyV3,
    request: &PayRequest,
    state: &mut PolicyState,
    registry: &StrategyRegistry,
    method: &str,
) -> StrategyDecision {
    evaluate_v3_with_strategies(policy, request, state, registry, method, &NoHostFacts)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v2::{BudgetAllocation, PolicyRulesV2, PolicyV2};

    // --- helpers ---

    fn base_v2_policy() -> PolicyV2 {
        PolicyV2 {
            version: 2,
            session_key_id: "sk-test".into(),
            device_id: "dev-test".into(),
            rules: PolicyRulesV2 {
                max_single_amount_usd: 10.0,
                max_daily_amount_usd: 100.0,
                max_monthly_amount_usd: 1000.0,
                expiry_unix: 999_999_999,
                rate_limit_per_minute: 10,
                rate_limit_per_hour: 100,
                cooldown_after_denial_sec: 0,
                asset_whitelist: vec!["USDC".into()],
                chain_whitelist: vec!["eip155:8453".into()],
                contract_whitelist: vec!["0xABC".into()],
                payment_protocols: vec!["x402".into()],
            },
            budget_allocation: BudgetAllocation {
                allocated_usd: 50.0,
                allocated_at_unix: 0,
                parent_total_usd: 1000.0,
                parent_session_id: "parent".into(),
            },
        }
    }

    fn test_request() -> PayRequest {
        PayRequest {
            session_key_id: "sk-test".into(),
            device_id: "dev-test".into(),
            amount_usd: 5.0,
            asset: "USDC".into(),
            chain_id: "eip155:8453".into(),
            recipient: Some("0xABC".into()),
        }
    }

    /// Fresh state with no policy attached (evaluate_v3 injects the v2 portion).
    fn fresh_state() -> PolicyState {
        PolicyState::new("sk-test".into()).with_now_override(1_000_000)
    }

    fn v3_policy(rules: Vec<PolicyRule>) -> PolicyV3 {
        PolicyV3 { v2: base_v2_policy(), rules }
    }

    fn forbid(id: &str, condition: RuleCondition) -> PolicyRule {
        PolicyRule { id: id.into(), effect: RuleEffect::Forbid, condition, description: None }
    }

    fn permit(id: &str, condition: RuleCondition) -> PolicyRule {
        PolicyRule { id: id.into(), effect: RuleEffect::Permit, condition, description: None }
    }

    fn cmp(field: &str, op: ComparisonOp, value: serde_json::Value) -> RuleCondition {
        RuleCondition::Comparison { field: field.into(), operator: op, value }
    }

    // --- baseline: no rules => v2 decision passes through ---

    #[test]
    fn test_no_rules_passes_through_v2_allow() {
        let policy = v3_policy(vec![]);
        let mut state = fresh_state();
        let decision = evaluate_v3(&policy, &test_request(), &mut state);
        assert_eq!(decision, Decision::Allow);
    }

    #[test]
    fn test_no_rules_passes_through_v2_deny() {
        // Tighten the single-amount cap so v2 denies.
        let mut v2 = base_v2_policy();
        v2.rules.max_single_amount_usd = 1.0;
        let policy = PolicyV3 { v2, rules: vec![] };
        let mut state = fresh_state();
        let decision = evaluate_v3(&policy, &test_request(), &mut state);
        assert_eq!(decision, Decision::Deny(DenyReason::BudgetExceeded));
    }

    // --- Forbid rule ---

    #[test]
    fn test_forbid_denies_when_condition_matches() {
        let rule =
            forbid("forbid-high", cmp("amount_usd", ComparisonOp::Gt, serde_json::json!(4.0)));
        let policy = v3_policy(vec![rule]);
        let mut state = fresh_state();
        // amount_usd = 5.0 > 4.0 => forbid matches
        let decision = evaluate_v3(&policy, &test_request(), &mut state);
        assert_eq!(decision, Decision::Deny(DenyReason::Unknown));
    }

    #[test]
    fn test_forbid_does_not_deny_when_condition_not_matched() {
        let rule =
            forbid("forbid-high", cmp("amount_usd", ComparisonOp::Gt, serde_json::json!(100.0)));
        let policy = v3_policy(vec![rule]);
        let mut state = fresh_state();
        // amount_usd = 5.0 > 100.0 => false => forbid does not match
        let decision = evaluate_v3(&policy, &test_request(), &mut state);
        assert_eq!(decision, Decision::Allow);
    }

    // --- Permit rule ---

    #[test]
    fn test_permit_required_no_match_denies() {
        // Permit only allows ETH, but request is USDC => no permit match => deny.
        let rule = permit("permit-eth", cmp("asset", ComparisonOp::Eq, serde_json::json!("ETH")));
        let policy = v3_policy(vec![rule]);
        let mut state = fresh_state();
        let decision = evaluate_v3(&policy, &test_request(), &mut state);
        assert_eq!(decision, Decision::Deny(DenyReason::Unknown));
    }

    #[test]
    fn test_permit_match_allows() {
        let rule = permit("permit-usdc", cmp("asset", ComparisonOp::Eq, serde_json::json!("USDC")));
        let policy = v3_policy(vec![rule]);
        let mut state = fresh_state();
        let decision = evaluate_v3(&policy, &test_request(), &mut state);
        assert_eq!(decision, Decision::Allow);
    }

    #[test]
    fn test_permit_any_one_matches_allows() {
        let rules = vec![
            permit("p1", cmp("asset", ComparisonOp::Eq, serde_json::json!("ETH"))),
            permit("p2", cmp("chain_id", ComparisonOp::Eq, serde_json::json!("eip155:8453"))),
        ];
        let policy = v3_policy(rules);
        let mut state = fresh_state();
        let decision = evaluate_v3(&policy, &test_request(), &mut state);
        assert_eq!(decision, Decision::Allow);
    }

    #[test]
    fn test_forbid_overrides_permit_match() {
        let rules = vec![
            permit("p1", RuleCondition::Always { value: true }),
            forbid("f1", cmp("amount_usd", ComparisonOp::Gt, serde_json::json!(1.0))),
        ];
        let policy = v3_policy(rules);
        let mut state = fresh_state();
        let decision = evaluate_v3(&policy, &test_request(), &mut state);
        assert_eq!(decision, Decision::Deny(DenyReason::Unknown));
    }

    // --- AND / OR / NOT ---

    #[test]
    fn test_and_all_true() {
        let cond = RuleCondition::All {
            conditions: vec![
                cmp("amount_usd", ComparisonOp::Gt, serde_json::json!(1.0)),
                cmp("asset", ComparisonOp::Eq, serde_json::json!("USDC")),
            ],
        };
        let policy = v3_policy(vec![forbid("f", cond)]);
        let mut state = fresh_state();
        let decision = evaluate_v3(&policy, &test_request(), &mut state);
        assert_eq!(decision, Decision::Deny(DenyReason::Unknown));
    }

    #[test]
    fn test_and_one_false() {
        let cond = RuleCondition::All {
            conditions: vec![
                cmp("amount_usd", ComparisonOp::Gt, serde_json::json!(1.0)),
                cmp("asset", ComparisonOp::Eq, serde_json::json!("ETH")), // false
            ],
        };
        let policy = v3_policy(vec![forbid("f", cond)]);
        let mut state = fresh_state();
        let decision = evaluate_v3(&policy, &test_request(), &mut state);
        assert_eq!(decision, Decision::Allow);
    }

    #[test]
    fn test_or_one_true() {
        let cond = RuleCondition::Any {
            conditions: vec![
                cmp("asset", ComparisonOp::Eq, serde_json::json!("ETH")), // false
                cmp("chain_id", ComparisonOp::Eq, serde_json::json!("eip155:8453")), // true
            ],
        };
        let policy = v3_policy(vec![forbid("f", cond)]);
        let mut state = fresh_state();
        let decision = evaluate_v3(&policy, &test_request(), &mut state);
        assert_eq!(decision, Decision::Deny(DenyReason::Unknown));
    }

    #[test]
    fn test_or_all_false() {
        let cond = RuleCondition::Any {
            conditions: vec![
                cmp("asset", ComparisonOp::Eq, serde_json::json!("ETH")),
                cmp("chain_id", ComparisonOp::Eq, serde_json::json!("eip155:1")),
            ],
        };
        let policy = v3_policy(vec![forbid("f", cond)]);
        let mut state = fresh_state();
        let decision = evaluate_v3(&policy, &test_request(), &mut state);
        assert_eq!(decision, Decision::Allow);
    }

    #[test]
    fn test_not_negates_true_to_false() {
        // NOT(amount_usd > 1.0) => NOT(true) => false => forbid does not match
        let cond = RuleCondition::Not {
            condition: Box::new(cmp("amount_usd", ComparisonOp::Gt, serde_json::json!(1.0))),
        };
        let policy = v3_policy(vec![forbid("f", cond)]);
        let mut state = fresh_state();
        let decision = evaluate_v3(&policy, &test_request(), &mut state);
        assert_eq!(decision, Decision::Allow);
    }

    #[test]
    fn test_not_negates_false_to_true() {
        // NOT(asset == "ETH") => NOT(false) => true => forbid matches
        let cond = RuleCondition::Not {
            condition: Box::new(cmp("asset", ComparisonOp::Eq, serde_json::json!("ETH"))),
        };
        let policy = v3_policy(vec![forbid("f", cond)]);
        let mut state = fresh_state();
        let decision = evaluate_v3(&policy, &test_request(), &mut state);
        assert_eq!(decision, Decision::Deny(DenyReason::Unknown));
    }

    // --- comparison operators ---

    #[test]
    fn test_comparison_eq_number() {
        let policy = v3_policy(vec![permit(
            "p",
            cmp("amount_usd", ComparisonOp::Eq, serde_json::json!(5.0)),
        )]);
        let mut state = fresh_state();
        assert_eq!(evaluate_v3(&policy, &test_request(), &mut state), Decision::Allow);
    }

    #[test]
    fn test_comparison_ne_number() {
        let policy = v3_policy(vec![permit(
            "p",
            cmp("amount_usd", ComparisonOp::Ne, serde_json::json!(6.0)),
        )]);
        let mut state = fresh_state();
        assert_eq!(evaluate_v3(&policy, &test_request(), &mut state), Decision::Allow);
    }

    #[test]
    fn test_comparison_lt() {
        let policy = v3_policy(vec![permit(
            "p",
            cmp("amount_usd", ComparisonOp::Lt, serde_json::json!(10.0)),
        )]);
        let mut state = fresh_state();
        assert_eq!(evaluate_v3(&policy, &test_request(), &mut state), Decision::Allow);
    }

    #[test]
    fn test_comparison_le() {
        let policy = v3_policy(vec![permit(
            "p",
            cmp("amount_usd", ComparisonOp::Le, serde_json::json!(5.0)),
        )]);
        let mut state = fresh_state();
        assert_eq!(evaluate_v3(&policy, &test_request(), &mut state), Decision::Allow);
    }

    #[test]
    fn test_comparison_gt() {
        let policy = v3_policy(vec![permit(
            "p",
            cmp("amount_usd", ComparisonOp::Gt, serde_json::json!(1.0)),
        )]);
        let mut state = fresh_state();
        assert_eq!(evaluate_v3(&policy, &test_request(), &mut state), Decision::Allow);
    }

    #[test]
    fn test_comparison_ge() {
        let policy = v3_policy(vec![permit(
            "p",
            cmp("amount_usd", ComparisonOp::Ge, serde_json::json!(5.0)),
        )]);
        let mut state = fresh_state();
        assert_eq!(evaluate_v3(&policy, &test_request(), &mut state), Decision::Allow);
    }

    #[test]
    fn test_comparison_eq_string() {
        let policy =
            v3_policy(vec![permit("p", cmp("asset", ComparisonOp::Eq, serde_json::json!("USDC")))]);
        let mut state = fresh_state();
        assert_eq!(evaluate_v3(&policy, &test_request(), &mut state), Decision::Allow);
    }

    #[test]
    fn test_comparison_string_ordering_returns_false() {
        // String with an ordering operator => always false => permit no match => deny.
        let policy =
            v3_policy(vec![permit("p", cmp("asset", ComparisonOp::Gt, serde_json::json!("AAA")))]);
        let mut state = fresh_state();
        assert_eq!(
            evaluate_v3(&policy, &test_request(), &mut state),
            Decision::Deny(DenyReason::Unknown)
        );
    }

    // --- membership (in) ---

    #[test]
    fn test_membership_present() {
        let cond = RuleCondition::Membership {
            field: "recipient".into(),
            values: vec![serde_json::json!("0xABC"), serde_json::json!("0xDEF")],
        };
        let policy = v3_policy(vec![permit("p", cond)]);
        let mut state = fresh_state();
        assert_eq!(evaluate_v3(&policy, &test_request(), &mut state), Decision::Allow);
    }

    #[test]
    fn test_membership_absent() {
        let cond = RuleCondition::Membership {
            field: "recipient".into(),
            values: vec![serde_json::json!("0xDEF"), serde_json::json!("0x123")],
        };
        let policy = v3_policy(vec![permit("p", cond)]);
        let mut state = fresh_state();
        assert_eq!(
            evaluate_v3(&policy, &test_request(), &mut state),
            Decision::Deny(DenyReason::Unknown)
        );
    }

    #[test]
    fn test_membership_chain_id() {
        let cond = RuleCondition::Membership {
            field: "chain_id".into(),
            values: vec![serde_json::json!("eip155:1"), serde_json::json!("eip155:8453")],
        };
        let policy = v3_policy(vec![permit("p", cond)]);
        let mut state = fresh_state();
        assert_eq!(evaluate_v3(&policy, &test_request(), &mut state), Decision::Allow);
    }

    // --- Always ---

    #[test]
    fn test_always_true() {
        let policy = v3_policy(vec![permit("p", RuleCondition::Always { value: true })]);
        let mut state = fresh_state();
        assert_eq!(evaluate_v3(&policy, &test_request(), &mut state), Decision::Allow);
    }

    #[test]
    fn test_always_false() {
        let policy = v3_policy(vec![permit("p", RuleCondition::Always { value: false })]);
        let mut state = fresh_state();
        assert_eq!(
            evaluate_v3(&policy, &test_request(), &mut state),
            Decision::Deny(DenyReason::Unknown)
        );
    }

    // --- nested complex condition ---

    #[test]
    fn test_nested_complex_condition() {
        // (amount > 1 AND asset == "USDC") OR NOT(recipient in blacklist)
        // For the test request: (5>1 AND USDC==USDC) is true => whole OR is true.
        let cond = RuleCondition::Any {
            conditions: vec![
                RuleCondition::All {
                    conditions: vec![
                        cmp("amount_usd", ComparisonOp::Gt, serde_json::json!(1.0)),
                        cmp("asset", ComparisonOp::Eq, serde_json::json!("USDC")),
                    ],
                },
                RuleCondition::Not {
                    condition: Box::new(RuleCondition::Membership {
                        field: "recipient".into(),
                        values: vec![serde_json::json!("0xBAD")],
                    }),
                },
            ],
        };
        let policy = v3_policy(vec![forbid("f", cond)]);
        let mut state = fresh_state();
        let decision = evaluate_v3(&policy, &test_request(), &mut state);
        assert_eq!(decision, Decision::Deny(DenyReason::Unknown));
    }

    // --- JSON round-trip ---

    #[test]
    fn test_policy_v3_json_roundtrip() {
        let policy = v3_policy(vec![
            forbid("f1", cmp("amount_usd", ComparisonOp::Gt, serde_json::json!(100.0))),
            permit(
                "p1",
                RuleCondition::Membership {
                    field: "asset".into(),
                    values: vec![serde_json::json!("USDC"), serde_json::json!("ETH")],
                },
            ),
        ]);
        let json = serde_json::to_string(&policy).expect("serialize");
        let parsed: PolicyV3 = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.rules.len(), 2);
        assert_eq!(parsed.rules[0].effect, RuleEffect::Forbid);
        assert_eq!(parsed.rules[1].effect, RuleEffect::Permit);
        // State is not part of PolicyV3; check the v2 portion round-trips.
        assert_eq!(parsed.v2.session_key_id, "sk-test");
    }

    #[test]
    fn test_parse_policy_v3_from_json() {
        let json = r#"{
            "v2": {
                "version": 2,
                "session_key_id": "sk-test",
                "device_id": "dev-test",
                "rules": {
                    "max_single_amount_usd": 10.0,
                    "max_daily_amount_usd": 100.0,
                    "max_monthly_amount_usd": 1000.0,
                    "expiry_unix": 999999999,
                    "rate_limit_per_minute": 10,
                    "rate_limit_per_hour": 100,
                    "cooldown_after_denial_sec": 0,
                    "asset_whitelist": ["USDC"],
                    "chain_whitelist": ["eip155:8453"],
                    "contract_whitelist": ["0xABC"],
                    "payment_protocols": ["x402"]
                },
                "budget_allocation": {
                    "allocated_usd": 50.0,
                    "allocated_at_unix": 0,
                    "parent_total_usd": 1000.0,
                    "parent_session_id": "parent"
                }
            },
            "rules": [
                {
                    "id": "forbid-high",
                    "effect": "Forbid",
                    "condition": {
                        "op": "Comparison",
                        "field": "amount_usd",
                        "operator": ">",
                        "value": 4.0
                    },
                    "description": null
                }
            ]
        }"#;
        let policy = parse_policy_v3(json).expect("parse");
        assert_eq!(policy.rules.len(), 1);
        assert_eq!(policy.rules[0].effect, RuleEffect::Forbid);

        let mut state = fresh_state();
        // amount_usd = 5.0 > 4.0 => forbid matches => deny
        let decision = evaluate_v3(&policy, &test_request(), &mut state);
        assert_eq!(decision, Decision::Deny(DenyReason::Unknown));
    }

    // --- Wasm strategy registry integration --------------------------------

    // The canned JSON blobs the guest returns. They are declared here (rather
    // than only inside the WAT) so the `(i32.const <len>)` operands can be
    // generated from `.len()` instead of hand-counted — an off-by-one there
    // truncates the JSON and silently turns a deny into a parse error.
    const CANNED_ALLOW: &str = r#"{"outcome":"allow"}"#;
    const CANNED_DENY: &str = r#"{"outcome":"deny","reason":"marker","message":"blocked"}"#;
    const CANNED_WARN: &str = r#"{"outcome":"warn","message":"suspicious"}"#;

    /// Escape a JSON string for embedding in a WAT `(data ...)` segment.
    fn wat_escape(s: &str) -> String {
        s.replace('\\', r"\\").replace('"', r#"\""#)
    }

    /// Build the marker guest's WAT with the data segments and their lengths
    /// both derived from [`CANNED_ALLOW`] / [`CANNED_DENY`] / [`CANNED_WARN`],
    /// so the two can never disagree.
    ///
    /// The guest denies iff the request JSON contains the byte sequence
    /// `DENYME`, and warns iff it contains `WARNME`. Implements ABI v1.
    fn marker_wat() -> String {
        // Segment offsets. 64 B of slack after each blob keeps them from
        // overlapping if a message is edited.
        const ALLOW_AT: usize = 1024;
        const DENY_AT: usize = 1152;
        const WARN_AT: usize = 1280;
        assert!(ALLOW_AT + CANNED_ALLOW.len() < DENY_AT, "allow blob overruns the deny segment");
        assert!(DENY_AT + CANNED_DENY.len() < WARN_AT, "deny blob overruns the warn segment");

        MARKER_WAT_TEMPLATE
            .replace("@ALLOW_AT@", &ALLOW_AT.to_string())
            .replace("@DENY_AT@", &DENY_AT.to_string())
            .replace("@WARN_AT@", &WARN_AT.to_string())
            .replace("@ALLOW_LEN@", &CANNED_ALLOW.len().to_string())
            .replace("@DENY_LEN@", &CANNED_DENY.len().to_string())
            .replace("@WARN_LEN@", &CANNED_WARN.len().to_string())
            .replace("@ALLOW@", &wat_escape(CANNED_ALLOW))
            .replace("@DENY@", &wat_escape(CANNED_DENY))
            .replace("@WARN@", &wat_escape(CANNED_WARN))
    }

    const MARKER_WAT_TEMPLATE: &str = r#"
(module
  (memory (export "memory") 1)
  (data (i32.const @ALLOW_AT@) "@ALLOW@")
  (data (i32.const @DENY_AT@) "@DENY@")
  (data (i32.const @WARN_AT@) "@WARN@")
  (global $cursor (mut i32) (i32.const 64))

  (func (export "oc_alloc") (param $n i32) (result i32)
    (local $ptr i32)
    (local.set $ptr (global.get $cursor))
    (global.set $cursor (i32.add (global.get $cursor) (local.get $n)))
    (local.get $ptr))

  ;; Search [ptr, ptr+len) for a 6-byte needle whose bytes are $a..$f.
  (func $find6 (param $ptr i32) (param $len i32)
                (param $a i32) (param $b i32) (param $c i32)
                (param $d i32) (param $e i32) (param $f i32) (result i32)
    (local $i i32) (local $p i32)
    (if (i32.lt_s (local.get $len) (i32.const 6)) (then (return (i32.const 0))))
    (block $done
      (loop $scan
        (br_if $done (i32.gt_s (local.get $i) (i32.sub (local.get $len) (i32.const 6))))
        (local.set $p (i32.add (local.get $ptr) (local.get $i)))
        (if (i32.and
              (i32.eq (i32.load8_u (local.get $p)) (local.get $a))
              (i32.and
                (i32.eq (i32.load8_u offset=1 (local.get $p)) (local.get $b))
                (i32.and
                  (i32.eq (i32.load8_u offset=2 (local.get $p)) (local.get $c))
                  (i32.and
                    (i32.eq (i32.load8_u offset=3 (local.get $p)) (local.get $d))
                    (i32.and
                      (i32.eq (i32.load8_u offset=4 (local.get $p)) (local.get $e))
                      (i32.eq (i32.load8_u offset=5 (local.get $p)) (local.get $f)))))))
          (then (return (i32.const 1))))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $scan)))
    (i32.const 0))

  (func $pack (param $ptr i32) (param $len i32) (result i64)
    (i64.or (i64.shl (i64.extend_i32_u (local.get $ptr)) (i64.const 32))
            (i64.extend_i32_u (local.get $len))))

  (func (export "oc_evaluate") (param $ptr i32) (param $len i32) (result i64)
    ;; DENYME = 68 69 78 89 77 69
    (if (result i64)
        (call $find6 (local.get $ptr) (local.get $len)
              (i32.const 68) (i32.const 69) (i32.const 78)
              (i32.const 89) (i32.const 77) (i32.const 69))
      (then (call $pack (i32.const @DENY_AT@) (i32.const @DENY_LEN@)))
      (else
        ;; WARNME = 87 65 82 78 77 69
        (if (result i64)
            (call $find6 (local.get $ptr) (local.get $len)
                  (i32.const 87) (i32.const 65) (i32.const 82)
                  (i32.const 78) (i32.const 77) (i32.const 69))
          (then (call $pack (i32.const @WARN_AT@) (i32.const @WARN_LEN@)))
          (else (call $pack (i32.const @ALLOW_AT@) (i32.const @ALLOW_LEN@))))))))
"#;

    fn marker_registry() -> StrategyRegistry {
        let mut registry = StrategyRegistry::new();
        registry.insert(
            crate::wasm::StrategyPlugin::from_wat("marker", &marker_wat())
                .expect("the marker guest must compile"),
        );
        registry
    }

    /// The canned blobs must be valid `StrategyOutcome` JSON, and the template
    /// must have no unsubstituted placeholders left.
    #[test]
    fn marker_guest_canned_blobs_are_valid_outcomes() {
        use crate::wasm::StrategyOutcome;
        assert_eq!(
            serde_json::from_str::<StrategyOutcome>(CANNED_ALLOW).unwrap(),
            StrategyOutcome::Allow
        );
        assert_eq!(
            serde_json::from_str::<StrategyOutcome>(CANNED_DENY).unwrap(),
            StrategyOutcome::Deny { reason: "marker".into(), message: "blocked".into() }
        );
        assert_eq!(
            serde_json::from_str::<StrategyOutcome>(CANNED_WARN).unwrap(),
            StrategyOutcome::Warn { message: "suspicious".into() }
        );
        assert!(!marker_wat().contains('@'), "an ABI placeholder was left unsubstituted");
    }

    #[test]
    fn empty_registry_is_a_passthrough() {
        let policy = v3_policy(vec![]);
        let mut state = fresh_state();
        let out = evaluate_v3_with_registry(
            &policy,
            &test_request(),
            &mut state,
            &StrategyRegistry::new(),
            "eth_sendTransaction",
        );
        assert_eq!(out.decision, Decision::Allow);
        assert!(!out.is_denied());
        assert!(out.denied_by.is_none());
        assert!(out.warnings.is_empty());
        assert!(out.errors.is_empty());
    }

    #[test]
    fn plugin_allow_leaves_core_decision_intact() {
        let policy = v3_policy(vec![]);
        let mut state = fresh_state();
        let out = evaluate_v3_with_registry(
            &policy,
            &test_request(),
            &mut state,
            &marker_registry(),
            "eth_sendTransaction",
        );
        assert_eq!(out.decision, Decision::Allow);
        assert!(out.warnings.is_empty());
    }

    #[test]
    fn plugin_can_deny_a_request_the_core_allowed() {
        let policy = v3_policy(vec![]);
        let mut state = fresh_state();
        let mut req = test_request();
        req.recipient = Some("0xDENYME".into());
        // The core allows: 0xDENYME is not in `contract_whitelist`... it must
        // be, or step 4 would deny for the wrong reason. Widen the whitelist.
        let mut policy = policy;
        policy.v2.rules.contract_whitelist.push("0xDENYME".into());

        let out = evaluate_v3_with_registry(
            &policy,
            &req,
            &mut state,
            &marker_registry(),
            "eth_sendTransaction",
        );
        assert_eq!(out.decision, Decision::Deny(DenyReason::Unknown));
        let (plugin, reason, _) = out.denied_by.expect("plugin identity must be preserved");
        assert_eq!(plugin, "marker");
        assert_eq!(reason, "marker");
    }

    #[test]
    fn plugin_warning_does_not_block() {
        let mut policy = v3_policy(vec![]);
        policy.v2.rules.contract_whitelist.push("0xWARNME".into());
        let mut req = test_request();
        req.recipient = Some("0xWARNME".into());
        let mut state = fresh_state();

        let out = evaluate_v3_with_registry(
            &policy,
            &req,
            &mut state,
            &marker_registry(),
            "eth_sendTransaction",
        );
        assert_eq!(out.decision, Decision::Allow, "a warn must not block");
        assert_eq!(out.warnings, vec![("marker".to_string(), "suspicious".to_string())]);
    }

    #[test]
    fn plugins_are_not_consulted_when_the_core_denies() {
        // Tighten the cap so v2 denies, and use a recipient that WOULD trip
        // the plugin. The plugin must never see it, so `denied_by` stays None
        // and the deny reason stays the core's, not `Unknown`.
        let mut v2 = base_v2_policy();
        v2.rules.max_single_amount_usd = 1.0;
        v2.rules.contract_whitelist.push("0xDENYME".into());
        let policy = PolicyV3 { v2, rules: vec![] };
        let mut req = test_request();
        req.recipient = Some("0xDENYME".into());
        let mut state = fresh_state();

        let out = evaluate_v3_with_registry(
            &policy,
            &req,
            &mut state,
            &marker_registry(),
            "eth_sendTransaction",
        );
        assert_eq!(out.decision, Decision::Deny(DenyReason::BudgetExceeded));
        assert!(out.denied_by.is_none(), "the guest must not observe an already-denied request");
    }

    #[test]
    fn a_broken_plugin_does_not_brick_the_wallet() {
        // A guest that imports a host function cannot instantiate against the
        // empty linker. That is an error, not a deny.
        let mut registry = StrategyRegistry::new();
        registry.insert(
            crate::wasm::StrategyPlugin::from_wat(
                "evil",
                r#"(module
  (import "env" "exfiltrate" (func $x (param i32 i32)))
  (memory (export "memory") 1)
  (func (export "oc_alloc") (param i32) (result i32) (i32.const 64))
  (func (export "oc_evaluate") (param i32 i32) (result i64) (i64.const 0)))"#,
            )
            .unwrap(),
        );
        let policy = v3_policy(vec![]);
        let mut state = fresh_state();
        let out = evaluate_v3_with_registry(
            &policy,
            &test_request(),
            &mut state,
            &registry,
            "eth_sendTransaction",
        );
        assert_eq!(out.decision, Decision::Allow);
        assert_eq!(out.errors.len(), 1);
        assert_eq!(out.errors[0].0, "evil");
    }

    #[test]
    fn host_facts_reach_the_guest() {
        struct Balance;
        impl WasmHostCalls for Balance {
            fn get_wallet_balance(&self, _asset: &str) -> Option<f64> {
                Some(7.0)
            }
        }
        // The guest denies on the substring `DENYME`; put it in the host facts
        // rather than the request body to prove facts are serialized in.
        struct Sneaky;
        impl WasmHostCalls for Sneaky {
            fn host_facts(&self, _req: &WasmEvalRequest) -> serde_json::Value {
                serde_json::json!({ "note": "DENYME" })
            }
        }

        let policy = v3_policy(vec![]);
        let mut state = fresh_state();
        let registry = marker_registry();

        let allowed = evaluate_v3_with_strategies(
            &policy,
            &test_request(),
            &mut state,
            &registry,
            "eth_sendTransaction",
            &Balance,
        );
        assert_eq!(allowed.decision, Decision::Allow);

        let mut state = fresh_state();
        let denied = evaluate_v3_with_strategies(
            &policy,
            &test_request(),
            &mut state,
            &registry,
            "eth_sendTransaction",
            &Sneaky,
        );
        assert_eq!(denied.decision, Decision::Deny(DenyReason::Unknown));
    }

    #[test]
    fn plugin_deny_does_not_consume_budget() {
        // The 11-step flow commits the spend before the plugins are consulted.
        // A plugin deny must roll that back, or a blocked burst would silently
        // drain the session key's cap.
        let mut policy = v3_policy(vec![]);
        policy.v2.rules.contract_whitelist.push("0xDENYME".into());
        let mut req = test_request();
        req.recipient = Some("0xDENYME".into());

        let mut state = fresh_state();
        let before = state.local_spent_usd;
        let out = evaluate_v3_with_registry(
            &policy,
            &req,
            &mut state,
            &marker_registry(),
            "eth_sendTransaction",
        );
        assert!(out.is_denied());
        assert!(
            (state.local_spent_usd - before).abs() < f64::EPSILON,
            "a plugin-denied request must not consume budget (got {} -> {})",
            before,
            state.local_spent_usd
        );
        assert!(state.minutely_window.is_empty(), "no rate-limit slot may be consumed");
        assert!(state.hourly_window.is_empty());
        assert!(state.daily_window.is_empty());
        assert!(state.monthly_window.is_empty());
    }

    #[test]
    fn three_consecutive_plugin_denies_fire_the_r78_alert() {
        use std::sync::{Arc, Mutex};

        use crate::v2::{AlertSink, HumanAlert};

        #[derive(Default)]
        struct Recording(Arc<Mutex<Vec<HumanAlert>>>);
        impl AlertSink for Recording {
            fn notify(&self, alert: &HumanAlert) {
                self.0.lock().unwrap().push(alert.clone());
            }
        }

        let alerts = Arc::new(Mutex::new(Vec::new()));
        let mut policy = v3_policy(vec![]);
        policy.v2.rules.contract_whitelist.push("0xDENYME".into());
        let mut req = test_request();
        req.recipient = Some("0xDENYME".into());

        let mut state = PolicyState::new("sk-test".into())
            .with_alert_sink(Box::new(Recording(Arc::clone(&alerts))))
            .with_now_override(1_000_000);
        let registry = marker_registry();

        for _ in 0..3 {
            let out = evaluate_v3_with_registry(
                &policy,
                &req,
                &mut state,
                &registry,
                "eth_sendTransaction",
            );
            assert!(out.is_denied());
        }

        assert_eq!(
            alerts.lock().unwrap().len(),
            1,
            "3 consecutive plugin denies must fire exactly one R78 alert"
        );
        assert_eq!(state.consecutive_deny_counter, 0, "the counter resets after firing");
    }

    #[test]
    fn plugin_allow_still_consumes_budget() {
        // The mirror of the rollback test: an allowed request MUST be counted.
        let policy = v3_policy(vec![]);
        let mut state = fresh_state();
        let out = evaluate_v3_with_registry(
            &policy,
            &test_request(),
            &mut state,
            &marker_registry(),
            "eth_sendTransaction",
        );
        assert!(!out.is_denied());
        assert!((state.local_spent_usd - 5.0).abs() < f64::EPSILON);
        assert_eq!(state.minutely_window.len(), 1);
    }

    #[test]
    fn rollback_allow_is_a_noop_without_a_matching_record() {
        // Defensive: calling rollback without a preceding record_allow must not
        // corrupt the windows or drive spend negative.
        let mut state = fresh_state();
        let now_ms = state.now_ms();
        state.rollback_allow(&test_request(), now_ms, 0, Vec::new());
        assert!(state.local_spent_usd >= 0.0);
        assert!(state.minutely_window.is_empty());
        assert!(state.daily_window.is_empty());
    }

    #[test]
    fn wasm_request_maps_pay_request_fields() {
        let req = test_request();
        let w = wasm_request_from_pay(&req, "wallet_sendCalls");
        assert_eq!(w.method, "wallet_sendCalls");
        assert_eq!(w.chain_id, "eip155:8453");
        assert!((w.amount_usd - 5.0).abs() < f64::EPSILON);
        assert_eq!(w.asset, "USDC");
        assert_eq!(w.recipient, "0xABC");
        assert_eq!(w.session_key_id, "sk-test");
    }

    #[test]
    fn wasm_request_maps_absent_recipient_to_empty_string() {
        let mut req = test_request();
        req.recipient = None;
        assert_eq!(wasm_request_from_pay(&req, "m").recipient, "");
    }
}
