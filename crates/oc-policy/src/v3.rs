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
    OcPolicyError,
    native_strategy::{
        NoHostFacts, RegistryOutcome, StrategyEvalRequest, StrategyHost, StrategyRegistry,
    },
    v2::{Decision, DenyReason, PayRequest, PolicyState},
};

// ---------------------------------------------------------------------------
// Resource limits (M-11)
// ---------------------------------------------------------------------------

/// Maximum accepted JSON input size for [`parse_policy_v3`] (M-11): 256 KiB.
///
/// Chosen so the byte cap alone bounds parse memory while still leaving room
/// for the node-count cap to be the binding constraint on pathological trees
/// (the smallest serializable condition node is ~28 bytes, so ~9k nodes fit in
/// 256 KiB — [`MAX_RULE_NODES`] is set below that ceiling).
pub const MAX_POLICY_JSON_BYTES: usize = 256 * 1024;

/// Maximum number of rule-condition nodes per parsed policy (M-11).
pub const MAX_RULE_NODES: usize = 8_192;

/// Maximum recursion depth for condition-tree evaluation (M-11).
///
/// A tree deeper than this fails closed: the affected rule never matches for
/// `Permit`, and any rule under evaluation at overflow aborts the whole v3
/// evaluation with `Deny(Unknown)` so a deep `Forbid` can neither be bypassed
/// nor blow the stack.
pub const MAX_CONDITION_DEPTH: usize = 64;

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
/// **Fail-closed rules (M-11):**
/// - A condition tree deeper than [`MAX_CONDITION_DEPTH`] aborts evaluation of the whole rule set
///   with `Deny(Unknown)` — never a stack overflow, never a silent skip of a `Forbid`.
/// - A numeric comparison whose runtime operand is non-finite evaluates as *not matched* under
///   `Permit`, but a `Forbid` whose comparison touches such an operand MATCHES (fires). This
///   asymmetry is deliberate: NaN must never silently disable a prohibition, while it must also
///   never grant a permission.
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

    // Evaluate every rule once. A depth-cap overflow anywhere fails closed for
    // the entire rule set (M-11).
    let mut outcomes = Vec::with_capacity(policy.rules.len());
    for rule in &policy.rules {
        let outcome = evaluate_condition_outcome(&rule.condition, request, 0);
        if outcome == CondOutcome::DepthExceeded {
            tracing::warn!(
                target: "oc-policy::v3",
                rule_id = %rule.id,
                max_depth = MAX_CONDITION_DEPTH,
                "condition tree exceeded recursion depth cap; failing closed"
            );
            return Decision::Deny(DenyReason::Unknown);
        }
        outcomes.push(outcome);
    }

    // Any matching Forbid rule overrides to Deny.
    for (rule, outcome) in policy.rules.iter().zip(&outcomes) {
        if rule.effect != RuleEffect::Forbid {
            continue;
        }
        // M-11 fail-closed asymmetry: a Forbid whose numeric comparison reads a
        // non-finite runtime value fires even though the raw comparison would
        // evaluate false (NaN ordering/equality is always false).
        let non_finite_hit = *outcome != CondOutcome::Matched &&
            condition_touches_non_finite_number(&rule.condition, request);
        if *outcome == CondOutcome::Matched || non_finite_hit {
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
            .zip(&outcomes)
            .any(|(r, o)| r.effect == RuleEffect::Permit && *o == CondOutcome::Matched);
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

/// Outcome of evaluating one condition subtree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CondOutcome {
    /// The condition matched.
    Matched,
    /// The condition did not match.
    NotMatched,
    /// The recursion-depth cap was hit; callers MUST fail closed.
    DepthExceeded,
}

/// Evaluate a condition tree with an explicit recursion-depth budget (M-11).
///
/// `depth` counts composite-node nesting; leaves terminate the recursion. When
/// `depth` reaches [`MAX_CONDITION_DEPTH`] the subtree reports
/// [`CondOutcome::DepthExceeded`] instead of recursing further, so a hostile
/// deep tree cannot overflow the stack.
fn evaluate_condition_outcome(
    condition: &RuleCondition,
    request: &PayRequest,
    depth: usize,
) -> CondOutcome {
    if depth >= MAX_CONDITION_DEPTH {
        return CondOutcome::DepthExceeded;
    }
    match condition {
        RuleCondition::Always { value } => {
            if *value {
                CondOutcome::Matched
            } else {
                CondOutcome::NotMatched
            }
        }
        RuleCondition::Comparison { field, operator, value } => {
            let field_value = get_field(request, field);
            if compare_values(&field_value, operator, value) {
                CondOutcome::Matched
            } else {
                CondOutcome::NotMatched
            }
        }
        RuleCondition::Membership { field, values } => {
            let field_value = get_field(request, field);
            if values.iter().any(|v| v == &field_value) {
                CondOutcome::Matched
            } else {
                CondOutcome::NotMatched
            }
        }
        RuleCondition::All { conditions } => {
            let mut result = CondOutcome::Matched;
            for c in conditions {
                match evaluate_condition_outcome(c, request, depth + 1) {
                    CondOutcome::DepthExceeded => return CondOutcome::DepthExceeded,
                    CondOutcome::NotMatched => result = CondOutcome::NotMatched,
                    CondOutcome::Matched => {}
                }
            }
            result
        }
        RuleCondition::Any { conditions } => {
            let mut result = CondOutcome::NotMatched;
            for c in conditions {
                match evaluate_condition_outcome(c, request, depth + 1) {
                    CondOutcome::DepthExceeded => return CondOutcome::DepthExceeded,
                    CondOutcome::Matched => result = CondOutcome::Matched,
                    CondOutcome::NotMatched => {}
                }
            }
            result
        }
        RuleCondition::Not { condition } => {
            match evaluate_condition_outcome(condition, request, depth + 1) {
                CondOutcome::DepthExceeded => CondOutcome::DepthExceeded,
                CondOutcome::Matched => CondOutcome::NotMatched,
                CondOutcome::NotMatched => CondOutcome::Matched,
            }
        }
    }
}

/// True if any `Comparison` node in the tree reads a numeric request field
/// whose runtime value is non-finite (M-11).
///
/// Iterative walk with the same depth cap as evaluation; a depth overflow here
/// simply stops the walk (it cannot claim a non-finite hit that was not seen).
fn condition_touches_non_finite_number(condition: &RuleCondition, request: &PayRequest) -> bool {
    let mut stack = vec![(condition, 0usize)];
    while let Some((cond, depth)) = stack.pop() {
        if depth >= MAX_CONDITION_DEPTH {
            continue;
        }
        match cond {
            RuleCondition::Comparison { field, .. } => {
                if field == "amount_usd" && !request.amount_usd.is_finite() {
                    return true;
                }
            }
            RuleCondition::All { conditions } | RuleCondition::Any { conditions } => {
                stack.extend(conditions.iter().map(|c| (c, depth + 1)));
            }
            RuleCondition::Not { condition } => stack.push((condition.as_ref(), depth + 1)),
            RuleCondition::Membership { .. } | RuleCondition::Always { .. } => {}
        }
    }
    false
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

/// Absolute tolerance for numeric equality comparisons (M-11).
const NUM_ABS_EPSILON: f64 = 1e-9;

/// Relative tolerance component for numeric equality comparisons (M-11).
///
/// The equality tolerance is `NUM_ABS_EPSILON.max(NUM_REL_EPSILON * max(|a|, |b|))`:
/// an absolute floor for small magnitudes plus a relative term so large USD
/// values (where 1 ULP already exceeds any absolute epsilon) still compare
/// stably.
const NUM_REL_EPSILON: f64 = 1e-9;

/// Tolerant numeric equality (M-11).
fn numbers_eq(a: f64, b: f64) -> bool {
    (a - b).abs() <= NUM_ABS_EPSILON.max(NUM_REL_EPSILON * a.abs().max(b.abs()))
}

/// Compare two JSON values with the given operator.
///
/// Numeric comparisons use `f64`. String comparisons support `==` / `!=`
/// only; ordering operators on strings return `false`. Mismatched types
/// return `false`.
///
/// **M-11 semantics:**
/// - No silent coercion: operands that cannot be represented as `f64` make the comparison *not
///   matched* instead of being substituted with `0.0`.
/// - Non-finite operands compare as "not equal": `Eq` and all orderings return `false`, only `Ne`
///   returns `true`. Rule-level fail-closed handling for `Forbid` lives in [`evaluate_v3`] /
///   [`condition_touches_non_finite_number`].
fn compare_values(
    actual: &serde_json::Value,
    op: &ComparisonOp,
    expected: &serde_json::Value,
) -> bool {
    match (actual, expected) {
        (serde_json::Value::Number(a), serde_json::Value::Number(e)) => {
            // M-11: no fabricated 0.0 on conversion gaps — treat as not matched.
            let (Some(a), Some(e)) = (a.as_f64(), e.as_f64()) else {
                return false;
            };
            // Non-finite operands never compare equal or ordered ("not equal").
            if !a.is_finite() || !e.is_finite() {
                return matches!(op, ComparisonOp::Ne);
            }
            match op {
                ComparisonOp::Eq => numbers_eq(a, e),
                ComparisonOp::Ne => !numbers_eq(a, e),
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

/// Count rule-condition nodes across all rules, iteratively (M-11).
///
/// The walk is explicitly stack-based so counting a hostile tree cannot
/// overflow the call stack either; returns early once [`MAX_RULE_NODES`] is
/// exceeded.
fn count_condition_nodes<'a>(rules: impl Iterator<Item = &'a PolicyRule>) -> usize {
    let mut count = 0usize;
    let mut stack: Vec<&RuleCondition> = rules.map(|r| &r.condition).collect();
    while let Some(cond) = stack.pop() {
        count += 1;
        if count > MAX_RULE_NODES {
            return count;
        }
        match cond {
            RuleCondition::All { conditions } | RuleCondition::Any { conditions } => {
                stack.extend(conditions.iter());
            }
            RuleCondition::Not { condition } => stack.push(condition.as_ref()),
            RuleCondition::Comparison { .. } |
            RuleCondition::Membership { .. } |
            RuleCondition::Always { .. } => {}
        }
    }
    count
}

/// Parse a Cedar-like v3 policy from JSON.
///
/// **Resource limits (M-11):** input larger than [`MAX_POLICY_JSON_BYTES`] or a
/// condition tree with more than [`MAX_RULE_NODES`] nodes is rejected with
/// [`OcPolicyError::InvalidInput`] before evaluation, bounding both parse
/// memory and evaluation cost. (serde_json's own 128-level recursion limit
/// already bounds deserialization depth.)
///
/// # Errors
///
/// Returns [`OcPolicyError::Serde`] if `json` is not a valid `PolicyV3`, and
/// [`OcPolicyError::InvalidInput`] if a resource limit is exceeded.
pub fn parse_policy_v3(json: &str) -> Result<PolicyV3, OcPolicyError> {
    if json.len() > MAX_POLICY_JSON_BYTES {
        return Err(OcPolicyError::InvalidInput(format!(
            "policy JSON exceeds maximum size: {} bytes > {MAX_POLICY_JSON_BYTES}",
            json.len()
        )));
    }
    let policy: PolicyV3 = serde_json::from_str(json)?;
    let nodes = count_condition_nodes(policy.rules.iter());
    if nodes > MAX_RULE_NODES {
        return Err(OcPolicyError::InvalidInput(format!(
            "policy exceeds maximum rule-node count: {nodes} > {MAX_RULE_NODES}"
        )));
    }
    Ok(policy)
}

// ---------------------------------------------------------------------------
// Native strategy plugin integration
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

/// Build the strategy-facing request from a [`PayRequest`].
///
/// `method` is supplied by the caller because `PayRequest` is payment-shaped
/// and does not carry the originating JSON-RPC method.
pub fn strategy_request_from_pay(req: &PayRequest, method: &str) -> StrategyEvalRequest {
    StrategyEvalRequest {
        method: method.to_string(),
        chain_id: req.chain_id.clone(),
        amount_usd: req.amount_usd,
        asset: req.asset.clone(),
        recipient: req.recipient.clone().unwrap_or_default(),
        session_key_id: req.session_key_id.clone(),
        host_facts: serde_json::Value::Object(serde_json::Map::new()),
    }
}

/// Evaluate a request against a v3 policy **and** the strategy registry.
///
/// Ordering is deliberate and is the whole point of the design:
///
/// 1. The built-in v2 11-step pipeline and the v3 Cedar rules run first, via [`evaluate_v3`].
/// 2. **If they already deny, the plugins are not run at all.** A strategy never observes a request
///    the core has already rejected, and a plugin can never *upgrade* a deny into an allow.
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
    host: &dyn StrategyHost,
) -> StrategyDecision {
    // Captured BEFORE evaluation: step 10 clears the deny streak on allow, and
    // we must restore it if a plugin later overturns that allow.
    let prior_counter = state.consecutive_deny_counter;
    let prior_reasons = state.last_deny_reasons.clone();

    let decision = evaluate_v3(policy, request, state);

    // Fail-closed short-circuit: never hand a already-denied request to a
    // strategy, and never let a plugin overturn a core deny.
    if matches!(decision, Decision::Deny(_)) || registry.is_empty() {
        return StrategyDecision::passthrough(decision);
    }

    let req = strategy_request_from_pay(request, method);
    let RegistryOutcome { denied_by, warnings, errors } = registry.evaluate(&req, host);

    for (plugin, message) in &warnings {
        tracing::warn!(
            target: "oc-policy::native_strategy",
            plugin = %plugin,
            message = %message,
            "strategy plugin raised a warning"
        );
    }
    for (plugin, error) in &errors {
        tracing::warn!(
            target: "oc-policy::native_strategy",
            plugin = %plugin,
            error = %error,
            "strategy plugin failed to evaluate; treated as non-blocking"
        );
    }

    let decision = if let Some((plugin, reason, message)) = &denied_by {
        tracing::warn!(
            target: "oc-policy::native_strategy",
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
    use crate::{
        native_strategy::{StrategyOutcome, StrategyPlugin},
        v2::{BudgetAllocation, PolicyRulesV2, PolicyV2},
    };

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

    // --- M-11: parse resource limits ----------------------------------------

    #[test]
    fn parse_rejects_oversized_input() {
        let oversized = " ".repeat(MAX_POLICY_JSON_BYTES + 1);
        let err = parse_policy_v3(&oversized).unwrap_err();
        assert!(
            matches!(err, OcPolicyError::InvalidInput(ref m) if m.contains("maximum size")),
            "unexpected error: {err:?}"
        );
    }

    /// Build a v3 policy JSON whose single rule is an `All` over `n` leaf
    /// nodes. Total node count is `n + 1` (the root `All` counts too).
    fn policy_json_with_nodes(n: usize) -> String {
        let cond =
            RuleCondition::All { conditions: vec![RuleCondition::Always { value: true }; n] };
        let policy = v3_policy(vec![forbid("bulk", cond)]);
        serde_json::to_string(&policy).unwrap()
    }

    #[test]
    fn parse_rejects_excessive_rule_node_count() {
        // MAX_RULE_NODES + 1 total nodes: ~230 KB, under the byte cap, over
        // the node cap.
        let json = policy_json_with_nodes(MAX_RULE_NODES);
        assert!(json.len() <= MAX_POLICY_JSON_BYTES, "test payload must hit the node cap first");
        let err = parse_policy_v3(&json).unwrap_err();
        assert!(
            matches!(err, OcPolicyError::InvalidInput(ref m) if m.contains("rule-node count")),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn parse_accepts_policy_at_node_cap_boundary() {
        // Root All + (MAX_RULE_NODES - 1) leaves == exactly MAX_RULE_NODES.
        let json = policy_json_with_nodes(MAX_RULE_NODES - 1);
        let policy = parse_policy_v3(&json).unwrap();
        assert_eq!(policy.rules.len(), 1);
    }

    // --- M-11: recursion depth cap -------------------------------------------

    /// Wrap `inner` in `depth` layers of `Not`.
    fn nest_not(depth: usize, inner: RuleCondition) -> RuleCondition {
        let mut cond = inner;
        for _ in 0..depth {
            cond = RuleCondition::Not { condition: Box::new(cond) };
        }
        cond
    }

    #[test]
    fn deep_condition_tree_fails_closed_instead_of_overflowing() {
        // NOT^100(Always(false)): if this were evaluable, 100 even flips yield
        // false and the forbid would NOT fire (Allow). The depth cap must turn
        // it into a fail-closed deny instead of a stack overflow.
        let cond = nest_not(100, RuleCondition::Always { value: false });
        let policy = v3_policy(vec![forbid("deep", cond)]);
        let mut state = fresh_state();
        let decision = evaluate_v3(&policy, &test_request(), &mut state);
        assert_eq!(decision, Decision::Deny(DenyReason::Unknown));
    }

    #[test]
    fn condition_just_under_depth_cap_still_evaluates() {
        // NOT^10(Always(false)) => false => forbid does not fire => Allow.
        let cond = nest_not(10, RuleCondition::Always { value: false });
        let policy = v3_policy(vec![forbid("shallow", cond)]);
        let mut state = fresh_state();
        let decision = evaluate_v3(&policy, &test_request(), &mut state);
        assert_eq!(decision, Decision::Allow);
    }

    #[test]
    fn depth_exceeded_propagates_through_composites() {
        let request = test_request();
        let deep = || nest_not(MAX_CONDITION_DEPTH + 10, RuleCondition::Always { value: true });
        // Inside All: any DepthExceeded child poisons the whole All.
        let all =
            RuleCondition::All { conditions: vec![RuleCondition::Always { value: true }, deep()] };
        assert_eq!(evaluate_condition_outcome(&all, &request, 0), CondOutcome::DepthExceeded);
        // Inside Any.
        let any =
            RuleCondition::Any { conditions: vec![RuleCondition::Always { value: false }, deep()] };
        assert_eq!(evaluate_condition_outcome(&any, &request, 0), CondOutcome::DepthExceeded);
        // Inside Not.
        assert_eq!(
            evaluate_condition_outcome(
                &RuleCondition::Not { condition: Box::new(deep()) },
                &request,
                0
            ),
            CondOutcome::DepthExceeded
        );
    }

    // --- M-11: non-finite numeric operands fail closed -----------------------

    #[test]
    fn forbid_touching_non_finite_amount_fires() {
        let mut req = test_request();
        req.amount_usd = f64::NAN;
        let cond = cmp("amount_usd", ComparisonOp::Gt, serde_json::json!(1.0));
        // Raw comparison is false (NaN field serializes to Null), but the
        // fail-closed detector flags it, so evaluate_v3's forbid loop fires.
        assert_eq!(evaluate_condition_outcome(&cond, &req, 0), CondOutcome::NotMatched);
        assert!(condition_touches_non_finite_number(&cond, &req));

        // Finite amounts are not flagged.
        let finite_req = test_request();
        assert!(!condition_touches_non_finite_number(&cond, &finite_req));

        // Non-numeric fields are not flagged even with a NaN amount.
        let asset_cond = cmp("asset", ComparisonOp::Eq, serde_json::json!("USDC"));
        assert!(!condition_touches_non_finite_number(&asset_cond, &req));
    }

    #[test]
    fn permit_with_non_finite_amount_does_not_match() {
        // Asymmetry (documented on evaluate_v3): the same non-finite comparison
        // that fires a Forbid does NOT satisfy a Permit.
        let mut req = test_request();
        req.amount_usd = f64::INFINITY;
        let cond = cmp("amount_usd", ComparisonOp::Gt, serde_json::json!(1.0));
        assert_eq!(evaluate_condition_outcome(&cond, &req, 0), CondOutcome::NotMatched);
    }

    // --- M-11: numeric comparison semantics ----------------------------------

    #[test]
    fn numeric_equality_uses_mixed_absolute_relative_tolerance() {
        // Within the absolute floor.
        assert!(numbers_eq(1.0, 1.0 + 5e-10));
        // Clearly different.
        assert!(!numbers_eq(1.0, 1.1));
        // Large magnitudes: relative term covers what f64::EPSILON could not.
        assert!(numbers_eq(1e12, 1e12 + 0.5));
        // ...but only up to the tolerance.
        assert!(!numbers_eq(1e12, 1e12 + 1e4));
    }

    #[test]
    fn out_of_range_integers_are_not_coerced_to_zero() {
        // Old code did `as_f64().unwrap_or(0.0)`; a conversion gap must now be
        // "not matched" rather than silently comparing against 0.0. Large ints
        // keep their real magnitude.
        let big = serde_json::json!(18_446_744_073_709_551_615u64);
        assert!(compare_values(&big, &ComparisonOp::Ge, &serde_json::json!(1e18)));
        assert!(!compare_values(&big, &ComparisonOp::Le, &serde_json::json!(1e18)));
    }

    #[test]
    fn non_finite_operand_compares_as_not_equal() {
        // Defensive: serde_json Numbers cannot hold NaN/inf today, but if a
        // non-finite f64 ever reaches comparison it must behave as "not equal"
        // (Ne true, everything else false) rather than by accident.
        assert!(!numbers_eq(f64::NAN, f64::NAN));
        assert!(!numbers_eq(f64::INFINITY, f64::INFINITY));
    }

    // --- Strategy registry integration -------------------------------------

    /// A registry with a single "marker" plugin: denies on `DENYME`, warns on
    /// `WARNME`, otherwise allows. The marker string is matched against both
    /// the recipient and the serialized `host_facts` so host-fact injection is
    /// observable (mirrors the old Wasm guest, which scanned the whole request
    /// JSON).
    fn marker_registry() -> StrategyRegistry {
        let mut registry = StrategyRegistry::new();
        registry.insert(StrategyPlugin::new(
            "marker",
            Box::new(|req, _| {
                let deny_hit = req.recipient.contains("DENYME") ||
                    req.host_facts.to_string().contains("DENYME");
                let warn_hit = req.recipient.contains("WARNME") ||
                    req.host_facts.to_string().contains("WARNME");
                if deny_hit {
                    StrategyOutcome::Deny { reason: "marker".into(), message: "blocked".into() }
                } else if warn_hit {
                    StrategyOutcome::Warn { message: "suspicious".into() }
                } else {
                    StrategyOutcome::Allow
                }
            }),
        ));
        registry
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
        assert_eq!(out.warnings.len(), 0);
        assert_eq!(out.errors.len(), 0);
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
        assert_eq!(out.warnings.len(), 0);
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
        assert!(out.denied_by.is_none(), "the plugin must not observe an already-denied request");
    }

    #[test]
    fn host_facts_reach_the_strategy() {
        // A strategy that injects `DENYME` into the request via host facts
        // must be observed by the marker plugin (facts are serialized in).
        struct Sneaky;
        impl StrategyHost for Sneaky {
            fn host_facts(&self, _req: &StrategyEvalRequest) -> serde_json::Value {
                serde_json::json!({ "note": "DENYME" })
            }
        }

        let policy = v3_policy(vec![]);
        let mut state = fresh_state();
        let registry = marker_registry();

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
    fn strategy_request_maps_pay_request_fields() {
        let req = test_request();
        let w = strategy_request_from_pay(&req, "wallet_sendCalls");
        assert_eq!(w.method, "wallet_sendCalls");
        assert_eq!(w.chain_id, "eip155:8453");
        assert!((w.amount_usd - 5.0).abs() < f64::EPSILON);
        assert_eq!(w.asset, "USDC");
        assert_eq!(w.recipient, "0xABC");
        assert_eq!(w.session_key_id, "sk-test");
    }

    #[test]
    fn strategy_request_maps_absent_recipient_to_empty_string() {
        let mut req = test_request();
        req.recipient = None;
        assert_eq!(strategy_request_from_pay(&req, "m").recipient, "");
    }
}
