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

use crate::v2::{Decision, DenyReason, PayRequest, PolicyState};

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
}
