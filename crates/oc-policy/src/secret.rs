//! Secret access policy rules and evaluation.
//!
//! Per R56, this module MUST NOT depend on `oc-secret` (which would pull in
//! the `age` dependency chain). Policy checks operate solely on string
//! parameters (secret name, item type) — actual secret I/O happens in the
//! caller (oc-cli / daemon).
//!
//! Default-deny semantics: if no explicit `Allow` rule matches, the decision
//! is `Deny`. This mirrors the v1/v2 policy engine's default-deny posture.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Effect
// ---------------------------------------------------------------------------

/// Whether a policy rule allows or denies an operation.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    Allow,
    Deny,
}

// ---------------------------------------------------------------------------
// SecretOperation
// ---------------------------------------------------------------------------

/// The kind of secret operation being policy-checked.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SecretOperation {
    Read,
    Write,
    Delete,
    TotpGenerate,
}

// ---------------------------------------------------------------------------
// SecretPolicyRule
// ---------------------------------------------------------------------------

/// A policy rule governing agent access to secrets.
///
/// Rules are evaluated in order. The first matching rule's `effect` wins.
/// If no rule matches, the decision is `Deny` (default-deny).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecretPolicyRule {
    /// Agent ID this rule applies to (`"*"` matches all agents).
    pub agent_id: String,
    /// Operation to check.
    pub operation: SecretOperation,
    /// Whether to allow or deny.
    pub effect: Effect,
    /// Glob pattern for the secret name (e.g. `"github/*"`, `"totp/*"`).
    pub name_pattern: String,
    /// Optional item-type filter (e.g. `"password"`, `"totp"`). `None` matches all.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub item_type: Option<String>,
    /// Rate limit: max operations per minute (not yet enforced — informational).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limit_per_minute: Option<u32>,
    /// Daily budget in USD for x402-style metering (not yet enforced — informational).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub daily_budget_usd: Option<f64>,
}

// ---------------------------------------------------------------------------
// PolicyDecision
// ---------------------------------------------------------------------------

/// The result of a secret policy check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyDecision {
    /// `true` if the operation is allowed.
    pub allow: bool,
    /// Human-readable reason (populated on deny, or when an allow rule matched).
    pub reason: Option<String>,
}

impl PolicyDecision {
    /// Build an allow decision with an optional reason.
    pub fn allow(reason: Option<String>) -> Self {
        Self { allow: true, reason }
    }

    /// Build a deny decision with an optional reason.
    pub fn deny(reason: Option<String>) -> Self {
        Self { allow: false, reason }
    }
}

// ---------------------------------------------------------------------------
// Glob matching
// ---------------------------------------------------------------------------

/// Match a glob pattern with `*` wildcard support.
///
/// Supports:
/// - `*` matches any sequence of characters (including empty).
/// - Literal characters match themselves.
///
/// This is a minimal implementation — no `?` or character classes. The
/// pattern is applied to the full secret name (no partial matching).
fn glob_match(pattern: &str, name: &str) -> bool {
    // Fast paths.
    if pattern == "*" {
        return true;
    }
    if pattern == name {
        return true;
    }

    // Split pattern by `*` and walk through the name.
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        // No wildcard — literal match.
        return pattern == name;
    }

    let mut cursor = 0usize;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            // Consecutive `*` or leading/trailing `*` — skip.
            continue;
        }
        if i == 0 {
            // First segment must match at the start.
            if !name[cursor..].starts_with(part) {
                return false;
            }
            cursor += part.len();
        } else if i == parts.len() - 1 {
            // Last segment must match at the end.
            return name.ends_with(part) && cursor <= name.len() - part.len();
        } else {
            // Middle segment — find it after the cursor.
            match name[cursor..].find(part) {
                Some(pos) => cursor += pos + part.len(),
                None => return false,
            }
        }
    }
    // If the pattern ends with `*`, any remaining name is acceptable.
    // If it doesn't end with `*`, the last-segment branch already handled it.
    pattern.ends_with('*') || cursor == name.len()
}

// ---------------------------------------------------------------------------
// check_secret_access
// ---------------------------------------------------------------------------

/// Check if an agent can perform a secret operation.
///
/// Rules are evaluated in order. The first rule whose `agent_id` matches
/// (`"*"` or exact), whose `operation` matches, whose `name_pattern` glob
/// matches `secret_name`, and whose `item_type` matches (or is `None`) wins.
///
/// If no rule matches, the decision is `Deny` (default-deny).
///
/// Per R56, this function takes only string parameters — it does NOT read
/// the secret or reference any `oc_secret` types.
pub fn check_secret_access(
    rules: &[SecretPolicyRule],
    agent_id: &str,
    operation: SecretOperation,
    secret_name: &str,
    item_type: Option<&str>,
) -> PolicyDecision {
    for rule in rules {
        // Agent ID: "*" matches all, otherwise exact match.
        if rule.agent_id != "*" && rule.agent_id != agent_id {
            continue;
        }
        // Operation must match.
        if rule.operation != operation {
            continue;
        }
        // Name pattern must match.
        if !glob_match(&rule.name_pattern, secret_name) {
            continue;
        }
        // Item type: if the rule specifies one, it must match. If the rule
        // has no item_type, it matches all.
        if let Some(ref rule_item_type) = rule.item_type {
            if item_type != Some(rule_item_type.as_str()) {
                continue;
            }
        }
        // Rule matched — return its effect.
        return match rule.effect {
            Effect::Allow => {
                PolicyDecision::allow(Some(format!("allowed by rule for agent '{agent_id}'")))
            }
            Effect::Deny => {
                PolicyDecision::deny(Some(format!("denied by rule for agent '{agent_id}'")))
            }
        };
    }
    // No rule matched — default deny.
    PolicyDecision::deny(Some("no matching allow rule (default-deny)".into()))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn allow_rule(agent: &str, op: SecretOperation, pattern: &str) -> SecretPolicyRule {
        SecretPolicyRule {
            agent_id: agent.into(),
            operation: op,
            effect: Effect::Allow,
            name_pattern: pattern.into(),
            item_type: None,
            rate_limit_per_minute: None,
            daily_budget_usd: None,
        }
    }

    fn deny_rule(agent: &str, op: SecretOperation, pattern: &str) -> SecretPolicyRule {
        SecretPolicyRule {
            agent_id: agent.into(),
            operation: op,
            effect: Effect::Deny,
            name_pattern: pattern.into(),
            item_type: None,
            rate_limit_per_minute: None,
            daily_budget_usd: None,
        }
    }

    // --- glob_match ---

    #[test]
    fn glob_match_literal() {
        assert!(glob_match("github", "github"));
        assert!(!glob_match("github", "gitlab"));
    }

    #[test]
    fn glob_match_star_only() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("*", ""));
    }

    #[test]
    fn glob_match_prefix_wildcard() {
        assert!(glob_match("github/*", "github/token"));
        assert!(glob_match("github/*", "github/api-key"));
        assert!(!glob_match("github/*", "gitlab/token"));
    }

    #[test]
    fn glob_match_suffix_wildcard() {
        assert!(glob_match("*/token", "github/token"));
        assert!(glob_match("*/token", "gitlab/token"));
        assert!(!glob_match("*/token", "github/password"));
    }

    #[test]
    fn glob_match_middle_wildcard() {
        assert!(glob_match("git*/token", "github/token"));
        assert!(glob_match("git*/token", "gitlab/token"));
        assert!(!glob_match("git*/token", "hub/token"));
    }

    #[test]
    fn glob_match_multiple_wildcards() {
        assert!(glob_match("*/*", "github/token"));
        assert!(glob_match("*/*", "a/b"));
        assert!(!glob_match("*/*", "nomatch"));
    }

    // --- check_secret_access: default deny ---

    #[test]
    fn no_rules_denies() {
        let decision = check_secret_access(&[], "agent-1", SecretOperation::Read, "github", None);
        assert!(!decision.allow);
    }

    // --- check_secret_access: allow rules ---

    #[test]
    fn allow_rule_matches() {
        let rules = [allow_rule("agent-1", SecretOperation::Read, "github/*")];
        let decision =
            check_secret_access(&rules, "agent-1", SecretOperation::Read, "github/token", None);
        assert!(decision.allow);
    }

    #[test]
    fn wildcard_agent_matches() {
        let rules = [allow_rule("*", SecretOperation::Read, "github/*")];
        let decision =
            check_secret_access(&rules, "any-agent", SecretOperation::Read, "github/token", None);
        assert!(decision.allow);
    }

    #[test]
    fn wrong_agent_denied() {
        let rules = [allow_rule("agent-1", SecretOperation::Read, "github/*")];
        let decision =
            check_secret_access(&rules, "agent-2", SecretOperation::Read, "github/token", None);
        assert!(!decision.allow);
    }

    #[test]
    fn wrong_operation_denied() {
        let rules = [allow_rule("agent-1", SecretOperation::Read, "github/*")];
        let decision =
            check_secret_access(&rules, "agent-1", SecretOperation::Write, "github/token", None);
        assert!(!decision.allow);
    }

    #[test]
    fn wrong_pattern_denied() {
        let rules = [allow_rule("agent-1", SecretOperation::Read, "github/*")];
        let decision =
            check_secret_access(&rules, "agent-1", SecretOperation::Read, "gitlab/token", None);
        assert!(!decision.allow);
    }

    // --- check_secret_access: deny rules ---

    #[test]
    fn deny_rule_overrides_when_first() {
        let rules = [
            deny_rule("agent-1", SecretOperation::Read, "github/*"),
            allow_rule("agent-1", SecretOperation::Read, "github/*"),
        ];
        let decision =
            check_secret_access(&rules, "agent-1", SecretOperation::Read, "github/token", None);
        // First match wins — deny.
        assert!(!decision.allow);
    }

    #[test]
    fn allow_then_deny_for_different_patterns() {
        let rules = [
            allow_rule("agent-1", SecretOperation::Read, "github/*"),
            deny_rule("agent-1", SecretOperation::Read, "github/secret/*"),
        ];
        // github/token matches the first rule (allow).
        let d1 =
            check_secret_access(&rules, "agent-1", SecretOperation::Read, "github/token", None);
        assert!(d1.allow);
        // github/secret/key matches the second rule (deny) — but the first rule
        // "github/*" also matches and comes first, so it wins (allow).
        let d2 = check_secret_access(
            &rules,
            "agent-1",
            SecretOperation::Read,
            "github/secret/key",
            None,
        );
        assert!(d2.allow);
    }

    // --- check_secret_access: item_type filter ---

    #[test]
    fn item_type_filter_matches() {
        let mut rule = allow_rule("agent-1", SecretOperation::Read, "totp/*");
        rule.item_type = Some("totp".into());
        let rules = [rule];
        let decision = check_secret_access(
            &rules,
            "agent-1",
            SecretOperation::Read,
            "totp/github",
            Some("totp"),
        );
        assert!(decision.allow);
    }

    #[test]
    fn item_type_filter_mismatch_denied() {
        let mut rule = allow_rule("agent-1", SecretOperation::Read, "totp/*");
        rule.item_type = Some("totp".into());
        let rules = [rule];
        let decision = check_secret_access(
            &rules,
            "agent-1",
            SecretOperation::Read,
            "totp/github",
            Some("password"),
        );
        assert!(!decision.allow);
    }

    #[test]
    fn item_type_none_on_rule_matches_all() {
        let rules = [allow_rule("agent-1", SecretOperation::Read, "*")];
        // Rule has no item_type — matches any item_type.
        let d1 =
            check_secret_access(&rules, "agent-1", SecretOperation::Read, "x", Some("password"));
        let d2 = check_secret_access(&rules, "agent-1", SecretOperation::Read, "x", Some("totp"));
        let d3 = check_secret_access(&rules, "agent-1", SecretOperation::Read, "x", None);
        assert!(d1.allow);
        assert!(d2.allow);
        assert!(d3.allow);
    }

    // --- serde round-trip ---

    #[test]
    fn secret_policy_rule_serde_roundtrip() {
        let rule = SecretPolicyRule {
            agent_id: "agent-1".into(),
            operation: SecretOperation::Read,
            effect: Effect::Allow,
            name_pattern: "github/*".into(),
            item_type: Some("password".into()),
            rate_limit_per_minute: Some(10),
            daily_budget_usd: Some(5.0),
        };
        let json = serde_json::to_string(&rule).unwrap();
        let back: SecretPolicyRule = serde_json::from_str(&json).unwrap();
        assert_eq!(back.agent_id, "agent-1");
        assert_eq!(back.operation, SecretOperation::Read);
        assert_eq!(back.effect, Effect::Allow);
        assert_eq!(back.name_pattern, "github/*");
        assert_eq!(back.item_type.as_deref(), Some("password"));
        assert_eq!(back.rate_limit_per_minute, Some(10));
        assert_eq!(back.daily_budget_usd, Some(5.0));
    }

    #[test]
    fn effect_serde_snake_case() {
        assert_eq!(serde_json::to_string(&Effect::Allow).unwrap(), "\"allow\"");
        assert_eq!(serde_json::to_string(&Effect::Deny).unwrap(), "\"deny\"");
    }

    #[test]
    fn secret_operation_serde_snake_case() {
        assert_eq!(serde_json::to_string(&SecretOperation::Read).unwrap(), "\"read\"");
        assert_eq!(serde_json::to_string(&SecretOperation::Write).unwrap(), "\"write\"");
        assert_eq!(serde_json::to_string(&SecretOperation::Delete).unwrap(), "\"delete\"");
        assert_eq!(
            serde_json::to_string(&SecretOperation::TotpGenerate).unwrap(),
            "\"totp_generate\""
        );
    }
}
