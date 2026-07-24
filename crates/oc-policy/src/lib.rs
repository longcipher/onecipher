//! Policy Engine v2 for OneCipher.
//!
//! Fully designed and implemented in accordance with the Open Wallet Standard's policy engine
//! (declarative rules + executable subprocess, AND semantics, default-deny) into `v1.rs`, then
//! extends to v2 with:
//! - `PolicyV2` / `PolicyRulesV2` / `BudgetAllocation` (R28)
//! - 11-step evaluation flow (R29 / AD-04)
//! - Persisted counters (`PolicyState::load/persist`) with fsync after every decision
//! - `AlertSink` trait + `LogAlertSink` default (C-10)
//!
//! **Deviation note:** The v1 implementation replaces `chrono::DateTime::parse_from_rfc3339`
//! with a stdlib-only RFC3339-to-unix parser (20-line function) to keep `cargo tree`
//! clean (R56 — no `chrono` in `oc-policy`). Fork behavior is otherwise verbatim.

#![deny(unsafe_code)]

pub mod error;
pub mod secret;
pub mod v1;
pub mod v2;
pub mod v3;

pub use error::OcPolicyError;
pub use secret::{Effect, PolicyDecision, SecretOperation, SecretPolicyRule, check_secret_access};
pub use v1::{evaluate_executable, evaluate_one, evaluate_policies, evaluate_rule};
pub use v2::{
    AlertSink, BudgetAllocation, Decision, DenyReason, HumanAlert, LogAlertSink, PayRequest,
    PolicyRulesV2, PolicyState, PolicyV2, evaluate_11_step,
};
pub use v3::{
    ComparisonOp, PolicyRule, PolicyV3, RuleCondition, RuleEffect, evaluate_v3, parse_policy_v3,
};

// ---------------------------------------------------------------------------
// DenyReason → wire string (R80 mapping)
// ---------------------------------------------------------------------------

/// Converts a [`DenyReason`] to its R80 wire-string form for `PayX402Response`.
///
/// R80 caps `DenyReason` at exactly 9 variants. The wire-string form is the
/// Agent/UI-facing representation carried in `PayX402Response.deny_reason`
/// and the `PayX402` audit payload.
///
/// `context` disambiguates [`DenyReason::BudgetExceeded`]:
/// - `"step_9"` (single-amount check) → `"AMOUNT_EXCEEDED"` (T25 mapping)
/// - any other context (step_8 / step_8a / step_8b) → `"BUDGET_EXCEEDED"`
///
/// Full mapping (see `crates/oc-conformance/.../x402_deny_reason.rs`):
/// - `RateLimitMinute` → `RATE_LIMIT_MINUTE`
/// - `RateLimitHour`   → `RATE_LIMIT_HOUR`
/// - `BudgetExceeded` (step_8/8a/8b) → `BUDGET_EXCEEDED`
/// - `BudgetExceeded` (step_9) → `AMOUNT_EXCEEDED`
/// - `Whitelist`       → `WHITELIST`
/// - `Expired`         → `EXPIRED`
/// - `Cooldown`        → `COOLDOWN`
/// - `PolicyMissing`   → `POLICY_INVALID` (T30 mapping)
/// - `PasskeyForged`   → `PASSKEY_FORGED`
/// - `Unknown`         → `UNKNOWN`
pub fn deny_reason_to_wire_string(reason: &DenyReason, context: &str) -> String {
    match (reason, context) {
        (DenyReason::BudgetExceeded, "step_9") => "AMOUNT_EXCEEDED",
        (DenyReason::BudgetExceeded, _) => "BUDGET_EXCEEDED",
        (DenyReason::RateLimitMinute, _) => "RATE_LIMIT_MINUTE",
        (DenyReason::RateLimitHour, _) => "RATE_LIMIT_HOUR",
        (DenyReason::Whitelist, _) => "WHITELIST",
        (DenyReason::Expired, _) => "EXPIRED",
        (DenyReason::Cooldown, _) => "COOLDOWN",
        (DenyReason::PolicyMissing, _) => "POLICY_INVALID",
        (DenyReason::PasskeyForged, _) => "PASSKEY_FORGED",
        (DenyReason::Unknown, _) => "UNKNOWN",
    }
    .to_string()
}
