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
