// Test code may unwrap/expect/panic (workspace lint phase-1 carve-out).
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
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
//! with a `jiff`-backed RFC3339-to-unix parser to keep `cargo tree`
//! clean (R56 — no `chrono` in `oc-policy`). Fork behavior is otherwise verbatim.

#![deny(unsafe_code)]

pub mod error;
pub mod native_strategy;
pub mod secret;
pub mod v1;
pub mod v2;
#[cfg(feature = "experimental-v3")]
pub mod v3;

pub use error::OcPolicyError;
pub use native_strategy::{
    NoHostFacts, RegistryOutcome, StrategyEvalRequest, StrategyHost, StrategyOutcome,
    StrategyPlugin, StrategyRegistry, strategy_request_from_pay,
};
pub use secret::{Effect, PolicyDecision, SecretOperation, SecretPolicyRule, check_secret_access};
// v1 entry points. `evaluate_policies` / `evaluate_one` / `evaluate_rule` are
// public because `oc-wallet::key_ops` drives OWS-compatible v1 policy bundles
// for legacy/upstream compatibility. `evaluate_executable` is intentionally
// crate-internal (see its doc note): it forks a subprocess and is not part of
// the recommended evaluation path.
pub use v1::{evaluate_one, evaluate_policies, evaluate_rule};
pub use v2::{
    AlertSink, BudgetAllocation, Decision, DenyReason, HumanAlert, LogAlertSink, PayRequest,
    PolicyRulesV2, PolicyState, PolicyV2, WarnReason, evaluate_11_step,
};
#[cfg(feature = "experimental-v3")]
pub use v3::{
    ComparisonOp, PolicyRule, PolicyV3, RuleCondition, RuleEffect, StrategyDecision, evaluate_v3,
    evaluate_v3_with_registry, evaluate_v3_with_strategies, parse_policy_v3,
};
