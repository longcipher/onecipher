//! Shared Background step definitions reused across multiple Phase E feature
//! files.
//!
//! cucumber 0.21 panics at startup if two modules register the same step
//! pattern. To avoid that, any `Given`/`When`/`Then` step that appears in more
//! than one `.feature` file's Background (or scenarios) MUST live here, with a
//! single canonical handler. Feature-specific steps stay in their own modules.
//!
//! Currently shared:
//! - `Given an Agent holds an active Session Key with a Policy` — used by `policy_amount.feature`
//!   (T25) and `policy_rate_limit.feature` (T26).
//!
//! Per the T22 design, Background steps here orchestrate EXISTING components
//! directly (no `dispatch()` call). They set up just enough `ConformanceWorld`
//! state for the per-scenario steps to call `evaluate_11_step` and assert on
//! the resulting `Decision`.

use cucumber::given;
use ed25519_dalek::SigningKey;
use oc_keyagent::AuditLog;
use oc_policy::{BudgetAllocation, PolicyRulesV2, PolicyState, PolicyV2};
use tempfile::tempdir;

use crate::ConformanceWorld;

/// Build a default test `PolicyV2` with all R28 fields populated to reasonable
/// permissive values. Per-scenario `Given` steps mutate specific fields (e.g.
/// `max_single_amount_usd` for T25 scenario 1) before `evaluate_11_step` runs.
pub(crate) fn default_test_policy(session_key_id: &str) -> PolicyV2 {
    let now = jiff::Timestamp::now().as_second().max(0) as u64;
    PolicyV2 {
        version: 2,
        session_key_id: session_key_id.to_string(),
        device_id: "dev-test".to_string(),
        rules: PolicyRulesV2 {
            max_single_amount_usd: 10.0,
            max_daily_amount_usd: 100.0,
            max_monthly_amount_usd: 1000.0,
            expiry_unix: now + 3600,
            rate_limit_per_minute: 10,
            rate_limit_per_hour: 100,
            cooldown_after_denial_sec: 60,
            asset_whitelist: vec!["USDC".to_string()],
            chain_whitelist: vec!["eip155:8453".to_string()],
            contract_whitelist: vec![],
            payment_protocols: vec!["x402".to_string()],
        },
        budget_allocation: BudgetAllocation {
            allocated_usd: 50.0,
            allocated_at_unix: now,
            parent_total_usd: 1000.0,
            parent_session_id: "owner-wallet".to_string(),
        },
    }
}

/// Shared Background step used by `policy_amount.feature` and
/// `policy_rate_limit.feature`.
///
/// Sets up:
/// - A fresh Ed25519 device key + audit log (in a leaked `TempDir`).
/// - An active `session_key_id = "oc_sk_active"`.
/// - A default `PolicyV2` (permissive — scenarios tighten specific fields).
/// - A `PolicyState` with the policy attached, backed by a temp JSON file.
#[given("an Agent holds an active Session Key with a Policy")]
async fn agent_holds_active_session_key(world: &mut ConformanceWorld) {
    // 1. Device key + audit log (leaked TempDir keeps the file alive for the scenario's lifetime —
    //    same pattern as T22).
    let device_key = SigningKey::generate(&mut rand_core::UnwrapErr(getrandom::SysRng));
    world.device_key = Some(device_key.clone());
    let tmp_audit = tempdir().expect("tempdir for audit log");
    let audit_path = tmp_audit.path().join("audit.jsonl");
    std::mem::forget(tmp_audit);
    let audit_log = AuditLog::open(&audit_path, "dev-test", device_key).expect("AuditLog::open");
    world.audit_path = Some(audit_path);
    world.audit_log = Some(audit_log);

    // 2. Active session key id.
    world.session_key_id = Some("oc_sk_active".to_string());

    // 3. Default permissive policy. Per-scenario `Given` steps will tighten specific fields (e.g.
    //    `max_single_amount_usd = 0.50`) before `evaluate_11_step` runs.
    let policy = default_test_policy("oc_sk_active");
    world.policy = Some(policy.clone());

    // 4. Policy state with policy attached, backed by a temp file. The `PolicyState` carries the
    //    runtime `policy` field (`#[serde(skip)]`) so we attach it after `load`.
    let tmp_state = tempdir().expect("tempdir for policy state");
    let state_path = tmp_state.path().join("policy_state.json");
    std::mem::forget(tmp_state);
    let state = PolicyState::load(&state_path, "oc_sk_active".to_string())
        .expect("PolicyState::load")
        .with_policy(policy);
    world.policy_state = Some(state);
    world.policy_state_path = Some(state_path);
}
