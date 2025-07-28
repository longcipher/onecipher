//! Criterion benchmark for `evaluate_11_step`.
//!
//! Performance goal (R29 / Non-Functional Goals): p99 < 5 ms in-process.
//! CI gate may consume the `target/criterion/policy_eval/.../estimates.json`
//! to assert the p99 bound.

use criterion::{Criterion, criterion_group, criterion_main};
use oc_policy::{
    BudgetAllocation, PayRequest, PolicyRulesV2, PolicyState, PolicyV2, evaluate_11_step,
};

fn bench_policy() -> PolicyV2 {
    PolicyV2 {
        version: 2,
        session_key_id: "sk-bench".into(),
        device_id: "dev-bench".into(),
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
            allocated_usd: 100.0,
            allocated_at_unix: 0,
            parent_total_usd: 1000.0,
            parent_session_id: "parent".into(),
        },
    }
}

fn bench_request() -> PayRequest {
    PayRequest {
        session_key_id: "sk-bench".into(),
        device_id: "dev-bench".into(),
        amount_usd: 1.0,
        asset: "USDC".into(),
        chain_id: "eip155:8453".into(),
        recipient: Some("0xABC".into()),
    }
}

fn bench_eval(c: &mut Criterion) {
    let policy = bench_policy();
    let req = bench_request();

    c.bench_function("evaluate_11_step_allow", |b| {
        b.iter(|| {
            // Fresh state each iteration so the ALLOW path is exercised without
            // accumulating budget / filling rate-limit windows.
            let mut state = PolicyState::new("sk-bench".into())
                .with_policy(policy.clone())
                .with_now_override(1_700_000_000);
            let req = std::hint::black_box(&req);
            evaluate_11_step(req, "sk-bench", &mut state)
        });
    });

    c.bench_function("evaluate_11_step_deny_policy_missing", |b| {
        b.iter(|| {
            // No policy attached → step 2 returns PolicyMissing (DENY fast-path).
            let mut state = PolicyState::new("sk-bench".into()).with_now_override(1_700_000_000);
            let req = std::hint::black_box(&req);
            evaluate_11_step(req, "sk-bench", &mut state)
        });
    });
}

criterion_group!(benches, bench_eval);
criterion_main!(benches);
