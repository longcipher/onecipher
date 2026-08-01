//! v1 policy engine, fully designed and implemented in accordance with the Open Wallet Standard's
//! policy engine.
//!
//! Preserves the upstream PolicyRule enum + AND semantics + executable subprocess (5s timeout,
//! default-deny). The only deviation is replacing `chrono::DateTime::parse_from_rfc3339`
//! with a stdlib-only [`parse_rfc3339_to_unix`] helper (R56: no `chrono` in `oc-policy`).

use std::{io::Write as _, process::Command, time::Duration};

use oc_core::{Policy, PolicyContext, PolicyResult, PolicyRule};

/// Evaluate all policies against a context. AND semantics: short-circuits on
/// first denial. Returns `PolicyResult::allowed()` if every policy passes.
pub fn evaluate_policies(policies: &[Policy], context: &PolicyContext) -> PolicyResult {
    for policy in policies {
        let result = evaluate_one(policy, context);
        if !result.allow {
            return result;
        }
    }
    PolicyResult::allowed()
}

/// Evaluate a single policy: declarative rules first, then executable (if any).
pub fn evaluate_one(policy: &Policy, context: &PolicyContext) -> PolicyResult {
    // Declarative rules — fast, in-process
    for rule in &policy.rules {
        let result = evaluate_rule(rule, &policy.id, context);
        if !result.allow {
            return result;
        }
    }

    // Executable — only if declarative rules passed
    if let Some(ref exe) = policy.executable {
        return evaluate_executable(exe, policy.config.as_ref(), &policy.id, context);
    }

    PolicyResult::allowed()
}

// ---------------------------------------------------------------------------
// Declarative rule evaluation
// ---------------------------------------------------------------------------

/// Evaluate a single declarative rule against the context.
pub fn evaluate_rule(rule: &PolicyRule, policy_id: &str, ctx: &PolicyContext) -> PolicyResult {
    match rule {
        PolicyRule::AllowedChains { chain_ids } => eval_allowed_chains(policy_id, chain_ids, ctx),
        PolicyRule::ExpiresAt { timestamp } => eval_expires_at(policy_id, timestamp, ctx),
        PolicyRule::AllowedTypedDataContracts { contracts } => {
            eval_allowed_typed_data_contracts(policy_id, contracts, ctx)
        }
    }
}

fn eval_allowed_chains(policy_id: &str, chain_ids: &[String], ctx: &PolicyContext) -> PolicyResult {
    if chain_ids.iter().any(|c| c == &ctx.chain_id) {
        PolicyResult::allowed()
    } else {
        PolicyResult::denied(policy_id, format!("chain {} not in allowlist", ctx.chain_id))
    }
}

fn eval_expires_at(policy_id: &str, timestamp: &str, ctx: &PolicyContext) -> PolicyResult {
    let now = parse_rfc3339_to_unix(&ctx.timestamp);
    let exp = parse_rfc3339_to_unix(timestamp);
    match (now, exp) {
        (Some(now_secs), Some(exp_secs)) if now_secs > exp_secs => {
            PolicyResult::denied(policy_id, format!("policy expired at {timestamp}"))
        }
        (Some(_), Some(_)) => PolicyResult::allowed(),
        _ => PolicyResult::denied(
            policy_id,
            format!("invalid timestamp in expiry check: ctx={}, rule={}", ctx.timestamp, timestamp),
        ),
    }
}

fn eval_allowed_typed_data_contracts(
    policy_id: &str,
    contracts: &[String],
    ctx: &PolicyContext,
) -> PolicyResult {
    let td = match &ctx.typed_data {
        None => return PolicyResult::allowed(),
        Some(td) => td,
    };

    let contract = match &td.verifying_contract {
        None => {
            return PolicyResult::denied(
                policy_id,
                "typed data has no verifyingContract but policy requires one",
            );
        }
        Some(c) => c,
    };

    let contract_lower = contract.to_lowercase();
    if contracts.iter().any(|c| c.to_lowercase() == contract_lower) {
        PolicyResult::allowed()
    } else {
        PolicyResult::denied(policy_id, format!("verifyingContract {contract} not in allowed list"))
    }
}

// ---------------------------------------------------------------------------
// Executable policy evaluation
// ---------------------------------------------------------------------------

/// Evaluate an executable policy program (subprocess with 5s timeout, default-deny).
///
/// Preserved verbatim from Open Wallet Standard for advanced deployments (AD-04: "The optional
/// executable-subpolicy hook from the upstream project is preserved for advanced deployments but
/// is not on the v2 hot path.")
pub fn evaluate_executable(
    exe: &str,
    config: Option<&serde_json::Value>,
    policy_id: &str,
    ctx: &PolicyContext,
) -> PolicyResult {
    // Build stdin payload: context + policy_config
    let mut payload = match serde_json::to_value(ctx) {
        Ok(v) => v,
        Err(e) => {
            return PolicyResult::denied(policy_id, format!("failed to serialize context: {e}"))
        }
    };
    if let Some(cfg) = config {
        payload.as_object_mut().map(|m| m.insert("policy_config".to_string(), cfg.clone()));
    }

    let stdin_bytes = match serde_json::to_vec(&payload) {
        Ok(b) => b,
        Err(e) => {
            return PolicyResult::denied(policy_id, format!("failed to serialize context: {e}"))
        }
    };

    let mut child = match Command::new(exe)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            return PolicyResult::denied(policy_id, format!("failed to start executable: {e}"))
        }
    };

    // Write stdin
    if let Some(mut stdin) = child.stdin.take() {
        if let Err(e) = stdin.write_all(&stdin_bytes) {
            tracing::warn!("failed to write stdin to policy executable: {e}");
            return PolicyResult::denied(policy_id, format!("failed to write stdin: {e}"));
        }
    }

    // Wait with timeout (5 seconds)
    let output = match wait_with_timeout(&mut child, Duration::from_secs(5)) {
        Ok(output) => output,
        Err(reason) => return PolicyResult::denied(policy_id, reason),
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return PolicyResult::denied(
            policy_id,
            format!("executable exited with {}: {}", output.status, stderr.trim()),
        );
    }

    // Parse stdout as PolicyResult
    match serde_json::from_slice::<PolicyResult>(&output.stdout) {
        Ok(result) => {
            if result.allow {
                PolicyResult::allowed()
            } else {
                // Ensure the policy_id is set even if the executable omitted it
                PolicyResult::denied(
                    policy_id,
                    result.reason.unwrap_or_else(|| "denied by executable".into()),
                )
            }
        }
        Err(e) => PolicyResult::denied(policy_id, format!("invalid JSON from executable: {e}")),
    }
}

fn wait_with_timeout(
    child: &mut std::process::Child,
    timeout: Duration,
) -> Result<std::process::Output, String> {
    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_status)) => {
                // Process has exited — collect output.
                let mut stdout = Vec::new();
                let mut stderr = Vec::new();
                if let Some(mut out) = child.stdout.take() {
                    use std::io::Read;
                    if let Err(e) = out.read_to_end(&mut stdout) {
                        tracing::warn!("failed to read stdout from policy executable: {e}");
                    }
                }
                if let Some(mut err) = child.stderr.take() {
                    use std::io::Read;
                    if let Err(e) = err.read_to_end(&mut stderr) {
                        tracing::warn!("failed to read stderr from policy executable: {e}");
                    }
                }
                let status = child.wait().map_err(|e| e.to_string())?;
                return Ok(std::process::Output { status, stdout, stderr });
            }
            Ok(None) => {
                if start.elapsed() > timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("executable timed out after {}s", timeout.as_secs()));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(format!("failed to wait on executable: {e}")),
        }
    }
}

// ---------------------------------------------------------------------------
// stdlib-only RFC3339 parser (replaces chrono, R56)
// ---------------------------------------------------------------------------

/// Parse an RFC3339 timestamp (e.g. `"2026-03-22T10:35:22Z"`) into Unix seconds.
///
/// Returns `None` on parse failure. Handles the subset of RFC3339 used by policy
/// timestamps: `YYYY-MM-DDTHH:MM:SS[.fff][Z|±HH:MM]`. Uses Howard
/// Hinnant's civil-from-days algorithm for the date-to-days conversion.
///
/// This is a deviation from the upstream Open Wallet Standard v1 which uses
/// `chrono::DateTime::parse_from_rfc3339`. The deviation keeps `cargo tree -p oc-policy` free of
/// `chrono` (R56).
fn parse_rfc3339_to_unix(s: &str) -> Option<i64> {
    let bytes = s.as_bytes();
    // Minimum: "YYYY-MM-DDTHH:MM:SSZ" = 20 chars
    if bytes.len() < 20 {
        return None;
    }

    // Parse date: YYYY-MM-DD
    let year: i64 = s.get(0..4)?.parse().ok()?;
    if bytes[4] != b'-' {
        return None;
    }
    let month: i64 = s.get(5..7)?.parse().ok()?;
    if bytes[7] != b'-' {
        return None;
    }
    let day: i64 = s.get(8..10)?.parse().ok()?;

    // Separator: T, t, or space
    if bytes[10] != b'T' && bytes[10] != b't' && bytes[10] != b' ' {
        return None;
    }

    // Parse time: HH:MM:SS
    let hour: i64 = s.get(11..13)?.parse().ok()?;
    if bytes[13] != b':' {
        return None;
    }
    let minute: i64 = s.get(14..16)?.parse().ok()?;
    if bytes[16] != b':' {
        return None;
    }
    let second: i64 = s.get(17..19)?.parse().ok()?;

    // Skip fractional seconds if present (e.g. ".123")
    let mut tz_pos = 19;
    if bytes.len() > 19 && bytes[19] == b'.' {
        tz_pos = 20;
        while tz_pos < bytes.len() && bytes[tz_pos].is_ascii_digit() {
            tz_pos += 1;
        }
    }

    if tz_pos >= bytes.len() {
        return None; // no timezone suffix
    }

    // Timezone: Z or +HH:MM or -HH:MM
    let tz_offset_sec: i64 = match bytes[tz_pos] {
        b'Z' | b'z' => 0,
        b'+' | b'-' => {
            let rest = s.get(tz_pos..)?;
            // rest is like "+HH:MM" (6 chars) — may have trailing content, we only need first 6
            if rest.len() < 6 {
                return None;
            }
            let sign = if rest.starts_with('+') { 1 } else { -1 };
            let tz_hour: i64 = rest.get(1..3)?.parse().ok()?;
            if rest.as_bytes()[3] != b':' {
                return None;
            }
            let tz_min: i64 = rest.get(4..6)?.parse().ok()?;
            sign * (tz_hour * 3600 + tz_min * 60)
        }
        _ => return None,
    };

    // Validate ranges
    if !(1..=12).contains(&month) ||
        !(1..=31).contains(&day) ||
        !(0..=23).contains(&hour) ||
        !(0..=59).contains(&minute) ||
        !(0..=60).contains(&second)
    {
        return None;
    }

    // Days from Unix epoch (1970-01-01) — Howard Hinnant's civil-from-days algorithm.
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let m = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * m + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days_since_epoch = era * 146097 + doe - 719468;

    Some(days_since_epoch * 86400 + hour * 3600 + minute * 60 + second - tz_offset_sec)
}

#[cfg(test)]
mod tests {
    use oc_core::{
        PolicyAction,
        policy::{SpendingContext, TransactionContext, TypedDataContext},
    };

    use super::*;

    fn base_context() -> PolicyContext {
        PolicyContext {
            chain_id: "eip155:8453".to_string(),
            wallet_id: "wallet-1".to_string(),
            api_key_id: "key-1".to_string(),
            transaction: TransactionContext {
                to: Some("0x742d35Cc6634C0532925a3b844Bc9e7595f2bD0C".to_string()),
                value: Some("100000000000000000".to_string()), // 0.1 ETH
                raw_hex: "0x02f8...".to_string(),
                data: None,
            },
            spending: SpendingContext {
                daily_total: "50000000000000000".to_string(), // 0.05 ETH already spent
                date: "2026-03-22".to_string(),
            },
            timestamp: "2026-03-22T10:35:22Z".to_string(),
            typed_data: None,
        }
    }

    fn policy_with_rules(id: &str, rules: Vec<PolicyRule>) -> Policy {
        Policy {
            id: id.to_string(),
            name: id.to_string(),
            version: 1,
            created_at: "2026-03-22T10:00:00Z".to_string(),
            rules,
            executable: None,
            config: None,
            action: PolicyAction::Deny,
        }
    }

    // --- AllowedChains ---

    #[test]
    fn allowed_chains_passes_matching_chain() {
        let ctx = base_context(); // chain_id = eip155:8453
        let policy = policy_with_rules(
            "chains",
            vec![PolicyRule::AllowedChains {
                chain_ids: vec!["eip155:8453".to_string(), "eip155:84532".to_string()],
            }],
        );

        let result = evaluate_policies(&[policy], &ctx);
        assert!(result.allow);
    }

    #[test]
    fn allowed_chains_denies_non_matching() {
        let ctx = base_context();
        let policy = policy_with_rules(
            "chains",
            vec![PolicyRule::AllowedChains {
                chain_ids: vec!["eip155:1".to_string()], // mainnet only
            }],
        );

        let result = evaluate_policies(&[policy], &ctx);
        assert!(!result.allow);
        assert!(result.reason.unwrap().contains("not in allowlist"));
    }

    // --- ExpiresAt ---

    #[test]
    fn expires_at_allows_before_expiry() {
        let ctx = base_context(); // timestamp = 2026-03-22T10:35:22Z
        let policy = policy_with_rules(
            "exp",
            vec![PolicyRule::ExpiresAt { timestamp: "2026-04-01T00:00:00Z".to_string() }],
        );

        let result = evaluate_policies(&[policy], &ctx);
        assert!(result.allow);
    }

    #[test]
    fn expires_at_denies_after_expiry() {
        let ctx = base_context(); // timestamp = 2026-03-22T10:35:22Z
        let policy = policy_with_rules(
            "exp",
            vec![PolicyRule::ExpiresAt {
                timestamp: "2026-03-01T00:00:00Z".to_string(), // already expired
            }],
        );

        let result = evaluate_policies(&[policy], &ctx);
        assert!(!result.allow);
        assert!(result.reason.unwrap().contains("expired"));
    }

    // --- Multi-rule / multi-policy AND semantics ---

    #[test]
    fn multiple_rules_all_must_pass() {
        let ctx = base_context();
        let policy = policy_with_rules(
            "multi",
            vec![
                PolicyRule::AllowedChains { chain_ids: vec!["eip155:8453".to_string()] },
                PolicyRule::ExpiresAt { timestamp: "2026-04-01T00:00:00Z".to_string() },
            ],
        );

        let result = evaluate_policies(&[policy], &ctx);
        assert!(result.allow);
    }

    #[test]
    fn short_circuits_on_first_denial() {
        let ctx = base_context();
        let policies = vec![
            policy_with_rules(
                "pass",
                vec![PolicyRule::AllowedChains { chain_ids: vec!["eip155:8453".to_string()] }],
            ),
            policy_with_rules(
                "fail",
                vec![PolicyRule::AllowedChains {
                    chain_ids: vec!["eip155:1".to_string()], // wrong chain
                }],
            ),
            policy_with_rules(
                "never-reached",
                vec![PolicyRule::ExpiresAt { timestamp: "2020-01-01T00:00:00Z".to_string() }],
            ),
        ];

        let result = evaluate_policies(&policies, &ctx);
        assert!(!result.allow);
        assert_eq!(result.policy_id.unwrap(), "fail");
    }

    #[test]
    fn empty_policies_allows() {
        let ctx = base_context();
        let result = evaluate_policies(&[], &ctx);
        assert!(result.allow);
    }

    #[test]
    fn policy_with_no_rules_and_no_executable_allows() {
        let ctx = base_context();
        let policy = policy_with_rules("empty", vec![]);
        let result = evaluate_policies(&[policy], &ctx);
        assert!(result.allow);
    }

    // --- Executable policy ---

    #[test]
    fn executable_invalid_json_denies() {
        let ctx = base_context();
        // sh without args just reads stdin, won't produce valid JSON → denied
        let result = evaluate_executable("sh", None, "exe-invalid", &ctx);
        assert!(!result.allow);
    }

    #[test]
    fn executable_nonexistent_binary_denies() {
        let ctx = base_context();
        let result = evaluate_executable("/nonexistent/binary", None, "bad-exe", &ctx);
        assert!(!result.allow);
        assert!(result.reason.unwrap().contains("failed to start"));
    }

    #[test]
    fn executable_with_script() {
        // Create a temp script that outputs {"allow": true}
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("allow.sh");
        std::fs::write(&script, "#!/bin/sh\ncat > /dev/null\necho '{\"allow\": true}'\n").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let ctx = base_context();
        let result = evaluate_executable(script.to_str().unwrap(), None, "script-allow", &ctx);
        assert!(result.allow);
    }

    #[test]
    fn executable_deny_script() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("deny.sh");
        std::fs::write(
            &script,
            "#!/bin/sh\ncat > /dev/null\necho '{\"allow\": false, \"reason\": \"nope\"}'\n",
        )
        .unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let ctx = base_context();
        let result = evaluate_executable(script.to_str().unwrap(), None, "script-deny", &ctx);
        assert!(!result.allow);
        assert_eq!(result.reason.as_deref(), Some("nope"));
        assert_eq!(result.policy_id.as_deref(), Some("script-deny"));
    }

    #[test]
    fn executable_nonzero_exit_denies() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("fail.sh");
        std::fs::write(&script, "#!/bin/sh\nexit 1\n").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let ctx = base_context();
        let result = evaluate_executable(script.to_str().unwrap(), None, "exit-fail", &ctx);
        assert!(!result.allow);
    }

    #[test]
    fn rules_prefilter_before_executable() {
        // If declarative rules deny, executable should not run
        let dir = tempfile::tempdir().unwrap();
        // Create a marker file approach: if exe runs, it creates a file
        let marker = dir.path().join("ran");
        let script = dir.path().join("marker.sh");
        std::fs::write(
            &script,
            format!("#!/bin/sh\ntouch {}\necho '{{\"allow\": true}}'\n", marker.display()),
        )
        .unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let ctx = base_context();
        let policy = Policy {
            id: "prefilter".to_string(),
            name: "prefilter".to_string(),
            version: 1,
            created_at: "2026-03-22T10:00:00Z".to_string(),
            rules: vec![PolicyRule::AllowedChains {
                chain_ids: vec!["eip155:1".to_string()], // wrong chain → deny
            }],
            executable: Some(script.to_str().unwrap().to_string()),
            config: None,
            action: PolicyAction::Deny,
        };

        let result = evaluate_policies(&[policy], &ctx);
        assert!(!result.allow);
        assert!(!marker.exists(), "executable should not have run");
    }

    // --- AllowedTypedDataContracts ---

    fn typed_data_context(verifying_contract: Option<&str>) -> TypedDataContext {
        TypedDataContext {
            verifying_contract: verifying_contract.map(String::from),
            domain_chain_id: Some(8453),
            primary_type: "PermitSingle".into(),
            domain_name: Some("Permit2".into()),
            domain_version: Some("1".into()),
            raw_json: "{}".into(),
        }
    }

    #[test]
    fn allowed_typed_data_contracts_matching_allows() {
        let mut ctx = base_context();
        ctx.typed_data =
            Some(typed_data_context(Some("0x000000000022D473030F116dDEE9F6B43aC78BA3")));
        let policy = policy_with_rules(
            "td",
            vec![PolicyRule::AllowedTypedDataContracts {
                contracts: vec!["0x000000000022D473030F116dDEE9F6B43aC78BA3".into()],
            }],
        );
        let result = evaluate_policies(&[policy], &ctx);
        assert!(result.allow);
    }

    #[test]
    fn allowed_typed_data_contracts_non_matching_denies() {
        let mut ctx = base_context();
        ctx.typed_data = Some(typed_data_context(Some("0xDEAD")));
        let policy = policy_with_rules(
            "td",
            vec![PolicyRule::AllowedTypedDataContracts {
                contracts: vec!["0x000000000022D473030F116dDEE9F6B43aC78BA3".into()],
            }],
        );
        let result = evaluate_policies(&[policy], &ctx);
        assert!(!result.allow);
        assert!(result.reason.unwrap().contains("not in allowed list"));
    }

    #[test]
    fn allowed_typed_data_contracts_case_insensitive() {
        let mut ctx = base_context();
        ctx.typed_data =
            Some(typed_data_context(Some("0x000000000022d473030f116ddee9f6b43ac78ba3")));
        let policy = policy_with_rules(
            "td",
            vec![PolicyRule::AllowedTypedDataContracts {
                contracts: vec!["0x000000000022D473030F116dDEE9F6B43aC78BA3".into()],
            }],
        );
        let result = evaluate_policies(&[policy], &ctx);
        assert!(result.allow);
    }

    #[test]
    fn allowed_typed_data_contracts_no_typed_data_passes() {
        let ctx = base_context();
        let policy = policy_with_rules(
            "td",
            vec![PolicyRule::AllowedTypedDataContracts {
                contracts: vec!["0x000000000022D473030F116dDEE9F6B43aC78BA3".into()],
            }],
        );
        let result = evaluate_policies(&[policy], &ctx);
        assert!(result.allow);
    }

    #[test]
    fn allowed_typed_data_contracts_no_verifying_contract_denies() {
        let mut ctx = base_context();
        ctx.typed_data = Some(typed_data_context(None));
        let policy = policy_with_rules(
            "td",
            vec![PolicyRule::AllowedTypedDataContracts {
                contracts: vec!["0x000000000022D473030F116dDEE9F6B43aC78BA3".into()],
            }],
        );
        let result = evaluate_policies(&[policy], &ctx);
        assert!(!result.allow);
        assert!(result.reason.unwrap().contains("no verifyingContract"));
    }

    #[test]
    fn allowed_typed_data_contracts_empty_list_denies_everything() {
        let mut ctx = base_context();
        ctx.typed_data =
            Some(typed_data_context(Some("0x000000000022D473030F116dDEE9F6B43aC78BA3")));
        let policy = policy_with_rules(
            "td",
            vec![PolicyRule::AllowedTypedDataContracts { contracts: vec![] }],
        );
        let result = evaluate_policies(&[policy], &ctx);
        assert!(!result.allow);
        assert!(result.reason.unwrap().contains("not in allowed list"));
    }

    #[test]
    fn combined_rules_with_typed_data_contracts() {
        let mut ctx = base_context();
        ctx.typed_data =
            Some(typed_data_context(Some("0x000000000022D473030F116dDEE9F6B43aC78BA3")));
        let policy = policy_with_rules(
            "combined",
            vec![
                PolicyRule::AllowedChains { chain_ids: vec!["eip155:8453".into()] },
                PolicyRule::AllowedTypedDataContracts {
                    contracts: vec!["0x000000000022D473030F116dDEE9F6B43aC78BA3".into()],
                },
                PolicyRule::ExpiresAt { timestamp: "2027-01-01T00:00:00Z".into() },
            ],
        );
        let result = evaluate_policies(&[policy], &ctx);
        assert!(result.allow);
    }

    // --- RFC3339 parser (chrono replacement) ---

    #[test]
    fn rfc3339_parser_z_suffix() {
        // 2026-03-22T10:35:22Z
        let unix = parse_rfc3339_to_unix("2026-03-22T10:35:22Z");
        assert!(unix.is_some());
        // Should equal: days_since_epoch(20534) * 86400 + 10*3600 + 35*60 + 22
        assert_eq!(unix.unwrap(), 20534 * 86400 + 10 * 3600 + 35 * 60 + 22);
    }

    #[test]
    fn rfc3339_parser_offset() {
        // 2026-03-22T10:35:22+00:00 == Z
        let z = parse_rfc3339_to_unix("2026-03-22T10:35:22Z");
        let off = parse_rfc3339_to_unix("2026-03-22T10:35:22+00:00");
        assert_eq!(z, off);

        // -05:00 offset: should be 5 hours ahead of Z
        let neg = parse_rfc3339_to_unix("2026-03-22T05:35:22-05:00");
        assert_eq!(z, neg);
    }

    #[test]
    fn rfc3339_parser_fractional() {
        let z = parse_rfc3339_to_unix("2026-03-22T10:35:22Z");
        let f = parse_rfc3339_to_unix("2026-03-22T10:35:22.500Z");
        assert_eq!(z, f); // fractional part is truncated, whole seconds match
    }

    #[test]
    fn rfc3339_parser_invalid() {
        assert!(parse_rfc3339_to_unix("not-a-date").is_none());
        assert!(parse_rfc3339_to_unix("2026-03-22").is_none());
        assert!(parse_rfc3339_to_unix("2026-13-01T00:00:00Z").is_none()); // month 13
        assert!(parse_rfc3339_to_unix("").is_none());
    }
}
