//! Policy Engine v2 — 11-step evaluation flow (R29 / AD-04).
//!
//! Extends the v1 implementation with frequency, budget, cooldown, and persisted counters.
//! Evaluation is entirely in-process (AD-04); the caller calls `PolicyState::persist`
//! after `evaluate_11_step` returns to flush counters to disk with fsync.

use std::{
    collections::VecDeque,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

use crate::OcPolicyError;

// ---------------------------------------------------------------------------
// Data structures (R28)
// ---------------------------------------------------------------------------

/// A payment request evaluated by the 11-step Policy Engine.
///
/// Defined locally in `oc-policy`; the wire-format `PayX402Request` lives in
/// `oc_keyagent::proto` (UDS IPC codec).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayRequest {
    pub session_key_id: String,
    pub device_id: String,
    pub amount_usd: f64,
    /// e.g. "USDC", "ETH"
    pub asset: String,
    /// CAIP-2, e.g. "eip155:8453"
    pub chain_id: String,
    /// Contract address or `None` for native transfers.
    pub recipient: Option<String>,
}

/// Policy v2 container (R28).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyV2 {
    pub version: u16,
    pub session_key_id: String,
    pub device_id: String,
    pub rules: PolicyRulesV2,
    pub budget_allocation: BudgetAllocation,
}

/// v2 rule set (R28).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRulesV2 {
    pub max_single_amount_usd: f64,
    pub max_daily_amount_usd: f64,
    pub max_monthly_amount_usd: f64,
    pub expiry_unix: u64,
    pub rate_limit_per_minute: u32,
    pub rate_limit_per_hour: u32,
    pub cooldown_after_denial_sec: u64,
    pub asset_whitelist: Vec<String>,
    pub chain_whitelist: Vec<String>,
    pub contract_whitelist: Vec<String>,
    /// e.g. `["x402", "mpp"]`
    pub payment_protocols: Vec<String>,
}

/// Budget allocation for a session key (R28).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetAllocation {
    pub allocated_usd: f64,
    pub allocated_at_unix: u64,
    pub parent_total_usd: f64,
    pub parent_session_id: String,
}

// ---------------------------------------------------------------------------
// Decision + DenyReason (R80)
// ---------------------------------------------------------------------------

/// Deny reasons (R80 — exactly 9 variants).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenyReason {
    RateLimitMinute,
    RateLimitHour,
    BudgetExceeded,
    Whitelist,
    Expired,
    PasskeyForged,
    PolicyMissing,
    Cooldown,
    Unknown,
}

/// Evaluation outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny(DenyReason),
}

// ---------------------------------------------------------------------------
// AlertSink (C-10)
// ---------------------------------------------------------------------------

/// Human-readable alert fired after 3 consecutive DENY decisions (C-10).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HumanAlert {
    pub session_key_id: String,
    pub device_id: String,
    /// The last 3 consecutive deny reasons.
    pub deny_reasons: Vec<DenyReason>,
    pub timestamp_unix: u64,
}

/// Sink for human alerts (C-10). Implementations may log, send to a notification
/// channel, or push to a monitoring system.
pub trait AlertSink: Send + Sync {
    fn notify(&self, alert: &HumanAlert);
}

/// Default Phase 1 sink: logs to stderr.
pub struct LogAlertSink;

impl AlertSink for LogAlertSink {
    fn notify(&self, alert: &HumanAlert) {
        eprintln!(
            "[POLICY-ALERT] session_key_id={} device_id={} reasons={:?} ts={}",
            alert.session_key_id, alert.device_id, alert.deny_reasons, alert.timestamp_unix
        );
    }
}

/// Constructs the default alert sink (`LogAlertSink`) for `PolicyState` deserialization.
fn default_alert_sink() -> Box<dyn AlertSink> {
    Box::new(LogAlertSink)
}

// ---------------------------------------------------------------------------
// PolicyState — persisted counters (AD-04)
// ---------------------------------------------------------------------------

/// Runtime policy state: persisted counters + non-serialised runtime fields.
///
/// The serializable fields are written to `~/.onecipher/state/policy_counters.json`
/// (0600 perms) after every ALLOW / DENY decision via [`PolicyState::persist`].
/// The `policy` and `alert_sink` fields are `#[serde(skip)]` (runtime-only).
///
/// **Deviation note:** `local_spent_usd` is monotonic (cumulative budget counter);
/// true rolling 24h/30d spend tracking lives in `daily_window` / `monthly_window`.
/// The monotonic counter is only reset when the `BudgetAllocation` changes
/// (caller's responsibility).
///
/// **Deviation note:** `now_override` is a test-only field (`#[serde(skip)]`) that
/// allows deterministic time injection for unit/proptest. In production it is `None`
/// and `evaluate_11_step` uses `SystemTime::now`.
#[derive(Serialize, Deserialize)]
pub struct PolicyState {
    // --- serializable counters (persisted to JSON) ---
    pub session_key_id: String,
    /// Cumulative spent (budget counter).
    pub local_spent_usd: f64,
    /// Unix-millis timestamps of recent ALLOW decisions (60s window).
    pub minutely_window: VecDeque<u64>,
    /// Unix-millis timestamps of recent ALLOW decisions (3600s window).
    pub hourly_window: VecDeque<u64>,
    /// (timestamp_ms, amount_usd) pairs for ALLOW decisions in the rolling 24h window.
    pub daily_window: VecDeque<(u64, f64)>,
    /// (timestamp_ms, amount_usd) pairs for ALLOW decisions in the rolling 30d window.
    pub monthly_window: VecDeque<(u64, f64)>,
    /// Last deny timestamp (unix seconds) — for cooldown.
    pub last_deny_at_unix: Option<u64>,
    /// Consecutive deny counter — for alert (C-10).
    pub consecutive_deny_counter: u32,
    /// Last 3 deny reasons — for alert payload.
    pub last_deny_reasons: Vec<DenyReason>,

    // --- runtime (NOT serialized) ---
    #[serde(skip, default = "default_alert_sink")]
    pub alert_sink: Box<dyn AlertSink>,
    /// Loaded by the caller; `None` => step 2 returns `PolicyMissing`.
    #[serde(skip)]
    pub policy: Option<PolicyV2>,
    /// Test-only time override; `None` => uses `SystemTime::now()`.
    #[serde(skip)]
    pub now_override: Option<u64>,
}

impl std::fmt::Debug for PolicyState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PolicyState")
            .field("session_key_id", &self.session_key_id)
            .field("local_spent_usd", &self.local_spent_usd)
            .field("minutely_window", &self.minutely_window)
            .field("hourly_window", &self.hourly_window)
            .field("daily_window", &self.daily_window)
            .field("monthly_window", &self.monthly_window)
            .field("last_deny_at_unix", &self.last_deny_at_unix)
            .field("consecutive_deny_counter", &self.consecutive_deny_counter)
            .field("last_deny_reasons", &self.last_deny_reasons)
            .field("policy", &self.policy)
            .field("now_override", &self.now_override)
            .finish_non_exhaustive()
    }
}

impl PolicyState {
    /// Create a fresh state with zero counters and the default `LogAlertSink`.
    pub fn new(session_key_id: String) -> Self {
        Self {
            session_key_id,
            local_spent_usd: 0.0,
            minutely_window: VecDeque::new(),
            hourly_window: VecDeque::new(),
            daily_window: VecDeque::new(),
            monthly_window: VecDeque::new(),
            last_deny_at_unix: None,
            consecutive_deny_counter: 0,
            last_deny_reasons: Vec::new(),
            alert_sink: default_alert_sink(),
            policy: None,
            now_override: None,
        }
    }

    /// Builder: inject a custom `AlertSink` (e.g. a mock for testing).
    pub fn with_alert_sink(mut self, sink: Box<dyn AlertSink>) -> Self {
        self.alert_sink = sink;
        self
    }

    /// Builder: attach the loaded `PolicyV2` (caller loads from storage).
    pub fn with_policy(mut self, policy: PolicyV2) -> Self {
        self.policy = Some(policy);
        self
    }

    /// Builder: override `now` for deterministic testing.
    pub const fn with_now_override(mut self, now_unix: u64) -> Self {
        self.now_override = Some(now_unix);
        self
    }

    /// Load state from `path`. If the file does not exist, returns a fresh state
    /// for `session_key_id`. On Unix, warns (not errors) if the file mode != 0600.
    pub fn load(path: &Path, session_key_id: String) -> Result<Self, OcPolicyError> {
        if !path.exists() {
            return Ok(Self::new(session_key_id));
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::metadata(path) {
                let mode = meta.permissions().mode();
                if mode & 0o077 != 0 {
                    eprintln!(
                        "[POLICY-WARN] {} has mode {:o}, expected 0600",
                        path.display(),
                        mode
                    );
                }
            }
        }

        let data = std::fs::read(path)?;
        let mut state: Self = serde_json::from_slice(&data)?;
        state.session_key_id = session_key_id;
        Ok(state)
    }

    /// Persist state to `path` with fsync + atomic rename (AD-04).
    ///
    /// Writes to a temp file in the same directory, fsyncs, sets 0600 perms,
    /// then atomically renames to `path`. Parent dirs are created with 0700 perms.
    pub fn persist(&self, path: &Path) -> Result<(), OcPolicyError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
            }
        }

        let tmp = path.with_extension("json.tmp");
        let json = serde_json::to_vec_pretty(self)?;
        std::fs::write(&tmp, json)?;

        // fsync the temp file before rename (crash safety)
        let f = std::fs::File::open(&tmp)?;
        f.sync_all()?;
        drop(f);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        }

        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    /// Record an ALLOW decision: increment `local_spent`, push to sliding windows
    /// (minutely/hourly timestamps + daily/monthly (timestamp, amount) pairs),
    /// reset `consecutive_deny_counter` and `last_deny_reasons`.
    pub fn record_allow(&mut self, req: &PayRequest, now_ms: u64) {
        self.local_spent_usd += req.amount_usd;
        self.minutely_window.push_back(now_ms);
        self.hourly_window.push_back(now_ms);
        self.daily_window.push_back((now_ms, req.amount_usd));
        self.monthly_window.push_back((now_ms, req.amount_usd));
        self.consecutive_deny_counter = 0;
        self.last_deny_reasons.clear();
    }

    /// Record a DENY decision: update `last_deny_at`, increment `consecutive_deny_counter`,
    /// push reason to `last_deny_reasons`. If counter reaches 3, fire `AlertSink` and reset.
    pub fn record_deny(&mut self, reason: DenyReason, session_key_id: &str, now_ms: u64) {
        let now_unix = now_ms / 1000;
        self.last_deny_at_unix = Some(now_unix);
        self.consecutive_deny_counter += 1;
        self.last_deny_reasons.push(reason);
        if self.last_deny_reasons.len() > 3 {
            self.last_deny_reasons.remove(0);
        }

        // C-10: 3 consecutive DENYs → fire alert, then reset.
        if self.consecutive_deny_counter == 3 {
            let device_id = self.policy.as_ref().map(|p| p.device_id.clone()).unwrap_or_default();
            let alert = HumanAlert {
                session_key_id: session_key_id.to_string(),
                device_id,
                deny_reasons: self.last_deny_reasons.clone(),
                timestamp_unix: now_unix,
            };
            self.alert_sink.notify(&alert);
            self.consecutive_deny_counter = 0;
            self.last_deny_reasons.clear();
        }
    }
}

// ---------------------------------------------------------------------------
// Time helpers (stdlib only — no chrono, R56)
// ---------------------------------------------------------------------------

/// Current Unix time in seconds.
fn current_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

// ---------------------------------------------------------------------------
// Sliding-window helpers
// ---------------------------------------------------------------------------

/// Evict entries from `window` that are older than `window_ms` relative to `now_ms`.
fn slide_window(window: &mut VecDeque<u64>, now_ms: u64, window_ms: u64) {
    while let Some(&front) = window.front() {
        if now_ms.saturating_sub(front) > window_ms {
            window.pop_front();
        } else {
            break;
        }
    }
}

/// Evict `(timestamp_ms, amount)` entries older than `window_ms` relative to `now_ms`.
/// Used by the rolling 24h / 30d cumulative-spend windows.
fn slide_amount_window(window: &mut VecDeque<(u64, f64)>, now_ms: u64, window_ms: u64) {
    while let Some(&(front_ts, _)) = window.front() {
        if now_ms.saturating_sub(front_ts) > window_ms {
            window.pop_front();
        } else {
            break;
        }
    }
}

/// Slide rate-limit windows (60s + 3600s) and rolling amount windows (24h + 30d).
fn slide_all_windows(state: &mut PolicyState, now_ms: u64) {
    slide_window(&mut state.minutely_window, now_ms, 60_000);
    slide_window(&mut state.hourly_window, now_ms, 3_600_000);
    slide_amount_window(&mut state.daily_window, now_ms, 86_400_000);
    slide_amount_window(&mut state.monthly_window, now_ms, 2_592_000_000);
}

// ---------------------------------------------------------------------------
// 11-step evaluation — each step is a named function (Readability Priorities)
// ---------------------------------------------------------------------------

/// Step 1: Parse the request. (Structural no-op — `PayRequest` arrives pre-parsed
/// from the wire. This step exists for explicitness in the 11-step flow.)
///
/// **Deviation note:** the "parse" step is structurally present but a no-op since
/// `PayRequest` arrives pre-parsed from the wire.
const fn step_1_parse_request(req: &PayRequest) -> &PayRequest {
    req
}

/// Step 2: Load the policy. Returns `Err(PolicyMissing)` if no policy is loaded.
fn step_2_load_policy(state: &PolicyState) -> Result<&PolicyV2, DenyReason> {
    state.policy.as_ref().ok_or(DenyReason::PolicyMissing)
}

/// Step 3: Check policy expiry. `now > expiry` → `Expired`.
const fn step_3_check_expiry(policy: &PolicyV2, now_unix: u64) -> Result<(), DenyReason> {
    if now_unix > policy.rules.expiry_unix {
        return Err(DenyReason::Expired);
    }
    Ok(())
}

/// Step 4: Check asset / chain / contract whitelists. Mismatch → `Whitelist`.
///
/// Empty whitelists are treated as "no restriction" (allow all). For the contract
/// whitelist, a `None` recipient (native transfer) is allowed.
fn step_4_check_whitelists(policy: &PolicyV2, req: &PayRequest) -> Result<(), DenyReason> {
    // Asset whitelist
    if !policy.rules.asset_whitelist.is_empty() &&
        !policy.rules.asset_whitelist.iter().any(|a| a == &req.asset)
    {
        return Err(DenyReason::Whitelist);
    }

    // Chain whitelist
    if !policy.rules.chain_whitelist.is_empty() &&
        !policy.rules.chain_whitelist.iter().any(|c| c == &req.chain_id)
    {
        return Err(DenyReason::Whitelist);
    }

    // Contract whitelist (case-insensitive; None recipient = native, allowed)
    if let Some(recipient) = &req.recipient &&
        !policy.rules.contract_whitelist.is_empty() &&
        !policy.rules.contract_whitelist.iter().any(|c| c.eq_ignore_ascii_case(recipient))
    {
        return Err(DenyReason::Whitelist);
    }

    Ok(())
}

/// Step 5: Check deny cooldown. If `last_deny + cooldown > now` → `Cooldown`.
const fn step_5_check_cooldown(
    state: &PolicyState,
    policy: &PolicyV2,
    now_unix: u64,
) -> Result<(), DenyReason> {
    if let Some(last_deny) = state.last_deny_at_unix &&
        last_deny.saturating_add(policy.rules.cooldown_after_denial_sec) > now_unix
    {
        return Err(DenyReason::Cooldown);
    }
    Ok(())
}

/// Step 6: Check per-minute rate limit. `window.len() >= limit` → `RateLimitMinute`.
fn step_6_check_rate_limit_minute(
    state: &PolicyState,
    policy: &PolicyV2,
) -> Result<(), DenyReason> {
    if state.minutely_window.len() >= policy.rules.rate_limit_per_minute as usize {
        return Err(DenyReason::RateLimitMinute);
    }
    Ok(())
}

/// Step 7: Check per-hour rate limit. `window.len() >= limit` → `RateLimitHour`.
fn step_7_check_rate_limit_hour(state: &PolicyState, policy: &PolicyV2) -> Result<(), DenyReason> {
    if state.hourly_window.len() >= policy.rules.rate_limit_per_hour as usize {
        return Err(DenyReason::RateLimitHour);
    }
    Ok(())
}

/// Step 8: Check pessimistic budget. `local_spent + amount > allocated` → `BudgetExceeded`.
fn step_8_check_budget(
    state: &PolicyState,
    policy: &PolicyV2,
    req: &PayRequest,
) -> Result<(), DenyReason> {
    if state.local_spent_usd + req.amount_usd > policy.budget_allocation.allocated_usd {
        return Err(DenyReason::BudgetExceeded);
    }
    Ok(())
}

/// Step 8a: Check daily cumulative. `sum(daily_window.amounts) + req.amount > max_daily`
/// → `BudgetExceeded`.
fn step_8a_check_daily_cumulative(
    state: &PolicyState,
    policy: &PolicyV2,
    req: &PayRequest,
) -> Result<(), DenyReason> {
    let daily_spent: f64 = state.daily_window.iter().map(|(_, a)| a).sum();
    if daily_spent + req.amount_usd > policy.rules.max_daily_amount_usd {
        return Err(DenyReason::BudgetExceeded);
    }
    Ok(())
}

/// Step 8b: Check monthly cumulative. `sum(monthly_window.amounts) + req.amount > max_monthly`
/// → `BudgetExceeded`.
fn step_8b_check_monthly_cumulative(
    state: &PolicyState,
    policy: &PolicyV2,
    req: &PayRequest,
) -> Result<(), DenyReason> {
    let monthly_spent: f64 = state.monthly_window.iter().map(|(_, a)| a).sum();
    if monthly_spent + req.amount_usd > policy.rules.max_monthly_amount_usd {
        return Err(DenyReason::BudgetExceeded);
    }
    Ok(())
}

/// Step 9: Check single amount. `amount > max_single` → `BudgetExceeded`.
///
/// Single-amount exceed IS a budget violation, not a whitelist violation.
/// R80 caps `DenyReason` at exactly 9 variants; `BudgetExceeded` is reused
/// for single-payment cap violations (feature-file term `AMOUNT_EXCEEDED`).
fn step_9_check_single_amount(policy: &PolicyV2, req: &PayRequest) -> Result<(), DenyReason> {
    if req.amount_usd > policy.rules.max_single_amount_usd {
        return Err(DenyReason::BudgetExceeded);
    }
    Ok(())
}

/// Step 10: ALLOW — record counters, reset consecutive deny, return `Decision::Allow`.
fn step_10_allow(state: &mut PolicyState, req: &PayRequest, now_ms: u64) -> Decision {
    state.record_allow(req, now_ms);
    Decision::Allow
}

/// Step 11: DENY — record `last_deny_at` + counter, fire alert if counter == 3,
/// return `Decision::Deny(reason)`.
fn step_11_deny(
    state: &mut PolicyState,
    reason: DenyReason,
    session_key_id: &str,
    now_ms: u64,
) -> Decision {
    state.record_deny(reason.clone(), session_key_id, now_ms);
    Decision::Deny(reason)
}

/// Evaluate a `PayRequest` through the 11-step flow (R29 / AD-04).
///
/// Explicit control flow, no combinators (Readability Priorities). Each step is a
/// named function. The caller persists counters via `state.persist(path)` after
/// this returns.
pub fn evaluate_11_step(
    req: &PayRequest,
    session_key_id: &str,
    state: &mut PolicyState,
) -> Decision {
    // Step 1: parse (no-op — PayRequest arrives pre-parsed)
    let _ = step_1_parse_request(req);

    // Resolve "now" — use override for testing, else SystemTime::now()
    let now_unix = state.now_override.unwrap_or_else(current_unix);
    let now_ms = now_unix.saturating_mul(1000);

    // Slide rate-limit windows before checks
    slide_all_windows(state, now_ms);

    // Step 2: load policy (missing → PolicyMissing)
    let policy = match step_2_load_policy(state) {
        Ok(p) => p,
        Err(r) => return step_11_deny(state, r, session_key_id, now_ms),
    };

    // Step 3: expiry
    if let Err(r) = step_3_check_expiry(policy, now_unix) {
        return step_11_deny(state, r, session_key_id, now_ms);
    }

    // Step 4: whitelists
    if let Err(r) = step_4_check_whitelists(policy, req) {
        return step_11_deny(state, r, session_key_id, now_ms);
    }

    // Step 5: cooldown
    if let Err(r) = step_5_check_cooldown(state, policy, now_unix) {
        return step_11_deny(state, r, session_key_id, now_ms);
    }

    // Step 6: rate limit per minute
    if let Err(r) = step_6_check_rate_limit_minute(state, policy) {
        return step_11_deny(state, r, session_key_id, now_ms);
    }

    // Step 7: rate limit per hour
    if let Err(r) = step_7_check_rate_limit_hour(state, policy) {
        return step_11_deny(state, r, session_key_id, now_ms);
    }

    // Step 8: budget
    if let Err(r) = step_8_check_budget(state, policy, req) {
        return step_11_deny(state, r, session_key_id, now_ms);
    }

    // Step 8a: daily cumulative
    if let Err(r) = step_8a_check_daily_cumulative(state, policy, req) {
        return step_11_deny(state, r, session_key_id, now_ms);
    }

    // Step 8b: monthly cumulative
    if let Err(r) = step_8b_check_monthly_cumulative(state, policy, req) {
        return step_11_deny(state, r, session_key_id, now_ms);
    }

    // Step 9: single amount
    if let Err(r) = step_9_check_single_amount(policy, req) {
        return step_11_deny(state, r, session_key_id, now_ms);
    }

    // Step 10: allow
    step_10_allow(state, req, now_ms)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use proptest::prelude::*;

    use super::*;

    // --- Test helpers ---

    fn test_policy() -> PolicyV2 {
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

    fn fresh_state() -> PolicyState {
        PolicyState::new("sk-test".into()).with_policy(test_policy()).with_now_override(1_000_000)
    }

    /// Mock alert sink that records alerts for inspection.
    struct MockAlertSink {
        alerts: Arc<Mutex<Vec<HumanAlert>>>,
    }

    impl MockAlertSink {
        fn new() -> (Self, Arc<Mutex<Vec<HumanAlert>>>) {
            let alerts = Arc::new(Mutex::new(Vec::new()));
            (Self { alerts: alerts.clone() }, alerts)
        }
    }

    impl AlertSink for MockAlertSink {
        fn notify(&self, alert: &HumanAlert) {
            if let Ok(mut a) = self.alerts.lock() {
                a.push(alert.clone());
            }
        }
    }

    // --- Step 1: parse ---

    #[test]
    fn test_step_1_parse_noop() {
        let req = test_request();
        let parsed = step_1_parse_request(&req);
        assert!(std::ptr::eq(parsed, &raw const req));
    }

    // --- Step 2: load policy ---

    #[test]
    fn test_step_2_policy_missing() {
        let state = PolicyState::new("sk".into()); // no policy
        let result = step_2_load_policy(&state);
        assert_eq!(result.unwrap_err(), DenyReason::PolicyMissing);
    }

    #[test]
    fn test_step_2_policy_loaded() {
        let state = fresh_state();
        let result = step_2_load_policy(&state);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().version, 2);
    }

    // --- Step 3: expiry ---

    #[test]
    fn test_step_3_expired() {
        let policy = test_policy();
        assert_eq!(step_3_check_expiry(&policy, 1_000_000_000).unwrap_err(), DenyReason::Expired);
    }

    #[test]
    fn test_step_3_not_expired() {
        let policy = test_policy();
        assert!(step_3_check_expiry(&policy, 500_000).is_ok());
    }

    // --- Step 4: whitelists ---

    #[test]
    fn test_step_4_asset_pass() {
        let policy = test_policy();
        let req = test_request();
        assert!(step_4_check_whitelists(&policy, &req).is_ok());
    }

    #[test]
    fn test_step_4_asset_fail() {
        let policy = test_policy();
        let mut req = test_request();
        req.asset = "ETH".into();
        assert_eq!(step_4_check_whitelists(&policy, &req).unwrap_err(), DenyReason::Whitelist);
    }

    #[test]
    fn test_step_4_chain_fail() {
        let policy = test_policy();
        let mut req = test_request();
        req.chain_id = "eip155:1".into();
        assert_eq!(step_4_check_whitelists(&policy, &req).unwrap_err(), DenyReason::Whitelist);
    }

    #[test]
    fn test_step_4_contract_fail() {
        let policy = test_policy();
        let mut req = test_request();
        req.recipient = Some("0xDEF".into());
        assert_eq!(step_4_check_whitelists(&policy, &req).unwrap_err(), DenyReason::Whitelist);
    }

    #[test]
    fn test_step_4_contract_case_insensitive() {
        let policy = test_policy();
        let mut req = test_request();
        req.recipient = Some("0xabc".into()); // lowercase
        assert!(step_4_check_whitelists(&policy, &req).is_ok());
    }

    #[test]
    fn test_step_4_native_transfer_allowed() {
        // None recipient (native transfer) with non-empty contract whitelist → allowed
        let policy = test_policy();
        let mut req = test_request();
        req.recipient = None;
        assert!(step_4_check_whitelists(&policy, &req).is_ok());
    }

    #[test]
    fn test_step_4_empty_whitelists_allow_all() {
        let mut policy = test_policy();
        policy.rules.asset_whitelist = vec![];
        policy.rules.chain_whitelist = vec![];
        policy.rules.contract_whitelist = vec![];
        let mut req = test_request();
        req.asset = "anything".into();
        req.chain_id = "any:chain".into();
        req.recipient = Some("0xWHATEVER".into());
        assert!(step_4_check_whitelists(&policy, &req).is_ok());
    }

    // --- Step 5: cooldown ---

    #[test]
    fn test_step_5_no_previous_deny() {
        let state = fresh_state();
        let policy = test_policy();
        assert!(step_5_check_cooldown(&state, &policy, 1_000_000).is_ok());
    }

    #[test]
    fn test_step_5_cooldown_active() {
        let mut state = fresh_state();
        state.last_deny_at_unix = Some(999_000);
        let mut policy = test_policy();
        policy.rules.cooldown_after_denial_sec = 10_000; // 999000 + 10000 > 1000000
        assert_eq!(
            step_5_check_cooldown(&state, &policy, 1_000_000).unwrap_err(),
            DenyReason::Cooldown
        );
    }

    #[test]
    fn test_step_5_cooldown_expired() {
        let mut state = fresh_state();
        state.last_deny_at_unix = Some(980_000);
        let mut policy = test_policy();
        policy.rules.cooldown_after_denial_sec = 10_000; // 980000 + 10000 < 1000000
        assert!(step_5_check_cooldown(&state, &policy, 1_000_000).is_ok());
    }

    // --- Step 6: rate limit minute ---

    #[test]
    fn test_step_6_rate_minute_ok() {
        let state = fresh_state(); // empty window
        let policy = test_policy(); // limit = 10
        assert!(step_6_check_rate_limit_minute(&state, &policy).is_ok());
    }

    #[test]
    fn test_step_6_rate_minute_exceeded() {
        let mut state = fresh_state();
        for _ in 0..10 {
            state.minutely_window.push_back(999_999);
        }
        let policy = test_policy(); // limit = 10, window has 10 → exceeded
        assert_eq!(
            step_6_check_rate_limit_minute(&state, &policy).unwrap_err(),
            DenyReason::RateLimitMinute
        );
    }

    // --- Step 7: rate limit hour ---

    #[test]
    fn test_step_7_rate_hour_ok() {
        let state = fresh_state();
        let policy = test_policy();
        assert!(step_7_check_rate_limit_hour(&state, &policy).is_ok());
    }

    #[test]
    fn test_step_7_rate_hour_exceeded() {
        let mut state = fresh_state();
        for _ in 0..100 {
            state.hourly_window.push_back(999_999);
        }
        let policy = test_policy();
        assert_eq!(
            step_7_check_rate_limit_hour(&state, &policy).unwrap_err(),
            DenyReason::RateLimitHour
        );
    }

    // --- Step 8: budget ---

    #[test]
    fn test_step_8_budget_ok() {
        let state = fresh_state(); // local_spent = 0
        let policy = test_policy(); // allocated = 50
        let req = test_request(); // amount = 5; 0 + 5 <= 50
        assert!(step_8_check_budget(&state, &policy, &req).is_ok());
    }

    #[test]
    fn test_step_8_budget_exceeded() {
        let mut state = fresh_state();
        state.local_spent_usd = 48.0;
        let policy = test_policy(); // allocated = 50
        let req = test_request(); // amount = 5; 48 + 5 > 50
        assert_eq!(
            step_8_check_budget(&state, &policy, &req).unwrap_err(),
            DenyReason::BudgetExceeded
        );
    }

    // --- Step 8a: daily cumulative ---

    #[test]
    fn test_step_8a_daily_cumulative_ok() {
        // fresh_state() has empty daily_window → sum = 0; 0 + 5 <= 100 (default).
        let state = fresh_state();
        let policy = test_policy(); // max_daily = 100
        let req = test_request(); // amount = 5
        assert!(step_8a_check_daily_cumulative(&state, &policy, &req).is_ok());
    }

    #[test]
    fn test_step_8a_daily_cumulative_exceed() {
        // fresh_state sets now_override = 1_000_000 sec → now_ms = 1_000_000_000 ms.
        let mut state = fresh_state();
        // Pre-populate daily_window with $9.60 spent 1 minute ago (within 24h).
        state.daily_window.push_back((1_000_000_000 - 60_000, 9.60));
        // Tighten daily limit to $10.00 (default is 100.0).
        let mut policy = test_policy();
        policy.rules.max_daily_amount_usd = 10.0;
        let mut req = test_request();
        req.amount_usd = 0.50; // 9.60 + 0.50 = 10.10 > 10.0
        assert_eq!(
            step_8a_check_daily_cumulative(&state, &policy, &req).unwrap_err(),
            DenyReason::BudgetExceeded
        );
    }

    // --- Step 8b: monthly cumulative ---

    #[test]
    fn test_step_8b_monthly_cumulative_exceed() {
        let mut state = fresh_state();
        // Pre-populate monthly_window with $199.60 spent 1 hour ago (within 30d).
        state.monthly_window.push_back((1_000_000_000 - 3_600_000, 199.60));
        // Tighten monthly limit to $200.00 (default is 1000.0).
        let mut policy = test_policy();
        policy.rules.max_monthly_amount_usd = 200.0;
        let mut req = test_request();
        req.amount_usd = 0.50; // 199.60 + 0.50 = 200.10 > 200.0
        assert_eq!(
            step_8b_check_monthly_cumulative(&state, &policy, &req).unwrap_err(),
            DenyReason::BudgetExceeded
        );
    }

    // --- Step 9: single amount ---

    #[test]
    fn test_step_9_single_amount_ok() {
        let policy = test_policy(); // max_single = 10
        let req = test_request(); // amount = 5
        assert!(step_9_check_single_amount(&policy, &req).is_ok());
    }

    #[test]
    fn test_step_9_single_amount_exceeded() {
        let policy = test_policy(); // max_single = 10
        let mut req = test_request();
        req.amount_usd = 15.0;
        assert_eq!(
            step_9_check_single_amount(&policy, &req).unwrap_err(),
            DenyReason::BudgetExceeded
        );
    }

    // --- Step 10/11: record_allow / record_deny ---

    #[test]
    fn test_step_10_allow_records() {
        let mut state = fresh_state();
        let req = test_request();
        let now_ms = 1_000_000_000;
        let decision = step_10_allow(&mut state, &req, now_ms);
        assert_eq!(decision, Decision::Allow);
        assert_eq!(state.local_spent_usd, 5.0);
        assert_eq!(state.minutely_window.len(), 1);
        assert_eq!(state.hourly_window.len(), 1);
        assert_eq!(state.daily_window.len(), 1);
        assert_eq!(state.daily_window[0], (now_ms, 5.0));
        assert_eq!(state.monthly_window.len(), 1);
        assert_eq!(state.monthly_window[0], (now_ms, 5.0));
        assert_eq!(state.consecutive_deny_counter, 0);
    }

    #[test]
    fn test_step_11_deny_records() {
        let mut state = fresh_state();
        let now_ms = 1_000_000_000;
        let decision = step_11_deny(&mut state, DenyReason::Expired, "sk-test", now_ms);
        assert_eq!(decision, Decision::Deny(DenyReason::Expired));
        assert_eq!(state.last_deny_at_unix, Some(1_000_000));
        assert_eq!(state.consecutive_deny_counter, 1);
        assert_eq!(state.last_deny_reasons.len(), 1);
    }

    #[test]
    fn test_step_11_three_denies_fire_alert() {
        let (sink, alerts) = MockAlertSink::new();
        let mut state = PolicyState::new("sk-test".into())
            .with_policy(test_policy())
            .with_now_override(1_000_000)
            .with_alert_sink(Box::new(sink));

        // First deny
        step_11_deny(&mut state, DenyReason::Expired, "sk-test", 1_000_000);
        assert_eq!(state.consecutive_deny_counter, 1);
        assert!(alerts.lock().unwrap().is_empty());

        // Second deny
        step_11_deny(&mut state, DenyReason::Cooldown, "sk-test", 1_000_000);
        assert_eq!(state.consecutive_deny_counter, 2);
        assert!(alerts.lock().unwrap().is_empty());

        // Third deny → alert + reset
        step_11_deny(&mut state, DenyReason::Whitelist, "sk-test", 1_000_000);
        assert_eq!(state.consecutive_deny_counter, 0); // reset after alert
        assert_eq!(state.last_deny_reasons.len(), 0); // cleared
        assert_eq!(alerts.lock().unwrap().len(), 1);
        let alert = &alerts.lock().unwrap()[0];
        assert_eq!(alert.session_key_id, "sk-test");
        assert_eq!(alert.deny_reasons.len(), 3);
    }

    // --- evaluate_11_step end-to-end ---

    #[test]
    fn test_evaluate_policy_missing() {
        let mut state = PolicyState::new("sk".into()); // no policy
        let req = test_request();
        let decision = evaluate_11_step(&req, "sk", &mut state);
        assert_eq!(decision, Decision::Deny(DenyReason::PolicyMissing));
    }

    #[test]
    fn test_evaluate_allow() {
        let mut state = fresh_state();
        let req = test_request();
        let decision = evaluate_11_step(&req, "sk-test", &mut state);
        assert_eq!(decision, Decision::Allow);
        assert_eq!(state.local_spent_usd, 5.0);
    }

    #[test]
    fn test_evaluate_expired() {
        let mut state = fresh_state();
        state.policy = Some(PolicyV2 {
            version: 2,
            session_key_id: "sk-test".into(),
            device_id: "dev-test".into(),
            rules: PolicyRulesV2 {
                expiry_unix: 500_000, // already expired (now_override = 1_000_000)
                ..test_policy().rules
            },
            budget_allocation: test_policy().budget_allocation,
        });
        let req = test_request();
        let decision = evaluate_11_step(&req, "sk-test", &mut state);
        assert_eq!(decision, Decision::Deny(DenyReason::Expired));
    }

    #[test]
    fn test_evaluate_whitelist_asset() {
        let mut state = fresh_state();
        let mut req = test_request();
        req.asset = "ETH".into(); // not in asset_whitelist
        let decision = evaluate_11_step(&req, "sk-test", &mut state);
        assert_eq!(decision, Decision::Deny(DenyReason::Whitelist));
    }

    #[test]
    fn test_evaluate_rate_limit_minute() {
        let mut state = fresh_state();
        // now_override = 1_000_000 sec → now_ms = 1_000_000_000 ms.
        // Push entries 1s before now_ms (well within the 60s window).
        for _ in 0..10 {
            state.minutely_window.push_back(1_000_000_000 - 1_000);
        }
        let req = test_request();
        let decision = evaluate_11_step(&req, "sk-test", &mut state);
        assert_eq!(decision, Decision::Deny(DenyReason::RateLimitMinute));
    }

    #[test]
    fn test_evaluate_budget_exceeded() {
        let mut state = fresh_state();
        state.local_spent_usd = 48.0;
        let req = test_request(); // amount = 5; 48 + 5 > 50
        let decision = evaluate_11_step(&req, "sk-test", &mut state);
        assert_eq!(decision, Decision::Deny(DenyReason::BudgetExceeded));
    }

    #[test]
    fn test_evaluate_single_amount_exceeded() {
        let mut state = fresh_state();
        let mut req = test_request();
        req.amount_usd = 15.0; // > max_single (10)
        let decision = evaluate_11_step(&req, "sk-test", &mut state);
        assert_eq!(decision, Decision::Deny(DenyReason::BudgetExceeded));
    }

    #[test]
    fn test_evaluate_allow_then_budget_exceeded() {
        let mut state = fresh_state();
        let req = test_request(); // amount = 5

        // First request: allow (local_spent = 0 + 5 = 5)
        let d1 = evaluate_11_step(&req, "sk-test", &mut state);
        assert_eq!(d1, Decision::Allow);
        assert_eq!(state.local_spent_usd, 5.0);

        // Second request: allow (local_spent = 5 + 5 = 10)
        let d2 = evaluate_11_step(&req, "sk-test", &mut state);
        assert_eq!(d2, Decision::Allow);
        assert_eq!(state.local_spent_usd, 10.0);

        // Set local_spent near budget limit
        state.local_spent_usd = 48.0;

        // Third request: deny (48 + 5 > 50)
        let d3 = evaluate_11_step(&req, "sk-test", &mut state);
        assert_eq!(d3, Decision::Deny(DenyReason::BudgetExceeded));
    }

    // --- Sliding window ---

    #[test]
    fn test_slide_window_evicts_old() {
        let mut window = VecDeque::new();
        window.push_back(1_000_000); // 1000s old
        window.push_back(1_059_000); // 1s old (within 60s)
        window.push_back(1_060_000); // exactly 60s old (within, since > is exclusive)
        slide_window(&mut window, 1_060_000, 60_000);
        // 1_000_000 evicted (1_060_000 - 1_000_000 = 60000 > 60000 is false, so NOT evicted!)
        // Actually: 60000 > 60000 is false, so 1_000_000 stays. Let me recalculate.
        // The condition is `now - front > window_ms`. 1060000 - 1000000 = 60000. 60000 > 60000 is
        // false. So 1_000_000 is NOT evicted. Only entries strictly older than 60000ms are
        // evicted. To evict 1_000_000, we need now = 1_060_001.
        assert_eq!(window.len(), 3); // none evicted

        slide_window(&mut window, 1_060_001, 60_000);
        assert_eq!(window.len(), 2); // 1_000_000 evicted
    }

    #[test]
    fn test_slide_window_empty() {
        let mut window: VecDeque<u64> = VecDeque::new();
        slide_window(&mut window, 1_000_000, 60_000);
        assert!(window.is_empty());
    }

    #[test]
    fn test_slide_amount_window_evicts_old() {
        let mut window: VecDeque<(u64, f64)> = VecDeque::new();
        // 24h window = 86_400_000 ms. now = 1_060_000_000 ms.
        // Entry at 1_000_000_000 is 60_000_000 ms ago (within 24h).
        // Entry at 900_000_000 is 160_000_000 ms ago (older than 24h).
        window.push_back((900_000_000, 1.0)); // older than 24h → evicted
        window.push_back((1_000_000_000, 2.0)); // within 24h → kept
        window.push_back((1_059_000_000, 3.0)); // within 24h → kept
        slide_amount_window(&mut window, 1_060_000_000, 86_400_000);
        assert_eq!(window.len(), 2);
        assert_eq!(window[0], (1_000_000_000, 2.0));
        assert_eq!(window[1], (1_059_000_000, 3.0));
    }

    #[test]
    fn test_slide_amount_window_empty() {
        let mut window: VecDeque<(u64, f64)> = VecDeque::new();
        slide_amount_window(&mut window, 1_000_000_000, 86_400_000);
        assert!(window.is_empty());
    }

    // --- PolicyState persist/load ---

    #[test]
    fn test_state_persist_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy_counters.json");

        let mut state = fresh_state();
        state.local_spent_usd = 42.5;
        state.minutely_window.push_back(1_000_000);
        state.daily_window.push_back((1_000_000_000, 9.60));
        state.monthly_window.push_back((1_000_000_000, 199.60));
        state.consecutive_deny_counter = 2;
        state.last_deny_at_unix = Some(999_999);
        state.last_deny_reasons.push(DenyReason::Expired);

        state.persist(&path).unwrap();
        assert!(path.exists());

        // Check file permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "file should have 0600 perms");
        }

        // Load and verify
        let loaded = PolicyState::load(&path, "sk-test".into()).unwrap();
        assert_eq!(loaded.session_key_id, "sk-test");
        assert_eq!(loaded.local_spent_usd, 42.5);
        assert_eq!(loaded.minutely_window.len(), 1);
        assert_eq!(loaded.daily_window.len(), 1);
        assert_eq!(loaded.daily_window[0], (1_000_000_000, 9.60));
        assert_eq!(loaded.monthly_window.len(), 1);
        assert_eq!(loaded.monthly_window[0], (1_000_000_000, 199.60));
        assert_eq!(loaded.consecutive_deny_counter, 2);
        assert_eq!(loaded.last_deny_at_unix, Some(999_999));
        assert_eq!(loaded.last_deny_reasons.len(), 1);
        // Runtime fields should be default (policy=None, now_override=None)
        assert!(loaded.policy.is_none());
        assert!(loaded.now_override.is_none());
    }

    #[test]
    fn test_state_load_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonexistent.json");
        let state = PolicyState::load(&path, "sk-new".into()).unwrap();
        assert_eq!(state.session_key_id, "sk-new");
        assert_eq!(state.local_spent_usd, 0.0);
        assert!(state.minutely_window.is_empty());
        assert!(state.daily_window.is_empty());
        assert!(state.monthly_window.is_empty());
    }

    #[test]
    fn test_state_persist_creates_parent_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("deep").join("policy_counters.json");
        let state = fresh_state();
        state.persist(&path).unwrap();
        assert!(path.exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let parent_mode =
                std::fs::metadata(path.parent().unwrap()).unwrap().permissions().mode();
            assert_eq!(parent_mode & 0o777, 0o700, "parent dir should have 0700 perms");
        }
    }

    // --- proptest on 11-step state transitions ---

    fn arb_amount() -> impl Strategy<Value = f64> {
        0.0f64..100.0
    }

    fn arb_policy_with_expiry(expiry: u64) -> PolicyV2 {
        PolicyV2 {
            version: 2,
            session_key_id: "sk-prop".into(),
            device_id: "dev-prop".into(),
            rules: PolicyRulesV2 {
                max_single_amount_usd: 20.0,
                max_daily_amount_usd: 100.0,
                max_monthly_amount_usd: 1000.0,
                expiry_unix: expiry,
                rate_limit_per_minute: 10,
                rate_limit_per_hour: 100,
                cooldown_after_denial_sec: 0,
                asset_whitelist: vec!["USDC".into()],
                chain_whitelist: vec!["eip155:8453".into()],
                contract_whitelist: vec![],
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

    fn arb_request(amount: f64, asset: &str, chain: &str) -> PayRequest {
        PayRequest {
            session_key_id: "sk-prop".into(),
            device_id: "dev-prop".into(),
            amount_usd: amount,
            asset: asset.into(),
            chain_id: chain.into(),
            recipient: None,
        }
    }

    proptest! {
        /// Property: if policy is None, decision is always Deny(PolicyMissing).
        #[test]
        fn prop_policy_missing_when_none(amount in arb_amount()) {
            let mut state = PolicyState::new("sk-prop".into())
                .with_now_override(1_000_000);
            // No policy set
            let req = arb_request(amount, "USDC", "eip155:8453");
            let decision = evaluate_11_step(&req, "sk-prop", &mut state);
            prop_assert_eq!(decision, Decision::Deny(DenyReason::PolicyMissing));
        }

        /// Property: if now > expiry_unix, decision is Deny(Expired).
        #[test]
        fn prop_expired_after_expiry(
            now in 1_000_000u64..2_000_000,
            expiry_delta in 1u64..500_000
        ) {
            let expiry = now - expiry_delta;
            let mut state = PolicyState::new("sk-prop".into())
                .with_policy(arb_policy_with_expiry(expiry))
                .with_now_override(now);
            let req = arb_request(5.0, "USDC", "eip155:8453");
            let decision = evaluate_11_step(&req, "sk-prop", &mut state);
            prop_assert_eq!(decision, Decision::Deny(DenyReason::Expired));
        }

        /// Property: if amount > max_single_amount_usd, decision is Deny(BudgetExceeded).
        #[test]
        fn prop_single_amount_exceeded(amount in 21.0f64..1000.0) {
            let mut state = PolicyState::new("sk-prop".into())
                .with_policy(arb_policy_with_expiry(999_999_999))
                .with_now_override(1_000_000);
            let req = arb_request(amount, "USDC", "eip155:8453");
            let decision = evaluate_11_step(&req, "sk-prop", &mut state);
            // amount > 20 (max_single) → BudgetExceeded. Either step 8 (budget:
            // 0 + amount > allocated 50) fires first for amount > 50, or step 9
            // (single amount) fires for 20 < amount <= 50. Both return BudgetExceeded.
            // Step 8a/8b (daily/monthly) pass because windows are empty.
            prop_assert_eq!(decision, Decision::Deny(DenyReason::BudgetExceeded));
        }

        /// Property: if local_spent + amount > allocated, decision is Deny(BudgetExceeded).
        #[test]
        fn prop_budget_exceeded(
            spent in 40.0f64..49.0,
            amount in 2.0f64..20.0 // amount <= max_single (20) so single-amount passes
        ) {
            let mut state = PolicyState::new("sk-prop".into())
                .with_policy(arb_policy_with_expiry(999_999_999))
                .with_now_override(1_000_000);
            state.local_spent_usd = spent;
            let req = arb_request(amount, "USDC", "eip155:8453");
            let decision = evaluate_11_step(&req, "sk-prop", &mut state);
            if spent + amount > 50.0 {
                prop_assert_eq!(decision, Decision::Deny(DenyReason::BudgetExceeded));
            } else {
                prop_assert_eq!(decision, Decision::Allow);
            }
        }

        /// Property: after ALLOW, local_spent_usd increases by amount.
        #[test]
        fn prop_allow_increases_spent(amount in 0.0f64..20.0) {
            let mut state = PolicyState::new("sk-prop".into())
                .with_policy(arb_policy_with_expiry(999_999_999))
                .with_now_override(1_000_000);
            let req = arb_request(amount, "USDC", "eip155:8453");
            let before = state.local_spent_usd;
            let decision = evaluate_11_step(&req, "sk-prop", &mut state);
            if decision == Decision::Allow {
                prop_assert!((state.local_spent_usd - before - amount).abs() < 1e-9);
            }
        }

        /// Property: after DENY, last_deny_at_unix is set to now.
        #[test]
        fn prop_deny_sets_last_deny_at(now in 1_000_000u64..2_000_000) {
            let mut state = PolicyState::new("sk-prop".into())
                .with_policy(arb_policy_with_expiry(500_000)) // expired → deny
                .with_now_override(now);
            let req = arb_request(5.0, "USDC", "eip155:8453");
            let decision = evaluate_11_step(&req, "sk-prop", &mut state);
            prop_assert!(matches!(decision, Decision::Deny(_)));
            prop_assert_eq!(state.last_deny_at_unix, Some(now));
        }

        /// Property: after 3 consecutive DENYs, counter resets to 0 and alert fires.
        #[test]
        fn prop_three_denies_reset_counter(now in 1_000_000u64..2_000_000) {
            let (sink, alerts) = MockAlertSink::new();
            let mut state = PolicyState::new("sk-prop".into())
                .with_policy(arb_policy_with_expiry(500_000)) // expired → deny
                .with_now_override(now)
                .with_alert_sink(Box::new(sink));
            let req = arb_request(5.0, "USDC", "eip155:8453");

            for _ in 0..3 {
                evaluate_11_step(&req, "sk-prop", &mut state);
            }

            prop_assert_eq!(state.consecutive_deny_counter, 0);
            prop_assert_eq!(alerts.lock().unwrap().len(), 1);
        }

        /// Property: ALLOW resets consecutive_deny_counter to 0.
        #[test]
        fn prop_allow_resets_counter(amount in 1.0f64..10.0) {
            let mut state = PolicyState::new("sk-prop".into())
                .with_policy(arb_policy_with_expiry(999_999_999))
                .with_now_override(1_000_000);
            state.consecutive_deny_counter = 2; // simulate prior denies

            let req = arb_request(amount, "USDC", "eip155:8453");
            let decision = evaluate_11_step(&req, "sk-prop", &mut state);

            if decision == Decision::Allow {
                prop_assert_eq!(state.consecutive_deny_counter, 0);
            }
        }

        /// Property: rate_limit_per_minute is enforced.
        #[test]
        fn prop_rate_limit_minute_enforced(rate in 1u32..20) {
            let mut policy = arb_policy_with_expiry(999_999_999);
            policy.rules.rate_limit_per_minute = rate;
            let mut state = PolicyState::new("sk-prop".into())
                .with_policy(policy)
                .with_now_override(1_000_000);

            // now_ms = 1_000_000 sec * 1000 = 1_000_000_000 ms.
            // Push `rate` entries 1s before now_ms (within the 60s window).
            for _ in 0..rate {
                state.minutely_window.push_back(1_000_000_000 - 1_000);
            }

            let req = arb_request(5.0, "USDC", "eip155:8453");
            let decision = evaluate_11_step(&req, "sk-prop", &mut state);
            prop_assert_eq!(decision, Decision::Deny(DenyReason::RateLimitMinute));
        }
    }
}
