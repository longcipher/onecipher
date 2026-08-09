//! In-process strategy plugins for the policy engine.
//!
//! Runtime-loadable strategy logic that is consulted *after* the built-in
//! 11-step pipeline allows. The 11-step pipeline in [`crate::v2`] is untouched:
//! a strategy plugin is an *additional* gate consulted alongside the built-in
//! evaluation (see [`StrategyRegistry`] and [`crate::v3`] integration).
//!
//! ## Why native (not Wasm)
//!
//! `oc-policy` has a hard gate (R56): it MUST NOT depend on
//! `tokio`/`reqwest`/`tungstenite`/`hyper`/`async-std`/`smol` — even as
//! dev-deps — verified by `cargo tree -p oc-policy`. The previous Wasm plugin
//! system (`wasmi`) added a heavyweight interpreter dependency and a custom
//! guest ABI for a feature whose complexity far exceeded its use: policy
//! changes are rare, so hot-reloading strategy logic over a Wasm boundary was
//! over-engineering. Strategies are now plain in-process Rust closures.
//!
//! ## Sandboxing guarantees
//!
//! * **Deterministic**: a strategy is a pure function of its input ([`StrategyEvalRequest`] with
//!   `host_facts` already embedded). No clock, no RNG, no I/O is reachable unless the closure does
//!   it itself.
//! * **Bounded**: each closure is supplied by the caller (typically compiled into the daemon), so
//!   no memory ceiling or fuel metering is needed.
//! * **Auditable**: a strategy's verdict is returned in [`RegistryOutcome`] and the caller writes
//!   it to the audit log.
//!
//! ## Host facts
//!
//! Rather than a live host-call bridge, host-provided facts (wallet balance,
//! rate-limit counters, …) are *pushed* into the request's `host_facts` field
//! before evaluation. [`StrategyHost`] is the trait a caller implements to
//! populate them. This keeps the strategy a pure function of its input, which
//! is what makes strategy evaluation reproducible and auditable.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::v2::PayRequest;

/// The outcome of a strategy evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum StrategyOutcome {
    /// The strategy permits the request; defer to the built-in pipeline.
    Allow,
    /// The strategy flags the request but does not block it.
    Warn { message: String },
    /// The strategy blocks the request.
    Deny { reason: String, message: String },
}

impl StrategyOutcome {
    /// Whether this outcome blocks the request.
    pub fn is_deny(&self) -> bool {
        matches!(self, Self::Deny { .. })
    }
}

/// Serializable inputs to a strategy evaluation.
///
/// `host_facts` is a free-form JSON object populated by the caller (via
/// [`StrategyHost`]) with host-side facts such as wallet balance or
/// rate-limit counters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrategyEvalRequest {
    pub method: String,
    pub chain_id: String,
    pub amount_usd: f64,
    pub asset: String,
    pub recipient: String,
    pub session_key_id: String,
    #[serde(default)]
    pub host_facts: serde_json::Value,
}

impl Default for StrategyEvalRequest {
    fn default() -> Self {
        Self {
            method: String::new(),
            chain_id: String::new(),
            amount_usd: 0.0,
            asset: String::new(),
            recipient: String::new(),
            session_key_id: String::new(),
            host_facts: serde_json::Value::Object(serde_json::Map::new()),
        }
    }
}

/// Host-side facts a caller can provide to a strategy evaluation.
///
/// The default implementation returns an empty object.
pub trait StrategyHost {
    /// Build the `host_facts` JSON object embedded into the request.
    ///
    /// Override this to expose wallet balances, rate-limit counters, or any
    /// other host-side state a strategy may need.
    fn host_facts(&self, _req: &StrategyEvalRequest) -> serde_json::Value {
        serde_json::Value::Object(serde_json::Map::new())
    }
}

/// A [`StrategyHost`] implementation that provides no facts.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoHostFacts;

impl StrategyHost for NoHostFacts {}

/// The strategy evaluation function.
pub type StrategyFn =
    Box<dyn Fn(&StrategyEvalRequest, &dyn StrategyHost) -> StrategyOutcome + Send + Sync>;

/// A registered strategy plugin.
pub struct StrategyPlugin {
    name: String,
    func: StrategyFn,
}

impl std::fmt::Debug for StrategyPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StrategyPlugin").field("name", &self.name).finish_non_exhaustive()
    }
}

impl StrategyPlugin {
    /// Register a strategy under `name`.
    pub fn new(name: impl Into<String>, func: StrategyFn) -> Self {
        Self { name: name.into(), func }
    }

    /// The plugin's name (used in audit records and error messages).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Evaluate a request against this strategy plugin.
    pub fn evaluate(&self, req: &StrategyEvalRequest, host: &dyn StrategyHost) -> StrategyOutcome {
        let mut req = req.clone();
        req.host_facts = host.host_facts(&req);
        (self.func)(&req, host)
    }
}

/// The combined result of consulting every plugin in a [`StrategyRegistry`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryOutcome {
    /// The blocking outcome, if any plugin denied. Carries the plugin name.
    pub denied_by: Option<(String, String, String)>,
    /// Non-blocking warnings as `(plugin_name, message)`.
    pub warnings: Vec<(String, String)>,
    /// Plugins that failed to evaluate, as `(plugin_name, error)`.
    ///
    /// A failing plugin is **not** treated as a deny: a mis-behaving strategy
    /// must not brick the wallet. Failures are surfaced for the audit log.
    pub errors: Vec<(String, String)>,
}

impl RegistryOutcome {
    /// Whether any plugin blocked the request.
    pub fn is_denied(&self) -> bool {
        self.denied_by.is_some()
    }
}

/// A set of strategy plugins consulted in deterministic (name) order.
///
/// Evaluation semantics are **deny-wins**: every plugin is consulted and the
/// first `Deny` short-circuits. `Warn` outcomes are accumulated.
#[derive(Debug, Default)]
pub struct StrategyRegistry {
    plugins: BTreeMap<String, StrategyPlugin>,
}

impl StrategyRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert (or replace) a plugin.
    pub fn insert(&mut self, plugin: StrategyPlugin) {
        self.plugins.insert(plugin.name().to_string(), plugin);
    }

    /// Remove a plugin by name.
    pub fn remove(&mut self, name: &str) -> Option<StrategyPlugin> {
        self.plugins.remove(name)
    }

    /// The number of loaded plugins.
    pub fn len(&self) -> usize {
        self.plugins.len()
    }

    /// Whether no plugins are loaded.
    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }

    /// The names of loaded plugins, in deterministic order.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.plugins.keys().map(String::as_str)
    }

    /// Consult every plugin. Deny short-circuits; warnings accumulate.
    pub fn evaluate(&self, req: &StrategyEvalRequest, host: &dyn StrategyHost) -> RegistryOutcome {
        let mut outcome =
            RegistryOutcome { denied_by: None, warnings: Vec::new(), errors: Vec::new() };
        for (name, plugin) in &self.plugins {
            match plugin.evaluate(req, host) {
                StrategyOutcome::Allow => {}
                StrategyOutcome::Warn { message } => {
                    outcome.warnings.push((name.clone(), message));
                }
                StrategyOutcome::Deny { reason, message } => {
                    outcome.denied_by = Some((name.clone(), reason, message));
                    return outcome;
                }
            }
        }
        outcome
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

/// Deprecated alias retained for callers migrating from the retired Wasm
/// strategy system.
#[deprecated(note = "renamed to `strategy_request_from_pay`")]
pub fn wasm_request_from_pay(req: &PayRequest, method: &str) -> StrategyEvalRequest {
    strategy_request_from_pay(req, method)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v2::PayRequest;

    fn make_req(recipient: &str) -> StrategyEvalRequest {
        StrategyEvalRequest {
            method: "eth_sendTransaction".into(),
            chain_id: "eip155:1".into(),
            amount_usd: 50.0,
            asset: "eip155:1/slip44:60".into(),
            recipient: recipient.into(),
            session_key_id: "sk-1".into(),
            host_facts: serde_json::Value::Object(serde_json::Map::new()),
        }
    }

    fn marker_plugin() -> StrategyPlugin {
        StrategyPlugin::new(
            "marker",
            Box::new(|req, _| {
                if req.recipient.contains("DENYME") {
                    StrategyOutcome::Deny { reason: "marker".into(), message: "blocked".into() }
                } else if req.recipient.contains("WARNME") {
                    StrategyOutcome::Warn { message: "suspicious".into() }
                } else {
                    StrategyOutcome::Allow
                }
            }),
        )
    }

    #[test]
    fn allows_when_marker_absent() {
        let plugin = marker_plugin();
        let outcome = plugin.evaluate(&make_req("0xsafe"), &NoHostFacts);
        assert_eq!(outcome, StrategyOutcome::Allow);
    }

    #[test]
    fn denies_when_marker_present() {
        let plugin = marker_plugin();
        let outcome = plugin.evaluate(&make_req("0xDENYME"), &NoHostFacts);
        assert_eq!(
            outcome,
            StrategyOutcome::Deny { reason: "marker".into(), message: "blocked".into() }
        );
        assert!(outcome.is_deny());
    }

    #[test]
    fn no_host_facts_yields_empty_object() {
        let facts = NoHostFacts.host_facts(&make_req("0xabc"));
        assert_eq!(facts, serde_json::json!({}));
    }

    #[test]
    fn registry_deny_short_circuits() {
        let mut registry = StrategyRegistry::new();
        registry.insert(marker_plugin());

        let allowed = registry.evaluate(&make_req("0xsafe"), &NoHostFacts);
        assert!(!allowed.is_denied());
        assert_eq!(allowed.warnings.len(), 0);
        assert_eq!(allowed.errors.len(), 0);

        let denied = registry.evaluate(&make_req("0xDENYME"), &NoHostFacts);
        let (plugin, reason, _msg) = denied.denied_by.expect("must be denied");
        assert_eq!(plugin, "marker");
        assert_eq!(reason, "marker");
    }

    #[test]
    fn registry_accumulates_warnings_without_denying() {
        let mut registry = StrategyRegistry::new();
        registry.insert(marker_plugin());
        let outcome = registry.evaluate(&make_req("0xWARNME"), &NoHostFacts);
        assert!(!outcome.is_denied());
        assert_eq!(outcome.warnings, vec![("marker".to_string(), "suspicious".to_string())]);
    }

    #[test]
    fn registry_insert_replaces_by_name() {
        let mut registry = StrategyRegistry::new();
        registry.insert(marker_plugin());
        registry.insert(marker_plugin());
        assert_eq!(registry.len(), 1);
        assert!(registry.remove("marker").is_some());
        assert!(registry.is_empty());
    }

    #[test]
    fn empty_registry_is_a_passthrough() {
        let registry = StrategyRegistry::new();
        let outcome = registry.evaluate(&make_req("0xsafe"), &NoHostFacts);
        assert!(!outcome.is_denied());
        assert_eq!(outcome.warnings.len(), 0);
        assert_eq!(outcome.errors.len(), 0);
    }

    #[test]
    fn outcome_json_round_trips() {
        for outcome in [
            StrategyOutcome::Allow,
            StrategyOutcome::Warn { message: "hmm".into() },
            StrategyOutcome::Deny { reason: "r".into(), message: "m".into() },
        ] {
            let json = serde_json::to_string(&outcome).unwrap();
            let back: StrategyOutcome = serde_json::from_str(&json).unwrap();
            assert_eq!(outcome, back);
        }
    }

    #[test]
    fn strategy_request_maps_pay_request_fields() {
        let req = PayRequest {
            session_key_id: "sk-test".into(),
            device_id: "dev-test".into(),
            amount_usd: 5.0,
            asset: "USDC".into(),
            chain_id: "eip155:8453".into(),
            recipient: Some("0xABC".into()),
        };
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
        let mut req = make_pay_request();
        req.recipient = None;
        assert_eq!(strategy_request_from_pay(&req, "m").recipient, "");
    }

    fn make_pay_request() -> PayRequest {
        PayRequest {
            session_key_id: "sk-test".into(),
            device_id: "dev-test".into(),
            amount_usd: 5.0,
            asset: "USDC".into(),
            chain_id: "eip155:8453".into(),
            recipient: Some("0xABC".into()),
        }
    }
}
