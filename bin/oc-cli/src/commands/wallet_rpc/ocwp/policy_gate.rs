//! Policy evaluation for OCWP signing requests (design D8).
//!
//! Today `oc-policy` is enforced only on the API-token path
//! (`oc_wallet::key_ops`). OCWP extends enforcement to owner-mode sessions so
//! that dApp-originated signing from the browser extension is policy-gated
//! exactly like automation signing. Every `oc_sign_*` / `oc_send_transaction`
//! builds a [`PolicyContext`] and runs `oc_policy::evaluate_policies` before
//! the signer is touched; `oc_policy_preview` is the same evaluation without
//! side effects, used by the consent UI at enqueue time and re-checked at
//! approval time.

use std::path::Path;

use oc_core::{
    Policy, PolicyContext, TypedDataContext,
    policy::{SpendingContext, TransactionContext},
};
use serde_json::{Value, json};

use super::{errors::OcwpError, session::SessionEntry};

/// A signing request projected into the fields policy rules can inspect.
pub(super) struct PolicyView<'a> {
    /// OCWP method name (diagnostics / executable policies).
    pub method: &'a str,
    /// CAIP-2 chain id of the signing account.
    pub chain_id: &'a str,
    pub to: Option<&'a str>,
    /// Native value in the smallest unit, decimal string.
    pub value: Option<&'a str>,
    pub data: Option<&'a str>,
    /// Raw (unsigned) transaction hex, empty for message/typed-data signing.
    pub raw_hex: &'a str,
    /// EIP-712 typed data document (typed-data signing only).
    pub typed_data: Option<&'a Value>,
}

/// Current UTC time as an RFC-3339 string (the format `oc-policy` parses).
fn now_rfc3339() -> String {
    jiff::Timestamp::now().to_string()
}

/// Today's date as `YYYY-MM-DD` (UTC) for `SpendingContext`.
fn today() -> String {
    jiff::Timestamp::now().strftime("%Y-%m-%d").to_string()
}

/// Project EIP-712 typed data into the policy-visible context fields.
fn build_typed_data_context(td: &Value) -> Option<TypedDataContext> {
    let domain = td.get("domain")?;
    Some(TypedDataContext {
        verifying_contract: domain
            .get("verifyingContract")
            .and_then(Value::as_str)
            .map(String::from),
        domain_chain_id: domain.get("chainId").and_then(Value::as_u64),
        primary_type: td.get("primaryType").and_then(Value::as_str).unwrap_or_default().to_string(),
        domain_name: domain.get("name").and_then(Value::as_str).map(String::from),
        domain_version: domain.get("version").and_then(Value::as_str).map(String::from),
        raw_json: serde_json::to_string(td).unwrap_or_default(),
    })
}

/// Build the full [`PolicyContext`] for a session + signing request.
pub(super) fn build_context(session: &SessionEntry, view: &PolicyView<'_>) -> PolicyContext {
    let short_id = &session.session_id[..8.min(session.session_id.len())];
    PolicyContext {
        chain_id: view.chain_id.to_string(),
        wallet_id: session.wallet_id.clone(),
        // Sessions are not API tokens; a stable synthetic id keeps executable
        // policies able to attribute the caller.
        api_key_id: format!("ocwp-session:{short_id}"),
        transaction: TransactionContext {
            to: view.to.map(String::from),
            value: view.value.map(String::from),
            raw_hex: view.raw_hex.to_string(),
            data: view.data.map(String::from),
        },
        spending: SpendingContext { daily_total: "0".to_string(), date: today() },
        timestamp: now_rfc3339(),
        typed_data: view.typed_data.and_then(build_typed_data_context),
    }
}

/// Load the policies selected for a session (empty selection = all policies).
pub(super) fn selected_policies(
    session: &SessionEntry,
    vault_path: Option<&Path>,
) -> Result<Vec<Policy>, OcwpError> {
    let all = oc_wallet::policy_store::list_policies(vault_path).map_err(|e| {
        tracing::warn!(error = %e, "ocwp: failed to list policies");
        OcwpError::internal("policy store unavailable")
    })?;
    if session.policy_ids.is_empty() {
        return Ok(all);
    }
    Ok(all.into_iter().filter(|p| session.policy_ids.iter().any(|id| id == &p.id)).collect())
}

/// Evaluate policies; a denial maps to the matching OCWP error code.
pub(super) fn enforce(
    session: &SessionEntry,
    policies: &[Policy],
    view: &PolicyView<'_>,
) -> Result<(), OcwpError> {
    let ctx = build_context(session, view);
    let result = oc_policy::evaluate_policies(policies, &ctx);
    if result.allow {
        Ok(())
    } else {
        let reason = result.reason.as_deref().unwrap_or("denied by policy");
        Err(OcwpError::from_policy_reason(reason, result.policy_id.as_deref()))
    }
}

/// Preview shape for the consent UI: decision + reasons, no side effects.
pub(super) fn preview(session: &SessionEntry, policies: &[Policy], view: &PolicyView<'_>) -> Value {
    let ctx = build_context(session, view);
    let result = oc_policy::evaluate_policies(policies, &ctx);
    json!({
        "method": view.method,
        "decision": if result.allow { "allow" } else { "deny" },
        "reasons": match &result.reason {
            Some(reason) => vec![json!({ "code": "policy", "message": reason })],
            None => Vec::new(),
        },
        "matched_policy_ids": match &result.policy_id {
            Some(id) => vec![json!(id)],
            None => Vec::new(),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> SessionEntry {
        SessionEntry {
            session_id: "0123456789abcdef".repeat(4),
            wallet: "default".into(),
            wallet_id: "wallet-uuid".into(),
            index: 0,
            passphrase: std::sync::Arc::new(zeroize::Zeroizing::new("pass".into())),
            policy_ids: Vec::new(),
            origin: "chrome-extension://test".into(),
            created_at: 0,
            expires_at: u64::MAX,
            last_activity: 0,
        }
    }

    fn allowed_chains_policy(id: &str, chain_ids: &[&str]) -> Policy {
        Policy {
            id: id.into(),
            name: id.into(),
            version: 1,
            created_at: "2026-01-01T00:00:00Z".into(),
            rules: vec![oc_core::PolicyRule::AllowedChains {
                chain_ids: chain_ids.iter().map(|s| s.to_string()).collect(),
            }],
            executable: None,
            config: None,
            action: oc_core::PolicyAction::Deny,
        }
    }

    fn tx_view(chain_id: &str) -> PolicyView<'_> {
        PolicyView {
            method: "oc_send_transaction",
            chain_id,
            to: Some("0x1111111111111111111111111111111111111111"),
            value: Some("1000"),
            data: None,
            raw_hex: "0x02f8",
            typed_data: None,
        }
    }

    #[test]
    fn context_carries_session_and_request_fields() {
        let ctx = build_context(&session(), &tx_view("eip155:8453"));
        assert_eq!(ctx.chain_id, "eip155:8453");
        assert_eq!(ctx.wallet_id, "wallet-uuid");
        assert_eq!(
            ctx.transaction.to.as_deref(),
            Some("0x1111111111111111111111111111111111111111")
        );
        assert_eq!(ctx.transaction.value.as_deref(), Some("1000"));
        assert!(ctx.api_key_id.starts_with("ocwp-session:"));
        assert!(ctx.typed_data.is_none());
    }

    #[test]
    fn enforce_denies_chain_not_in_policy() {
        let policies = vec![allowed_chains_policy("p1", &["eip155:1"])];
        let err = enforce(&session(), &policies, &tx_view("eip155:8453"))
            .expect_err("chain not allowed must deny");
        // An allowlist miss maps to CODE_NOT_WHITELISTED (4303).
        assert_eq!(err.code, super::super::errors::CODE_NOT_WHITELISTED);
        let data = err.data.expect("denial carries data");
        assert_eq!(data["policy_id"], "p1");
    }

    #[test]
    fn enforce_allows_matching_chain() {
        let policies = vec![allowed_chains_policy("p1", &["eip155:8453"])];
        assert!(enforce(&session(), &policies, &tx_view("eip155:8453")).is_ok());
    }

    #[test]
    fn empty_policy_set_allows_default_deny_semantics() {
        // No policies configured at all: `evaluate_policies(&[])` allows.
        assert!(enforce(&session(), &[], &tx_view("eip155:8453")).is_ok());
    }

    #[test]
    fn preview_reports_decision_and_reasons() {
        let policies = vec![allowed_chains_policy("p1", &["eip155:1"])];
        let view = preview(&session(), &policies, &tx_view("eip155:8453"));
        assert_eq!(view["decision"], "deny");
        assert_eq!(view["matched_policy_ids"][0], "p1");
        assert!(view["reasons"][0]["message"].as_str().is_some());
        let ok = preview(&session(), &policies, &tx_view("eip155:1"));
        assert_eq!(ok["decision"], "allow");
    }

    #[test]
    fn typed_data_context_extracts_domain_fields() {
        let td = json!({
            "domain": {
                "name": "Permit2",
                "version": "1",
                "chainId": 8453,
                "verifyingContract": "0x000000000022D473030F116dDEE9F6B43aC78BA3"
            },
            "primaryType": "PermitSingle",
            "message": {}
        });
        let view = PolicyView {
            method: "oc_sign_typed_data",
            chain_id: "eip155:8453",
            to: None,
            value: None,
            data: None,
            raw_hex: "",
            typed_data: Some(&td),
        };
        let ctx = build_context(&session(), &view);
        let typed = ctx.typed_data.expect("typed data context");
        assert_eq!(typed.primary_type, "PermitSingle");
        assert_eq!(typed.domain_chain_id, Some(8453));
        assert_eq!(
            typed.verifying_contract.as_deref(),
            Some("0x000000000022D473030F116dDEE9F6B43aC78BA3")
        );
    }
}
