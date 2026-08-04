//! Step definitions for `specs/webui-approval/features/risk_gate.feature`.
//!
//! Covers `@w2-*` scenarios:
//! - Policy Deny → Forbidden (immediate reject)
//! - Policy Warn → Warning level (ack-gated)
//! - Acknowledge flow (Disabled → Armed)
//! - Danger countdown
//! - Forbidden hides Sign
//! - Two-step confirm (Armed → Submitting)
//! - Color mapping

use cucumber::{given, then, when};

use crate::ConformanceWorld;

// ===========================================================================
// @w2-policy-deny-forbidden
// ===========================================================================

#[given(regex = r#"the Policy Engine returns Decision::Deny with reason "(.+)""#)]
async fn given_policy_deny(_world: &mut ConformanceWorld, _reason: String) {
    // TODO(W2.4): Configure mock policy to return Deny with the given reason.
}

#[then(regex = r#"the dApp immediately receives a JSON-RPC error with code -32001 and "(.+)""#)]
async fn then_dapp_receives_rpc_error(_world: &mut ConformanceWorld, _message: String) {
    // TODO(W2.4): Assert WC response contains JSON-RPC error -32001.
}

#[then("no PendingApproval is created")]
async fn fn_no_pending_approval(_world: &mut ConformanceWorld) {
    // TODO(W2.4): Assert approval queue is empty.
}

#[then("no `pending` event is appended to approval_queue.jsonl")]
async fn then_no_jsonl_pending(_world: &mut ConformanceWorld) {
    // TODO(W2.4): Assert no pending event in jsonl.
}

// ===========================================================================
// @w2-policy-warn
// ===========================================================================

#[given(regex = r"the Policy Engine returns Decision::Warn with reason (.+)")]
async fn given_policy_warn(_world: &mut ConformanceWorld, _reason: String) {
    // TODO(W2.4): Configure mock policy to return Warn with the given reason.
}

#[then(regex = r"the PendingApproval has risk_level = (\w+)")]
async fn then_risk_level(_world: &mut ConformanceWorld, _level: String) {
    // TODO(W2.4): Assert PendingApproval.risk_level matches.
}

#[then(regex = r#"the risk_reasons list contains an entry with code "(.+)""#)]
async fn then_risk_reason_code(_world: &mut ConformanceWorld, _code: String) {
    // TODO(W2.4): Assert risk_reasons contains the given code.
}

#[then("the Sign button is rendered Disabled")]
async fn then_sign_disabled(_world: &mut ConformanceWorld) {
    // TODO(W2.4): Assert Sign button is disabled in rendered UI.
}

#[then(regex = r#"the RiskCard for "(.+)" is shown"#)]
async fn then_risk_card_shown(_world: &mut ConformanceWorld, _code: String) {
    // TODO(W2.4): Assert RiskCard is rendered.
}

// ===========================================================================
// @w2-policy-warn-ack
// ===========================================================================

#[given(regex = r"a PendingApproval with risk_level = (\w+) and one unacknowledged RiskReason")]
async fn given_pending_with_risk(_world: &mut ConformanceWorld, _level: String) {
    // TODO(W2.4): Create PendingApproval with risk and unacknowledged reason.
}

#[when(regex = r#"^the user clicks "Acknowledge" on the RiskCard$"#)]
async fn when_acknowledge_risk(_world: &mut ConformanceWorld) {
    // TODO(W2.4): Simulate clicking Acknowledge.
}

#[then("the RiskReason is removed from the unprocessed list")]
async fn then_risk_removed(_world: &mut ConformanceWorld) {
    // TODO(W2.4): Assert unprocessed_warnings is empty.
}

#[then("the Sign button transitions from Disabled to enabled")]
async fn then_sign_enabled(_world: &mut ConformanceWorld) {
    // TODO(W2.4): Assert Sign button is enabled.
}

#[when("the user clicks Sign")]
async fn when_click_sign(_world: &mut ConformanceWorld) {
    // TODO(W2.4): Simulate clicking Sign.
}

#[then(regex = r#"the button transitions to (\w+) state, revealing "(.+)" and "(.+)""#)]
async fn then_button_state_reveal(
    _world: &mut ConformanceWorld,
    _state: String,
    _btn1: String,
    _btn2: String,
) {
    // TODO(W2.4): Assert button state and revealed buttons.
}

// ===========================================================================
// @w2-danger-countdown
// ===========================================================================

#[given(regex = r"^a PendingApproval with risk_level = (\w+)$")]
async fn given_pending_risk_level(_world: &mut ConformanceWorld, _level: String) {
    // TODO(W2.4): Create PendingApproval with given risk level.
}

#[when("the approval detail view renders")]
async fn when_detail_renders(_world: &mut ConformanceWorld) {
    // TODO(W2.4): Navigate to approval detail.
}

#[then(regex = r#"the Sign button is Disabled and shows "(.+)""#)]
async fn then_sign_disabled_with_text(_world: &mut ConformanceWorld, _text: String) {
    // TODO(W2.4): Assert Sign button disabled with countdown text.
}

#[then(regex = r#"After (\d+) second[s]? the text reads "(.+)""#)]
async fn then_countdown_text(_world: &mut ConformanceWorld, _secs: u64, _text: String) {
    // TODO(W2.4): Assert countdown text after delay.
}

#[then(regex = r"After (\d+) seconds the Sign button becomes enabled for first-click")]
async fn then_sign_becomes_enabled(_world: &mut ConformanceWorld, _secs: u64) {
    // TODO(W2.4): Assert Sign button enabled after countdown.
}

// ===========================================================================
// @w2-forbidden-hides-sign
// ===========================================================================

#[then("no Sign button is rendered")]
async fn then_no_sign_button(_world: &mut ConformanceWorld) {
    // TODO(W2.4): Assert Sign button is not present.
}

#[then(regex = r"only a Reject button \((.+)\) is shown")]
async fn then_only_reject(_world: &mut ConformanceWorld, _style: String) {
    // TODO(W2.4): Assert only Reject button visible.
}

// ===========================================================================
// @w2-two-step-cancel
// ===========================================================================

#[given(regex = r"a PendingApproval and the user has clicked Sign \(state = (\w+)\)")]
async fn given_state_armed(_world: &mut ConformanceWorld, _state: String) {
    // TODO(W2.4): Set up Armed state.
}

#[when("the user clicks Cancel")]
async fn when_click_cancel(_world: &mut ConformanceWorld) {
    // TODO(W2.4): Simulate clicking Cancel.
}

#[then("the state returns to Disabled")]
async fn fn_state_disabled(_world: &mut ConformanceWorld) {
    // TODO(W2.4): Assert state is Disabled.
}

#[then(regex = r"no POST /api/approvals/:id/decision is sent")]
async fn fn_no_decision_post(_world: &mut ConformanceWorld) {
    // TODO(W2.4): Assert no POST was made.
}

#[then("the PendingApproval remains in the queue")]
async fn fn_still_in_queue(_world: &mut ConformanceWorld) {
    // TODO(W2.4): Assert approval still in queue.
}

// ===========================================================================
// @w2-two-step-confirm
// ===========================================================================

#[given(regex = r"a PendingApproval and state = (\w+)")]
async fn given_state(_world: &mut ConformanceWorld, _state: String) {
    // TODO(W2.4): Set up given state.
}

#[when(regex = r#"^the user clicks "(.+)"$"#)]
async fn when_click_button(_world: &mut ConformanceWorld, _button: String) {
    // TODO(W2.4): Simulate clicking the named button.
}

#[then(regex = r"the state transitions to (\w+)")]
async fn fn_state_transition(_world: &mut ConformanceWorld, _state: String) {
    // TODO(W2.4): Assert state transition.
}

#[then(regex = r"the browser POSTs /api/approvals/:id/decision with (\w+)")]
async fn fn_post_decision(_world: &mut ConformanceWorld, _decision: String) {
    // TODO(W2.4): Assert POST was made with correct decision.
}

#[then(regex = r#"the Sign button shows "(.+)" and is disabled"#)]
async fn fn_sign_showing(_world: &mut ConformanceWorld, _text: String) {
    // TODO(W2.4): Assert Sign button text and disabled state.
}

// ===========================================================================
// @w2-color-mapping
// ===========================================================================

#[given(regex = r"PendingApprovals exist with risk levels (.+)")]
async fn given_multiple_risk_levels(_world: &mut ConformanceWorld, _levels: String) {
    // TODO(W2.4): Create PendingApprovals with different risk levels.
}

#[when("the approval list renders")]
async fn when_list_renders(_world: &mut ConformanceWorld) {
    // TODO(W2.4): Navigate to approval list.
}

#[then(regex = r"the (\w+) card border uses (.+)")]
async fn then_card_border_color(_world: &mut ConformanceWorld, _level: String, _color: String) {
    // TODO(W2.4): Assert card border color matches CSS variable.
}

// ===========================================================================
// @w3-sim-balance-change
// ===========================================================================

#[given(regex = r"a dApp sends `eth_sendTransaction` swapping (.+) for (.+) on Uniswap V2")]
async fn given_swap_tx(_world: &mut ConformanceWorld, _from: String, _to: String) {
    // TODO(W3.5): Set up mock WC request for Uniswap swap.
}

#[when("the daemon runs evm2 simulation")]
async fn when_run_simulation(_world: &mut ConformanceWorld) {
    // TODO(W3.5): Trigger simulation.
}

#[then(regex = r"TxSimulation\.success = (true|false)")]
async fn then_sim_success(_world: &mut ConformanceWorld, _success: String) {
    // TODO(W3.5): Assert simulation success flag.
}

#[then(
    regex = r#"balance_change contains TokenDelta \{ token: "(.+)", direction: (\w+), amount: "(.+)" \}"#
)]
async fn then_balance_delta(
    _world: &mut ConformanceWorld,
    _token: String,
    _direction: String,
    _amount: String,
) {
    // TODO(W3.5): Assert balance change entry.
}

#[then("the SimPanel renders both deltas in human-readable form")]
async fn then_sim_panel_deltas(_world: &mut ConformanceWorld) {
    // TODO(W3.5): Assert SimPanel displays deltas.
}

// ===========================================================================
// @w3-sim-decoded-action
// ===========================================================================

#[given(regex = r"a dApp calls `(.+)` on a known Uniswap V2 router")]
async fn given_known_function_call(_world: &mut ConformanceWorld, _function: String) {
    // TODO(W3.5): Set up mock WC request with known function selector.
}

#[when("the daemon runs ABI decoding against the local abi_cache")]
async fn when_abi_decode(_world: &mut ConformanceWorld) {
    // TODO(W3.5): Trigger ABI decoding.
}

#[then(regex = r#"DecodedAction\.contract_name = "(.+)""#)]
async fn then_contract_name(_world: &mut ConformanceWorld, _name: String) {
    // TODO(W3.5): Assert contract name.
}

#[then(regex = r#"DecodedAction\.function_name = "(.+)""#)]
async fn then_function_name(_world: &mut ConformanceWorld, _name: String) {
    // TODO(W3.5): Assert function name.
}

#[then(regex = r#"DecodedAction\.human_readable = "(.+)""#)]
async fn then_human_readable(_world: &mut ConformanceWorld, _text: String) {
    // TODO(W3.5): Assert human-readable text.
}

// ===========================================================================
// @w3-sim-failure-degrade
// ===========================================================================

#[given("a dApp sends `eth_sendTransaction` with calldata for an unknown contract")]
async fn given_unknown_contract_tx(_world: &mut ConformanceWorld) {
    // TODO(W3.5): Set up mock WC request with unknown contract.
}

#[when("the daemon runs evm2 simulation and it fails")]
async fn when_sim_fails(_world: &mut ConformanceWorld) {
    // TODO(W3.5): Trigger failed simulation.
}

#[then("PendingApproval.simulation = None")]
async fn fn_simulation_none(_world: &mut ConformanceWorld) {
    // TODO(W3.5): Assert simulation is None.
}

#[then("the SimPanel shows the raw calldata hex")]
async fn fn_shows_raw_hex(_world: &mut ConformanceWorld) {
    // TODO(W3.5): Assert raw hex displayed.
}

#[then(regex = r#"a "(.+)" notice is displayed"#)]
async fn fn_notice_displayed(_world: &mut ConformanceWorld, _notice: String) {
    // TODO(W3.5): Assert notice text.
}

#[then("the Sign button is NOT blocked by simulation state")]
async fn fn_sign_not_blocked(_world: &mut ConformanceWorld) {
    // TODO(W3.5): Assert Sign button is enabled.
}

// ===========================================================================
// @w3-sim-gas-used
// ===========================================================================

#[given(regex = r"a PendingApproval with TxSimulation\.gas_used = (\d+)")]
async fn given_gas_used(_world: &mut ConformanceWorld, _gas: u64) {
    // TODO(W3.5): Set up PendingApproval with gas_used.
}

#[when("the SimPanel renders")]
async fn when_sim_panel_renders(_world: &mut ConformanceWorld) {
    // TODO(W3.5): Navigate to SimPanel.
}

#[then(regex = r#"the gas estimate "(.+)""#)]
async fn then_gas_estimate(_world: &mut ConformanceWorld, _text: String) {
    // TODO(W3.5): Assert gas estimate text.
}
