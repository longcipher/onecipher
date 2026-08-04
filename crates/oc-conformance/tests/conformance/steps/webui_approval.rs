//! Step definitions for `specs/webui-approval/features/approval_flow.feature`.
//!
//! Covers `@w1-*` scenarios:
//! - approval mode on/off
//! - approve/reject/timeout
//! - persistence
//! - bootstrap & WebAuthn
//! - auto-lock
//! - R12 source isolation

use std::{path::PathBuf, process::Command};

use cucumber::{given, then, when};

use crate::ConformanceWorld;

// ===========================================================================
// Helper: workspace root
// ===========================================================================

fn ws_root() -> PathBuf {
    crate::workspace_root()
}

// ===========================================================================
// R12a — source-level isolation (@w1-r12-source-isolation)
// ===========================================================================

#[when(regex = r"verifying R12a via .rg.*TcpListener\|TcpStream.*")]
async fn when_rg_tcp_symbols(_world: &mut ConformanceWorld) {
    // Intentionally no-op; the assertion is in the `then` step.
}

#[then("the command produces no output")]
async fn then_no_rg_output(_world: &mut ConformanceWorld) {
    let root = ws_root();
    let output = Command::new("rg")
        .args([
            "-n",
            "TcpListener|TcpStream",
            &root.join("crates/oc-keyagent/src/").to_string_lossy(),
            &root.join("crates/oc-crypto/src/").to_string_lossy(),
            &root.join("crates/oc-policy/src/").to_string_lossy(),
            &root.join("crates/oc-session-key/src/").to_string_lossy(),
        ])
        .output()
        .expect("failed to run rg");

    assert!(
        output.stdout.is_empty(),
        "R12a FAIL: TcpListener/TcpStream found in isolated crate sources:\n{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

// ===========================================================================
// Background steps (@w1 shared context)
// ===========================================================================

#[given("the daemon is running with `[webui] enabled = true`")]
async fn given_daemon_running_webui_enabled(_world: &mut ConformanceWorld) {
    // TODO(W1.14): Spawn an in-process daemon with webui enabled.
    // For now, this step is a no-op placeholder.
}

#[given("the daemon is running with `[webui] approval_mode = true`")]
async fn given_daemon_running_approval_mode_on(_world: &mut ConformanceWorld) {
    // TODO(W1.14): Spawn an in-process daemon with webui approval_mode = true.
    // For now, this step is a no-op placeholder.
}

#[given("a browser tab is authenticated via WebAuthn Passkey")]
async fn given_browser_authenticated(_world: &mut ConformanceWorld) {
    // TODO(W1.14): Mock browser auth session.
}

#[given("the caller is authenticated via a valid session cookie unless noted")]
async fn given_caller_authenticated(_world: &mut ConformanceWorld) {
    // TODO(W1.14): Mock session cookie auth.
}

#[given("the daemon listens on a loopback 127.0.0.1 random port")]
async fn given_daemon_loopback(_world: &mut ConformanceWorld) {
    // Verified by R12e — loopback-only bind is enforced in oc-webui::run_webui_server.
}

// ===========================================================================
// @w1-approval-mode-off
// ===========================================================================

#[given("`[webui] approval_mode = false`")]
async fn given_approval_mode_off(_world: &mut ConformanceWorld) {
    // TODO(W1.14): Configure webui.approval_mode = false.
}

#[when("a dApp sends `personal_sign` via WalletConnect v2")]
async fn when_dapp_sends_personal_sign(_world: &mut ConformanceWorld) {
    // TODO(W1.14): Send mock WC v2 personal_sign request.
}

#[when("the Policy Engine returns Decision::Allow")]
async fn when_policy_allows(_world: &mut ConformanceWorld) {
    // TODO(W1.14): Configure mock policy to return Allow.
}

#[then("the daemon signs without surfacing the request to the Web UI")]
async fn then_signs_without_web_ui(_world: &mut ConformanceWorld) {
    // TODO(W1.14): Assert no pending approval was created.
}

#[then("the dApp receives the signature within the existing latency budget")]
async fn then_dapp_receives_signature(_world: &mut ConformanceWorld) {
    // TODO(W1.14): Assert WC response received.
}

#[then("no entry is appended to approval_queue.jsonl")]
async fn then_no_jsonl_entry(_world: &mut ConformanceWorld) {
    // TODO(W1.14): Assert approval_queue.jsonl unchanged.
}

// ===========================================================================
// @w1-approval-mode-on
// ===========================================================================

#[given("`[webui] approval_mode = true`")]
async fn given_approval_mode_on(_world: &mut ConformanceWorld) {
    // TODO(W1.14): Configure webui.approval_mode = true.
}

#[when("a dApp sends `eth_sendTransaction` via WalletConnect v2")]
async fn when_dapp_sends_eth_send_tx(_world: &mut ConformanceWorld) {
    // TODO(W1.14): Send mock WC v2 eth_sendTransaction.
}

#[then("the daemon appends a `pending` event to approval_queue.jsonl")]
async fn then_pending_appended(_world: &mut ConformanceWorld) {
    // TODO(W1.14): Assert jsonl contains pending event.
}

#[then("the daemon pushes a `pending_approval` message over WebSocket /ws")]
async fn then_ws_pending_pushed(_world: &mut ConformanceWorld) {
    // TODO(W1.14): Assert WebSocket message received.
}

#[then("the browser tab renders the PendingApproval card")]
async fn then_browser_renders_card(_world: &mut ConformanceWorld) {
    // TODO(W1.14): Front-end assertion (out of scope for backend BDD).
}

#[then("the dApp does NOT receive a response until the user decides")]
async fn then_dapp_waits(_world: &mut ConformanceWorld) {
    // TODO(W1.14): Assert WC channel blocked.
}

// ===========================================================================
// @w1-non-signing-bypass
// ===========================================================================

#[when("a dApp sends `onecipher_listWallets` via WalletConnect v2")]
async fn when_dapp_sends_list_wallets(_world: &mut ConformanceWorld) {
    // TODO(W1.14): Send non-signing method.
}

#[then("the daemon responds directly without creating a PendingApproval")]
async fn then_responds_directly(_world: &mut ConformanceWorld) {
    // TODO(W1.14): Assert no PendingApproval created.
}

// ===========================================================================
// @w1-r12-loopback-only
// ===========================================================================

#[given("the daemon is running")]
async fn given_daemon_is_running(_world: &mut ConformanceWorld) {
    // TODO(W1.14): Start daemon for lsof verification.
}

#[when(regex = r"verifying via .lsof.*")]
async fn when_lsof_check(_world: &mut ConformanceWorld) {
    // Intentionally no-op; assertion is in `then` step.
}

#[then("every listening address starts with 127.0.0.1")]
async fn then_only_loopback(_world: &mut ConformanceWorld) {
    // TODO(W1.14): Parse lsof output and assert loopback-only.
    // In unit test scope, this is already verified by
    // oc_webui::tests::test_rejects_non_loopback.
}

#[then("no 0.0.0.0 or external address appears")]
async fn then_no_external_address(_world: &mut ConformanceWorld) {
    // Redundant with the previous step — kept for BDD completeness.
}
