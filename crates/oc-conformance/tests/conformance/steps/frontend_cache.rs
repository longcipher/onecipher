//! Step definitions for `specs/webui-approval/features/frontend_cache.feature`
//! and `specs/webui-approval/features/api_surface.feature`.
//!
//! Covers `@w4-*` scenarios:
//! - Cache fresh/stale/empty
//! - Invalidate on events
//! - SortHat redirect
//! - Persistent mount
//! - Theme dark mode
//! - i18n
//! - Wallets, sessions, audit, policy, session-keys, secrets API surface

use cucumber::{given, then, when};

use crate::ConformanceWorld;

// ===========================================================================
// @w4-sort-hat-*
// ===========================================================================

#[given("no authenticated session and no wallets")]
async fn given_no_auth_no_wallets(_world: &mut ConformanceWorld) {
    // TODO(W4.8): Set up state with no auth and no wallets.
}

#[when("the user opens the Web UI")]
async fn when_open_webui(_world: &mut ConformanceWorld) {
    // TODO(W4.8): Navigate to Web UI root.
}

#[then("the SortHat redirects to /welcome")]
async fn then_redirect_welcome(_world: &mut ConformanceWorld) {
    // TODO(W4.8): Assert redirect to /welcome.
}

#[given("no authenticated session and wallets exist")]
async fn given_no_auth_has_wallets(_world: &mut ConformanceWorld) {
    // TODO(W4.8): Set up state with wallets but no auth.
}

#[then("the SortHat redirects to /unlock")]
async fn then_redirect_unlock(_world: &mut ConformanceWorld) {
    // TODO(W4.8): Assert redirect to /unlock.
}

#[given("authenticated session and a pending approval exists")]
async fn given_auth_pending(_world: &mut ConformanceWorld) {
    // TODO(W4.8): Set up authenticated state with pending approval.
}

#[then(regex = r"the SortHat redirects to /approvals/([\w-]+)")]
async fn then_redirect_approval(_world: &mut ConformanceWorld, _id: String) {
    // TODO(W4.8): Assert redirect to approval detail.
}

#[given("authenticated session and page state cached as /sessions")]
async fn given_auth_cached_sessions(_world: &mut ConformanceWorld) {
    // TODO(W4.8): Set up auth with cached page state.
}

#[then("the SortHat redirects to /sessions")]
async fn then_redirect_cached(_world: &mut ConformanceWorld) {
    // TODO(W4.8): Assert redirect to cached page.
}

// ===========================================================================
// @w4-cache-*
// ===========================================================================

#[given("the IndexedDB cache is empty")]
async fn given_cache_empty(_world: &mut ConformanceWorld) {
    // TODO(W4.8): Clear cache.
}

#[when("the dashboard requests wallet balances")]
async fn when_request_balances(_world: &mut ConformanceWorld) {
    // TODO(W4.8): Trigger balance fetch.
}

#[then("the API fetches from the backend")]
async fn then_fetch_backend(_world: &mut ConformanceWorld) {
    // TODO(W4.8): Assert backend was called.
}

#[then("the result is cached in IndexedDB")]
async fn fn_result_cached(_world: &mut ConformanceWorld) {
    // TODO(W4.8): Assert cache populated.
}

#[given("the cache has balances from 61 seconds ago")]
async fn given_stale_cache(_world: &mut ConformanceWorld) {
    // TODO(W4.8): Set up stale cache entry.
}

#[when("the dashboard requests balances")]
async fn when_request_balances_again(_world: &mut ConformanceWorld) {
    // TODO(W4.8): Trigger balance fetch.
}

#[then("stale data is returned immediately")]
async fn fn_stale_returned(_world: &mut ConformanceWorld) {
    // TODO(W4.8): Assert stale data served.
}

#[then("a background revalidation fetch is triggered")]
async fn fn_background_fetch(_world: &mut ConformanceWorld) {
    // TODO(W4.8): Assert background fetch started.
}

// ===========================================================================
// @w4-invalidate-*
// ===========================================================================

#[when("a `sign` WebSocket event arrives")]
async fn when_sign_ws_event(_world: &mut ConformanceWorld) {
    // TODO(W4.8): Send sign WS event.
}

#[then("the approvals scene cache is invalidated")]
async fn fn_approvals_invalidated(_world: &mut ConformanceWorld) {
    // TODO(W4.8): Assert approvals cache cleared.
}

#[when("a `wc_session` WebSocket event arrives")]
async fn when_wc_session_event(_world: &mut ConformanceWorld) {
    // TODO(W4.8): Send WC session WS event.
}

#[then("the sessions scene cache is invalidated")]
async fn fn_sessions_invalidated(_world: &mut ConformanceWorld) {
    // TODO(W4.8): Assert sessions cache cleared.
}

#[when("a `policy` WebSocket event arrives")]
async fn when_policy_event(_world: &mut ConformanceWorld) {
    // TODO(W4.8): Send policy WS event.
}

#[then("the policy scene cache is invalidated")]
async fn fn_policy_invalidated(_world: &mut ConformanceWorld) {
    // TODO(W4.8): Assert policy cache cleared.
}

// ===========================================================================
// @w4-persistent-mount-*
// ===========================================================================

#[given("the user is on the Sessions page")]
async fn given_on_sessions(_world: &mut ConformanceWorld) {
    // TODO(W4.8): Navigate to Sessions.
}

#[when("the user navigates to Settings")]
async fn when_navigate_settings(_world: &mut ConformanceWorld) {
    // TODO(W4.8): Navigate to Settings.
}

#[then("the Sessions component is hidden (not unmounted)")]
async fn fn_sessions_hidden(_world: &mut ConformanceWorld) {
    // TODO(W4.8): Assert Sessions has display:none.
}

#[then("the WebSocket subscription is still active")]
async fn fn_ws_still_active(_world: &mut ConformanceWorld) {
    // TODO(W4.8): Assert WS subscription not torn down.
}

// ===========================================================================
// @w4-theme-*
// ===========================================================================

#[given("the user toggles dark mode")]
async fn given_toggle_dark(_world: &mut ConformanceWorld) {
    // TODO(W4.8): Toggle dark mode.
}

#[then("the html element gets class 'dark'")]
async fn fn_html_dark(_world: &mut ConformanceWorld) {
    // TODO(W4.8): Assert html.dark class.
}

#[then("CSS custom properties update to dark values")]
async fn fn_css_dark_values(_world: &mut ConformanceWorld) {
    // TODO(W4.8): Assert CSS vars updated.
}

// ===========================================================================
// @w4-i18n-*
// ===========================================================================

#[when("the user switches language to zh-CN")]
async fn when_switch_lang(_world: &mut ConformanceWorld) {
    // TODO(W4.8): Switch language.
}

#[then("UI text is loaded from zh-CN.ftl")]
async fn fn_text_zhcn(_world: &mut ConformanceWorld) {
    // TODO(W4.8): Assert Chinese text displayed.
}

// ===========================================================================
// @w4-wallets-*
// ===========================================================================

#[when("the user requests wallet list")]
async fn when_request_wallets(_world: &mut ConformanceWorld) {
    // TODO(W4.8): Call GET /api/wallets.
}

#[then("the API returns the list of wallets")]
async fn fn_wallets_returned(_world: &mut ConformanceWorld) {
    // TODO(W4.8): Assert wallet list returned.
}

#[when("the user creates a new wallet")]
async fn when_create_wallet(_world: &mut ConformanceWorld) {
    // TODO(W4.8): Call POST /api/wallets.
}

#[then("the API returns the new wallet details")]
async fn fn_wallet_created(_world: &mut ConformanceWorld) {
    // TODO(W4.8): Assert wallet created.
}

#[when("the user sends a transaction from wallet")]
async fn when_send_tx(_world: &mut ConformanceWorld) {
    // TODO(W4.8): Call POST /api/wallets/{id}/send.
}

#[then("the API forwards to Key-Agent for signing")]
async fn fn_forwarded_to_ka(_world: &mut ConformanceWorld) {
    // TODO(W4.8): Assert forwarding.
}

// ===========================================================================
// @w4-wc-*
// ===========================================================================

#[when("the user requests WC sessions")]
async fn when_request_sessions(_world: &mut ConformanceWorld) {
    // TODO(W4.8): Call GET /api/sessions.
}

#[then("the API returns active sessions")]
async fn fn_sessions_returned(_world: &mut ConformanceWorld) {
    // TODO(W4.8): Assert sessions returned.
}

#[when("the user pairs with a WC URI")]
async fn when_pair_wc(_world: &mut ConformanceWorld) {
    // TODO(W4.8): Call POST /api/sessions/pair.
}

#[then("the API returns the pairing result")]
async fn fn_pair_result(_world: &mut ConformanceWorld) {
    // TODO(W4.8): Assert pairing result.
}

#[when("the user generates a WC pairing URI")]
async fn when_generate_wc(_world: &mut ConformanceWorld) {
    // TODO(W4.8): Call POST /api/sessions/generate.
}

#[then("the API returns a pairing URI")]
async fn fn_uri_returned(_world: &mut ConformanceWorld) {
    // TODO(W4.8): Assert URI returned.
}

// ===========================================================================
// @w4-audit-*
// ===========================================================================

#[when("the user requests audit log")]
async fn when_request_audit(_world: &mut ConformanceWorld) {
    // TODO(W4.8): Call GET /api/audit.
}

#[then("the API returns paginated audit entries")]
async fn fn_audit_returned(_world: &mut ConformanceWorld) {
    // TODO(W4.8): Assert audit entries returned.
}

// ===========================================================================
// @w4-policy-*
// ===========================================================================

#[when("the user requests policy rules")]
async fn when_request_policy(_world: &mut ConformanceWorld) {
    // TODO(W4.8): Call GET /api/settings/policy.
}

#[then("the API returns the policy rules")]
async fn fn_policy_returned(_world: &mut ConformanceWorld) {
    // TODO(W4.8): Assert policy rules returned.
}

#[when("the user patches a policy rule")]
async fn when_patch_policy(_world: &mut ConformanceWorld) {
    // TODO(W4.8): Call PATCH /api/settings/policy/{id}.
}

#[then("the API returns the updated rule")]
async fn fn_policy_updated(_world: &mut ConformanceWorld) {
    // TODO(W4.8): Assert rule updated.
}

// ===========================================================================
// @w4-session-keys-*
// ===========================================================================

#[when("the user requests session keys")]
async fn when_request_sk(_world: &mut ConformanceWorld) {
    // TODO(W4.8): Call GET /api/settings/session-keys.
}

#[then("the API returns session keys")]
async fn fn_sk_returned(_world: &mut ConformanceWorld) {
    // TODO(W4.8): Assert session keys returned.
}

#[when("the user creates a session key")]
async fn when_create_sk(_world: &mut ConformanceWorld) {
    // TODO(W4.8): Call POST /api/settings/session-keys.
}

#[then("the API returns the new session key")]
async fn fn_sk_created(_world: &mut ConformanceWorld) {
    // TODO(W4.8): Assert session key created.
}

// ===========================================================================
// @w4-secrets-*
// ===========================================================================

#[when("the user requests secrets list")]
async fn when_request_secrets(_world: &mut ConformanceWorld) {
    // TODO(W4.8): Call GET /api/settings/secrets.
}

#[then("the API returns secrets metadata")]
async fn fn_secrets_returned(_world: &mut ConformanceWorld) {
    // TODO(W4.8): Assert secrets returned.
}

#[when("the user requests a secret value with WebAuthn assertion")]
async fn when_get_secret_webauthn(_world: &mut ConformanceWorld) {
    // TODO(W4.8): Call GET /api/settings/secrets/{id} with assertion header.
}

#[then("the API returns the decrypted secret")]
async fn fn_secret_decrypted(_world: &mut ConformanceWorld) {
    // TODO(W4.8): Assert secret returned.
}
