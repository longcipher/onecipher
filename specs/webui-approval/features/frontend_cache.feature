Feature: Frontend Cache, Navigation, and Theming
  As a wallet Owner
  I want the Web UI to cache data locally, recover navigation on refresh, and respect theme preferences
  So that the experience is responsive and consistent

  # —— IndexedDB cache layer (Improvement E) ——

  @w4-cache-fresh
  Scenario: Fresh cache returns immediately without network fetch
    Given IndexedDB sync table has scene "balances" with updated_at = now - 60s for wallet "w1"
    When the dashboard requests balances for wallet "w1"
    Then the cached balances render within 50ms
    And no GET /api/wallets/w1/balances request is sent

  @w4-cache-stale
  Scenario: Stale cache returns immediately and triggers background refetch
    Given IndexedDB sync table has scene "balances" with updated_at = now - 700s for wallet "w1"
    And the cache holds { USDC: 100 } from a previous fetch
    When the dashboard requests balances
    Then the cached { USDC: 100 } renders immediately
    And a background GET /api/wallets/w1/balances request is sent
    When the response returns { USDC: 110 }
    Then the cache is updated to { USDC: 110 }
    And the dashboard re-renders with the new value

  @w4-cache-empty
  Scenario: Empty cache blocks on first fetch
    Given IndexedDB has no cached balances for wallet "w1"
    When the dashboard requests balances
    Then a GET /api/wallets/w1/balances request is sent
    And the dashboard shows a loading spinner until the response arrives
    And on success the cache is populated and sync.updated_at = now

  @w4-invalidate-on-sign
  Scenario: SignCompleted event invalidates balances + approval_history + audit_log + wc_sessions
    Given the WebSocket receives `{ type: "sign_completed", data: { wallet_id: "w1", chain_id: "eip155:1" } }`
    When the event is processed
    Then the sync table rows for scenes "balances", "approval_history", "audit_log", "wc_sessions" have updated_at = 0
    And the next read of any of those scenes triggers a refetch

  @w4-invalidate-on-wc-session
  Scenario: WCSessionChanged event invalidates only wc_sessions
    Given the WebSocket receives `{ type: "wc_session_changed", data: { topic: "abc", action: "closed" } }`
    When the event is processed
    Then only the sync row for scene "wc_sessions" has updated_at = 0
    And the "balances" sync row is unchanged

  @w4-invalidate-on-policy
  Scenario: PolicyChanged event invalidates policy_snapshot
    Given the WebSocket receives `{ type: "policy_changed", data: { rule_id: "r1", enabled: false } }`
    When the event is processed
    Then the sync row for scene "policy_snapshot" has updated_at = 0

  # —— SortHat dispatcher (Improvement F) ——

  @w4-sort-hat-no-auth-no-wallets
  Scenario: No auth and no wallets → redirect to /welcome
    Given no session cookie is present
    And the wallets list is empty
    When the user opens https://127.0.0.1:port/
    Then SortHat redirects to /welcome

  @w4-sort-hat-no-auth-has-wallets
  Scenario: No auth but wallets exist → redirect to /unlock
    Given no session cookie is present
    And the wallets list is non-empty
    When the user opens https://127.0.0.1:port/
    Then SortHat redirects to /unlock

  @w4-sort-hat-pending-approval
  Scenario: Authed with pending approval → redirect to /approvals/:id
    Given a session cookie is valid
    And a PendingApproval with id "abc-123" exists
    When the user opens https://127.0.0.1:port/
    Then SortHat redirects to /approvals/abc-123

  @w4-sort-hat-page-state-cache
  Scenario: Refresh restores last route via page_state_cache
    Given the user was last on /wallets/w1
    And localStorage["oc_page_state"] = { path: "/wallets/w1", search: "" }
    When the user refreshes the page
    Then SortHat redirects to /wallets/w1

  # —— Persistent mounting (Improvement G) ——

  @w4-persistent-mount-sessions
  Scenario: Sessions view stays mounted when navigating away
    Given the user is on /sessions and the WC sessions list is loaded
    When the user navigates to /dashboard
    Then the Sessions component remains mounted with display:none
    When the user navigates back to /sessions
    Then the WC sessions list is shown immediately without refetching
    And the WebSocket subscription was never torn down

  # —— Theming ——

  @w4-theme-dark
  Scenario: Dark mode toggled via html.dark class
    Given the user has selected dark mode in settings
    When any page renders
    Then the <html> element has class "dark"
    And the body background uses var(--oc-neutral-bg-1) which resolves to the dark RGB triplet

  @w4-theme-single-source
  Scenario: Theme tokens are injected from oc-core::theme at daemon startup
    When the daemon starts
    Then a <style id="oc-tokens"> element is present in the served index.html
    And it contains --oc-blue-rgb, --oc-blue, and --oc-color-primary definitions
    And the front-end does not duplicate these definitions

  # —— i18n ——

  @w4-i18n-lazy-load
  Scenario: Locale switching fetches .ftl on demand
    Given the default locale is "en" and only en.ftl is loaded
    When the user switches to "zh-CN" in settings
    Then the browser fetches /locales/zh-CN.ftl
    And the locale is cached in localStorage
    And all UI text re-renders in Chinese

  @w4-i18n-plural
  Scenario: Fluent handles pluralization natively
    Given the locale is "en" and the count of pending approvals is 1
    When the approval list header renders
    Then the text reads "1 pending approval"
    When the count is 3
    Then the text reads "3 pending approvals"
