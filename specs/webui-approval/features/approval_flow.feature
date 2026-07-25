Feature: Web UI Approval Flow
  As a wallet Owner
  I want signing requests from WalletConnect v2 dApps to surface in a local Web UI
  So that I can review and approve/reject them with full context

  Background:
    Given the daemon is running with `[webui] enabled = true`
    And a browser tab is authenticated via WebAuthn Passkey
    And the daemon listens on a loopback 127.0.0.1 random port

  # —— W1: happy path, mode switch, timeout ——

  @w1-approval-mode-off
  Scenario: Approval mode OFF and Safe risk → implicit signing (zero regression)
    Given `[webui] approval_mode = false`
    When a dApp sends `personal_sign` via WalletConnect v2
    And the Policy Engine returns Decision::Allow
    Then the daemon signs without surfacing the request to the Web UI
    And the dApp receives the signature within the existing latency budget
    And no entry is appended to approval_queue.jsonl

  @w1-approval-mode-on
  Scenario: Approval mode ON → request surfaces in Web UI
    Given `[webui] approval_mode = true`
    When a dApp sends `eth_sendTransaction` via WalletConnect v2
    Then the daemon appends a `pending` event to approval_queue.jsonl
    And the daemon pushes a `pending_approval` message over WebSocket /ws
    And the browser tab renders the PendingApproval card
    And the dApp does NOT receive a response until the user decides

  @w1-approve
  Scenario: User approves → daemon signs and dApp receives signature
    Given a PendingApproval with id "abc-123" exists in the queue
    When the user clicks Sign, then Confirm Sign
    Then the browser POSTs /api/approvals/abc-123/decision with Approve
    And the daemon forwards the request to Key-Agent via UDS
    And the dApp receives the signature
    And the daemon appends a `resolved` event with decision "approved" to approval_queue.jsonl
    And the WebSocket broadcasts `approval_resolved` with decision "approved"

  @w1-reject
  Scenario: User rejects → dApp receives JSON-RPC error -32001
    Given a PendingApproval with id "abc-123" exists in the queue
    When the user clicks Reject
    Then the browser POSTs /api/approvals/abc-123/decision with Reject
    And the dApp receives a JSON-RPC error with code -32001 and message "user rejected"
    And the daemon appends a `resolved` event with decision "rejected" to approval_queue.jsonl

  @w1-timeout
  Scenario: Approval timeout → dApp receives JSON-RPC error -32001 RequestTimeout
    Given `[webui] approval_timeout_secs = 300`
    And a PendingApproval with expires_at_unix = T0 exists
    When 300 seconds elapse without a user decision
    Then the daemon cancels the pending request
    And the dApp receives a JSON-RPC error with code -32001 and message "approval timeout"
    And the daemon appends a `resolved` event with decision "timeout" to approval_queue.jsonl

  @w1-multi-tab
  Scenario: Multi-tab consistency — first decision wins
    Given a PendingApproval with id "abc-123" exists
    And two browser tabs are both connected via WebSocket /ws
    When tab A POSTs /api/approvals/abc-123/decision with Approve
    And tab B POSTs /api/approvals/abc-123/decision with Reject concurrently
    Then exactly one POST returns 200 and the other returns 409
    And the WebSocket broadcasts `approval_resolved` with the winning decision
    And both tabs remove the PendingApproval card

  @w1-non-signing-bypass
  Scenario: Non-signing methods bypass the approval gate
    When a dApp sends `onecipher_listWallets` via WalletConnect v2
    Then the daemon responds directly without creating a PendingApproval
    And no `pending` event is appended to approval_queue.jsonl

  # —— Persistence & recovery (Improvement D) ——

  @w1-persist-pending
  Scenario: Daemon restart replays unresolved approvals
    Given a PendingApproval with id "abc-123" is in the queue
    And approval_queue.jsonl contains its `pending` event but no `resolved` event
    When the daemon restarts
    Then the daemon re-queues the PendingApproval with id "abc-123"
    And the next browser tab to authenticate receives the PendingApproval via WebSocket
    And the original created_at_unix is preserved

  @w1-persist-resolved-gc
  Scenario: Resolved entries are archived after 7 days
    Given approval_queue.jsonl contains a `resolved` event from 8 days ago
    When the daily GC runs
    Then the entry is moved to approval_queue.YYYY-MM-DD.jsonl.gz
    And the original approval_queue.jsonl no longer contains that entry

  # —— Bootstrap & WebAuthn ——

  @w1-bootstrap-token
  Scenario: Bootstrap token is single-use and 5-minute TTL
    Given the daemon just started and wrote a bootstrap_token to ~/.onecipher/bootstrap_token
    When the user runs `onecipher webui open`
    Then a browser opens at https://127.0.0.1:port/register?bootstrap=<token>
    When the browser POSTs /api/auth/bootstrap with the token
    Then the response is 200 and the token is invalidated
    When a second POST /api/auth/bootstrap is attempted with the same token
    Then the response is 401

  @w1-bootstrap-expired
  Scenario: Bootstrap token expires after 5 minutes
    Given a bootstrap_token was written 6 minutes ago
    When the browser POSTs /api/auth/bootstrap with that token
    Then the response is 401

  @w1-webauthn-register
  Scenario: First-time Passkey registration via WebAuthn
    Given a valid bootstrap session
    When the browser calls navigator.credentials.create() with the challenge from /api/auth/webauthn/register/begin
    And POSTs the credential to /api/auth/webauthn/register/finish
    Then the daemon stores the credential in ~/.onecipher/webauthn_passkeys.json (mode 0600)
    And the response sets a session cookie with HttpOnly and SameSite=Strict
    And the daemon does NOT modify ~/.onecipher/passkeys.json (Key-Agent's Ed25519 store)

  @w1-webauthn-login
  Scenario: Subsequent login via WebAuthn assertion
    Given a registered Passkey exists in webauthn_passkeys.json
    And no active session cookie is present
    When the browser calls navigator.credentials.get() with the challenge from /api/auth/webauthn/login/begin
    And POSTs the assertion to /api/auth/webauthn/login/finish
    Then the daemon verifies the assertion
    And the response sets a fresh session cookie

  @w1-webauthn-session-missing
  Scenario: API call without session cookie returns 401
    Given no session cookie is present
    When the browser GETs /api/approvals
    Then the response is 401 with WWW-Authenticate: WebAuthn

  # —— Auto-lock (Improvement H) ——

  @w1-auto-lock-deadline
  Scenario: Auto-lock deadline persists across daemon restart
    Given the session_timeout_secs is 1800
    And the user authenticated at T0 and last_seen was updated at T0+600
    When the daemon restarts at T0+1200
    Then the daemon reads auto_lock_at = T0+2400 from config.toml
    And the daemon arms tokio::time::sleep_until(T0+2400)
    And authenticated API calls between T0+1200 and T0+2400 succeed

  @w1-auto-lock-fire
  Scenario: Auto-lock fires at deadline
    Given auto_lock_at = T0+1800 and now = T0+1800
    When the auto-lock timer fires
    Then the daemon clears all sessions from the in-memory DashMap
    And all session cookies become invalid
    And the WebSocket broadcasts `{ type: "auto_locked" }`
    And auto_lock_at is reset to empty in config.toml

  @w1-auto-lock-warning
  Scenario: Auto-lock warning 60s before deadline
    Given auto_lock_at = T0+1800
    When now = T0+1740
    Then the WebSocket broadcasts `{ type: "auto_lock_warning", data: { in_secs: 60 } }`

  @w1-activity-extends
  Scenario: User activity extends auto_lock_at
    Given auto_lock_at = T0+1800 and now = T0+1700
    When the user makes an authenticated API call
    Then auto_lock_at is updated to T0+3500 (now + 1800)
    And config.toml is rewritten atomically with the new deadline

  # —— R12 revision ——

  @w1-r12-source-isolation
  Scenario: R12a — isolated crates' source has no TcpListener/TcpStream
    When verifying R12a via `rg -n 'TcpListener|TcpStream' crates/oc-keyagent/src/ crates/oc-crypto/src/ crates/oc-policy/src/ crates/oc-session-key/src/`
    Then the command produces no output

  @w1-r12-loopback-only
  Scenario: R12c — daemon listens only on 127.0.0.1
    Given the daemon is running
    When verifying via `lsof -iTCP -sTCP:LISTEN -P -n | grep onecipher`
    Then every listening address starts with 127.0.0.1
    And no 0.0.0.0 or external address appears
