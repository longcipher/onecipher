Feature: API Surface and WebSocket Protocol
  As a wallet Owner or integrator
  I want the Web UI's HTTP API and WebSocket protocol to be stable and well-defined
  So that the daemon's surface is auditable and the front-end can rely on it

  Background:
    Given the daemon is running with `[webui] enabled = true`
    And the caller is authenticated via a valid session cookie unless noted

  # —— Health ——

  @w1-health
  Scenario: GET /api/health works without authentication
    When the caller GETs /api/health without a session cookie
    Then the response is 200 with body { ok: true, version: "<daemon_version>" }

  # —— Wallets ——

  @w4-wallets-list
  Scenario: GET /api/wallets returns wallet summaries
    When the caller GETs /api/wallets
    Then the response is 200 with a Vec<WalletSummary>
    And each summary contains id, name, chain_type, and created_at

  @w4-wallets-create
  Scenario: POST /api/wallets creates a wallet via Key-Agent
    Given the request body is { type: "create", name: "main", chain_type: "evm" }
    When the caller POSTs /api/wallets
    Then the daemon forwards the create request to Key-Agent via UDS
    And the response is 201 with the new WalletId

  @w4-wallets-send
  Scenario: POST /api/wallets/:id/send signs and broadcasts
    Given wallet "w1" exists and is unlocked
    And the request body is { to: "0x...", value: "1000000000000000", data: "0x", chain_id: "eip155:1" }
    When the caller POSTs /api/wallets/w1/send
    Then the daemon constructs a SignTransactionRequest
    And forwards it to Key-Agent via UDS
    And the response is 200 with the TxHash

  # —— WC sessions ——

  @w4-wc-sessions-list
  Scenario: GET /api/wc/sessions lists active WC v2 sessions
    When the caller GETs /api/wc/sessions
    Then the response is 200 with a Vec<WcSession>
    And each session contains topic, dapp_name, dapp_origin, chain_ids, created_at

  @w4-wc-pair
  Scenario: POST /api/wc/pair injects a pairing URI via WcServerHandle
    Given the request body is { uri: "wc:..." }
    When the caller POSTs /api/wc/pair
    Then the daemon calls WcServerHandle::pair(uri)
    And the response is 200 on success

  @w4-wc-pair-generate
  Scenario: POST /api/wc/pair/generate returns a new pairing URI
    Given the request body is { ttl_secs: 600 }
    When the caller POSTs /api/wc/pair/generate
    Then the daemon calls WcServerHandle::generate_pairing(600)
    And the response is 200 with { uri: "wc:..." }

  # —— Audit ——

  @w4-audit-list
  Scenario: GET /api/audit returns paginated audit entries
    When the caller GETs /api/audit?limit=50&offset=0
    Then the response is 200 with a Vec<AuditEntry>
    And each entry contains timestamp, device_id, seq, action, wallet_id, chain_id

  # —— Settings ——

  @w1-settings-get
  Scenario: GET /api/settings returns current webui config
    When the caller GETs /api/settings
    Then the response is 200 with { enabled, approval_mode, approval_timeout_secs, listen, session_timeout_secs, auto_lock_at }

  @w1-settings-patch-approval-mode
  Scenario: PATCH /api/settings toggles approval_mode atomically
    Given the request body is { approval_mode: true }
    When the caller PATCHes /api/settings
    Then the daemon updates the Arc<AtomicBool> for approval_mode
    And config.toml is rewritten atomically with approval_mode = true
    And the response is 200 with the updated Settings
    And subsequent signing requests surface in the Web UI

  # —— Policy ——

  @w4-policy-rules-list
  Scenario: GET /api/policy/rules returns rule metadata
    When the caller GETs /api/policy/rules
    Then the response is 200 with a Vec<Rule>
    And each rule contains id, name, description, enabled, level

  @w4-policy-rules-patch
  Scenario: PATCH /api/policy/rules/:id toggles a rule
    Given rule "rate_limit" exists with enabled = false
    When the caller PATCHes /api/policy/rules/rate_limit with { enabled: true }
    Then the daemon updates the rule in the policy store
    And the WebSocket broadcasts { type: "policy_changed", data: { rule_id: "rate_limit", enabled: true } }

  # —— Session keys ——

  @w4-session-keys-list
  Scenario: GET /api/session-keys returns active session keys
    When the caller GETs /api/session-keys
    Then the response is 200 with a Vec<SessionKey>
    And each session key contains id, wallet_id, chain_id, scope, expires_at

  @w4-session-keys-create
  Scenario: POST /api/session-keys creates a new session key
    Given the request body is { wallet_id: "w1", chain_id: "eip155:1", scope: "0x...", ttl: 3600 }
    When the caller POSTs /api/session-keys
    Then the daemon creates the session key via oc-session-key
    And the response is 201 with the new SessionKey

  # —— Secrets ——

  @w4-secrets-list
  Scenario: GET /api/secrets returns secret metadata only
    When the caller GETs /api/secrets
    Then the response is 200 with a Vec<SecretMeta>
    And no entry contains the secret value

  @w4-secrets-get-second-webauthn
  Scenario: GET /api/secrets/:id requires a second WebAuthn assertion
    Given a secret with id "api-key-1" exists
    When the caller GETs /api/secrets/api-key-1 without a fresh WebAuthn assertion
    Then the response is 401 with WWW-Authenticate: WebAuthn step-up
    When the caller provides a fresh assertion in the X-WebAuthn-Assertion header
    Then the response is 200 with the secret value

  # —— WebSocket protocol ——

  @w1-ws-pending-approval
  Scenario: WebSocket pushes pending_approval on new request
    Given a WebSocket /ws connection is open and authenticated
    When a dApp sends a signing request via WC v2
    Then the WebSocket receives `{ type: "pending_approval", data: PendingApproval }`
    And the data contains request_id, method, risk, risk_reasons, simulation

  @w1-ws-approval-resolved
  Scenario: WebSocket pushes approval_resolved on decision
    Given a WebSocket /ws connection is open and PendingApproval "abc-123" exists
    When the user POSTs /api/approvals/abc-123/decision with Approve
    Then the WebSocket receives `{ type: "approval_resolved", data: { id: "abc-123", decision: "approved" } }`

  @w1-ws-unauthenticated
  Scenario: WebSocket rejects unauthenticated connections
    When a client opens a WebSocket /ws without a session cookie
    Then the upgrade completes but the server immediately closes with code 4401
