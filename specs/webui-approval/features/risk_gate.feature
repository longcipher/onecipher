Feature: Risk Grading and Sign-Button Gating
  As a wallet Owner
  I want the Web UI to grade signing requests by risk and gate the Sign button accordingly
  So that I cannot reflexively sign dangerous transactions

  Background:
    Given the daemon is running with `[webui] approval_mode = true`
    And a browser tab is authenticated via WebAuthn Passkey

  # —— Risk level determination ——

  @w2-policy-deny-forbidden
  Scenario: Policy Deny → Forbidden, never enters queue
    Given the Policy Engine returns Decision::Deny with reason "AMOUNT_EXCEEDED"
    When a dApp sends `eth_sendTransaction` via WalletConnect v2
    Then the dApp immediately receives a JSON-RPC error with code -32001 and "policy denied: AMOUNT_EXCEEDED"
    And no PendingApproval is created
    And no `pending` event is appended to approval_queue.jsonl

  @w2-policy-warn
  Scenario: Policy Warn → Warning level, must be acknowledged before Sign
    Given the Policy Engine returns Decision::Warn with reason LargeApproval { token: "USDC", amount: 340282366920938463463374607431768211455 }
    When a dApp sends `eth_sendTransaction` via WalletConnect v2
    Then the PendingApproval has risk_level = Warning
    And the risk_reasons list contains an entry with code "policy_warn_large_approval"
    And the Sign button is rendered Disabled
    And the RiskCard for "policy_warn_large_approval" is shown

  @w2-policy-warn-ack
  Scenario: Acknowledging all Warning reasons unlocks Sign (first click → Armed)
    Given a PendingApproval with risk_level = Warning and one unacknowledged RiskReason
    When the user clicks "Acknowledge" on the RiskCard
    Then the RiskReason is removed from the unprocessed list
    And the Sign button transitions from Disabled to enabled
    When the user clicks Sign
    Then the button transitions to Armed state, revealing "Confirm Sign" and "Cancel"

  @w2-danger-countdown
  Scenario: Danger risk → Sign disabled 5 seconds with countdown
    Given a PendingApproval with risk_level = Danger
    When the approval detail view renders
    Then the Sign button is Disabled and shows "Wait 5s before signing (Danger)"
    After 1 second the text reads "Wait 4s before signing (Danger)"
    After 5 seconds the Sign button becomes enabled for first-click

  @w2-sim-revert-danger
  Scenario: evm2 simulation revert → risk escalated to Danger
    Given a dApp sends `eth_sendTransaction` with calldata that will revert
    When the daemon runs evm2 simulation
    Then TxSimulation.success = false
    And TxSimulation.error contains the revert message
    And a RiskReason with code "sim_revert" and level Danger is added to risk_reasons
    And the PendingApproval risk_level is Danger

  @w2-forbidden-hides-sign
  Scenario: Forbidden risk → Sign button hidden, only Reject shown
    Given a PendingApproval with risk_level = Forbidden
    When the approval detail view renders
    Then no Sign button is rendered
    And only a Reject button (red background) is shown

  # —— Two-step confirm ——

  @w2-two-step-cancel
  Scenario: Cancel from Armed state returns to Disabled
    Given a PendingApproval and the user has clicked Sign (state = Armed)
    When the user clicks Cancel
    Then the state returns to Disabled
    And no POST /api/approvals/:id/decision is sent
    And the PendingApproval remains in the queue

  @w2-two-step-confirm
  Scenario: Confirm Sign from Armed state submits the decision
    Given a PendingApproval and state = Armed
    When the user clicks "Confirm Sign"
    Then the state transitions to Submitting
    And the browser POSTs /api/approvals/:id/decision with Approve
    And the Sign button shows "Signing..." and is disabled

  # —— Simulation result rendering (W3, but scenarios live here for traceability) ——

  @w3-sim-balance-change
  Scenario: evm2 success → balance_change rendered in SimPanel
    Given a dApp sends `eth_sendTransaction` swapping 100 USDC for ~99.5 WETH on Uniswap V2
    When the daemon runs evm2 simulation
    Then TxSimulation.success = true
    And balance_change contains TokenDelta { token: "USDC", direction: Send, amount: "100" }
    And balance_change contains TokenDelta { token: "WETH", direction: Receive, amount: "99.5" }
    And the SimPanel renders both deltas in human-readable form

  @w3-sim-decoded-action
  Scenario: ABI decoding produces human-readable action
    Given a dApp calls `swapExactTokensForTokens` on a known Uniswap V2 router
    When the daemon runs ABI decoding against the local abi_cache
    Then DecodedAction.contract_name = "UniswapV2Router02"
    And DecodedAction.function_name = "swapExactTokensForTokens"
    And DecodedAction.human_readable = "Swap 100 USDC for ~99.5 WETH on Uniswap"

  @w3-sim-failure-degrade
  Scenario: Simulation failure degrades to raw hex display
    Given a dApp sends `eth_sendTransaction` with calldata for an unknown contract
    When the daemon runs evm2 simulation and it fails
    Then PendingApproval.simulation = None
    And the SimPanel shows the raw calldata hex
    And a "Decoding failed (offline)" notice is displayed
    And the Sign button is NOT blocked by simulation state

  @w3-sim-gas-used
  Scenario: Gas used is displayed
    Given a PendingApproval with TxSimulation.gas_used = 142500
    When the SimPanel renders
    Then the gas estimate "142500 gas" is displayed

  # —— Risk-level color tokens ——

  @w2-color-mapping
  Scenario: Risk-level color tokens match semantic aliases
    Given PendingApprovals exist with risk levels Safe, Warning, Danger, Forbidden
    When the approval list renders
    Then the Safe card border uses var(--oc-color-success)
    And the Warning card border uses var(--oc-color-warning)
    And the Danger card border uses var(--oc-color-danger)
    And the Forbidden card border uses var(--oc-color-danger) with darker shade
