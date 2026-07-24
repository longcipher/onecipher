Feature: x402 DENY Reason Enumeration
  As an integrator
  I want PayX402Response to carry a structured deny_reason on every DENY
  So that the UI can display actionable feedback to the human Owner

  Background:
    Given the Agent holds an active Session Key
    And the Agent issues PayX402 requests that may be denied by the Policy Engine

  Scenario: PayX402Response.deny_reason populated on DENY
    Given a PayX402 request that violates a Policy rule
    When the Policy Engine denies the request
    Then the PayX402Response has status DENY
    And the deny_reason field is a non-empty string identifying the rule that was violated
    And the error field is populated with a human-readable description
    And an audit entry records the same deny_reason

  Scenario: deny_reason enumerates all supported rejection causes
    Given the Agent triggers one DENY for each of the supported rejection causes
    When the Agent inspects the corresponding PayX402Response messages
    Then the observed deny_reason values include each of the following exactly once
      | deny_reason       |
      | RATE_LIMIT_MINUTE |
      | RATE_LIMIT_HOUR   |
      | BUDGET_EXCEEDED   |
      | WHITELIST         |
      | AMOUNT_EXCEEDED   |
      | EXPIRED           |
      | COOLDOWN          |
      | POLICY_INVALID    |
      | PASSKEY_FORGED    |
    And no other deny_reason string is observed
