Feature: Policy Cooldown After Denial
  As a wallet Owner
  I want the Policy Engine to enforce a cooldown after any DENY
  So that a misbehaving Agent cannot retry rapidly until it finds a rule that passes

  Background:
    Given an Agent holds an active Session Key with a Policy
    And the Policy rules include cooldown_after_denial_sec

  Scenario: First DENY triggers cooldown timer
    Given the Agent has no prior DENY in the current cooldown window
    When the Agent triggers a PayX402 that is DENIED for any reason
    Then the Policy Engine records the timestamp of the DENY
    And the cooldown timer is started with duration cooldown_after_denial_sec
    And an audit entry is appended recording the DENY reason and the cooldown start

  Scenario: Subsequent request within cooldown is immediately denied
    Given the Agent received a DENY 30 seconds ago
    And the Policy sets cooldown_after_denial_sec to 300
    When the Agent makes another PayX402 request now
    Then the Policy Engine detects the active cooldown before evaluating other rules
    And the response has status DENY and deny_reason "COOLDOWN"
    And no other policy rules are evaluated for this request
    And an audit entry is appended recording the COOLDOWN denial
