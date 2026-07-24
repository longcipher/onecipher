Feature: Policy Consecutive-DENY Human Alert
  As a wallet Owner
  I want to be alerted when an Agent accumulates consecutive DENYs
  So that I can investigate a misbehaving or compromised Agent

  Background:
    Given an Agent holds an active Session Key
    And the alert threshold for consecutive DENYs is 3

  Scenario: 3 consecutive DENYs trigger HUMAN_ALERT
    Given the Agent has accumulated exactly 2 consecutive DENYs for the same session_key_id
    When the Agent triggers a third consecutive DENY
    Then the Key-Agent appends an audit entry of event_type HUMAN_ALERT
    And the UI shows a notification to the human Owner
    And on the Server platform the configured webhook receives a POST with the alert payload
    And the consecutive-DENY counter is reset after the alert is dispatched

  Scenario: Alert payload carries session_key_id, device_id, and deny_reasons
    Given the Agent has triggered 3 consecutive DENYs with reasons RATE_LIMIT_MINUTE, AMOUNT_EXCEEDED, and WHITELIST
    When the alert is dispatched
    Then the alert payload includes the session_key_id
    And the alert payload includes the device_id
    And the alert payload includes the ordered list of deny_reasons
    And the audit entry of event_type HUMAN_ALERT references the same fields
