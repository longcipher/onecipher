Feature: Policy Amount Limits
  As a wallet Owner
  I want the Policy Engine to enforce per-payment and cumulative spending limits
  So that an AI Agent cannot exceed the budget I allocated

  Background:
    Given an Agent holds an active Session Key with a Policy
    And the Policy rules include max_single_amount_usd, max_daily_amount_usd, and max_monthly_amount_usd

  Scenario: Single payment exceeds max_single_amount_usd
    Given the Policy sets max_single_amount_usd to 0.50
    When the Agent requests a PayX402 for 1.00 USD
    Then the Policy Engine evaluates the single-amount rule
    And the response has status DENY and deny_reason "AMOUNT_EXCEEDED"
    And an audit entry is appended with the requested amount and the limit

  Scenario: Daily cumulative exceeds max_daily_amount_usd
    Given the Policy sets max_daily_amount_usd to 5.00
    And the Agent has already spent 4.50 USD within the rolling 24-hour window
    When the Agent requests a PayX402 for 1.00 USD
    Then the cumulative daily spend becomes 5.50 USD which exceeds the limit
    And the response has status DENY and deny_reason "DAILY_EXCEEDED"
    And an audit entry records both the prior cumulative and the rejected amount

  Scenario: Monthly cumulative exceeds max_monthly_amount_usd
    Given the Policy sets max_monthly_amount_usd to 50.00
    And the Agent has already spent 49.50 USD within the rolling 30-day window
    When the Agent requests a PayX402 for 1.00 USD
    Then the cumulative monthly spend becomes 50.50 USD which exceeds the limit
    And the response has status DENY and deny_reason "MONTHLY_EXCEEDED"
    And an audit entry records both the prior cumulative and the rejected amount
