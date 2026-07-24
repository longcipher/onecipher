Feature: Policy Rate Limits
  As a wallet Owner
  I want the Policy Engine to enforce per-minute and per-hour rate limits
  So that an AI Agent cannot flood the signing pipeline

  Background:
    Given an Agent holds an active Session Key with a Policy
    And the Policy rules include rate_limit_per_minute and rate_limit_per_hour

  Scenario: Per-minute rate limit exceeded
    Given the Policy sets rate_limit_per_minute to 5
    And the Agent has already made 5 PayX402 requests within the last 60 seconds
    When the Agent makes a sixth PayX402 request within the same minute
    Then the Policy Engine evaluates the sliding 60-second window counter
    And the response has status DENY and deny_reason "RATE_LIMIT_MINUTE"

  Scenario: Per-hour rate limit exceeded
    Given the Policy sets rate_limit_per_hour to 50
    And the Agent has already made 50 PayX402 requests within the last 3600 seconds
    And the per-minute counter is below its limit
    When the Agent makes a fifty-first PayX402 request within the same hour
    Then the Policy Engine evaluates the sliding 3600-second window counter
    And the response has status DENY and deny_reason "RATE_LIMIT_HOUR"
    And the cooldown timer is started
