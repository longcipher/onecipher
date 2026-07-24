Feature: Audit Log CLI
  As a user
  I want to filter the audit log via the CLI
  So that I can investigate specific Agents, time windows, and denial statuses

  Background:
    Given the onecipher CLI is installed and configured to talk to the local daemon
    And the audit log contains a representative history of Agent operations

  Scenario: Filter by agent and 24-hour time window
    Given the audit log contains entries from multiple Agents spanning the last 48 hours
    When the user runs `onecipher audit list --since 24h --agent agent-01`
    Then the CLI prints only entries authored by agent-01
    And every printed entry has a timestamp within the last 24 hours
    And each printed entry shows device_id, seq, timestamp, event_type, session_key_id, status, and amount_usd

  Scenario: Filter by agent, 7-day window, and DENIED status
    Given the audit log contains a mix of ALLOWED and DENIED entries from multiple Agents over multiple days
    When the user runs `onecipher audit list --since 7d --agent agent-02 --status DENIED`
    Then the CLI prints only entries authored by agent-02 within the last 7 days
    And every printed entry has status DENIED
    And every printed entry exposes its deny_reason
    And no entries from other Agents or other time windows appear in the output
