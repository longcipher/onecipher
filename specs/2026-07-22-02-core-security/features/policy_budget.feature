Feature: Policy Pessimistic Budget
  As a wallet Owner
  I want the Policy Engine to enforce pessimistic per-device budget allocations
  So that multiple offline devices cannot collectively overspend the parent total

  Background:
    Given the main wallet has a parent_total_usd daily budget
    And the Owner has allocated pessimistic budget_allocation entries to one or more device-Agent pairs
    And each device evaluates its budget locally without cross-device synchronization

  Scenario: Pessimistic budget allocation per device
    Given the main wallet parent_total_usd is 10.00
    When the Owner creates a Session Key on device "dev-01" with allocated_usd 3.00
    Then the budget_allocation is stored locally on the device
    And the parent reserve pool becomes 7.00
    And the device may approve payments up to 3.00 USD cumulatively without consulting other devices

  Scenario: Cumulative spend plus current exceeds allocated_usd
    Given a device has allocated_usd of 3.00
    And the device has already spent 2.50 USD within the current allocation period
    When the Agent on that device requests a PayX402 for 1.00 USD
    Then the local cumulative spend becomes 3.50 USD which exceeds the allocation
    And the response has status DENY and deny_reason "BUDGET_EXCEEDED"
    And an audit entry records the prior cumulative, the requested amount, and the allocation

  Scenario: Two devices with hard sub-quotas cannot overspend parent total
    Given device "dev-01" is allocated 6.00 USD out of parent_total 10.00 USD
    And device "dev-02" is allocated 4.00 USD out of parent_total 10.00 USD
    And both devices operate offline from each other
    When both Agents attempt to spend their full allocations simultaneously
    Then the combined cumulative spend across both devices is at most 10.00 USD
    And the parent_total of 10.00 USD is never exceeded because the reserve pool of 0.00 USD is untouched

  Scenario: Budget reclaim on Session Key revocation
    Given a Session Key on device "dev-01" has spent 1.00 USD of its 3.00 USD allocation
    When the Owner revokes the Session Key
    Then the remaining 2.00 USD is returned to the parent reserve pool
    And the local Policy Engine on device "dev-01" denies all subsequent requests for that session_key_id
    And an audit entry of event_type BUDGET_RECLAIM is appended with the reclaimed amount
