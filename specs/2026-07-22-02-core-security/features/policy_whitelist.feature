Feature: Policy Whitelists
  As a wallet Owner
  I want the Policy Engine to enforce asset, chain, and contract whitelists
  So that an AI Agent cannot pay unapproved assets or interact with unapproved chains

  Background:
    Given an Agent holds an active Session Key with a Policy
    And the Policy rules include asset_whitelist, chain_whitelist, and contract_whitelist

  Scenario: Asset not in asset_whitelist
    Given the Policy asset_whitelist contains only "USDC"
    When the Agent requests a PayX402 paying in "USDT"
    Then the Policy Engine evaluates the asset_whitelist rule
    And the response has status DENY and deny_reason "WHITELIST"
    And an audit entry records the requested asset and the whitelist

  Scenario: Chain not in chain_whitelist
    Given the Policy chain_whitelist contains "eip155:8453" and "eip155:1"
    When the Agent requests a PayX402 on chain "eip155:137"
    Then the Policy Engine evaluates the chain_whitelist rule
    And the response has status DENY and deny_reason "WHITELIST"
    And an audit entry records the requested chain and the whitelist

  Scenario: Contract recipient not in contract_whitelist
    Given the Policy contract_whitelist contains the x402 settler contract on "eip155:8453"
    When the Agent requests a PayX402 whose recipient is an unlisted contract on "eip155:8453"
    Then the Policy Engine evaluates the contract_whitelist rule
    And the response has status DENY and deny_reason "WHITELIST"
    And an audit entry records the requested recipient and the whitelist
