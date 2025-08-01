Feature: Unified vault operations
  As a user
  I want to manage wallets, passwords, and TOTP in a single unified vault
  So that I have one consistent interface for all sensitive data

  Scenario: Wallet and password coexist
    Given a vault with a wallet secret "wallets/primary" of type "mnemonic"
    And a password secret "github/personal" of type "password"
    When I list all secrets
    Then the result should contain both secrets
    And each should have its correct item_type

  Scenario: Sign message using vault-stored mnemonic
    Given a vault with wallet "wallets/primary" of type "mnemonic"
    When I sign a message "hello" using wallet "primary"
    Then the signature should be valid for the derived address
    And the audit log should contain both "SecretRead" and "SignUserOp" events

  Scenario: Policy denies reading a secret
    Given a vault with secret "admin/root" of type "password"
    And a policy that denies reading "admin/*" for the current agent
    When I attempt to read the secret "admin/root"
    Then the operation should be denied
    And the audit log should contain a "PolicyLookupFailed" event

  Scenario: CLI JSON output
    Given a vault with multiple secrets
    When I run "secret list --json"
    Then the output should be valid JSON
    And each entry should have "id", "name", "item_type", "metadata" fields

  Scenario: TUI and CLI produce same results
    Given a vault with secrets
    When I list secrets via CLI
    And I list secrets via TUI
    Then both should show the same set of secrets

  Scenario: Index file stays in sync
    Given a vault with 3 secrets
    When I create a new secret
    Then the index file should contain 4 entries
    And each index entry should have a valid Ed25519 signature
