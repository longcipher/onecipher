Feature: Legacy wallet migration
  As a user with existing keystore v3 wallets
  I want to migrate them to the unified age-based vault
  So that I can use the new unified interface

  Scenario: Migrate legacy wallets to age format
    Given a legacy wallet "primary" stored as keystore v3 JSON
    And an initialized age identity
    When I run "migrate legacy-wallets"
    Then a new secret "wallets/primary" should exist with type "mnemonic"
    And the secret should be encrypted with age
    And the mnemonic should be readable after decryption
    And the audit log should contain a "SecretMigrated" event

  Scenario: Legacy wallet remains readable after migration
    Given a migrated wallet "primary"
    When I sign a message with wallet "primary"
    Then the signature should be valid
    And the signing should use the age-based secret

  Scenario: Rollback migration
    Given a migrated wallet "primary"
    When I run "migrate legacy-wallets --rollback"
    Then the age-based secret "wallets/primary" should be removed
    And the legacy keystore v3 JSON should be the primary source

  Scenario: Migrate with dry-run
    Given a legacy wallet "primary"
    When I run "migrate legacy-wallets --dry-run"
    Then no new secrets should be created
    And the output should list "primary" as a migration candidate
