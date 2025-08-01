Feature: age encryption
  As a user
  I want my secrets encrypted with age
  So that they are protected by modern cryptography without GPG dependency

  Scenario: Initialize age identity
    When I initialize age encryption
    Then the file "~/.onecipher/keys/age-identity.txt" should exist with mode 0600
    And the file "~/.onecipher/age-recipient.txt" should exist
    And the recipient file should contain a valid age bech32 public key

  Scenario: Encrypt a secret for multiple recipients
    Given a vault with age identity "age1alice"
    And an additional recipient "age1bob"
    When I create a secret named "shared/notes" of type "note"
    Then the secret file should be an age envelope encrypted for both "age1alice" and "age1bob"

  Scenario: Decrypt with the correct identity
    Given a vault with secret "shared/notes" encrypted for "age1alice"
    When I decrypt the secret with identity "age1alice"
    Then the decryption should succeed

  Scenario: Cannot decrypt without the correct identity
    Given a vault with secret "shared/notes" encrypted for "age1alice"
    And an identity "age1eve" that is not a recipient
    When I attempt to decrypt the secret with identity "age1eve"
    Then the decryption should fail

  Scenario: Re-encrypt all secrets when recipient changes
    Given a vault with 3 secrets encrypted for "age1alice"
    When I add recipient "age1bob" and re-encrypt
    Then all 3 secrets should be encrypted for both "age1alice" and "age1bob"
    And the audit log should contain an "AgeReencrypted" event

  Scenario: Subdirectory-level recipient override
    Given a vault with root recipient "age1alice"
    When I create a secret under "work/" with subdirectory recipient "age1bob"
    Then the secret should be encrypted for "age1bob" but not "age1alice"
