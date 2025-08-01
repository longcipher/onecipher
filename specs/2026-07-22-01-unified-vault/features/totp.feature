Feature: TOTP management
  As a user
  I want to store TOTP seeds and generate one-time codes
  So that I can manage two-factor authentication in my vault

  Scenario: Add a TOTP secret from otpauth URI
    Given a vault initialized with age encryption
    When I add a TOTP secret named "discord" with otpauth URI "otpauth://totp/Discord:alice?secret=JBSWY3DPEHPK3PXP&issuer=Discord&algorithm=SHA1&digits=6&period=30"
    Then the secret "discord" should exist with type "totp"
    And the audit log should contain a "SecretWritten" event for "discord"

  Scenario: Generate a TOTP code
    Given a vault with TOTP secret "discord" using secret "JBSWY3DPEHPK3PXP"
    When I generate a TOTP code for "discord"
    Then the result should be a 6-digit numeric string
    And the audit log should contain a "SecretRead" event for "discord"

  Scenario: TOTP code changes over time
    Given a vault with TOTP secret "discord" using secret "JBSWY3DPEHPK3PXP"
    When I generate a TOTP code at time T1
    And I generate a TOTP code at time T2 where T2 = T1 + 30 seconds
    Then the two codes should be different

  Scenario: Add TOTP from raw base32 secret
    Given a vault initialized with age encryption
    When I add a TOTP secret named "aws" with base32 secret "JBSWY3DPEHPK3PXP" and issuer "AWS" and account "alice"
    Then the secret "aws" should exist with type "totp"
    And generating a TOTP code for "aws" should produce a 6-digit string
