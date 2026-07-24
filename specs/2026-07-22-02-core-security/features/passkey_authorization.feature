Feature: Passkey Authorization
  As a wallet Owner
  I want high-risk operations to require Passkey authorization
  So that an AI Agent cannot create session keys or export wallets without my biometric consent

  Background:
    Given the Key-Agent is running with a registered Passkey public key
    And high-risk operations are CreateSessionKey, RevokeSessionKey, and wallet export

  Scenario: Missing PasskeyAuthorization field rejects the request
    Given the Agent initiates a CreateSessionKey request
    When the request reaches the Key-Agent without a PasskeyAuthorization field
    Then the Key-Agent rejects the request before policy evaluation
    And an audit entry of event_type PASSKEY_MISSING is appended
    And no Session Key is created

  Scenario: Fresh 32-byte challenge for each high-risk request
    Given the Agent initiates two consecutive CreateSessionKey requests
    When the Key-Agent returns a challenge for each request
    Then each challenge is exactly 32 bytes of cryptographically random data
    And the two challenges are not equal
    And each challenge is single-use and discarded after the response is verified

  Scenario: Replayed challenge is rejected
    Given the Agent captured a valid PasskeyAuthorization from a previous request
    When the Agent resubmits the same PasskeyAuthorization in a new high-risk request
    Then the Key-Agent rejects it because the challenge has already been consumed
    And the response deny_reason is "PASSKEY_FORGED"
    And an audit entry of event_type PASSKEY_REPLAY is appended

  Scenario: Forged Passkey signature is rejected
    Given a tampered UI process attempts to bypass biometric authentication
    When the UI sends an IPC message containing a boolean field "authorized=true" without a Passkey signature
    Then the Key-Agent ignores the boolean field entirely
    And the Key-Agent denies the high-risk operation
    And an audit entry of event_type PASSKEY_FORGED is appended

  Scenario: Valid Passkey signature authorizes the high-risk operation
    Given the Key-Agent holds the Passkey public key in its own protected storage
    When the UI returns a PasskeyAuthorization with challenge, signature, and credential_id
    Then the Key-Agent verifies the signature against the stored public key
    And the Key-Agent verifies the challenge matches the one it generated
    And the Key-Agent verifies the credential_id is the registered credential
    And only after all three verifications pass is the high-risk operation executed
    And no boolean from the UI is consulted
