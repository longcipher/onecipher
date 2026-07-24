Feature: Session Key Lifecycle
  As an AI Agent
  I want to request and use ephemeral Session Keys
  So that I can sign transactions without ever touching the Owner key

  Background:
    Given the OneCipher daemon is running with Key-Agent and Network-Agent
    And the main wallet is unlocked and its Owner key is in Key-Agent memory only
    And an AI Agent has been provisioned with a WalletConnect v2 client
    And the human Owner has a registered Passkey credential

  Scenario: CreateSessionKey with Passkey authorization
    Given a Policy is drafted with max_single_amount_usd 10.0
    When the Agent calls CreateSessionKey with the Policy and a PasskeyAuthorization
    Then the Key-Agent verifies the Passkey signature locally against a fresh 32-byte challenge
    And the Key-Agent derives an ephemeral Session Key pair
    And the SessionKeyProvider registers the Session Key permissions on-chain
    And the Agent receives a session_key_id "oc_sk_active"
    And an audit entry of event_type CREATE_SESSION_KEY is appended

  Scenario: RevokeSessionKey by Owner with Passkey
    Given an active Session Key with session_key_id "oc_sk_active"
    When the Owner calls RevokeSessionKey authenticated by Passkey
    Then the SessionKeyProvider submits an on-chain revoke transaction signed by the Owner key
    And the Policy Engine marks the session_key_id as revoked locally
    And the remaining budget is returned to the parent wallet reserve pool
    And an audit entry of event_type REVOKE_SESSION_KEY is appended

  Scenario: Expired Session Key is denied before any other policy rule
    Given an active Session Key whose expiry_unix is in the past
    When the Agent calls PayX402 using that session_key_id
    Then the Policy Engine evaluates the expiry_unix before any other rule
    And the response has status DENY and deny_reason "EXPIRED"
    And an audit entry is appended with status DENIED and reason EXPIRED

  Scenario: WalletConnect v2 method surface never exposes Owner key
    Given an Agent has been issued a Session Key
    When the Agent lists available WalletConnect v2 methods
    Then no method returns the Owner key, BIP-32 root, or mnemonic
    And all signing operations performed by the Agent use only the Session Key
    And the audit log shows every Owner-key signature is co-signed by a PasskeyAuthorization

  Scenario: EVM Session Key via ERC-7579
    Given the main wallet uses an ERC-7579 modular Smart Contract Account
    When the Owner creates an EVM Session Key
    Then the SessionKeyProvider calls grant on the EVM SessionKeyProvider
    And the SCA contract stores a MerkleRoot committing to the Session Key policy via ERC-7715
    And a GrantReceipt with the on-chain transaction hash is returned
    And the SCA validates every subsequent UserOp against the registered ERC-7715 permissions

  Scenario: Solana Session Key via Session Tokens program
    Given the main wallet has a Solana account on chain solana:mainnet
    When the Owner creates a Solana Session Key
    Then the SessionKeyProvider calls grant on the Solana SessionKeyProvider
    And the Solana Session Tokens program records the delegated permissions on-chain
    And a GrantReceipt referencing the Session Tokens account is returned
    And subsequent Solana transactions signed by the Session Key are validated by the Session Tokens program
