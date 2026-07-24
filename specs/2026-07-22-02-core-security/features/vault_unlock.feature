Feature: Vault Unlock
  As a wallet Owner
  I want the vault unlocked only via Passkey challenge-response
  So that the decrypted mnemonic never touches disk and is held only in hardened memory

  Background:
    Given the encrypted vault file is stored on disk under the OneCipher data directory
    And the Owner has a registered Passkey credential with the Key-Agent

  Scenario: Unlock wallet via Passkey challenge-response
    Given the Key-Agent is started with the vault file locked
    When the Owner initiates an unlock via the UI or CLI
    Then the Key-Agent generates a fresh 32-byte challenge
    And the Owner signs the challenge with the Passkey private key
    And the Key-Agent verifies the Passkey signature locally
    And on verification the Key-Agent decrypts the vault into HardenedBytes
    And the decrypted material is wrapped in SecretBox and held only in Key-Agent memory
    And no plaintext wallet content is written back to disk

  Scenario: Vault file permissions enforced
    Given the OneCipher data directory and vault file are created on a Unix-like system
    When the file permissions are inspected
    Then the data directory has mode 700 (owner read/write/execute only)
    And the vault file has mode 600 (owner read/write only)
    And the owner of both is the daemon's OS user

  Scenario: Encrypted wallet file decrypts to HardenedBytes
    Given the vault file is encrypted with the wallet encryption key
    When the Key-Agent decrypts the vault after a successful Passkey challenge-response
    Then the decrypted bytes are stored in a HardenedBytes container
    And the underlying memory page is mlock'd and marked MADV_DONTDUMP
    And the decrypted material is zeroized and munlock'd as soon as signing completes
    And no copy of the decrypted material escapes the Key-Agent process boundary
