Feature: Encrypted Backup .ocbk
  As a wallet Owner
  I want to export and import encrypted backups in the .ocbk format
  So that I can recover my wallet on a new device without exposing secrets in plaintext

  Background:
    Given the daemon has a wallet, policy files, and an audit log loaded
    And the .ocbk format uses Argon2id key derivation and XChaCha20-Poly1305 AEAD encryption

  Scenario: Export encrypted backup to .ocbk file
    Given the user supplies a strong passphrase
    When the user runs the export command
    Then a .ocbk file is written containing the magic header, version, Argon2id parameters, salt, nonce, ciphertext, and Poly1305 mac
    And the Argon2id parameters are m=64MB, t=3, p=4
    And the ciphertext decrypts only with a key derived from the supplied passphrase and salt
    And the file does not contain the passphrase or the derived key in plaintext

  Scenario: Import .ocbk with correct passphrase succeeds
    Given a previously exported .ocbk file
    When the user runs the import command with the same passphrase used during export
    Then the Poly1305 mac verification succeeds
    And the wallet, policies, and audit log are restored into the local daemon
    And the audit log preserves the append-only history with original device_id and seq values

  Scenario: Wrong passphrase triggers exponential backoff
    Given a previously exported .ocbk file
    When the user repeatedly provides incorrect passphrases
    Then the Poly1305 mac verification fails for each attempt
    And the daemon enforces an exponentially increasing backoff between allowed attempts
    And each failed attempt is recorded in an audit entry of event_type BACKUP_ATTEMPT_FAILED

  Scenario: 10 cumulative failures lock the file
    Given a previously exported .ocbk file with 9 cumulative failed attempts
    When the user provides a 10th incorrect passphrase
    Then the .ocbk file is locked
    And further import attempts are rejected without checking the passphrase
    And an audit entry of event_type BACKUP_LOCKED is appended
    And unlocking requires an explicit reset action by the Owner, authenticated by Passkey or KMS
