Feature: Append-Only Audit Log
  As a security auditor
  I want every Key-Agent operation recorded in an append-only audit log
  So that I can reconstruct the full history of Agent actions after an incident

  Background:
    Given the Key-Agent maintains a local encrypted audit log
    And each device holds a stable device_id and an Ed25519 device signing key
    And the Key-Agent processes a representative workload of signing and payment operations

  Scenario: Every operation appends exactly one audit entry
    When each operation completes
    Then exactly one audit entry is appended for each operation regardless of ALLOW or DENY outcome
    And the audit log contains entries for CREATE_SESSION_KEY, REVOKE_SESSION_KEY, PayX402, PayMPP, SignUserOp, and PASSKEY_FORGED events

  Scenario: Audit entry fields
    Given an audit entry is appended for a PayX402 operation
    When the entry is inspected
    Then it contains device_id matching the writing device
    And it contains a monotonically increasing seq for that device
    And it contains an RFC 3339 timestamp
    And it contains an event_type field
    And it contains the session_key_id of the operation
    And it contains a payload with amount_usd, chain, tx_hash, and status
    And it contains prev_hash equal to the SHA-256 hash of the previous entry
    And it contains device_sig equal to an Ed25519 signature over the entry by the device signing key

  Scenario: Append-only guarantee — existing entries unchanged
    Given an audit log with N existing entries
    When a new operation is recorded
    Then the new entry is appended at position N+1
    And the existing N entries remain byte-for-byte unchanged
    And no API exposes a delete or update operation on existing entries

  Scenario: Merge overlapping fragments from the same device
    Given two audit log fragments from the same device that overlap
    When the fragments are merged
    Then entries with the same (device_id, seq) pair are deduplicated
    And the merged log contains exactly one entry per (device_id, seq) pair
    And entries are ordered by timestamp across devices

  Scenario: Chain hash verification detects tampering
    Given an audit log with a sequence of entries linked by prev_hash
    When a single field of one historical entry is modified
    Then re-computing the chain of SHA-256 hashes from the first entry fails to match at the modified entry
    And the device_sig verification of the modified entry fails
    And the tampering is reported as a chain-verification error

  Scenario: Conflicting state resolved by latest REVOKE
    Given the audit log contains an ALLOWED PayX402 for a session_key_id
    And the same session_key_id has a later REVOKE_SESSION_KEY entry
    When the log is reconciled
    Then the session_key_id is considered revoked as of the REVOKE timestamp
    And any ALLOWED operations after the REVOKE are flagged as conflicting
    And the resolved state of the session_key_id is revoked
