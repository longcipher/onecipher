//! Integration tests for the oc-keyagent audit log (T14).
//!
//! Per R39 / R40 / R75 / AD-03. Covers:
//!  - single + multiple append with chain integrity
//!  - tamper detection (field mutation + signature mutation)
//!  - append-only API invariant (no `delete` / `update` / `remove` / `edit`)
//!  - merge dedup by `(device_id, seq)`
//!  - filesystem mode 0600 on the log file
//!  - proptest on chain-hash tamper detection (mutate one entry → verify_chain fails)
//!
//! Per R56 / R77: synchronous std only, NO tokio / async.

#![cfg(unix)]

use std::{fs, os::unix::fs::PermissionsExt};

use ed25519_dalek::{Signature, SigningKey, Verifier};
use oc_keyagent::audit::{AuditEntry, AuditError, AuditLog, EventType};
use proptest::prelude::*;
use serde_json::json;
use sha2::{Digest, Sha256};

/// Generate a fresh Ed25519 signing key using `OsRng`.
fn fresh_key() -> SigningKey {
    SigningKey::generate(&mut rand::rng())
}

/// Recompute the canonical bytes of an entry (entry serialized with
/// `device_sig = ""`, compact JSON). Mirrors the private `canonical_bytes`
/// in `audit.rs` so tests can independently verify chain hashes + sigs.
fn canonical_bytes(entry: &AuditEntry) -> Vec<u8> {
    let mut copy = entry.clone();
    copy.device_sig = String::new();
    serde_json::to_vec(&copy).unwrap()
}

/// SHA-256 hex of an entry's canonical bytes (mirrors `hash_entry`).
fn hash_entry(entry: &AuditEntry) -> String {
    let mut hasher = Sha256::new();
    hasher.update(canonical_bytes(entry));
    hex::encode(hasher.finalize())
}

/// Read all non-empty lines from a JSONL file as `AuditEntry`s.
fn read_entries(path: &std::path::Path) -> Vec<AuditEntry> {
    let content = fs::read_to_string(path).unwrap();
    content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str::<AuditEntry>(l).unwrap())
        .collect()
}

#[test]
fn test_append_single_entry() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("audit.jsonl");
    let device_key = fresh_key();

    let mut log = AuditLog::open(&path, "dev-1", device_key).unwrap();
    let seq =
        log.append(EventType::CreateSessionKey, Some("sk-1".into()), json!({"v": 1})).unwrap();
    assert_eq!(seq, 1, "first append must be seq 1");

    // File has exactly one line.
    let content = fs::read_to_string(&path).unwrap();
    assert_eq!(content.lines().filter(|l| !l.trim().is_empty()).count(), 1);

    // verify_chain passes.
    log.verify_chain().expect("chain must verify after single append");

    // Round-trip the entry: device_sig is non-empty, prev_hash is empty.
    let entries = read_entries(&path);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].seq, 1);
    assert_eq!(entries[0].device_id, "dev-1");
    assert_eq!(entries[0].prev_hash, "", "first entry's prev_hash must be empty");
    assert!(!entries[0].device_sig.is_empty(), "device_sig must be populated");
}

#[test]
fn test_append_multiple_entries_chain() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("audit.jsonl");
    let device_key = fresh_key();

    let mut log = AuditLog::open(&path, "dev-chain", device_key.clone()).unwrap();
    for i in 0..5u64 {
        let et = match i % 3 {
            0 => EventType::CreateSessionKey,
            1 => EventType::PayX402,
            _ => EventType::SignUserOp,
        };
        let seq = log.append(et, Some(format!("sk-{}", i)), json!({"i": i})).unwrap();
        assert_eq!(seq, i + 1, "seq must increment");
    }

    // File has exactly 5 lines.
    let content = fs::read_to_string(&path).unwrap();
    assert_eq!(content.lines().filter(|l| !l.trim().is_empty()).count(), 5);

    // verify_chain passes.
    log.verify_chain().expect("chain must verify after 5 appends");

    // Independently verify the prev_hash chain.
    let entries = read_entries(&path);
    assert_eq!(entries.len(), 5);
    let mut prev_hash = String::new();
    for (i, e) in entries.iter().enumerate() {
        assert_eq!(
            e.prev_hash,
            prev_hash,
            "entry {} prev_hash must equal hash of entry {}'s canonical bytes",
            i,
            i.saturating_sub(1)
        );
        // Recompute this entry's hash for the next iteration.
        prev_hash = hash_entry(e);
    }

    // Verify each entry's signature against the device public key.
    let vk = device_key.verifying_key();
    for e in &entries {
        let canonical = canonical_bytes(e);
        let sig_bytes = hex::decode(&e.device_sig).unwrap();
        assert_eq!(sig_bytes.len(), 64);
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&sig_bytes);
        let sig = Signature::from_bytes(&arr);
        vk.verify(&canonical, &sig).expect("signature must verify");
    }
}

#[test]
fn test_verify_chain_detects_tampering() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("audit.jsonl");
    let device_key = fresh_key();

    let mut log = AuditLog::open(&path, "dev-tamper", device_key).unwrap();
    for i in 0..3u64 {
        log.append(EventType::SignUserOp, None, json!({"i": i})).unwrap();
    }
    log.verify_chain().expect("chain must verify before tampering");

    // Tamper with line 2's payload field.
    let content = fs::read_to_string(&path).unwrap();
    let mut lines: Vec<String> =
        content.lines().filter(|l| !l.trim().is_empty()).map(str::to_string).collect();
    assert_eq!(lines.len(), 3);

    let mut entry: serde_json::Value = serde_json::from_str(&lines[1]).unwrap();
    entry["payload"] = json!({"tampered": true});
    lines[1] = serde_json::to_string(&entry).unwrap();

    let mut new_content = String::new();
    for l in &lines {
        new_content.push_str(l);
        new_content.push('\n');
    }
    fs::write(&path, new_content).unwrap();

    // verify_chain must now fail.
    let err = log.verify_chain().expect_err("verify_chain must fail after tampering");
    match err {
        AuditError::Tampered(seq) => assert_eq!(seq, 2, "tampering detected at seq 2"),
        AuditError::ChainHashMismatch(seq) => {
            // Could also be a chain mismatch if the canonical bytes change
            // happens to be picked up at entry 3's prev_hash check.
            assert!(seq == 2 || seq == 3, "unexpected seq: {}", seq);
        }
        other => panic!("expected Tampered or ChainHashMismatch, got {:?}", other),
    }
}

#[test]
fn test_verify_chain_detects_signature_tampering() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("audit.jsonl");
    let device_key = fresh_key();

    let mut log = AuditLog::open(&path, "dev-sig", device_key).unwrap();
    for i in 0..3u64 {
        log.append(EventType::SignUserOp, None, json!({"i": i})).unwrap();
    }
    log.verify_chain().expect("chain must verify before tampering");

    // Tamper with line 2's device_sig field (replace with a different valid
    // hex string of length 128 = 64 bytes — this changes the signature but
    // leaves the canonical bytes unchanged, so we hit the signature check).
    let content = fs::read_to_string(&path).unwrap();
    let mut lines: Vec<String> =
        content.lines().filter(|l| !l.trim().is_empty()).map(str::to_string).collect();

    let mut entry: serde_json::Value = serde_json::from_str(&lines[1]).unwrap();
    // Use all-zeros (64 bytes of zeros) — definitely not a valid signature
    // for the canonical bytes.
    entry["device_sig"] = json!("00".repeat(64));
    lines[1] = serde_json::to_string(&entry).unwrap();

    let mut new_content = String::new();
    for l in &lines {
        new_content.push_str(l);
        new_content.push('\n');
    }
    fs::write(&path, new_content).unwrap();

    let err = log.verify_chain().expect_err("verify_chain must fail after sig tampering");
    match err {
        AuditError::Tampered(seq) => assert_eq!(seq, 2, "sig tampering detected at seq 2"),
        other => panic!("expected Tampered(2), got {:?}", other),
    }
}

#[test]
fn test_no_delete_or_update_api() {
    // R40 / AD-03: the audit log is strictly append-only. No public
    // `delete` / `update` / `remove` / `edit` methods may exist on
    // `AuditLog`. Corrections are appended as new entries, never in-place
    // rewrites.
    //
    // This test reads the audit.rs source at compile time and asserts that
    // none of the forbidden method names appear as `pub fn <name>`.
    let src = include_str!("../src/audit.rs");
    assert!(
        !src.contains("pub fn delete"),
        "AuditLog must not expose a `delete` method (R40/AD-03 append-only)"
    );
    assert!(
        !src.contains("pub fn update"),
        "AuditLog must not expose an `update` method (R40/AD-03 append-only)"
    );
    assert!(
        !src.contains("pub fn remove"),
        "AuditLog must not expose a `remove` method (R40/AD-03 append-only)"
    );
    assert!(
        !src.contains("pub fn edit"),
        "AuditLog must not expose an `edit` method (R40/AD-03 append-only)"
    );
}

#[test]
fn test_merge_dedup() {
    // Two fragments with overlapping (device_id, seq) entries.
    // Fragment A: device_id="dev-merge", seqs 1, 2, 3
    // Fragment B: device_id="dev-merge", seqs 1, 2, 3, 4, 5 (overlap on 1, 2, 3)
    // Merged output should have exactly 5 entries (deduped to one per (dev, seq)).
    let tmp = tempfile::tempdir().unwrap();
    let frag_a = tmp.path().join("a.jsonl");
    let frag_b = tmp.path().join("b.jsonl");
    let merged = tmp.path().join("merged.jsonl");
    let device_key = fresh_key();

    // Fragment A: 3 entries.
    let mut log_a = AuditLog::open(&frag_a, "dev-merge", device_key.clone()).unwrap();
    for i in 0..3u64 {
        log_a.append(EventType::CreateSessionKey, None, json!({"from": "A", "i": i})).unwrap();
    }

    // Fragment B: 5 entries (overlapping on seqs 1, 2, 3).
    let mut log_b = AuditLog::open(&frag_b, "dev-merge", device_key.clone()).unwrap();
    for i in 0..5u64 {
        log_b.append(EventType::SignUserOp, None, json!({"from": "B", "i": i})).unwrap();
    }

    // Sanity: each fragment has the expected line count.
    assert_eq!(read_entries(&frag_a).len(), 3);
    assert_eq!(read_entries(&frag_b).len(), 5);

    // Merge.
    let merged_log =
        AuditLog::merge(vec![frag_a, frag_b], &merged, &device_key).expect("merge must succeed");

    // Output should have 5 unique (device_id, seq) entries (1, 2, 3, 4, 5).
    let merged_entries = read_entries(&merged);
    assert_eq!(merged_entries.len(), 5, "merge must dedupe to one entry per (device_id, seq)");

    // Each seq 1..=5 appears exactly once.
    let mut seqs: Vec<u64> = merged_entries.iter().map(|e| e.seq).collect();
    seqs.sort_unstable();
    assert_eq!(seqs, vec![1, 2, 3, 4, 5]);

    // First-seen wins: seqs 1, 2, 3 should come from fragment A (payload
    // `from: "A"`), seqs 4, 5 from fragment B.
    let by_seq: std::collections::HashMap<u64, &AuditEntry> =
        merged_entries.iter().map(|e| (e.seq, e)).collect();
    for seq in 1..=3 {
        let e = by_seq.get(&seq).unwrap();
        assert_eq!(
            e.payload["from"], "A",
            "seq {} should come from fragment A (first-seen wins)",
            seq
        );
    }
    for seq in 4..=5 {
        let e = by_seq.get(&seq).unwrap();
        assert_eq!(e.payload["from"], "B", "seq {} should come from fragment B", seq);
    }

    // NOTE: We intentionally do NOT call `verify_chain` on the merged log
    // here. Fragments A and B are independent logs with independent
    // prev_hash chains; after dedup, the merged log's chain is broken at
    // the boundary between A's last entry (seq 3, from A) and B's first
    // non-overlapping entry (seq 4, whose prev_hash was computed from B's
    // seq 3, not A's seq 3). Per the T14 spec, `merge` only dedupes +
    // sorts — it does NOT re-chain or re-sign entries. Chain verification
    // on a merged log is the caller's responsibility and requires the
    // fragments to be a consistent single-chain split (not the case here).
    //
    // We DO verify that the merged log's `verify_chain` returns a
    // `ChainHashMismatch` (rather than, say, `Tampered`) — confirming
    // that the signatures are intact but the chain is broken at the
    // boundary, which is the expected post-merge state for independent
    // fragments.
    let chain_result = merged_log.verify_chain();
    assert!(
        matches!(chain_result, Err(AuditError::ChainHashMismatch(_))),
        "merged log of independent fragments should fail chain check with ChainHashMismatch, got {:?}",
        chain_result
    );

    // The merged log's file mode is still 0600 (merge enforces this).
    let file_mode = fs::metadata(&merged).unwrap().permissions().mode() & 0o777;
    assert_eq!(file_mode, 0o600, "merged log file must have mode 0600");

    // Suppress unused-variable warning for `merged_log` (we use it above
    // for the verify_chain call).
    let _ = &merged_log;
}

#[test]
fn test_filesystem_mode_600() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("audit.jsonl");
    let device_key = fresh_key();

    let mut log = AuditLog::open(&path, "dev-mode", device_key).unwrap();
    log.append(EventType::HumanAlert, None, json!({"k": "v"})).unwrap();

    let mode = fs::metadata(&path).unwrap().permissions().mode();
    let perm_bits = mode & 0o777;
    assert_eq!(perm_bits, 0o600, "audit log file must have mode 0600, got {:o}", perm_bits);
}

#[test]
fn test_filesystem_parent_dir_mode_700() {
    let tmp = tempfile::tempdir().unwrap();
    let nested = tmp.path().join("logs");
    let path = nested.join("audit.jsonl");
    let device_key = fresh_key();

    let mut log = AuditLog::open(&path, "dev-parent", device_key).unwrap();
    log.append(EventType::HumanAlert, None, json!({"k": "v"})).unwrap();

    let parent_mode = fs::metadata(&nested).unwrap().permissions().mode() & 0o777;
    assert_eq!(parent_mode, 0o700, "parent dir must have mode 0700, got {:o}", parent_mode);

    let file_mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(file_mode, 0o600);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn test_proptest_chain_tamper_detection(
        // Generate 1..=32 random event types — one per appended entry.
        event_types in proptest::collection::vec(
            proptest::sample::select(vec![
                EventType::CreateSessionKey,
                EventType::RevokeSessionKey,
                EventType::PayX402,
                EventType::PayMpp,
                EventType::SignUserOp,
                EventType::PasskeyForged,
                EventType::PasskeyMissing,
                EventType::PasskeyReplay,
                EventType::PolicyLookupFailed,
                EventType::PolicyParseFailed,
                EventType::HumanAlert,
                EventType::BudgetReclaim,
                EventType::BackupAttemptFailed,
                EventType::BackupLocked,
                EventType::MppChannelOpen,
                EventType::MppChannelClose,
                EventType::AuthFailed,
            ]),
            1..=32,
        ),
        // Factor used to pick the entry index to mutate (mod n).
        mutate_idx_factor in 0u32..1024u32,
        // 0 = mutate timestamp, 1 = mutate payload, 2 = mutate prev_hash.
        field_to_mutate in 0u8..3u8,
    ) {
        let n = event_types.len();
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        let device_key = SigningKey::generate(&mut rand::rng());

        let mut log = AuditLog::open(&path, "dev-proptest", device_key).unwrap();

        // Append N entries with random event types + varied payloads.
        for (i, &et) in event_types.iter().enumerate() {
            let session_key_id = (i % 2 == 0).then(|| format!("sk-{}", i));
            let payload = json!({
                "index": i,
                "tag": format!("entry-{}", i),
                "data": [i as u64, (i as u64) * 2, (i as u64) * 3],
            });
            let seq = log.append(et, session_key_id, payload).unwrap();
            prop_assert_eq!(seq, (i as u64) + 1);
        }

        // Sanity: chain is intact before mutation.
        prop_assert!(
            log.verify_chain().is_ok(),
            "chain must verify before mutation (n={})",
            n
        );

        // Pick a random entry index to mutate.
        let idx = (mutate_idx_factor as usize) % n;

        // Read all lines.
        let content = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = content
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(str::to_string)
            .collect();
        prop_assert_eq!(lines.len(), n, "expected exactly N lines");

        // Mutate line at idx.
        let mut entry: serde_json::Value = serde_json::from_str(&lines[idx]).unwrap();
        match field_to_mutate {
            0 => {
                // Mutate timestamp — use a clearly different value.
                entry["timestamp"] = serde_json::Value::String(format!(
                    "1970-01-01T00:00:0{}Z",
                    (idx + 1) % 10
                ));
            }
            1 => {
                // Mutate payload.
                entry["payload"] = json!({"tampered": true, "idx": idx});
            }
            2 => {
                // Mutate prev_hash — use a clearly different hex string.
                entry["prev_hash"] = serde_json::Value::String("00".repeat(32));
            }
            _ => unreachable!(),
        }
        lines[idx] = serde_json::to_string(&entry).unwrap();

        // Write back.
        let mut new_content = String::new();
        for line in &lines {
            new_content.push_str(line);
            new_content.push('\n');
        }
        std::fs::write(&path, new_content).unwrap();

        // verify_chain must fail.
        let result = log.verify_chain();
        prop_assert!(
            result.is_err(),
            "verify_chain must fail after tampering at idx {} (field={}, n={})",
            idx,
            field_to_mutate,
            n
        );

        // The error must be a Tampered or ChainHashMismatch (a Signature
        // error would indicate malformed input — that's a test bug, not a
        // successful tamper detection).
        match &result {
            Err(e) => {
                match e {
                    AuditError::Tampered(_) | AuditError::ChainHashMismatch(_) => {
                        // expected
                    }
                    AuditError::Signature(msg) => {
                        return Err(proptest::test_runner::TestCaseError::fail(
                            format!("unexpected Signature error: {}", msg)
                        ));
                    }
                    other => {
                        return Err(proptest::test_runner::TestCaseError::fail(
                            format!("unexpected error: {:?}", other)
                        ));
                    }
                }
            }
            Ok(()) => unreachable!("already asserted is_err above"),
        }
    }
}

// Silence unused-import warnings for `Digest` / `Sha256` / etc. when the
// proptest feature-gates exclude certain code paths on some targets.
#[allow(dead_code)]
fn _silence_unused() {
    let _: Sha256 = Sha256::new();
    let _ = std::any::TypeId::of::<EventType>();
}
