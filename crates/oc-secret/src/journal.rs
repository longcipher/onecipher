//! Two-phase READY journal for recipient rotation and renames.
//!
//! Recipient rotation and renames stage their work in a per-operation staging
//! tree and only then write a `READY` file as the commit point:
//!
//! ```text
//! <root>/.staging-<op-id>/
//!   dst          # staged destination copy
//!   meta.json    # { src, dst }
//!   READY        # commit point (written last)
//! ```
//!
//! Crash recovery ([`recover_journal`]) is idempotent:
//! - `READY` present: roll forward (install `dst`, then unlink `src` only after `dst` is durable —
//!   "never delete src without dst").
//! - `READY` absent: roll back (delete the staging tree, leave `src` alone).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Staging directory prefix.
pub const STAGING_PREFIX: &str = ".staging-";
/// Commit-point file name inside a staging tree.
pub const READY_FILE: &str = "READY";

/// Journal metadata persisted next to the staged copy.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct JournalMeta {
    src: String,
    dst: String,
}

/// Begin a staged operation: create `<root>/.staging-<op_id>/` with the
/// staged `dst` bytes and `meta.json` (no `READY` yet).
pub fn stage_operation(
    root: &Path,
    op_id: &str,
    src_name: &str,
    dst_name: &str,
    dst_bytes: &[u8],
) -> std::io::Result<PathBuf> {
    let dir = staging_dir(root, op_id);
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join("dst"), dst_bytes)?;
    let meta = JournalMeta { src: src_name.to_string(), dst: dst_name.to_string() };
    std::fs::write(dir.join("meta.json"), serde_json::to_vec(&meta).unwrap_or_default())?;
    Ok(dir)
}

/// Mark a staged operation committed by writing `READY` last.
pub fn mark_ready(staging: &Path) -> std::io::Result<()> {
    oc_core::paths::write_atomic_private(&staging.join(READY_FILE), b"READY")
}

/// Install a committed operation: copy staged `dst` to its final path with
/// fsync, then unlink `src` only after `dst` is durable.
///
/// `resolve` maps a secret name to its final file path.
pub fn install_committed<F>(root: &Path, staging: &Path, resolve: F) -> std::io::Result<()>
where
    F: Fn(&str) -> PathBuf,
{
    let _ = root;
    let meta: JournalMeta = serde_json::from_slice(&std::fs::read(staging.join("meta.json"))?)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let staged_dst = staging.join("dst");
    let final_dst = resolve(&meta.dst);
    if let Some(parent) = final_dst.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let bytes = std::fs::read(&staged_dst)?;
    oc_core::paths::write_atomic_private(&final_dst, &bytes)?;
    // "Never delete src without dst": src is unlinked only after dst is
    // atomically installed and fsynced.
    if meta.src != meta.dst {
        let src_path = resolve(&meta.src);
        if final_dst.exists() && src_path.exists() {
            std::fs::remove_file(&src_path)?;
        }
    }
    std::fs::remove_dir_all(staging)?;
    Ok(())
}

/// Recover all staging trees under `root`.
///
/// Returns `(rolled_forward, rolled_back)`. `resolve` maps secret names to
/// final file paths (same closure shape as [`install_committed`]).
pub fn recover_journal<F>(root: &Path, resolve: F) -> (usize, usize)
where
    F: Fn(&str) -> PathBuf,
{
    let mut forward = 0;
    let mut back = 0;
    let Ok(entries) = std::fs::read_dir(root) else {
        return (0, 0);
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with(STAGING_PREFIX) {
            continue;
        }
        let staging = entry.path();
        if staging.join(READY_FILE).exists() {
            if install_committed(root, &staging, &resolve).is_ok() {
                forward += 1;
            } else {
                // Corrupt commit point: drop staging but keep src (fail safe).
                let _ = std::fs::remove_dir_all(&staging);
                back += 1;
            }
        } else {
            let _ = std::fs::remove_dir_all(&staging);
            back += 1;
        }
    }
    (forward, back)
}

/// Staging directory for an operation id.
pub fn staging_dir(root: &Path, op_id: &str) -> PathBuf {
    root.join(format!("{STAGING_PREFIX}{op_id}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolve_in(dir: &Path) -> impl Fn(&str) -> PathBuf + '_ {
        move |name: &str| dir.join(format!("{name}.age"))
    }

    #[test]
    fn crash_before_ready_rolls_back_and_keeps_src() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(resolve_in(root)("src"), b"orig").unwrap();
        // Stage but never mark READY (crash before commit point).
        stage_operation(root, "op1", "src", "dst", b"new").unwrap();
        let (fwd, back) = recover_journal(root, resolve_in(root));
        assert_eq!((fwd, back), (0, 1));
        assert!(resolve_in(root)("src").exists(), "src must survive rollback");
        assert!(!resolve_in(root)("dst").exists(), "dst must not appear");
    }

    #[test]
    fn crash_after_ready_rolls_forward_and_never_loses_dst() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(resolve_in(root)("src"), b"orig").unwrap();
        let staging = stage_operation(root, "op2", "src", "dst", b"new").unwrap();
        mark_ready(&staging).unwrap();
        // Crash after READY: recovery installs dst then unlinks src.
        let (fwd, back) = recover_journal(root, resolve_in(root));
        assert_eq!((fwd, back), (1, 0));
        assert_eq!(std::fs::read(resolve_in(root)("dst")).unwrap(), b"new");
        assert!(!resolve_in(root)("src").exists());
    }

    #[test]
    fn no_dst_never_deletes_src() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(resolve_in(root)("src"), b"orig").unwrap();
        // Corrupt staging with READY but no dst payload.
        let staging = staging_dir(root, "op3");
        std::fs::create_dir_all(&staging).unwrap();
        std::fs::write(
            staging.join("meta.json"),
            serde_json::json!({"src":"src","dst":"dst"}).to_string(),
        )
        .unwrap();
        mark_ready(&staging).unwrap();
        let _ = recover_journal(root, resolve_in(root));
        assert!(resolve_in(root)("src").exists(), "src must never be deleted without dst");
        assert!(!resolve_in(root)("dst").exists());
    }
}
