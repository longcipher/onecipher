//! Shared atomic secret writer (B7).
//!
//! Canonical alias over [`oc_core::paths::write_atomic_private`], documented
//! here so `oc-secret`, `oc-vault` and `oc-wallet::policy_store` converge on
//! one sequence:
//!
//! parent `0700` -> unique `.{name}.{pid}.{nanos}.{seq}.tmp` in the same
//! directory -> `O_EXCL` (`create_new`) + `0600` at creation -> `write_all` +
//! `sync_all` -> `rename` into place -> `fsync` parent dir.
//!
//! `O_EXCL` defeats symlink planting at the temp path (creation fails instead
//! of following a planted link); `rename` never follows a symlink planted at
//! the target (it replaces the link itself).

use std::path::Path;

/// Atomically write a secret-bearing file with mode `0600` (B7 shared helper).
///
/// See [`oc_core::paths::write_atomic_private`]. All secret writes in this
/// workspace MUST go through this function (or the `oc-core` original
/// directly); direct `fs::write` for secrets is forbidden.
pub fn write_atomic_secret(path: &Path, contents: &[u8]) -> Result<(), std::io::Error> {
    oc_core::paths::write_atomic_private(path, contents)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_and_reads_back() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("w.json");
        write_atomic_secret(&path, b"{\"k\":1}").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"{\"k\":1}");
    }

    #[cfg(unix)]
    #[test]
    fn symlink_at_target_is_replaced_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        std::fs::write(&victim, b"original").unwrap();
        let link = dir.path().join("target.json");
        std::os::unix::fs::symlink(&victim, &link).unwrap();

        write_atomic_secret(&link, b"new").unwrap();

        assert_eq!(std::fs::read(&victim).unwrap(), b"original");
        assert!(!std::fs::symlink_metadata(&link).unwrap().file_type().is_symlink());
        assert_eq!(std::fs::read(&link).unwrap(), b"new");
    }

    #[cfg(unix)]
    #[test]
    fn parent_dir_is_narrowed_to_0700() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o755)).unwrap();
        write_atomic_secret(&sub.join("s"), b"x").unwrap();
        let mode = std::fs::metadata(&sub).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn leaves_no_temp_files() {
        let dir = tempfile::tempdir().unwrap();
        write_atomic_secret(&dir.path().join("f"), b"x").unwrap();
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty());
    }
}
