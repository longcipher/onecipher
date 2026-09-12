//! Canonical filesystem path resolution for OneCipher.
//!
//! Every crate previously resolved the home directory inline via
//! `std::env::var("HOME")`, with five mutually inconsistent failure
//! behaviors across 17 call sites:
//!
//! - `unwrap_or_else(|_| "/tmp".to_string())` (7 sites)
//! - `map_or_else(|_| PathBuf::from("."), ...)` (2 sites)
//! - propagate an error (5 sites)
//! - silently `return` (2 sites)
//! - a bespoke `USERPROFILE` fallback (1 site)
//!
//! The `/tmp` fallback was a real security defect, not just an
//! inconsistency: with `HOME` unset (empty systemd units, some container
//! entrypoints, cron, `env -i`), the wallet vault, key store and audit log
//! would be written to a world-writable directory, exposing them to
//! symlink attacks and cross-user disclosure.
//!
//! This module is the single source of truth. `HOME` unset is an error, never
//! a silent downgrade to an insecure location.

use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::error::OcError;

/// Directory name for OneCipher state, relative to the home directory.
pub const STATE_DIR_NAME: &str = ".onecipher";

/// Mode for files that may contain secrets or credentials.
pub const MODE_PRIVATE_FILE: u32 = 0o600;

/// Mode for non-secret files (policies, session metadata).
pub const MODE_REGULAR_FILE: u32 = 0o644;

/// Build a unique temp-file path next to `path`.
///
/// Deterministic names (`.{filename}.tmp`) collide under concurrent writes and
/// interleave writes; pid + nanos + a process-local monotonic counter makes
/// collisions practically impossible even within the same nanosecond.
/// Canonical implementation — `oc_policy::v2::unique_tmp_path` delegates here.
pub fn unique_tmp_path(path: &Path) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos());
    let mut name = path
        .file_name()
        .map_or_else(|| "onecipher".to_string(), |n| n.to_string_lossy().into_owned());
    name.push_str(&format!(".{}.{}.{}.tmp", std::process::id(), nanos, seq));
    path.with_file_name(name)
}

/// Atomically write `contents` to `path` with mode `mode`.
///
/// This is the shared atomic writer for the workspace (B7): `oc-secret`,
/// `oc-vault` and `oc-wallet::policy_store` all route secret-bearing writes
/// through [`write_atomic_private`]. Direct `fs::write` must NOT be used for
/// secrets.
///
/// The naive `fs::write` + `set_permissions` sequence used across this
/// workspace had two defects that this helper exists to eliminate:
///
/// 1. **Permission race.** `fs::write` creates the file with `0o666 & !umask` (commonly `0o644`)
///    and only *then* is it narrowed to `0o600`. For credential files that leaves a window in which
///    the contents are world-readable.
/// 2. **Torn writes.** `fs::write` truncates before writing, so a crash or full disk mid-write
///    leaves a truncated or empty file. For a key store that destroys the credential; for a policy
///    file it can silently drop restrictions.
///
/// Sequence (B7): parent dir `0700` (private mode only) -> unique
/// `.{name}.{pid}.{nanos}.{seq}.tmp` in the same directory -> `O_EXCL`
/// (`create_new`) + `0600` at creation -> `write_all` + `sync_all` ->
/// `rename` into place -> `fsync` parent dir.
///
/// `O_EXCL` is the symlink-planting defense: if an attacker pre-creates a
/// symlink at the temporary path, creation fails instead of following it.
/// A symlink pre-planted at the *target* path is never followed either:
/// `rename` atomically replaces the symlink itself, leaving the link target
/// untouched.
///
/// This writes to a temporary file in the *same directory* (so the final
/// `rename` is a same-filesystem atomic operation), sets the mode **before**
/// any data is written, `fsync`s the data, renames into place, and then
/// `fsync`s the parent directory so the rename itself is durable.
///
/// The temporary file is removed on any failure.
///
/// # Errors
///
/// Returns [`std::io::Error`] if the parent directory cannot be determined or
/// created, or if any filesystem operation fails. `io::Error` is used rather
/// than [`OcError`] because every caller already has a `From<io::Error>`
/// conversion, and `OcError` is `Clone + PartialEq` (which `io::Error` is not).
pub fn write_atomic(path: &Path, contents: &[u8], mode: u32) -> Result<(), std::io::Error> {
    use std::io::Write as _;

    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("path has no parent directory: {}", path.display()),
        )
    })?;
    std::fs::create_dir_all(parent)?;
    // B7: secret-bearing files live under a 0700 directory so a sibling
    // symlink or world-readable parent cannot expose them.
    if mode == MODE_PRIVATE_FILE {
        ensure_dir_private(parent);
    }

    // Same directory as the target so `rename` cannot cross a filesystem
    // boundary (which would make it non-atomic). Use a unique temp name to
    // avoid races under concurrency.
    let tmp_path = unique_tmp_path(path);
    // Best-effort cleanup of a leftover deterministic temp file from a previous
    // crash / old version for migration. Unique path needs no pre-remove.
    let _ = std::fs::remove_file(parent.join(format!(
        ".{}.tmp",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("onecipher")
    )));

    let result = (|| -> Result<(), std::io::Error> {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        // Set the mode at creation time — never widen-then-narrow.
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(mode);
        }
        let mut file = opts.open(&tmp_path)?;
        file.write_all(contents)?;
        file.sync_all()?;
        drop(file);

        // On non-Unix the mode argument is not expressible at creation time.
        #[cfg(not(unix))]
        let _ = mode;

        std::fs::rename(&tmp_path, path)?;

        // fsync the directory so the rename survives a power loss.
        #[cfg(unix)]
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
        Ok(())
    })();

    if result.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }
    result
}

/// Atomically write a secret-bearing file with mode `0600`.
///
/// The parent directory is created when missing and narrowed to `0700` on
/// Unix. See [`write_atomic`] for the full durability and symlink-planting
/// rationale (B7).
///
/// # Errors
///
/// See [`write_atomic`].
pub fn write_atomic_private(path: &Path, contents: &[u8]) -> Result<(), std::io::Error> {
    write_atomic(path, contents, MODE_PRIVATE_FILE)
}

/// Best-effort narrowing of a secret parent directory to `0700` (Unix only).
///
/// Creation via `create_dir_all` honors the umask, so a freshly created
/// parent could otherwise be `0755`. Failures are ignored: callers already
/// enforce directory modes on their vault roots, and a chmod failure must
/// not turn an otherwise durable write into an error.
#[cfg(unix)]
fn ensure_dir_private(dir: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
}

#[cfg(not(unix))]
fn ensure_dir_private(_dir: &Path) {}

// ── Validation helpers (unified, Rxx) ───────────────────────────────────────

/// Validate a wallet ID (used for vault file names). Rejects '/', '\\', '..' to prevent traversal.
///
/// Wallet IDs are flat file names (`<vault>/wallets/<id>.json`); a '/' would
/// create subdirectories or escape the vault. Hierarchical names are **not**
/// supported here — see [`validate_secret_name`] for the hierarchical case.
///
/// Rejects: empty/blank, '/', '\\', ".." substring, leading '.', exact "."/"..",
/// and NUL bytes. The allowed character set in practice is alphanumeric plus
/// '-'/'_' (but the validator only enforces the forbidden patterns to stay
/// permissive on other punctuation).
pub fn validate_wallet_id(id: &str) -> Result<(), crate::error::OcError> {
    if id.trim().is_empty() {
        return Err(crate::error::OcError::InvalidInput {
            message: "wallet ID must not be empty".to_string(),
        });
    }
    if id.contains('/') || id.contains('\\') || id.contains("..") {
        return Err(crate::error::OcError::InvalidInput {
            message: format!(
                "wallet ID contains forbidden pattern: '{id}' (allowed: alphanumeric + '-'/'_' only; '/' is rejected)"
            ),
        });
    }
    if id.contains('\0') {
        return Err(crate::error::OcError::InvalidInput {
            message: format!("wallet ID contains forbidden characters: '{id}'"),
        });
    }
    if id == "." || id == ".." || id.starts_with('.') {
        return Err(crate::error::OcError::InvalidInput {
            message: format!("wallet ID must not be '.'/'..' or start with '.': '{id}'"),
        });
    }
    Ok(())
}

/// Validate a secret name (allows '/' for hierarchy, percent-encodes to %2F).
///
/// Secret names are hierarchical (e.g. `github/personal`) and '/' is **allowed**
/// — it is percent-encoded to `%2F` on disk via [`secret_name_to_filename`] so
/// the filesystem stays flat. This is the intentional difference from
/// [`validate_wallet_id`], where '/' is forbidden because wallet IDs map
/// directly to file names without encoding.
///
/// Strict rules (B9):
/// - byte length 1..=1024.
/// - no NUL, newline, carriage return, backslash.
/// - no leading or trailing `/`; no `//` (empty segment).
/// - no leading or trailing `.` for the whole name; no segment equal to `.` or `..`; no `/./` or
///   `/../` substrings.
/// - no segment starting or ending with `.` or space (Windows trailing-dot ambiguity).
/// - Windows reserved device names are rejected per segment (case-insensitive): `CON`, `PRN`,
///   `AUX`, `NUL`, `COM1`-`COM9`, `LPT1`-`LPT9`, with or without an extension (`CON.txt` is also
///   reserved on Windows).
/// - shell-unsafe `:` `*` `?` `"` `<` `>` `|` are rejected to keep filenames portable.
pub fn validate_secret_name(name: &str) -> Result<(), crate::error::OcError> {
    let invalid = |reason: &str| crate::error::OcError::InvalidInput {
        message: format!("invalid secret name '{name}': {reason}"),
    };
    if name.trim().is_empty() {
        return Err(invalid("name must not be empty or blank"));
    }
    if name.len() > 1024 {
        return Err(invalid("name exceeds 1024 bytes"));
    }
    for ch in ['\0', '\n', '\r', '\\', ':', '*', '?', '"', '<', '>', '|'] {
        if name.contains(ch) {
            return Err(invalid("name contains a forbidden character"));
        }
    }
    if name.starts_with('/') || name.ends_with('/') {
        return Err(invalid("name must not start or end with '/'"));
    }
    if name.starts_with('.') || name.ends_with('.') {
        return Err(invalid("name must not start or end with '.'"));
    }
    if name.contains("//") || name.contains("/./") || name.contains("/../") {
        return Err(invalid("name must not contain '//', '/./' or '/../'"));
    }
    for segment in name.split('/') {
        if segment.is_empty() {
            return Err(invalid("name contains an empty path segment"));
        }
        if segment == "." || segment == ".." {
            return Err(invalid("path segment must not be '.' or '..'"));
        }
        if segment.starts_with('.') || segment.ends_with('.') {
            return Err(invalid("path segment must not start or end with '.'"));
        }
        if segment.ends_with(' ') {
            return Err(invalid("path segment must not end with space"));
        }
        // Windows reserved device name, ignoring any extension.
        let stem = segment.split('.').next().unwrap_or(segment).to_ascii_uppercase();
        let reserved = stem == "CON" ||
            stem == "PRN" ||
            stem == "AUX" ||
            stem == "NUL" ||
            (stem.len() == 4 &&
                (stem.starts_with("COM") || stem.starts_with("LPT")) &&
                stem.as_bytes()[3].is_ascii_digit() &&
                stem.as_bytes()[3] != b'0');
        if reserved {
            return Err(invalid("path segment is a Windows reserved device name"));
        }
    }
    Ok(())
}

/// Percent-encode a secret name for filesystem storage (shared).
///
/// Encodes `%` as `%25` first, then `/` as `%2F`. This allows hierarchical
/// names like `github/personal` while keeping the filesystem flat and safe.
pub fn secret_name_to_filename(name: &str) -> String {
    name.replace('%', "%25").replace('/', "%2F")
}

/// Resolve the current user's home directory.
///
/// On Unix this reads `HOME`. On non-Unix targets `USERPROFILE` is tried
/// first, then `HOME`.
///
/// # Errors
///
/// Returns [`OcError::InvalidInput`] if no home directory can be determined,
/// or if the variable is set but empty. Callers MUST NOT substitute a
/// fallback such as `/tmp` or `.` — see the module docs.
pub fn home_dir() -> Result<PathBuf, OcError> {
    #[cfg(unix)]
    let raw = std::env::var("HOME").ok();
    #[cfg(not(unix))]
    let raw = std::env::var("USERPROFILE").ok().or_else(|| std::env::var("HOME").ok());

    match raw {
        Some(h) if !h.trim().is_empty() => Ok(PathBuf::from(h)),
        _ => Err(OcError::InvalidInput {
            message: "cannot determine home directory: HOME is not set (refusing to fall back \
                      to a world-writable location such as /tmp)"
                .to_string(),
        }),
    }
}

/// Resolve the OneCipher state directory (`~/.onecipher`).
///
/// This is the parent of the vault, key store, audit log and config file.
///
/// # Errors
///
/// Propagates the [`home_dir`] error when `HOME` is unavailable.
pub fn state_dir() -> Result<PathBuf, OcError> {
    Ok(home_dir()?.join(STATE_DIR_NAME))
}

/// Resolve a path inside the OneCipher state directory.
///
/// ```no_run
/// # use oc_core::paths::state_path;
/// let cfg = state_path("config.json")?; // ~/.onecipher/config.json
/// //
/// # Ok::<_, oc_core::OcError>(())
/// ```
///
/// # Errors
///
/// Propagates the [`home_dir`] error when `HOME` is unavailable.
pub fn state_path(relative: impl AsRef<std::path::Path>) -> Result<PathBuf, OcError> {
    Ok(state_dir()?.join(relative))
}

/// Resolve the config file path (`~/.onecipher/config.json`).
///
/// # Errors
///
/// Propagates the [`home_dir`] error when `HOME` is unavailable.
pub fn config_path() -> Result<PathBuf, OcError> {
    state_path("config.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `home_dir` must reject an unset or blank `HOME` rather than silently
    /// returning an insecure location. Serialized with the other env-mutating
    /// test via a shared mutex because env vars are process-global.
    #[test]
    fn test_home_dir_rejects_unset_and_blank() {
        let _guard = crate::test_support::env_lock();
        let original = std::env::var("HOME").ok();

        // SAFETY: guarded by `env_lock()`, and the original value is restored
        // before the guard is released.
        unsafe { std::env::remove_var("HOME") };
        let err = home_dir().unwrap_err();
        assert!(
            format!("{err}").contains("home directory"),
            "unset HOME must produce a home-directory error, got: {err}"
        );

        unsafe { std::env::set_var("HOME", "   ") };
        assert!(home_dir().is_err(), "blank HOME must be rejected");

        match original {
            Some(v) => unsafe { std::env::set_var("HOME", v) },
            None => unsafe { std::env::remove_var("HOME") },
        }
    }

    #[test]
    fn test_write_atomic_creates_file_with_exact_mode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.json");

        write_atomic_private(&path, b"{\"k\":1}").unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"{\"k\":1}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "secret file must never be group/world readable");
        }
    }

    /// The whole point of the helper: the file must *never* exist with a
    /// wider mode, not even briefly. `fs::write` + `set_permissions` created
    /// the file at `0o644` first; creating with `O_CREAT|mode` does not.
    #[test]
    fn test_write_atomic_never_widens_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("creds");

        // Pre-existing file with permissive mode must end up narrowed.
        std::fs::write(&path, b"old").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        }

        write_atomic_private(&path, b"new").unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "replacing a 0666 file must yield 0600");
        }
    }

    #[test]
    fn test_write_atomic_overwrites_and_truncates() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f.json");

        write_atomic(&path, b"aaaaaaaaaaaaaaaaaaaa", MODE_REGULAR_FILE).unwrap();
        write_atomic(&path, b"bb", MODE_REGULAR_FILE).unwrap();

        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"bb",
            "shorter content must fully replace longer content"
        );
    }

    #[test]
    fn test_write_atomic_creates_missing_parent_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a").join("b").join("c.json");

        write_atomic_private(&path, b"x").unwrap();
        assert!(path.exists());
    }

    /// No `.tmp` scratch file may survive a successful write.
    #[test]
    fn test_write_atomic_leaves_no_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f.json");
        write_atomic_private(&path, b"x").unwrap();

        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "temp files left behind: {leftovers:?}");
    }

    /// A stale temp file from a previous crash must not block a later write.
    #[test]
    fn test_write_atomic_recovers_from_stale_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f.json");
        std::fs::write(dir.path().join(".f.json.tmp"), b"stale").unwrap();

        write_atomic_private(&path, b"fresh").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"fresh");
    }

    #[test]
    fn test_state_paths_are_nested_under_home() {
        let _guard = crate::test_support::env_lock();
        let original = std::env::var("HOME").ok();

        // SAFETY: guarded by `env_lock()`; original restored below.
        unsafe { std::env::set_var("HOME", "/home/tester") };

        assert_eq!(state_dir().unwrap(), PathBuf::from("/home/tester/.onecipher"));
        assert_eq!(config_path().unwrap(), PathBuf::from("/home/tester/.onecipher/config.json"));
        assert_eq!(
            state_path("keys/wallet.json").unwrap(),
            PathBuf::from("/home/tester/.onecipher/keys/wallet.json")
        );

        match original {
            Some(v) => unsafe { std::env::set_var("HOME", v) },
            None => unsafe { std::env::remove_var("HOME") },
        }
    }

    #[test]
    fn test_validate_secret_name_accepts_hierarchical() {
        assert!(validate_secret_name("github").is_ok());
        assert!(validate_secret_name("github/personal").is_ok());
        assert!(validate_secret_name("my-wallet_123").is_ok());
        assert!(validate_secret_name("a/b/c").is_ok());
    }

    #[test]
    fn test_validate_secret_name_rejects_traversal_and_shape() {
        for bad in [
            "",
            "   ",
            "/leading",
            "trailing/",
            ".leading",
            "trailing.",
            "a//b",
            "a/./b",
            "a/../b",
            "..",
            ".",
            "a\\b",
            "a:b",
            "a*b",
            "a|b",
            ".hidden/ok",
        ] {
            assert!(validate_secret_name(bad).is_err(), "must reject: {bad:?}");
        }
        // Over-long names are rejected.
        let long = "a".repeat(1025);
        assert!(validate_secret_name(&long).is_err());
        assert!(validate_secret_name(&"a".repeat(1024)).is_ok());
        // Control characters are rejected.
        assert!(validate_secret_name("a\nb").is_err());
        assert!(validate_secret_name("a\0b").is_err());
    }

    #[test]
    fn test_validate_secret_name_rejects_windows_reserved() {
        for bad in ["CON", "con", "NUL", "nul.txt", "COM1", "com9", "LPT1", "lpt9.cfg", "a/CON/b"] {
            assert!(validate_secret_name(bad).is_err(), "must reject reserved: {bad:?}");
        }
        // COM0/COM10/LPT0 are not reserved device names.
        assert!(validate_secret_name("COM0").is_ok());
        assert!(validate_secret_name("COM10").is_ok());
        assert!(validate_secret_name("console").is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn test_write_atomic_private_narrows_parent_to_0700() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = sub.join("s.age");
        write_atomic_private(&path, b"secret").unwrap();
        let mode = std::fs::metadata(&sub).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "secret parent dir must be narrowed to 0700");
    }

    #[cfg(unix)]
    #[test]
    fn test_write_atomic_does_not_follow_target_symlink() {
        // Attacker plants a symlink at the target path pointing at a victim
        // file. The atomic rename must replace the symlink itself, never
        // follow it to overwrite the victim.
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim.txt");
        std::fs::write(&victim, b"victim-original").unwrap();
        let link = dir.path().join("link.age");
        std::os::unix::fs::symlink(&victim, &link).unwrap();

        write_atomic_private(&link, b"attacker-payload").unwrap();

        // Victim is untouched; the link path is now a regular file.
        assert_eq!(std::fs::read(&victim).unwrap(), b"victim-original");
        assert!(!std::fs::symlink_metadata(&link).unwrap().file_type().is_symlink());
        assert_eq!(std::fs::read(&link).unwrap(), b"attacker-payload");
    }
}
