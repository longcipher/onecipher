//! Secure external editor (D4).
//!
//! Edits arbitrary text in `$EDITOR` (or `vi` fallback) using a temp file
//! created 0600 inside a 0700 staging directory **under the OneCipher state
//! directory**, never under the shared system temp directory: `/tmp` is
//! world-traversable, and a plaintext secret staged there is exposed to
//! co-resident users (the exact gap pago avoids by editing in memory). After
//! the editor exits the file is read back, then zero-filled before unlink so
//! plaintext does not linger in freed blocks.
//!
//! Callers that can avoid the filesystem entirely should prefer
//! [`super::tui_edit::edit_in_memory`], which never creates a file.
//!
//! Honesty note for SSDs: overwriting a file in place cannot guarantee the
//! old bytes are gone — wear-leveling, journaling, and copy-on-write
//! filesystems may retain stale copies in unmapped flash pages. The zero-fill
//! is best-effort defense for HDD/page-cache; true erasure on SSD requires
//! full-disk encryption.

use std::{io::Write, path::PathBuf};

use zeroize::{Zeroize, Zeroizing};

use crate::CliError;

/// Edit `initial` in an external editor, returning the edited value.
///
/// - staging dir: 0700 under the OneCipher state dir, file: 0600 (created exclusively, never
///   widen-then-narrow),
/// - editor: `editor` override > `$VISUAL` > `$EDITOR` > `vi`,
/// - post-read: overwrite the file with zeros (best-effort, see module docs) then unlink it and
///   remove the staging dir. The cleanup runs even when the editor exits non-zero, so a failed edit
///   never leaves plaintext on disk.
pub(crate) fn edit_text(
    initial: &str,
    editor: Option<&str>,
) -> Result<Zeroizing<String>, CliError> {
    let dir = staging_dir()?;
    let path = dir.join("secret.edit");
    write_private(&path, initial.as_bytes())?;

    // Run the editor, but keep the cleanup unconditional: a failed edit must
    // not leave the plaintext staging file behind.
    let editor_result = run_editor(&path, editor);

    let content = std::fs::read_to_string(&path).unwrap_or_default();
    zero_fill_and_remove(&path, content.len() as u64);
    let _ = std::fs::remove_dir_all(&dir);

    match editor_result {
        Ok(()) => Ok(Zeroizing::new(content.trim_end_matches(['\n', '\r']).to_string())),
        Err(e) => Err(e),
    }
}

/// Create a 0700 staging directory for the edit session.
///
/// The staging directory lives inside the OneCipher state directory
/// (`~/.onecipher`, itself 0700) rather than `std::env::temp_dir()`: `/tmp`
/// is world-traversable, so plaintext staged there is readable by
/// co-resident users.
fn staging_dir() -> Result<PathBuf, CliError> {
    let base = oc_core::paths::state_dir()?;
    let dir = base.join(format!("edit-{}-{}", std::process::id(), unique_suffix()));
    std::fs::create_dir_all(&dir).map_err(CliError::Io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .map_err(CliError::Io)?;
    }
    Ok(dir)
}

fn unique_suffix() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos() as u64)
}

/// Write bytes to `path` created exclusively at 0600.
fn write_private(path: &std::path::Path, bytes: &[u8]) -> Result<(), CliError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(CliError::Io)?;
        f.write_all(bytes).map_err(CliError::Io)?;
        f.sync_all().map_err(CliError::Io)?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes).map_err(CliError::Io)
    }
}

/// Launch the editor on `path`.
///
/// Precedence: the explicit `editor` argument (`--editor`), then `$VISUAL`,
/// then `$EDITOR`, then `vi` as a last resort.
fn run_editor(path: &std::path::Path, editor: Option<&str>) -> Result<(), CliError> {
    let editor = editor
        .map(str::to_owned)
        .or_else(|| std::env::var("VISUAL").ok())
        .or_else(|| std::env::var("EDITOR").ok())
        .unwrap_or_else(|| "vi".to_string());
    let status = std::process::Command::new(&editor).arg(path).status().map_err(CliError::Io)?;
    if !status.success() {
        return Err(CliError::InvalidArgs(format!("editor '{editor}' exited with {status}")));
    }
    Ok(())
}

/// Best-effort zero-fill then unlink. Length is taken from the bytes read so
/// short reads cannot leave a tail.
fn zero_fill_and_remove(path: &std::path::Path, len: u64) {
    if let Ok(f) = std::fs::OpenOptions::new().write(true).open(path) {
        let zeros = vec![0u8; len.min(1 << 20) as usize];
        let mut remaining = len;
        let mut f = f;
        while remaining > 0 {
            let n = zeros.len().min(remaining as usize);
            if f.write_all(&zeros[..n]).is_err() {
                break;
            }
            remaining -= n as u64;
        }
        let _ = f.sync_all();
    }
    // Drop any Zeroize-on-drop buffers holding the length side-channel is out
    // of scope here; unlink last.
    let mut dummy = [0u8; 1];
    dummy.zeroize();
    let _ = std::fs::remove_file(path);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_private_creates_0600_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.edit");
        write_private(&path, b"hello").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"hello");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    /// Regression guard for the plaintext-on-disk gap: the staging directory
    /// must live inside the 0700 OneCipher state directory (which is what
    /// keeps it out of the world-traversable system temp dir), never in
    /// `std::env::temp_dir()` directly.
    #[test]
    fn staging_dir_is_private_and_inside_the_state_dir() {
        // HOME is process-global and other tests redirect it in parallel; the
        // shared lock keeps both reads below observing the same value.
        let _lock =
            crate::test_util::HOME_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        let Ok(dir) = staging_dir() else { return }; // HOME unset in this environment.
        let Ok(state) = oc_core::paths::state_dir() else { return };

        assert!(
            dir.starts_with(&state) && dir != state,
            "staging dir {} must live inside the state dir {}",
            dir.display(),
            state.display()
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "staging dir must be owner-only");
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn zero_fill_removes_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("z.edit");
        std::fs::write(&path, b"secret-data").unwrap();
        zero_fill_and_remove(&path, 11);
        assert!(!path.exists());
    }
}
