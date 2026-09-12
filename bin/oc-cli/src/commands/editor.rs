//! Secure external editor (D4).
//!
//! Edits a secret value in `$EDITOR` (or `vi` fallback) using a temp file
//! created 0600 inside a 0700 staging directory. After the editor exits the
//! file is read back, then zero-filled before unlink so plaintext does not
//! linger in freed blocks.
//!
//! Honesty note for SSDs: overwriting a file in place cannot guarantee the
//! old bytes are gone — wear-leveling, journaling, and copy-on-write
//! filesystems may retain stale copies in unmapped flash pages. The zero-fill
//! is best-effort defense for HDD/page-cache; true erasure on SSD requires
//! full-disk encryption.

use std::{
    io::{Read, Write},
    path::PathBuf,
};

use zeroize::{Zeroize, Zeroizing};

use crate::CliError;

/// Edit `initial` in an external editor, returning the edited value.
///
/// - staging dir: 0700, file: 0600 (created exclusively, never widen-then-narrow),
/// - editor: `$VISUAL` > `$EDITOR` > `vi`,
/// - post-read: overwrite the file with zeros (best-effort, see module docs) then unlink it and
///   remove the staging dir.
///
/// Currently exercised by unit tests; wiring into `secret edit` stays with
/// that command's owner (its multi-field payload format is still evolving,
/// and this helper edits a single value).
#[allow(dead_code)]
pub(crate) fn edit_secret(initial: &str) -> Result<Zeroizing<String>, CliError> {
    let dir = staging_dir()?;
    let path = dir.join("secret.edit");
    write_private(&path, initial.as_bytes())?;
    run_editor(&path)?;
    let mut content = String::new();
    std::fs::File::open(&path)
        .map_err(CliError::Io)?
        .read_to_string(&mut content)
        .map_err(CliError::Io)?;
    zero_fill_and_remove(&path, content.len() as u64);
    let _ = std::fs::remove_dir(&dir);
    Ok(Zeroizing::new(content.trim_end_matches(['\n', '\r']).to_string()))
}

/// Create a 0700 staging directory for the edit session.
fn staging_dir() -> Result<PathBuf, CliError> {
    let mut dir = std::env::temp_dir();
    dir.push(format!("onecipher-edit-{}-{}", std::process::id(), unique_suffix()));
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

fn run_editor(path: &std::path::Path) -> Result<(), CliError> {
    let editor = std::env::var("VISUAL")
        .or_else(|_| std::env::var("EDITOR"))
        .unwrap_or_else(|_| "vi".to_string());
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

    #[test]
    fn zero_fill_removes_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("z.edit");
        std::fs::write(&path, b"secret-data").unwrap();
        zero_fill_and_remove(&path, 11);
        assert!(!path.exists());
    }
}
