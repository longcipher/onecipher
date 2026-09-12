//! Strict secret-path validation and filesystem mapping (B9).
//!
//! A secret path (e.g. `github/personal`) is hierarchical and maps to a flat
//! file `<secrets_dir>/<percent-encoded>.age`. Appending `.age` (never
//! replacing an extension) keeps `foo.age` distinct from `foo`. Directory
//! walks skip symlinks and hidden entries so a planted link or a stray
//! dotfile can never shadow a real secret.

use std::path::{Path, PathBuf};

/// Maximum secret-path length in bytes (B9).
pub const MAX_PATH_LEN: usize = 1024;
/// File extension appended to every entry file (B9: append, never replace).
pub const ENTRY_EXTENSION: &str = "age";

/// Errors returned by path helpers.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PathError {
    #[error("invalid secret path '{path}': {reason}")]
    Invalid { path: String, reason: String },
}

/// Validate a secret path with the strict B9 rules.
///
/// Delegates the character/shape checks to
/// [`oc_core::paths::validate_secret_name`] (single source of truth) and adds
/// the length bound here so the limit lives next to the filesystem mapping.
pub fn validate_path(path: &str) -> Result<(), PathError> {
    if path.len() > MAX_PATH_LEN {
        return Err(PathError::Invalid {
            path: path.to_string(),
            reason: format!("path exceeds {MAX_PATH_LEN} bytes"),
        });
    }
    oc_core::paths::validate_secret_name(path).map_err(|e| {
        let reason = match e {
            oc_core::OcError::InvalidInput { message } => message,
            other => other.to_string(),
        };
        PathError::Invalid { path: path.to_string(), reason }
    })
}

/// Map a secret path to its entry file under `secrets_dir`.
///
/// Percent-encodes `%` then `/` (flat directory, hierarchy preserved) and
/// **appends** `.age` rather than replacing any extension.
pub fn to_file(secrets_dir: &Path, path: &str) -> Result<PathBuf, PathError> {
    validate_path(path)?;
    let mut filename = oc_core::paths::secret_name_to_filename(path);
    filename.push('.');
    filename.push_str(ENTRY_EXTENSION);
    Ok(secrets_dir.join(filename))
}

/// Collect live entry files under `secrets_dir`.
///
/// Skips symlinks (planted links must never shadow secrets) and hidden
/// entries (dotfiles / hidden directories). Only regular files ending in
/// `.age` are returned, sorted for deterministic output. Missing directories
/// yield an empty list.
pub fn collect_entry_files(secrets_dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(secrets_dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let file_name = entry.file_name().to_string_lossy().into_owned();
        if file_name.starts_with('.') {
            continue;
        }
        let Ok(meta) = std::fs::symlink_metadata(entry.path()) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        if !meta.is_file() {
            continue;
        }
        if entry.path().extension().and_then(|e| e.to_str()) != Some(ENTRY_EXTENSION) {
            continue;
        }
        out.push(entry.path());
    }
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_hierarchical_paths() {
        assert!(validate_path("github").is_ok());
        assert!(validate_path("github/personal").is_ok());
        assert!(validate_path("a/b/c").is_ok());
    }

    #[test]
    fn rejects_shape_violations() {
        for bad in [
            "", "/lead", "trail/", ".lead", "trail.", "a//b", "a/./b", "a/../b", "CON", "NUL.txt",
            "a/COM1",
        ] {
            assert!(validate_path(bad).is_err(), "must reject {bad:?}");
        }
        assert!(validate_path(&"x".repeat(MAX_PATH_LEN + 1)).is_err());
        assert!(validate_path(&"x".repeat(MAX_PATH_LEN)).is_ok());
    }

    #[test]
    fn to_file_appends_age_extension() {
        let dir = Path::new("/tmp/s");
        // A name that already ends in `.age` gets a second suffix: append,
        // never replace, so `foo.age` and `foo` never collide.
        assert_eq!(to_file(dir, "foo").unwrap(), dir.join("foo.age"));
        assert_eq!(to_file(dir, "foo.age").unwrap(), dir.join("foo.age.age"));
        assert_eq!(to_file(dir, "a/b").unwrap(), dir.join("a%2Fb.age"));
    }

    #[cfg(unix)]
    #[test]
    fn walk_skips_symlinks_and_hidden() {
        let dir = tempfile::tempdir().unwrap();
        let secrets = dir.path().join("secrets");
        std::fs::create_dir_all(&secrets).unwrap();
        std::fs::write(secrets.join("real.age"), b"{}").unwrap();
        std::fs::write(secrets.join(".hidden.age"), b"{}").unwrap();
        std::fs::write(secrets.join("notes.txt"), b"{}").unwrap();
        std::os::unix::fs::symlink(secrets.join("real.age"), secrets.join("link.age")).unwrap();

        let files = collect_entry_files(&secrets);
        assert_eq!(files, vec![secrets.join("real.age")]);
    }

    #[test]
    fn walk_missing_dir_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(collect_entry_files(&dir.path().join("nope")), [] as [std::path::PathBuf; 0]);
    }
}
