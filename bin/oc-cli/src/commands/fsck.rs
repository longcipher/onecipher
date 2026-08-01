//! `onecipher fsck` — secret store integrity check and repair.
//!
//! Verifies directory/file permissions, index.jsonl consistency, orphan/phantom
//! detection, recipients file validity, age identity validity, and optionally
//! full decrypt validation.

use std::{
    collections::HashSet,
    path::{Path, PathBuf},
};

use oc_core::SecretIndexEntry;
use oc_secret::{AgeIdentity, RecipientsFile, SecretStore, StoreConfig};

use crate::CliError;

/// Run the fsck command.
pub(crate) fn run(fix: bool, decrypt: bool) -> Result<(), CliError> {
    let home = super::onecipher_home();
    let store_root = super::secret_store_root();
    let config = StoreConfig::new(store_root.clone());

    let mut warnings = 0u32;
    let mut errors = 0u32;
    let mut fixed = 0u32;

    eprintln!("onecipher fsck — checking secret store at {}", store_root.display());
    eprintln!();

    // ── (a) Directory permissions ───────────────────────────────────────
    check_dir_permissions(
        &home,
        0o700,
        "onecipher home",
        fix,
        &mut warnings,
        &mut errors,
        &mut fixed,
    );
    check_dir_permissions(
        &store_root,
        0o700,
        "store root",
        fix,
        &mut warnings,
        &mut errors,
        &mut fixed,
    );
    check_dir_permissions(
        &config.secrets_dir(),
        0o700,
        "secrets dir",
        fix,
        &mut warnings,
        &mut errors,
        &mut fixed,
    );

    // ── (b) File permissions for .age files ─────────────────────────────
    let secrets_dir = config.secrets_dir();
    let age_files = collect_age_files(&secrets_dir);
    for path in &age_files {
        check_file_permissions(
            path,
            0o600,
            &format!("age file {}", path.display()),
            fix,
            &mut warnings,
            &mut errors,
            &mut fixed,
        );
    }

    // ── (c) index.jsonl consistency ─────────────────────────────────────
    let index_path = config.index_path();
    let (index_entries, index_parse_errors) = parse_index(&index_path);
    if index_parse_errors > 0 {
        report(
            Status::Fail,
            &format!("index.jsonl has {index_parse_errors} unparseable line(s)"),
            &mut errors,
        );
    } else {
        report(
            Status::Ok,
            &format!("index.jsonl has {} valid entries", index_entries.len()),
            &mut warnings,
        );
    }

    // index.jsonl file permissions
    if index_path.exists() {
        check_file_permissions(
            &index_path,
            0o600,
            "index.jsonl",
            fix,
            &mut warnings,
            &mut errors,
            &mut fixed,
        );
    }

    // ── (d) Orphan detection: .age files not in index ───────────────────
    let index_names: HashSet<String> = index_entries.iter().map(|e| e.name.clone()).collect();
    let mut orphans: Vec<PathBuf> = Vec::new();
    for path in &age_files {
        let filename = match path.file_stem().and_then(|s| s.to_str()) {
            Some(f) => f,
            None => continue,
        };
        let name = filename_to_name(filename);
        if !index_names.contains(&name) {
            orphans.push(path.clone());
            report(
                Status::Warn,
                &format!("orphan .age file: {} (name: '{name}')", path.display()),
                &mut warnings,
            );
        }
    }

    // ── (e) Phantom detection: index entries without .age file ──────────
    let age_file_names: HashSet<String> = age_files
        .iter()
        .filter_map(|p| p.file_stem().and_then(|s| s.to_str()).map(filename_to_name))
        .collect();
    let mut phantoms: Vec<&SecretIndexEntry> = Vec::new();
    for entry in &index_entries {
        if !age_file_names.contains(&entry.name) {
            phantoms.push(entry);
            report(
                Status::Warn,
                &format!("phantom index entry: '{}' (no .age file)", entry.name),
                &mut warnings,
            );
        }
    }

    // ── (f) Recipients file ────────────────────────────────────────────
    let recipients_path = super::age_recipients_path();
    if recipients_path.exists() {
        match RecipientsFile::load(&recipients_path) {
            Ok(recipients) => {
                report(
                    Status::Ok,
                    &format!("recipients file valid ({} recipient(s))", recipients.len()),
                    &mut warnings,
                );
            }
            Err(e) => {
                report(Status::Fail, &format!("recipients file parse error: {e}"), &mut errors);
            }
        }
    } else {
        report(Status::Warn, "recipients file not found", &mut warnings);
    }

    // ── (g) Age identity ───────────────────────────────────────────────
    let identity_path = super::age_identity_path();
    let identity = if identity_path.exists() {
        match std::fs::read_to_string(&identity_path) {
            Ok(content) => match AgeIdentity::parse(content.trim()) {
                Ok(id) => {
                    report(Status::Ok, "age identity is valid", &mut warnings);
                    Some(id)
                }
                Err(e) => {
                    report(Status::Fail, &format!("age identity parse error: {e}"), &mut errors);
                    None
                }
            },
            Err(e) => {
                report(Status::Fail, &format!("cannot read age identity: {e}"), &mut errors);
                None
            }
        }
    } else {
        report(Status::Warn, "age identity file not found", &mut warnings);
        None
    };

    // ── (h) Decrypt validation (optional) ───────────────────────────────
    if decrypt {
        if let Some(ref id) = identity {
            eprintln!();
            eprintln!("decrypt validation (this may take a while)...");
            let store = SecretStore::open(config)
                .map_err(|e| CliError::InvalidArgs(format!("failed to open store: {e}")))?;
            for entry in &index_entries {
                if !age_file_names.contains(&entry.name) {
                    // Already reported as phantom — skip.
                    continue;
                }
                match store.get(&entry.name) {
                    Ok(secret_entry) => match secret_entry.decrypt(id) {
                        Ok(_) => {
                            report(
                                Status::Ok,
                                &format!("decrypt ok: '{}'", entry.name),
                                &mut warnings,
                            );
                        }
                        Err(e) => {
                            report(
                                Status::Fail,
                                &format!("decrypt failed: '{}' — {e}", entry.name),
                                &mut errors,
                            );
                        }
                    },
                    Err(e) => {
                        report(
                            Status::Fail,
                            &format!("cannot load '{}': {e}", entry.name),
                            &mut errors,
                        );
                    }
                }
            }
        } else {
            report(
                Status::Warn,
                "skipping decrypt validation (no valid age identity)",
                &mut warnings,
            );
        }
    }

    // ── Fix phase ───────────────────────────────────────────────────────
    if fix {
        eprintln!();
        eprintln!("applying fixes...");

        // Fix orphan .age files: remove them.
        for path in &orphans {
            match std::fs::remove_file(path) {
                Ok(()) => {
                    report(
                        Status::Fixed,
                        &format!("removed orphan file: {}", path.display()),
                        &mut fixed,
                    );
                }
                Err(e) => {
                    report(
                        Status::Fail,
                        &format!("failed to remove {}: {e}", path.display()),
                        &mut errors,
                    );
                }
            }
        }

        // Fix phantom index entries: rewrite index without them.
        if !phantoms.is_empty() {
            let phantom_names: HashSet<&str> = phantoms.iter().map(|e| e.name.as_str()).collect();
            let cleaned: Vec<&SecretIndexEntry> =
                index_entries.iter().filter(|e| !phantom_names.contains(e.name.as_str())).collect();
            match write_index(&index_path, &cleaned) {
                Ok(()) => {
                    report(
                        Status::Fixed,
                        &format!(
                            "rewrote index.jsonl (removed {} phantom entry/entries)",
                            phantoms.len()
                        ),
                        &mut fixed,
                    );
                }
                Err(e) => {
                    report(
                        Status::Fail,
                        &format!("failed to rewrite index.jsonl: {e}"),
                        &mut errors,
                    );
                }
            }
        }
    }

    // ── Summary ─────────────────────────────────────────────────────────
    eprintln!();
    if errors == 0 && warnings == 0 && fixed == 0 {
        eprintln!("fsck complete: no issues found");
    } else {
        eprintln!(
            "fsck complete: {errors} error(s), {warnings} warning(s){}",
            if fix { format!(", {fixed} fixed") } else { String::new() }
        );
        if errors > 0 && !fix {
            eprintln!("hint: run with --fix to automatically repair issues");
        }
    }

    if errors > 0 {
        Err(CliError::InvalidArgs(format!("fsck found {errors} error(s)")))
    } else {
        Ok(())
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
enum Status {
    Ok,
    Warn,
    Fail,
    Fixed,
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ok => write!(f, "[OK]"),
            Self::Warn => write!(f, "[WARN]"),
            Self::Fail => write!(f, "[FAIL]"),
            Self::Fixed => write!(f, "[FIXED]"),
        }
    }
}

fn report(status: Status, msg: &str, counter: &mut u32) {
    eprintln!("  {status} {msg}");
    *counter += 1;
}

/// Check directory permissions and optionally fix them.
#[cfg(unix)]
fn check_dir_permissions(
    path: &Path,
    expected: u32,
    label: &str,
    fix: bool,
    warnings: &mut u32,
    errors: &mut u32,
    fixed: &mut u32,
) {
    use std::os::unix::fs::PermissionsExt;

    if !path.exists() {
        report(Status::Warn, &format!("{label} does not exist: {}", path.display()), warnings);
        return;
    }
    let mode = match std::fs::metadata(path) {
        Ok(m) => m.permissions().mode() & 0o777,
        Err(e) => {
            report(Status::Fail, &format!("cannot stat {label}: {e}"), errors);
            return;
        }
    };
    if mode == expected {
        report(Status::Ok, &format!("{label} permissions {:04o}", expected), warnings);
    } else {
        let msg = format!(
            "{label} has mode {:04o} (expected {:04o}): {}",
            mode,
            expected,
            path.display()
        );
        if fix {
            match std::fs::set_permissions(path, std::fs::Permissions::from_mode(expected)) {
                Ok(()) => {
                    report(Status::Fixed, &format!("{msg} — fixed"), fixed);
                }
                Err(e) => {
                    report(Status::Fail, &format!("{msg} — fix failed: {e}"), errors);
                }
            }
        } else {
            report(Status::Fail, &msg, errors);
        }
    }
}

#[cfg(not(unix))]
fn check_dir_permissions(
    _path: &Path,
    _expected: u32,
    label: &str,
    _fix: bool,
    warnings: &mut u32,
    _errors: &mut u32,
    _fixed: &mut u32,
) {
    report(Status::Ok, &format!("{label} permissions (skipped, non-unix)"), warnings);
}

/// Check file permissions and optionally fix them.
#[cfg(unix)]
fn check_file_permissions(
    path: &Path,
    expected: u32,
    label: &str,
    fix: bool,
    warnings: &mut u32,
    errors: &mut u32,
    fixed: &mut u32,
) {
    use std::os::unix::fs::PermissionsExt;

    let mode = match std::fs::metadata(path) {
        Ok(m) => m.permissions().mode() & 0o777,
        Err(e) => {
            report(Status::Fail, &format!("cannot stat {label}: {e}"), errors);
            return;
        }
    };
    if mode == expected {
        report(Status::Ok, &format!("{label} permissions {:04o}", expected), warnings);
    } else {
        let msg = format!("{label} has mode {:04o} (expected {:04o})", mode, expected);
        if fix {
            match std::fs::set_permissions(path, std::fs::Permissions::from_mode(expected)) {
                Ok(()) => {
                    report(Status::Fixed, &format!("{msg} — fixed"), fixed);
                }
                Err(e) => {
                    report(Status::Fail, &format!("{msg} — fix failed: {e}"), errors);
                }
            }
        } else {
            report(Status::Fail, &msg, errors);
        }
    }
}

#[cfg(not(unix))]
fn check_file_permissions(
    _path: &Path,
    _expected: u32,
    label: &str,
    _fix: bool,
    warnings: &mut u32,
    _errors: &mut u32,
    _fixed: &mut u32,
) {
    report(Status::Ok, &format!("{label} permissions (skipped, non-unix)"), warnings);
}

/// Collect all `.age` files in the secrets directory.
fn collect_age_files(secrets_dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if !secrets_dir.exists() {
        return files;
    }
    if let Ok(entries) = std::fs::read_dir(secrets_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "age") {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

/// Parse the index.jsonl file into a list of `SecretIndexEntry` values,
/// returning the count of unparseable lines.
fn parse_index(index_path: &Path) -> (Vec<SecretIndexEntry>, usize) {
    let content = match std::fs::read_to_string(index_path) {
        Ok(c) => c,
        Err(_) => return (Vec::new(), 0),
    };
    let mut entries = Vec::new();
    let mut parse_errors = 0usize;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        match serde_json::from_str::<SecretIndexEntry>(trimmed) {
            Ok(entry) => entries.push(entry),
            Err(_) => parse_errors += 1,
        }
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    (entries, parse_errors)
}

/// Reverse the `name_to_filename` encoding: `%2F` → `/`, then `%25` → `%`.
fn filename_to_name(stem: &str) -> String {
    stem.replace("%2F", "/").replace("%25", "%")
}

/// Write the index entries back to index.jsonl.
fn write_index(index_path: &Path, entries: &[&SecretIndexEntry]) -> Result<(), std::io::Error> {
    let mut content = String::new();
    for e in entries {
        let line = serde_json::to_string(e)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        content.push_str(&line);
        content.push('\n');
    }
    std::fs::write(index_path, content)?;
    Ok(())
}
