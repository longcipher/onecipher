//! Doctor CLI — system health diagnostics for OneCipher.
//!
//! `onecipher doctor` checks the local environment for common issues:
//! home directory, secret store, age identity, recipients, index integrity,
//! file permissions, and config parseability.

use std::{collections::HashSet, os::unix::fs::PermissionsExt};

use oc_core::Config;
use oc_secret::RecipientsFile;

use crate::CliError;

/// Entry point for `onecipher doctor`.
pub(crate) fn run(verbose: bool) -> Result<(), CliError> {
    eprintln!("onecipher doctor — checking system health\n");

    let mut warnings = 0u32;
    let mut failures = 0u32;

    macro_rules! check {
        ($label:expr) => {
            CheckCx { label: $label, verbose, warnings: &mut warnings, failures: &mut failures }
        };
    }

    let home = super::onecipher_home();
    let store_root = super::secret_store_root();
    let identity_path = super::age_identity_path();
    let recipients_path = super::age_recipients_path();

    // 1. Home directory exists and has mode 0700.
    {
        let mut cx = check!("Home directory");
        if !home.exists() {
            cx.fail(&format!("{} does not exist", home.display()));
        } else {
            cx.ok(&format!("{}", home.display()));
            #[cfg(unix)]
            {
                let mode =
                    std::fs::metadata(&home).map(|m| m.permissions().mode() & 0o777).unwrap_or(0);
                if mode != 0o700 {
                    cx.warn(&format!("permissions are {mode:04o}, expected 0700"));
                } else if verbose {
                    cx.ok("permissions are 0700");
                }
            }
        }
    }

    // 2. Secret store directory exists.
    {
        let mut cx = check!("Secret store");
        if !store_root.exists() {
            cx.fail(&format!("{} does not exist", store_root.display()));
        } else {
            cx.ok(&format!("{}", store_root.display()));
            #[cfg(unix)]
            {
                let mode = std::fs::metadata(&store_root)
                    .map(|m| m.permissions().mode() & 0o777)
                    .unwrap_or(0);
                if mode != 0o700 {
                    cx.warn(&format!("permissions are {mode:04o}, expected 0700"));
                } else if verbose {
                    cx.ok("permissions are 0700");
                }
            }
        }
    }

    // 3. Age identity file exists and is parseable.
    {
        let mut cx = check!("Age identity");
        match std::fs::read_to_string(&identity_path) {
            Err(e) => {
                cx.fail(&format!("cannot read {}: {e}", identity_path.display()));
            }
            Ok(content) => {
                let trimmed = content.trim();
                match oc_secret::AgeIdentity::parse(trimmed) {
                    Err(e) => {
                        cx.fail(&format!("parse error: {e}"));
                    }
                    Ok(_) => {
                        cx.ok(&format!("{}", identity_path.display()));
                    }
                }
            }
        }
    }

    // 4. Age recipients file exists and has at least 1 recipient.
    {
        let mut cx = check!("Age recipients");
        if !recipients_path.exists() {
            cx.fail(&format!(
                "{} does not exist — run `onecipher age init`",
                recipients_path.display()
            ));
        } else {
            match RecipientsFile::load(&recipients_path) {
                Err(e) => {
                    cx.fail(&format!("parse error: {e}"));
                }
                Ok(recipients) => {
                    if recipients.is_empty() {
                        cx.fail("no recipients configured");
                    } else {
                        cx.ok(&format!("{} recipient(s)", recipients.len()));
                    }
                }
            }
        }
    }

    // 5. index.jsonl exists and is valid JSONL.
    {
        let mut cx = check!("Index (index.jsonl)");
        let index_path = store_root.join("index.jsonl");
        if !index_path.exists() {
            cx.fail(&format!("{} does not exist", index_path.display()));
        } else {
            match std::fs::read_to_string(&index_path) {
                Err(e) => {
                    cx.fail(&format!("cannot read: {e}"));
                }
                Ok(content) => {
                    let mut parse_errors = 0u32;
                    let mut count = 0u32;
                    for (lineno, line) in content.lines().enumerate() {
                        let trimmed = line.trim();
                        if trimmed.is_empty() {
                            continue;
                        }
                        count += 1;
                        if serde_json::from_str::<oc_core::SecretIndexEntry>(trimmed).is_err() {
                            parse_errors += 1;
                            if parse_errors <= 3 {
                                cx.fail(&format!(
                                    "invalid JSON on line {}: {}",
                                    lineno + 1,
                                    trimmed.chars().take(60).collect::<String>()
                                ));
                            }
                        }
                    }
                    if parse_errors == 0 {
                        cx.ok(&format!("{count} entries"));
                    } else if parse_errors > 3 {
                        cx.fail(&format!("... and {} more parse errors", parse_errors - 3));
                    }
                }
            }
        }
    }

    // 6. Each .age file in secrets/ has permission 0600.
    {
        let mut cx = check!("Secret file permissions");
        let secrets_dir = store_root.join("secrets");
        if !secrets_dir.exists() {
            cx.warn(&format!("{} does not exist", secrets_dir.display()));
        } else {
            #[cfg(unix)]
            {
                let mut bad_perms = Vec::new();
                match std::fs::read_dir(&secrets_dir) {
                    Err(e) => {
                        cx.fail(&format!("cannot read directory: {e}"));
                    }
                    Ok(entries) => {
                        for entry in entries.flatten() {
                            let path = entry.path();
                            if path.extension().is_some_and(|ext| ext == "age") {
                                let mode = entry
                                    .metadata()
                                    .map(|m| m.permissions().mode() & 0o777)
                                    .unwrap_or(0);
                                if mode != 0o600 {
                                    bad_perms.push((
                                        path.file_name()
                                            .unwrap_or_default()
                                            .to_string_lossy()
                                            .into_owned(),
                                        mode,
                                    ));
                                }
                            }
                        }
                        if bad_perms.is_empty() {
                            cx.ok("all .age files have mode 0600");
                        } else {
                            for (name, mode) in &bad_perms {
                                cx.warn(&format!("{name} has mode {mode:04o}, expected 0600"));
                            }
                        }
                    }
                }
            }
            #[cfg(not(unix))]
            {
                cx.ok("(permission check skipped on non-Unix)");
            }
        }
    }

    // 7. Orphan/phantom detection: count secrets in index vs actual .age files.
    {
        let mut cx = check!("Secret consistency");
        let secrets_dir = store_root.join("secrets");
        let index_path = store_root.join("index.jsonl");

        let index_names: HashSet<String> = match std::fs::read_to_string(&index_path) {
            Err(_) => HashSet::new(),
            Ok(content) => {
                let mut names = HashSet::new();
                for line in content.lines() {
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    if let Ok(entry) = serde_json::from_str::<oc_core::SecretIndexEntry>(trimmed) {
                        names.insert(entry.name);
                    }
                }
                names
            }
        };

        let file_names: HashSet<String> = match std::fs::read_dir(&secrets_dir) {
            Err(_) => HashSet::new(),
            Ok(entries) => entries
                .flatten()
                .filter(|e| e.path().extension().is_some_and(|ext| ext == "age"))
                .filter_map(|e| {
                    let fname = e.file_name();
                    let fname = fname.to_string_lossy();
                    fname.strip_suffix(".age").map(|s| s.replace("%2F", "/").replace("%25", "%"))
                })
                .collect(),
        };

        let orphans: Vec<&String> = file_names.difference(&index_names).collect();
        let phantoms: Vec<&String> = index_names.difference(&file_names).collect();

        if orphans.is_empty() && phantoms.is_empty() {
            cx.ok(&format!("{} secret(s), index and files match", index_names.len()));
        } else {
            if !orphans.is_empty() {
                for name in &orphans {
                    cx.warn(&format!("orphan .age file not in index: '{name}'"));
                }
            }
            if !phantoms.is_empty() {
                for name in &phantoms {
                    cx.warn(&format!("phantom index entry without .age file: '{name}'"));
                }
            }
        }
    }

    // 8. Config file exists and is parseable.
    {
        let mut cx = check!("Config file");
        let config_path = home.join("config.json");
        if !config_path.exists() {
            cx.warn(&format!("{} does not exist (using defaults)", config_path.display()));
        } else {
            match Config::load(&config_path) {
                Err(e) => {
                    cx.fail(&format!("parse error: {e}"));
                }
                Ok(_) => {
                    cx.ok(&format!("{}", config_path.display()));
                }
            }
        }
    }

    // 9. Git repo status (if git feature enabled).
    {
        let mut cx = check!("Git sync");
        #[cfg(feature = "git")]
        {
            let git_dir = store_root.join(".git");
            if git_dir.exists() {
                cx.ok("vault is a git repository");
            } else {
                cx.warn("vault is not a git repository (run `onecipher git init` to enable sync)");
            }
        }
        #[cfg(not(feature = "git"))]
        {
            if verbose {
                cx.ok("(git feature not compiled in)");
            }
        }
    }

    // Summary.
    eprintln!();
    if failures > 0 {
        eprintln!("doctor: {failures} failure(s), {warnings} warning(s) — fix failures before use");
    } else if warnings > 0 {
        eprintln!("doctor: 0 failures, {warnings} warning(s) — system is operational");
    } else {
        eprintln!("doctor: all checks passed");
    }

    if failures > 0 {
        Err(CliError::InvalidArgs(format!("{failures} diagnostic check(s) failed")))
    } else {
        Ok(())
    }
}

/// Helper struct for a single diagnostic check — tracks pass/warn/fail state.
struct CheckCx<'a> {
    label: &'a str,
    verbose: bool,
    warnings: &'a mut u32,
    failures: &'a mut u32,
}

impl<'a> CheckCx<'a> {
    fn ok(&self, detail: &str) {
        if self.verbose {
            eprintln!("  [OK]   {}: {}", self.label, detail);
        }
    }

    fn warn(&mut self, detail: &str) {
        *self.warnings += 1;
        eprintln!("  [WARN] {}: {}", self.label, detail);
    }

    fn fail(&mut self, detail: &str) {
        *self.failures += 1;
        eprintln!("  [FAIL] {}: {}", self.label, detail);
    }
}
