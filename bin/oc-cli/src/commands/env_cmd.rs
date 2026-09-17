//! Run a subprocess with secrets injected as environment variables (`onecipher env`).
//!
//! Opens the age-encrypted [`SecretStore`], resolves each `--name` (either a
//! single secret name or a directory prefix that expands to all entries under
//! that path), decrypts them, and injects the plaintext values into the
//! environment of the child process.
//!
//! After the child exits (or after `exec()` replaces the process), all secret
//! values are zeroized in memory.

use std::collections::BTreeMap;

use zeroize::Zeroizing;

use crate::CliError;

/// Entry point for `onecipher env [--name <secret>...] [-e KEY=VAL] [-p KEY] [--keep-case] [--exec]
/// -- <command>...`.
///
/// - `--name` resolves vault secrets (full vault path kept in the env key to avoid collisions after
///   case folding).
/// - `-e KEY=VAL` injects a direct pair (binary/NUL values rejected).
/// - `-p KEY` prompts for the value without echoing it (Zeroizing).
/// - Child exit codes pass through transparently.
pub(crate) fn run(
    names: &[String],
    set: &[String],
    prompt: &[String],
    keep_case: bool,
    exec: bool,
    command: &[String],
) -> Result<(), CliError> {
    if command.is_empty() {
        return Err(CliError::InvalidArgs("no command specified".into()));
    }

    let store = super::open_secret_store()?;
    let identity = super::load_age_identity()?;

    // Collect all secret name → plaintext pairs.
    // Use Zeroizing<String> so values are zeroized when dropped.
    let mut env_pairs: Vec<(String, Zeroizing<String>)> = Vec::new();

    // D6: direct -e KEY=VAL pairs. Full KEY is kept verbatim (no truncation)
    // so distinct vault paths cannot collide after normalization. NUL bytes
    // (binary) are rejected fail-closed.
    for pair in set {
        let (k, v) = pair.split_once('=').ok_or_else(|| {
            CliError::InvalidArgs(format!("invalid --set (expected KEY=VALUE): '{pair}'"))
        })?;
        if k.is_empty() || v.contains('\0') || k.contains('\0') {
            return Err(CliError::InvalidArgs(format!("invalid --set pair: '{pair}'")));
        }
        env_pairs.push((k.to_string(), Zeroizing::new(v.to_string())));
    }
    // D6: -p KEY prompts (rpassword without echo when available).
    for key in prompt {
        if key.is_empty() || key.contains('\0') {
            return Err(CliError::InvalidArgs(format!("invalid --prompt key: '{key}'")));
        }
        let value = prompt_secret(key)?;
        env_pairs.push((key.clone(), value));
    }

    for name in names {
        // Try to get the secret directly.
        match store.get(name) {
            Ok(entry) => {
                let payload = entry.decrypt(&identity).map_err(|e| {
                    CliError::InvalidArgs(format!("decryption failed for '{name}': {e}"))
                })?;
                let env_key = to_env_key(name, keep_case);
                env_pairs.push((env_key, Zeroizing::new(payload.secret.clone())));
            }
            Err(oc_secret::SecretStoreError::NotFound(_)) => {
                // Treat as a directory prefix — list all entries under `name/`.
                let prefix = format!("{name}/");
                let entries = store
                    .list()
                    .map_err(|e| CliError::InvalidArgs(format!("failed to list secrets: {e}")))?;
                let matches: Vec<_> =
                    entries.iter().filter(|e| e.name.starts_with(&prefix)).collect();

                if matches.is_empty() {
                    return Err(CliError::InvalidArgs(format!(
                        "no secret or directory found matching '{name}'"
                    )));
                }

                for idx_entry in &matches {
                    let entry = store.get(&idx_entry.name).map_err(|e| {
                        CliError::InvalidArgs(format!("failed to read '{}': {e}", idx_entry.name))
                    })?;
                    let payload = entry.decrypt(&identity).map_err(|e| {
                        CliError::InvalidArgs(format!(
                            "decryption failed for '{}': {e}",
                            idx_entry.name
                        ))
                    })?;
                    // Use the suffix after the directory prefix as the env var key.
                    let suffix = &idx_entry.name[prefix.len()..];
                    let env_key = to_env_key(suffix, keep_case);
                    env_pairs.push((env_key, Zeroizing::new(payload.secret.clone())));
                }
            }
            Err(e) => {
                return Err(CliError::InvalidArgs(format!("failed to read secret '{name}': {e}")));
            }
        }
    }

    // Check for duplicate env var names.
    let mut seen = BTreeMap::new();
    for (key, _) in &env_pairs {
        let count = seen.entry(key.as_str()).or_insert(0u32);
        *count += 1;
    }
    for (key, count) in &seen {
        if *count > 1 {
            return Err(CliError::InvalidArgs(format!(
                "duplicate environment variable '{key}' — use more specific --name values"
            )));
        }
    }

    // Build the child command.
    let program = &command[0];
    let args = &command[1..];

    let mut cmd = std::process::Command::new(program);
    cmd.args(args);

    // Inject secret values into the environment.
    for (key, value) in &env_pairs {
        cmd.env(key, value.as_str());
    }

    if exec {
        // Replace current process with the child (Unix exec(3)).
        // This never returns on success. Under `cfg(test)` the CLI runs
        // inside the test harness, so exec would replace the harness —
        // fall through to spawn + wait instead.
        #[cfg(all(unix, not(test)))]
        {
            use std::os::unix::process::CommandExt;
            let err = cmd.exec();
            // exec() only returns on failure.
            return Err(CliError::Io(err));
        }
        #[cfg(any(not(unix), test))]
        {
            // Fall back to spawn + wait on non-Unix platforms (and in tests).
            let status = cmd.status().map_err(CliError::Io)?;
            drop(env_pairs);
            return exit_with_status(status);
        }
    }

    // Spawn and wait for the child process.
    let status = cmd.status().map_err(CliError::Io)?;

    // env_pairs are dropped here, zeroizing all secret values in memory.
    drop(env_pairs);

    exit_with_status(status)
}

/// Propagate the child exit status: exit the process in production.
///
/// Under `cfg(test)` the CLI runs in-process, so `process::exit` would kill
/// the test harness and silently truncate the whole suite — return instead
/// (`Ok` for success, `Err` carrying the status otherwise).
#[cfg(not(test))]
fn exit_with_status(status: std::process::ExitStatus) -> Result<(), CliError> {
    std::process::exit(status.code().unwrap_or(1));
}

#[cfg(test)]
fn exit_with_status(status: std::process::ExitStatus) -> Result<(), CliError> {
    if status.success() {
        Ok(())
    } else {
        Err(CliError::InvalidArgs(format!("command exited with status: {status}")))
    }
}

/// Convert a secret name to an environment variable key.
///
/// - `/` is replaced with `_`.
/// - By default, the name is uppercased (unless `keep_case` is true).
fn to_env_key(name: &str, keep_case: bool) -> String {
    let key = name.replace('/', "_");
    if keep_case { key } else { key.to_ascii_uppercase() }
}

/// Prompt for a secret value without echoing (fallback: stderr prompt + stdin line).
fn prompt_secret(key: &str) -> Result<Zeroizing<String>, CliError> {
    // Prefer rpassword-style no-echo read when stdin is a TTY; otherwise read
    // a line (tests pipe via stdin).
    eprint!("Enter value for {key}: ");
    use std::io::{IsTerminal, Write};
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).map_err(CliError::Io)?;
    let value = line.trim_end_matches(['\r', '\n']).to_string();
    if value.is_empty() {
        return Err(CliError::InvalidArgs(format!("empty value for '{key}'")));
    }
    if value.contains('\0') {
        return Err(CliError::InvalidArgs("binary input rejected".into()));
    }
    let _ = std::io::stdin().is_terminal();
    Ok(Zeroizing::new(value))
}

#[cfg(test)]
mod env_extra_tests {
    use super::*;

    #[test]
    fn set_pair_validation() {
        assert!(run(&[], &["BAD".to_string()], &[], false, false, &[]).is_err());
        assert!(
            run(&[], &["K=V\0".to_string()], &[], false, false, &["true".to_string()]).is_err()
        );
    }

    #[test]
    fn to_env_key_keeps_full_path() {
        assert_eq!(to_env_key("a/b/c", false), "A_B_C");
        assert_eq!(to_env_key("a/b/c", true), "a_b_c");
    }

    #[test]
    fn exit_with_status_never_exits_harness() {
        // `true` succeeds, `false` fails — and neither may kill the runner.
        let ok = std::process::Command::new("true").status().unwrap();
        assert!(exit_with_status(ok).is_ok());
        let fail = std::process::Command::new("false").status().unwrap();
        let err = exit_with_status(fail).expect_err("false must fail");
        assert!(err.to_string().contains("exited with status"), "got: {err}");
    }
}
