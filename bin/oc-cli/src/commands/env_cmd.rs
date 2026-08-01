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

/// Entry point for `onecipher env [--name <secret>...] [--keep-case] [--exec] -- <command>...`.
pub(crate) fn run(
    names: &[String],
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

    for name in names {
        // Try to get the secret directly.
        match store.get(name) {
            Ok(entry) => {
                let payload = entry.decrypt(&identity).map_err(|e| {
                    CliError::InvalidArgs(format!("decryption failed for '{name}': {e}"))
                })?;
                let env_key = to_env_key(name, keep_case);
                env_pairs.push((env_key, Zeroizing::new(payload.secret)));
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
                    env_pairs.push((env_key, Zeroizing::new(payload.secret)));
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
        // This never returns on success.
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            let err = cmd.exec();
            // exec() only returns on failure.
            return Err(CliError::Io(err));
        }
        #[cfg(not(unix))]
        {
            // Fall back to spawn + wait on non-Unix platforms.
            let status = cmd.status().map_err(CliError::Io)?;
            std::process::exit(status.code().unwrap_or(1));
        }
    }

    // Spawn and wait for the child process.
    let status = cmd.status().map_err(CliError::Io)?;

    // env_pairs are dropped here, zeroizing all secret values in memory.

    std::process::exit(status.code().unwrap_or(1));
}

/// Convert a secret name to an environment variable key.
///
/// - `/` is replaced with `_`.
/// - By default, the name is uppercased (unless `keep_case` is true).
fn to_env_key(name: &str, keep_case: bool) -> String {
    let key = name.replace('/', "_");
    if keep_case { key } else { key.to_ascii_uppercase() }
}
