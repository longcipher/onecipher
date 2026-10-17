//! Run a subprocess with secrets injected as environment variables (`onecipher env`).
//!
//! Opens the age-encrypted [`SecretStore`], resolves each `--name` (either a
//! single secret name or a directory prefix that expands to all entries under
//! that path), optional `--reference KEY=oc://secret?...` bindings, and injects
//! the plaintext values into the environment of the child process.
//!
//! `--print` emits the resolved environment in `dotenv` or `json` form instead
//! of spawning a child. This is the agent/plugin-friendly path: config files
//! keep stable secret references while plaintext only materializes at runtime.
//!
//! After the child exits (or after `exec()` replaces the process), all secret
//! values are zeroized in memory.

use std::{
    collections::{BTreeMap, btree_map::Entry},
    path::PathBuf,
};

use zeroize::Zeroizing;

use crate::CliError;

pub(crate) struct EnvRunOptions<'a> {
    pub names: &'a [String],
    pub set: &'a [String],
    pub prompt: &'a [String],
    pub references: &'a [String],
    pub manifest: Option<&'a PathBuf>,
    pub environment: Option<&'a str>,
    pub keep_case: bool,
    pub exec: bool,
    pub print: bool,
    pub validate: bool,
    pub format: &'a str,
    pub command: &'a [String],
}

/// Entry point for `onecipher env [--name <secret>...] [-e KEY=VAL] [-p KEY] [--keep-case] [--exec]
/// [--reference KEY=oc://secret?field=...] [--manifest PATH] [--environment NAME]
/// [--print|--validate] [--format dotenv|json] -- <command>...`.
///
/// - `--name` resolves vault secrets (full vault path kept in the env key to avoid collisions after
///   case folding).
/// - `-e KEY=VAL` injects a direct pair (binary/NUL values rejected).
/// - `-p KEY` prompts for the value without echoing it (Zeroizing).
/// - `--reference KEY=oc://...` resolves a specific secret reference into `KEY`.
/// - `--manifest` + `--environment` load project environment references from
///   `.onecipher/environments.toml`.
/// - `--print` renders the resolved environment instead of running a child.
/// - `--validate` verifies project / explicit references without printing secret values.
/// - Child exit codes pass through transparently.
pub(crate) fn run(options: EnvRunOptions<'_>) -> Result<(), CliError> {
    let EnvRunOptions {
        names,
        set,
        prompt,
        references,
        manifest,
        environment,
        keep_case,
        exec,
        print,
        validate,
        format,
        command,
    } = options;
    if (print || validate) && exec {
        return Err(CliError::InvalidArgs(
            "--print/--validate and --exec cannot be used together".into(),
        ));
    }
    if print && validate {
        return Err(CliError::InvalidArgs("--print and --validate cannot be used together".into()));
    }
    if (print || validate) && !command.is_empty() {
        return Err(CliError::InvalidArgs(
            "--print/--validate do not accept a child command".into(),
        ));
    }
    if !print && !validate && command.is_empty() {
        return Err(CliError::InvalidArgs(
            "no command specified (use --print or --validate to avoid running a child command)"
                .into(),
        ));
    }
    if validate && (!names.is_empty() || !set.is_empty() || !prompt.is_empty()) {
        return Err(CliError::InvalidArgs(
            "--validate only supports --reference and manifest-backed environments".into(),
        ));
    }

    let manifest_bindings = load_manifest_bindings(manifest, environment)?;
    let mut reference_bindings = manifest_bindings.bindings.clone();
    reference_bindings.extend(references.iter().cloned());

    if validate {
        if reference_bindings.is_empty() {
            return Err(CliError::InvalidArgs(
                "--validate requires --reference or --manifest/--environment".into(),
            ));
        }
        let store = super::open_secret_store()?;
        let identity = super::load_age_identity()?;
        let report =
            validate_reference_pairs(&store, &identity, &reference_bindings, manifest_bindings)?;
        print_validation_report(&report, format)?;
        if report.entries.iter().all(|entry| entry.ok) {
            return Ok(());
        }
        return Err(CliError::InvalidArgs(format!(
            "environment validation failed ({} of {} bindings failed)",
            report.entries.iter().filter(|entry| !entry.ok).count(),
            report.entries.len()
        )));
    }

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

    if !names.is_empty() || !reference_bindings.is_empty() {
        let store = super::open_secret_store()?;
        let identity = super::load_age_identity()?;
        resolve_named_pairs(&store, &identity, names, keep_case, &mut env_pairs)?;
        resolve_reference_pairs(&store, &identity, &reference_bindings, &mut env_pairs)?;
    }

    reject_duplicate_keys(&env_pairs)?;

    if print {
        let rendered = render_env_pairs(&env_pairs, format)?;
        println!("{rendered}");
        return Ok(());
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

fn resolve_named_pairs(
    store: &oc_secret::SecretStore,
    identity: &oc_secret::AgeIdentity,
    names: &[String],
    keep_case: bool,
    env_pairs: &mut Vec<(String, Zeroizing<String>)>,
) -> Result<(), CliError> {
    for name in names {
        // Try to get the secret directly.
        match store.get(name) {
            Ok(entry) => {
                let payload = entry.decrypt(identity).map_err(|e| {
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
                    let payload = entry.decrypt(identity).map_err(|e| {
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
    Ok(())
}

fn resolve_reference_pairs(
    store: &oc_secret::SecretStore,
    identity: &oc_secret::AgeIdentity,
    references: &[String],
    env_pairs: &mut Vec<(String, Zeroizing<String>)>,
) -> Result<(), CliError> {
    for pair in references {
        let (key, _raw_reference, reference) = super::env_support::parse_reference_binding(pair)?;
        let value = super::env_support::resolve_reference(store, identity, &reference)?;
        env_pairs.push((key, value));
    }
    Ok(())
}

fn reject_duplicate_keys(env_pairs: &[(String, Zeroizing<String>)]) -> Result<(), CliError> {
    let mut seen = BTreeMap::new();
    for (key, _) in env_pairs {
        let count = seen.entry(key.as_str()).or_insert(0u32);
        *count += 1;
    }
    for (key, count) in &seen {
        if *count > 1 {
            return Err(CliError::InvalidArgs(format!(
                "duplicate environment variable '{key}' — use more specific --name values or references"
            )));
        }
    }
    Ok(())
}

fn render_env_pairs(
    env_pairs: &[(String, Zeroizing<String>)],
    format: &str,
) -> Result<String, CliError> {
    let mut ordered = BTreeMap::new();
    for (key, value) in env_pairs {
        match ordered.entry(key.clone()) {
            Entry::Vacant(slot) => {
                slot.insert(value.as_str().to_string());
            }
            Entry::Occupied(_) => {
                return Err(CliError::InvalidArgs(format!(
                    "duplicate environment variable '{key}' — cannot render"
                )));
            }
        }
    }

    match format {
        "dotenv" => Ok(ordered
            .iter()
            .map(|(key, value)| format!("{key}={}", dotenv_quote(value)))
            .collect::<Vec<_>>()
            .join("\n")),
        "json" => serde_json::to_string_pretty(&ordered).map_err(Into::into),
        other => Err(CliError::InvalidArgs(format!(
            "invalid --format '{other}' (expected: dotenv, json)"
        ))),
    }
}

fn dotenv_quote(value: &str) -> String {
    let escaped = value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t");
    format!("\"{escaped}\"")
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

#[derive(Debug, Clone)]
struct ManifestBindings {
    path: Option<PathBuf>,
    environment: Option<String>,
    bindings: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct ValidationReport {
    #[serde(skip_serializing_if = "Option::is_none")]
    manifest_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    environment: Option<String>,
    entries: Vec<super::env_support::ReferenceValidation>,
}

fn load_manifest_bindings(
    manifest: Option<&PathBuf>,
    environment: Option<&str>,
) -> Result<ManifestBindings, CliError> {
    if manifest.is_none() && environment.is_none() {
        return Ok(ManifestBindings { path: None, environment: None, bindings: Vec::new() });
    }
    let path =
        super::env_manifest::resolve_manifest_path(manifest.map(std::path::PathBuf::as_path))?;
    let parsed = super::env_manifest::EnvironmentManifest::load(&path)?;
    let selected_environment = parsed.selected_environment_name(environment)?.to_string();
    let bindings = parsed
        .bindings_for(Some(selected_environment.as_str()))?
        .into_iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect();
    Ok(ManifestBindings { path: Some(path), environment: Some(selected_environment), bindings })
}

fn validate_reference_pairs(
    store: &oc_secret::SecretStore,
    identity: &oc_secret::AgeIdentity,
    references: &[String],
    manifest_bindings: ManifestBindings,
) -> Result<ValidationReport, CliError> {
    let mut entries = Vec::new();
    for pair in references {
        let (key, raw_reference, reference) = super::env_support::parse_reference_binding(pair)?;
        entries.push(super::env_support::validate_reference_binding(
            store,
            identity,
            &key,
            &raw_reference,
            &reference,
        ));
    }
    Ok(ValidationReport {
        manifest_path: manifest_bindings.path.map(|path| path.display().to_string()),
        environment: manifest_bindings.environment,
        entries,
    })
}

fn print_validation_report(report: &ValidationReport, format: &str) -> Result<(), CliError> {
    match format {
        "json" => {
            println!("{}", serde_json::to_string_pretty(report)?);
            Ok(())
        }
        "dotenv" | "summary" => {
            if let Some(path) = &report.manifest_path {
                println!("manifest: {path}");
            }
            if let Some(environment) = &report.environment {
                println!("environment: {environment}");
            }
            for entry in &report.entries {
                if entry.ok {
                    println!(
                        "ok   {} -> {} ({})",
                        entry.key,
                        entry.secret_name,
                        entry.field.as_str()
                    );
                } else {
                    println!(
                        "fail {} -> {} ({}) :: {}",
                        entry.key,
                        entry.secret_name,
                        entry.field.as_str(),
                        entry.error.as_deref().unwrap_or("unknown error")
                    );
                }
            }
            Ok(())
        }
        other => Err(CliError::InvalidArgs(format!(
            "invalid --format '{other}' (expected: dotenv, json, summary)"
        ))),
    }
}

#[cfg(test)]
mod env_extra_tests {
    use super::*;
    use crate::commands::env_support;

    #[test]
    fn set_pair_validation() {
        assert!(
            run(EnvRunOptions {
                names: &[],
                set: &["BAD".to_string()],
                prompt: &[],
                references: &[],
                manifest: None,
                environment: None,
                keep_case: false,
                exec: false,
                print: false,
                validate: false,
                format: "dotenv",
                command: &[],
            },)
            .is_err()
        );
        assert!(
            run(EnvRunOptions {
                names: &[],
                set: &["K=V\0".to_string()],
                prompt: &[],
                references: &[],
                manifest: None,
                environment: None,
                keep_case: false,
                exec: false,
                print: false,
                validate: false,
                format: "dotenv",
                command: &["true".to_string()],
            },)
            .is_err()
        );
    }

    #[test]
    fn to_env_key_keeps_full_path() {
        assert_eq!(to_env_key("a/b/c", false), "A_B_C");
        assert_eq!(to_env_key("a/b/c", true), "a_b_c");
    }

    #[test]
    fn parse_secret_reference_supports_fields() {
        assert_eq!(
            env_support::parse_secret_reference("oc://api/openai?field=otp").unwrap(),
            env_support::SecretReference {
                name: "api/openai".into(),
                field: env_support::SecretReferenceField::Otp
            }
        );
        assert_eq!(
            env_support::parse_secret_reference("oc:///api/openai").unwrap(),
            env_support::SecretReference {
                name: "api/openai".into(),
                field: env_support::SecretReferenceField::Secret
            }
        );
    }

    #[test]
    fn render_env_pairs_supports_dotenv_and_json() {
        let env_pairs = vec![
            ("OPENAI_API_KEY".to_string(), Zeroizing::new("sk-test".to_string())),
            ("MULTILINE".to_string(), Zeroizing::new("line1\nline2".to_string())),
        ];
        let dotenv = render_env_pairs(&env_pairs, "dotenv").unwrap();
        assert!(dotenv.contains("OPENAI_API_KEY=\"sk-test\""));
        assert!(dotenv.contains("MULTILINE=\"line1\\nline2\""));

        let json = render_env_pairs(&env_pairs, "json").unwrap();
        assert!(json.contains("\"OPENAI_API_KEY\""));
        assert!(json.contains("\"sk-test\""));
    }

    #[test]
    fn validate_report_supports_json_and_summary() {
        let report = ValidationReport {
            manifest_path: Some("/tmp/project/.onecipher/environments.toml".into()),
            environment: Some("default".into()),
            entries: vec![env_support::ReferenceValidation {
                key: "OPENAI_API_KEY".into(),
                reference: "oc://api/openai".into(),
                secret_name: "api/openai".into(),
                field: env_support::SecretReferenceField::Secret,
                ok: true,
                error: None,
            }],
        };
        assert!(print_validation_report(&report, "json").is_ok());
        assert!(print_validation_report(&report, "summary").is_ok());
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
