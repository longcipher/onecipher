//! Self-upgrade via external `curl`/`wget` (D11: zero in-process HTTP).
//!
//! Design: the `update` command performs NO in-process HTTP (no `hpx`,
//! `reqwest`, or `tokio` networking). It shells out to `curl -fsSL` (preferred)
//! or `wget -qO-` (fallback) to fetch the GitHub releases API, scans the
//! `tag_name` field with a minimal string scanner (no JSON dependency needed
//! on this path), compares versions NUMERICALLY per dot-separated component,
//! and downloads the release binary the same way. If neither `curl` nor
//! `wget` is installed, the command fails closed with actionable guidance
//! instead of silently doing nothing.

use std::{cmp::Ordering, path::PathBuf, process::Command};

const REPO: &str = "longcipher/onecipher";
const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

pub(crate) fn run(force: bool) -> Result<(), crate::CliError> {
    let install_dir = install_dir();

    let tag = get_latest_tag()?;
    let latest_version = tag.strip_prefix('v').unwrap_or(&tag);

    println!("installed: v{CURRENT_VERSION}");
    println!("   latest: {tag}");

    if !force && !is_newer_version(latest_version, CURRENT_VERSION) {
        println!("Already up to date.");
        return Ok(());
    }

    if force {
        println!("Forcing update...");
    } else {
        println!("Downloading update...");
    }

    let platform = detect_platform()?;
    let binary_url =
        format!("https://github.com/{REPO}/releases/download/{tag}/onecipher-{platform}");

    let tmp = tempfile::NamedTempFile::new()
        .map_err(|e| crate::CliError::InvalidArgs(format!("failed to create temp file: {e}")))?;
    let tmp_path = tmp.path().to_path_buf();

    // Download the binary
    download_binary(&binary_url, &tmp_path)?;

    // Install it
    std::fs::create_dir_all(&install_dir)
        .map_err(|e| crate::CliError::InvalidArgs(format!("failed to create install dir: {e}")))?;

    let dest = install_dir.join("onecipher");
    std::fs::copy(&tmp_path, &dest)
        .map_err(|e| crate::CliError::InvalidArgs(format!("failed to copy binary: {e}")))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| crate::CliError::InvalidArgs(format!("failed to set permissions: {e}")))?;
    }

    println!("Updated onecipher to {tag}");

    // Trigger vault migration in case the user is upgrading from lws
    oc_wallet::migrate::migrate_vault_if_needed();
    crate::update_shell_rc_paths(".lws/bin", ".onecipher/bin");
    crate::update_shell_rc_paths(".ows/bin", ".onecipher/bin");

    // Update language bindings
    update_node_bindings();
    update_python_bindings();

    Ok(())
}

/// Update Node.js bindings if npm is available.
fn update_node_bindings() {
    if Command::new("npm").arg("--version").output().is_err() {
        return;
    }

    // Check if already installed
    let check = Command::new("npm").args(["list", "-g", "@onecipher/core"]).output();

    match check {
        Ok(output) if output.status.success() => {
            println!("Updating Node bindings...");
            let status =
                Command::new("npm").args(["install", "-g", "@onecipher/core@latest"]).status();
            match status {
                Ok(s) if s.success() => println!("Node bindings updated."),
                _ => eprintln!("warn: failed to update Node bindings"),
            }
        }
        _ => {} // not installed, skip
    }
}

/// Update Python bindings if pip is available.
fn update_python_bindings() {
    // Try pip3 first, then python3 -m pip
    let pip_cmd = if Command::new("pip3").arg("--version").output().is_ok() {
        Some(("pip3", vec![]))
    } else if Command::new("python3").args(["-m", "pip", "--version"]).output().is_ok() {
        Some(("python3", vec!["-m", "pip"]))
    } else {
        None
    };

    let Some((cmd, prefix)) = pip_cmd else {
        return;
    };

    // Check if already installed
    let mut check = Command::new(cmd);
    for arg in &prefix {
        check.arg(arg);
    }
    check.args(["show", "onecipher"]);

    match check.output() {
        Ok(output) if output.status.success() => {
            println!("Updating Python bindings...");
            let mut upgrade = Command::new(cmd);
            for arg in &prefix {
                upgrade.arg(arg);
            }
            upgrade.args(["install", "--upgrade", "onecipher"]);
            match upgrade.status() {
                Ok(s) if s.success() => println!("Python bindings updated."),
                _ => eprintln!("warn: failed to update Python bindings"),
            }
        }
        _ => {} // not installed, skip
    }
}

/// Fetch a URL as text via `curl` (preferred) or `wget` (fallback).
///
/// Zero in-process HTTP: the only network I/O on this path is the child
/// `curl`/`wget` process. Both are invoked with a 30 s timeout so a hung
/// endpoint fails closed instead of hanging the CLI.
fn fetch_url_text(url: &str) -> Result<String, crate::CliError> {
    let bytes = fetch_url_bytes(url)?;
    String::from_utf8(bytes)
        .map_err(|e| crate::CliError::InvalidArgs(format!("non-UTF8 response from {url}: {e}")))
}

/// Fetch a URL as raw bytes via `curl` (preferred) or `wget` (fallback).
fn fetch_url_bytes(url: &str) -> Result<Vec<u8>, crate::CliError> {
    // Preferred: curl -fsSL (fail on HTTP error, silent, follow redirects,
    // 30 s max time) with the GitHub API Accept header (harmless for binary
    // downloads).
    if let Ok(out) = Command::new("curl")
        .args(["-fsSL", "--max-time", "30", "-H", "Accept: application/vnd.github+json", url])
        .output()
    {
        if out.status.success() {
            return Ok(out.stdout);
        }
    }
    // Fallback: wget -qO- (quiet, stdout) with timeout + header.
    if let Ok(out) = Command::new("wget")
        .args(["-qO-", "--timeout=30", "--header=Accept: application/vnd.github+json", url])
        .output()
    {
        if out.status.success() {
            return Ok(out.stdout);
        }
    }
    Err(crate::CliError::InvalidArgs(format!(
        "failed to fetch {url} — install `curl` or `wget` and check your network connection"
    )))
}

/// Fetch the latest release tag from the GitHub API via `curl`/`wget`.
///
/// Scans the `tag_name` field with a minimal string scanner (no serde needed
/// on this path — the CLI already depends on serde_json elsewhere, but the
/// scanner keeps this module dependency-light and robust to API shape drift).
fn get_latest_tag() -> Result<String, crate::CliError> {
    let api_url = format!("https://api.github.com/repos/{REPO}/releases/latest");
    let body = fetch_url_text(&api_url).map_err(|_| {
        crate::CliError::InvalidArgs(
            "failed to fetch latest release — check your network connection".to_string(),
        )
    })?;

    extract_json_string(&body, "tag_name").ok_or_else(|| {
        crate::CliError::InvalidArgs(
            "no releases found — push a version tag (e.g. v0.2.0) to create one".to_string(),
        )
    })
}

/// Download a binary from a URL via `curl`/`wget` into `dest`.
fn download_binary(url: &str, dest: &std::path::Path) -> Result<(), crate::CliError> {
    let bytes = fetch_url_bytes(url).map_err(|_| {
        crate::CliError::InvalidArgs(format!(
            "failed to download binary from {url} — no prebuilt binary for your platform?"
        ))
    })?;

    std::fs::write(dest, bytes)
        .map_err(|e| crate::CliError::InvalidArgs(format!("failed to write binary: {e}")))?;
    Ok(())
}

/// Returns `true` if `latest` is strictly newer than `current`.
///
/// Comparison is NUMERIC per dot-separated component (`0.9.10` > `0.9.9`,
/// which a lexicographic `>` gets wrong). A leading `v` is stripped. Missing
/// components compare as `0` (`1.2` == `1.2.0`). Non-numeric suffixes
/// (`-rc.1`, `+build`) compare lexically after the numeric prefix so
/// pre-releases sort below their release.
fn is_newer_version(latest: &str, current: &str) -> bool {
    compare_versions_numeric(latest, current) == Ordering::Greater
}

/// Numeric version comparison (see [`is_newer_version`]).
fn compare_versions_numeric(a: &str, b: &str) -> Ordering {
    let norm = |v: &str| v.strip_prefix('v').unwrap_or(v).trim().to_string();
    let (a, b) = (norm(a), norm(b));
    let split = |v: &str| {
        v.split('.')
            .map(|part| {
                let num_end = part.bytes().take_while(u8::is_ascii_digit).count();
                let num: u64 = part[..num_end].parse().unwrap_or(0);
                (num, part[num_end..].to_string())
            })
            .collect::<Vec<_>>()
    };
    let (pa, pb) = (split(&a), split(&b));
    for i in 0..pa.len().max(pb.len()) {
        let (na, sa) = pa.get(i).cloned().unwrap_or((0, String::new()));
        let (nb, sb) = pb.get(i).cloned().unwrap_or((0, String::new()));
        match na.cmp(&nb) {
            Ordering::Equal => {}
            other => return other,
        }
        // SemVer: a release (empty suffix) sorts above any pre-release
        // suffix, so `1.0.0` > `1.0.0-rc.1`. Lexical `cmp` alone gets this
        // backwards (`"-rc" > ""`), hence the explicit empty-check first.
        match (sa.is_empty(), sb.is_empty()) {
            (true, false) => return Ordering::Greater,
            (false, true) => return Ordering::Less,
            _ => match sa.cmp(&sb) {
                Ordering::Equal => {}
                other => return other,
            },
        }
    }
    Ordering::Equal
}

/// Detect the current platform in the same format as release assets.
fn detect_platform() -> Result<String, crate::CliError> {
    let os = if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "macos") {
        "darwin"
    } else {
        return Err(crate::CliError::InvalidArgs(
            "unsupported OS for prebuilt binaries".to_string(),
        ));
    };

    let arch = if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        return Err(crate::CliError::InvalidArgs(
            "unsupported architecture for prebuilt binaries".to_string(),
        ));
    };

    Ok(format!("{os}-{arch}"))
}

/// Minimal JSON string extractor (avoids serde dependency for this one command).
fn extract_json_string(json: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{}\"", key);
    let idx = json.find(&pattern)?;
    let rest = &json[idx + pattern.len()..];
    // skip `: "`  or `:"`
    let rest = rest.trim_start().strip_prefix(':')?.trim_start().strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn install_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("ONECIPHER_INSTALL_DIR") {
        PathBuf::from(dir)
    } else if let Ok(dir) = std::env::var("OWS_INSTALL_DIR") {
        PathBuf::from(dir)
    } else if let Ok(dir) = std::env::var("LWS_INSTALL_DIR") {
        PathBuf::from(dir)
    } else {
        dirs_or_home().join(".onecipher/bin")
    }
}

fn dirs_or_home() -> PathBuf {
    // `main()` validates HOME before dispatch, so the fallback is unreachable.
    oc_core::paths::home_dir().unwrap_or_else(|_| PathBuf::from("."))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_tag_name_scans_github_api_shape() {
        let body = r#"{"url":"https://api.github.com/repos/x/y/releases/1","tag_name":"v0.2.0","name":"v0.2.0"}"#;
        assert_eq!(extract_json_string(body, "tag_name").as_deref(), Some("v0.2.0"));
    }

    #[test]
    fn extract_tag_name_returns_none_when_missing() {
        assert_eq!(extract_json_string(r#"{"x":1}"#, "tag_name"), None);
    }

    #[test]
    fn numeric_compare_handles_multi_digit_components() {
        // Lexicographic compare gets this wrong ("0.9.10" < "0.9.9").
        assert_eq!(compare_versions_numeric("0.9.10", "0.9.9"), Ordering::Greater);
        assert_eq!(compare_versions_numeric("v0.2.0", "0.2.0"), Ordering::Equal);
        assert_eq!(compare_versions_numeric("1.2", "1.2.0"), Ordering::Equal);
        assert!(is_newer_version("0.2.0", "0.1.0"));
        assert!(!is_newer_version("0.1.0", "0.1.0"));
        assert!(!is_newer_version("0.1.0", "0.2.0"));
    }

    #[test]
    fn prerelease_sorts_below_release() {
        assert_eq!(compare_versions_numeric("1.0.0-rc.1", "1.0.0"), Ordering::Less);
    }
}
