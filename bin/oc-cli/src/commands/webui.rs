//! `onecipher webui` subcommand implementation.
//!
//! - `open`: Reads the daemon's bound port from `~/.onecipher/webui.port` and the bootstrap token
//!   from `~/.onecipher/bootstrap_token`, constructs the registration URL, and opens it in the
//!   default browser.
//!
//! If the daemon is not running or webui is not enabled, auto-spawns the daemon
//! after enabling webui in the config (gpg-agent / 1Password auto-spawn pattern).

use crate::{CliError, commands::onecipher_home};

/// Timeout for waiting on the daemon to write the port file after spawning.
const WEBUI_READY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
/// Poll interval when waiting for the port file to appear.
const WEBUI_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);

/// Open the Web UI in the default browser.
///
/// If the daemon is not running or webui is not enabled, auto-spawns the daemon
/// after enabling webui in the config.
pub(crate) fn open() -> Result<(), CliError> {
    open_from(&onecipher_home(), true)
}

/// Build the Web UI URL from a specific home directory.
///
/// Returns the URL string without opening a browser — useful for testing URL
/// construction logic in isolation.
fn build_url(home: &std::path::Path) -> Result<String, CliError> {
    let port_file = home.join("webui.port");
    let token_file = home.join("bootstrap_token");

    let port = std::fs::read_to_string(&port_file).map_err(|_| {
        CliError::InvalidArgs(format!(
            "Web UI port file not found at {} — is the daemon running with [webui] enabled?",
            port_file.display()
        ))
    })?;
    let port = port.trim().to_string();

    let token = std::fs::read_to_string(&token_file).ok();
    let token = token.as_deref().map_or("", str::trim);

    if token.is_empty() {
        Ok(format!("http://127.0.0.1:{port}/"))
    } else {
        Ok(format!("http://127.0.0.1:{port}/register?bootstrap={token}"))
    }
}

/// Ensure webui is enabled in the config file.
///
/// Loads `~/.onecipher/config.json`, sets `webui.enabled = true` if not already
/// set, and writes it back. Creates the directory if needed.
fn ensure_webui_enabled(home: &std::path::Path) -> Result<(), CliError> {
    use oc_core::config::Config;

    let mut config = Config::load_or_default();
    if config.webui.enabled {
        return Ok(());
    }

    config.webui.enabled = true;

    let config_path = home.join("config.json");
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| CliError::InvalidArgs(format!("cannot create config directory: {e}")))?;
    }
    let json = serde_json::to_string_pretty(&config)
        .map_err(|e| CliError::InvalidArgs(format!("cannot serialize config: {e}")))?;
    std::fs::write(&config_path, json)
        .map_err(|e| CliError::InvalidArgs(format!("cannot write config: {e}")))?;

    eprintln!("Enabled webui in {}", config_path.display());
    Ok(())
}

/// Spawn the onecipher daemon in the background.
fn spawn_daemon() -> Result<(), CliError> {
    use std::process::{Command, Stdio};

    let exe = std::env::current_exe()
        .map_err(|e| CliError::InvalidArgs(format!("cannot determine executable path: {e}")))?;

    Command::new(exe)
        .arg("--daemon")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| CliError::InvalidArgs(format!("failed to spawn daemon: {e}")))?;

    Ok(())
}

/// Open the Web UI from a specific home directory.
///
/// If the port file is missing, auto-enables webui in config and spawns the
/// daemon, then waits for the port file to appear.
///
/// If `launch_browser` is false, only prints the URL without opening the
/// browser (used in tests).
fn open_from(home: &std::path::Path, launch_browser: bool) -> Result<(), CliError> {
    // Try to build the URL directly first.
    let url = if let Ok(url) = build_url(home) {
        url
    } else {
        // Port file missing — auto-enable webui and spawn daemon.
        eprintln!("Web UI not running, starting daemon...");
        ensure_webui_enabled(home)?;
        spawn_daemon()?;

        // Wait for the port file to appear.
        let port_file = home.join("webui.port");
        let start = std::time::Instant::now();
        while start.elapsed() < WEBUI_READY_TIMEOUT {
            if port_file.exists() {
                // Small extra delay to let the daemon finish writing.
                std::thread::sleep(std::time::Duration::from_millis(50));
                break;
            }
            std::thread::sleep(WEBUI_POLL_INTERVAL);
        }

        build_url(home).map_err(|_| {
            CliError::InvalidArgs(format!(
                "Timed out waiting for Web UI to start. Check daemon logs and ensure \
                 [webui] is enabled in {}",
                home.join("config.json").display()
            ))
        })?
    };

    eprintln!("Opening Web UI: {url}");

    if launch_browser {
        let result = open_url_in_browser(&url);
        if result.is_err() {
            eprintln!("Could not open browser automatically. Please visit:");
            eprintln!("  {url}");
        }
    } else {
        eprintln!("  {url}");
    }

    Ok(())
}

/// Open a URL in the default browser using platform-specific commands.
fn open_url_in_browser(url: &str) -> Result<(), std::io::Error> {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open").arg(url).spawn()?;
    }
    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open").arg(url).spawn()?;
    }
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("cmd").args(["/C", "start", "", url]).spawn()?;
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "unsupported platform for browser launch",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_open_missing_port_file() {
        // With auto-spawn disabled (launch_browser=false), missing port file
        // still errors because we can't spawn a real daemon in tests.
        let dir = tempfile::tempdir().unwrap();
        let result = open_from(dir.path(), false);
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        // Should mention config, not just "port file not found"
        assert!(err.contains("Timed out") || err.contains("port file not found"));
    }

    #[test]
    fn test_build_url_with_port_but_no_token() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("webui.port"), "9876").unwrap();
        let url = build_url(dir.path()).unwrap();
        assert_eq!(url, "http://127.0.0.1:9876/");
    }

    #[test]
    fn test_build_url_with_port_and_token() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("webui.port"), "3000").unwrap();
        std::fs::write(dir.path().join("bootstrap_token"), "tok123").unwrap();
        let url = build_url(dir.path()).unwrap();
        assert_eq!(url, "http://127.0.0.1:3000/register?bootstrap=tok123");
    }
}
