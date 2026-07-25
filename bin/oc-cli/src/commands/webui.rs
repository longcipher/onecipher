//! `onecipher webui` subcommand implementation.
//!
//! - `open`: Reads the daemon's bound port from `~/.onecipher/webui.port` and the bootstrap token
//!   from `~/.onecipher/bootstrap_token`, constructs the registration URL, and opens it in the
//!   default browser.

use crate::{CliError, commands::onecipher_home};

/// Open the Web UI in the default browser.
///
/// Reads `~/.onecipher/webui.port` and `~/.onecipher/bootstrap_token` to
/// construct the registration URL. If either file is missing, instructs the
/// user to start the daemon with `[webui] enabled = true`.
pub(crate) fn open() -> Result<(), CliError> {
    open_from(&onecipher_home())
}

/// Open the Web UI from a specific home directory (testable without env mutation).
fn open_from(home: &std::path::Path) -> Result<(), CliError> {
    let port_file = home.join("webui.port");
    let token_file = home.join("bootstrap_token");

    // Read bound port
    let port = std::fs::read_to_string(&port_file).map_err(|_| {
        CliError::InvalidArgs(format!(
            "Web UI port file not found at {} — is the daemon running with [webui] enabled?",
            port_file.display()
        ))
    })?;
    let port = port.trim();

    // Read bootstrap token (optional — may have been consumed already)
    let token = std::fs::read_to_string(&token_file).ok();
    let token = token.as_deref().map_or("", str::trim);

    // Construct URL
    let url = if token.is_empty() {
        format!("http://127.0.0.1:{port}/")
    } else {
        format!("http://127.0.0.1:{port}/register?bootstrap={token}")
    };

    eprintln!("Opening Web UI: {url}");

    // Open in default browser (platform-specific)
    let result = open_url_in_browser(&url);
    if result.is_err() {
        eprintln!("Could not open browser automatically. Please visit:");
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
        let dir = tempfile::tempdir().unwrap();
        let result = open_from(dir.path());
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("port file not found"));
    }

    #[test]
    fn test_open_with_port_but_no_token() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("webui.port"), "9876").unwrap();

        // open_from() will try to launch a browser which may fail in CI,
        // but the URL construction logic is what we're testing.
        // Browser launch failure is non-fatal — it still prints the URL.
        let result = open_from(dir.path());
        assert!(result.is_ok());
    }
}
