//! systemd user-service management for the onecipher daemon.
//!
//! - `onecipher service install` — write `~/.config/systemd/user/onecipher.service` pointing at the
//!   current binary with `--daemon`, then best-effort `systemctl --user daemon-reload` + `enable
//!   --now`.
//! - `onecipher service uninstall` — best-effort `disable --now`, then remove the unit file.
//! - `onecipher service status` — report whether the unit file exists and best-effort print
//!   `systemctl --user status`.
//!
//! Every `systemctl` invocation is best-effort: on systems without systemd
//! (or without a user manager) the unit file is still written/removed and the
//! command reports what could not be done. Panic-free by construction.

use std::path::PathBuf;

use crate::CliError;

/// Unit file name (also the systemd unit name used with `systemctl --user`).
const UNIT_NAME: &str = "onecipher.service";

/// Directory for systemd user units.
fn systemd_user_dir() -> Result<PathBuf, CliError> {
    let home = oc_core::paths::home_dir()?;
    Ok(home.join(".config").join("systemd").join("user"))
}

/// Absolute path of the unit file.
fn unit_path() -> Result<PathBuf, CliError> {
    Ok(systemd_user_dir()?.join(UNIT_NAME))
}

/// Run `systemctl --user <args...>`, capturing output.
///
/// Returns `Ok(Some(status))` when systemctl ran (even with a non-zero exit),
/// `Ok(None)` when the binary is unavailable.
fn run_systemctl(args: &[&str]) -> Option<std::process::ExitStatus> {
    let output = std::process::Command::new("systemctl").arg("--user").args(args).output().ok()?;
    Some(output.status)
}

fn report_systemctl_unavailable(action: &str) {
    eprintln!(
        "warning: 'systemctl' is not available — could not {action} the \
         onecipher user service automatically"
    );
}

/// `onecipher service install`
pub(crate) fn install() -> Result<(), CliError> {
    let exe = std::env::current_exe().map_err(|e| {
        CliError::InvalidArgs(format!("cannot resolve current executable path: {e}"))
    })?;

    let dir = systemd_user_dir()?;
    std::fs::create_dir_all(&dir).map_err(CliError::Io)?;

    let unit = format!(
        "[Unit]\n\
         Description=OneCipher wallet daemon (WC v2 wallet + signing engine)\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         ExecStart={} --daemon\n\
         Restart=on-failure\n\
         RestartSec=2\n\
         \n\
         [Install]\n\
         WantedBy=default.target\n",
        exe.display()
    );
    let path = unit_path()?;
    std::fs::write(&path, unit).map_err(CliError::Io)?;
    println!("Wrote systemd user unit: {}", path.display());

    match run_systemctl(&["daemon-reload"]) {
        Some(status) if status.success() => println!("systemctl --user daemon-reload: ok"),
        Some(status) => {
            eprintln!("warning: systemctl --user daemon-reload exited with {status}");
        }
        None => report_systemctl_unavailable("daemon-reload"),
    }

    match run_systemctl(&["enable", "--now", UNIT_NAME]) {
        Some(status) if status.success() => {
            println!("systemctl --user enable --now {UNIT_NAME}: ok");
        }
        Some(status) => {
            eprintln!("warning: systemctl --user enable --now {UNIT_NAME} exited with {status}");
        }
        None => report_systemctl_unavailable("enable/start the service"),
    }

    Ok(())
}

/// `onecipher service uninstall`
pub(crate) fn uninstall() -> Result<(), CliError> {
    match run_systemctl(&["disable", "--now", UNIT_NAME]) {
        Some(status) if status.success() => {
            println!("systemctl --user disable --now {UNIT_NAME}: ok");
        }
        Some(status) => {
            eprintln!("warning: systemctl --user disable --now {UNIT_NAME} exited with {status}");
        }
        None => report_systemctl_unavailable("disable/stop the service"),
    }

    let path = unit_path()?;
    if path.exists() {
        std::fs::remove_file(&path).map_err(CliError::Io)?;
        println!("Removed systemd user unit: {}", path.display());
    } else {
        println!("No unit file at {} (already uninstalled)", path.display());
    }
    Ok(())
}

/// `onecipher service status`
pub(crate) fn status() -> Result<(), CliError> {
    let path = unit_path()?;
    if path.exists() {
        println!("Unit file: {} (present)", path.display());
    } else {
        println!("Unit file: {} (NOT installed)", path.display());
    }

    match std::process::Command::new("systemctl")
        .arg("--user")
        .arg("status")
        .arg("--no-pager")
        .arg(UNIT_NAME)
        .output()
    {
        Ok(output) => {
            print!("{}", String::from_utf8_lossy(&output.stdout));
            if !output.stderr.is_empty() {
                eprint!("{}", String::from_utf8_lossy(&output.stderr));
            }
        }
        Err(e) => {
            eprintln!("warning: could not run systemctl --user status: {e}");
        }
    }
    Ok(())
}
