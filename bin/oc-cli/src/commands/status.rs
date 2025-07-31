//! Status CLI — local check of Key-Agent socket, vault, and WC v2 daemon.
//!
//! `onecipher status` is a LOCAL operation: it probes the UDS sockets and
//! lists wallets from the vault. No RPC is sent to the Key-Agent or
//! Network-Agent.

use std::os::unix::net::UnixStream;

use oc_core::Config;

use crate::CliError;

/// Entry point for `onecipher status`.
pub(crate) fn run() -> Result<(), CliError> {
    // --- Key-Agent socket probe ---
    let ka_socket = oc_keyagent::server::default_socket_path();
    let ka_status = match UnixStream::connect(&ka_socket) {
        Ok(_) => {
            // Connection succeeded — Key-Agent is running. Dropping the
            // stream closes it cleanly.
            "RUNNING".to_string()
        }
        Err(_) => "STOPPED".to_string(),
    };
    eprintln!("Key-Agent: {ka_status} (socket: {ka_socket})");

    // --- Vault status ---
    let vault_path = Config::default().vault_path;
    let wallets = oc_wallet::list_wallets(None).unwrap_or_default();
    if wallets.is_empty() {
        eprintln!("Vault:     EMPTY (no wallets) at {}", vault_path.display());
    } else {
        eprintln!("Vault:     {} ({} wallet(s))", vault_path.display(), wallets.len());
    }

    // --- WC v2 daemon control socket probe ---
    let ctrl_socket = super::wc::control_socket_path();
    let wc_status = match UnixStream::connect(&ctrl_socket) {
        Ok(_) => "RUNNING".to_string(),
        Err(_) => "STOPPED".to_string(),
    };
    eprintln!("WC Daemon: {wc_status} (control: {ctrl_socket})");

    Ok(())
}
