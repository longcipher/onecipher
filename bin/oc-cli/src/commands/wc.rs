use std::{
    fs,
    io::{Read, Write},
    path::PathBuf,
};

use oc_walletconnect::PairingUri;
use serde::{Deserialize, Serialize};

use crate::CliError;

/// Resolved path to `~/.local/share/onecipher/` (platform-specific via `dirs`).
fn data_dir() -> Result<PathBuf, CliError> {
    let base = dirs::data_dir()
        .ok_or_else(|| CliError::InvalidArgs("cannot determine data directory".into()))?;
    let dir = base.join("onecipher");
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Control socket path for daemon IPC.
///
/// Mirrors [`oc_keyagent::server::default_socket_path`] logic: uses
/// `$XDG_RUNTIME_DIR/onecipher/control.sock` when `XDG_RUNTIME_DIR` is set,
/// falling back to `/tmp/onecipher-control.sock` (same deviation as the
/// Key-Agent socket — see `oc_keyagent::server::socket_path_from` docs).
pub(crate) fn control_socket_path() -> String {
    match std::env::var("XDG_RUNTIME_DIR") {
        Ok(xdg) => format!("{xdg}/onecipher/control.sock"),
        Err(_) => "/tmp/onecipher-control.sock".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Stored pairing / session types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct StoredPairing {
    pub topic: String,
    pub sym_key: String,
    pub relay_protocol: Option<String>,
    pub version: u32,
    pub methods: Vec<String>,
}

impl From<&PairingUri> for StoredPairing {
    fn from(uri: &PairingUri) -> Self {
        Self {
            topic: uri.topic.clone(),
            sym_key: uri.sym_key.clone().unwrap_or_default(),
            relay_protocol: uri.relay_protocol.clone(),
            version: uri.version,
            methods: uri.methods.clone(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct StoredSession {
    pub topic: String,
    pub sym_key: String,
    pub state: String,
    pub expiry_unix: u64,
    pub methods: Vec<String>,
    pub dapp_name: Option<String>,
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/// Generate a fresh pairing URI via the running daemon.
///
/// The daemon creates a random topic + symKey, inserts it as a `Propose`-state
/// session, and returns the `wc:` URI for the user to scan with a dApp.
pub(crate) fn pair(ttl: Option<u64>) -> Result<(), CliError> {
    let ctrl_sock = control_socket_path();
    match std::os::unix::net::UnixStream::connect(&ctrl_sock) {
        Ok(mut stream) => {
            let cmd = match ttl {
                Some(t) => format!("PAIR {t}\n"),
                None => "PAIR\n".to_string(),
            };
            stream
                .write_all(cmd.as_bytes())
                .map_err(|e| CliError::InvalidArgs(format!("control socket write: {e}")))?;
            let mut buf = String::new();
            stream
                .read_to_string(&mut buf)
                .map_err(|e| CliError::InvalidArgs(format!("control socket read: {e}")))?;
            let resp = buf.trim();
            if let Some(uri_str) = resp.strip_prefix("OK ") {
                println!("Pairing URI (scan with dApp):");
                println!("  {uri_str}");
            } else {
                eprintln!("daemon error: {resp}");
            }
            Ok(())
        }
        Err(_) => Err(CliError::InvalidArgs(
            "daemon not running. Start it with: onecipher --daemon".into(),
        )),
    }
}

/// Connect to a dApp by submitting its pairing URI to the daemon.
///
/// The daemon subscribes to the pairing topic on the WC v2 relay and waits
/// for the dApp's `wc_sessionPropose` request.
pub(crate) fn connect(uri_str: &str) -> Result<(), CliError> {
    let uri = PairingUri::parse(uri_str)
        .map_err(|e| CliError::InvalidArgs(format!("invalid WC pairing URI: {e}")))?;

    // Persist to file (durability — daemon loads on next start if not running now)
    let pairing = StoredPairing::from(&uri);
    let path = data_dir()?.join("wc_dapp.json");
    let json = serde_json::to_string_pretty(&pairing)?;
    fs::write(&path, json)?;

    // Send to daemon control socket for immediate pairing
    let ctrl_sock = control_socket_path();
    if let Ok(mut stream) = std::os::unix::net::UnixStream::connect(&ctrl_sock) {
        let msg = format!("CONNECT {uri_str}\n");
        if stream.write_all(msg.as_bytes()).is_ok() {
            let mut buf = String::new();
            if stream.read_to_string(&mut buf).is_ok() {
                let resp = buf.trim();
                if resp.starts_with("OK") {
                    println!("{resp}");
                    println!("  topic: {}", uri.topic);
                    if let Some(rp) = &uri.relay_protocol {
                        println!("  relay: {rp}");
                    }
                    return Ok(());
                }
                eprintln!("daemon responded: {resp}");
                // Fall through — pairing is saved to disk
            }
        }
    }

    println!("Pairing saved to {}", path.display());
    println!("  topic: {}", uri.topic);
    if let Some(rp) = &uri.relay_protocol {
        println!("  relay: {rp}");
    }
    println!("(daemon not reachable — will load on next start)");
    Ok(())
}

pub(crate) fn sessions() -> Result<(), CliError> {
    let path = data_dir()?.join("wc_sessions.json");
    if !path.exists() {
        println!("No WalletConnect sessions found.");
        return Ok(());
    }

    let data = fs::read_to_string(&path)?;
    let list: Vec<StoredSession> = serde_json::from_str(&data)?;

    if list.is_empty() {
        println!("No WalletConnect sessions found.");
        return Ok(());
    }

    for s in &list {
        println!(
            "  topic={}  state={}  expiry={}  methods={}",
            s.topic,
            s.state,
            s.expiry_unix,
            s.methods.join(",")
        );
    }
    Ok(())
}

pub(crate) fn disconnect(topic: &str) -> Result<(), CliError> {
    let dir = data_dir()?;

    // Remove from sessions file.
    let sessions_path = dir.join("wc_sessions.json");
    if sessions_path.exists() {
        let data = fs::read_to_string(&sessions_path)?;
        let mut list: Vec<StoredSession> = serde_json::from_str(&data)?;
        let before = list.len();
        list.retain(|s| s.topic != topic);
        if list.len() < before {
            fs::write(&sessions_path, serde_json::to_string_pretty(&list)?)?;
            println!("Removed session {topic} from {}", sessions_path.display());
        }
    }

    // Clear dapp pairing if it matches.
    let dapp_path = dir.join("wc_dapp.json");
    if dapp_path.exists() {
        let data = fs::read_to_string(&dapp_path)?;
        let pairing: StoredPairing = serde_json::from_str(&data)?;
        if pairing.topic == topic {
            fs::remove_file(&dapp_path)?;
            println!("Removed pairing {topic} from {}", dapp_path.display());
        }
    }

    Ok(())
}
