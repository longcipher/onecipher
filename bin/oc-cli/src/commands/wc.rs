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

    // Persist to file (durability — daemon loads on next start if not running now).
    // H-02: the stored pairing carries WC key material — atomic private write.
    let pairing = StoredPairing::from(&uri);
    let path = data_dir()?.join("wc_dapp.json");
    let json = serde_json::to_string_pretty(&pairing)?;
    oc_core::paths::write_atomic_private(&path, json.as_bytes())?;

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

// ---------------------------------------------------------------------------
// Relay configuration & protocol diagnostics (non-interactive, test-friendly)
// ---------------------------------------------------------------------------

/// `onecipher wc relay <url> [--project-id <id>]`
///
/// Persists the WC v2 relay endpoint + optional project ID into
/// `~/.onecipher/config.json` (keys `wc.relay_url`, `wc.project_id`) so the
/// daemon, CLI dApp client, and generated pairing URIs all target the same
/// relay. Local relays (e.g. `wss://127.0.0.1:7443`) can omit the project ID.
pub(crate) fn relay_config(url: &str, project_id: Option<&str>) -> Result<(), CliError> {
    // Validate the URL parses as a WebSocket URL.
    let normalized = url.trim();
    if !normalized.starts_with("wss://") && !normalized.starts_with("ws://") {
        return Err(CliError::InvalidArgs(format!(
            "invalid relay URL '{normalized}' (expected wss:// or ws://)"
        )));
    }

    crate::commands::config::set("wc.relay_url", normalized)?;
    if let Some(pid) = project_id {
        if pid.trim().is_empty() {
            return Err(CliError::InvalidArgs("--project-id cannot be empty".into()));
        }
        crate::commands::config::set("wc.project_id", pid.trim())?;
    }
    Ok(())
}

/// Resolve the effective relay URL + project ID from, in priority order:
/// explicit override > config (`wc.relay_url` / `wc.project_id`) >
/// `OC_WC_RELAY_URL` / `OC_WC_PROJECT_ID` env > built-in default.
fn resolve_relay(
    url_override: Option<&str>,
    project_id_override: Option<&str>,
) -> (String, Option<String>) {
    let config = oc_core::Config::load_or_default();
    let url = url_override
        .map(String::from)
        .or_else(|| std::env::var("OC_WC_RELAY_URL").ok().filter(|s| !s.is_empty()))
        .or_else(|| {
            if config.wc.relay_url.is_empty() { None } else { Some(config.wc.relay_url.clone()) }
        })
        .unwrap_or_else(|| "wss://relay.walletconnect.com".to_string());
    let project_id = project_id_override
        .map(String::from)
        .or_else(|| std::env::var("OC_WC_PROJECT_ID").ok().filter(|s| !s.is_empty()))
        .or_else(|| {
            if config.wc.project_id.is_empty() { None } else { Some(config.wc.project_id.clone()) }
        });
    (url, project_id)
}

/// `onecipher wc probe [--url <wss>] [--project-id <id>] [--timeout N]`
///
/// Connects to the relay, subscribes to a fresh random topic, publishes a
/// probe message (with an attestation if `OC_WC_ATTESTATION` is set), and
/// waits for the relay's `irn_subscription` echo. Exits 0 on success, nonzero
/// with a diagnostic on failure. This is the CLI-level connectivity check for
/// WC v2 relay testing.
pub(crate) fn probe(
    url_override: Option<&str>,
    project_id_override: Option<&str>,
    timeout_secs: u64,
) -> Result<(), CliError> {
    let (base_url, project_id) = resolve_relay(url_override, project_id_override);
    let url = oc_walletconnect::apply_project_id(&base_url, project_id.as_deref());

    eprintln!("probing relay: {url}");

    crate::shared_runtime().block_on(async {
        let cfg = oc_walletconnect::RelayConfig { url: url.clone(), reconnect_max_ms: 60_000 };
        let mut relay = oc_walletconnect::RelayClient::connect(cfg)
            .await
            .map_err(|e| CliError::InvalidArgs(format!("relay connect failed: {e}")))?;

        let topic = hex::encode(rand::random::<[u8; 32]>());
        let sub_id = relay_id_string();
        let sub_msg = serde_json::json!({
            "id": sub_id,
            "jsonrpc": "2.0",
            "method": "irn_subscribe",
            "params": { "topic": topic }
        });
        relay
            .send_text(serde_json::to_string(&sub_msg).map_err(CliError::Json)?)
            .await
            .map_err(|e| CliError::InvalidArgs(format!("subscribe failed: {e}")))?;
        eprintln!("subscribed to topic {topic}");

        // Publish a probe message (type-2 plaintext envelope).
        let probe_payload =
            serde_json::json!({ "probe": true, "ts": jiff::Timestamp::now().to_string() });
        let probe_bytes = serde_json::to_vec(&probe_payload).map_err(CliError::Json)?;
        let mut envelope = vec![oc_walletconnect::crypto::ENVELOPE_TYPE_2];
        envelope.extend_from_slice(&probe_bytes);
        let message_b64 = base64_std(&envelope);

        let attestation = std::env::var("OC_WC_ATTESTATION").ok().filter(|s| !s.is_empty());
        relay
            .publish_irn(&relay_id_string(), &topic, &message_b64, 60, 1108, attestation.as_deref())
            .await
            .map_err(|e| CliError::InvalidArgs(format!("publish failed: {e}")))?;
        eprintln!("published probe on {topic}");

        // Wait for the echo.
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs.max(1));
        loop {
            if std::time::Instant::now() > deadline {
                return Err(CliError::InvalidArgs("timeout waiting for relay echo".into()));
            }
            let raw = tokio::time::timeout(
                std::time::Duration::from_secs(timeout_secs.max(1)),
                relay.recv(),
            )
            .await
            .map_err(|_| CliError::InvalidArgs("timeout waiting for relay echo".into()))?
            .map_err(|e| CliError::InvalidArgs(format!("relay recv: {e}")))?;

            let val: serde_json::Value = serde_json::from_str(&raw)
                .map_err(|e| CliError::InvalidArgs(format!("bad relay message: {e}")))?;
            if val.get("method").and_then(|m| m.as_str()) != Some("irn_subscription") {
                continue;
            }
            let echo_topic =
                val.pointer("/params/data/topic").and_then(|t| t.as_str()).unwrap_or("");
            let echo_msg =
                val.pointer("/params/data/message").and_then(|m| m.as_str()).unwrap_or("");
            if echo_topic == topic {
                // Decode the type-2 envelope and verify the payload.
                let echo_bytes = base64_decode(echo_msg)?;
                if echo_bytes.first() == Some(&oc_walletconnect::crypto::ENVELOPE_TYPE_2) {
                    let echo_json: serde_json::Value = serde_json::from_slice(&echo_bytes[1..])
                        .map_err(|e| CliError::InvalidArgs(format!("bad echo payload: {e}")))?;
                    println!("relay echo received on {echo_topic}: {echo_json}");
                    println!("OK");
                    return Ok(());
                }
                eprintln!("echo received but not a type-2 envelope");
            }
        }
    })
}

/// `onecipher wc dapp-send <topic> <method> <params-json> [--sym-key <hex>] [--url <wss>]`
///
/// Acts as a WC v2 dApp: binds to the given session topic and sends a
/// JSON-RPC request, printing the (decrypted) response. Useful for driving a
/// running daemon's wallet server from the CLI (non-interactive testing).
pub(crate) fn dapp_send(
    topic: &str,
    method: &str,
    params_json: &str,
    sym_key_hex: Option<&str>,
    url_override: Option<&str>,
) -> Result<(), CliError> {
    let params: serde_json::Value = serde_json::from_str(params_json)
        .map_err(|e| CliError::InvalidArgs(format!("invalid params JSON: {e}")))?;

    // Resolve the session symKey: explicit flag > wc_dapp.json.
    let sym_key_hex = if let Some(h) = sym_key_hex {
        Some(h.to_string())
    } else {
        let dapp_path = data_dir()?.join("wc_dapp.json");
        if dapp_path.exists() {
            let data = fs::read_to_string(&dapp_path)?;
            let pairing: StoredPairing = serde_json::from_str(&data)?;
            (pairing.topic == topic && !pairing.sym_key.is_empty()).then_some(pairing.sym_key)
        } else {
            None
        }
    };
    let sym_key_hex = sym_key_hex
        .ok_or_else(|| CliError::InvalidArgs("no sym key for topic (pass --sym-key)".into()))?;
    let sym_bytes = hex::decode(sym_key_hex.strip_prefix("0x").unwrap_or(&sym_key_hex))
        .map_err(|e| CliError::InvalidArgs(format!("invalid sym-key hex: {e}")))?;
    if sym_bytes.len() != 32 {
        return Err(CliError::InvalidArgs("sym-key must be 32 bytes (64 hex chars)".into()));
    }
    let mut sym_arr = [0u8; 32];
    sym_arr.copy_from_slice(&sym_bytes);
    let sym_key = oc_walletconnect::WcSymKey::from_bytes(sym_arr);

    let (base_url, project_id) = resolve_relay(url_override, None);
    let url = oc_walletconnect::apply_project_id(&base_url, project_id.as_deref());

    crate::shared_runtime().block_on(async {
        let cfg = oc_walletconnect::RelayConfig { url, reconnect_max_ms: 60_000 };
        let mut relay = oc_walletconnect::RelayClient::connect(cfg)
            .await
            .map_err(|e| CliError::InvalidArgs(format!("relay connect failed: {e}")))?;

        let sub_msg = serde_json::json!({
            "id": relay_id_string(),
            "jsonrpc": "2.0",
            "method": "irn_subscribe",
            "params": { "topic": topic }
        });
        relay
            .send_text(serde_json::to_string(&sub_msg).map_err(CliError::Json)?)
            .await
            .map_err(|e| CliError::InvalidArgs(format!("subscribe failed: {e}")))?;

        let id: i64 = i64::from(rand::random::<u32>());
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": id
        });
        let req_bytes = serde_json::to_vec(&req).map_err(CliError::Json)?;
        let envelope = oc_walletconnect::WcCipher::seal_type0(&sym_key, &req_bytes)
            .map_err(|e| CliError::InvalidArgs(format!("encrypt failed: {e}")))?;

        let attestation = std::env::var("OC_WC_ATTESTATION").ok().filter(|s| !s.is_empty());
        relay
            .publish_irn(
                &relay_id_string(),
                topic,
                &base64_std(&envelope),
                300,
                1108,
                attestation.as_deref(),
            )
            .await
            .map_err(|e| CliError::InvalidArgs(format!("publish failed: {e}")))?;

        // Wait for the encrypted response.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            if std::time::Instant::now() > deadline {
                return Err(CliError::InvalidArgs("timeout waiting for response".into()));
            }
            let raw = relay
                .recv()
                .await
                .map_err(|e| CliError::InvalidArgs(format!("relay recv: {e}")))?;
            let val: serde_json::Value = serde_json::from_str(&raw)
                .map_err(|e| CliError::InvalidArgs(format!("bad relay message: {e}")))?;
            if val.get("method").and_then(|m| m.as_str()) != Some("irn_subscription") {
                continue;
            }
            let echo_topic =
                val.pointer("/params/data/topic").and_then(|t| t.as_str()).unwrap_or("");
            let echo_msg =
                val.pointer("/params/data/message").and_then(|m| m.as_str()).unwrap_or("");
            if echo_topic != topic {
                continue;
            }
            let env_bytes = base64_decode(echo_msg)?;
            if env_bytes.first() != Some(&oc_walletconnect::crypto::ENVELOPE_TYPE_0) &&
                env_bytes.first() != Some(&oc_walletconnect::crypto::ENVELOPE_TYPE_1)
            {
                continue;
            }
            let plaintext = match env_bytes[0] {
                oc_walletconnect::crypto::ENVELOPE_TYPE_0 => {
                    oc_walletconnect::WcCipher::open_type0(&sym_key, &env_bytes)
                }
                oc_walletconnect::crypto::ENVELOPE_TYPE_1 => {
                    oc_walletconnect::WcCipher::open_type1(&sym_key, &env_bytes).map(|(_, p)| p)
                }
                _ => continue,
            }
            .map_err(|e| CliError::InvalidArgs(format!("decrypt failed: {e}")))?;

            let resp: serde_json::Value = serde_json::from_slice(&plaintext)
                .map_err(|e| CliError::InvalidArgs(format!("bad response JSON: {e}")))?;
            if resp.get("id").and_then(|v| v.as_i64()) != Some(id) {
                continue;
            }
            println!("{}", serde_json::to_string_pretty(&resp).map_err(CliError::Json)?);
            return Ok(());
        }
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn relay_id_string() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let millis = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64);
    let entropy = u64::from(rand::random::<u16>());
    let id = (millis << 20) | (entropy & 0xFFFFF);
    format!("{id:019}")
}

fn base64_std(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn base64_decode(s: &str) -> Result<Vec<u8>, CliError> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| CliError::InvalidArgs(format!("invalid base64: {e}")))
}
