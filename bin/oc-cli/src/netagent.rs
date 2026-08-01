//! Network-Agent client abstraction for the CLI.
//!
//! The daemon (`onecipher daemon`) hosts the Network-Agent (WalletConnect v2
//! wallet-role server) which forwards inbound requests to the Key-Agent over
//! UDS. This trait abstracts that path so unit tests can inject a mock client
//! to verify RPC construction without a real daemon.

use std::os::unix::net::UnixStream;

use oc_keyagent::{
    frame::FrameClient,
    proto::{
        CreateSessionKeyRequest, CreateSessionKeyResponse, ListSessionKeysResponse, PayX402Request,
        PayX402Response, RevokeSessionKeyRequest, RevokeSessionKeyResponse,
    },
    request::{KeyAgentRequest, KeyAgentRequestKind},
    response::{KeyAgentResponse, KeyAgentResponseKind},
};
use prost::Message;

use crate::CliError;

/// Abstracts the Network-Agent client surface (WalletConnect v2 method calls
/// translated to Key-Agent UDS frames by the daemon).
///
/// Each method maps 1:1 to a Key-Agent request variant. The production
/// implementation [`UdsKeyAgentClient`] talks to the Key-Agent UDS socket
/// directly; [`UnimplementedClient`] is used by `main()` when the daemon is
/// not reachable so the CLI's arg-parsing and RPC-construction paths can still
/// be exercised via the mock in tests.
pub(crate) trait NetAgentClient: Send + Sync {
    /// RPC: `CreateSessionKey(CreateSessionKeyRequest) → CreateSessionKeyResponse`
    fn create_session_key(
        &self,
        req: CreateSessionKeyRequest,
    ) -> Result<CreateSessionKeyResponse, CliError>;

    /// RPC: `RevokeSessionKey(RevokeSessionKeyRequest) → RevokeSessionKeyResponse`
    fn revoke_session_key(
        &self,
        req: RevokeSessionKeyRequest,
    ) -> Result<RevokeSessionKeyResponse, CliError>;

    /// RPC: `ListSessionKeys(Empty) → ListSessionKeysResponse`
    fn list_session_keys(&self) -> Result<ListSessionKeysResponse, CliError>;

    /// RPC: `PayX402(PayX402Request) → PayX402Response`
    fn pay_x402(&self, req: PayX402Request) -> Result<PayX402Response, CliError>;
}

/// Production stub — returns `CliError::NetAgentUnavailable` for all RPCs.
///
/// Used by `main()` when the Key-Agent daemon is not reachable. The real
/// daemon path goes through [`UdsKeyAgentClient`] below.
pub(crate) struct UnimplementedClient;

impl NetAgentClient for UnimplementedClient {
    fn create_session_key(
        &self,
        _req: CreateSessionKeyRequest,
    ) -> Result<CreateSessionKeyResponse, CliError> {
        Err(CliError::NetAgentUnavailable)
    }

    fn revoke_session_key(
        &self,
        _req: RevokeSessionKeyRequest,
    ) -> Result<RevokeSessionKeyResponse, CliError> {
        Err(CliError::NetAgentUnavailable)
    }

    fn list_session_keys(&self) -> Result<ListSessionKeysResponse, CliError> {
        Err(CliError::NetAgentUnavailable)
    }

    fn pay_x402(&self, _req: PayX402Request) -> Result<PayX402Response, CliError> {
        Err(CliError::NetAgentUnavailable)
    }
}

/// UDS-backed client that talks to the Key-Agent daemon via [`FrameClient`].
///
/// Each RPC opens a fresh UDS connection (one request per connection, matching
/// the Key-Agent server's `handle_conn` loop), sends a [`KeyAgentRequest`]
/// frame, and decodes the [`KeyAgentResponse`].
///
/// Falls back to [`UnimplementedClient`] in `main()` when the daemon is not
/// reachable.
pub(crate) struct UdsKeyAgentClient {
    client: FrameClient,
}

/// Timeout for waiting on the daemon to become ready after spawning.
const DAEMON_READY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
/// Poll interval when waiting for the daemon socket to appear.
const DAEMON_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(50);

impl UdsKeyAgentClient {
    /// Connect to the Key-Agent, auto-spawning the daemon if the socket is
    /// unreachable.
    ///
    /// This is the recommended entry point for the CLI. It follows the
    /// gpg-agent / 1Password pattern:
    ///
    /// 1. Try to connect to the existing daemon socket.
    /// 2. If the socket file exists but connection is refused, clean up the stale socket.
    /// 3. Acquire a spawn lock file to prevent concurrent CLI instances from spawning multiple
    ///    daemons.
    /// 4. Fork/spawn `onecipher --daemon` in the background.
    /// 5. Poll until the socket appears and accepts connections (max 3s).
    /// 6. Connect and return.
    pub(crate) fn connect_or_spawn() -> Result<Self, String> {
        let client = FrameClient::connect_default().map_err(|e| e.to_string())?;
        let socket_path = client.socket_path();

        // Fast path: daemon already running.
        if UnixStream::connect(socket_path).is_ok() {
            return Ok(Self { client });
        }

        // Clean up stale socket file (daemon crashed without removing it).
        if socket_path.exists() {
            let _ = std::fs::remove_file(socket_path);
        }

        // Ensure parent directory exists.
        if let Some(parent) = socket_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create socket directory {}: {e}", parent.display()))?;
        }

        // Acquire spawn lock to prevent concurrent spawning.
        let lock_path = lock_file_path();
        if let Some(parent) = lock_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let _lock = acquire_spawn_lock(&lock_path);

        // Check if another CLI already spawned the daemon while we waited
        // for the lock.
        if UnixStream::connect(socket_path).is_ok() {
            return Ok(Self { client });
        }

        // Spawn the daemon in the background.
        spawn_daemon()?;

        // Poll until the socket is ready.
        let start = std::time::Instant::now();
        while start.elapsed() < DAEMON_READY_TIMEOUT {
            if let Ok(stream) = UnixStream::connect(socket_path) {
                // Connection succeeded — drop the probe stream and return.
                drop(stream);
                return Ok(Self { client });
            }
            std::thread::sleep(DAEMON_POLL_INTERVAL);
        }

        // Clean up lock file on failure.
        let _ = std::fs::remove_file(&lock_path);
        Err(format!("timed out waiting for Key-Agent daemon at {}", socket_path.display()))
    }

    /// Send a request frame and return the raw response.
    fn send(&self, req: &KeyAgentRequest) -> Result<KeyAgentResponse, CliError> {
        self.client
            .send_request(req)
            .map_err(|e| CliError::InvalidArgs(format!("key-agent IPC failed: {e}")))
    }
}

/// Return the path to the spawn lock file: `~/.onecipher/agent.spawn-lock`.
fn lock_file_path() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    std::path::PathBuf::from(home).join(".onecipher").join("agent.spawn-lock")
}

/// Try to acquire the spawn lock by atomically creating the lock file.
///
/// Returns a guard that removes the file on drop. If the file already exists
/// (another CLI holds the lock), returns `None` — the caller should wait for
/// the socket instead.
fn acquire_spawn_lock(path: &std::path::Path) -> Option<SpawnLockGuard> {
    use std::fs::OpenOptions;

    // Atomic create — fails if file already exists (O_EXCL).
    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(mut file) => {
            use std::io::Write;
            let _ = write!(file, "{}", std::process::id());
            Some(SpawnLockGuard { path: path.to_path_buf() })
        }
        Err(_) => None,
    }
}

/// RAII guard that removes the spawn lock file on drop.
struct SpawnLockGuard {
    path: std::path::PathBuf,
}

impl Drop for SpawnLockGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Spawn `onecipher --daemon` as a detached background process.
fn spawn_daemon() -> Result<(), String> {
    use std::process::{Command, Stdio};

    // Find the current executable — the daemon is the same binary with `--daemon`.
    let exe =
        std::env::current_exe().map_err(|e| format!("cannot determine executable path: {e}"))?;

    Command::new(exe)
        .arg("--daemon")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("failed to spawn daemon: {e}"))?;

    Ok(())
}

impl NetAgentClient for UdsKeyAgentClient {
    fn create_session_key(
        &self,
        req: CreateSessionKeyRequest,
    ) -> Result<CreateSessionKeyResponse, CliError> {
        let req = KeyAgentRequest { kind: Some(KeyAgentRequestKind::CreateSessionKey(req)) };
        let resp = self.send(&req)?;
        decode_ok(resp)
    }

    fn revoke_session_key(
        &self,
        req: RevokeSessionKeyRequest,
    ) -> Result<RevokeSessionKeyResponse, CliError> {
        let req = KeyAgentRequest { kind: Some(KeyAgentRequestKind::RevokeSessionKey(req)) };
        let resp = self.send(&req)?;
        decode_ok(resp)
    }

    fn list_session_keys(&self) -> Result<ListSessionKeysResponse, CliError> {
        // The Key-Agent has no ListSessionKeys request variant (folded into
        // the ListWallets slot per request.rs deviation note; T18 will wire
        // it). Return an error rather than sending an unmatched request.
        Err(CliError::InvalidArgs(
            "ListSessionKeys not supported by Key-Agent (T18 pending)".to_string(),
        ))
    }

    fn pay_x402(&self, req: PayX402Request) -> Result<PayX402Response, CliError> {
        let req = KeyAgentRequest { kind: Some(KeyAgentRequestKind::PayX402(req)) };
        let resp = self.send(&req)?;
        decode_ok(resp)
    }
}

/// Decode a [`KeyAgentResponse`] expecting the `Ok` variant carrying a
/// prost-encoded payload of type `T`.
fn decode_ok<T: Message + Default>(resp: KeyAgentResponse) -> Result<T, CliError> {
    match resp.kind {
        Some(KeyAgentResponseKind::Ok(bytes)) => T::decode(bytes.as_slice())
            .map_err(|e| CliError::InvalidArgs(format!("response decode failed: {e}"))),
        Some(KeyAgentResponseKind::Deny(payload)) => Err(CliError::InvalidArgs(format!(
            "request denied by policy (reason code: {})",
            payload.reason
        ))),
        Some(KeyAgentResponseKind::Error(msg)) => {
            Err(CliError::InvalidArgs(format!("key-agent error: {msg}")))
        }
        None => Err(CliError::InvalidArgs("empty response from key-agent".to_string())),
    }
}
