//! Key-Agent server: UDS listener + per-connection thread.
//!
//! Per R55 / R56 / AD-01, this module uses `std::os::unix::net::UnixListener`
//! and `std::thread` (NO tokio, NO async runtime). The Key-Agent is a
//! single-machine signing service with very low concurrency, so a
//! thread-per-connection model is more than sufficient.

use std::{
    os::unix::{
        fs::PermissionsExt,
        net::{UnixListener, UnixStream},
    },
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::{
    error::KeyAgentError,
    frame::{Frame, read_typed, write_typed},
    handler::dispatch,
    request::KeyAgentRequest,
    response::KeyAgentResponse,
    socket_guard::{current_uid, verify_socket_dir},
};

/// Default UDS path: `$XDG_RUNTIME_DIR/onecipher/key-agent.sock`.
///
/// **Deviation note (T11):** If `XDG_RUNTIME_DIR` is unset, the fallback is
/// `/tmp/onecipher-key-agent-$UID.sock`. The per-UID suffix prevents the
/// classic multi-user hazard of a predictable shared `/tmp` path (pre-created
// socket files / symlink games by other local users). Production deployments
/// MUST still prefer `XDG_RUNTIME_DIR`.
pub fn default_socket_path() -> String {
    socket_path_from(std::env::var("XDG_RUNTIME_DIR").ok().as_deref(), current_uid())
}

/// Tighten the file-mode creation mask around `f` so nodes it creates are
/// owner-only. Returns the result of `f` (the old mask is always restored).
#[cfg(unix)]
fn with_tight_umask<T>(f: impl FnOnce() -> T) -> T {
    #[allow(unsafe_code)]
    // SAFETY: `umask` is a simple process-wide getter/setter of the
    // file-mode creation mask; no pointers involved.
    let old = unsafe { libc::umask(0o077) };
    let out = f();
    #[allow(unsafe_code)]
    // SAFETY: same primitive as above; restores the previous mask.
    unsafe {
        libc::umask(old)
    };
    out
}

/// Pure path-computation helper (no env access).
///
/// Exposed so tests can verify the path logic without mutating the global
/// `XDG_RUNTIME_DIR` (which races under parallel test execution).
pub fn socket_path_from(xdg: Option<&str>, uid: u64) -> String {
    match xdg {
        Some(xdg) => format!("{xdg}/onecipher/key-agent.sock"),
        None => format!("/tmp/onecipher-key-agent-{uid}.sock"),
    }
}

/// Maximum number of concurrently served connections. Thread-per-connection
/// is unbounded by default; a local process could otherwise exhaust threads
/// by opening UDS connections in a tight loop.
const MAX_CONNECTIONS: usize = 64;

/// Default inactivity lock: the server shuts down after this many seconds
/// without a single accepted connection.
///
/// A long-lived daemon holding session keys and cached derived keys is a
/// standing exposure on an unattended machine; the idle lock bounds it the
/// same way `ssh-agent -t` / `gpg-agent` do. Override with
/// `ONECIPHER_KEY_AGENT_IDLE_SECS`; `0` disables the lock entirely.
const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 900;

/// Environment variable overriding [`DEFAULT_IDLE_TIMEOUT_SECS`].
const IDLE_TIMEOUT_ENV: &str = "ONECIPHER_KEY_AGENT_IDLE_SECS";

/// How often the idle watchdog samples the last-activity timestamp.
const IDLE_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Current wall-clock time as whole seconds since the Unix epoch.
///
/// Saturates at 0 on platforms where the clock predates the epoch — the
/// value only feeds elapsed-time comparisons, so a wrong absolute value is
/// harmless.
fn now_unix_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// Parse an idle-timeout seconds value (pure; no env access).
///
/// Unset, empty, or unparseable input falls back to
/// [`DEFAULT_IDLE_TIMEOUT_SECS`] — fail toward locking, never toward a
/// silently immortal daemon. An explicit `0` disables the lock.
fn parse_idle_timeout_secs(raw: Option<&str>) -> u64 {
    match raw.map(str::trim) {
        Some(s) if !s.is_empty() => s.parse().unwrap_or(DEFAULT_IDLE_TIMEOUT_SECS),
        _ => DEFAULT_IDLE_TIMEOUT_SECS,
    }
}

/// Idle timeout in seconds read from [`IDLE_TIMEOUT_ENV`].
fn idle_timeout_from_env() -> u64 {
    parse_idle_timeout_secs(std::env::var(IDLE_TIMEOUT_ENV).ok().as_deref())
}

/// Run the Key-Agent server with a cooperative shutdown flag.
///
/// The loop checks `stop` between accepts; when set, the listener is dropped
/// and the function returns `Ok(())`. The caller (daemon) sets `stop` on
/// Ctrl+C; `run` then removes the socket file before returning so the next
/// launch does not trip over a stale `.sock`.
///
/// Per R55 / AD-01, uses `std::thread::spawn` (NOT `tokio::spawn`).
///
/// `socket_path` overrides `default_socket_path()` if set (used by tests and
/// the `OC_KEYAGENT_SOCK` env var in `main.rs`).
///
/// The inactivity lock is configured from the environment; see
/// [`run_with_idle_timeout`] for the injectable variant.
pub fn run(socket_path: Option<&str>, stop: Option<Arc<AtomicBool>>) -> Result<(), KeyAgentError> {
    run_with_idle_timeout(socket_path, stop, idle_timeout_from_env())
}

/// Run the Key-Agent server with an explicit inactivity lock.
///
/// Identical to [`run`], except the idle timeout is injected rather than
/// read from the environment. `idle_timeout_secs == 0` disables the lock.
/// The watchdog requires a `stop` flag to shut the accept loop down; when
/// none is supplied the lock is skipped (an embedder without a shutdown
/// handle owns the lifecycle itself).
///
/// Each accepted connection refreshes the activity timestamp, so the lock
/// measures time since the last request rather than process age.
pub fn run_with_idle_timeout(
    socket_path: Option<&str>,
    stop: Option<Arc<AtomicBool>>,
    idle_timeout_secs: u64,
) -> Result<(), KeyAgentError> {
    let path = socket_path.map_or_else(default_socket_path, String::from);

    // Ensure parent dir exists with mode 0700.
    if let Some(parent) = Path::new(&path).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
            // R12: `create_dir_all` succeeds on a pre-existing directory and
            // `chmod` cannot repair ownership — verify before binding so a
            // co-resident user cannot squat the predictable socket path with
            // a symlink or a directory they own.
            verify_socket_dir(parent)?;
        }
    }
    // Remove stale socket file if present (best-effort).
    let _ = std::fs::remove_file(&path);

    // Tighten the creation mask around bind so the socket node is created
    // owner-only — closing the bind→chmod permission window.
    #[cfg(unix)]
    let bind_result = with_tight_umask(|| UnixListener::bind(&path));
    #[cfg(not(unix))]
    let bind_result = UnixListener::bind(&path);
    let listener = bind_result?;
    // R55: chmod 0600 on the socket file — belt-and-braces behind the umask.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;

    tracing::info!(path = %path, idle_timeout_secs, "oc-keyagent: listening");

    // Live-connection counter enforcing MAX_CONNECTIONS.
    let live_connections = Arc::new(AtomicUsize::new(0));

    // Last-activity timestamp (unix seconds), refreshed on every accepted
    // connection. The CLI opens one connection per request, so an accept is
    // a faithful "the daemon is in use" signal.
    let last_activity = Arc::new(AtomicU64::new(now_unix_secs()));

    // Inactivity watchdog: set `stop` once no request has arrived for
    // `idle_timeout_secs`. The accept loop observes the flag within one
    // poll interval (50 ms) and performs the normal clean shutdown, which
    // removes the socket file and zeroizes cached state via the daemon's
    // shutdown path.
    if idle_timeout_secs > 0 {
        if let Some(stop_flag) = stop.clone() {
            let activity = Arc::clone(&last_activity);
            thread::spawn(move || {
                loop {
                    thread::sleep(IDLE_POLL_INTERVAL);
                    if stop_flag.load(Ordering::Relaxed) {
                        return;
                    }
                    let idle_for = now_unix_secs().saturating_sub(activity.load(Ordering::Relaxed));
                    if idle_for >= idle_timeout_secs {
                        tracing::info!(
                            idle_for,
                            idle_timeout_secs,
                            "oc-keyagent: inactivity lock engaged; shutting down"
                        );
                        stop_flag.store(true, Ordering::Relaxed);
                        return;
                    }
                }
            });
        }
    }

    // Cooperative shutdown. The listener is kept non-blocking at all times:
    // a blocking `accept()` would sit inside the syscall and never observe
    // `stop` until an unrelated connection arrived (the daemon only escaped
    // this via the EINTR from a signal, which the idle watchdog does not
    // generate). The 50 ms poll bounds shutdown and idle-lock latency at
    // one wakeup per interval — negligible for a local signing agent.
    loop {
        if stop.as_ref().is_some_and(|s| s.load(Ordering::Relaxed)) {
            break;
        }

        let _ = listener.set_nonblocking(true);

        match listener.accept() {
            Ok((stream, _addr)) => {
                last_activity.store(now_unix_secs(), Ordering::Relaxed);
                if live_connections.load(Ordering::Relaxed) >= MAX_CONNECTIONS {
                    tracing::warn!("connection limit {MAX_CONNECTIONS} reached; rejecting");
                    // Best-effort rejection notice so well-behaved clients see
                    // an error instead of a hang.
                    let _ = write_typed(
                        &mut &stream,
                        &Frame::new(KeyAgentResponse::error("connection limit reached")),
                    );
                    continue;
                }
                live_connections.fetch_add(1, Ordering::Relaxed);
                let live = Arc::clone(&live_connections);
                thread::spawn(move || {
                    if let Err(e) = handle_conn(stream) {
                        tracing::warn!(error = %e, "connection error");
                    }
                    live.fetch_sub(1, Ordering::Relaxed);
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // Non-blocking poll: yield briefly, then re-check `stop`.
                thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(e) => {
                // If the listener was closed (e.g. dropped), `accept` returns an
                // error — treat that as shutdown, not a transient error.
                if stop.as_ref().is_some_and(|s| s.load(Ordering::Relaxed)) {
                    break;
                }
                tracing::warn!(error = %e, "accept error");
                // Continue accepting — transient errors must not kill the agent.
            }
        }
    }
    // Best-effort cleanup of the socket file on clean shutdown.
    let _ = std::fs::remove_file(&path);
    Ok(())
}

/// Per-connection handler: read frames, dispatch, write responses.
///
/// Loops until the client disconnects cleanly (EOF between frames) or an
/// unrecoverable write error occurs. Decode failures and dispatch errors
/// are converted to `KeyAgentResponse::Error(...)` and written back so the
/// connection can continue serving subsequent requests (per the design.md
/// main loop pseudocode — the loop `continue`s on handler errors).
pub fn handle_conn(stream: UnixStream) -> Result<(), KeyAgentError> {
    // Split the stream into separate read/write halves. try_clone duplicates
    // the file descriptor so both halves can be moved independently.
    let mut reader = stream.try_clone()?;
    let mut writer = stream;

    loop {
        let req = match read_typed::<_, KeyAgentRequest>(&mut reader) {
            Ok(frame) => frame.into_inner(),
            Err(crate::frame::FrameError::Eof) => {
                // Clean client disconnect between frames.
                return Ok(());
            }
            Err(crate::frame::FrameError::Decode(e)) => {
                // Decode failure — respond with Error and continue the loop
                // so the client can send a corrected request on the same
                // connection.
                let resp = KeyAgentResponse::error(format!("decode error: {e}"));
                write_typed(&mut writer, &Frame::new(resp))?;
                continue;
            }
            Err(e) => return Err(e.into()),
        };

        let resp = match dispatch(&req) {
            Ok(resp) => resp,
            Err(e) => KeyAgentResponse::error(format!("dispatch error: {e}")),
        };
        write_typed(&mut writer, &Frame::new(resp))?;
    }
}

#[cfg(test)]
mod tests {
    use std::{os::unix::net::UnixStream, thread};

    use prost::Message;

    use super::*;
    use crate::{
        frame::{read_frame, write_frame},
        proto::Empty,
        request::{KeyAgentRequest, KeyAgentRequestKind},
        response::{KeyAgentResponse, KeyAgentResponseKind},
    };

    #[test]
    fn test_socket_path_from_xdg_runtime_dir() {
        // Pure-logic test — no env mutation, no race under parallel execution.
        assert_eq!(
            socket_path_from(Some("/run/user/12345"), 12345),
            "/run/user/12345/onecipher/key-agent.sock"
        );
    }

    #[test]
    fn test_socket_path_from_no_xdg_fallback_includes_uid() {
        // Deviation: per-UID fallback prevents cross-user /tmp collisions.
        assert_eq!(socket_path_from(None, 42), "/tmp/onecipher-key-agent-42.sock");
    }

    #[test]
    fn idle_timeout_defaults_when_unset_or_invalid() {
        assert_eq!(parse_idle_timeout_secs(None), DEFAULT_IDLE_TIMEOUT_SECS);
        assert_eq!(parse_idle_timeout_secs(Some("")), DEFAULT_IDLE_TIMEOUT_SECS);
        assert_eq!(parse_idle_timeout_secs(Some("  ")), DEFAULT_IDLE_TIMEOUT_SECS);
        // Unparseable values fail toward locking, never toward an immortal daemon.
        assert_eq!(parse_idle_timeout_secs(Some("soon")), DEFAULT_IDLE_TIMEOUT_SECS);
        assert_eq!(parse_idle_timeout_secs(Some("-1")), DEFAULT_IDLE_TIMEOUT_SECS);
    }

    #[test]
    fn idle_timeout_explicit_zero_disables_lock() {
        assert_eq!(parse_idle_timeout_secs(Some("0")), 0);
    }

    #[test]
    fn idle_timeout_parses_positive_values() {
        assert_eq!(parse_idle_timeout_secs(Some("60")), 60);
        assert_eq!(parse_idle_timeout_secs(Some(" 30 ")), 30);
    }

    #[test]
    fn idle_lock_shuts_server_down_and_removes_socket() {
        // `verify_socket_dir` rejects any group/other-accessible directory, so
        // the socket cannot live directly in `std::env::temp_dir()` (usually
        // `/tmp` at 0755). `TempDir` is created 0700 and cleans up on drop.
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("test.sock");
        let sock_str = sock.to_string_lossy().into_owned();
        let _ = std::fs::remove_file(&sock);

        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = Arc::clone(&stop);
        let server = thread::spawn(move || {
            // One-second idle lock; the watchdog samples once per second.
            let _ = run_with_idle_timeout(Some(&sock_str), Some(stop_thread), 1);
        });

        // Wait for the socket to appear, then stay silent.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !sock.exists() && std::time::Instant::now() < deadline {
            thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(sock.exists(), "server must bind the socket");

        // No request arrives: within a few seconds the watchdog must engage.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(8);
        while sock.exists() && std::time::Instant::now() < deadline {
            thread::sleep(std::time::Duration::from_millis(50));
        }
        assert!(!sock.exists(), "idle lock must remove the socket file");
        assert!(stop.load(Ordering::Relaxed), "idle lock must set the stop flag");
        server.join().expect("server thread must exit cleanly");
    }

    #[test]
    fn activity_keeps_server_alive_when_idle_lock_disabled() {
        // See `idle_lock_shuts_server_down_and_removes_socket`: the socket
        // needs a private 0700 parent directory.
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("test.sock");
        let sock_str = sock.to_string_lossy().into_owned();
        let _ = std::fs::remove_file(&sock);

        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = Arc::clone(&stop);
        let server = thread::spawn(move || {
            let _ = run_with_idle_timeout(Some(&sock_str), Some(stop_thread), 0);
        });

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !sock.exists() && std::time::Instant::now() < deadline {
            thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(sock.exists(), "server must bind the socket");

        // Idle lock disabled: the socket must survive well past one second.
        thread::sleep(std::time::Duration::from_millis(1500));
        assert!(sock.exists(), "a disabled idle lock must keep the server alive");

        stop.store(true, Ordering::Relaxed);
        server.join().expect("server thread must exit after stop");
    }

    #[test]
    fn test_handle_conn_request_response_round_trip() {
        let (client, server) = UnixStream::pair().unwrap();
        let handle = thread::spawn(move || handle_conn(server));

        let req = KeyAgentRequest { kind: Some(KeyAgentRequestKind::LockVault(Empty {})) };
        let mut client_w = client.try_clone().unwrap();
        write_frame(&mut client_w, &req.encode_to_vec()).unwrap();

        let mut client_r = client;
        let payload = read_frame(&mut client_r).unwrap();
        let resp = KeyAgentResponse::decode(payload.as_slice()).unwrap();

        // Handler now processes real requests — response may be Ok, Deny, or
        // Error depending on policy/vault state. We just verify a valid
        // response was returned without panic.
        assert!(resp.kind.is_some(), "response must have a kind");

        drop(client_w);
        drop(client_r);
        handle.join().unwrap().unwrap();
    }

    #[test]
    fn test_handle_conn_clean_disconnect() {
        // If the peer closes the connection cleanly between frames,
        // handle_conn must return Ok(()).
        let (client, server) = UnixStream::pair().unwrap();
        let handle = thread::spawn(move || handle_conn(server));
        drop(client);
        let result = handle.join().unwrap();
        assert!(result.is_ok(), "handle_conn should Ok(()) on clean disconnect");
    }

    #[test]
    fn test_handle_conn_malformed_frame_returns_error_then_continues() {
        let (client, server) = UnixStream::pair().unwrap();
        let handle = thread::spawn(move || handle_conn(server));

        // Send a frame whose payload is not a valid prost KeyAgentRequest.
        let mut client_w = client.try_clone().unwrap();
        write_frame(&mut client_w, b"not a valid prost payload").unwrap();

        let mut client_r = client;
        let payload = read_frame(&mut client_r).unwrap();
        let resp = KeyAgentResponse::decode(payload.as_slice()).unwrap();
        assert!(
            matches!(resp.kind, Some(KeyAgentResponseKind::Error(_))),
            "expected Error response for malformed payload"
        );

        // Send a SECOND, valid request on the same connection — the handler
        // must still be alive (decode error must not kill the loop).
        let req = KeyAgentRequest { kind: Some(KeyAgentRequestKind::ListWallets(Empty {})) };
        write_frame(&mut client_w, &req.encode_to_vec()).unwrap();
        let payload2 = read_frame(&mut client_r).unwrap();
        let resp2 = KeyAgentResponse::decode(payload2.as_slice()).unwrap();
        assert!(resp2.kind.is_some(), "second request must also be served");

        drop(client_w);
        drop(client_r);
        handle.join().unwrap().unwrap();
    }

    #[test]
    fn test_handle_conn_multiple_requests_on_one_connection() {
        let (client, server) = UnixStream::pair().unwrap();
        let handle = thread::spawn(move || handle_conn(server));

        let mut client_w = client.try_clone().unwrap();
        let mut client_r = client;

        // Send 3 ListWallets requests in sequence.
        for i in 0..3 {
            let req = KeyAgentRequest { kind: Some(KeyAgentRequestKind::ListWallets(Empty {})) };
            write_frame(&mut client_w, &req.encode_to_vec()).unwrap();
            let payload = read_frame(&mut client_r).unwrap();
            let resp = KeyAgentResponse::decode(payload.as_slice()).unwrap();
            assert!(resp.kind.is_some(), "request {i} must be served");
        }

        drop(client_w);
        drop(client_r);
        handle.join().unwrap().unwrap();
    }
}
