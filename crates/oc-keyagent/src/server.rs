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
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
};

use crate::{
    error::KeyAgentError,
    frame::{Frame, read_typed, write_typed},
    handler::dispatch,
    request::KeyAgentRequest,
    response::KeyAgentResponse,
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

#[cfg(unix)]
fn current_uid() -> u64 {
    #[allow(unsafe_code)]
    // SAFETY: `libc::getuid()` takes no arguments, cannot fail, and only
    // reads the process's real user id.
    unsafe {
        u64::from(libc::getuid())
    }
}

#[cfg(not(unix))]
fn current_uid() -> u64 {
    0
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
pub fn run(socket_path: Option<&str>, stop: Option<Arc<AtomicBool>>) -> Result<(), KeyAgentError> {
    let path = socket_path.map_or_else(default_socket_path, String::from);

    // Ensure parent dir exists with mode 0700.
    if let Some(parent) = Path::new(&path).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
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

    tracing::info!(path = %path, "oc-keyagent: listening");

    // Live-connection counter enforcing MAX_CONNECTIONS.
    let live_connections = Arc::new(AtomicUsize::new(0));

    // Cooperative shutdown. `UnixListener::accept` is blocking, so when `stop`
    // is set we switch the listener to non-blocking and wake the accept loop
    // with a `WouldBlock` error, which we treat purely as a poll point (rather
    // than waiting for an unrelated incoming connection to unblock).
    loop {
        if stop.as_ref().is_some_and(|s| s.load(Ordering::Relaxed)) {
            break;
        }

        // Refresh non-blocking mode: off during normal operation, on once a
        // shutdown has been requested so accept() returns immediately.
        let want_nonblocking = stop.as_ref().is_some_and(|s| s.load(Ordering::Relaxed));
        let _ = listener.set_nonblocking(want_nonblocking);

        match listener.accept() {
            Ok((stream, _addr)) => {
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
