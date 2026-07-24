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
    thread,
};

use prost::Message;

use crate::{
    error::KeyAgentError,
    frame::{read_frame, write_frame},
    handler::dispatch,
    request::KeyAgentRequest,
    response::KeyAgentResponse,
};

/// Default UDS path: `$XDG_RUNTIME_DIR/onecipher/key-agent.sock`.
///
/// **Deviation note (T11):** If `XDG_RUNTIME_DIR` is unset, the fallback is
/// `/tmp/onecipher-key-agent.sock` (NO uid suffix). This is acceptable for T11
/// scaffolding because:
/// 1. On systemd Linux, `XDG_RUNTIME_DIR` is always set (`/run/user/$UID`).
/// 2. On macOS dev (this build host), `/tmp` is fine for testing.
/// 3. T12 (sandbox) will enforce proper isolation via seccomp + landlock + App Sandbox entitlements
///    at runtime — the socket path itself is not the security boundary.
/// 4. The original plan called for `unsafe { libc::getuid() }` to build
///    `/tmp/onecipher-key-agent-$UID.sock`. We skipped `libc` entirely to keep
///    `#![deny(unsafe_code)]` at the crate root without any `#[allow(unsafe_code)]` exceptions
///    (ponytail step 2 — stdlib beats step 3 native). Production deployments MUST set
///    `XDG_RUNTIME_DIR`.
pub fn default_socket_path() -> String {
    socket_path_from(std::env::var("XDG_RUNTIME_DIR").ok().as_deref())
}

/// Pure path-computation helper (no env access).
///
/// Exposed so tests can verify the path logic without mutating the global
/// `XDG_RUNTIME_DIR` (which races under parallel test execution).
pub fn socket_path_from(xdg: Option<&str>) -> String {
    match xdg {
        Some(xdg) => format!("{xdg}/onecipher/key-agent.sock"),
        None => "/tmp/onecipher-key-agent.sock".to_string(),
    }
}

/// Run the Key-Agent server: bind UDS, chmod 0600, spawn a thread per
/// connection.
///
/// Blocks forever (until the listener is closed or the process is killed).
/// Per R55 / AD-01, uses `std::thread::spawn` (NOT `tokio::spawn`).
///
/// `socket_path` overrides `default_socket_path()` if set (used by tests and
/// the `OC_KEYAGENT_SOCK` env var in `main.rs`).
pub fn run(socket_path: Option<&str>) -> Result<(), KeyAgentError> {
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

    // Bind.
    let listener = UnixListener::bind(&path)?;
    // R55: chmod 0600 on the socket file — only the owner may connect.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;

    eprintln!("oc-keyagent: listening on {path}");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                thread::spawn(move || {
                    if let Err(e) = handle_conn(stream) {
                        eprintln!("oc-keyagent: connection error: {e}");
                    }
                });
            }
            Err(e) => {
                eprintln!("oc-keyagent: accept error: {e}");
                // Continue accepting — transient errors must not kill the agent.
            }
        }
    }
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
        let payload = match read_frame(&mut reader) {
            Ok(payload) => payload,
            Err(crate::frame::FrameError::Eof) => {
                // Clean client disconnect between frames.
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        };

        let req = match KeyAgentRequest::decode(payload.as_slice()) {
            Ok(req) => req,
            Err(e) => {
                // Decode failure — respond with Error and continue the loop
                // so the client can send a corrected request on the same
                // connection.
                let resp = KeyAgentResponse::error(format!("decode error: {e}"));
                write_frame(&mut writer, &resp.encode_to_vec())?;
                continue;
            }
        };

        let resp = match dispatch(&req) {
            Ok(resp) => resp,
            Err(e) => KeyAgentResponse::error(format!("dispatch error: {e}")),
        };
        write_frame(&mut writer, &resp.encode_to_vec())?;
    }
}

#[cfg(test)]
mod tests {
    use std::{os::unix::net::UnixStream, thread};

    use prost::Message;

    use super::*;
    use crate::{
        frame::{read_frame, write_frame},
        proto::{Empty, PayX402Request},
        request::{KeyAgentRequest, KeyAgentRequestKind},
        response::{KeyAgentResponse, KeyAgentResponseKind},
    };

    #[test]
    fn test_socket_path_from_xdg_runtime_dir() {
        // Pure-logic test — no env mutation, no race under parallel execution.
        assert_eq!(
            socket_path_from(Some("/run/user/12345")),
            "/run/user/12345/onecipher/key-agent.sock"
        );
    }

    #[test]
    fn test_socket_path_from_no_xdg_fallback() {
        // Deviation: no UID suffix in the fallback path.
        assert_eq!(socket_path_from(None), "/tmp/onecipher-key-agent.sock");
    }

    #[test]
    fn test_handle_conn_request_response_round_trip() {
        let (client, server) = UnixStream::pair().unwrap();
        let handle = thread::spawn(move || handle_conn(server));

        let req = KeyAgentRequest {
            kind: Some(KeyAgentRequestKind::PayX402(PayX402Request {
                session_key_id: "sk-round-trip".to_string(),
                url: "https://example.com".to_string(),
                method: "GET".to_string(),
                body: vec![],
                headers: std::collections::HashMap::new(),
                ..Default::default()
            })),
        };
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
