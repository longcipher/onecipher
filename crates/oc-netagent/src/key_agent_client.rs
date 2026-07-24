//! Async Key-Agent client: UDS + length-prefixed prost frames.
//!
//! Wire format mirrors [`oc_keyagent::frame`]: a 4-byte big-endian length
//! prefix followed by a prost-encoded payload. The `oc_keyagent::frame`
//! codec uses synchronous `std::io::{Read, Write}` traits which do not
//! compose with tokio's `UnixStream`, so rather than bridging sync/async we
//! re-implement the ~30-line frame codec inline using tokio's
//! `AsyncReadExt`/`AsyncWriteExt` (ponytail step 4 — minimum code).
//!
//! Each [`KeyAgentClient::send`] call opens a fresh `UnixStream` connection to
//! the Key-Agent, sends one `KeyAgentRequest` frame, and reads one
//! `KeyAgentResponse` frame. The Key-Agent's `handle_conn` loop supports
//! multiple requests per connection, so reusing the connection is possible —
//! but for T17 scaffolding, one-request-per-connection keeps the client
//! stateless and avoids lifetime issues across `&self` borrows.

use oc_keyagent::{KeyAgentRequest, KeyAgentResponse};
use prost::Message;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};

use crate::error::NetAgentError;

/// Maximum frame size: 4 MiB (mirrors `oc_keyagent::frame::MAX_FRAME_SIZE`).
const MAX_FRAME_SIZE: u32 = 4 * 1024 * 1024;

/// Async client for the Key-Agent over UDS.
///
/// Stateless — each [`send`] call opens a new connection. The socket path is
/// stored as a `String` so `KeyAgentClient` is `Clone` (the WC method router
/// may be invoked from multiple tokio tasks).
#[derive(Clone)]
pub struct KeyAgentClient {
    sock_path: String,
}

impl KeyAgentClient {
    /// Construct a new client targeting the Key-Agent UDS at `sock_path`.
    pub fn new(sock_path: impl Into<String>) -> Self {
        Self { sock_path: sock_path.into() }
    }

    /// Return the configured socket path (used by tests / diagnostics).
    pub fn sock_path(&self) -> &str {
        &self.sock_path
    }

    /// Send a `KeyAgentRequest` frame and wait for the matching
    /// `KeyAgentResponse` frame.
    ///
    /// One request per connection — opens a fresh `UnixStream`, sends the
    /// encoded request, reads the encoded response, and closes the stream.
    pub async fn send(&self, req: &KeyAgentRequest) -> Result<KeyAgentResponse, NetAgentError> {
        let mut stream = UnixStream::connect(&self.sock_path).await?;

        // Encode + send request frame.
        let payload = req.encode_to_vec();
        if payload.len() > MAX_FRAME_SIZE as usize {
            return Err(NetAgentError::KeyAgentWire(format!(
                "request too large: {} bytes (max {MAX_FRAME_SIZE})",
                payload.len()
            )));
        }
        let len = u32::try_from(payload.len()).map_err(|_| {
            NetAgentError::KeyAgentWire(format!("request length overflow: {} bytes", payload.len()))
        })?;
        stream.write_all(&len.to_be_bytes()).await?;
        stream.write_all(&payload).await?;
        stream.flush().await?;

        // Read response frame.
        let mut len_buf = [0u8; 4];
        stream
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| NetAgentError::KeyAgentWire(format!("reading length prefix: {e}")))?;
        let len = u32::from_be_bytes(len_buf);
        if len == 0 {
            // Empty payload — decode as a default (kind=None) response.
            return Ok(KeyAgentResponse::default());
        }
        if len > MAX_FRAME_SIZE {
            return Err(NetAgentError::KeyAgentWire(format!(
                "response too large: {len} bytes (max {MAX_FRAME_SIZE})"
            )));
        }
        let mut buf = vec![0u8; len as usize];
        stream
            .read_exact(&mut buf)
            .await
            .map_err(|e| NetAgentError::KeyAgentWire(format!("reading payload: {e}")))?;

        KeyAgentResponse::decode(buf.as_slice()).map_err(NetAgentError::ProstDecode)
    }
}

#[cfg(test)]
mod tests {
    use oc_keyagent::{KeyAgentRequest, KeyAgentRequestKind, proto::Empty};
    use tokio::net::UnixListener;

    use super::*;

    /// Spin up a one-shot mock Key-Agent that echoes a canned response.
    async fn spawn_mock_keyagent(
        sock_path: String,
        canned: KeyAgentResponse,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let listener = UnixListener::bind(&sock_path).expect("bind mock keyagent");
            let (mut stream, _) = listener.accept().await.expect("accept mock keyagent");

            // Read one request frame.
            let mut len_buf = [0u8; 4];
            stream.read_exact(&mut len_buf).await.unwrap();
            let len = u32::from_be_bytes(len_buf);
            let mut req_buf = vec![0u8; len as usize];
            stream.read_exact(&mut req_buf).await.unwrap();
            // (We don't need to decode the request for this test — we just
            // need to drain it.)

            // Write canned response frame.
            let resp_bytes = canned.encode_to_vec();
            stream.write_all(&(resp_bytes.len() as u32).to_be_bytes()).await.unwrap();
            stream.write_all(&resp_bytes).await.unwrap();
            stream.flush().await.unwrap();
        })
    }

    #[tokio::test]
    async fn test_send_receives_canned_response() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("keyagent.sock").to_string_lossy().to_string();

        let canned = KeyAgentResponse::ok(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let handle = spawn_mock_keyagent(sock_path.clone(), canned).await;

        // Tiny delay so the listener is bound before we connect.
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        let client = KeyAgentClient::new(&sock_path);
        let req = KeyAgentRequest { kind: Some(KeyAgentRequestKind::ListWallets(Empty {})) };
        let resp = client.send(&req).await.expect("send must succeed");
        match resp.kind {
            Some(oc_keyagent::KeyAgentResponseKind::Ok(payload)) => {
                assert_eq!(payload, vec![0xDE, 0xAD, 0xBE, 0xEF]);
            }
            other => panic!("expected Ok, got {other:?}"),
        }

        handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_send_returns_error_when_keyagent_unreachable() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("nonexistent.sock").to_string_lossy().to_string();

        let client = KeyAgentClient::new(&sock_path);
        let req = KeyAgentRequest { kind: Some(KeyAgentRequestKind::ListWallets(Empty {})) };
        let result = client.send(&req).await;
        assert!(result.is_err(), "connecting to a missing socket must error");
        match result.unwrap_err() {
            NetAgentError::Io(_) => {}
            other => panic!("expected Io error, got {other:?}"),
        }
    }
}
