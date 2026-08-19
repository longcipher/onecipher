//! Async Key-Agent client: UDS + length-prefixed prost frames.
//!
//! Wire format mirrors [`oc_keyagent::frame`]: a 4-byte big-endian length
//! prefix followed by a prost-encoded payload. The `oc_keyagent::frame`
//! codec uses synchronous `std::io::{Read, Write}` traits which do not
//! compose with tokio's `UnixStream`, so rather than bridging sync/async we
//! re-implement the ~30-line frame codec inline using tokio's
//! `AsyncReadExt`/`AsyncWriteExt` (ponytail step 4 — minimum code).
//!
//! The Key-Agent's `handle_conn` loop supports multiple requests per
//! connection. By default this client reuses a single long-lived connection
//! (opened lazily, guarded by a `Mutex`), which eliminates the UDS
//! connect + file-descriptor churn on every signing request under WC
//! high-concurrency. If the pooled connection is closed by the peer (EOF) or
//! errors, it is transparently re-established on the next [`send`].

use oc_keyagent::{
    KeyAgentRequest, KeyAgentResponse,
    frame::{Frame, FrameError},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    sync::Mutex,
};

use crate::error::NetAgentError;

/// Maximum frame size: 4 MiB (mirrors `oc_keyagent::frame::MAX_FRAME_SIZE`).
const MAX_FRAME_SIZE: u32 = 4 * 1024 * 1024;

/// Async client for the Key-Agent over UDS.
///
/// Reuses a single pooled connection by default (the socket path is stored as
/// a `String` so `KeyAgentClient` is `Clone`; every clone shares the same
/// underlying connection pool). Falls back to reconnect-on-error if the peer
/// closes the stream.
#[derive(Clone)]
pub struct KeyAgentClient {
    sock_path: String,
    /// Lazily-established pooled connection. `None` means "not yet connected"
    /// or "was closed — reconnect on next send". Guarded by a `Mutex` because
    /// `send` takes `&self`.
    pooled: std::sync::Arc<Mutex<Option<UnixStream>>>,
}

impl KeyAgentClient {
    /// Construct a new client targeting the Key-Agent UDS at `sock_path`.
    pub fn new(sock_path: impl Into<String>) -> Self {
        Self { sock_path: sock_path.into(), pooled: std::sync::Arc::new(Mutex::new(None)) }
    }

    /// Return the configured socket path (used by tests / diagnostics).
    pub fn sock_path(&self) -> &str {
        &self.sock_path
    }

    /// Take the pooled connection out of the shared slot, if one is present.
    ///
    /// The `Mutex` is held only for the duration of this check-and-take: the
    /// `tokio::sync::Mutex` guard is **not** retained across any `.await`
    /// point (doing so would block the worker thread). Actual I/O happens
    /// after the guard is dropped. If no pooled connection exists, a fresh
    /// one is established.
    async fn take_pooled(&self) -> Option<UnixStream> {
        self.pooled.lock().await.take()
    }

    /// Return a live connection to the pool for reuse by a later `send`.
    ///
    /// Held under the lock only for the `Option::replace`; no I/O runs while
    /// the guard is alive.
    async fn return_pooled(&self, stream: UnixStream) {
        *self.pooled.lock().await = Some(stream);
    }

    /// Obtain a live connection, reusing the pool or reconnecting as needed.
    async fn connection(&self) -> Result<UnixStream, NetAgentError> {
        if let Some(stream) = self.take_pooled().await {
            // We rely on the write/read error in `send` to reconnect if the
            // peer has since closed the socket; reusing is simpler and correct.
            return Ok(stream);
        }
        let stream = UnixStream::connect(&self.sock_path).await?;
        Ok(stream)
    }

    /// Send a `KeyAgentRequest` frame and wait for the matching
    /// `KeyAgentResponse` frame.
    ///
    /// Reuses the pooled connection when available; transparently reconnects
    /// if the peer closed it. The connection pool `Mutex` is released before
    /// any async I/O so the tokio worker thread is never blocked on a held
    /// lock (H1 fix).
    pub async fn send(&self, req: &KeyAgentRequest) -> Result<KeyAgentResponse, NetAgentError> {
        let mut stream = self.connection().await?;

        // Encode + send request frame. The typed `Frame` wrapper handles the
        // prost encode; the async transport writes the length-prefixed bytes.
        let payload = Frame::new(req.clone())
            .encode()
            .map_err(|e| NetAgentError::KeyAgentWire(format!("request encode failed: {e}")))?;
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
            self.return_pooled(stream).await;
            return Ok(KeyAgentResponse::default());
        }
        if len > MAX_FRAME_SIZE {
            self.return_pooled(stream).await;
            return Err(NetAgentError::KeyAgentWire(format!(
                "response too large: {len} bytes (max {MAX_FRAME_SIZE})"
            )));
        }
        let mut buf = vec![0u8; len as usize];
        stream
            .read_exact(&mut buf)
            .await
            .map_err(|e| NetAgentError::KeyAgentWire(format!("reading payload: {e}")))?;

        let resp = Frame::<KeyAgentResponse>::decode(buf.as_slice())
            .map(|f| f.into_inner())
            .map_err(|e| match e {
                FrameError::Decode(de) => NetAgentError::ProstDecode(de),
                other => NetAgentError::KeyAgentWire(format!("response decode failed: {other}")),
            })?;

        // Return the connection to the pool for reuse.
        self.return_pooled(stream).await;
        Ok(resp)
    }
}

#[cfg(test)]
mod tests {
    use oc_keyagent::{KeyAgentRequest, KeyAgentRequestKind, proto::Empty};
    use prost::Message;
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
