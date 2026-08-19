//! WC v2 relay client (WebSocket Secure).
//!
//! Connects to a Waku v2 relay endpoint, provides send/recv over text frames.
//! Real WC v2 also uses Waku v2 pub/sub — for MVP we implement a thin
//! request/response wrapper where each JSON-RPC message is one WS text frame.

use std::time::Duration;

use backon::{ExponentialBuilder, Retryable};
use futures::{SinkExt, StreamExt};
use hpx_yawc::{
    MaybeTlsStream, WebSocket,
    frame::{Frame, OpCode},
};

use crate::error::{WcError, WcResult};

#[derive(Debug, Clone)]
pub struct RelayConfig {
    pub url: String,
    pub reconnect_max_ms: u64,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self { url: "wss://relay.walletconnect.com".into(), reconnect_max_ms: 60_000 }
    }
}

/// Normalize a relay URL by ensuring a `projectId` query param is present when
/// a project ID is supplied and the URL does not already carry one.
///
/// The official WalletConnect Cloud relay (`relay.walletconnect.com`) requires
/// `?projectId=<id>`; local/self-hosted relays may accept it or not, so the
/// param is only appended when a project ID is explicitly configured.
pub fn apply_project_id(url: &str, project_id: Option<&str>) -> String {
    match project_id {
        Some(pid) if !pid.is_empty() => {
            if url.contains('?') {
                format!("{url}&projectId={pid}")
            } else {
                format!("{url}?projectId={pid}")
            }
        }
        _ => url.to_string(),
    }
}

pub struct RelayClient {
    ws: WebSocket<MaybeTlsStream<tokio::net::TcpStream>>,
    cfg: RelayConfig,
}

impl RelayClient {
    pub async fn connect(cfg: RelayConfig) -> WcResult<Self> {
        let url = cfg.url.parse().map_err(|e| WcError::Relay(format!("invalid url: {e}")))?;
        let ws = WebSocket::connect(url).await?;
        Ok(Self { ws, cfg })
    }

    pub async fn send_text(&mut self, s: impl Into<String>) -> WcResult<()> {
        self.ws.send(Frame::text(s.into())).await?;
        Ok(())
    }

    pub async fn send_binary(&mut self, b: impl Into<Vec<u8>>) -> WcResult<()> {
        self.ws.send(Frame::binary(b.into())).await?;
        Ok(())
    }

    /// Publish a message to a topic using the IRN `irn_publish` JSON-RPC
    /// method. `message` is the base64-encoded envelope; `attestation` is an
    /// optional Verify-service JWT (per the official relay RPC spec).
    pub async fn publish_irn(
        &mut self,
        id: &str,
        topic: &str,
        message_b64: &str,
        ttl: u32,
        tag: u32,
        attestation: Option<&str>,
    ) -> WcResult<()> {
        let mut params = serde_json::json!({
            "topic": topic,
            "message": message_b64,
            "ttl": ttl,
            "tag": tag,
        });
        if let Some(a) = attestation {
            params["attestation"] = serde_json::json!(a);
        }
        let msg = serde_json::json!({
            "id": id,
            "jsonrpc": "2.0",
            "method": "irn_publish",
            "params": params,
        });
        self.send_text(serde_json::to_string(&msg)?).await
    }

    pub async fn recv(&mut self) -> WcResult<String> {
        loop {
            match self.ws.next().await {
                Some(frame) => match frame.opcode() {
                    OpCode::Text => return Ok(frame.as_str()?.to_owned()),
                    OpCode::Binary => {
                        return Ok(String::from_utf8_lossy(frame.payload()).into_owned());
                    }
                    OpCode::Ping => {
                        self.ws.send(Frame::pong(frame.payload().to_vec())).await?;
                    }
                    OpCode::Close => {
                        return Err(WcError::Relay("connection closed".into()));
                    }
                    _ => {}
                },
                None => return Err(WcError::Relay("stream ended".into())),
            }
        }
    }

    /// Like [`recv`](Self::recv) but bounds the wait with `timeout`. On timeout
    /// it returns [`WcError::RelayTimeout`] instead of blocking forever, so the
    /// caller's event loop can re-check cancellation / subscription state
    /// (M2 fix — the previous unbounded `recv` could hang indefinitely if the
    /// relay went silent).
    pub async fn recv_timeout(&mut self, timeout: Duration) -> WcResult<String> {
        match tokio::time::timeout(timeout, self.recv()).await {
            Ok(res) => res,
            Err(_) => Err(WcError::RelayTimeout(format!("no relay message within {timeout:?}"))),
        }
    }

    /// Gracefully close the underlying WebSocket by sending a Close frame.
    ///
    /// Best-effort: any error is swallowed because the connection is being
    /// torn down anyway. Without this, a dropped `RelayClient` simply drops
    /// the socket, leaving the peer to time out the half-open connection.
    pub async fn close(&mut self) {
        let _ = self.ws.send(Frame::close(hpx_yawc::close::CloseCode::Normal, b"shutdown")).await;
    }

    /// Reconnect with exponential backoff (capped at `reconnect_max_ms`),
    /// jitter enabled to avoid thundering-herd on shared relay outages.
    pub async fn reconnect(&mut self) -> WcResult<()> {
        let url_str = self.cfg.url.clone();
        let builder = ExponentialBuilder::default()
            .with_min_delay(Duration::from_millis(100))
            .with_max_delay(Duration::from_millis(self.cfg.reconnect_max_ms))
            .with_jitter();

        let ws = {
            || async {
                let url =
                    url_str.parse().map_err(|e: url::ParseError| WcError::Relay(e.to_string()))?;
                WebSocket::connect(url).await.map_err(WcError::from)
            }
        }
        .retry(builder)
        .await?;

        self.ws = ws;
        Ok(())
    }
}
