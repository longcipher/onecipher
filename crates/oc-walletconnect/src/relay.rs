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

    pub async fn recv(&mut self) -> WcResult<String> {
        loop {
            match self.ws.next().await {
                Some(frame) => match frame.opcode() {
                    OpCode::Text => return Ok(frame.as_str().to_owned()),
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
