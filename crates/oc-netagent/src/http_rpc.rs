//! Local loopback-only HTTP JSON-RPC 2.0 server.
//!
//! A lightweight, transport-independent surface for AI agents and local scripts
//! to invoke the same signing methods exposed over WalletConnect v2 — but
//! *without* the WC relay. Requests arrive over plain HTTP on a loopback-only
//! address, are decoded as JSON-RPC 2.0, and are dispatched through the same
//! [`WcMethodRouter`] the WC wallet server uses.
//!
//! Endpoints:
//! - `POST /rpc`    — JSON-RPC 2.0 method dispatch.
//! - `GET  /health` — liveness probe (`{"ok": true, "version": ...}`).
//!
//! The `oc_health` method is handled locally (no Key-Agent round trip). Every
//! other method (including `oc_listWallets` and all `onecipher_*` signing
//! methods) is forwarded to the router, which translates it into a
//! `KeyAgentRequest` frame sent to the Key-Agent over UDS.
//!
//! ## R12e (loopback-only bind)
//!
//! [`LocalRpcServer::bind`] refuses any non-loopback listen address — mirroring
//! the Web UI's enforcement in `oc-webui` — so a misconfigured config cannot
//! expose the signing surface to the network.

use std::{
    net::SocketAddr,
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};

use axum::{
    Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use oc_walletconnect::WalletMethodHandler;
use serde_json::{Value, json};

use crate::{WcMethodRouter, error::NetAgentError, key_agent_client::KeyAgentClient};

/// Standard JSON-RPC 2.0 error codes. (Unknown-method errors surface as the
/// router's `UnsupportedMethod` code instead of `-32601`, so it is not listed
/// here.)
const PARSE_ERROR: i64 = -32700;
const INVALID_REQUEST: i64 = -32600;

/// Configuration for the local HTTP JSON-RPC server.
#[allow(clippy::struct_field_names)]
pub struct LocalRpcServerConfig {
    /// Address to bind. MUST be loopback (R12e); anything else is rejected.
    pub listen: SocketAddr,
    /// UDS path to the Key-Agent.
    pub key_agent_sock: String,
    /// Optional approval channel, mirroring `WcMethodRouter::with_approval`.
    pub approval: Option<crate::approval::ApprovalChannel>,
    /// Whether approval mode is active for signing requests.
    pub approval_mode: Arc<AtomicBool>,
    /// Timeout for waiting on an approval decision.
    pub approval_timeout: Duration,
    /// Optional persistent log for approvals.
    pub approval_log: Option<Arc<oc_core::approval_log::ApprovalLog>>,
}

/// Local HTTP JSON-RPC server backed by a [`WcMethodRouter`].
pub struct LocalRpcServer {
    router: WcMethodRouter,
    listen: SocketAddr,
}

impl LocalRpcServer {
    /// Build a new server from the given configuration.
    ///
    /// When `config.approval` is `Some`, the router is constructed with the
    /// approval wiring via [`WcMethodRouter::with_approval`]; otherwise it is a
    /// plain [`WcMethodRouter::new`].
    pub fn new(config: LocalRpcServerConfig) -> Self {
        let key_agent = KeyAgentClient::new(&config.key_agent_sock);
        let router = match config.approval {
            Some(channel) => WcMethodRouter::with_approval(
                key_agent,
                channel,
                config.approval_mode,
                config.approval_timeout,
                config.approval_log,
            ),
            None => WcMethodRouter::new(key_agent),
        };
        Self { router, listen: config.listen }
    }

    /// Validate R12e (loopback-only) and bind the TCP listener.
    ///
    /// Returns the bound listener and the actual port (useful when `listen`
    /// specified port `0`). Call [`Self::router`] before serving.
    pub async fn bind(&self) -> Result<(tokio::net::TcpListener, u16), NetAgentError> {
        if !self.listen.ip().is_loopback() {
            return Err(NetAgentError::InvalidRequest(format!(
                "HTTP-RPC MUST bind to loopback (127.0.0.1) only; got {}",
                self.listen
            )));
        }
        let listener = tokio::net::TcpListener::bind(self.listen).await?;
        let port = listener.local_addr()?.port();
        Ok((listener, port))
    }

    /// Build the axum [`Router`].
    ///
    /// State is the shared [`WcMethodRouter`]; `POST /rpc` dispatches
    /// JSON-RPC methods, `GET /health` is a plain liveness probe.
    pub fn router(self) -> Router {
        let state = Arc::new(self.router);
        Router::new()
            .route("/rpc", post(handle_rpc))
            .route("/health", get(handle_health))
            .with_state(state)
    }

    /// Bind (R12e-checked) and serve forever.
    ///
    /// Returns the bound port (useful when `listen` specified port `0`).
    /// Convenience wrapper around [`Self::bind`] + `axum::serve`; prefer
    /// [`Self::bind`]/[`Self::router`] when the caller needs the listener or
    /// wants to control the serve task.
    pub async fn serve(self) -> Result<u16, NetAgentError> {
        let (listener, port) = self.bind().await?;
        let app = self.router();
        tracing::info!(port, "HTTP-RPC server listening on loopback");
        axum::serve(listener, app).await?;
        Ok(port)
    }
}

/// Decoded JSON-RPC 2.0 request. Fields are lenient so a malformed body maps
/// to a JSON-RPC error rather than an HTTP-level rejection.
#[derive(serde::Deserialize)]
struct JsonRpcRequest {
    #[serde(default)]
    id: Option<Value>,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    params: Option<Value>,
}

/// Handle `GET /health`.
async fn handle_health() -> Response {
    (StatusCode::OK, axum::Json(json!({ "ok": true, "version": env!("CARGO_PKG_VERSION") })))
        .into_response()
}

/// Handle `POST /rpc` — JSON-RPC 2.0 dispatch.
async fn handle_rpc(State(router): State<Arc<WcMethodRouter>>, body: String) -> Response {
    let req: JsonRpcRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(e) => return error_response(Value::Null, PARSE_ERROR, &format!("parse error: {e}")),
    };
    let id = req.id.unwrap_or(Value::Null);
    let Some(method) = req.method else {
        return error_response(id, INVALID_REQUEST, "missing method");
    };

    // Local methods served without a Key-Agent round trip.
    if method == "oc_health" {
        return success_response(id, json!({ "ok": true, "version": env!("CARGO_PKG_VERSION") }));
    }

    // Everything else goes through the WC method router translation layer
    // (empty session topic — the router ignores it for local dispatch).
    let params = req.params.unwrap_or_else(|| Value::Object(Default::default()));
    match router.handle(&method, params, "").await {
        Ok(result) => success_response(id, result),
        Err((code, message)) => error_response(id, code as i64, &message),
    }
}

/// JSON-RPC 2.0 success response (HTTP 200).
fn success_response(id: Value, result: Value) -> Response {
    (StatusCode::OK, axum::Json(json!({ "jsonrpc": "2.0", "id": id, "result": result })))
        .into_response()
}

/// JSON-RPC 2.0 error response (HTTP 200 with an `error` object, per spec).
fn error_response(id: Value, code: i64, message: &str) -> Response {
    (
        StatusCode::OK,
        axum::Json(
            json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } }),
        ),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, atomic::AtomicBool},
        time::Duration,
    };

    use axum::http::StatusCode;
    use serde_json::Value;
    use tokio::time::sleep;

    use super::*;

    fn config(listen: SocketAddr) -> LocalRpcServerConfig {
        LocalRpcServerConfig {
            listen,
            key_agent_sock: "/tmp/onecipher-rpc-test-nonexistent.sock".to_string(),
            approval: None,
            approval_mode: Arc::new(AtomicBool::new(false)),
            approval_timeout: Duration::from_secs(5),
            approval_log: None,
        }
    }

    /// Bind, build the router, and serve in the background. Returns the port.
    async fn serve_in_background(listen: SocketAddr) -> u16 {
        let server = LocalRpcServer::new(config(listen));
        let (listener, port) = server.bind().await.expect("bind loopback");
        let app = server.router();
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });
        // Let the listener accept before the first request.
        sleep(Duration::from_millis(30)).await;
        port
    }

    #[tokio::test]
    async fn bind_rejects_non_loopback() {
        let server = LocalRpcServer::new(config("0.0.0.0:8080".parse().expect("addr")));
        let err = server.bind().await.expect_err("must reject non-loopback");
        assert!(err.to_string().contains("loopback"), "got {err}");
    }

    #[tokio::test]
    async fn health_endpoint_returns_ok() {
        let port = serve_in_background("127.0.0.1:0".parse().expect("addr")).await;
        let resp = reqwest::get(format!("http://127.0.0.1:{port}/health")).await.expect("get");
        assert_eq!(resp.status(), StatusCode::OK);
        let v: Value = resp.json().await.expect("json");
        assert_eq!(v["ok"], true);
        assert!(v["version"].is_string());
    }

    #[tokio::test]
    async fn oc_health_method_served_locally() {
        let port = serve_in_background("127.0.0.1:0".parse().expect("addr")).await;
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://127.0.0.1:{port}/rpc"))
            .header("content-type", "application/json")
            .body(r#"{"jsonrpc":"2.0","id":7,"method":"oc_health","params":{}}"#)
            .send()
            .await
            .expect("post");
        assert_eq!(resp.status(), StatusCode::OK);
        let v: Value = resp.json().await.expect("json");
        assert_eq!(v["id"], 7);
        assert_eq!(v["result"]["ok"], true);
    }

    #[tokio::test]
    async fn unknown_method_returns_jsonrpc_error() {
        let port = serve_in_background("127.0.0.1:0".parse().expect("addr")).await;
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://127.0.0.1:{port}/rpc"))
            .header("content-type", "application/json")
            .body(r#"{"jsonrpc":"2.0","id":1,"method":"oc_doesNotExist","params":{}}"#)
            .send()
            .await
            .expect("post");
        let v: Value = resp.json().await.expect("json");
        assert_eq!(v["error"]["code"], 4200); // UnsupportedMethod
        assert!(v["error"]["message"].as_str().is_some());
    }

    #[tokio::test]
    async fn missing_method_returns_invalid_request() {
        let port = serve_in_background("127.0.0.1:0".parse().expect("addr")).await;
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://127.0.0.1:{port}/rpc"))
            .header("content-type", "application/json")
            .body(r#"{"jsonrpc":"2.0","id":1,"params":{}}"#)
            .send()
            .await
            .expect("post");
        let v: Value = resp.json().await.expect("json");
        assert_eq!(v["error"]["code"], INVALID_REQUEST);
    }

    #[tokio::test]
    async fn malformed_body_returns_parse_error() {
        let port = serve_in_background("127.0.0.1:0".parse().expect("addr")).await;
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://127.0.0.1:{port}/rpc"))
            .header("content-type", "application/json")
            .body("not json")
            .send()
            .await
            .expect("post");
        let v: Value = resp.json().await.expect("json");
        assert_eq!(v["error"]["code"], PARSE_ERROR);
    }

    #[tokio::test]
    async fn key_agent_dependent_method_errors_without_panic() {
        // onecipher_listWallets forwards to a non-existent Key-Agent socket; it
        // must surface a JSON-RPC internal error, not panic the server.
        let port = serve_in_background("127.0.0.1:0".parse().expect("addr")).await;
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://127.0.0.1:{port}/rpc"))
            .header("content-type", "application/json")
            .body(r#"{"jsonrpc":"2.0","id":2,"method":"onecipher_listWallets","params":{}}"#)
            .send()
            .await
            .expect("post");
        let v: Value = resp.json().await.expect("json");
        assert_eq!(v["error"]["code"], 5000); // Internal
    }
}
