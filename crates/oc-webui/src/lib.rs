//! Web UI approval surface for OneCipher daemon.
//!
//! Provides a locally-served browser-based approval flow for signing requests
//! received via WalletConnect v2. Built on axum with WebAuthn authentication
//! and real-time WebSocket updates.

#![forbid(unsafe_code)]

use std::{io, net::SocketAddr, path::PathBuf};

use axum::response::IntoResponse;
use oc_core::{
    WebuiConfig,
    approval::{ApprovalDecision, PendingApproval},
};
use tokio::{
    net::TcpListener,
    sync::{mpsc, oneshot},
    task::JoinHandle,
};

pub mod approval_queue;
pub mod auth;
pub mod error;
pub mod routes;
pub mod submit_actions;

pub use approval_queue::ApprovalQueue;
pub use auth::SessionStore;
pub use routes::approvals::AppState;

/// Run the Web UI HTTP server on a loopback-only address.
///
/// Returns the spawned task handle and the actual bound port.
///
/// # Arguments
///
/// - `config` — Web UI configuration from `config.toml`.
/// - `state_dir` — Path to `~/.onecipher/` state directory.
/// - `approval_rx` — Receiver end of the approval channel (from `ApprovalChannel::new()`).
///
/// # Errors
///
/// Returns an error if the bind address is not loopback or the listener
/// cannot be created.
pub async fn run_webui_server(
    config: &WebuiConfig,
    state_dir: PathBuf,
    approval_rx: mpsc::Receiver<(PendingApproval, oneshot::Sender<ApprovalDecision>)>,
) -> io::Result<(JoinHandle<()>, u16)> {
    let addr: SocketAddr = config.listen.parse().map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidInput, format!("invalid listen address: {e}"))
    })?;

    // R12e: reject non-loopback bind
    if !addr.ip().is_loopback() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Web UI MUST bind to loopback (127.0.0.1) only",
        ));
    }

    let listener = TcpListener::bind(addr).await?;
    let bound_port = listener.local_addr()?.port();

    // Set up the approval queue
    let queue = ApprovalQueue::new(64);
    queue.spawn_receiver(approval_rx);

    // Session store for WebAuthn sessions (default 30-minute idle timeout)
    let session_store = SessionStore::new(1800);

    let state = AppState { queue, state_dir, session_store };

    let app = axum::Router::new()
        .route("/api/health", axum::routing::get(health_handler))
        // Approvals
        .route("/api/approvals", axum::routing::get(routes::approvals::list_approvals))
        .route("/api/approvals/history", axum::routing::get(routes::approvals::approval_history))
        .route("/api/approvals/{id}", axum::routing::get(routes::approvals::get_approval))
        .route(
            "/api/approvals/{id}/decision",
            axum::routing::post(routes::approvals::submit_decision),
        )
        .route(
            "/api/approvals/{id}/simulate",
            axum::routing::post(routes::approvals::simulate_approval),
        )
        // Wallets
        .route("/api/wallets", axum::routing::get(routes::wallets::list_wallets))
        .route("/api/wallets", axum::routing::post(routes::wallets::create_wallet))
        .route("/api/wallets/import", axum::routing::post(routes::wallets::import_wallet))
        .route("/api/wallets/{id}", axum::routing::get(routes::wallets::get_wallet))
        .route("/api/wallets/{id}", axum::routing::delete(routes::wallets::delete_wallet))
        .route(
            "/api/wallets/{id}/balances",
            axum::routing::get(routes::wallets::get_wallet_balances),
        )
        .route("/api/wallets/{id}/send", axum::routing::post(routes::wallets::send_transaction))
        // WC Sessions
        .route("/api/sessions", axum::routing::get(routes::sessions::list_sessions))
        .route("/api/sessions/{topic}", axum::routing::delete(routes::sessions::disconnect_session))
        .route("/api/sessions/pair", axum::routing::post(routes::sessions::pair_session))
        .route("/api/sessions/generate", axum::routing::post(routes::sessions::generate_session))
        // Audit
        .route("/api/audit", axum::routing::get(routes::audit::get_audit))
        // Settings
        .route("/api/settings", axum::routing::get(routes::settings::get_settings))
        .route("/api/settings", axum::routing::patch(routes::settings::patch_settings))
        // Settings: Policy
        .route(
            "/api/settings/policy",
            axum::routing::get(routes::settings::policy::list_policy_rules),
        )
        .route(
            "/api/settings/policy",
            axum::routing::post(routes::settings::policy::create_policy_rule),
        )
        .route(
            "/api/settings/policy/{id}",
            axum::routing::get(routes::settings::policy::get_policy_rule),
        )
        .route(
            "/api/settings/policy/{id}",
            axum::routing::put(routes::settings::policy::update_policy_rule),
        )
        .route(
            "/api/settings/policy/{id}",
            axum::routing::delete(routes::settings::policy::delete_policy_rule),
        )
        // Settings: Session Keys
        .route(
            "/api/settings/session-keys",
            axum::routing::get(routes::settings::session_keys::list_session_keys),
        )
        .route(
            "/api/settings/session-keys",
            axum::routing::post(routes::settings::session_keys::create_session_key),
        )
        .route(
            "/api/settings/session-keys/{id}",
            axum::routing::get(routes::settings::session_keys::get_session_key),
        )
        .route(
            "/api/settings/session-keys/{id}",
            axum::routing::put(routes::settings::session_keys::update_session_key),
        )
        .route(
            "/api/settings/session-keys/{id}",
            axum::routing::delete(routes::settings::session_keys::delete_session_key),
        )
        // Settings: Secrets
        .route("/api/settings/secrets", axum::routing::get(routes::settings::secrets::list_secrets))
        .route(
            "/api/settings/secrets",
            axum::routing::post(routes::settings::secrets::create_secret),
        )
        .route(
            "/api/settings/secrets/{id}",
            axum::routing::get(routes::settings::secrets::get_secret),
        )
        .route(
            "/api/settings/secrets/{id}",
            axum::routing::put(routes::settings::secrets::update_secret),
        )
        .route(
            "/api/settings/secrets/{id}",
            axum::routing::delete(routes::settings::secrets::delete_secret),
        )
        // WebSocket
        .route("/ws", axum::routing::get(routes::ws::ws_handler))
        .with_state(state)
        // Serve frontend SPA for all non-API routes.
        .fallback(spa_fallback);

    let handle = tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            tracing::error!(error = %e, "Web UI server exited with error");
        }
    });

    tracing::info!(port = bound_port, "Web UI server started on 127.0.0.1");
    Ok((handle, bound_port))
}

/// Health check handler (no auth required).
async fn health_handler() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "ok": true,
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

/// SPA fallback handler: serves static files from the frontend dist directory.
///
/// If the requested path matches a file in the dist directory, serve it.
/// Otherwise, serve `index.html` for SPA client-side routing.
async fn spa_fallback(
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
) -> impl axum::response::IntoResponse {
    let path = uri.path().trim_start_matches('/');
    let dist = find_frontend_dist();

    // Try to serve the exact file from the dist directory.
    if !path.is_empty() {
        let file_path = dist.join(path);
        if file_path.is_file() {
            return serve_file(&file_path).await;
        }
    }

    // SPA fallback: serve index.html for any non-file route.
    let index = dist.join("index.html");
    if index.is_file() {
        return serve_file(&index).await;
    }

    // No frontend built — return a helpful message.
    (
        axum::http::StatusCode::NOT_FOUND,
        axum::response::Html(
            "<h1>Frontend not built</h1>\
             <p>Run <code>trunk build --release</code> in \
             <code>crates/oc-webui/frontend/</code> to build the SPA.</p>\
             <p>API is available at <a href=\"/api/health\">/api/health</a>.</p>"
                .to_string(),
        ),
    )
        .into_response()
}

/// Serve a single file with the correct content type.
async fn serve_file(path: &std::path::Path) -> axum::response::Response {
    let content_type = match path.extension().and_then(|e| e.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "application/javascript; charset=utf-8",
        Some("wasm") => "application/wasm",
        Some("css") => "text/css; charset=utf-8",
        Some("json") => "application/json",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("ico") => "image/x-icon",
        _ => "application/octet-stream",
    };

    match tokio::fs::read(path).await {
        Ok(bytes) => {
            (axum::http::StatusCode::OK, [(axum::http::header::CONTENT_TYPE, content_type)], bytes)
                .into_response()
        }
        Err(_) => axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// Find the frontend dist directory.
///
/// Searches in order:
/// 1. `~/.onecipher/webui-dist/` (user override)
/// 2. Workspace-relative `crates/oc-webui/frontend/dist/`
/// 3. Binary-relative `../share/onecipher/webui-dist/`
fn find_frontend_dist() -> PathBuf {
    // 1. User override in state dir
    if let Ok(home) = std::env::var("HOME") {
        let user_dist = PathBuf::from(home).join(".onecipher").join("webui-dist");
        if user_dist.join("index.html").is_file() {
            return user_dist;
        }
    }

    // 2. Workspace-relative (development)
    if let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") {
        let dev_dist = PathBuf::from(manifest_dir).join("frontend").join("dist");
        if dev_dist.join("index.html").is_file() {
            return dev_dist;
        }
    }

    // 3. Fallback: try the crate's frontend/dist relative to the source tree. This covers `cargo
    //    run` from the workspace root.
    let workspace_dist = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("frontend").join("dist");
    if workspace_dist.join("index.html").is_file() {
        return workspace_dist;
    }

    // 4. Return the workspace path even if not found — the fallback handler will show a helpful
    //    "not built" message.
    workspace_dist
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rejects_non_loopback() {
        let config =
            WebuiConfig { enabled: true, listen: "0.0.0.0:8080".to_string(), ..Default::default() };
        let (_tx, rx) = mpsc::channel(16);
        let result = run_webui_server(&config, PathBuf::from("/tmp"), rx).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn test_binds_loopback_successfully() {
        let config =
            WebuiConfig { enabled: true, listen: "127.0.0.1:0".to_string(), ..Default::default() };
        let state_dir = tempfile::tempdir().unwrap();
        let (_tx, rx) = mpsc::channel(16);
        let result = run_webui_server(&config, state_dir.path().to_path_buf(), rx).await;
        assert!(result.is_ok());
        let (handle, port) = result.unwrap();
        assert!(port > 0);
        handle.abort();
    }

    #[tokio::test]
    async fn test_health_endpoint() {
        let config =
            WebuiConfig { enabled: true, listen: "127.0.0.1:0".to_string(), ..Default::default() };
        let state_dir = tempfile::tempdir().unwrap();
        let (_tx, rx) = mpsc::channel(16);
        let (_handle, port) =
            run_webui_server(&config, state_dir.path().to_path_buf(), rx).await.unwrap();

        // Make an HTTP request to the health endpoint
        let resp = reqwest::get(format!("http://127.0.0.1:{port}/api/health")).await.unwrap();
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["ok"], true);

        _handle.abort();
    }
}
