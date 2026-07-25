//! Web UI approval surface for OneCipher daemon.
//!
//! Provides a locally-served browser-based approval flow for signing requests
//! received via WalletConnect v2. Built on axum with WebAuthn authentication
//! and real-time WebSocket updates.

#![forbid(unsafe_code)]

use std::{io, net::SocketAddr, path::PathBuf};

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
    _state_dir: PathBuf,
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

    let state = AppState { queue };

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
        .with_state(state);

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
