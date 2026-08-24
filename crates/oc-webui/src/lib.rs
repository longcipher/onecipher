// Test code may unwrap/expect/panic (workspace lint phase-1 carve-out).
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
//! Web UI approval surface for OneCipher daemon.
//!
//! Provides a locally-served browser-based approval flow for signing requests
//! received via WalletConnect v2. Built on axum with WebAuthn authentication
//! and real-time WebSocket updates.

#![forbid(unsafe_code)]

use std::{
    io,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use axum::{middleware::from_fn_with_state, response::IntoResponse};
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
    pairing_tx: mpsc::Sender<oc_walletconnect::PairingUri>,
    dual_register: Option<routes::auth::DualRegistrationFn>,
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

    // Set up the approval queue with a persistent JSONL log for crash recovery.
    let log = std::sync::Arc::new(
        oc_core::approval_log::ApprovalLog::open(&state_dir)
            .map_err(|e| io::Error::other(format!("approval log: {e}")))?,
    );
    let queue = ApprovalQueue::with_log(64, log.clone());

    // Replay unresolved approvals from a previous daemon run so the user can
    // still see and clear them after a restart.
    match log.replay_unresolved() {
        Ok(orphans) if !orphans.is_empty() => {
            tracing::info!(count = orphans.len(), "replaying orphaned approvals from log");
            queue.replay_orphans(orphans);
        }
        Ok(_) => {}
        Err(e) => tracing::warn!(error = %e, "failed to replay approval log"),
    }

    // Best-effort GC of resolved entries older than 7 days.
    if let Err(e) = log.gc_older_than(7) {
        tracing::warn!(error = %e, "approval log GC failed");
    }

    queue.spawn_receiver(approval_rx);

    // Session store for WebAuthn sessions (default 30-minute idle timeout)
    let session_store = SessionStore::new(1800);

    // WebAuthn manager + bootstrap token for the auth routes (W1.6). The
    // relying-party origin is the loopback server's own origin.
    // webauthn-rs requires a hostname RP ID — an IP address is rejected as an
    // invalid origin. `localhost` is what the browser treats as loopback, so
    // the RP origin and the loopback-only listener agree.
    let origin = url::Url::parse(&format!("http://localhost:{bound_port}"))
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("origin parse: {e}")))?;
    let webauthn = auth::WebAuthnManager::new(&state_dir, &origin)
        .map_err(|e| io::Error::other(format!("webauthn init: {e}")))?;
    let bootstrap = auth::BootstrapToken::new(&state_dir);
    let auto_lock_at = std::sync::Arc::new(tokio::sync::Mutex::new(None));
    // The daemon installs a dual-registration callback that mirrors a browser
    // passkey into the Key-Agent's PasskeyPubkeyStore. oc-webui itself must
    // NOT depend on oc-keyagent (that would drag BoringSSL into this crate's
    // graph and break the OpenSSL/BoringSSL link ordering in the final
    // binary), so the wiring happens in oc-cli.
    let auth_state = routes::auth::AuthState {
        webauthn,
        bootstrap,
        session_store: session_store.clone(),
        dual_register,
        auto_lock_at,
    };
    // Generate a bootstrap token only when no credential exists yet.
    if !auth_state.webauthn.has_credentials().await {
        if let Err(e) = auth_state.bootstrap.generate().await {
            tracing::warn!(error = %e, "bootstrap token generation failed");
        }
    }

    // Persist (or reuse) the loopback CLI capability token so `onecipher
    // webui …` bridge commands can authenticate without a WebAuthn session.
    let cli_token = match auth::cli_token::ensure_cli_token(&state_dir) {
        Ok(t) => Some(std::sync::Arc::new(t)),
        Err(e) => {
            tracing::warn!(error = %e, "CLI token generation failed; CLI bridge auth disabled");
            None
        }
    };

    let state = AppState { queue, state_dir, session_store: session_store.clone(), pairing_tx };

    // Auth routes carry their own state (WebAuthn manager + bootstrap token).
    let auth_router = axum::Router::new()
        .route("/bootstrap", axum::routing::post(routes::auth::bootstrap))
        .route("/webauthn/register/begin", axum::routing::post(routes::auth::register_begin))
        .route("/webauthn/register/finish", axum::routing::post(routes::auth::register_finish))
        .route("/webauthn/login/begin", axum::routing::post(routes::auth::login_begin))
        .route("/webauthn/login/finish", axum::routing::post(routes::auth::login_finish))
        .route("/logout", axum::routing::post(routes::auth::logout))
        .route("/status", axum::routing::get(routes::auth::status))
        .with_state(auth_state);

    let protected_api = axum::Router::new()
        .route("/api/auth/lock", axum::routing::post(routes::auth::lock_with_session))
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
        // Pairings (URI injection into the daemon's wallet server)
        .route("/api/pairings", axum::routing::post(routes::pairings::inject_pairing))
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
        .layer(from_fn_with_state(
            routes::auth::SessionGate { session_store: session_store.clone(), cli_token },
            routes::auth::require_session,
        ));

    let app = axum::Router::new()
        .nest("/api/auth", auth_router)
        .route("/api/health", axum::routing::get(health_handler))
        .merge(protected_api)
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
///
/// Request paths are strictly validated before any filesystem access: they
/// must be relative, slash-separated, and free of traversal segments (`..`),
/// backslashes, and NUL bytes; after canonicalization the candidate must stay
/// inside the dist root (C-03 path-traversal hardening).
async fn spa_fallback(
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
) -> axum::response::Response {
    let dist = find_frontend_dist();
    serve_spa_path(&dist, uri.path()).await
}

/// Outcome of validating a static file request path.
enum StaticPath {
    /// Serve this exact (canonicalized) file from the dist directory.
    File(PathBuf),
    /// Safe path that does not name an existing file — SPA index fallback.
    Fallback,
    /// Malformed or traversing path — reject without touching the disk.
    Reject,
}

/// Validate a raw request path against the dist root.
fn resolve_static_path(dist: &std::path::Path, request_path: &str) -> StaticPath {
    let trimmed = request_path.trim_start_matches('/');
    if trimmed.is_empty() {
        return StaticPath::Fallback;
    }

    // Percent-decode first so encoded separators/traversal cannot slip past
    // the segment checks below.
    let Some(decoded) = percent_decode(trimmed) else {
        return StaticPath::Reject;
    };

    // Reject backslashes (Windows separator tricks), NUL bytes, absolute
    // paths, and any path with non-normal components (`..`, leading `.`).
    if decoded.contains('\\') || decoded.contains('\0') {
        return StaticPath::Reject;
    }
    let rel = Path::new(&decoded);
    if rel.is_absolute() || !rel.components().all(|c| matches!(c, std::path::Component::Normal(_)))
    {
        return StaticPath::Reject;
    }

    let candidate = dist.join(rel);
    if !candidate.is_file() {
        return StaticPath::Fallback;
    }

    // Defense in depth: resolve symlinks on both sides and require the
    // candidate to remain inside the canonicalized dist root.
    let (Ok(canon_file), Ok(canon_root)) = (candidate.canonicalize(), dist.canonicalize()) else {
        return StaticPath::Reject;
    };
    if canon_file.starts_with(&canon_root) {
        StaticPath::File(canon_file)
    } else {
        StaticPath::Reject
    }
}

/// Serve a request path from the SPA dist directory.
async fn serve_spa_path(dist: &std::path::Path, request_path: &str) -> axum::response::Response {
    match resolve_static_path(dist, request_path) {
        StaticPath::File(file) => serve_file(&file).await,
        StaticPath::Reject => axum::http::StatusCode::NOT_FOUND.into_response(),
        StaticPath::Fallback => {
            let index = dist.join("index.html");
            if index.is_file() { serve_file(&index).await } else { frontend_not_built_response() }
        }
    }
}

/// Helpful message shown when the SPA has not been built yet.
fn frontend_not_built_response() -> axum::response::Response {
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

/// Percent-decode a URL path string.
///
/// Returns `None` for malformed escapes (`%` not followed by two hex digits)
/// or non-UTF-8 output.
fn percent_decode(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hex = bytes.get(i + 1..i + 3)?;
                let hi = char::from(hex[0]).to_digit(16)?;
                let lo = char::from(hex[1]).to_digit(16)?;
                out.push((hi * 16 + lo) as u8);
                i += 3;
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
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
    if let Ok(user_dist) = oc_core::paths::state_path("webui-dist") {
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
    use tower::ServiceExt;

    use super::*;

    #[tokio::test]
    async fn test_rejects_non_loopback() {
        let config =
            WebuiConfig { enabled: true, listen: "0.0.0.0:8080".to_string(), ..Default::default() };
        let (_tx, rx) = mpsc::channel(16);
        let (pairing_tx, _pairing_rx) = mpsc::channel(16);
        let result = run_webui_server(&config, PathBuf::from("/tmp"), rx, pairing_tx, None).await;
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
        let (pairing_tx, _pairing_rx) = mpsc::channel(16);
        let result =
            run_webui_server(&config, state_dir.path().to_path_buf(), rx, pairing_tx, None).await;
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
        let (pairing_tx, _pairing_rx) = mpsc::channel(16);
        let (_handle, port) =
            run_webui_server(&config, state_dir.path().to_path_buf(), rx, pairing_tx, None)
                .await
                .unwrap();

        // Make an HTTP request to the health endpoint
        let resp = hpx::Client::new()
            .get(format!("http://127.0.0.1:{port}/api/health"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["ok"], true);

        _handle.abort();
    }

    // -----------------------------------------------------------------------
    // SPA static fallback (C-03 path traversal hardening)
    // -----------------------------------------------------------------------

    /// Build a test SPA app rooted at a temporary dist directory containing
    /// `index.html` and `assets/app.js`.
    fn spa_app() -> (tempfile::TempDir, axum::Router) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("assets")).unwrap();
        std::fs::write(dir.path().join("index.html"), "<html>index</html>").unwrap();
        std::fs::write(dir.path().join("assets").join("app.js"), "// js").unwrap();
        let dist = dir.path().to_path_buf();
        let app = axum::Router::new().fallback(
            move |axum::extract::OriginalUri(uri): axum::extract::OriginalUri| {
                let dist = dist.clone();
                async move { serve_spa_path(&dist, uri.path()).await }
            },
        );
        (dir, app)
    }

    async fn get(app: axum::Router, path: &str) -> (axum::http::StatusCode, String) {
        let resp = app
            .oneshot(
                axum::http::Request::builder().uri(path).body(axum::body::Body::empty()).unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    #[tokio::test]
    async fn spa_blocks_parent_traversal() {
        let (_dir, app) = spa_app();
        let (status, _) = get(app, "/../../etc/passwd").await;
        assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn spa_blocks_percent_encoded_traversal() {
        let (_dir, app) = spa_app();
        let (status, _) = get(app, "/..%2f..%2fetc%2fpasswd").await;
        assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn spa_blocks_traversal_into_real_file() {
        let (_dir, app) = spa_app();
        // Even when the traversal target exists outside dist (Cargo.toml at
        // the workspace root), it must be rejected.
        let (status, _) = get(app, "/assets/../../Cargo.toml").await;
        assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn spa_blocks_backslash_and_nul_paths() {
        let (_dir, app) = spa_app();
        for path in ["/..%5C..%5Cetc%5Cpasswd", "/foo%00bar"] {
            let (status, _) = get(app.clone(), path).await;
            assert_eq!(status, axum::http::StatusCode::NOT_FOUND, "path: {path}");
        }
    }

    #[tokio::test]
    async fn spa_serves_valid_asset() {
        let (_dir, app) = spa_app();
        let (status, body) = get(app, "/assets/app.js").await;
        assert_eq!(status, axum::http::StatusCode::OK);
        assert_eq!(body, "// js");
    }

    #[tokio::test]
    async fn spa_root_serves_index() {
        let (_dir, app) = spa_app();
        let (status, body) = get(app, "/").await;
        assert_eq!(status, axum::http::StatusCode::OK);
        assert_eq!(body, "<html>index</html>");
    }

    #[tokio::test]
    async fn spa_unknown_route_falls_back_to_index() {
        let (_dir, app) = spa_app();
        let (status, body) = get(app, "/approvals/some-id").await;
        assert_eq!(status, axum::http::StatusCode::OK);
        assert_eq!(body, "<html>index</html>");
    }
}
