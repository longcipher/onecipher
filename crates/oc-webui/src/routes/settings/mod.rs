//! Settings routes: GET and PATCH for webui configuration.
//!
//! - `GET  /api/settings` — returns current webui config
//! - `PATCH /api/settings` — updates webui config fields atomically

pub mod policy;
pub mod secrets;
pub mod session_keys;

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde::Deserialize;

use crate::routes::approvals::AppState;

/// GET /api/settings — return current webui configuration.
pub async fn get_settings(State(_state): State<AppState>) -> impl IntoResponse {
    let config = oc_core::Config::load_or_default();
    let webui = &config.webui;
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "enabled": webui.enabled,
            "approval_mode": webui.approval_mode,
            "approval_timeout_secs": webui.approval_timeout_secs,
            "listen": webui.listen,
            "session_timeout_secs": webui.session_timeout_secs,
            "auto_lock_at": webui.auto_lock_at,
        })),
    )
}

/// Request body for PATCH /api/settings.
#[derive(Debug, Deserialize)]
pub struct PatchSettings {
    #[serde(default)]
    pub approval_mode: Option<bool>,
    #[serde(default)]
    pub approval_timeout_secs: Option<u64>,
    #[serde(default)]
    pub session_timeout_secs: Option<u64>,
    #[serde(default)]
    pub auto_lock_at: Option<String>,
}

/// PATCH /api/settings — update webui config fields.
pub async fn patch_settings(
    State(state): State<AppState>,
    Json(body): Json<PatchSettings>,
) -> impl IntoResponse {
    let mut config = oc_core::Config::load_or_default();
    let mut changes = Vec::new();

    if let Some(mode) = body.approval_mode {
        config.webui.approval_mode = mode;
        changes.push(format!("approval_mode={mode}"));
    }
    if let Some(timeout) = body.approval_timeout_secs {
        config.webui.approval_timeout_secs = timeout;
        changes.push(format!("approval_timeout_secs={timeout}"));
    }
    if let Some(session) = body.session_timeout_secs {
        config.webui.session_timeout_secs = session;
        changes.push(format!("session_timeout_secs={session}"));
    }
    if let Some(ref lock) = body.auto_lock_at {
        config.webui.auto_lock_at = lock.clone();
        changes.push(format!("auto_lock_at={lock}"));
    }

    // Persist to config.json atomically so a crash or full disk does not
    // leave a truncated config that (for instance) resets the session timeout.
    let config_path = state.state_dir.join("config.json");
    match serde_json::to_string_pretty(&config) {
        Ok(content) => {
            let p = config_path.clone();
            let io_result = tokio::task::spawn_blocking(move || {
                oc_core::paths::write_atomic(
                    &p,
                    content.as_bytes(),
                    oc_core::paths::MODE_REGULAR_FILE,
                )
            })
            .await
            .unwrap_or_else(|e| Err(std::io::Error::other(e)));
            if let Err(e) = io_result {
                tracing::error!(error = %e, "failed to write config.json");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": format!("failed to write config: {e}")})),
                );
            }
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to serialize config");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("failed to serialize config: {e}")})),
            );
        }
    }

    tracing::info!(changes = ?changes, "settings patched");

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "applied": changes,
        })),
    )
}
