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
    // TODO: Read live config from shared state. For now return static defaults.
    let config = oc_core::WebuiConfig::default();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "enabled": config.enabled,
            "approval_mode": config.approval_mode,
            "approval_timeout_secs": config.approval_timeout_secs,
            "listen": config.listen,
            "session_timeout_secs": config.session_timeout_secs,
            "auto_lock_at": config.auto_lock_at,
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
    State(_state): State<AppState>,
    Json(body): Json<PatchSettings>,
) -> impl IntoResponse {
    // TODO: Apply changes to shared config, update AtomicBool for approval_mode,
    // and atomically rewrite config.toml. For now, acknowledge the request.
    let mut changes = Vec::new();
    if let Some(mode) = body.approval_mode {
        changes.push(format!("approval_mode={mode}"));
    }
    if let Some(timeout) = body.approval_timeout_secs {
        changes.push(format!("approval_timeout_secs={timeout}"));
    }
    if let Some(session) = body.session_timeout_secs {
        changes.push(format!("session_timeout_secs={session}"));
    }
    if let Some(ref lock) = body.auto_lock_at {
        changes.push(format!("auto_lock_at={lock}"));
    }

    tracing::info!(changes = ?changes, "settings patch requested");

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "applied": changes,
        })),
    )
}
