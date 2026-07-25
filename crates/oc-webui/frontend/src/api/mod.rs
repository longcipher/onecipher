pub mod ws;

use gloo_net::http::Request;
use serde::de::DeserializeOwned;

/// Base API path (same origin since the daemon serves everything).
const API_BASE: &str = "/api";

#[derive(Debug, Clone)]
pub struct ApiError(pub String);

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

pub async fn get_json<T: DeserializeOwned>(path: &str) -> Result<T, ApiError> {
    let url = format!("{API_BASE}{path}");
    let resp = Request::get(&url)
        .send()
        .await
        .map_err(|e| ApiError(format!("request failed: {e}")))?;

    if !resp.ok() {
        return Err(ApiError(format!("HTTP {}", resp.status())));
    }

    resp.json::<T>()
        .await
        .map_err(|e| ApiError(format!("json parse failed: {e}")))
}

pub async fn post_json<B: serde::Serialize, T: DeserializeOwned>(
    path: &str,
    body: &B,
) -> Result<T, ApiError> {
    let url = format!("{API_BASE}{path}");
    let resp = Request::post(&url)
        .json(body)
        .map_err(|e| ApiError(format!("serialize failed: {e}")))?
        .send()
        .await
        .map_err(|e| ApiError(format!("request failed: {e}")))?;

    if !resp.ok() {
        return Err(ApiError(format!("HTTP {}", resp.status())));
    }

    resp.json::<T>()
        .await
        .map_err(|e| ApiError(format!("json parse failed: {e}")))
}

pub async fn patch_json<B: serde::Serialize, T: DeserializeOwned>(
    path: &str,
    body: &B,
) -> Result<T, ApiError> {
    let url = format!("{API_BASE}{path}");
    let resp = Request::patch(&url)
        .json(body)
        .map_err(|e| ApiError(format!("serialize failed: {e}")))?
        .send()
        .await
        .map_err(|e| ApiError(format!("request failed: {e}")))?;

    if !resp.ok() {
        return Err(ApiError(format!("HTTP {}", resp.status())));
    }

    resp.json::<T>()
        .await
        .map_err(|e| ApiError(format!("json parse failed: {e}")))
}

pub async fn delete(path: &str) -> Result<(), ApiError> {
    let url = format!("{API_BASE}{path}");
    let resp = Request::delete(&url)
        .send()
        .await
        .map_err(|e| ApiError(format!("request failed: {e}")))?;

    if !resp.ok() {
        return Err(ApiError(format!("HTTP {}", resp.status())));
    }
    Ok(())
}
