//! Wallet REST endpoints.
//!
//! - `GET    /api/wallets`              — list wallets
//! - `POST   /api/wallets`              — create wallet
//! - `POST   /api/wallets/import`       — import wallet
//! - `GET    /api/wallets/{id}`         — wallet detail
//! - `GET    /api/wallets/{id}/balances` — wallet balances
//! - `POST   /api/wallets/{id}/send`    — send transaction
//! - `DELETE /api/wallets/{id}`         — delete wallet

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;

use crate::routes::approvals::AppState;

/// GET /api/wallets — list all wallets.
pub async fn list_wallets(State(_state): State<AppState>) -> impl IntoResponse {
    tracing::debug!("list_wallets called");
    // ponytail: stub, forward to key-agent via UDS later
    Json(serde_json::json!({ "wallets": [] }))
}

/// Request body for POST /api/wallets.
#[derive(Debug, Deserialize)]
pub struct CreateWalletRequest {
    pub name: String,
    #[serde(default)]
    pub chain: Option<String>,
}

/// POST /api/wallets — create a new wallet.
pub async fn create_wallet(
    State(_state): State<AppState>,
    Json(body): Json<CreateWalletRequest>,
) -> impl IntoResponse {
    tracing::info!(name = %body.name, "create_wallet requested");
    // ponytail: stub, forward to key-agent via UDS later
    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "id": "stub-wallet-id",
            "name": body.name,
            "chain": body.chain.unwrap_or_else(|| "evm".to_string()),
        })),
    )
}

/// Request body for POST /api/wallets/import.
#[derive(Debug, Deserialize)]
pub struct ImportWalletRequest {
    pub name: String,
    pub mnemonic: String,
    #[serde(default)]
    pub chain: Option<String>,
}

/// POST /api/wallets/import — import a wallet from mnemonic.
pub async fn import_wallet(
    State(_state): State<AppState>,
    Json(body): Json<ImportWalletRequest>,
) -> impl IntoResponse {
    tracing::info!(name = %body.name, "import_wallet requested");
    // ponytail: stub, forward to key-agent via UDS later
    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "id": "stub-imported-wallet",
            "name": body.name,
            "chain": body.chain.unwrap_or_else(|| "evm".to_string()),
        })),
    )
}

/// GET /api/wallets/{id} — wallet detail.
pub async fn get_wallet(
    State(_state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    tracing::debug!(id = %id, "get_wallet called");
    // ponytail: stub, forward to key-agent via UDS later
    Json(serde_json::json!({
        "id": id,
        "name": "stub-wallet",
        "chain": "evm",
        "address": "0x0000000000000000000000000000000000000000",
    }))
}

/// GET /api/wallets/{id}/balances — wallet balances.
pub async fn get_wallet_balances(
    State(_state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    tracing::debug!(id = %id, "get_wallet_balances called");
    // ponytail: stub, use oc-wallet RPC client later
    Json(serde_json::json!({
        "wallet_id": id,
        "balances": [],
    }))
}

/// Request body for POST /api/wallets/{id}/send.
#[derive(Debug, Deserialize)]
pub struct SendRequest {
    pub to: String,
    pub amount: String,
    pub token: Option<String>,
    #[serde(default)]
    pub chain: Option<String>,
}

/// POST /api/wallets/{id}/send — send a transaction.
pub async fn send_transaction(
    State(_state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<SendRequest>,
) -> impl IntoResponse {
    tracing::info!(id = %id, to = %body.to, amount = %body.amount, "send_transaction requested");
    // ponytail: stub, construct SignTransactionRequest and forward to key-agent later
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "tx_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "wallet_id": id,
            "status": "pending",
        })),
    )
}

/// DELETE /api/wallets/{id} — delete a wallet.
pub async fn delete_wallet(
    State(_state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    tracing::info!(id = %id, "delete_wallet requested");
    // ponytail: stub, forward to key-agent via UDS later
    Json(serde_json::json!({ "ok": true, "id": id }))
}

#[cfg(test)]
mod tests {
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    use super::*;
    use crate::approval_queue::ApprovalQueue;

    fn test_state() -> AppState {
        AppState { queue: ApprovalQueue::new(16), state_dir: std::path::PathBuf::from("/tmp") }
    }

    fn json_body(value: serde_json::Value) -> Body {
        Body::from(serde_json::to_vec(&value).unwrap())
    }

    #[tokio::test]
    async fn test_list_wallets() {
        let app = axum::Router::new()
            .route("/api/wallets", axum::routing::get(list_wallets))
            .with_state(test_state());
        let resp = app
            .oneshot(Request::builder().uri("/api/wallets").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_create_wallet() {
        let app = axum::Router::new()
            .route("/api/wallets", axum::routing::post(create_wallet))
            .with_state(test_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/wallets")
                    .header("content-type", "application/json")
                    .body(json_body(serde_json::json!({"name": "test"})))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn test_import_wallet() {
        let app = axum::Router::new()
            .route("/api/wallets/import", axum::routing::post(import_wallet))
            .with_state(test_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/wallets/import")
                    .header("content-type", "application/json")
                    .body(json_body(
                        serde_json::json!({"name": "test", "mnemonic": "abandon abandon ..."}),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn test_get_wallet() {
        let app = axum::Router::new()
            .route("/api/wallets/{id}", axum::routing::get(get_wallet))
            .with_state(test_state());
        let resp = app
            .oneshot(Request::builder().uri("/api/wallets/abc123").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_get_wallet_balances() {
        let app = axum::Router::new()
            .route("/api/wallets/{id}/balances", axum::routing::get(get_wallet_balances))
            .with_state(test_state());
        let resp = app
            .oneshot(
                Request::builder().uri("/api/wallets/abc123/balances").body(Body::empty()).unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_send_transaction() {
        let app = axum::Router::new()
            .route("/api/wallets/{id}/send", axum::routing::post(send_transaction))
            .with_state(test_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/wallets/abc123/send")
                    .header("content-type", "application/json")
                    .body(json_body(serde_json::json!({"to": "0x123", "amount": "1.0"})))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_delete_wallet() {
        let app = axum::Router::new()
            .route("/api/wallets/{id}", axum::routing::delete(delete_wallet))
            .with_state(test_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/wallets/abc123")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
