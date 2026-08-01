//! WebSocket endpoint for real-time approval events.
//!
//! `GET /ws?token=<session_id>` upgrades to WebSocket.
//! Unauthenticated connections are rejected with 401 Unauthorized.

use std::collections::HashMap;

use axum::{
    extract::{
        Query, State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    response::IntoResponse,
};
use tokio::sync::broadcast;

use crate::{approval_queue::WsEvent, routes::approvals::AppState};

/// WebSocket upgrade handler.
///
/// Validates the session token from the `token` query parameter before
/// allowing the upgrade. Returns 401 for unauthenticated requests.
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String, std::hash::RandomState>>,
) -> impl IntoResponse {
    let token = params.get("token").or_else(|| params.get("session"));
    if let Some(_session) = token.and_then(|t| state.session_store.validate(t)) {
        let rx = state.queue.subscribe();
        ws.on_upgrade(move |socket| handle_ws(socket, rx))
    } else {
        tracing::warn!("WebSocket connection rejected: missing or invalid session token");
        (axum::http::StatusCode::UNAUTHORIZED, "WebSocket authentication required").into_response()
    }
}

async fn handle_ws(mut socket: WebSocket, mut rx: broadcast::Receiver<WsEvent>) {
    loop {
        tokio::select! {
            result = rx.recv() => {
                match result {
                    Ok(event) => {
                        let json = match serde_json::to_string(&event) {
                            Ok(j) => j,
                            Err(_) => continue,
                        };
                        if socket.send(Message::Text(json.into())).await.is_err() {
                            break; // Client disconnected
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(missed = n, "ws client lagged, dropping events");
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        break;
                    }
                }
            }
            // Handle incoming messages (e.g., ping/pong)
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(Message::Ping(data))) => {
                        if socket.send(Message::Pong(data)).await.is_err() {
                            break;
                        }
                    }
                    _ => {} // Ignore other messages
                }
            }
        }
    }
}
