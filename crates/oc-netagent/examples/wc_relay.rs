//! Minimal local WC v2 relay for end-to-end development.
//!
//! Implements the subset of the IRN (Waku v2) relay protocol that both the
//! OneCipher wallet-role daemon and a dApp client (e.g. the account portal)
//! use: `irn_subscribe`, `irn_publish` and the `irn_subscription` push. Every
//! JSON-RPC message is one WebSocket text frame, exactly like the real relay.
//!
//! Usage: `cargo run -p oc-netagent --example wc_relay [--port 7443]`, then
//! point both sides at `ws://127.0.0.1:7443` via their relay config.

use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use axum::{
    Router,
    extract::{
        State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    response::IntoResponse,
    routing::get,
};
use futures::{SinkExt, StreamExt};
use tokio::sync::{Mutex, mpsc};

/// Shared relay state: topic → subscriber connection ids, and each connection
/// id → outbound message channel (so any handler can push to any subscriber).
#[derive(Default)]
struct RelayState {
    subs: Mutex<HashMap<String, Vec<u64>>>,
    sockets: Mutex<HashMap<u64, mpsc::UnboundedSender<Message>>>,
    next_conn: AtomicU64,
    next_msg_id: AtomicU64,
}

#[tokio::main]
async fn main() {
    let port: u16 = std::env::args()
        .nth(1)
        .and_then(|s| s.strip_prefix("--port=").map(str::to_owned))
        .and_then(|s| s.parse().ok())
        .unwrap_or(7443);

    let state = Arc::new(RelayState::default());
    let app = Router::new().route("/", get(ws_handler)).with_state(state);
    let addr = format!("127.0.0.1:{port}");
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    println!("mock WC relay listening on ws://{addr}");
    axum::serve(listener, app).await.unwrap();
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<RelayState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket(socket: WebSocket, state: Arc<RelayState>) {
    let conn_id = state.next_conn.fetch_add(1, Ordering::SeqCst) + 1;

    // Own outbound channel → socket forwarder.
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Message>();
    state.sockets.lock().await.insert(conn_id, out_tx.clone());

    let (mut sender, mut receiver) = socket.split();
    let forwarder = tokio::spawn(async move {
        while let Some(msg) = out_rx.recv().await {
            if sender.send(msg).await.is_err() {
                break;
            }
        }
    });

    while let Some(Ok(msg)) = receiver.next().await {
        let Message::Text(text) = msg else { continue };
        println!("RELAY-RECV conn={conn_id} text={text}");
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else { continue };
        let method = value.get("method").and_then(serde_json::Value::as_str).unwrap_or("");
        let id = value.get("id").cloned();

        match method {
            "irn_subscribe" => {
                let topic = value.pointer("/params/topic").and_then(serde_json::Value::as_str);
                if let Some(topic) = topic {
                    let mut subs = state.subs.lock().await;
                    subs.entry(topic.to_string()).or_default().push(conn_id);
                }
                let _ = out_tx.send(Message::Text(ack(id).into()));
            }
            "irn_batchSubscribe" => {
                if let Some(topics) =
                    value.pointer("/params/topics").and_then(serde_json::Value::as_array)
                {
                    for t in topics.iter().filter_map(serde_json::Value::as_str) {
                        let mut subs = state.subs.lock().await;
                        subs.entry(t.to_string()).or_default().push(conn_id);
                    }
                }
                let _ = out_tx.send(Message::Text(ack(id).into()));
            }
            "irn_publish" => {
                let topic = value.pointer("/params/topic").and_then(serde_json::Value::as_str);
                let message = value.pointer("/params/message").and_then(serde_json::Value::as_str);
                if let (Some(topic), Some(message)) = (topic, message) {
                    deliver(&state, topic, message, Some(conn_id)).await;
                }
                let _ = out_tx.send(Message::Text(ack(id).into()));
            }
            "irn_batchPublish" => {
                if let Some(batch) =
                    value.pointer("/params/batch").and_then(serde_json::Value::as_array)
                {
                    for item in batch {
                        let topic = item.get("topic").and_then(serde_json::Value::as_str);
                        let message = item.get("message").and_then(serde_json::Value::as_str);
                        if let (Some(topic), Some(message)) = (topic, message) {
                            deliver(&state, topic, message, Some(conn_id)).await;
                        }
                    }
                }
                let _ = out_tx.send(Message::Text(ack(id).into()));
            }
            _ => {}
        }
    }

    // Cleanup: drop subscription entries for this connection.
    state.sockets.lock().await.remove(&conn_id);
    let mut subs = state.subs.lock().await;
    for targets in subs.values_mut() {
        targets.retain(|c| *c != conn_id);
    }
    forwarder.abort();
}

/// Broadcast an `irn_subscription` push to every subscriber of `topic`
/// except `exclude` (usually the publisher, matching real relay semantics).
async fn deliver(state: &Arc<RelayState>, topic: &str, message: &str, exclude: Option<u64>) {
    let msg_id = state.next_msg_id.fetch_add(1, Ordering::SeqCst) + 1;
    let push = serde_json::json!({
        "id": format!("{msg_id:019}"),
        "jsonrpc": "2.0",
        "method": "irn_subscription",
        "params": {
            "id": format!("{msg_id:019}"),
            "data": { "topic": topic, "message": message },
        },
    })
    .to_string();

    let targets: Vec<u64> = {
        let subs = state.subs.lock().await;
        subs.get(topic)
            .map(|v| v.iter().copied().filter(|c| Some(*c) != exclude).collect())
            .unwrap_or_default()
    };

    let sockets = state.sockets.lock().await;
    for conn in targets {
        if let Some(tx) = sockets.get(&conn) {
            println!("RELAY-DELIVER topic={topic} -> conn={conn}");
            let _ = tx.send(Message::Text(push.clone().into()));
        }
    }
}

/// JSON-RPC acknowledgement: `{id, jsonrpc: "2.0", result: true}`.
fn ack(id: Option<serde_json::Value>) -> String {
    serde_json::json!({ "id": id, "jsonrpc": "2.0", "result": true }).to_string()
}
