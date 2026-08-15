//! Wallet-server handling of WC v2 **session-level** methods and the Auth
//! protocol request, driven through the mock relay.
//!
//! Session-level methods (`wc_sessionPing`, `wc_sessionUpdate`,
//! `wc_sessionDelete`) are spec-level: they must be answered by the server
//! and must NOT be gated by `is_method_allowed` (which only applies to dApp
//! namespace methods like `personal_sign`). `wc_authRequest` is a one-time
//! pairing-topic request that also bypasses the method gate.

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use oc_walletconnect::{
    jsonrpc::{JsonRpcRequest, JsonRpcResponse},
    method::{AUTH_REQUEST, SESSION_DELETE, SESSION_PING, SESSION_UPDATE},
    mock_relay::MockRelay,
    session::WcSession,
    wallet_server::{HandlerResult, WalletMethodHandler, WcWalletConfig, WcWalletServer},
};
use serde_json::{Value, json};

/// A handler that records every method it sees and echoes it back.
#[derive(Clone, Default)]
struct EchoHandler {
    seen: Arc<Mutex<Vec<String>>>,
}

impl WalletMethodHandler for EchoHandler {
    fn handle<'a>(
        &'a self,
        method: &str,
        params: Value,
        _topic: &str,
        _dapp_name: Option<&str>,
        _dapp_origin: Option<&str>,
    ) -> HandlerResult<'a> {
        let method = method.to_string();
        Box::pin(async move {
            self.seen.lock().unwrap().push(method.clone());
            Ok(json!({ "method": method, "params": params }))
        })
    }
}

/// Spawn a background task pumping `process_one` for `messages` messages.
fn spawn_server_pump<H: WalletMethodHandler + Send + Sync + 'static>(
    server: WcWalletServer<H>,
    topic: String,
    messages: usize,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        for _ in 0..messages {
            let _ = server.process_one(&topic).await;
        }
    })
}

fn settled_session(topic: &str, key_hex: &str) -> WcSession {
    let mut s = WcSession::new_pairing(topic.into(), key_hex.into(), u64::MAX);
    s.settle(topic.into(), vec!["eip155:1".into()], vec!["personal_sign".into()]);
    s
}

/// Publish a plaintext JSON-RPC request and read the (non-echo) response.
async fn roundtrip(relay: &MockRelay, topic: &str, req: JsonRpcRequest) -> JsonRpcResponse {
    let mut sub = relay.subscribe(topic).await;
    let bytes = serde_json::to_vec(&req).unwrap();
    relay.publish(topic, &bytes).await;
    let _echo = sub.recv().await.unwrap();
    let resp_bytes = sub.recv().await.unwrap();
    serde_json::from_slice(&resp_bytes).unwrap()
}

#[tokio::test]
async fn session_ping_is_acknowledged_without_method_allowed() {
    let relay = Arc::new(MockRelay::new());
    let cfg = WcWalletConfig {
        relay_url: "mock://ping".into(),
        relay_protocol: "irn".into(),
        trusted_origins: vec![],
    };
    let handler = EchoHandler::default();
    let mut server = WcWalletServer::new(cfg, handler);
    server.attach_mock_relay(relay.clone());
    let topic = "ping-topic".to_string();
    server.insert_session(settled_session(&topic, &"ab".repeat(32))).await;

    let server_task = spawn_server_pump(server, topic.clone(), 1);
    tokio::time::sleep(Duration::from_millis(50)).await;

    // wc_sessionPing is NOT in the session's approved methods — it must still
    // be answered (spec-level), not rejected with UnsupportedMethod.
    let resp = roundtrip(&relay, &topic, JsonRpcRequest::new(SESSION_PING, json!({}), 1)).await;
    assert_eq!(resp.id, 1);
    assert!(resp.error.is_none(), "ping must not error: {:?}", resp.error);
    assert_eq!(resp.result, Some(json!({ "acknowledged": true })));
    server_task.await.unwrap();
}

#[tokio::test]
async fn session_delete_removes_the_session_and_acknowledges() {
    let relay = Arc::new(MockRelay::new());
    let cfg = WcWalletConfig {
        relay_url: "mock://del".into(),
        relay_protocol: "irn".into(),
        trusted_origins: vec![],
    };
    let handler = EchoHandler::default();
    let mut server = WcWalletServer::new(cfg, handler);
    server.attach_mock_relay(relay.clone());
    let topic = "delete-topic".to_string();
    server.insert_session(settled_session(&topic, &"cd".repeat(32))).await;

    // Capture the table handle before moving the server into the pump.
    let table = server.session_table();
    let server_task = spawn_server_pump(server, topic.clone(), 1);
    tokio::time::sleep(Duration::from_millis(50)).await;

    let resp = roundtrip(&relay, &topic, JsonRpcRequest::new(SESSION_DELETE, json!({}), 2)).await;
    assert!(resp.error.is_none(), "delete must not error: {:?}", resp.error);
    assert_eq!(resp.result, Some(json!({ "acknowledged": true })));
    server_task.await.unwrap();

    // The session must be gone from the shared table.
    assert!(
        table.lock().await.get(&topic).is_none(),
        "session must be removed from the table after wc_sessionDelete"
    );
}

#[tokio::test]
async fn session_update_refreshes_namespaces_and_methods() {
    let relay = Arc::new(MockRelay::new());
    let cfg = WcWalletConfig {
        relay_url: "mock://upd".into(),
        relay_protocol: "irn".into(),
        trusted_origins: vec![],
    };
    let handler = EchoHandler::default();
    let mut server = WcWalletServer::new(cfg, handler);
    server.attach_mock_relay(relay.clone());
    let topic = "update-topic".to_string();
    server.insert_session(settled_session(&topic, &"ef".repeat(32))).await;
    let table = server.session_table();

    let server_task = spawn_server_pump(server, topic.clone(), 2);
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Update the session: add a new namespace + method not in the original set.
    let update = json!({
        "namespaces": {
            "eip155": {
                "methods": ["personal_sign", "eth_signTypedData_v4"],
                "chains": ["eip155:1"]
            },
            "solana": {
                "methods": ["solana_signMessage"],
                "chains": ["solana:mainnet"]
            }
        }
    });
    let resp = roundtrip(&relay, &topic, JsonRpcRequest::new(SESSION_UPDATE, update, 3)).await;
    assert!(resp.error.is_none(), "update must not error: {:?}", resp.error);
    assert_eq!(resp.result, Some(json!({ "acknowledged": true })));

    // The previously-unauthorized method must now be dispatched to the handler.
    let resp = roundtrip(
        &relay,
        &topic,
        JsonRpcRequest::new("eth_signTypedData_v4", json!({"data": "0x1"}), 4),
    )
    .await;
    assert!(resp.error.is_none(), "updated method must be allowed: {:?}", resp.error);
    server_task.await.unwrap();

    let guard = table.lock().await;
    let s = guard.get(&topic).expect("session still present");
    assert!(s.is_method_allowed("eth_signTypedData_v4"));
    assert!(s.is_method_allowed("solana_signMessage"));
    assert!(s.is_chain_allowed("solana:mainnet"));
}

#[tokio::test]
async fn auth_request_on_pairing_topic_bypasses_method_gate() {
    let relay = Arc::new(MockRelay::new());
    let cfg = WcWalletConfig {
        relay_url: "mock://auth".into(),
        relay_protocol: "irn".into(),
        trusted_origins: vec![],
    };
    let handler = EchoHandler::default();
    let seen = handler.seen.clone();
    let mut server = WcWalletServer::new(cfg, handler);
    server.attach_mock_relay(relay.clone());
    // A *pairing* topic: Propose state, no approved methods.
    let topic = "pairing-auth-topic".to_string();
    server.insert_session(WcSession::new_pairing(topic.clone(), "12".repeat(32), u64::MAX)).await;

    let server_task = spawn_server_pump(server, topic.clone(), 1);
    tokio::time::sleep(Duration::from_millis(50)).await;

    let params = json!({
        "type": "eip4361",
        "chainId": "eip155:1",
        "aud": "https://iam.example.com",
        "domain": "iam.example.com",
        "nonce": "abcdefgh12345678"
    });
    let resp =
        roundtrip(&relay, &topic, JsonRpcRequest::new(AUTH_REQUEST, params.clone(), 5)).await;
    // The pairing session has NO approved methods — without the bypass this
    // would be rejected with UnsupportedMethod. It must reach the handler.
    assert!(resp.error.is_none(), "wc_authRequest must not be method-gated: {:?}", resp.error);
    assert_eq!(resp.result, Some(json!({ "method": AUTH_REQUEST, "params": params })));
    assert_eq!(seen.lock().unwrap().as_slice(), &[AUTH_REQUEST.to_string()]);
    server_task.await.unwrap();
}
