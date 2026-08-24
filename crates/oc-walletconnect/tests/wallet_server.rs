// Test code may unwrap/expect/panic (workspace lint phase-1 carve-out).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use oc_walletconnect::{
    WcCipher, WcSymKey, crypto,
    jsonrpc::{JsonRpcErrorCode, JsonRpcRequest, JsonRpcResponse},
    mock_relay::MockRelay,
    session::WcSession,
    wallet_server::{HandlerResult, WalletMethodHandler, WcWalletConfig, WcWalletServer},
};
use serde_json::{Value, json};

#[derive(Clone, Default)]
struct CountingHandler {
    calls: Arc<Mutex<Vec<(String, Value)>>>,
}

impl WalletMethodHandler for CountingHandler {
    fn handle<'a>(
        &'a self,
        method: &str,
        params: Value,
        _session_topic: &str,
        _dapp_name: Option<&str>,
        _dapp_origin: Option<&str>,
    ) -> HandlerResult<'a> {
        let method = method.to_string();
        Box::pin(async move {
            self.calls.lock().unwrap().push((method, params.clone()));
            Ok(json!({"echoed": params}))
        })
    }
}

#[tokio::test]
async fn server_responds_to_session_request() {
    let relay = Arc::new(MockRelay::new());
    let cfg = WcWalletConfig {
        relay_url: "mock://test".into(),
        relay_protocol: "waku".into(),
        trusted_origins: vec!["localhost".into(), "127.0.0.1".into()],
    };
    let handler = CountingHandler::default();
    let mut server = WcWalletServer::new(cfg, handler);
    server.attach_mock_relay(relay.clone());

    // dApp subscribes to receive the response
    let mut sub = relay.subscribe("t1").await;

    // Spawn server's process_one (it subscribes internally)
    let server_task = tokio::spawn(async move {
        server.process_one("t1").await.unwrap();
    });
    // Let process_one's subscribe happen
    tokio::time::sleep(Duration::from_millis(50)).await;

    // dApp publishes the request
    relay
        .publish(
            "t1",
            serde_json::to_vec(&JsonRpcRequest::new("personal_sign", json!({"data":"0xdead"}), 1))
                .unwrap()
                .as_slice(),
        )
        .await;

    // Wait for server to process and publish response
    server_task.await.unwrap();

    // Skip the request echo (dApp receives its own published message via broadcast)
    let _echo = sub.recv().await.unwrap();

    // Receive the response
    let resp_bytes = sub.recv().await.unwrap();
    let resp: JsonRpcResponse = serde_json::from_slice(&resp_bytes).unwrap();
    assert_eq!(resp.id, 1);
    assert!(resp.error.is_none());
    assert_eq!(resp.result, Some(json!({"echoed":{"data":"0xdead"}})));
}

#[tokio::test]
async fn server_returns_method_error_when_handler_fails() {
    let relay = Arc::new(MockRelay::new());
    let cfg = WcWalletConfig {
        relay_url: "mock://test".into(),
        relay_protocol: "waku".into(),
        trusted_origins: vec!["localhost".into(), "127.0.0.1".into()],
    };

    struct FailHandler;
    impl WalletMethodHandler for FailHandler {
        fn handle<'a>(
            &'a self,
            _: &str,
            _: Value,
            _: &str,
            _: Option<&str>,
            _: Option<&str>,
        ) -> HandlerResult<'a> {
            Box::pin(async { Err((JsonRpcErrorCode::UserRejected, "no".into())) })
        }
    }

    let mut server = WcWalletServer::new(cfg, FailHandler);
    server.attach_mock_relay(relay.clone());

    // dApp subscribes to receive the response
    let mut sub = relay.subscribe("t2").await;

    // Spawn server's process_one (it subscribes internally)
    let server_task = tokio::spawn(async move {
        server.process_one("t2").await.unwrap();
    });
    // Let process_one's subscribe happen
    tokio::time::sleep(Duration::from_millis(50)).await;

    // dApp publishes the request
    relay
        .publish(
            "t2",
            serde_json::to_vec(&JsonRpcRequest::new("personal_sign", json!({}), 9))
                .unwrap()
                .as_slice(),
        )
        .await;

    // Wait for server to process and publish response
    server_task.await.unwrap();

    // Skip the request echo (dApp receives its own published message via broadcast)
    let _echo = sub.recv().await.unwrap();

    // Receive the response
    let resp_bytes = sub.recv().await.unwrap();
    let resp: JsonRpcResponse = serde_json::from_slice(&resp_bytes).unwrap();
    assert_eq!(resp.id, 9);
    assert!(resp.result.is_none());
    assert_eq!(resp.error.unwrap().code, 4001);
}

/// C-04: a sequence of [garbage, valid envelope, corrupt envelope, valid
/// envelope] must not kill the server — per-message failures are contained,
/// and both valid requests are processed and answered.
#[tokio::test]
async fn garbage_messages_do_not_kill_the_server() {
    let relay = Arc::new(MockRelay::new());
    let cfg = WcWalletConfig {
        relay_url: "mock://garbage".into(),
        relay_protocol: "irn".into(),
        trusted_origins: vec![],
    };
    let handler = CountingHandler::default();
    let calls = handler.calls.clone();
    let mut server = WcWalletServer::new(cfg, handler);
    server.attach_mock_relay(relay.clone());

    // Settled session with a known session key + topic.
    let session_key = WcSymKey::from_random();
    let topic = crypto::hash_key(&session_key);
    let mut session = WcSession::new_pairing(topic.clone(), session_key.to_hex(), u64::MAX);
    session.settle(topic.clone(), vec!["eip155:1".into()], vec!["personal_sign".into()]);
    server.insert_session(session).await;

    let mut sub = relay.subscribe(&topic).await;
    // 4 inbound messages → 4 process_one iterations; per-message failures
    // must be contained (Ok), so the pump itself never errors.
    let pump_topic = topic.clone();
    let server_task = tokio::spawn(async move {
        for _ in 0..4 {
            server.process_one(&pump_topic).await.expect("per-message failures must be contained");
        }
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    // 1) Garbage that is neither an envelope nor JSON.
    relay.publish(&topic, b"\xff\xff not json at all").await;
    let _echo = sub.recv().await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    // 2) Valid encrypted request.
    let req1 = JsonRpcRequest::new("personal_sign", json!({ "n": 1 }), 11);
    let env1 = WcCipher::seal_type0(&session_key, &serde_json::to_vec(&req1).unwrap()).unwrap();
    relay.publish(&topic, &env1).await;
    let _echo = sub.recv().await.unwrap();
    let resp1 = WcCipher::open_type0(&session_key, &sub.recv().await.unwrap()).unwrap();
    let resp1: JsonRpcResponse = serde_json::from_slice(&resp1).unwrap();
    assert_eq!(resp1.id, 11);
    assert!(resp1.error.is_none(), "valid request 1 must succeed: {:?}", resp1.error);
    tokio::time::sleep(Duration::from_millis(50)).await;

    // 3) Corrupted type-0 envelope (AEAD open must fail).
    let mut corrupt = WcCipher::seal_type0(&session_key, b"{}").unwrap();
    corrupt[5] ^= 0xff;
    relay.publish(&topic, &corrupt).await;
    let _echo = sub.recv().await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    // 4) Valid again — the server is still alive.
    let req2 = JsonRpcRequest::new("personal_sign", json!({ "n": 2 }), 12);
    let env2 = WcCipher::seal_type0(&session_key, &serde_json::to_vec(&req2).unwrap()).unwrap();
    relay.publish(&topic, &env2).await;
    let _echo = sub.recv().await.unwrap();
    let resp2 = WcCipher::open_type0(&session_key, &sub.recv().await.unwrap()).unwrap();
    let resp2: JsonRpcResponse = serde_json::from_slice(&resp2).unwrap();
    assert_eq!(resp2.id, 12);
    assert!(resp2.error.is_none(), "valid request 2 must succeed: {:?}", resp2.error);

    server_task.await.unwrap();

    // Exactly the two valid requests reached the method handler.
    let seen = calls.lock().unwrap();
    assert_eq!(seen.len(), 2, "only the valid requests may reach the handler");
    assert_eq!(seen[0].0, "personal_sign");
    assert_eq!(seen[1].0, "personal_sign");
}
