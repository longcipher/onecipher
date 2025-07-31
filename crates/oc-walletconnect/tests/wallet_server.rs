use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use oc_walletconnect::{
    jsonrpc::{JsonRpcErrorCode, JsonRpcRequest, JsonRpcResponse},
    mock_relay::MockRelay,
    wallet_server::{WalletMethodHandler, WcWalletConfig, WcWalletServer},
};
use serde_json::{Value, json};

#[derive(Clone, Default)]
struct CountingHandler {
    calls: Arc<Mutex<Vec<(String, Value)>>>,
}

#[async_trait::async_trait]
impl WalletMethodHandler for CountingHandler {
    async fn handle(
        &self,
        method: &str,
        params: Value,
        _session_topic: &str,
    ) -> Result<Value, (JsonRpcErrorCode, String)> {
        self.calls.lock().unwrap().push((method.into(), params.clone()));
        Ok(json!({"echoed": params}))
    }
}

#[tokio::test]
async fn server_responds_to_session_request() {
    let relay = Arc::new(MockRelay::new());
    let cfg = WcWalletConfig { relay_url: "mock://test".into(), relay_protocol: "waku".into() };
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
    let cfg = WcWalletConfig { relay_url: "mock://test".into(), relay_protocol: "waku".into() };

    struct FailHandler;
    #[async_trait::async_trait]
    impl WalletMethodHandler for FailHandler {
        async fn handle(
            &self,
            _: &str,
            _: Value,
            _: &str,
        ) -> Result<Value, (JsonRpcErrorCode, String)> {
            Err((JsonRpcErrorCode::UserRejected, "no".into()))
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
