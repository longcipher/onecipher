use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use oc_walletconnect::{
    dapp_client::WcDappClient,
    mock_relay::MockRelay,
    wallet_server::{WalletMethodHandler, WcWalletConfig, WcWalletServer},
};
use serde_json::{Value, json};

#[derive(Clone, Default)]
struct EchoHandler {
    seen: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl WalletMethodHandler for EchoHandler {
    async fn handle(
        &self,
        method: &str,
        params: Value,
        _topic: &str,
    ) -> Result<Value, (oc_walletconnect::jsonrpc::JsonRpcErrorCode, String)> {
        self.seen.lock().unwrap().push(method.into());
        Ok(json!({"method": method, "params": params}))
    }
}

#[tokio::test]
async fn end_to_end_request_response_loop() {
    let relay = Arc::new(MockRelay::new());

    // Set up wallet server with a pre-settled session on topic "e2e-1"
    let mut server = WcWalletServer::new(
        WcWalletConfig { relay_url: "mock://e2e".into(), relay_protocol: "waku".into() },
        EchoHandler::default(),
    );
    server.attach_mock_relay(relay.clone());

    let mut session = oc_walletconnect::WcSession::new_pairing(
        "e2e-1".into(),
        "0xsym".into(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() +
            3600,
    );
    session.settle(
        "e2e-1".into(),
        vec!["eip155:8453".into()],
        vec!["personal_sign".into(), "eth_sendTransaction".into()],
    );
    server.insert_session(session).await;

    // Spawn server processing task
    tokio::spawn(async move {
        // Process 2 messages then stop (test sends 2 requests)
        for _ in 0..2 {
            let _ = server.process_one("e2e-1").await;
        }
    });
    // Let the server's first process_one subscribe before the dApp publishes
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Set up dApp client bound to the same topic
    let mut client = WcDappClient::new();
    client.attach_mock_relay(relay.clone());
    client.bind_session("e2e-1".into()).await;

    let r1: Value = client.request("personal_sign", json!({"data":"0xaa"})).await.unwrap();
    assert_eq!(r1["method"], "personal_sign");
    assert_eq!(r1["params"]["data"], "0xaa");

    // Let the server's second process_one subscribe before the dApp publishes #2
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let r2: Value = client.request("eth_sendTransaction", json!({"to":"0xabc"})).await.unwrap();
    assert_eq!(r2["method"], "eth_sendTransaction");
}
