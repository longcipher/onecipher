//! Integration test: WC v2 wallet ↔ dApp via mock relay.
//!
//! Replaces the old ConnectRPC-over-UDS integration test.

use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use oc_walletconnect::{
    WalletMethodHandler, WcDappClient, WcSession, WcWalletServer, jsonrpc::JsonRpcErrorCode,
    mock_relay::MockRelay, wallet_server::WcWalletConfig,
};
use serde_json::{Value, json};

#[derive(Clone)]
struct EchoHandler;

#[async_trait]
impl WalletMethodHandler for EchoHandler {
    async fn handle(
        &self,
        method: &str,
        params: Value,
        _topic: &str,
    ) -> Result<Value, (JsonRpcErrorCode, String)> {
        Ok(json!({"method": method, "params": params}))
    }
}

#[tokio::test]
async fn wallet_dapp_round_trip_through_mock_relay() {
    let relay = Arc::new(MockRelay::new());

    let mut server = WcWalletServer::new(
        WcWalletConfig { relay_url: "mock://integration".into(), relay_protocol: "waku".into() },
        EchoHandler,
    );
    server.attach_mock_relay(relay.clone());

    let mut session = WcSession::new_pairing("integration-1".into(), "0xsym".into(), u64::MAX / 2);
    session.settle(
        "integration-1".into(),
        vec!["eip155:8453".into()],
        vec!["personal_sign".into(), "eth_sendTransaction".into(), "onecipher_listWallets".into()],
    );
    server.insert_session(session).await;

    tokio::spawn(async move {
        for _ in 0..3 {
            let _ = server.process_one("integration-1").await;
        }
    });

    let mut client = WcDappClient::new();
    client.attach_mock_relay(relay);
    client.bind_session("integration-1".into()).await;

    // ponytail: small delay lets the server's first process_one subscribe
    // before we publish; avoids broadcast race where the message is lost.
    tokio::time::sleep(Duration::from_millis(20)).await;

    let r1 = client.request("personal_sign", json!({"data": "0xaa"})).await.unwrap();
    assert_eq!(r1["method"], "personal_sign");

    // ponytail: delay between requests — process_one drops its subscription on
    // return, so the server must loop back and re-subscribe before we publish.
    tokio::time::sleep(Duration::from_millis(20)).await;

    let r2 = client.request("eth_sendTransaction", json!({"to": "0xabc"})).await.unwrap();
    assert_eq!(r2["method"], "eth_sendTransaction");

    tokio::time::sleep(Duration::from_millis(20)).await;

    let r3 = client.request("onecipher_listWallets", json!({})).await.unwrap();
    assert_eq!(r3["method"], "onecipher_listWallets");
}
