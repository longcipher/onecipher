use std::{sync::Arc, time::Duration};

use oc_walletconnect::{
    dapp_client::WcDappClient,
    jsonrpc::{JsonRpcErrorCode, JsonRpcResponse},
    mock_relay::MockRelay,
};
use serde_json::json;

#[tokio::test]
async fn dapp_sends_request_and_receives_response() {
    let relay = Arc::new(MockRelay::new());

    // Pretend the wallet side pre-publishes a response for topic "t1", id 1
    let wallet_side = relay.clone();
    tokio::spawn(async move {
        let mut sub = wallet_side.subscribe("t1").await;
        let req_bytes = sub.recv().await.unwrap();
        let req: serde_json::Value = serde_json::from_slice(&req_bytes).unwrap();
        let id = req["id"].as_i64().unwrap();
        let resp = JsonRpcResponse::success(id, json!({"signature":"0xdeadbeef"}));
        wallet_side.publish("t1", serde_json::to_vec(&resp).unwrap().as_slice()).await;
    });

    // Let the wallet-side subscribe complete before the dApp publishes
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut client = WcDappClient::new();
    client.attach_mock_relay(relay.clone());
    client.bind_session("t1".into()).await;

    let result: serde_json::Value =
        client.request("personal_sign", json!({"data":"0xdead"})).await.unwrap();
    assert_eq!(result, json!({"signature":"0xdeadbeef"}));
}

#[tokio::test]
async fn dapp_propagates_error_response() {
    let relay = Arc::new(MockRelay::new());
    let wallet_side = relay.clone();
    tokio::spawn(async move {
        let mut sub = wallet_side.subscribe("t2").await;
        let req_bytes = sub.recv().await.unwrap();
        let req: serde_json::Value = serde_json::from_slice(&req_bytes).unwrap();
        let id = req["id"].as_i64().unwrap();
        let resp = JsonRpcResponse::error(
            id,
            oc_walletconnect::jsonrpc::JsonRpcError::new(
                JsonRpcErrorCode::UserRejected,
                "nope".into(),
            ),
        );
        wallet_side.publish("t2", serde_json::to_vec(&resp).unwrap().as_slice()).await;
    });

    // Let the wallet-side subscribe complete before the dApp publishes
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut client = WcDappClient::new();
    client.attach_mock_relay(relay);
    client.bind_session("t2".into()).await;

    let err = client.request("personal_sign", json!({})).await.unwrap_err();
    match err {
        oc_walletconnect::WcError::JsonRpc { code, message } => {
            assert_eq!(code, 4001);
            assert_eq!(message, "nope");
        }
        _ => panic!("wrong error: {err:?}"),
    }
}
