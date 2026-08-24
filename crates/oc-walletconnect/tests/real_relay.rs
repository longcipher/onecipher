// Test code may unwrap/expect/panic (workspace lint phase-1 carve-out).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Real-relay integration tests (L3).
//!
//! These tests exercise the protocol against a REAL WalletConnect relay
//! (self-hosted via Docker or the official cloud relay). They are `#[ignore]`d
//! by default because they require a running relay.
//!
//! ## Running
//!
//! 1. Start a local relay (e.g. the official `WalletConnect/relay` image): ```bash docker run
//!    --name wc-relay -p 7443:7443 walletconnect/relay ```
//! 2. Set `OC_TEST_RELAY` (required) and optionally `OC_WC_PROJECT_ID`: ```bash
//!    OC_TEST_RELAY=wss://127.0.0.1:7443 \ cargo test -p oc-walletconnect --features test-utils \
//!    --test real_relay -- --ignored ```

use oc_walletconnect::{
    WcCipher, WcSymKey, crypto,
    relay::{RelayClient, RelayConfig},
};
use serde_json::json;

fn test_relay_url() -> String {
    std::env::var("OC_TEST_RELAY")
        .unwrap_or_else(|_| panic!("OC_TEST_RELAY must be set to a running relay WSS URL"))
}

/// IRN subscribe → publish (type-2 plaintext envelope) → receive echo.
/// This validates basic relay connectivity and the exact
/// `irn_subscribe`/`irn_publish`/`irn_subscription` JSON-RPC contract.
#[tokio::test]
#[ignore = "requires a running relay (see OC_TEST_RELAY)"]
async fn real_relay_subscribe_publish_roundtrip() {
    let url = test_relay_url();
    let cfg = RelayConfig { url: url.clone(), reconnect_max_ms: 60_000 };
    let mut relay = RelayClient::connect(cfg).await.expect("connect to relay");

    let topic = hex::encode(rand::random::<[u8; 32]>());

    // Subscribe.
    let sub_id = format!("{:019}", 1u64);
    relay
        .send_text(
            serde_json::to_string(&json!({
                "id": sub_id,
                "jsonrpc": "2.0",
                "method": "irn_subscribe",
                "params": { "topic": topic }
            }))
            .unwrap(),
        )
        .await
        .expect("subscribe");

    // Publish a type-2 (plaintext) probe envelope.
    let payload = json!({ "probe": true, "ts": 1234 });
    let payload_bytes = serde_json::to_vec(&payload).unwrap();
    let mut envelope = vec![crypto::ENVELOPE_TYPE_2];
    envelope.extend_from_slice(&payload_bytes);
    relay
        .publish_irn(&format!("{:019}", 2u64), &topic, &base64(&envelope), 60, 1108, None)
        .await
        .expect("publish");

    // Wait for the echo.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        assert!(tokio::time::Instant::now() <= deadline, "timeout waiting for relay echo");
        let raw = relay.recv().await.expect("recv");
        let val: serde_json::Value = serde_json::from_str(&raw).unwrap();
        if val.get("method").and_then(|m| m.as_str()) != Some("irn_subscription") {
            continue;
        }
        let echo_topic = val.pointer("/params/data/topic").and_then(|t| t.as_str()).unwrap_or("");
        let echo_msg = val.pointer("/params/data/message").and_then(|m| m.as_str()).unwrap_or("");
        if echo_topic == topic {
            // Decode the type-2 envelope.
            let bytes = base64_decode(echo_msg).expect("decode echo");
            assert_eq!(bytes[0], crypto::ENVELOPE_TYPE_2);
            let parsed: serde_json::Value = serde_json::from_slice(&bytes[1..]).unwrap();
            assert_eq!(parsed["probe"], true);
            return;
        }
    }
}

/// Full encrypted dApp↔wallet round-trip against a real relay: the wallet
/// subscribes to a session topic, the dApp publishes an encrypted JSON-RPC
/// request, the wallet handler echoes, and the dApp decrypts the response.
#[tokio::test]
#[ignore = "requires a running relay (see OC_TEST_RELAY)"]
async fn real_relay_encrypted_session_request_roundtrip() {
    use std::sync::{Arc, Mutex};

    use oc_walletconnect::{
        jsonrpc::{JsonRpcRequest, JsonRpcResponse},
        session::WcSession,
        wallet_server::{HandlerResult, WalletMethodHandler, WcWalletConfig, WcWalletServer},
    };
    use serde_json::Value;

    #[derive(Clone, Default)]
    struct EchoHandler(Arc<Mutex<Vec<String>>>);
    impl WalletMethodHandler for EchoHandler {
        fn handle<'a>(
            &'a self,
            method: &str,
            params: Value,
            _: &str,
            _dapp_name: Option<&str>,
            _dapp_origin: Option<&str>,
        ) -> HandlerResult<'a> {
            let method = method.to_string();
            Box::pin(async move {
                self.0.lock().unwrap().push(method.clone());
                Ok(json!({"method": method, "params": params}))
            })
        }
    }

    let url = test_relay_url();
    let session_key = WcSymKey::from_random();
    let session_topic = crypto::hash_key(&session_key);

    // Wallet server bound to the session topic.
    let mut server = WcWalletServer::new(
        WcWalletConfig {
            relay_url: url.clone(),
            relay_protocol: "irn".into(),
            trusted_origins: vec!["localhost".into(), "127.0.0.1".into()],
        },
        EchoHandler::default(),
    );
    let mut session = WcSession::new_pairing(session_topic.clone(), session_key.to_hex(), u64::MAX);
    session.settle(session_topic.clone(), vec!["eip155:1".into()], vec!["personal_sign".into()]);
    server.insert_session(session).await;

    // Run the server loop in the background (it subscribes to the session topic).
    let server_task = tokio::spawn(async move { server.run(None).await });

    // Give the server time to connect + subscribe.
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;

    // dApp: connect to relay, subscribe to the session topic, publish an
    // encrypted request, and read the encrypted response.
    let mut dapp = RelayClient::connect(RelayConfig { url, reconnect_max_ms: 60_000 })
        .await
        .expect("dapp connect");
    dapp.send_text(
        serde_json::to_string(&json!({
            "id": "3",
            "jsonrpc": "2.0",
            "method": "irn_subscribe",
            "params": { "topic": session_topic }
        }))
        .unwrap(),
    )
    .await
    .unwrap();

    let req_id = 7;
    let req = JsonRpcRequest::new("personal_sign", json!({"data": "0xabc"}), req_id);
    let req_bytes = serde_json::to_vec(&req).unwrap();
    let req_env = WcCipher::seal_type0(&session_key, &req_bytes).unwrap();
    dapp.publish_irn("4", &session_topic, &base64(&req_env), 300, 1108, None)
        .await
        .expect("publish request");

    // Wait for the encrypted response.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        assert!(tokio::time::Instant::now() <= deadline, "timeout waiting for wallet response");
        let raw = dapp.recv().await.expect("recv");
        let val: serde_json::Value = serde_json::from_str(&raw).unwrap();
        if val.get("method").and_then(|m| m.as_str()) != Some("irn_subscription") {
            continue;
        }
        let msg = val.pointer("/params/data/message").and_then(|m| m.as_str()).unwrap_or("");
        let bytes = base64_decode(msg).expect("decode");
        if bytes.first() != Some(&crypto::ENVELOPE_TYPE_0) &&
            bytes.first() != Some(&crypto::ENVELOPE_TYPE_1)
        {
            continue;
        }
        let plaintext = match bytes[0] {
            crypto::ENVELOPE_TYPE_0 => WcCipher::open_type0(&session_key, &bytes).unwrap(),
            crypto::ENVELOPE_TYPE_1 => WcCipher::open_type1(&session_key, &bytes).unwrap().1,
            _ => continue,
        };
        let resp: JsonRpcResponse = serde_json::from_slice(&plaintext).unwrap();
        if resp.id == req_id {
            assert!(resp.error.is_none(), "wallet error: {:?}", resp.error);
            assert_eq!(
                resp.result,
                Some(json!({"method": "personal_sign", "params": {"data": "0xabc"}}))
            );
            server_task.abort();
            return;
        }
    }
}

fn base64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn base64_decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.decode(s)
}
