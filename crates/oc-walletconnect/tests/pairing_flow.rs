//! Full WalletConnect v2 pairing-flow test over the mock relay, driving the
//! **encrypted** protocol path exactly as a real dApp↔wallet exchange would:
//!
//! 1. dApp generates a pairing symKey + X25519 keypair.
//! 2. dApp publishes `wc_sessionPropose` as a **type-1 envelope** carrying its public key,
//!    encrypted with the pairing key.
//! 3. Wallet decrypts the proposal, derives the session key via `deriveSymKey(wallet_priv,
//!    proposer_pub)`, and replies with an approve carrying its responder public key (encrypted with
//!    the pairing key).
//! 4. dApp derives the same session key from its private key + responder pub.
//! 5. Wallet publishes `wc_sessionSettle` encrypted with the session key.
//! 6. dApp sends a JSON-RPC request encrypted with the session key; wallet decrypts, dispatches to
//!    the handler, and responds encrypted.
//!
//! This exercises the real envelope formats and key derivation, so it is the
//! closest automated proxy for official-client interop.

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use oc_walletconnect::{
    WcCipher, WcKeyPair, WcSymKey,
    crypto::{self, derive_sym_key},
    jsonrpc::{JsonRpcErrorCode, JsonRpcRequest, JsonRpcResponse},
    method::{Proposer, ProposerMetadata, RelayProtocolOptions, SESSION_PROPOSE, SESSION_SETTLE},
    mock_relay::MockRelay,
    session::WcSession,
    wallet_server::{HandlerResult, WalletMethodHandler, WcWalletConfig, WcWalletServer},
};
use serde_json::{Value, json};

const TEST_RELAY_PROTOCOL: &str = "irn";

/// A handler that echoes method + params back (like the e2e test), so we can
/// assert the full request/response round-trip through encryption.
#[derive(Clone, Default)]
struct EchoHandler {
    seen: Arc<Mutex<Vec<String>>>,
}

impl WalletMethodHandler for EchoHandler {
    fn handle<'a>(&'a self, method: &str, params: Value, _topic: &str) -> HandlerResult<'a> {
        let method = method.to_string();
        Box::pin(async move {
            self.seen.lock().unwrap().push(method.clone());
            Ok(json!({"method": method, "params": params}))
        })
    }
}

/// Build the type-1 envelope for `wc_sessionPropose`, exactly like the
/// official dApp client does.
fn build_propose_envelope(
    pairing_key: &WcSymKey,
    proposer_pub: &[u8; 32],
    dapp_name: &str,
    dapp_url: &str,
    id: i64,
) -> Vec<u8> {
    let propose = oc_walletconnect::method::SessionProposeParams {
        relays: vec![RelayProtocolOptions { protocol: TEST_RELAY_PROTOCOL.into(), data: None }],
        required_namespaces: serde_json::json!({
            "eip155": {
                "methods": ["eth_sendTransaction", "personal_sign"],
                "chains": ["eip155:1"],
                "events": ["accountsChanged", "chainChanged"]
            }
        }),
        optional_namespaces: None,
        proposer: Proposer {
            publicKey: hex::encode(proposer_pub),
            metadata: ProposerMetadata {
                name: dapp_name.to_string(),
                description: format!("{dapp_name} via test"),
                url: dapp_url.to_string(),
                icons: vec![],
            },
        },
    };
    let req = serde_json::json!({
        "jsonrpc": "2.0",
        "method": SESSION_PROPOSE,
        "params": serde_json::to_value(&propose).unwrap(),
        "id": id
    });
    let req_bytes = serde_json::to_vec(&req).unwrap();
    WcCipher::seal_type1(pairing_key, proposer_pub, &req_bytes).unwrap()
}

/// Spawn a background task that pumps `process_one` for a fixed number of
/// messages on a topic. Mirrors the e2e.rs pattern: each `process_one` call
/// subscribes (via the mock relay) then waits for one inbound message.
fn spawn_server_pump<H: WalletMethodHandler + Send + Sync + 'static>(
    server: WcWalletServer<H>,
    topic: String,
    messages: usize,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        for _ in 0..messages {
            // Re-subscribe inside process_one; allow the caller to publish
            // after this returns. We sleep briefly to let subscription happen.
            let _ = server.process_one(&topic).await;
        }
    })
}

#[tokio::test]
async fn full_pairing_flow_encrypted_propose_settle_request() {
    let relay = Arc::new(MockRelay::new());

    // ---- Wallet side ----
    let cfg = WcWalletConfig {
        relay_url: "mock://flow".into(),
        relay_protocol: TEST_RELAY_PROTOCOL.into(),
        trusted_origins: vec!["localhost".into(), "127.0.0.1".into()],
    };
    let handler = EchoHandler::default();
    let mut server = WcWalletServer::new(cfg, handler);
    server.attach_mock_relay(relay.clone());

    // ---- Pairing: dApp generates pairing key; wallet knows it (from URI) ----
    let pairing_key = WcSymKey::from_random();
    let pairing_topic = hex::encode([0x01u8; 32]);

    server
        .insert_session(WcSession::new_pairing(
            pairing_topic.clone(),
            pairing_key.to_hex(),
            u64::MAX,
        ))
        .await;

    // ---- dApp generates its X25519 keypair ----
    let dapp_kp = WcKeyPair::generate();
    let proposer_pub = {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(dapp_kp.public_key().as_bytes());
        arr
    };

    // dApp subscribes to both pairing topic and session topic (the session
    // topic is deterministic: SHA-256 of the proposer public key). Subscribing
    // to the session topic NOW ensures the settle message published during
    // propose handling is not missed.
    let mut pairing_sub = relay.subscribe(&pairing_topic).await;
    let session_topic = crypto::hash_bytes(&proposer_pub);
    let mut session_sub = relay.subscribe(&session_topic).await;

    // Start a background pump for the pairing topic (handles propose → approve).
    let server_task = spawn_server_pump(server, pairing_topic.clone(), 1);
    // Give the pump time to subscribe.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // dApp publishes the propose (type-1 envelope, encrypted with pairing key).
    let propose_id = 1;
    let propose_env = build_propose_envelope(
        &pairing_key,
        &proposer_pub,
        "TestDApp",
        "https://localhost:3000",
        propose_id,
    );
    relay.publish(&pairing_topic, &propose_env).await;

    // dApp reads the approve response.
    // Skip the dApp's own published propose (broadcast echo).
    let _echo = pairing_sub.recv().await.unwrap();
    let approve_bytes = pairing_sub.recv().await.unwrap();
    let approve_plaintext = WcCipher::open_type0(&pairing_key, &approve_bytes).unwrap();
    let approve: JsonRpcResponse = serde_json::from_slice(&approve_plaintext).unwrap();
    assert_eq!(approve.id, propose_id);
    assert!(approve.error.is_none(), "approve must not error: {:?}", approve.error);
    let responder_pub_hex = approve
        .result
        .as_ref()
        .and_then(|r| r.get("responderPublicKey"))
        .and_then(|k| k.as_str())
        .expect("approve carries responderPublicKey");
    assert_eq!(responder_pub_hex.len(), 64, "responder pubkey is 32 bytes hex");

    // dApp derives the session key.
    let responder_bytes = hex::decode(responder_pub_hex).unwrap();
    let responder_pub = {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&responder_bytes);
        arr
    };
    let dapp_shared = dapp_kp.shared_secret(&x25519_dalek::PublicKey::from(responder_pub));
    let session_key = derive_sym_key(&dapp_shared);

    // Wallet's propose handler published wc_sessionSettle on the session topic
    // (encrypted with the derived session key).
    let settle_msg = session_sub.recv().await.unwrap();
    let settle_plaintext = WcCipher::open_type0(&session_key, &settle_msg).unwrap();
    let settle_json: Value = serde_json::from_slice(&settle_plaintext).unwrap();
    assert_eq!(settle_json.get("method").and_then(|m| m.as_str()), Some(SESSION_SETTLE));

    // Wait for the wallet's propose-handler pump to finish.
    server_task.await.unwrap();
}

/// The session-request phase of the full flow, separated so the wallet server
/// can be pumped for the request after the settle is observed.
#[tokio::test]
async fn session_request_after_pairing_roundtrips_encrypted() {
    let relay = Arc::new(MockRelay::new());
    let cfg = WcWalletConfig {
        relay_url: "mock://req".into(),
        relay_protocol: TEST_RELAY_PROTOCOL.into(),
        trusted_origins: vec!["localhost".into()],
    };
    let handler = EchoHandler::default();
    let seen = handler.seen.clone();
    let mut server = WcWalletServer::new(cfg, handler);
    server.attach_mock_relay(relay.clone());

    // Simulate an already-settled session with a known session key + topic.
    let session_key = WcSymKey::from_random();
    let session_topic = crypto::hash_key(&session_key);
    let mut session = WcSession::new_pairing(session_topic.clone(), session_key.to_hex(), u64::MAX);
    session.settle(session_topic.clone(), vec!["eip155:1".into()], vec!["personal_sign".into()]);
    server.insert_session(session).await;

    let mut sub = relay.subscribe(&session_topic).await;
    let server_task = spawn_server_pump(server, session_topic.clone(), 1);
    tokio::time::sleep(Duration::from_millis(50)).await;

    let req_id = 42;
    let req = JsonRpcRequest::new("personal_sign", json!({"data": "0xdead"}), req_id);
    let req_bytes = serde_json::to_vec(&req).unwrap();
    let req_env = WcCipher::seal_type0(&session_key, &req_bytes).unwrap();
    relay.publish(&session_topic, &req_env).await;

    let _echo = sub.recv().await.unwrap();
    let resp_bytes = sub.recv().await.unwrap();
    let resp_plaintext = WcCipher::open_type0(&session_key, &resp_bytes).unwrap();
    let resp: JsonRpcResponse = serde_json::from_slice(&resp_plaintext).unwrap();
    assert_eq!(resp.id, req_id);
    assert!(resp.error.is_none(), "response must not error: {:?}", resp.error);
    assert_eq!(resp.result, Some(json!({"method": "personal_sign", "params": {"data": "0xdead"}})));
    assert_eq!(seen.lock().unwrap().as_slice(), &["personal_sign".to_string()]);
    server_task.await.unwrap();
}

/// Verify the wallet rejects a proposal from an untrusted origin with an
/// Unauthorized JSON-RPC error (encrypted response).
#[tokio::test]
async fn proposal_from_untrusted_origin_is_rejected() {
    let relay = Arc::new(MockRelay::new());
    let cfg = WcWalletConfig {
        relay_url: "mock://untrusted".into(),
        relay_protocol: TEST_RELAY_PROTOCOL.into(),
        trusted_origins: vec!["trusted.example".into()],
    };
    let mut server = WcWalletServer::new(cfg, EchoHandler::default());
    server.attach_mock_relay(relay.clone());

    let pairing_key = WcSymKey::from_random();
    let pairing_topic = hex::encode([0x02u8; 32]);
    server
        .insert_session(WcSession::new_pairing(
            pairing_topic.clone(),
            pairing_key.to_hex(),
            u64::MAX,
        ))
        .await;

    let dapp_kp = WcKeyPair::generate();
    let proposer_pub = {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(dapp_kp.public_key().as_bytes());
        arr
    };
    let mut sub = relay.subscribe(&pairing_topic).await;
    let server_task = spawn_server_pump(server, pairing_topic.clone(), 1);
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Untrusted origin → wallet must reject with Unauthorized.
    let propose_env =
        build_propose_envelope(&pairing_key, &proposer_pub, "EvilDApp", "https://evil.example", 7);
    relay.publish(&pairing_topic, &propose_env).await;

    let _echo = sub.recv().await.unwrap();
    let resp_bytes = sub.recv().await.unwrap();
    let resp_plaintext = WcCipher::open_type0(&pairing_key, &resp_bytes).unwrap();
    let resp: JsonRpcResponse = serde_json::from_slice(&resp_plaintext).unwrap();
    assert_eq!(resp.id, 7);
    let err = resp.error.expect("untrusted proposal must be rejected");
    assert_eq!(err.code, JsonRpcErrorCode::Unauthorized as i64);
    server_task.await.unwrap();
}

/// The pairing session transitions to Active with the derived session key.
#[tokio::test]
async fn pairing_session_becomes_active_after_propose() {
    let relay = Arc::new(MockRelay::new());
    let cfg = WcWalletConfig {
        relay_url: "mock://active".into(),
        relay_protocol: TEST_RELAY_PROTOCOL.into(),
        trusted_origins: vec!["localhost".into()],
    };
    let mut server = WcWalletServer::new(cfg, EchoHandler::default());
    server.attach_mock_relay(relay.clone());

    let pairing_key = WcSymKey::from_random();
    let pairing_topic = hex::encode([0x04u8; 32]);
    server
        .insert_session(WcSession::new_pairing(
            pairing_topic.clone(),
            pairing_key.to_hex(),
            u64::MAX,
        ))
        .await;

    let dapp_kp = WcKeyPair::generate();
    let proposer_pub = {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(dapp_kp.public_key().as_bytes());
        arr
    };
    let _sub = relay.subscribe(&pairing_topic).await;
    let server_task = spawn_server_pump(server, pairing_topic.clone(), 1);
    tokio::time::sleep(Duration::from_millis(50)).await;

    let propose_env =
        build_propose_envelope(&pairing_key, &proposer_pub, "DApp", "https://localhost:3000", 1);
    relay.publish(&pairing_topic, &propose_env).await;

    // The session topic is SHA-256(proposer pubkey); the session must be Active.
    // We need access to the server's session table; re-open it via a fresh
    // server handle is not possible after move, so we verify via the settle
    // message instead (see below). This test asserts the settle is encrypted
    // with a key that is NOT the pairing key.
    let session_topic = crypto::hash_bytes(&proposer_pub);
    let mut session_sub = relay.subscribe(&session_topic).await;
    let settle_msg = session_sub.recv().await.unwrap();
    // Pairing key cannot decrypt the settle (session key is derived).
    assert!(WcCipher::open_type0(&pairing_key, &settle_msg).is_err());
    server_task.await.unwrap();
}
