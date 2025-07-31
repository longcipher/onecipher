//! WC v2 dApp Role client (CLI side).
//!
//! Connects to a relay, binds to a session topic, sends JSON-RPC requests,
//! and awaits responses. Supports both real WSS relay and mock relay for tests.

#[cfg(any(test, feature = "test-utils"))]
use std::sync::Arc;

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use rand::RngExt;
use serde_json::Value;
use tokio::sync::Mutex;

#[cfg(any(test, feature = "test-utils"))]
use crate::mock_relay::MockRelay;
use crate::{
    crypto::{WcCipher, WcSymKey},
    error::{WcError, WcResult},
    jsonrpc::{JsonRpcRequest, JsonRpcResponse},
    method::{self, Proposer, ProposerMetadata, RelayProtocolOptions, SessionProposeParams},
    relay::{RelayClient, RelayConfig},
    uri::PairingUri,
};

const WC_AAD: &[u8] = b"wc-2.0";

pub struct WcDappClient {
    topic: Mutex<Option<String>>,
    next_id: Mutex<i64>,
    sym_key: Mutex<Option<WcSymKey>>,
    relay: Mutex<Option<RelayClient>>,
    #[cfg(any(test, feature = "test-utils"))]
    mock_relay: Option<Arc<MockRelay>>,
}

impl WcDappClient {
    pub fn new() -> Self {
        Self {
            topic: Mutex::new(None),
            next_id: Mutex::new(1),
            sym_key: Mutex::new(None),
            relay: Mutex::new(None),
            #[cfg(any(test, feature = "test-utils"))]
            mock_relay: None,
        }
    }

    /// Create a mock-relay client for tests.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn new_mock(relay: Arc<MockRelay>) -> Self {
        Self {
            topic: Mutex::new(None),
            next_id: Mutex::new(1),
            sym_key: Mutex::new(None),
            relay: Mutex::new(None),
            mock_relay: Some(relay),
        }
    }

    /// Connect to a real relay using pairing URI parameters.
    pub async fn connect(uri: &PairingUri) -> WcResult<Self> {
        let relay_url = "wss://relay.walletconnect.com";
        let relay_cfg = RelayConfig { url: relay_url.into(), reconnect_max_ms: 60_000 };
        let mut relay = RelayClient::connect(relay_cfg).await?;

        let sub_msg = serde_json::json!({
            "id": 1,
            "jsonrpc": "2.0",
            "method": "subscribe",
            "params": { "topic": uri.topic }
        });
        relay.send_text(serde_json::to_string(&sub_msg)?).await?;

        let sym_key = uri.sym_key.as_ref().and_then(|hex_str| {
            let bytes = hex::decode(hex_str).ok()?;
            (bytes.len() == 32).then(|| {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                WcSymKey::from_bytes(arr)
            })
        });

        Ok(Self {
            topic: Mutex::new(Some(uri.topic.clone())),
            next_id: Mutex::new(2),
            sym_key: Mutex::new(sym_key),
            relay: Mutex::new(Some(relay)),
            #[cfg(any(test, feature = "test-utils"))]
            mock_relay: None,
        })
    }

    pub fn set_sym_key(&self, key: WcSymKey) {
        // ponytail: blocking lock is fine — called once at init
        let rt = tokio::runtime::Handle::try_current();
        if let Ok(handle) = rt {
            handle.block_on(async { *self.sym_key.lock().await = Some(key) });
        }
    }

    pub async fn set_sym_key_async(&self, key: WcSymKey) {
        *self.sym_key.lock().await = Some(key);
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub fn attach_mock_relay(&mut self, relay: Arc<MockRelay>) {
        self.mock_relay = Some(relay);
    }

    pub async fn bind_session(&self, topic: String) {
        *self.topic.lock().await = Some(topic);
    }

    pub async fn unbind(&self) {
        *self.topic.lock().await = None;
    }

    /// Send a JSON-RPC request on the bound session topic and await the
    /// matching response. Dispatches to mock or real relay based on setup.
    pub async fn request(&self, method: &str, params: Value) -> WcResult<Value> {
        #[cfg(any(test, feature = "test-utils"))]
        if self.mock_relay.is_some() {
            return self.request_mock(method, params).await;
        }
        self.request_real(method, params).await
    }

    #[cfg(any(test, feature = "test-utils"))]
    async fn request_mock(&self, method: &str, params: Value) -> WcResult<Value> {
        let relay = self
            .mock_relay
            .clone()
            .ok_or_else(|| WcError::Relay("no mock relay attached".into()))?;
        let topic = self
            .topic
            .lock()
            .await
            .clone()
            .ok_or_else(|| WcError::SessionNotFound("no bound session".into()))?;

        let id = {
            let mut n = self.next_id.lock().await;
            let v = *n;
            *n += 1;
            v
        };

        let req = JsonRpcRequest::new(method, params, id);
        let req_bytes = serde_json::to_vec(&req)?;

        let mut sub = relay.subscribe(&topic).await;
        relay.publish(&topic, &req_bytes).await;

        loop {
            let payload = sub.recv().await.map_err(|e| WcError::Relay(format!("recv: {e:?}")))?;
            let resp: JsonRpcResponse = serde_json::from_slice(&payload)?;
            if resp.id != id {
                continue;
            }
            if resp.result.is_none() && resp.error.is_none() {
                continue;
            }
            if let Some(e) = resp.error {
                return Err(WcError::JsonRpc { code: e.code, message: e.message });
            }
            return Ok(resp.result.unwrap_or(Value::Null));
        }
    }

    async fn request_real(&self, method: &str, params: Value) -> WcResult<Value> {
        let topic = self
            .topic
            .lock()
            .await
            .clone()
            .ok_or_else(|| WcError::SessionNotFound("no bound session".into()))?;

        let sym_key = self
            .sym_key
            .lock()
            .await
            .clone()
            .ok_or_else(|| WcError::Crypto("no sym key set".into()))?;

        let mut relay_guard = self.relay.lock().await;
        let relay = relay_guard.as_mut().ok_or_else(|| WcError::Relay("not connected".into()))?;

        let id = {
            let mut n = self.next_id.lock().await;
            let v = *n;
            *n += 1;
            v
        };

        let req = JsonRpcRequest::new(method, params, id);
        let req_bytes = serde_json::to_vec(&req)?;

        let mut nonce = [0u8; 12];
        rand::rng().fill(&mut nonce[..]);
        let ciphertext = WcCipher::seal(&sym_key, &nonce, WC_AAD, &req_bytes)?;
        let mut envelope = nonce.to_vec();
        envelope.extend_from_slice(&ciphertext);

        let pub_msg = serde_json::json!({
            "id": id,
            "jsonrpc": "2.0",
            "method": "publish",
            "params": {
                "topic": topic,
                "message": BASE64.encode(&envelope),
                "tag": 1108,
                "ttl": 300
            }
        });
        relay.send_text(serde_json::to_string(&pub_msg)?).await?;

        loop {
            let raw = relay.recv().await.map_err(|e| WcError::Relay(format!("recv: {e}")))?;
            let envelope_val: serde_json::Value = serde_json::from_str(&raw)?;

            if envelope_val.get("method").and_then(|m| m.as_str()) != Some("subscription") {
                continue;
            }
            let data = match envelope_val.pointer("/params/data") {
                Some(d) => d,
                None => continue,
            };
            if data.get("topic").and_then(|t| t.as_str()) != Some(&topic) {
                continue;
            }
            let b64_msg = match data.get("message").and_then(|m| m.as_str()) {
                Some(m) => m,
                None => continue,
            };

            let encrypted = BASE64.decode(b64_msg).unwrap_or_default();
            if encrypted.len() < 12 {
                continue;
            }
            let resp_nonce: [u8; 12] = encrypted[..12].try_into().unwrap();
            let plaintext =
                WcCipher::open(&sym_key, &resp_nonce, WC_AAD, &encrypted[12..]).unwrap_or_default();
            if plaintext.is_empty() {
                continue;
            }

            let resp: JsonRpcResponse = serde_json::from_slice(&plaintext)?;
            if resp.id != id {
                continue;
            }
            if resp.result.is_none() && resp.error.is_none() {
                continue;
            }
            if let Some(e) = resp.error {
                return Err(WcError::JsonRpc { code: e.code, message: e.message });
            }
            return Ok(resp.result.unwrap_or(Value::Null));
        }
    }

    /// Send `wc_sessionPropose` and await the approval response.
    pub async fn propose(&self, dapp_name: &str, dapp_url: &str) -> WcResult<String> {
        let topic = self
            .topic
            .lock()
            .await
            .clone()
            .ok_or_else(|| WcError::SessionNotFound("no bound session".into()))?;

        let sym_key = self
            .sym_key
            .lock()
            .await
            .clone()
            .ok_or_else(|| WcError::Crypto("no sym key set".into()))?;

        let mut relay_guard = self.relay.lock().await;
        let relay = relay_guard.as_mut().ok_or_else(|| WcError::Relay("not connected".into()))?;

        let id = {
            let mut n = self.next_id.lock().await;
            let v = *n;
            *n += 1;
            v
        };

        let kp = crate::crypto::WcKeyPair::generate();
        let proposer_pubkey = hex::encode(kp.public_key().to_bytes());

        let propose = SessionProposeParams {
            relays: vec![RelayProtocolOptions { protocol: "waku".into(), data: None }],
            required_namespaces: serde_json::json!({
                "eip155": {
                    "methods": ["eth_sendTransaction", "personal_sign"],
                    "chains": ["eip155:1"],
                    "events": ["accountsChanged", "chainChanged"]
                }
            }),
            optional_namespaces: None,
            proposer: Proposer {
                publicKey: proposer_pubkey.clone(),
                metadata: ProposerMetadata {
                    name: dapp_name.to_string(),
                    description: format!("{dapp_name} via OneCipher"),
                    url: dapp_url.to_string(),
                    icons: vec![],
                },
            },
        };

        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "method": method::SESSION_PROPOSE,
            "params": serde_json::to_value(&propose)?,
            "id": id
        });
        let req_bytes = serde_json::to_vec(&req)?;

        let mut nonce = [0u8; 12];
        rand::rng().fill(&mut nonce[..]);
        let ciphertext = WcCipher::seal(&sym_key, &nonce, WC_AAD, &req_bytes)?;
        let mut envelope = nonce.to_vec();
        envelope.extend_from_slice(&ciphertext);

        let pub_msg = serde_json::json!({
            "id": id,
            "jsonrpc": "2.0",
            "method": "publish",
            "params": {
                "topic": topic,
                "message": BASE64.encode(&envelope),
                "tag": 1108,
                "ttl": 300
            }
        });
        relay.send_text(serde_json::to_string(&pub_msg)?).await?;

        loop {
            let raw = relay.recv().await.map_err(|e| WcError::Relay(format!("recv: {e}")))?;
            let envelope_val: serde_json::Value = serde_json::from_str(&raw)?;

            if envelope_val.get("method").and_then(|m| m.as_str()) != Some("subscription") {
                continue;
            }
            let data = match envelope_val.pointer("/params/data") {
                Some(d) => d,
                None => continue,
            };
            let b64_msg = match data.get("message").and_then(|m| m.as_str()) {
                Some(m) => m,
                None => continue,
            };

            let encrypted = BASE64.decode(b64_msg).unwrap_or_default();
            if encrypted.len() < 12 {
                continue;
            }
            let resp_nonce: [u8; 12] = encrypted[..12].try_into().unwrap();
            let plaintext =
                WcCipher::open(&sym_key, &resp_nonce, WC_AAD, &encrypted[12..]).unwrap_or_default();
            if plaintext.is_empty() {
                continue;
            }

            let resp: JsonRpcResponse = serde_json::from_slice(&plaintext)?;
            if resp.id == id {
                if let Some(e) = resp.error {
                    return Err(WcError::JsonRpc { code: e.code, message: e.message });
                }
                let new_topic = resp
                    .result
                    .as_ref()
                    .and_then(|r| r.get("topic"))
                    .and_then(|t| t.as_str())
                    .map(String::from);
                if let Some(t) = &new_topic {
                    *self.topic.lock().await = Some(t.clone());
                }
                return Ok(proposer_pubkey);
            }
        }
    }
}

impl Default for WcDappClient {
    fn default() -> Self {
        Self::new()
    }
}
