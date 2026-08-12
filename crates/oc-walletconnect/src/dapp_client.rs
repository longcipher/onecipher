//! WC v2 dApp Role client (CLI side) — spec-compliant.
//!
//! Connects to a relay, binds to a session topic, sends JSON-RPC requests,
//! and awaits responses. Supports both real WSS relay and mock relay for tests.
//!
//! Follows the official WalletConnect 2.0 flow:
//! 1. The pairing `symKey` from the URI encrypts pairing-phase messages with a **type-0 envelope**.
//! 2. `wc_sessionPropose` is sent as a **type-1 envelope** carrying the dApp's X25519 public key.
//! 3. On approval, the dApp derives the session key via `deriveSymKey(dapp_priv, responder_pub)`
//!    (X25519 + HKDF) and binds it.

#[cfg(any(test, feature = "test-utils"))]
use std::sync::Arc;

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use serde_json::Value;
use tokio::sync::Mutex;

#[cfg(any(test, feature = "test-utils"))]
use crate::mock_relay::MockRelay;
use crate::{
    crypto::{self, WcCipher, WcKeyPair, WcSymKey},
    error::{WcError, WcResult},
    jsonrpc::{JsonRpcRequest, JsonRpcResponse},
    method::{self, Proposer, ProposerMetadata, RelayProtocolOptions, SessionProposeParams},
    relay::{RelayClient, RelayConfig},
    uri::PairingUri,
};

pub struct WcDappClient {
    topic: Mutex<Option<String>>,
    next_id: Mutex<i64>,
    sym_key: Mutex<Option<WcSymKey>>,
    relay: Mutex<Option<RelayClient>>,
    // The dApp's X25519 keypair used for session-key derivation.
    keypair: Mutex<Option<WcKeyPair>>,
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
            keypair: Mutex::new(Some(WcKeyPair::generate())),
            #[cfg(any(test, feature = "test-utils"))]
            mock_relay: None,
        }
    }

    /// Create a mock-relay client for tests.
    #[cfg(test)]
    pub fn new_mock(relay: Arc<MockRelay>) -> Self {
        Self {
            topic: Mutex::new(None),
            next_id: Mutex::new(1),
            sym_key: Mutex::new(None),
            relay: Mutex::new(None),
            keypair: Mutex::new(Some(WcKeyPair::generate())),
            mock_relay: Some(relay),
        }
    }

    /// Connect to a relay using pairing URI parameters.
    ///
    /// The relay URL is taken from the URI's `relay_protocol` query, or falls
    /// back to the `OC_WC_RELAY_URL` env var, or the default
    /// `wss://relay.walletconnect.com`. The pairing `symKey` becomes the
    /// client's initial symmetric key.
    pub async fn connect(uri: &PairingUri) -> WcResult<Self> {
        // Resolve the relay URL: OC_WC_RELAY_URL env override > the URI's
        // projectId-aware default. The projectId (from the URI or env) is
        // appended to the URL if the URL does not already carry one.
        let project_id = uri.project_id.clone().or_else(|| std::env::var("OC_WC_PROJECT_ID").ok());
        let base_url = std::env::var("OC_WC_RELAY_URL")
            .ok()
            .unwrap_or_else(|| "wss://relay.walletconnect.com".to_string());
        let relay_url = crate::apply_project_id(&base_url, project_id.as_deref());
        let relay_cfg = RelayConfig { url: relay_url, reconnect_max_ms: 60_000 };
        let mut relay = RelayClient::connect(relay_cfg).await?;

        let sub_msg = serde_json::json!({
            "id": relay_id(1),
            "jsonrpc": "2.0",
            "method": "irn_subscribe",
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
            keypair: Mutex::new(Some(WcKeyPair::generate())),
            #[cfg(any(test, feature = "test-utils"))]
            mock_relay: None,
        })
    }

    pub fn set_sym_key(&self, key: WcSymKey) {
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
            // Accept plaintext or encrypted envelope.
            let resp: JsonRpcResponse = if payload.first() == Some(&crypto::ENVELOPE_TYPE_0) ||
                payload.first() == Some(&crypto::ENVELOPE_TYPE_1)
            {
                let key = self.sym_key.lock().await.clone().ok_or_else(|| {
                    WcError::Crypto("no sym key for encrypted mock response".into())
                })?;
                let pt = match payload[0] {
                    crypto::ENVELOPE_TYPE_0 => WcCipher::open_type0(&key, &payload)?,
                    crypto::ENVELOPE_TYPE_1 => WcCipher::open_type1(&key, &payload)?.1,
                    _ => unreachable!(),
                };
                serde_json::from_slice(&pt)?
            } else {
                serde_json::from_slice(&payload)?
            };
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

        let envelope = WcCipher::seal_type0(&sym_key, &req_bytes)?;

        let attestation = std::env::var("OC_WC_ATTESTATION").ok().filter(|s| !s.is_empty());
        relay
            .publish_irn(
                &relay_id(id),
                &topic,
                &BASE64.encode(&envelope),
                300,
                1108,
                attestation.as_deref(),
            )
            .await?;

        loop {
            let raw = relay.recv().await.map_err(|e| WcError::Relay(format!("recv: {e}")))?;
            let envelope_val: serde_json::Value = serde_json::from_str(&raw)?;

            if envelope_val.get("method").and_then(|m| m.as_str()) != Some("irn_subscription") {
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
            if encrypted.first() != Some(&crypto::ENVELOPE_TYPE_0) &&
                encrypted.first() != Some(&crypto::ENVELOPE_TYPE_1)
            {
                continue;
            }
            let plaintext = match encrypted[0] {
                crypto::ENVELOPE_TYPE_0 => WcCipher::open_type0(&sym_key, &encrypted)?,
                crypto::ENVELOPE_TYPE_1 => WcCipher::open_type1(&sym_key, &encrypted)?.1,
                _ => continue,
            };
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
    ///
    /// The propose request is sent as a **type-1 envelope** carrying the dApp's
    /// X25519 public key, and on approval the session key is derived via
    /// `deriveSymKey(dapp_priv, responder_pub)`.
    pub async fn propose(&self, dapp_name: &str, dapp_url: &str) -> WcResult<String> {
        let topic = self
            .topic
            .lock()
            .await
            .clone()
            .ok_or_else(|| WcError::SessionNotFound("no bound session".into()))?;

        let pairing_key = self
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

        let kp = WcKeyPair::generate();
        let proposer_pubkey = kp.public_key_hex();

        let propose = SessionProposeParams {
            relays: vec![RelayProtocolOptions { protocol: "irn".into(), data: None }],
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

        // Type-1 envelope: [type(1) ‖ senderPubKey(32) ‖ iv(12) ‖ ciphertext].
        let envelope = WcCipher::seal_type1(
            &pairing_key,
            &{
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&hex::decode(&proposer_pubkey).unwrap_or_default());
                arr
            },
            &req_bytes,
        )?;

        let attestation = std::env::var("OC_WC_ATTESTATION").ok().filter(|s| !s.is_empty());
        relay
            .publish_irn(
                &relay_id(id),
                &topic,
                &BASE64.encode(&envelope),
                300,
                1108,
                attestation.as_deref(),
            )
            .await?;

        // Store the proposer keypair for session-key derivation.
        *self.keypair.lock().await = Some(kp);

        loop {
            let raw = relay.recv().await.map_err(|e| WcError::Relay(format!("recv: {e}")))?;
            let envelope_val: serde_json::Value = serde_json::from_str(&raw)?;

            if envelope_val.get("method").and_then(|m| m.as_str()) != Some("irn_subscription") {
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
            if encrypted.first() != Some(&crypto::ENVELOPE_TYPE_0) &&
                encrypted.first() != Some(&crypto::ENVELOPE_TYPE_1)
            {
                continue;
            }
            // The approval response is encrypted with the pairing key.
            let plaintext = match encrypted[0] {
                crypto::ENVELOPE_TYPE_0 => WcCipher::open_type0(&pairing_key, &encrypted)?,
                crypto::ENVELOPE_TYPE_1 => WcCipher::open_type1(&pairing_key, &encrypted)?.1,
                _ => continue,
            };
            if plaintext.is_empty() {
                continue;
            }

            let resp: JsonRpcResponse = serde_json::from_slice(&plaintext)?;
            if resp.id == id {
                if let Some(e) = resp.error {
                    return Err(WcError::JsonRpc { code: e.code, message: e.message });
                }
                // Derive the session key from the responder's public key.
                let responder_pub_hex = resp
                    .result
                    .as_ref()
                    .and_then(|r| r.get("responderPublicKey"))
                    .and_then(|k| k.as_str())
                    .ok_or_else(|| {
                        WcError::InvalidMessage("approve missing responderPublicKey".into())
                    })?;
                let responder_bytes = hex::decode(responder_pub_hex).map_err(|e| {
                    WcError::InvalidMessage(format!("bad responder publicKey hex: {e}"))
                })?;
                if responder_bytes.len() != 32 {
                    return Err(WcError::InvalidMessage(
                        "responder publicKey must be 32 bytes".into(),
                    ));
                }
                let mut responder_pub = [0u8; 32];
                responder_pub.copy_from_slice(&responder_bytes);

                let kp = self
                    .keypair
                    .lock()
                    .await
                    .clone()
                    .ok_or_else(|| WcError::Crypto("proposer keypair missing".into()))?;
                let shared = kp.shared_secret(&x25519_dalek::PublicKey::from(responder_pub));
                let session_key = crypto::derive_sym_key(&shared);
                *self.sym_key.lock().await = Some(session_key.clone());

                // The session topic is SHA-256 of the proposer public key
                // (matches the wallet side).
                let session_topic =
                    crypto::hash_bytes(&hex::decode(&proposer_pubkey).unwrap_or_default());
                *self.topic.lock().await = Some(session_topic.clone());

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

/// Generate a relay JSON-RPC `id` matching the official client's recommendation
/// (19-digit value: 13-digit epoch milliseconds + 6-digit entropy).
fn relay_id(counter: i64) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let millis = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64);
    let id = (millis << 20) | ((counter as u64) & 0xFFFFF);
    format!("{id:019}")
}
