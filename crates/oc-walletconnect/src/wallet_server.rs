//! WC v2 Wallet Role server (daemon side).
//!
//! Maintains a session table, listens on the relay for inbound JSON-RPC
//! requests, dispatches them through a pluggable [`WalletMethodHandler`], and
//! publishes the encrypted response back to the relay on the same topic.
//!
//! For MVP, encryption is symmetric (per-session symKey) using ChaCha20-Poly1305.
//! The full X25519 + HKDF key derivation is wired in Task 3; this module uses
//! the derived symKey directly.

use std::sync::Arc;

use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use rand::RngExt;
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::Mutex;

#[cfg(any(test, feature = "test-utils"))]
use crate::mock_relay::MockRelay;
use crate::{
    crypto::{WcCipher, WcSymKey},
    error::{WcError, WcResult},
    jsonrpc::{JsonRpcError, JsonRpcErrorCode, JsonRpcRequest, JsonRpcResponse},
    method::{self, SessionProposeParams, SessionSettleParams},
    relay::{RelayClient, RelayConfig},
    session::{WcSession, WcSessionState, WcSessionTable},
    uri::PairingUri,
};

const WC_AAD: &[u8] = b"wc-2.0";

/// Trait implemented by the Net-Agent's WC method router.
///
/// `method` is the JSON-RPC method name (e.g. `"personal_sign"`,
/// `"onecipher_listWallets"`). `params` is the parsed JSON-RPC params object.
/// `session_topic` identifies the WC session the request came in on, so the
/// handler can look up the bound `SessionKeyInfo` and PolicyRulesV2.
#[async_trait]
pub trait WalletMethodHandler: Send + Sync {
    async fn handle(
        &self,
        method: &str,
        params: Value,
        session_topic: &str,
    ) -> Result<Value, (JsonRpcErrorCode, String)>;
}

#[derive(Debug, Clone)]
pub struct WcWalletConfig {
    pub relay_url: String,
    pub relay_protocol: String,
    /// If non-empty, only session proposals from dApps whose origin URL contains
    /// one of these strings are auto-approved. If empty, all proposals are
    /// rejected (secure default).
    pub trusted_origins: Vec<String>,
}

pub struct WcWalletServer<H: WalletMethodHandler> {
    cfg: WcWalletConfig,
    #[cfg_attr(not(any(test, feature = "test-utils")), allow(dead_code))]
    handler: H,
    sessions: Arc<Mutex<WcSessionTable>>,
    #[cfg(any(test, feature = "test-utils"))]
    mock_relay: Option<Arc<MockRelay>>,
}

impl<H: WalletMethodHandler> WcWalletServer<H> {
    pub fn new(cfg: WcWalletConfig, handler: H) -> Self {
        Self {
            cfg,
            handler,
            sessions: Arc::new(Mutex::new(WcSessionTable::new())),
            #[cfg(any(test, feature = "test-utils"))]
            mock_relay: None,
        }
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub fn attach_mock_relay(&mut self, relay: Arc<MockRelay>) {
        self.mock_relay = Some(relay);
    }

    /// Returns a clonable handle that can inject sessions while `run()` blocks.
    ///
    /// The handle shares the same `Arc<Mutex<WcSessionTable>>` as the server,
    /// so `insert_session` / `add_pairing` calls on the handle are visible to
    /// the `run()` loop, which will subscribe to newly inserted topics on its
    /// next iteration.
    pub fn session_handle(&self) -> WcServerHandle {
        WcServerHandle { sessions: Arc::clone(&self.sessions) }
    }

    pub async fn insert_session(&self, session: WcSession) {
        self.sessions.lock().await.insert(session);
    }

    pub async fn list_sessions(&self) -> Vec<WcSession> {
        self.sessions.lock().await.iter().cloned().collect()
    }

    pub async fn disconnect_session(&self, topic: &str) -> WcResult<()> {
        let mut t = self.sessions.lock().await;
        if let Some(s) = t.get_mut(topic) {
            s.close();
        }
        t.remove(topic);
        Ok(())
    }

    /// Process exactly one inbound message on the given topic (mock relay, for tests).
    #[cfg(any(test, feature = "test-utils"))]
    pub async fn process_one(&self, topic: &str) -> WcResult<()> {
        let relay = self
            .mock_relay
            .clone()
            .ok_or_else(|| WcError::Relay("no mock relay attached".into()))?;

        let mut sub = relay.subscribe(topic).await;
        let payload = sub.recv().await.map_err(|e| WcError::Relay(format!("recv: {e:?}")))?;

        let req: JsonRpcRequest = serde_json::from_slice(&payload)?;

        {
            let t = self.sessions.lock().await;
            if let Some(s) = t.get(topic) {
                if !s.is_active() {
                    let resp = JsonRpcResponse::error(
                        req.id,
                        JsonRpcError::new(
                            JsonRpcErrorCode::Unauthorized,
                            "session not active".into(),
                        ),
                    );
                    relay.publish(topic, serde_json::to_vec(&resp)?.as_slice()).await;
                    return Ok(());
                }
                if !s.is_method_allowed(&req.method) {
                    let resp = JsonRpcResponse::error(
                        req.id,
                        JsonRpcError::new(
                            JsonRpcErrorCode::UnsupportedMethod,
                            format!("method {} not authorized", req.method),
                        ),
                    );
                    relay.publish(topic, serde_json::to_vec(&resp)?.as_slice()).await;
                    return Ok(());
                }
            }
        }

        let result = self.handler.handle(&req.method, req.params.clone(), topic).await;
        let resp = match result {
            Ok(v) => JsonRpcResponse::success(req.id, v),
            Err((code, msg)) => JsonRpcResponse::error(req.id, JsonRpcError::new(code, msg)),
        };

        let bytes = serde_json::to_vec(&resp)?;
        relay.publish(topic, &bytes).await;

        Ok(())
    }

    /// Main run loop — connects to the real relay, subscribes to all known
    /// topics, and processes inbound messages. Reconnects on disconnect
    /// with exponential backoff.
    pub async fn run(&mut self) -> WcResult<()> {
        let relay_cfg = RelayConfig { url: self.cfg.relay_url.clone(), reconnect_max_ms: 60_000 };

        let mut relay = RelayClient::connect(relay_cfg).await?;
        let mut req_id: i64 = 1;

        let topics: Vec<String> = {
            let t = self.sessions.lock().await;
            t.iter().filter(|s| s.is_active()).map(|s| s.topic.clone()).collect()
        };
        let mut subscribed_topics: Vec<String> = topics.clone();
        for topic in &topics {
            req_id += 1;
            let sub_msg = serde_json::json!({
                "id": req_id - 1,
                "jsonrpc": "2.0",
                "method": "subscribe",
                "params": { "topic": topic }
            });
            relay.send_text(serde_json::to_string(&sub_msg)?).await?;
        }

        loop {
            {
                let t = self.sessions.lock().await;
                for s in t.iter() {
                    if s.is_active() && !subscribed_topics.contains(&s.topic) {
                        req_id += 1;
                        let sub_msg = serde_json::json!({
                            "id": req_id - 1,
                            "jsonrpc": "2.0",
                            "method": "subscribe",
                            "params": { "topic": s.topic }
                        });
                        let _ = relay.send_text(serde_json::to_string(&sub_msg)?).await;
                        subscribed_topics.push(s.topic.clone());
                    }
                }
            }

            let raw = match relay.recv().await {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("wallet_server: relay recv error: {e}, reconnecting");
                    relay.reconnect().await?;
                    let topics: Vec<String> = {
                        let t = self.sessions.lock().await;
                        t.iter().filter(|s| s.is_active()).map(|s| s.topic.clone()).collect()
                    };
                    subscribed_topics.clear();
                    for topic in &topics {
                        req_id += 1;
                        let sub_msg = serde_json::json!({
                            "id": req_id - 1,
                            "jsonrpc": "2.0",
                            "method": "subscribe",
                            "params": { "topic": topic }
                        });
                        relay.send_text(serde_json::to_string(&sub_msg)?).await?;
                        subscribed_topics.push(topic.clone());
                    }
                    continue;
                }
            };

            let envelope: RelayEnvelope = match serde_json::from_str(&raw) {
                Ok(e) => e,
                Err(_) => continue,
            };

            if envelope.method.as_deref() != Some("subscription") {
                continue;
            }
            let params = match envelope.params {
                Some(p) => p,
                None => continue,
            };
            let data = match params.data {
                Some(d) => d,
                None => continue,
            };
            let topic = &data.topic;

            let session = {
                let t = self.sessions.lock().await;
                t.get(topic).cloned()
            };
            let session = match session {
                Some(s) => s,
                None => continue,
            };

            if !session.is_active() {
                continue;
            }

            let encrypted_bytes = match BASE64.decode(&data.message) {
                Ok(b) => b,
                Err(_) => continue,
            };
            if encrypted_bytes.len() < 12 {
                continue;
            }
            let nonce: [u8; 12] = encrypted_bytes[..12].try_into().unwrap();
            let ciphertext = &encrypted_bytes[12..];

            let sym_key_bytes = match hex::decode(&session.sym_key) {
                Ok(b) => b,
                Err(_) => continue,
            };
            if sym_key_bytes.len() != 32 {
                continue;
            }
            let mut key_arr = [0u8; 32];
            key_arr.copy_from_slice(&sym_key_bytes);
            let sym_key = WcSymKey::from_bytes(key_arr);

            let plaintext = match WcCipher::open(&sym_key, &nonce, WC_AAD, ciphertext) {
                Ok(p) => p,
                Err(_) => continue,
            };

            if let Ok(req) = serde_json::from_slice::<JsonRpcRequest>(&plaintext) {
                if req.method == method::SESSION_PROPOSE {
                    self.handle_session_propose(&mut relay, &req, topic, &session, &mut req_id)
                        .await?;
                    continue;
                }
            }

            let req: JsonRpcRequest = serde_json::from_slice(&plaintext)?;
            let resp = {
                let t = self.sessions.lock().await;
                if let Some(s) = t.get(topic) {
                    if s.is_method_allowed(&req.method) {
                        drop(t);
                        match self.handler.handle(&req.method, req.params.clone(), topic).await {
                            Ok(v) => JsonRpcResponse::success(req.id, v),
                            Err((code, msg)) => {
                                JsonRpcResponse::error(req.id, JsonRpcError::new(code, msg))
                            }
                        }
                    } else {
                        JsonRpcResponse::error(
                            req.id,
                            JsonRpcError::new(
                                JsonRpcErrorCode::UnsupportedMethod,
                                format!("method {} not authorized", req.method),
                            ),
                        )
                    }
                } else {
                    JsonRpcResponse::error(
                        req.id,
                        JsonRpcError::new(JsonRpcErrorCode::Internal, "session gone".into()),
                    )
                }
            };

            let resp_bytes = serde_json::to_vec(&resp)?;
            let mut nonce_resp = [0u8; 12];
            rand::rng().fill(&mut nonce_resp[..]);
            let ciphertext_resp = WcCipher::seal(&sym_key, &nonce_resp, WC_AAD, &resp_bytes)?;
            let mut envelope_out = nonce_resp.to_vec();
            envelope_out.extend_from_slice(&ciphertext_resp);

            req_id += 1;
            let pub_msg = serde_json::json!({
                "id": req_id - 1,
                "jsonrpc": "2.0",
                "method": "publish",
                "params": {
                    "topic": topic,
                    "message": BASE64.encode(&envelope_out),
                    "tag": 1108,
                    "ttl": 300
                }
            });
            relay.send_text(serde_json::to_string(&pub_msg)?).await?;
        }
    }

    /// Handle `wc_sessionPropose` — approve only if dApp origin is trusted.
    async fn handle_session_propose(
        &self,
        relay: &mut RelayClient,
        req: &JsonRpcRequest,
        pairing_topic: &str,
        session: &WcSession,
        req_id: &mut i64,
    ) -> WcResult<()> {
        let mut next_id = || -> i64 {
            *req_id += 1;
            *req_id - 1
        };
        let propose_params: SessionProposeParams = serde_json::from_value(req.params.clone())
            .map_err(|e| WcError::InvalidMessage(format!("bad sessionPropose params: {e}")))?;

        let sym_key_bytes = hex::decode(&session.sym_key)
            .map_err(|_| WcError::InvalidMessage("bad sym_key hex".into()))?;
        if sym_key_bytes.len() != 32 {
            return Err(WcError::InvalidMessage("sym_key must be 32 bytes".into()));
        }
        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&sym_key_bytes);
        let sym_key = WcSymKey::from_bytes(key_arr);

        // Origin allowlist check
        let dapp_origin = &propose_params.proposer.metadata.url;
        if self.cfg.trusted_origins.is_empty() ||
            !self.cfg.trusted_origins.iter().any(|o| dapp_origin.contains(o.as_str()))
        {
            let reason = if self.cfg.trusted_origins.is_empty() {
                "no trusted origins configured; session proposal rejected"
            } else {
                "dApp origin not in trusted origins"
            };
            self.send_encrypted(
                relay,
                pairing_topic,
                &sym_key,
                &JsonRpcResponse::error(
                    req.id,
                    JsonRpcError::new(JsonRpcErrorCode::Unauthorized, reason.into()),
                ),
                &mut next_id,
            )
            .await?;
            return Ok(());
        }

        let session_topic = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(propose_params.proposer.publicKey.as_bytes());
            hex::encode(hasher.finalize())
        };

        let controller_pubkey = "0000000000000000000000000000000000000000000000000000000000000000";
        let approve_result = serde_json::json!({
            "relay": { "protocol": self.cfg.relay_protocol },
            "responderPublicKey": controller_pubkey,
            "expiry": session.expiry_unix
        });
        let approve_resp = JsonRpcResponse::success(req.id, approve_result);

        self.send_encrypted(relay, pairing_topic, &sym_key, &approve_resp, &mut next_id).await?;

        let sub_msg = serde_json::json!({
            "id": next_id(),
            "jsonrpc": "2.0",
            "method": "subscribe",
            "params": { "topic": session_topic }
        });
        relay.send_text(serde_json::to_string(&sub_msg)?).await?;

        let new_session = WcSession {
            topic: session_topic.clone(),
            sym_key: session.sym_key.clone(),
            state: WcSessionState::Active,
            expiry_unix: session.expiry_unix,
            namespaces: vec!["eip155:1".into()],
            methods: propose_params
                .required_namespaces
                .get("eip155")
                .and_then(|n| n.get("methods"))
                .and_then(|m| m.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                .unwrap_or_default(),
            dapp_origin: Some(propose_params.proposer.metadata.url.clone()),
            dapp_name: Some(propose_params.proposer.metadata.name.clone()),
            created_at_unix: crate::session::now_unix(),
        };
        self.sessions.lock().await.insert(new_session);

        let settle = serde_json::to_value(SessionSettleParams {
            relay: crate::method::RelayProtocolOptions {
                protocol: self.cfg.relay_protocol.clone(),
                data: None,
            },
            controller: crate::method::SessionParticipant {
                publicKey: controller_pubkey.to_string(),
                metadata: crate::method::ProposerMetadata {
                    name: "OneCipher".into(),
                    description: "OneCipher WalletConnect Server".into(),
                    url: "https://onecipher.dev".into(),
                    icons: vec![],
                },
            },
            namespaces: serde_json::json!({ "eip155": { "methods": [], "events": [], "chains": [] } }),
            expiry: session.expiry_unix,
        })?;
        let settle_req = serde_json::json!({
            "id": next_id(),
            "jsonrpc": "2.0",
            "method": method::SESSION_SETTLE,
            "params": settle
        });
        let settle_bytes = serde_json::to_vec(&settle_req)?;
        let mut settle_nonce = [0u8; 12];
        rand::rng().fill(&mut settle_nonce[..]);
        let settle_ct = WcCipher::seal(&sym_key, &settle_nonce, WC_AAD, &settle_bytes)?;
        let mut settle_env = settle_nonce.to_vec();
        settle_env.extend_from_slice(&settle_ct);

        let settle_pub = serde_json::json!({
            "id": next_id(),
            "jsonrpc": "2.0",
            "method": "publish",
            "params": {
                "topic": session_topic,
                "message": BASE64.encode(&settle_env),
                "tag": 1108,
                "ttl": 300
            }
        });
        relay.send_text(serde_json::to_string(&settle_pub)?).await?;

        Ok(())
    }

    /// Encrypt a JSON-RPC response with the session's symKey and publish it on `topic`.
    async fn send_encrypted(
        &self,
        relay: &mut RelayClient,
        topic: &str,
        sym_key: &WcSymKey,
        resp: &JsonRpcResponse,
        next_id: &mut impl FnMut() -> i64,
    ) -> WcResult<()> {
        let resp_bytes = serde_json::to_vec(resp)?;
        let mut nonce = [0u8; 12];
        rand::rng().fill(&mut nonce[..]);
        let ciphertext = WcCipher::seal(sym_key, &nonce, WC_AAD, &resp_bytes)?;
        let mut env = nonce.to_vec();
        env.extend_from_slice(&ciphertext);
        let pub_msg = serde_json::json!({
            "id": next_id(),
            "jsonrpc": "2.0",
            "method": "publish",
            "params": {
                "topic": topic,
                "message": BASE64.encode(&env),
                "tag": 1108,
                "ttl": 300
            }
        });
        relay.send_text(serde_json::to_string(&pub_msg)?).await?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// WcServerHandle — clonable handle for runtime pairing injection
// ---------------------------------------------------------------------------

/// Clonable handle to a running [`WcWalletServer`]'s session table.
///
/// Allows external tasks to inject new pairings or query session state while
/// [`WcWalletServer::run`] holds `&mut self` and blocks. Created via
/// [`WcWalletServer::session_handle`].
///
/// # Usage
///
/// ```ignore
/// let mut server = WcWalletServer::new(cfg, handler);
/// let handle = server.session_handle();
/// // Spawn server.run() in a background task
/// tokio::spawn(async move { server.run().await });
/// // From another task, inject a pairing:
/// handle.add_pairing(&uri, 86400).await?;
/// ```
#[derive(Clone)]
pub struct WcServerHandle {
    sessions: Arc<Mutex<WcSessionTable>>,
}

impl WcServerHandle {
    /// Insert a pre-built session into the table.
    pub async fn insert_session(&self, session: WcSession) {
        self.sessions.lock().await.insert(session);
    }

    /// Inject a pairing URI as a new `Propose`-state session.
    ///
    /// The `run()` loop will subscribe to the session's topic on its next
    /// iteration, allowing the dApp to send `wc_sessionPropose`.
    ///
    /// # Errors
    ///
    /// Returns [`WcError::InvalidUri`] if the URI has no `symKey`.
    pub async fn add_pairing(&self, uri: &PairingUri, ttl_secs: u64) -> WcResult<WcSession> {
        let sym_key = uri
            .sym_key
            .clone()
            .ok_or_else(|| WcError::InvalidUri("pairing URI missing symKey".into()))?;
        let now = crate::session::now_unix();
        let session = WcSession::new_pairing(uri.topic.clone(), sym_key, now + ttl_secs);
        self.insert_session(session.clone()).await;
        Ok(session)
    }

    /// List all sessions currently in the table.
    pub async fn list_sessions(&self) -> Vec<WcSession> {
        self.sessions.lock().await.iter().cloned().collect()
    }

    /// Remove a session by topic.
    pub async fn disconnect_session(&self, topic: &str) {
        self.sessions.lock().await.remove(topic);
    }
}

#[derive(Debug, Deserialize)]
struct RelayEnvelope {
    method: Option<String>,
    params: Option<RelaySubParams>,
}

#[derive(Debug, Deserialize)]
struct RelaySubParams {
    data: Option<RelaySubData>,
}

#[derive(Debug, Deserialize)]
struct RelaySubData {
    topic: String,
    message: String,
}
