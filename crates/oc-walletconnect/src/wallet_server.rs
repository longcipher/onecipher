//! WC v2 Wallet Role server (daemon side) — spec-compliant.
//!
//! Maintains a session table, listens on the relay for inbound JSON-RPC
//! requests, dispatches them through a pluggable [`WalletMethodHandler`], and
//! publishes the encrypted response back to the relay on the same topic.
//!
//! Wire format follows the official WalletConnect 2.0 spec:
//! - Pairing-phase messages are encrypted with the pairing `symKey` from the URI using a **type-0
//!   envelope** (empty AAD).
//! - On `wc_sessionPropose`, the wallet derives the **session symmetric key** via
//!   `deriveSymKey(wallet_private, proposer_public)` (X25519 + HKDF) and responds with its own
//!   X25519 public key; the dApp derives the same key from its private key + the responder's public
//!   key.

use std::{future::Future, pin::Pin, sync::Arc};

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::Mutex;

#[cfg(any(test, feature = "test-utils"))]
use crate::mock_relay::MockRelay;
use crate::{
    crypto::{self, WcCipher, WcKeyPair, WcSymKey},
    error::{WcError, WcResult},
    jsonrpc::{JsonRpcError, JsonRpcErrorCode, JsonRpcRequest, JsonRpcResponse},
    method::{self, SessionProposeParams, SessionSettleParams},
    relay::{RelayClient, RelayConfig},
    session::{WcSession, WcSessionState, WcSessionTable},
    uri::PairingUri,
};

pub type HandlerResult<'a> =
    Pin<Box<dyn Future<Output = Result<Value, (JsonRpcErrorCode, String)>> + Send + 'a>>;

/// Trait implemented by the Net-Agent's WC method router.
pub trait WalletMethodHandler: Send + Sync {
    fn handle<'a>(
        &'a self,
        method: &str,
        params: Value,
        session_topic: &str,
        dapp_name: Option<&str>,
        dapp_origin: Option<&str>,
    ) -> HandlerResult<'a>;
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

    /// Construct a wallet server sharing an existing session table with the
    /// method handler (e.g. so the router can resolve `dapp_name`/`dapp_origin`
    /// for the approval gate without a second lookup path).
    ///
    /// [`Self::new`] remains available and constructs its own table.
    pub fn with_session_table(
        cfg: WcWalletConfig,
        handler: H,
        sessions: Arc<Mutex<WcSessionTable>>,
    ) -> Self {
        Self {
            cfg,
            handler,
            sessions,
            #[cfg(any(test, feature = "test-utils"))]
            mock_relay: None,
        }
    }

    /// Expose the shared session table (used by the daemon to hand the same
    /// table to both the router and the server).
    pub fn session_table(&self) -> Arc<Mutex<WcSessionTable>> {
        Arc::clone(&self.sessions)
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub fn attach_mock_relay(&mut self, relay: Arc<MockRelay>) {
        self.mock_relay = Some(relay);
    }

    /// Returns a clonable handle that can inject sessions while `run()` blocks.
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
    ///
    /// Accepts both the spec-compliant encrypted envelope (type 0) and a
    /// plaintext JSON-RPC message (legacy mock path). Responses are published
    /// back in the same format that was received.
    #[cfg(any(test, feature = "test-utils"))]
    pub async fn process_one(&self, topic: &str) -> WcResult<()> {
        let relay = self
            .mock_relay
            .clone()
            .ok_or_else(|| WcError::Relay("no mock relay attached".into()))?;

        let mut sub = relay.subscribe(topic).await;
        let payload = sub.recv().await.map_err(|e| WcError::Relay(format!("recv: {e:?}")))?;

        // Determine whether the inbound message is an encrypted envelope.
        let session_key = {
            let t = self.sessions.lock().await;
            t.get(topic).and_then(|s| s.sym_key.to_sym_key())
        };
        let encrypted = payload.first() == Some(&crypto::ENVELOPE_TYPE_0) ||
            payload.first() == Some(&crypto::ENVELOPE_TYPE_1);

        let (req, outbound_encrypted): (JsonRpcRequest, bool) = if encrypted {
            let key = session_key
                .as_ref()
                .ok_or_else(|| WcError::Crypto("no sym key for topic".into()))?;
            let plaintext = match payload[0] {
                crypto::ENVELOPE_TYPE_0 => WcCipher::open_type0(key, &payload)?,
                crypto::ENVELOPE_TYPE_1 => {
                    let (_sender, pt) = WcCipher::open_type1(key, &payload)?;
                    pt
                }
                _ => unreachable!(),
            };
            (serde_json::from_slice(&plaintext)?, true)
        } else {
            (serde_json::from_slice(&payload)?, false)
        };

        // Handle a session proposal (approve + settle) on the mock path too, so
        // integration tests can drive the full encrypted pairing flow without a
        // real relay.
        if req.method == method::SESSION_PROPOSE {
            let pairing_key = session_key
                .as_ref()
                .ok_or_else(|| WcError::Crypto("no pairing key for propose".into()))?;
            let proposer_pub = if payload.first() == Some(&crypto::ENVELOPE_TYPE_1) {
                let (_sender, _) = WcCipher::open_type1(pairing_key, &payload)?;
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&_sender);
                arr
            } else {
                // Fall back: derive from params.
                let params: serde_json::Value = req.params.clone();
                let pk = params
                    .get("proposer")
                    .and_then(|p| p.get("publicKey"))
                    .and_then(|k| k.as_str())
                    .ok_or_else(|| {
                        WcError::InvalidMessage("propose missing proposer.publicKey".into())
                    })?;
                let bytes = hex::decode(pk)
                    .map_err(|e| WcError::InvalidMessage(format!("bad pubkey: {e}")))?;
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                arr
            };
            self.process_propose_mock(&relay, topic, &req, pairing_key, &proposer_pub).await?;
            return Ok(());
        }

        // Session-level spec methods and the Auth protocol's wc_authRequest
        // bypass the active-state + method-allowed gates (see
        // `dispatch_session_request` for the live-relay equivalent).
        let bypass_gate = matches!(
            req.method.as_str(),
            method::SESSION_DELETE |
                method::SESSION_UPDATE |
                method::SESSION_PING |
                method::AUTH_REQUEST
        );

        if !bypass_gate {
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
                    self.publish_response(
                        &relay,
                        topic,
                        &resp,
                        outbound_encrypted,
                        session_key.as_ref(),
                    )
                    .await?;
                    return Ok(());
                }
                if !s.is_method_allowed(&req.method) {
                    eprintln!(
                        "[wsdbg] method {} NOT allowed on topic {} methods={:?} state={:?}",
                        req.method, topic, s.methods, s.state
                    );
                    let resp = JsonRpcResponse::error(
                        req.id,
                        JsonRpcError::new(
                            JsonRpcErrorCode::UnsupportedMethod,
                            format!("method {} not authorized", req.method),
                        ),
                    );
                    self.publish_response(
                        &relay,
                        topic,
                        &resp,
                        outbound_encrypted,
                        session_key.as_ref(),
                    )
                    .await?;
                    return Ok(());
                }
            }
        }

        // Session-level lifecycle methods are answered directly by the server
        // (they are spec-level and must never reach the dApp method router).
        match req.method.as_str() {
            method::SESSION_DELETE => {
                self.sessions.lock().await.remove(topic);
                let resp = JsonRpcResponse::success(req.id, json!({ "acknowledged": true }));
                self.publish_response(
                    &relay,
                    topic,
                    &resp,
                    outbound_encrypted,
                    session_key.as_ref(),
                )
                .await?;
                return Ok(());
            }
            method::SESSION_UPDATE => {
                let namespaces = req.params.get("namespaces").cloned().unwrap_or_else(|| json!({}));
                let mut methods = Vec::new();
                let mut ns: Vec<String> = Vec::new();
                if let Some(obj) = namespaces.as_object() {
                    for value in obj.values() {
                        if let Some(arr) = value.get("chains").and_then(|m| m.as_array()) {
                            ns.extend(arr.iter().filter_map(|v| v.as_str().map(String::from)));
                        }
                        if let Some(arr) = value.get("methods").and_then(|m| m.as_array()) {
                            methods.extend(arr.iter().filter_map(|v| v.as_str().map(String::from)));
                        }
                    }
                }
                if let Some(s) = self.sessions.lock().await.get_mut(topic) {
                    s.namespaces = ns;
                    s.methods = methods;
                }
                let resp = JsonRpcResponse::success(req.id, json!({ "acknowledged": true }));
                self.publish_response(
                    &relay,
                    topic,
                    &resp,
                    outbound_encrypted,
                    session_key.as_ref(),
                )
                .await?;
                return Ok(());
            }
            method::SESSION_PING => {
                let resp = JsonRpcResponse::success(req.id, json!({ "acknowledged": true }));
                self.publish_response(
                    &relay,
                    topic,
                    &resp,
                    outbound_encrypted,
                    session_key.as_ref(),
                )
                .await?;
                return Ok(());
            }
            _ => {}
        }

        // Session metadata for the handler (dApp name/origin used in approval
        // decisions). Both are `None` when the session is not in the table.
        let (dapp_name, dapp_origin) = {
            let t = self.sessions.lock().await;
            match t.get(topic) {
                Some(s) => (s.dapp_name.clone(), s.dapp_origin.clone()),
                None => (None, None),
            }
        };

        let result = self
            .handler
            .handle(
                &req.method,
                req.params.clone(),
                topic,
                dapp_name.as_deref(),
                dapp_origin.as_deref(),
            )
            .await;
        let resp = match result {
            Ok(v) => JsonRpcResponse::success(req.id, v),
            Err((code, msg)) => {
                eprintln!("[wsdbg] method {} error code={code:?} msg={msg}", req.method);
                JsonRpcResponse::error(req.id, JsonRpcError::new(code, msg))
            }
        };

        self.publish_response(&relay, topic, &resp, outbound_encrypted, session_key.as_ref())
            .await?;
        Ok(())
    }

    #[cfg(any(test, feature = "test-utils"))]
    async fn publish_response(
        &self,
        relay: &MockRelay,
        topic: &str,
        resp: &JsonRpcResponse,
        encrypted: bool,
        key: Option<&WcSymKey>,
    ) -> WcResult<()> {
        let bytes = serde_json::to_vec(resp)?;
        if encrypted {
            let key =
                key.ok_or_else(|| WcError::Crypto("no sym key for encrypted response".into()))?;
            let envelope = WcCipher::seal_type0(key, &bytes)?;
            relay.publish(topic, &envelope).await;
        } else {
            relay.publish(topic, &bytes).await;
        }
        Ok(())
    }

    /// Mock-relay counterpart of [`Self::handle_session_propose`]: approves a
    /// session proposal and publishes `wc_sessionSettle`, both encrypted, to
    /// the mock relay so integration tests can drive the full pairing flow
    /// without a real relay.
    #[cfg(any(test, feature = "test-utils"))]
    async fn process_propose_mock(
        &self,
        relay: &MockRelay,
        pairing_topic: &str,
        req: &JsonRpcRequest,
        pairing_key: &WcSymKey,
        proposer_pub: &[u8; 32],
    ) -> WcResult<()> {
        let propose_params: SessionProposeParams = serde_json::from_value(req.params.clone())
            .map_err(|e| WcError::InvalidMessage(format!("bad sessionPropose params: {e}")))?;

        // Origin allowlist check.
        let dapp_origin = &propose_params.proposer.metadata.url;
        if self.cfg.trusted_origins.is_empty() ||
            !origin_matches_trusted(dapp_origin, &self.cfg.trusted_origins)
        {
            let reason = if self.cfg.trusted_origins.is_empty() {
                "no trusted origins configured; session proposal rejected"
            } else {
                "dApp origin not in trusted origins"
            };
            let resp = JsonRpcResponse::error(
                req.id,
                JsonRpcError::new(JsonRpcErrorCode::Unauthorized, reason.into()),
            );
            self.publish_response(relay, pairing_topic, &resp, true, Some(pairing_key)).await?;
            return Ok(());
        }

        // Derive the session key from the proposer's public key.
        let responder_kp = WcKeyPair::generate();
        let shared = responder_kp.shared_secret(&x25519_dalek::PublicKey::from(*proposer_pub));
        let session_key = crypto::derive_sym_key(&shared);
        let responder_pubkey_hex = responder_kp.public_key_hex();

        let session_topic = crypto::hash_bytes(proposer_pub);

        // Approve response (encrypted with the pairing key, type-0 envelope).
        let approve_result = serde_json::json!({
            "relay": { "protocol": self.cfg.relay_protocol },
            "responderPublicKey": responder_pubkey_hex.clone(),
            "expiry": u64::MAX
        });
        let approve_resp = JsonRpcResponse::success(req.id, approve_result);
        self.publish_response(relay, pairing_topic, &approve_resp, true, Some(pairing_key)).await?;

        // Insert the new active session.
        let new_session = WcSession {
            topic: session_topic.clone(),
            sym_key: session_key.clone().into(),
            state: WcSessionState::Active,
            expiry_unix: u64::MAX,
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

        // Publish wc_sessionSettle encrypted with the session key.
        let settle = serde_json::to_value(SessionSettleParams {
            relay: crate::method::RelayProtocolOptions {
                protocol: self.cfg.relay_protocol.clone(),
                data: None,
            },
            controller: crate::method::SessionParticipant {
                publicKey: responder_pubkey_hex,
                metadata: crate::method::ProposerMetadata {
                    name: "OneCipher".into(),
                    description: "OneCipher WalletConnect Server".into(),
                    url: "https://onecipher.dev".into(),
                    icons: vec![],
                },
            },
            namespaces: serde_json::json!({ "eip155": { "methods": [], "events": [], "chains": [] } }),
            expiry: u64::MAX,
        })?;
        let settle_req = serde_json::json!({
            "jsonrpc": "2.0",
            "method": method::SESSION_SETTLE,
            "params": settle,
            "id": 0
        });
        let settle_bytes = serde_json::to_vec(&settle_req)?;
        let settle_env = WcCipher::seal_type0(&session_key, &settle_bytes)?;
        relay.publish(&session_topic, &settle_env).await;

        Ok(())
    }

    /// Main run loop — connects to the real relay, subscribes to all known
    /// topics, and processes inbound messages. Reconnects on disconnect
    /// with exponential backoff.
    pub async fn run(&mut self) -> WcResult<()> {
        // Append projectId from the environment if the configured relay URL
        // does not already carry one (required by relay.walletconnect.com).
        let project_id = std::env::var("OC_WC_PROJECT_ID").ok();
        let relay_url = crate::apply_project_id(&self.cfg.relay_url, project_id.as_deref());
        let relay_cfg = RelayConfig { url: relay_url, reconnect_max_ms: 60_000 };

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
                "id": relay_id(req_id),
                "jsonrpc": "2.0",
                "method": "irn_subscribe",
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
                            "id": relay_id(req_id),
                            "jsonrpc": "2.0",
                            "method": "irn_subscribe",
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
                            "id": relay_id(req_id),
                            "jsonrpc": "2.0",
                            "method": "irn_subscribe",
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
                Err(e) => {
                    tracing::debug!(error = %e, "failed to parse relay envelope");
                    continue;
                }
            };

            if envelope.method.as_deref() != Some("irn_subscription") {
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

            let encrypted_bytes = match BASE64.decode(&data.message) {
                Ok(b) => b,
                Err(e) => {
                    tracing::debug!(error = %e, "failed to base64 decode message");
                    continue;
                }
            };

            // The message is an encrypted envelope. For a pairing (Propose)
            // topic, use the pairing symKey; for an active session topic, use
            // the session symKey (both live in session.sym_key).
            let Some(sym_key) = session.sym_key.to_sym_key() else {
                tracing::debug!("failed to decode session sym_key");
                continue;
            };

            // Propose phase: handle wc_sessionPropose specially (it may be a
            // type-1 envelope carrying the proposer's public key).
            let first_byte = encrypted_bytes.first().copied();
            if first_byte == Some(crypto::ENVELOPE_TYPE_1) ||
                first_byte == Some(crypto::ENVELOPE_TYPE_0)
            {
                let plaintext = match first_byte {
                    Some(crypto::ENVELOPE_TYPE_1) => {
                        // Derive the session key from the proposer's public key.
                        let (_proposer_pub, pt) = WcCipher::open_type1(&sym_key, &encrypted_bytes)?;
                        pt
                    }
                    _ => WcCipher::open_type0(&sym_key, &encrypted_bytes)?,
                };
                if let Ok(req) = serde_json::from_slice::<JsonRpcRequest>(&plaintext) {
                    if req.method == method::SESSION_PROPOSE {
                        self.handle_session_propose(
                            &mut relay,
                            &req,
                            topic,
                            &session,
                            &mut req_id,
                            &sym_key,
                        )
                        .await?;
                        continue;
                    }
                }
                // Non-propose request on a pairing topic — treat as regular.
                let req: JsonRpcRequest = serde_json::from_slice(&plaintext)?;
                self.dispatch_session_request(
                    &mut relay,
                    topic,
                    &req,
                    &session,
                    &sym_key,
                    &mut req_id,
                )
                .await?;
                continue;
            }

            // Legacy plaintext JSON-RPC over the relay (no envelope).
            let req: JsonRpcRequest = serde_json::from_slice(&encrypted_bytes)?;
            self.dispatch_session_request(&mut relay, topic, &req, &session, &sym_key, &mut req_id)
                .await?;
        }
    }

    /// Dispatch a session JSON-RPC request (encrypted response, type-0 envelope).
    ///
    /// Session-level spec methods (`wc_sessionDelete`, `wc_sessionUpdate`,
    /// `wc_sessionPing`) and the Auth protocol's `wc_authRequest` are handled
    /// **before** the `is_method_allowed` gate: the former are protocol
    /// lifecycle messages that the dApp may send regardless of the approved
    /// namespace methods, and the latter is a one-time pairing-topic request
    /// that never goes through session negotiation.
    #[allow(clippy::too_many_arguments)]
    async fn dispatch_session_request(
        &self,
        relay: &mut RelayClient,
        topic: &str,
        req: &JsonRpcRequest,
        session: &WcSession,
        sym_key: &WcSymKey,
        req_id: &mut i64,
    ) -> WcResult<()> {
        eprintln!(
            "[wsdbg] dispatch topic={} method={} methods={:?}",
            topic, req.method, session.methods
        );
        let resp = match req.method.as_str() {
            method::SESSION_DELETE => {
                // Remove the session from the table and acknowledge.
                self.sessions.lock().await.remove(topic);
                JsonRpcResponse::success(req.id, json!({ "acknowledged": true }))
            }
            method::SESSION_UPDATE => {
                // Update namespaces/methods from the params object. The
                // session's `namespaces` field holds CAIP-2 chain ids (per the
                // existing convention), so each namespace's `chains` array is
                // collected; `methods` is the union of all `methods` arrays.
                let namespaces = req.params.get("namespaces").cloned().unwrap_or_else(|| json!({}));
                let mut methods = Vec::new();
                let mut ns: Vec<String> = Vec::new();
                if let Some(obj) = namespaces.as_object() {
                    for value in obj.values() {
                        if let Some(arr) = value.get("chains").and_then(|m| m.as_array()) {
                            ns.extend(arr.iter().filter_map(|v| v.as_str().map(String::from)));
                        }
                        if let Some(arr) = value.get("methods").and_then(|m| m.as_array()) {
                            methods.extend(arr.iter().filter_map(|v| v.as_str().map(String::from)));
                        }
                    }
                }
                if let Some(s) = self.sessions.lock().await.get_mut(topic) {
                    s.namespaces = ns;
                    s.methods = methods;
                }
                JsonRpcResponse::success(req.id, json!({ "acknowledged": true }))
            }
            method::SESSION_PING => {
                JsonRpcResponse::success(req.id, json!({ "acknowledged": true }))
            }
            method::AUTH_REQUEST => {
                // WC v2 Auth protocol: one-time sign-in on a pairing topic.
                // No session namespaces/methods are required; dispatch straight
                // through the handler (the router builds + signs the SIWE
                // message and returns the signature).
                let t = self.sessions.lock().await;
                let session = t.get(topic);
                match self
                    .handler
                    .handle(
                        &req.method,
                        req.params.clone(),
                        topic,
                        session.and_then(|s| s.dapp_name.as_deref()),
                        session.and_then(|s| s.dapp_origin.as_deref()),
                    )
                    .await
                {
                    Ok(v) => JsonRpcResponse::success(req.id, v),
                    Err((code, msg)) => {
                        JsonRpcResponse::error(req.id, JsonRpcError::new(code, msg))
                    }
                }
            }
            _ => {
                let t = self.sessions.lock().await;
                if let Some(s) = t.get(topic) {
                    if s.is_method_allowed(&req.method) {
                        drop(t);
                        match self
                            .handler
                            .handle(
                                &req.method,
                                req.params.clone(),
                                topic,
                                session.dapp_name.as_deref(),
                                session.dapp_origin.as_deref(),
                            )
                            .await
                        {
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
            }
        };
        let _ = session;
        let _ = sym_key;

        let resp_bytes = serde_json::to_vec(&resp)?;
        eprintln!("[wsdbg] SEND-RESP {}", String::from_utf8_lossy(&resp_bytes));
        let envelope = WcCipher::seal_type0(sym_key, &resp_bytes)?;

        *req_id += 1;
        relay
            .publish_irn(
                &relay_id(*req_id),
                topic,
                &BASE64.encode(&envelope),
                300,
                1108,
                attestation_env().as_deref(),
            )
            .await?;
        Ok(())
    }

    /// Handle `wc_sessionPropose` — approve only if dApp origin is trusted.
    ///
    /// Spec-compliant response: approve result carries the wallet's real X25519
    /// responder public key, and the session key is derived via X25519 + HKDF.
    #[allow(clippy::too_many_arguments)]
    async fn handle_session_propose(
        &self,
        relay: &mut RelayClient,
        req: &JsonRpcRequest,
        pairing_topic: &str,
        session: &WcSession,
        req_id: &mut i64,
        pairing_key: &WcSymKey,
    ) -> WcResult<()> {
        let mut next_id = || -> i64 {
            *req_id += 1;
            *req_id - 1
        };
        let propose_params: SessionProposeParams = serde_json::from_value(req.params.clone())
            .map_err(|e| WcError::InvalidMessage(format!("bad sessionPropose params: {e}")))?;

        // Origin allowlist check.
        let dapp_origin = &propose_params.proposer.metadata.url;
        if self.cfg.trusted_origins.is_empty() ||
            !origin_matches_trusted(dapp_origin, &self.cfg.trusted_origins)
        {
            let reason = if self.cfg.trusted_origins.is_empty() {
                "no trusted origins configured; session proposal rejected"
            } else {
                "dApp origin not in trusted origins"
            };
            self.send_encrypted(
                relay,
                pairing_topic,
                pairing_key,
                &JsonRpcResponse::error(
                    req.id,
                    JsonRpcError::new(JsonRpcErrorCode::Unauthorized, reason.into()),
                ),
                &mut next_id,
            )
            .await?;
            return Ok(());
        }

        // Parse the proposer's X25519 public key (hex).
        let proposer_pub_hex = &propose_params.proposer.publicKey;
        let proposer_pub_bytes = hex::decode(proposer_pub_hex)
            .map_err(|e| WcError::InvalidMessage(format!("bad proposer publicKey hex: {e}")))?;
        if proposer_pub_bytes.len() != 32 {
            return Err(WcError::InvalidMessage("proposer publicKey must be 32 bytes".into()));
        }
        let mut proposer_pub = [0u8; 32];
        proposer_pub.copy_from_slice(&proposer_pub_bytes);

        // Generate the wallet (responder) X25519 keypair and derive the session
        // symmetric key: deriveSymKey(wallet_priv, proposer_pub).
        let responder_kp = WcKeyPair::generate();
        let shared = responder_kp.shared_secret(&x25519_dalek::PublicKey::from(proposer_pub));
        let session_key = crypto::derive_sym_key(&shared);
        let responder_pubkey_hex = responder_kp.public_key_hex();

        // The session topic is derived from the proposer's public key (SHA-256),
        // matching the official client.
        let session_topic = crypto::hash_bytes(&proposer_pub);

        let approve_result = serde_json::json!({
            "relay": { "protocol": self.cfg.relay_protocol },
            "responderPublicKey": responder_pubkey_hex,
            "expiry": session.expiry_unix
        });
        let approve_resp = JsonRpcResponse::success(req.id, approve_result);

        self.send_encrypted(relay, pairing_topic, pairing_key, &approve_resp, &mut next_id).await?;

        // Subscribe to the session topic.
        let sub_msg = serde_json::json!({
            "id": relay_id(next_id()),
            "jsonrpc": "2.0",
            "method": "irn_subscribe",
            "params": { "topic": session_topic }
        });
        relay.send_text(serde_json::to_string(&sub_msg)?).await?;

        let new_session = WcSession {
            topic: session_topic.clone(),
            sym_key: session_key.clone().into(),
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

        // Send wc_sessionSettle encrypted with the derived session key,
        // in a type-0 envelope on the session topic.
        let settle = serde_json::to_value(SessionSettleParams {
            relay: crate::method::RelayProtocolOptions {
                protocol: self.cfg.relay_protocol.clone(),
                data: None,
            },
            controller: crate::method::SessionParticipant {
                publicKey: responder_pubkey_hex,
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
            "id": relay_id(next_id()),
            "jsonrpc": "2.0",
            "method": method::SESSION_SETTLE,
            "params": settle
        });
        let settle_bytes = serde_json::to_vec(&settle_req)?;
        let settle_env = WcCipher::seal_type0(&session_key, &settle_bytes)?;

        if std::env::var("OC_SKIP_SETTLE").is_err() {
            relay
                .publish_irn(
                    &relay_id(next_id()),
                    &session_topic,
                    &BASE64.encode(&settle_env),
                    300,
                    1108,
                    attestation_env().as_deref(),
                )
                .await?;
        } else {
            eprintln!("[wsdbg] OC_SKIP_SETTLE set; skipping session settle");
        }

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
        let envelope = WcCipher::seal_type0(sym_key, &resp_bytes)?;
        relay
            .publish_irn(
                &relay_id(next_id()),
                topic,
                &BASE64.encode(&envelope),
                300,
                1108,
                attestation_env().as_deref(),
            )
            .await?;
        Ok(())
    }
}

/// Read the optional Verify-service attestation JWT from the environment.
/// Returns `None` when unset (the common case — attestation is optional).
fn attestation_env() -> Option<String> {
    std::env::var("OC_WC_ATTESTATION").ok().filter(|s| !s.is_empty())
}

// ---------------------------------------------------------------------------
// WcServerHandle — clonable handle for runtime pairing injection
// ---------------------------------------------------------------------------

/// Clonable handle to a running [`WcWalletServer`]'s session table.
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

// ---------------------------------------------------------------------------
// Relay envelope + helpers
// ---------------------------------------------------------------------------

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

/// Generate a relay JSON-RPC `id` matching the official client's recommendation
/// (a 19-digit value: 13-digit epoch milliseconds + 6-digit entropy). The
/// monotonic counter is folded into the low bits for uniqueness.
fn relay_id(counter: i64) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let millis = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64);
    let id = (millis << 20) | ((counter as u64) & 0xFFFFF);
    format!("{id:019}")
}

/// Check if `origin` matches any trusted domain, supporting subdomain matching
/// with dot-boundary check (e.g., "walletconnect.com" matches "app.walletconnect.com"
/// but NOT "evil-walletconnect.com").
fn origin_matches_trusted(origin: &str, trusted_origins: &[String]) -> bool {
    // Extract host from origin URL
    let origin_host = origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"))
        .unwrap_or(origin)
        .split('/')
        .next()
        .unwrap_or("")
        .split(':') // strip port
        .next()
        .unwrap_or("")
        .to_lowercase();

    trusted_origins.iter().any(|trusted| {
        let trusted = trusted.to_lowercase();
        origin_host == trusted || origin_host.ends_with(&format!(".{trusted}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn origins(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn trusted_origin_exact_match() {
        assert!(origin_matches_trusted("https://iam.example.com", &origins(&["iam.example.com"])));
        assert!(origin_matches_trusted("http://iam.example.com", &origins(&["iam.example.com"])));
    }

    #[test]
    fn trusted_origin_subdomain_dot_boundary() {
        let trusted = origins(&["example.com"]);
        assert!(origin_matches_trusted("https://app.example.com", &trusted));
        assert!(origin_matches_trusted("https://a.b.example.com", &trusted));
        // dot-boundary: a suffix without the leading dot must NOT match.
        assert!(!origin_matches_trusted("https://evil-example.com", &trusted));
        assert!(!origin_matches_trusted("https://notexample.com", &trusted));
    }

    #[test]
    fn trusted_origin_strips_scheme_port_and_path() {
        let trusted = origins(&["example.com"]);
        assert!(origin_matches_trusted("https://example.com:8443/app", &trusted));
        assert!(origin_matches_trusted("https://app.example.com/x/y", &trusted));
    }

    #[test]
    fn trusted_origin_case_insensitive() {
        assert!(origin_matches_trusted("https://EXAMPLE.com", &origins(&["example.com"])));
        assert!(origin_matches_trusted("https://example.com", &origins(&["EXAMPLE.COM"])));
    }

    #[test]
    fn empty_trusted_origins_match_nothing() {
        assert!(!origin_matches_trusted("https://example.com", &origins(&[])));
    }

    #[test]
    fn trusted_origin_matches_any_entry() {
        let trusted = origins(&["a.com", "b.org"]);
        assert!(origin_matches_trusted("https://b.org", &trusted));
        assert!(!origin_matches_trusted("https://c.net", &trusted));
    }

    #[test]
    fn raw_host_without_scheme_matches() {
        assert!(origin_matches_trusted("localhost:3000", &origins(&["localhost"])));
        assert!(origin_matches_trusted("127.0.0.1", &origins(&["127.0.0.1"])));
    }
}
