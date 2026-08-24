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

use std::{collections::HashMap, future::Future, pin::Pin, sync::Arc};

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::{Mutex, Notify};
use tracing::{debug, warn};

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
    /// Wake signal so the run loop re-checks topic subscriptions immediately
    /// when a pairing/session is injected while `recv()` is blocked (without
    /// this, a newly paired topic is never subscribed and its first message is
    /// never delivered — see the `session_handle` pairing-injection path).
    wakeup: Arc<Notify>,
    #[cfg(any(test, feature = "test-utils"))]
    mock_relay: Option<Arc<MockRelay>>,
}

impl<H: WalletMethodHandler> WcWalletServer<H> {
    pub fn new(cfg: WcWalletConfig, handler: H) -> Self {
        Self {
            cfg,
            handler,
            sessions: Arc::new(Mutex::new(WcSessionTable::new())),
            wakeup: Arc::new(Notify::new()),
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
            wakeup: Arc::new(Notify::new()),
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
        WcServerHandle { sessions: Arc::clone(&self.sessions), wakeup: Arc::clone(&self.wakeup) }
    }

    pub async fn insert_session(&self, session: WcSession) {
        self.sessions.lock().await.insert(session);
        self.wakeup.notify_waiters();
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
        self.wakeup.notify_waiters();
        Ok(())
    }

    /// Process exactly one inbound message on the given topic (mock relay, for tests).
    ///
    /// Accepts both the spec-compliant encrypted envelope (type 0) and a
    /// plaintext JSON-RPC message (legacy mock path). Responses are published
    /// back in the same format that was received.
    #[cfg(any(test, feature = "test-utils"))]
    pub async fn process_one(&self, topic: &str) -> WcResult<()> {
        // Containment mirrors the live-relay run loop (C-04): per-message
        // failures (undecryptable envelope, malformed JSON-RPC) are logged
        // and dropped so a pump survives garbage input; only infrastructure
        // failures propagate to the caller.
        match self.process_one_inner(topic).await {
            Ok(()) => Ok(()),
            Err(e) if is_infrastructure_failure(&e) => Err(e),
            Err(e) => {
                debug!(
                    topic = %topic, category = error_category(&e), error = %e,
                    "contained per-message failure on mock path"
                );
                Ok(())
            }
        }
    }

    #[cfg(any(test, feature = "test-utils"))]
    async fn process_one_inner(&self, topic: &str) -> WcResult<()> {
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
                other => {
                    // Defensive: the `encrypted` guard above only admits
                    // type-0/type-1, but never panic on an unexpected tag.
                    return Err(WcError::Crypto(format!(
                        "unexpected envelope type {other} in encrypted payload"
                    )));
                }
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
                if let Some(rejection) = cross_chain_rejection(s, &req) {
                    warn!(topic = %topic, method = %req.method, "rejecting cross-chain session request");
                    self.publish_response(
                        &relay,
                        topic,
                        &rejection,
                        outbound_encrypted,
                        session_key.as_ref(),
                    )
                    .await?;
                    return Ok(());
                }
                if !s.is_method_allowed(&req.method) {
                    debug!(
                        method = %req.method, topic = %topic, methods = ?s.methods, state = ?s.state,
                        "method not allowed on topic",
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
                // M-05a: the peer may only narrow the negotiated scope. An
                // update proposing chains/methods outside the negotiated sets
                // is rejected so a compromised dApp cannot grant itself
                // arbitrary scopes.
                let (ns, methods) = parse_update_namespaces(&req.params);
                let mut rejected: Option<String> = None;
                {
                    let mut t = self.sessions.lock().await;
                    if let Some(s) = t.get_mut(topic) {
                        if let Err(reason) = validate_update_subset(s, &ns, &methods) {
                            debug!(
                                topic = %topic, reason = %reason,
                                "rejecting wc_sessionUpdate outside negotiated scope",
                            );
                            rejected = Some(reason);
                        } else {
                            s.namespaces = ns;
                            s.methods = methods;
                        }
                    }
                }
                let resp = match rejected {
                    Some(reason) => JsonRpcResponse::error(
                        req.id,
                        JsonRpcError::new(JsonRpcErrorCode::Unauthorized, reason),
                    ),
                    None => JsonRpcResponse::success(req.id, json!({ "acknowledged": true })),
                };
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
                debug!(method = %req.method, code = ?code, msg = %msg, "method handler error");
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

        // Insert the new active session. Accepted namespaces are derived from
        // the proposal's requested chains (M-05b), not hardcoded.
        let accepted_namespaces =
            accepted_chains_from_proposal(&propose_params.required_namespaces);
        let accepted_methods = collect_chains_and_methods(&propose_params.required_namespaces).1;
        let new_session = WcSession {
            topic: session_topic.clone(),
            sym_key: session_key.clone().into(),
            state: WcSessionState::Active,
            expiry_unix: u64::MAX,
            namespaces: accepted_namespaces,
            methods: accepted_methods,
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
    ///
    /// `cancel` is polled cooperatively alongside the relay receive: when it
    /// is set (`Ordering::Relaxed` == `true`) the loop returns
    /// `Ok(())` after a best-effort graceful close of the relay socket (M3
    /// fix — previously the loop could only exit via an error or by being
    /// dropped). Pass `Some(flag)` to enable cooperative cancellation, or
    /// `None` to retain the old error-only-exit behaviour.
    pub async fn run(&mut self, cancel: Option<&std::sync::atomic::AtomicBool>) -> WcResult<()> {
        // Append projectId from the environment if the configured relay URL
        // does not already carry one (required by relay.walletconnect.com).
        let project_id = std::env::var("OC_WC_PROJECT_ID").ok();
        let relay_url = crate::apply_project_id(&self.cfg.relay_url, project_id.as_deref());
        let relay_cfg = RelayConfig { url: relay_url, reconnect_max_ms: 60_000 };

        let mut relay = RelayClient::connect(relay_cfg).await?;
        let mut req_id: i64 = 1;
        // M-06: runtime-only bounded replay-dedup window for inbound envelopes.
        let mut replay_guard = ReplayGuard::new(ReplayGuard::DEFAULT_CAPACITY);

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
                    if s.needs_relay() && !subscribed_topics.contains(&s.topic) {
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

            // Block for the next relay message, but also wake on session-table
            // changes so a freshly injected pairing is subscribed immediately.
            // Without the wakeup, a new pairing topic is only subscribed after
            // some other message arrives, and the first message published on it
            // (e.g. the dApp's `wc_sessionPropose`) is never delivered.
            // A bounded recv timeout (M2) and a cooperative cancel flag (M3)
            // ensure the loop can never hang on a silent relay and can be
            // stopped without dropping the task.
            let recv = tokio::select! {
                () = self.wakeup.notified() => {
                    // Just re-run the subscription check at the top of the loop.
                    continue;
                }
                true = async {
                    cancel.map_or(false, |f| f.load(std::sync::atomic::Ordering::Relaxed))
                } => {
                    // Graceful shutdown requested: close the relay socket and
                    // exit the loop with success.
                    relay.close().await;
                    tracing::info!("WC server run loop cancelled; shutting down");
                    return Ok(());
                }
                m = relay.recv_timeout(std::time::Duration::from_secs(30)) => m,
            };

            let raw = match recv {
                Ok(m) => m,
                Err(WcError::RelayTimeout(_)) => {
                    // No message within the window — re-check cancellation and
                    // subscription state, then loop. This is NOT a reconnect
                    // condition (the socket is still healthy).
                    continue;
                }
                Err(e) => {
                    warn!(error = %e, "relay recv error; reconnecting");
                    relay.reconnect().await?;
                    let topics: Vec<String> = {
                        let t = self.sessions.lock().await;
                        t.iter().filter(|s| s.needs_relay()).map(|s| s.topic.clone()).collect()
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

            // M-06: bounded replay dedup keyed by (topic, envelope nonce).
            // The relay is unauthenticated on publish, so redeliveries and
            // attacker-injected duplicates are dropped before any processing.
            let nonce = envelope_nonce(&encrypted_bytes);
            if replay_guard.is_replay(topic, &nonce, crate::session::now_unix()) {
                debug!(topic = %topic, "dropping replayed inbound envelope");
                continue;
            }

            // C-04: per-message containment. Decryption, parsing, and
            // dispatch failures affect only the offending message — a single
            // garbage publish from the unauthenticated relay must never kill
            // the whole network agent. Only infrastructure failures (relay
            // disconnect, socket I/O) terminate the loop.
            if let Err(e) = self
                .process_inbound_message(&mut relay, topic, &session, &encrypted_bytes, &mut req_id)
                .await
            {
                if is_infrastructure_failure(&e) {
                    return Err(e);
                }
                warn!(
                    topic = %topic,
                    category = error_category(&e),
                    error = %e,
                    "contained per-message failure; WC server loop continuing"
                );
            }
        }
    }

    /// Process exactly one inbound relay message for `topic`.
    ///
    /// Errors returned by this function are PER-MESSAGE failures
    /// (undecryptable envelope, malformed JSON-RPC, rejected update); the run
    /// loop contains them via [`Self::run`]'s containment match. Infrastructure
    /// errors from the relay/socket propagate unchanged.
    async fn process_inbound_message(
        &mut self,
        relay: &mut RelayClient,
        topic: &str,
        session: &WcSession,
        encrypted_bytes: &[u8],
        req_id: &mut i64,
    ) -> WcResult<()> {
        let sym_key = session
            .sym_key
            .to_sym_key()
            .ok_or_else(|| WcError::Crypto("failed to decode session sym_key".into()))?;

        // Propose phase: handle wc_sessionPropose specially (it may be a
        // type-1 envelope carrying the proposer's public key).
        let first_byte = encrypted_bytes.first().copied();
        if first_byte == Some(crypto::ENVELOPE_TYPE_1) ||
            first_byte == Some(crypto::ENVELOPE_TYPE_0)
        {
            let plaintext = match first_byte {
                Some(crypto::ENVELOPE_TYPE_1) => {
                    // Derive the session key from the proposer's public key.
                    let (_proposer_pub, pt) = WcCipher::open_type1(&sym_key, encrypted_bytes)?;
                    pt
                }
                _ => WcCipher::open_type0(&sym_key, encrypted_bytes)?,
            };
            if let Ok(req) = serde_json::from_slice::<JsonRpcRequest>(&plaintext) {
                if req.method == method::SESSION_PROPOSE {
                    return self
                        .handle_session_propose(relay, &req, topic, session, req_id, &sym_key)
                        .await;
                }
            }
            // Non-propose request on a pairing topic — treat as regular.
            let req: JsonRpcRequest = serde_json::from_slice(&plaintext)?;
            return self
                .dispatch_session_request(relay, topic, &req, session, &sym_key, req_id)
                .await;
        }

        // Legacy plaintext JSON-RPC over the relay (no envelope).
        let req: JsonRpcRequest = serde_json::from_slice(encrypted_bytes)?;
        self.dispatch_session_request(relay, topic, &req, session, &sym_key, req_id).await
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
        debug!(
            topic = %topic, method = %req.method, methods = ?session.methods,
            "dispatch session request",
        );
        let resp = match req.method.as_str() {
            method::SESSION_DELETE => {
                // Remove the session from the table and acknowledge.
                self.sessions.lock().await.remove(topic);
                JsonRpcResponse::success(req.id, json!({ "acknowledged": true }))
            }
            method::SESSION_UPDATE => {
                // M-05a: the peer may only narrow the negotiated scope. An
                // update proposing chains/methods outside the negotiated sets
                // is rejected so a compromised dApp cannot grant itself
                // arbitrary scopes.
                let (ns, methods) = parse_update_namespaces(&req.params);
                if let Err(reason) = validate_update_subset(session, &ns, &methods) {
                    warn!(
                        topic = %topic, reason = %reason,
                        "rejecting wc_sessionUpdate outside negotiated scope",
                    );
                    JsonRpcResponse::error(
                        req.id,
                        JsonRpcError::new(JsonRpcErrorCode::Unauthorized, reason),
                    )
                } else {
                    if let Some(s) = self.sessions.lock().await.get_mut(topic) {
                        s.namespaces = ns;
                        s.methods = methods;
                    }
                    JsonRpcResponse::success(req.id, json!({ "acknowledged": true }))
                }
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
                    // M-05c: enforce the negotiated chain scope. Requests
                    // carrying a `chainId` (WC v2 wire convention:
                    // top-level in wc_sessionRequest params) must stay within
                    // the session's approved namespaces; requests without one
                    // fall back to the topic-level (session-level) gates.
                    if let Some(rejection) = cross_chain_rejection(s, req) {
                        drop(t);
                        warn!(
                            topic = %topic, method = %req.method,
                            "rejecting cross-chain session request",
                        );
                        rejection
                    } else if s.is_method_allowed(&req.method) {
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

        let resp_bytes = serde_json::to_vec(&resp)?;
        debug!(resp_len = resp_bytes.len(), "sending session response");
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

        // Accepted namespaces are derived from the proposal's requested
        // chains (M-05b), not hardcoded to eip155:1.
        let accepted_namespaces =
            accepted_chains_from_proposal(&propose_params.required_namespaces);
        let accepted_methods = collect_chains_and_methods(&propose_params.required_namespaces).1;
        let new_session = WcSession {
            topic: session_topic.clone(),
            sym_key: session_key.clone().into(),
            state: WcSessionState::Active,
            expiry_unix: session.expiry_unix,
            namespaces: accepted_namespaces,
            methods: accepted_methods,
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
            debug!("OC_SKIP_SETTLE set; skipping session settle");
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
// Per-message containment helpers (C-04)
// ---------------------------------------------------------------------------

/// Coarse error category for containment logs (never logs payloads).
fn error_category(err: &WcError) -> &'static str {
    match err {
        WcError::InvalidUri(_) | WcError::InvalidMessage(_) => "invalid_message",
        WcError::Crypto(_) => "crypto",
        WcError::Json(_) => "json",
        WcError::JsonRpc { .. } => "json_rpc",
        WcError::SessionNotFound(_) | WcError::SessionExpired(_) => "session_state",
        WcError::MethodNotAuthorized(_) | WcError::PairingRejected => "unauthorized",
        WcError::Relay(_) | WcError::RelayTimeout(_) => "relay",
        WcError::Io(_) => "io",
        WcError::WebSocket(_) => "websocket",
    }
}

/// Whether an error must terminate the run loop (infrastructure failure:
/// relay disconnect, socket I/O) rather than just drop one inbound message.
///
/// [`WcError::RelayTimeout`] is deliberately NOT infrastructure: a receive
/// timeout means the socket is still healthy and must never kill the loop.
fn is_infrastructure_failure(err: &WcError) -> bool {
    matches!(err, WcError::Relay(_) | WcError::WebSocket(_) | WcError::Io(_))
}

// ---------------------------------------------------------------------------
// Replay dedup (M-06)
// ---------------------------------------------------------------------------

/// Extract the per-message nonce bytes used as the replay-dedup key.
///
/// Envelope layouts (see `crate::crypto`):
/// - type-0: `[0x00 ‖ iv(12) ‖ ciphertext ‖ tag]`
/// - type-1: `[0x01 ‖ senderPubKey(32) ‖ iv(12) ‖ ciphertext]`
///
/// Anything else (legacy plaintext JSON-RPC, truncated envelopes) falls back
/// to the full payload as the key material.
fn envelope_nonce(envelope: &[u8]) -> Vec<u8> {
    let iv_range = match envelope.first().copied() {
        Some(crypto::ENVELOPE_TYPE_0) => Some(1..1 + crypto::IV_LENGTH),
        Some(crypto::ENVELOPE_TYPE_1) => {
            Some((1 + crypto::KEY_LENGTH)..(1 + crypto::KEY_LENGTH + crypto::IV_LENGTH))
        }
        _ => None,
    };
    match iv_range.and_then(|r| envelope.get(r)) {
        Some(iv) => iv.to_vec(),
        None => envelope.to_vec(),
    }
}

/// Runtime-only bounded replay-dedup set for inbound relay envelopes.
///
/// Keys are `(topic, envelope nonce)` pairs; values are the Unix time of
/// first sight. Entries older than [`ReplayGuard::RETENTION_SECS`] are swept
/// on insert, so a message redelivered after the retention window is accepted
/// again. The window matches the 300-second TTL this wallet uses for its own
/// outbound publishes; relay-level per-envelope TTL fields (not present in
/// the current wire structs) are approximated by this fixed window.
struct ReplayGuard {
    seen: HashMap<(String, Vec<u8>), u64>,
    capacity: usize,
}

impl ReplayGuard {
    /// Default bound on tracked envelopes (>= 1024 required by design).
    const DEFAULT_CAPACITY: usize = 4096;
    /// Retention window for dedup entries, in seconds.
    const RETENTION_SECS: u64 = 300;

    fn new(capacity: usize) -> Self {
        Self { seen: HashMap::new(), capacity: capacity.max(1) }
    }

    /// Returns `true` when `(topic, nonce)` was already seen inside the
    /// retention window (a replay — caller must drop the message). First
    /// sightings are recorded and return `false`.
    ///
    /// Under a fail-closed clock (`now == u64::MAX`) entries simply never age
    /// out until the clock recovers; capacity still bounds memory.
    fn is_replay(&mut self, topic: &str, nonce: &[u8], now: u64) -> bool {
        self.seen.retain(|_, first_seen| now.saturating_sub(*first_seen) < Self::RETENTION_SECS);
        let key = (topic.to_string(), nonce.to_vec());
        if let Some(first_seen) = self.seen.get(&key) {
            if now.saturating_sub(*first_seen) < Self::RETENTION_SECS {
                return true;
            }
        }
        if self.seen.len() >= self.capacity {
            self.evict_oldest();
        }
        self.seen.insert(key, now);
        false
    }

    /// Evict least-recently-seen entries until below capacity.
    fn evict_oldest(&mut self) {
        while self.seen.len() >= self.capacity {
            let oldest = self.seen.iter().min_by_key(|(_, ts)| **ts).map(|(k, _)| k.clone());
            match oldest {
                Some(k) => {
                    self.seen.remove(&k);
                }
                None => break,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Namespace / scope helpers (M-05)
// ---------------------------------------------------------------------------

/// Union the `chains` and `methods` arrays across a WC namespaces object
/// (`requiredNamespaces` in proposals, `namespaces` in updates).
fn collect_chains_and_methods(namespaces: &Value) -> (Vec<String>, Vec<String>) {
    let mut chains = Vec::new();
    let mut methods = Vec::new();
    if let Some(obj) = namespaces.as_object() {
        for value in obj.values() {
            if let Some(arr) = value.get("chains").and_then(|m| m.as_array()) {
                chains.extend(arr.iter().filter_map(|v| v.as_str().map(String::from)));
            }
            if let Some(arr) = value.get("methods").and_then(|m| m.as_array()) {
                methods.extend(arr.iter().filter_map(|v| v.as_str().map(String::from)));
            }
        }
    }
    (chains, methods)
}

/// Parse the `namespaces` object of a `wc_sessionUpdate` params value into
/// `(chains, methods)` unions (existing wire convention).
fn parse_update_namespaces(params: &Value) -> (Vec<String>, Vec<String>) {
    match params.get("namespaces") {
        Some(ns) => collect_chains_and_methods(ns),
        None => (Vec::new(), Vec::new()),
    }
}

/// Derive the wallet-accepted CAIP-2 chain list from a proposal's
/// `requiredNamespaces` object (M-05b).
///
/// Each namespace's explicit `chains` array contributes verbatim; a namespace
/// entry without a `chains` array contributes the family wildcard `<ns>:*`.
/// There is no wallet-supported-chain registry in this crate, so proposal
/// chains are accepted verbatim (per-request risk stays gated by the policy
/// engine above this layer).
fn accepted_chains_from_proposal(required_namespaces: &Value) -> Vec<String> {
    let mut chains = Vec::new();
    if let Some(obj) = required_namespaces.as_object() {
        for (ns, value) in obj {
            match value.get("chains").and_then(|c| c.as_array()) {
                Some(arr) => {
                    chains.extend(arr.iter().filter_map(|v| v.as_str().map(String::from)));
                }
                None => chains.push(format!("{ns}:*")),
            }
        }
    }
    chains
}

/// Validate that a proposed `wc_sessionUpdate` only ever narrows the
/// negotiated session scope (M-05a): both the proposed chains and methods
/// must be subsets of the session's current sets. Returns a human-readable
/// reason on the first violation.
fn validate_update_subset(
    session: &WcSession,
    proposed_ns: &[String],
    proposed_methods: &[String],
) -> Result<(), String> {
    for ns in proposed_ns {
        if !session.namespaces.iter().any(|a| a == ns) {
            return Err(format!("chain {ns} was not negotiated for this session"));
        }
    }
    for method in proposed_methods {
        if !session.methods.iter().any(|a| a == method) {
            return Err(format!("method {method} was not negotiated for this session"));
        }
    }
    Ok(())
}

/// Extract the CAIP-2 chain id from request params (WC v2 wire convention:
/// top-level `chainId`, e.g. in `wc_sessionRequest`).
fn request_chain_id(params: &Value) -> Option<&str> {
    params.get("chainId").and_then(Value::as_str)
}

/// Build the Unauthorized response when `req` carries a `chainId` outside the
/// session's negotiated namespaces (M-05c). `None` means allowed — either the
/// chain is covered or no chainId is present (the topic-level gates apply).
fn cross_chain_rejection(session: &WcSession, req: &JsonRpcRequest) -> Option<JsonRpcResponse> {
    let chain = request_chain_id(&req.params)?;
    if session.is_chain_allowed(chain) {
        return None;
    }
    Some(JsonRpcResponse::error(
        req.id,
        JsonRpcError::new(
            JsonRpcErrorCode::Unauthorized,
            format!("chain {chain} not authorized for this session"),
        ),
    ))
}

// ---------------------------------------------------------------------------
// WcServerHandle — clonable handle for runtime pairing injection
// ---------------------------------------------------------------------------

/// Clonable handle to a running [`WcWalletServer`]'s session table.
#[derive(Clone)]
pub struct WcServerHandle {
    sessions: Arc<Mutex<WcSessionTable>>,
    wakeup: Arc<Notify>,
}

impl WcServerHandle {
    /// Insert a pre-built session into the table.
    pub async fn insert_session(&self, session: WcSession) {
        self.sessions.lock().await.insert(session);
        self.wakeup.notify_waiters();
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
        self.wakeup.notify_waiters();
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

    #[test]
    fn infrastructure_errors_are_classified_for_containment() {
        assert!(is_infrastructure_failure(&WcError::Relay("disconnect".into())));
        assert!(is_infrastructure_failure(&WcError::WebSocket("closed".into())));
        assert!(is_infrastructure_failure(&WcError::Io(std::io::Error::other("disk"))));
        // Per-message failures must never terminate the loop.
        assert!(!is_infrastructure_failure(&WcError::Crypto("bad tag".into())));
        assert!(!is_infrastructure_failure(&WcError::Json(
            serde_json::from_str::<Value>("not json").unwrap_err()
        )));
        assert!(!is_infrastructure_failure(&WcError::InvalidMessage("junk".into())));
        assert_eq!(error_category(&WcError::Crypto("x".into())), "crypto");
        assert_eq!(error_category(&WcError::InvalidMessage("x".into())), "invalid_message");
    }

    #[test]
    fn envelope_nonce_extracts_iv_per_envelope_type() {
        let key = WcSymKey::from_random();
        let env0 = WcCipher::seal_type0(&key, b"hello").unwrap();
        assert_eq!(envelope_nonce(&env0), env0[1..=crypto::IV_LENGTH].to_vec());
        let sender = [7u8; 32];
        let env1 = WcCipher::seal_type1(&key, &sender, b"hello").unwrap();
        assert_eq!(
            envelope_nonce(&env1),
            env1[1 + crypto::KEY_LENGTH..1 + crypto::KEY_LENGTH + crypto::IV_LENGTH].to_vec()
        );
        // Legacy plaintext falls back to the whole payload.
        assert_eq!(envelope_nonce(b"not-an-envelope"), b"not-an-envelope".to_vec());
        // Truncated envelopes fall back safely instead of panicking.
        assert_eq!(
            envelope_nonce(&[crypto::ENVELOPE_TYPE_0, 1, 2]),
            vec![crypto::ENVELOPE_TYPE_0, 1, 2]
        );
    }

    #[test]
    fn replay_guard_dedups_identical_nonce_within_window() {
        let mut g = ReplayGuard::new(1024);
        assert!(!g.is_replay("t", b"n1", 1_000));
        assert!(g.is_replay("t", b"n1", 1_100));
        assert!(!g.is_replay("t", b"n2", 1_100));
        // Same nonce on a different topic is NOT a replay.
        assert!(!g.is_replay("other", b"n1", 1_100));
    }

    #[test]
    fn replay_guard_accepts_redelivery_after_retention_window() {
        let mut g = ReplayGuard::new(1024);
        assert!(!g.is_replay("t", b"n1", 0));
        assert!(g.is_replay("t", b"n1", ReplayGuard::RETENTION_SECS - 1));
        assert!(!g.is_replay("t", b"n1", ReplayGuard::RETENTION_SECS));
    }

    #[test]
    fn replay_guard_stays_bounded_at_capacity() {
        let mut g = ReplayGuard::new(64);
        for i in 0..256u32 {
            assert!(!g.is_replay("t", &i.to_le_bytes(), 1_000));
        }
        assert!(g.seen.len() <= g.capacity);
    }

    #[test]
    fn accepted_chains_derived_from_proposal() {
        let explicit = json!({ "eip155": { "chains": ["eip155:1", "eip155:137"], "methods": [] } });
        assert_eq!(
            accepted_chains_from_proposal(&explicit),
            vec!["eip155:1".to_string(), "eip155:137".to_string()]
        );
        // Namespace without an explicit chains array gets the family wildcard.
        let implicit = json!({
            "eip155": { "methods": ["personal_sign"] },
            "solana": { "chains": ["solana:mainnet"] }
        });
        assert_eq!(
            accepted_chains_from_proposal(&implicit),
            vec!["eip155:*".to_string(), "solana:mainnet".to_string()]
        );
        assert_eq!(accepted_chains_from_proposal(&json!({})).len(), 0);
    }

    #[test]
    fn session_update_must_be_subset_of_negotiated_scope() {
        let mut s = WcSession::new_pairing("t".into(), "ab".repeat(32), u64::MAX);
        s.settle("t".into(), vec!["eip155:1".into()], vec!["personal_sign".into()]);
        // Identical scope is fine; narrowing is fine.
        assert!(
            validate_update_subset(&s, &["eip155:1".into()], &["personal_sign".into()]).is_ok()
        );
        assert!(validate_update_subset(&s, &[], &[]).is_ok());
        // Adding a chain is rejected.
        let err =
            validate_update_subset(&s, &["eip155:1".into(), "eip155:137".into()], &[]).unwrap_err();
        assert!(err.contains("eip155:137"), "reason mentions the offending chain: {err}");
        // Adding a method is rejected.
        let err = validate_update_subset(&s, &[], &["eth_sign".into()]).unwrap_err();
        assert!(err.contains("eth_sign"), "reason mentions the offending method: {err}");
    }

    #[test]
    fn cross_chain_requests_are_detected_via_chain_id_param() {
        let mut s = WcSession::new_pairing("t".into(), "ab".repeat(32), u64::MAX);
        s.settle("t".into(), vec!["eip155:1".into()], vec!["personal_sign".into()]);
        let ok_req = JsonRpcRequest::new("personal_sign", json!({ "chainId": "eip155:1" }), 1);
        assert!(cross_chain_rejection(&s, &ok_req).is_none());
        let bad_req = JsonRpcRequest::new("personal_sign", json!({ "chainId": "eip155:42" }), 2);
        let rejection = cross_chain_rejection(&s, &bad_req).expect("cross-chain must be rejected");
        assert_eq!(rejection.error.expect("error set").code, JsonRpcErrorCode::Unauthorized as i64);
        // No chainId → falls back to the topic-level gate (no rejection here).
        let no_chain = JsonRpcRequest::new("personal_sign", json!({}), 3);
        assert!(cross_chain_rejection(&s, &no_chain).is_none());
        // Wildcard-negotiated families admit any chain id in the family.
        let mut w = WcSession::new_pairing("w".into(), "cd".repeat(32), u64::MAX);
        w.settle("w".into(), vec!["eip155:*".into()], vec!["personal_sign".into()]);
        assert!(cross_chain_rejection(&w, &bad_req).is_none());
    }
}
