//! WC v2 session state machine + topic-indexed table.
//!
//! Lifecycle: Propose → Settle (Active) → Expired | Closed
//! Each session has: topic, symKey, expiry, approved CAIP-2 namespaces,
//! approved JSON-RPC methods, and optional dApp origin metadata.

use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

use crate::error::{WcError, WcResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WcSessionState {
    Propose,
    Active,
    Expired,
    Closed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WcSession {
    pub topic: String,
    pub sym_key: String,
    pub state: WcSessionState,
    pub expiry_unix: u64,
    pub namespaces: Vec<String>,
    pub methods: Vec<String>,
    pub dapp_origin: Option<String>,
    pub dapp_name: Option<String>,
    pub created_at_unix: u64,
}

impl WcSession {
    pub fn new_pairing(topic: String, sym_key: String, expiry_unix: u64) -> Self {
        Self {
            topic,
            sym_key,
            state: WcSessionState::Propose,
            expiry_unix,
            namespaces: Vec::new(),
            methods: Vec::new(),
            dapp_origin: None,
            dapp_name: None,
            created_at_unix: now_unix(),
        }
    }

    pub fn settle(&mut self, topic: String, namespaces: Vec<String>, methods: Vec<String>) {
        self.topic = topic;
        self.namespaces = namespaces;
        self.methods = methods;
        self.state = WcSessionState::Active;
    }

    pub fn expire(&mut self) {
        self.state = WcSessionState::Expired;
    }

    pub fn close(&mut self) {
        self.state = WcSessionState::Closed;
    }

    pub fn is_active(&self) -> bool {
        self.state == WcSessionState::Active && now_unix() < self.expiry_unix
    }

    pub fn is_method_allowed(&self, method: &str) -> bool {
        self.methods.iter().any(|m| m == method)
    }

    pub fn is_chain_allowed(&self, caip2: &str) -> bool {
        self.namespaces.iter().any(|n| n == caip2)
    }

    pub fn ensure_active(&self) -> WcResult<()> {
        if !self.is_active() {
            return Err(WcError::SessionExpired(self.topic.clone()));
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct WcSessionTable {
    sessions: HashMap<String, WcSession>,
}

impl WcSessionTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, session: WcSession) {
        self.sessions.insert(session.topic.clone(), session);
    }

    pub fn get(&self, topic: &str) -> Option<&WcSession> {
        self.sessions.get(topic)
    }

    pub fn get_mut(&mut self, topic: &str) -> Option<&mut WcSession> {
        self.sessions.get_mut(topic)
    }

    pub fn remove(&mut self, topic: &str) -> Option<WcSession> {
        self.sessions.remove(topic)
    }

    pub fn iter(&self) -> impl Iterator<Item = &WcSession> {
        self.sessions.values()
    }

    pub fn purge_expired(&mut self) {
        let now = now_unix();
        self.sessions.retain(|_, s| s.expiry_unix > now);
    }
}

pub fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}
