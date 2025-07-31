//! In-process mock WC v2 relay for tests.
//!
//! Implements a publish/subscribe bus by topic. Real WC v2 relay uses Waku v2
//! over WSS — this mock mirrors the API surface without network I/O.

use std::collections::HashMap;

use tokio::sync::{Mutex, broadcast};

/// In-process pub/sub bus keyed by topic.
#[derive(Debug, Default)]
pub struct MockRelay {
    topics: Mutex<HashMap<String, broadcast::Sender<Vec<u8>>>>,
}

impl MockRelay {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn subscribe(&self, topic: &str) -> MockRelaySubscription {
        let mut topics = self.topics.lock().await;
        let tx =
            topics.entry(topic.to_string()).or_insert_with(|| broadcast::channel(256).0).clone();
        MockRelaySubscription { rx: tx.subscribe() }
    }

    pub async fn publish(&self, topic: &str, payload: &[u8]) {
        let tx = {
            let mut topics = self.topics.lock().await;
            topics.entry(topic.to_string()).or_insert_with(|| broadcast::channel(256).0).clone()
        };
        // ignore send error if no subscribers
        let _ = tx.send(payload.to_vec());
    }
}

pub struct MockRelaySubscription {
    rx: broadcast::Receiver<Vec<u8>>,
}

impl MockRelaySubscription {
    pub async fn recv(&mut self) -> Result<Vec<u8>, broadcast::error::RecvError> {
        self.rx.recv().await
    }

    pub fn try_recv(&mut self) -> Result<Vec<u8>, broadcast::error::TryRecvError> {
        self.rx.try_recv()
    }
}
