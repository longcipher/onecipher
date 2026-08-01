//! Pairing URI generation + Passkey confirmation gate.

use oc_walletconnect::{PairingUri, WcSession, WcSessionState, WcSymKeyHex};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PairingError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("passkey rejected")]
    Rejected,
}

/// Generate a fresh pairing URI with a random 32-byte topic and symKey.
///
/// The returned `WcSession` is in `Propose` state. The caller must:
/// 1. Prompt the local user for Passkey confirmation.
/// 2. On confirmation, transition to `Settle` and insert into the `WcWalletServer`'s session table.
pub fn generate_pairing_uri(ttl_secs: u64) -> (PairingUri, WcSession) {
    let topic = hex::encode(rand::random::<[u8; 32]>());

    let sym_key = hex::encode(rand::random::<[u8; 32]>());

    let uri = PairingUri::new(topic.clone(), sym_key.clone());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let session = WcSession {
        topic,
        sym_key: WcSymKeyHex::new(sym_key),
        state: WcSessionState::Propose,
        expiry_unix: now + ttl_secs,
        namespaces: Vec::new(),
        methods: Vec::new(),
        dapp_origin: None,
        dapp_name: None,
        created_at_unix: now,
    };
    (uri, session)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_returns_propose_state_session() {
        let (_uri, session) = generate_pairing_uri(3600);
        assert_eq!(session.state, WcSessionState::Propose);
    }

    #[test]
    fn generate_topic_is_64_hex_chars() {
        let (_uri, session) = generate_pairing_uri(3600);
        assert_eq!(session.topic.len(), 64);
        assert!(session.topic.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn generate_sym_key_is_64_hex_chars() {
        let (_uri, session) = generate_pairing_uri(3600);
        // 32 bytes → 64 hex chars (no 0x prefix)
        assert_eq!(session.sym_key.as_str().len(), 64);
        assert!(session.sym_key.as_str().chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn generate_expiry_matches_ttl() {
        let ttl = 7200u64;
        let before =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let (_uri, session) = generate_pairing_uri(ttl);
        let after =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        assert!(session.expiry_unix >= before + ttl);
        assert!(session.expiry_unix <= after + ttl);
    }

    #[test]
    fn generate_uri_topic_matches_session_topic() {
        let (uri, session) = generate_pairing_uri(3600);
        assert_eq!(uri.topic, session.topic);
    }

    #[test]
    fn generate_unique_topics() {
        let (_, s1) = generate_pairing_uri(3600);
        let (_, s2) = generate_pairing_uri(3600);
        assert_ne!(s1.topic, s2.topic);
    }
}
