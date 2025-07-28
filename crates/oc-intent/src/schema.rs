use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// An AI Agent's payment/signing intent, expressed declaratively.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Intent {
    pub id: Uuid,
    pub kind: IntentKind,
    pub chain_id: String,
    pub session_key_id: String,
    pub created_at: u64,
    pub expires_at: u64,
}

impl Intent {
    /// Create a new intent with a random ID and 5-minute expiry.
    pub fn new(kind: IntentKind, chain_id: String, session_key_id: String) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        Self {
            id: Uuid::new_v4(),
            kind,
            chain_id,
            session_key_id,
            created_at: now,
            expires_at: now + 300, // 5 minutes
        }
    }

    /// Check if the intent has expired.
    pub fn is_expired(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        now > self.expires_at
    }
}

/// The kind of action an intent represents.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum IntentKind {
    Pay {
        amount: String,
        recipient: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        token: Option<String>,
    },
    SignTransaction {
        tx_hex: String,
        chain_id: String,
    },
    SignMessage {
        message: String,
        encoding: MessageEncoding,
    },
    CrossChainTransfer {
        amount: String,
        asset: String,
        from_chain: String,
        to_chain: String,
        recipient: String,
    },
}

/// Message encoding format.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MessageEncoding {
    #[serde(rename = "utf8")]
    Utf8,
    #[serde(rename = "hex")]
    Hex,
}

/// Status of an intent execution.
///
/// Lifecycle: `Pending` → `Simulated` → `Approved` (user confirms) →
/// `Submitted` (tx broadcast) → `Confirmed` (on-chain receipt) or
/// `Failed` / `Expired`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum IntentStatus {
    Pending,
    Simulated,
    Approved,
    Submitted,
    Confirmed,
    Failed,
    Expired,
}

/// Result of simulating an intent before execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentSummary {
    pub intent_id: Uuid,
    pub human_readable: String,
    pub gas_estimate_usd: f64,
    pub total_cost_usd: f64,
    pub warnings: Vec<String>,
    pub simulation_tx_hash: Option<String>,
}

/// Execution result after confirmation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentResult {
    pub intent_id: Uuid,
    pub status: IntentStatus,
    pub tx_hash: Option<String>,
    pub receipt: Option<serde_json::Value>,
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intent_new_sets_5min_expiry() {
        let intent = Intent::new(
            IntentKind::Pay {
                amount: "10.5 USDC".to_string(),
                recipient: "0xabc123".to_string(),
                token: None,
            },
            "eip155:8453".to_string(),
            "sk-test".to_string(),
        );
        assert!(intent.expires_at > intent.created_at);
        assert_eq!(intent.expires_at - intent.created_at, 300);
        assert!(!intent.is_expired());
    }

    #[test]
    fn intent_is_expired_when_past() {
        let mut intent = Intent::new(
            IntentKind::Pay {
                amount: "1 USDC".to_string(),
                recipient: "0xabc".to_string(),
                token: None,
            },
            "eip155:1".to_string(),
            "sk-test".to_string(),
        );
        intent.expires_at = intent.created_at - 1;
        assert!(intent.is_expired());
    }

    #[test]
    fn intent_kind_pay_serializes_with_tag() {
        let kind = IntentKind::Pay {
            amount: "10.5 USDC".to_string(),
            recipient: "0xabc".to_string(),
            token: None,
        };
        let json = serde_json::to_string(&kind).expect("serialize");
        assert!(json.contains("\"type\":\"Pay\""));
        assert!(json.contains("\"amount\":\"10.5 USDC\""));
        assert!(!json.contains("token")); // skip_serializing_if
    }

    #[test]
    fn intent_kind_pay_with_token_serializes_token() {
        let kind = IntentKind::Pay {
            amount: "1 USDC".to_string(),
            recipient: "0xabc".to_string(),
            token: Some("eip155:8453/erc20:0x8335".to_string()),
        };
        let json = serde_json::to_string(&kind).expect("serialize");
        assert!(json.contains("\"token\""));
    }

    #[test]
    fn message_encoding_serde_roundtrip() {
        for enc in [MessageEncoding::Utf8, MessageEncoding::Hex] {
            let json = serde_json::to_string(&enc).expect("serialize");
            let back: MessageEncoding = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(enc, back);
        }
    }

    #[test]
    fn message_encoding_renames() {
        assert_eq!(serde_json::to_string(&MessageEncoding::Utf8).unwrap(), "\"utf8\"");
        assert_eq!(serde_json::to_string(&MessageEncoding::Hex).unwrap(), "\"hex\"");
    }

    #[test]
    fn intent_full_roundtrip() {
        let intent = Intent::new(
            IntentKind::SignMessage {
                message: "hello".to_string(),
                encoding: MessageEncoding::Utf8,
            },
            "eip155:1".to_string(),
            "sk-1".to_string(),
        );
        let json = serde_json::to_string(&intent).expect("serialize");
        let back: Intent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(intent.id, back.id);
        assert_eq!(intent.chain_id, back.chain_id);
        assert_eq!(intent.session_key_id, back.session_key_id);
    }

    #[test]
    fn intent_status_serde_roundtrip() {
        for status in [
            IntentStatus::Pending,
            IntentStatus::Simulated,
            IntentStatus::Approved,
            IntentStatus::Submitted,
            IntentStatus::Confirmed,
            IntentStatus::Failed,
            IntentStatus::Expired,
        ] {
            let json = serde_json::to_string(&status).expect("serialize");
            let back: IntentStatus = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(status, back);
        }
    }

    #[test]
    fn cross_chain_transfer_serializes() {
        let kind = IntentKind::CrossChainTransfer {
            amount: "100 USDC".to_string(),
            asset: "eip155:8453/erc20:0x8335".to_string(),
            from_chain: "eip155:8453".to_string(),
            to_chain: "eip155:42161".to_string(),
            recipient: "0xdef".to_string(),
        };
        let json = serde_json::to_string(&kind).expect("serialize");
        assert!(json.contains("\"type\":\"CrossChainTransfer\""));
        assert!(json.contains("\"from_chain\""));
        assert!(json.contains("\"to_chain\""));
    }
}
