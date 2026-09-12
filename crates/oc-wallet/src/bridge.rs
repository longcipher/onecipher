//! Trait boundaries for wallet/swap/intent integration (C13).
//!
//! These traits fence the hot Intent path: implementations exchange only
//! opaque `serde_json::Value` payloads and identifiers. Private key bytes
//! never cross these boundaries — signing stays behind [`SwapSigner`], which
//! receives a digest and returns a signature without exposing key material.

use serde_json::Value;

/// Read-only wallet view for Intent pre-flight (balances, metadata).
pub trait WalletBridge: Send + Sync {
    /// Opaque wallet descriptor (address, chain, labels — never keys).
    fn describe(&self, wallet_id: &str) -> Result<Value, String>;
    /// Opaque balance snapshot.
    fn balance(&self, wallet_id: &str, asset: &str) -> Result<Value, String>;
}

/// Swap quote/execution backend (no key access).
pub trait SwapBackend: Send + Sync {
    /// Build an opaque unsigned swap payload.
    fn quote(&self, request: &Value) -> Result<Value, String>;
    /// Submit an opaque signed payload, returning an opaque receipt.
    fn submit(&self, signed: &Value) -> Result<Value, String>;
}

/// Signing boundary: digest in, signature out. Keys never leave the impl.
pub trait SwapSigner: Send + Sync {
    /// Sign a 32-byte digest for `wallet_id`, returning the opaque signature.
    fn sign_digest(&self, wallet_id: &str, digest: &[u8; 32]) -> Result<Value, String>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockBridge;
    impl WalletBridge for MockBridge {
        fn describe(&self, id: &str) -> Result<Value, String> {
            Ok(serde_json::json!({"wallet": id}))
        }
        fn balance(&self, id: &str, asset: &str) -> Result<Value, String> {
            Ok(serde_json::json!({"wallet": id, "asset": asset, "balance": "0"}))
        }
    }

    struct MockBackend;
    impl SwapBackend for MockBackend {
        fn quote(&self, req: &Value) -> Result<Value, String> {
            Ok(serde_json::json!({"quote_for": req}))
        }
        fn submit(&self, signed: &Value) -> Result<Value, String> {
            Ok(serde_json::json!({"receipt_for": signed}))
        }
    }

    struct MockSigner;
    impl SwapSigner for MockSigner {
        fn sign_digest(&self, _wallet: &str, digest: &[u8; 32]) -> Result<Value, String> {
            Ok(serde_json::json!({"sig": hex::encode(digest)}))
        }
    }

    #[test]
    fn opaque_value_passthrough_holds_no_keys() {
        let b = MockBridge;
        let desc = b.describe("w1").unwrap();
        assert_eq!(desc["wallet"], "w1");
        // Opaque payloads must not contain key material field names.
        let s = serde_json::to_string(&desc).unwrap();
        assert!(!s.contains("private"));
        assert!(!s.contains("mnemonic"));
        let s = MockSigner;
        let sig = s.sign_digest("w1", &[7u8; 32]).unwrap();
        assert!(sig.get("sig").is_some());
    }

    #[test]
    fn backend_quote_submit_round_trip() {
        let be = MockBackend;
        let q = be.quote(&serde_json::json!({"in":"ETH"})).unwrap();
        let r = be.submit(&q).unwrap();
        assert!(r.get("receipt_for").is_some());
    }
}
