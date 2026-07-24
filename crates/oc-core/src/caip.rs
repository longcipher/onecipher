pub use tap_caip::{AccountId, AssetId, ChainId};

pub trait ChainIdExt {
    /// Returns `true` if this is an EVM (eip155) chain.
    fn is_evm(&self) -> bool;

    /// Returns the numeric EVM chain id if the namespace is `eip155` and the
    /// reference parses as a `u64`, otherwise `None`.
    ///
    /// This is the type-safe equivalent of `parse_chain_id` — callers no longer
    /// need to manually split the CAIP-2 string and `unwrap_or(1)` on failure.
    fn evm_chain_id(&self) -> Option<u64>;
}

impl ChainIdExt for ChainId {
    fn is_evm(&self) -> bool {
        self.namespace() == "eip155"
    }

    fn evm_chain_id(&self) -> Option<u64> {
        if self.is_evm() { self.reference().parse().ok() } else { None }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_evm_chain_id() {
        let id: ChainId = "eip155:1".parse().unwrap();
        assert_eq!(id.namespace(), "eip155");
        assert_eq!(id.reference(), "1");
    }

    #[test]
    fn test_parse_solana_chain_id() {
        let id: ChainId = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp".parse().unwrap();
        assert_eq!(id.namespace(), "solana");
    }

    #[test]
    fn test_parse_cosmos_chain_id() {
        let id: ChainId = "cosmos:cosmoshub-4".parse().unwrap();
        assert_eq!(id.namespace(), "cosmos");
        assert_eq!(id.reference(), "cosmoshub-4");
    }

    #[test]
    fn test_parse_bitcoin_chain_id() {
        let id: ChainId = "bip122:000000000019d6689c085ae165831e93".parse().unwrap();
        assert_eq!(id.namespace(), "bip122");
    }

    #[test]
    fn test_parse_tron_chain_id() {
        let id: ChainId = "tron:mainnet".parse().unwrap();
        assert_eq!(id.namespace(), "tron");
        assert_eq!(id.reference(), "mainnet");
    }

    #[test]
    fn test_display_roundtrip() {
        let id: ChainId = "eip155:1".parse().unwrap();
        assert_eq!(id.to_string(), "eip155:1");
        let id2: ChainId = id.to_string().parse().unwrap();
        assert_eq!(id, id2);
    }

    #[test]
    fn test_serde_roundtrip() {
        let id: ChainId = "eip155:1".parse().unwrap();
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"eip155:1\"");
        let id2: ChainId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, id2);
    }

    #[test]
    fn test_chain_id_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        let id1: ChainId = "eip155:1".parse().unwrap();
        let id2: ChainId = "eip155:1".parse().unwrap();
        set.insert(id1);
        assert!(set.contains(&id2));
    }

    #[test]
    fn test_is_evm() {
        let evm: ChainId = "eip155:1".parse().unwrap();
        assert!(evm.is_evm());
        let sol: ChainId = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp".parse().unwrap();
        assert!(!sol.is_evm());
    }

    #[test]
    fn test_evm_chain_id_parses_numeric_reference() {
        let mainnet: ChainId = "eip155:1".parse().unwrap();
        assert_eq!(mainnet.evm_chain_id(), Some(1));

        let base: ChainId = "eip155:8453".parse().unwrap();
        assert_eq!(base.evm_chain_id(), Some(8453));

        let arbitrum: ChainId = "eip155:42161".parse().unwrap();
        assert_eq!(arbitrum.evm_chain_id(), Some(42161));
    }

    #[test]
    fn test_evm_chain_id_none_for_non_evm_namespace() {
        let sol: ChainId = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp".parse().unwrap();
        assert_eq!(sol.evm_chain_id(), None);

        let cosmos: ChainId = "cosmos:cosmoshub-4".parse().unwrap();
        assert_eq!(cosmos.evm_chain_id(), None);
    }

    #[test]
    fn test_evm_chain_id_none_for_non_numeric_reference() {
        // tap_caip's CAIP-2 regex still permits some non-numeric references
        // under eip155; evm_chain_id() must return None for those rather than
        // panicking.
        let id: ChainId = "eip155:foo".parse().unwrap();
        assert_eq!(id.evm_chain_id(), None);
    }
}
