pub use tap_caip::{AccountId, AssetId, ChainId};

pub trait ChainIdExt {
    fn is_evm(&self) -> bool;
}

impl ChainIdExt for ChainId {
    fn is_evm(&self) -> bool {
        self.namespace() == "eip155"
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
}
