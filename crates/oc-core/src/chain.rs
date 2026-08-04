// `parse_chain` surfaces a deprecation warning directly to CLI users via
// `eprintln!` (matching the OWS upstream behavior). Core lib normally uses
// `tracing`, but this user-facing diagnostic predates the tracing adoption
// and is intentionally synchronous.
#![expect(clippy::print_stderr, reason = "CLI-facing deprecation warning")]

use std::{
    collections::HashSet,
    fmt,
    str::FromStr,
    sync::{Mutex, OnceLock},
};

use serde::{Deserialize, Serialize};

use crate::caip::ChainId;

/// Interner backing the `&'static str` fields of dynamically-parsed [`Chain`]s.
///
/// `Chain` stores `&'static str` and is `Copy`, so a chain ID that is not in
/// [`KNOWN_CHAINS`] has to be given a `'static` lifetime somehow. This used to
/// be a bare `Box::leak` per call, which is an *unbounded* leak: `parse_chain`
/// is reachable from untrusted input (WalletConnect session proposals, x402
/// payment requirements), so a peer could grow the heap without limit by
/// sending an endless stream of distinct chain IDs.
///
/// Interning bounds the leak to the number of *distinct* chain IDs ever seen
/// rather than the number of *calls*, and caps that set at
/// [`MAX_INTERNED_CHAIN_IDS`]. Repeated parses of the same ID now allocate
/// nothing.
static CHAIN_ID_INTERNER: OnceLock<Mutex<HashSet<&'static str>>> = OnceLock::new();

/// Upper bound on distinct interned chain IDs.
///
/// Sized well above any plausible legitimate workload (the CAIP-2 registry is
/// in the low hundreds). Past this point `intern_chain_id` refuses to allocate
/// and the caller reports the chain as unknown, so a hostile peer cannot use
/// chain-ID churn as a memory-exhaustion vector.
const MAX_INTERNED_CHAIN_IDS: usize = 1024;

/// Intern `s`, returning a `'static` handle to a single shared allocation.
///
/// Returns `None` once [`MAX_INTERNED_CHAIN_IDS`] distinct IDs are held, or if
/// the interner lock was poisoned.
fn intern_chain_id(s: &str) -> Option<&'static str> {
    intern_chain_id_capped(s, MAX_INTERNED_CHAIN_IDS)
}

/// [`intern_chain_id`] with an explicit cap, so the bound can be exercised in
/// tests without exhausting the process-wide interner that other tests share.
fn intern_chain_id_capped(s: &str, cap: usize) -> Option<&'static str> {
    let interner = CHAIN_ID_INTERNER.get_or_init(|| Mutex::new(HashSet::new()));
    let mut set = interner.lock().ok()?;
    if let Some(existing) = set.get(s) {
        return Some(existing);
    }
    if set.len() >= cap {
        return None;
    }
    // Only reached the first time a given ID is observed, so total leaked
    // bytes are bounded by MAX_INTERNED_CHAIN_IDS * len(id).
    let leaked: &'static str = Box::leak(s.to_owned().into_boxed_str());
    set.insert(leaked);
    Some(leaked)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChainType {
    Evm,
    Solana,
    Cosmos,
    Bitcoin,
    Tron,
    Ton,
    Spark,
    Filecoin,
    Sui,
    Xrpl,
    Nano,
    Near,
}

/// All supported chain families, used for universal wallet derivation.
pub const ALL_CHAIN_TYPES: [ChainType; 12] = [
    ChainType::Evm,
    ChainType::Solana,
    ChainType::Bitcoin,
    ChainType::Cosmos,
    ChainType::Tron,
    ChainType::Ton,
    ChainType::Spark,
    ChainType::Filecoin,
    ChainType::Sui,
    ChainType::Xrpl,
    ChainType::Nano,
    ChainType::Near,
];

/// A specific chain (e.g. "ethereum", "arbitrum") with its family type and CAIP-2 ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Chain {
    pub name: &'static str,
    pub chain_type: ChainType,
    pub chain_id: &'static str,
}

impl Chain {
    /// Return the EIP-155 reference portion of this chain's CAIP-2 ID.
    pub fn evm_chain_reference(&self) -> Result<&str, String> {
        if self.chain_type != ChainType::Evm {
            return Err(format!("chain '{}' is not an EVM chain", self.chain_id));
        }

        let chain_id = self.chain_id.parse::<ChainId>().map_err(|e| e.to_string())?;
        if chain_id.namespace() != "eip155" {
            return Err(format!("EVM chain '{}' is missing an eip155 reference", self.chain_id));
        }

        self.chain_id
            .split_once(':')
            .map(|(_, reference)| reference)
            .ok_or_else(|| format!("invalid CAIP-2 chain ID: '{}'", self.chain_id))
    }

    /// Return the numeric EIP-155 chain ID for an EVM chain.
    pub fn evm_chain_id_u64(&self) -> Result<u64, String> {
        self.evm_chain_reference()?
            .parse()
            .map_err(|_| format!("cannot extract numeric chain ID from: {}", self.chain_id))
    }
}

/// Known chains registry.
pub const KNOWN_CHAINS: &[Chain] = &[
    Chain { name: "ethereum", chain_type: ChainType::Evm, chain_id: "eip155:1" },
    Chain { name: "polygon", chain_type: ChainType::Evm, chain_id: "eip155:137" },
    Chain { name: "arbitrum", chain_type: ChainType::Evm, chain_id: "eip155:42161" },
    Chain { name: "optimism", chain_type: ChainType::Evm, chain_id: "eip155:10" },
    Chain { name: "base", chain_type: ChainType::Evm, chain_id: "eip155:8453" },
    Chain { name: "plasma", chain_type: ChainType::Evm, chain_id: "eip155:9745" },
    Chain { name: "bsc", chain_type: ChainType::Evm, chain_id: "eip155:56" },
    Chain { name: "avalanche", chain_type: ChainType::Evm, chain_id: "eip155:43114" },
    Chain { name: "etherlink", chain_type: ChainType::Evm, chain_id: "eip155:42793" },
    Chain {
        name: "solana",
        chain_type: ChainType::Solana,
        chain_id: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
    },
    Chain {
        name: "bitcoin",
        chain_type: ChainType::Bitcoin,
        chain_id: "bip122:000000000019d6689c085ae165831e93",
    },
    Chain { name: "cosmos", chain_type: ChainType::Cosmos, chain_id: "cosmos:cosmoshub-4" },
    Chain { name: "tron", chain_type: ChainType::Tron, chain_id: "tron:mainnet" },
    Chain { name: "ton", chain_type: ChainType::Ton, chain_id: "ton:mainnet" },
    Chain { name: "spark", chain_type: ChainType::Spark, chain_id: "spark:mainnet" },
    Chain { name: "filecoin", chain_type: ChainType::Filecoin, chain_id: "fil:mainnet" },
    Chain { name: "sui", chain_type: ChainType::Sui, chain_id: "sui:mainnet" },
    Chain { name: "xrpl", chain_type: ChainType::Xrpl, chain_id: "xrpl:mainnet" },
    Chain { name: "xrpl-testnet", chain_type: ChainType::Xrpl, chain_id: "xrpl:testnet" },
    Chain { name: "xrpl-devnet", chain_type: ChainType::Xrpl, chain_id: "xrpl:devnet" },
    Chain { name: "nano", chain_type: ChainType::Nano, chain_id: "nano:mainnet" },
    Chain { name: "near", chain_type: ChainType::Near, chain_id: "near:mainnet" },
    Chain { name: "near-testnet", chain_type: ChainType::Near, chain_id: "near:testnet" },
    Chain { name: "tempo", chain_type: ChainType::Evm, chain_id: "eip155:4217" },
    Chain { name: "hyperliquid", chain_type: ChainType::Evm, chain_id: "eip155:999" },
];

/// Parse a chain string into a `Chain`. Accepts:
/// - Friendly names: "ethereum", "base", "arbitrum", "solana", etc.
/// - CAIP-2 chain IDs: "eip155:1", "eip155:8453", etc.
/// - Bare numeric EVM chain IDs: "8453" → eip155:8453
/// - Legacy "evm" (deprecated, warns on stderr, resolves to ethereum)
pub fn parse_chain(s: &str) -> Result<Chain, String> {
    let lower = s.to_lowercase();

    // Legacy "evm" — deprecated, warn and resolve
    if lower == "evm" {
        eprintln!(
            "warning: '--chain evm' is deprecated; use '--chain ethereum' \
             or a specific chain name (base, arbitrum, polygon, ...)"
        );
        return Ok(*KNOWN_CHAINS.iter().find(|c| c.name == "ethereum").unwrap());
    }

    // Try friendly name match
    if let Some(chain) = KNOWN_CHAINS.iter().find(|c| c.name == lower) {
        return Ok(*chain);
    }

    // Try CAIP-2 chain ID match
    if let Some(chain) = KNOWN_CHAINS.iter().find(|c| c.chain_id == s) {
        return Ok(*chain);
    }

    // Bare numeric → treat as EVM chain ID (eip155:<n>)
    if !lower.is_empty() && lower.chars().all(|c| c.is_ascii_digit()) {
        let caip2 = format!("eip155:{}", lower);
        if let Some(chain) = KNOWN_CHAINS.iter().find(|c| c.chain_id == caip2) {
            return Ok(*chain);
        }
        if let Some(interned) = intern_chain_id(&caip2) {
            return Ok(Chain { name: interned, chain_type: ChainType::Evm, chain_id: interned });
        }
        return Err(format!(
            "too many distinct chain IDs seen (limit {MAX_INTERNED_CHAIN_IDS}); \
             refusing to intern '{caip2}'"
        ));
    }

    // Try namespace match for unknown CAIP-2 IDs (e.g. eip155:4217, eip155:84532).
    // Uses the same signer as the namespace's default chain. The chain_id string is
    // interned (not leaked per-call) to satisfy the 'static lifetime — `parse_chain`
    // is reachable from untrusted input, so the allocation must be bounded.
    if let Some((namespace, _reference)) = s.split_once(':') &&
        let Some(ct) = ChainType::from_namespace(namespace)
    {
        if let Some(interned) = intern_chain_id(s) {
            return Ok(Chain { name: interned, chain_type: ct, chain_id: interned });
        }
        return Err(format!(
            "too many distinct chain IDs seen (limit {MAX_INTERNED_CHAIN_IDS}); \
             refusing to intern '{s}'"
        ));
    }

    Err(format!(
        "unknown chain: '{s}'\n\n\
         Supported chains:\n  \
           EVM:     ethereum, base, arbitrum, optimism, polygon, bsc, avalanche, plasma, etherlink\n  \
           Solana:  solana\n  \
           Bitcoin: bitcoin\n  \
           Other:   cosmos, tron, ton, sui, filecoin, spark, xrpl, nano, near\n\n\
         Or use a CAIP-2 ID (eip155:8453) or bare EVM chain ID (8453)"
    ))
}

/// Returns the default `Chain` for a given `ChainType` (first match in registry).
pub fn default_chain_for_type(ct: ChainType) -> Chain {
    *KNOWN_CHAINS.iter().find(|c| c.chain_type == ct).unwrap()
}

impl ChainType {
    /// Returns the CAIP-2 namespace for this chain type.
    pub const fn namespace(&self) -> &'static str {
        match self {
            Self::Evm => "eip155",
            Self::Solana => "solana",
            Self::Cosmos => "cosmos",
            Self::Bitcoin => "bip122",
            Self::Tron => "tron",
            Self::Ton => "ton",
            Self::Spark => "spark",
            Self::Filecoin => "fil",
            Self::Sui => "sui",
            Self::Xrpl => "xrpl",
            Self::Nano => "nano",
            Self::Near => "near",
        }
    }

    /// Returns the BIP-44 coin type for this chain type.
    pub const fn default_coin_type(&self) -> u32 {
        match self {
            Self::Evm => 60,
            Self::Solana => 501,
            Self::Cosmos => 118,
            Self::Bitcoin => 0,
            Self::Tron => 195,
            Self::Ton => 607,
            Self::Spark => 8797555,
            Self::Filecoin => 461,
            Self::Sui => 784,
            Self::Xrpl => 144,
            Self::Nano => 165,
            Self::Near => 397,
        }
    }

    /// Returns the ChainType for a given CAIP-2 namespace.
    pub fn from_namespace(ns: &str) -> Option<Self> {
        match ns {
            "eip155" => Some(Self::Evm),
            "solana" => Some(Self::Solana),
            "cosmos" => Some(Self::Cosmos),
            "bip122" => Some(Self::Bitcoin),
            "tron" => Some(Self::Tron),
            "ton" => Some(Self::Ton),
            "spark" => Some(Self::Spark),
            "fil" => Some(Self::Filecoin),
            "sui" => Some(Self::Sui),
            "xrpl" => Some(Self::Xrpl),
            "nano" => Some(Self::Nano),
            "near" => Some(Self::Near),
            _ => None,
        }
    }
}

impl fmt::Display for ChainType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Evm => "evm",
            Self::Solana => "solana",
            Self::Cosmos => "cosmos",
            Self::Bitcoin => "bitcoin",
            Self::Tron => "tron",
            Self::Ton => "ton",
            Self::Spark => "spark",
            Self::Filecoin => "filecoin",
            Self::Sui => "sui",
            Self::Xrpl => "xrpl",
            Self::Nano => "nano",
            Self::Near => "near",
        };
        write!(f, "{}", s)
    }
}

impl FromStr for ChainType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "evm" => Ok(Self::Evm),
            "solana" => Ok(Self::Solana),
            "cosmos" => Ok(Self::Cosmos),
            "bitcoin" => Ok(Self::Bitcoin),
            "tron" => Ok(Self::Tron),
            "ton" => Ok(Self::Ton),
            "spark" => Ok(Self::Spark),
            "filecoin" => Ok(Self::Filecoin),
            "sui" => Ok(Self::Sui),
            "xrpl" => Ok(Self::Xrpl),
            "nano" => Ok(Self::Nano),
            "near" => Ok(Self::Near),
            _ => Err(format!("unknown chain type: {}", s)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serde_roundtrip() {
        let chain = ChainType::Evm;
        let json = serde_json::to_string(&chain).unwrap();
        assert_eq!(json, "\"evm\"");
        let chain2: ChainType = serde_json::from_str(&json).unwrap();
        assert_eq!(chain, chain2);
    }

    #[test]
    fn test_serde_all_variants() {
        for (chain, expected) in [
            (ChainType::Evm, "\"evm\""),
            (ChainType::Solana, "\"solana\""),
            (ChainType::Cosmos, "\"cosmos\""),
            (ChainType::Bitcoin, "\"bitcoin\""),
            (ChainType::Tron, "\"tron\""),
            (ChainType::Ton, "\"ton\""),
            (ChainType::Spark, "\"spark\""),
            (ChainType::Filecoin, "\"filecoin\""),
            (ChainType::Sui, "\"sui\""),
            (ChainType::Xrpl, "\"xrpl\""),
            (ChainType::Nano, "\"nano\""),
            (ChainType::Near, "\"near\""),
        ] {
            let json = serde_json::to_string(&chain).unwrap();
            assert_eq!(json, expected);
            let deserialized: ChainType = serde_json::from_str(&json).unwrap();
            assert_eq!(chain, deserialized);
        }
    }

    #[test]
    fn test_namespace_mapping() {
        assert_eq!(ChainType::Evm.namespace(), "eip155");
        assert_eq!(ChainType::Solana.namespace(), "solana");
        assert_eq!(ChainType::Cosmos.namespace(), "cosmos");
        assert_eq!(ChainType::Bitcoin.namespace(), "bip122");
        assert_eq!(ChainType::Tron.namespace(), "tron");
        assert_eq!(ChainType::Ton.namespace(), "ton");
        assert_eq!(ChainType::Spark.namespace(), "spark");
        assert_eq!(ChainType::Filecoin.namespace(), "fil");
        assert_eq!(ChainType::Sui.namespace(), "sui");
        assert_eq!(ChainType::Xrpl.namespace(), "xrpl");
        assert_eq!(ChainType::Nano.namespace(), "nano");
        assert_eq!(ChainType::Near.namespace(), "near");
    }

    #[test]
    fn test_coin_type_mapping() {
        assert_eq!(ChainType::Evm.default_coin_type(), 60);
        assert_eq!(ChainType::Solana.default_coin_type(), 501);
        assert_eq!(ChainType::Cosmos.default_coin_type(), 118);
        assert_eq!(ChainType::Bitcoin.default_coin_type(), 0);
        assert_eq!(ChainType::Tron.default_coin_type(), 195);
        assert_eq!(ChainType::Ton.default_coin_type(), 607);
        assert_eq!(ChainType::Spark.default_coin_type(), 8797555);
        assert_eq!(ChainType::Filecoin.default_coin_type(), 461);
        assert_eq!(ChainType::Sui.default_coin_type(), 784);
        assert_eq!(ChainType::Xrpl.default_coin_type(), 144);
        assert_eq!(ChainType::Nano.default_coin_type(), 165);
        assert_eq!(ChainType::Near.default_coin_type(), 397);
    }

    #[test]
    fn test_from_namespace() {
        assert_eq!(ChainType::from_namespace("eip155"), Some(ChainType::Evm));
        assert_eq!(ChainType::from_namespace("solana"), Some(ChainType::Solana));
        assert_eq!(ChainType::from_namespace("cosmos"), Some(ChainType::Cosmos));
        assert_eq!(ChainType::from_namespace("bip122"), Some(ChainType::Bitcoin));
        assert_eq!(ChainType::from_namespace("tron"), Some(ChainType::Tron));
        assert_eq!(ChainType::from_namespace("ton"), Some(ChainType::Ton));
        assert_eq!(ChainType::from_namespace("spark"), Some(ChainType::Spark));
        assert_eq!(ChainType::from_namespace("fil"), Some(ChainType::Filecoin));
        assert_eq!(ChainType::from_namespace("sui"), Some(ChainType::Sui));
        assert_eq!(ChainType::from_namespace("xrpl"), Some(ChainType::Xrpl));
        assert_eq!(ChainType::from_namespace("nano"), Some(ChainType::Nano));
        assert_eq!(ChainType::from_namespace("near"), Some(ChainType::Near));
        assert_eq!(ChainType::from_namespace("unknown"), None);
    }

    #[test]
    fn test_from_str() {
        assert_eq!("evm".parse::<ChainType>().unwrap(), ChainType::Evm);
        assert_eq!("Solana".parse::<ChainType>().unwrap(), ChainType::Solana);
        assert!("unknown".parse::<ChainType>().is_err());
    }

    #[test]
    fn test_display() {
        assert_eq!(ChainType::Evm.to_string(), "evm");
        assert_eq!(ChainType::Bitcoin.to_string(), "bitcoin");
    }

    #[test]
    fn test_parse_chain_friendly_name() {
        let chain = parse_chain("ethereum").unwrap();
        assert_eq!(chain.name, "ethereum");
        assert_eq!(chain.chain_type, ChainType::Evm);
        assert_eq!(chain.chain_id, "eip155:1");
    }

    #[test]
    fn test_parse_chain_plasma_alias() {
        let chain = parse_chain("plasma").unwrap();
        assert_eq!(chain.name, "plasma");
        assert_eq!(chain.chain_type, ChainType::Evm);
        assert_eq!(chain.chain_id, "eip155:9745");
    }

    #[test]
    fn test_parse_chain_etherlink_alias() {
        let chain = parse_chain("etherlink").unwrap();
        assert_eq!(chain.name, "etherlink");
        assert_eq!(chain.chain_type, ChainType::Evm);
        assert_eq!(chain.chain_id, "eip155:42793");
    }

    #[test]
    fn test_parse_chain_caip2() {
        let chain = parse_chain("eip155:42161").unwrap();
        assert_eq!(chain.name, "arbitrum");
        assert_eq!(chain.chain_type, ChainType::Evm);
    }

    #[test]
    fn test_parse_chain_plasma_caip2() {
        let chain = parse_chain("eip155:9745").unwrap();
        assert_eq!(chain.name, "plasma");
        assert_eq!(chain.chain_type, ChainType::Evm);
        assert_eq!(chain.chain_id, "eip155:9745");
    }

    #[test]
    fn test_parse_chain_unknown_evm_caip2() {
        let chain = parse_chain("eip155:9746").unwrap();
        assert_eq!(chain.name, "eip155:9746");
        assert_eq!(chain.chain_type, ChainType::Evm);
        assert_eq!(chain.chain_id, "eip155:9746");
    }

    #[test]
    fn test_evm_chain_reference_for_known_chain() {
        let chain = parse_chain("base").unwrap();
        assert_eq!(chain.evm_chain_reference().unwrap(), "8453");
        assert_eq!(chain.evm_chain_id_u64().unwrap(), 8453);
    }

    #[test]
    fn test_evm_chain_reference_for_unknown_caip2_chain() {
        let chain = parse_chain("eip155:999999").unwrap();
        assert_eq!(chain.evm_chain_reference().unwrap(), "999999");
        assert_eq!(chain.evm_chain_id_u64().unwrap(), 999999);
    }

    #[test]
    fn test_evm_chain_reference_rejects_non_evm_chain() {
        let chain = parse_chain("solana").unwrap();
        let err = chain.evm_chain_reference().unwrap_err();
        assert!(err.contains("not an EVM chain"));
    }

    #[test]
    fn test_parse_chain_legacy_evm() {
        let chain = parse_chain("evm").unwrap();
        assert_eq!(chain.name, "ethereum");
        assert_eq!(chain.chain_type, ChainType::Evm);
    }

    #[test]
    fn test_parse_chain_solana() {
        let chain = parse_chain("solana").unwrap();
        assert_eq!(chain.chain_type, ChainType::Solana);
    }

    #[test]
    fn test_parse_chain_xrpl() {
        let chain = parse_chain("xrpl").unwrap();
        assert_eq!(chain.chain_type, ChainType::Xrpl);
        assert_eq!(chain.chain_id, "xrpl:mainnet");

        let testnet = parse_chain("xrpl-testnet").unwrap();
        assert_eq!(testnet.chain_type, ChainType::Xrpl);
        assert_eq!(testnet.chain_id, "xrpl:testnet");

        let devnet = parse_chain("xrpl-devnet").unwrap();
        assert_eq!(devnet.chain_type, ChainType::Xrpl);
        assert_eq!(devnet.chain_id, "xrpl:devnet");

        // CAIP-2 IDs also accepted directly
        let via_caip2 = parse_chain("xrpl:testnet").unwrap();
        assert_eq!(via_caip2.chain_type, ChainType::Xrpl);
        assert_eq!(via_caip2.chain_id, "xrpl:testnet");
    }

    #[test]
    fn test_parse_chain_bare_numeric_known() {
        // "8453" → Base (eip155:8453)
        let chain = parse_chain("8453").unwrap();
        assert_eq!(chain.name, "base");
        assert_eq!(chain.chain_type, ChainType::Evm);
        assert_eq!(chain.chain_id, "eip155:8453");
    }

    #[test]
    fn test_parse_chain_bare_numeric_mainnet() {
        let chain = parse_chain("1").unwrap();
        assert_eq!(chain.name, "ethereum");
        assert_eq!(chain.chain_id, "eip155:1");
    }

    #[test]
    fn test_parse_chain_bare_numeric_unknown() {
        // Unknown EVM chain ID still resolves
        let chain = parse_chain("99999").unwrap();
        assert_eq!(chain.chain_type, ChainType::Evm);
        assert_eq!(chain.chain_id, "eip155:99999");
    }

    #[test]
    fn test_parse_chain_unknown() {
        assert!(parse_chain("unknown_chain").is_err());
    }

    #[test]
    fn test_parse_chain_tempo_alias() {
        let chain = parse_chain("tempo").unwrap();
        assert_eq!(chain.name, "tempo");
        assert_eq!(chain.chain_type, ChainType::Evm);
        assert_eq!(chain.chain_id, "eip155:4217");
    }

    #[test]
    fn test_parse_chain_tempo_caip2() {
        let chain = parse_chain("eip155:4217").unwrap();
        assert_eq!(chain.name, "tempo");
        assert_eq!(chain.chain_type, ChainType::Evm);
        assert_eq!(chain.chain_id, "eip155:4217");
    }

    #[test]
    fn test_parse_chain_hyperliquid_alias() {
        let chain = parse_chain("hyperliquid").unwrap();
        assert_eq!(chain.name, "hyperliquid");
        assert_eq!(chain.chain_type, ChainType::Evm);
        assert_eq!(chain.chain_id, "eip155:999");
    }

    #[test]
    fn test_parse_chain_hyperliquid_caip2() {
        let chain = parse_chain("eip155:999").unwrap();
        assert_eq!(chain.name, "hyperliquid");
        assert_eq!(chain.chain_type, ChainType::Evm);
        assert_eq!(chain.chain_id, "eip155:999");
    }

    #[test]
    fn test_all_chain_types() {
        assert_eq!(ALL_CHAIN_TYPES.len(), 12);
    }

    #[test]
    fn test_parse_chain_near() {
        let chain = parse_chain("near").unwrap();
        assert_eq!(chain.name, "near");
        assert_eq!(chain.chain_type, ChainType::Near);
        assert_eq!(chain.chain_id, "near:mainnet");

        let testnet = parse_chain("near-testnet").unwrap();
        assert_eq!(testnet.chain_type, ChainType::Near);
        assert_eq!(testnet.chain_id, "near:testnet");

        // CAIP-2 IDs accepted directly
        let via_caip2 = parse_chain("near:testnet").unwrap();
        assert_eq!(via_caip2.chain_type, ChainType::Near);
        assert_eq!(via_caip2.chain_id, "near:testnet");
    }

    #[test]
    fn test_default_chain_for_type() {
        let chain = default_chain_for_type(ChainType::Evm);
        assert_eq!(chain.name, "ethereum");
        assert_eq!(chain.chain_id, "eip155:1");
    }

    /// Regression: `parse_chain` used to `Box::leak` on every call for an
    /// unknown chain ID. Because it is reachable from untrusted input, parsing
    /// the same ID repeatedly must reuse one allocation rather than leaking
    /// per call. Pointer equality is the observable proof of interning.
    #[test]
    fn unknown_chain_id_is_interned_not_leaked_per_call() {
        let first = parse_chain("eip155:1337").unwrap();
        let second = parse_chain("eip155:1337").unwrap();
        assert!(
            std::ptr::eq(first.chain_id.as_ptr(), second.chain_id.as_ptr()),
            "repeated parses must share one interned allocation"
        );

        // Bare-numeric form resolves to the same interned CAIP-2 string.
        let bare = parse_chain("1337").unwrap();
        assert_eq!(bare.chain_id, "eip155:1337");
        assert!(std::ptr::eq(bare.chain_id.as_ptr(), first.chain_id.as_ptr()));
    }

    /// Known chains must never touch the interner — they already have
    /// `'static` data in `KNOWN_CHAINS`.
    #[test]
    fn known_chain_ids_are_not_interned() {
        let a = parse_chain("ethereum").unwrap();
        let b = parse_chain("eip155:1").unwrap();
        assert!(std::ptr::eq(a.chain_id.as_ptr(), b.chain_id.as_ptr()));
        assert_eq!(a.chain_id, "eip155:1");
    }

    /// The interner must refuse to grow without bound, so chain-ID churn from
    /// a hostile peer cannot exhaust memory.
    ///
    /// Uses an explicit cap of 0 rather than driving the real
    /// `MAX_INTERNED_CHAIN_IDS`: the interner is process-wide, so exhausting it
    /// here would make unrelated tests fail depending on execution order.
    #[test]
    fn interner_is_bounded() {
        // An already-interned ID is still returned once the cap is reached —
        // the bound applies to *new* allocations only.
        let known = intern_chain_id("eip155:4242").expect("first intern succeeds");
        assert!(std::ptr::eq(
            intern_chain_id_capped("eip155:4242", 0).expect("hit is served past cap").as_ptr(),
            known.as_ptr()
        ));

        // A previously unseen ID is refused rather than allocated.
        assert!(
            intern_chain_id_capped("eip155:989898", 0).is_none(),
            "interner must reject new IDs once the cap is reached"
        );
    }
}
