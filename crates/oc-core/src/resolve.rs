// Three-level chain resolution with `ResolvedChain::{Known, Dynamic}` (C2).
//
// Levels, in order:
// 1. Alias: friendly name (`ethereum`, `solana`, `xrpl-testnet`, ...), legacy `evm` (warns), or
//    bare numeric EVM id (`8453`).
// 2. Known CAIP-2: exact `chain_id` match in `KNOWN_CHAINS`.
// 3. Dynamic namespace synthesis: any `<namespace>:<reference>` whose namespace maps to a
//    `ChainType` (e.g. `eip155:999999`) is synthesized via the bounded interner in `chain.rs`.
//
// `ResolvedChain::Known` wraps a registry entry; `ResolvedChain::Dynamic`
// wraps a synthesized `Chain` whose `name`/`chain_id` are interned. Both
// deref to [`crate::Chain`] so existing code keeps working, while new code
// can branch on provenance (e.g. warn on dynamic chains, pin known chains
// in policies).
//
// This module has no extra dependencies (R56-safe).

use std::{fmt, ops::Deref};

use crate::chain::{Chain, parse_chain};

/// A resolved chain with provenance.
///
/// - `Known`: the input matched a registry entry (alias or CAIP-2).
/// - `Dynamic`: the input was synthesized from a known namespace (`<namespace>:<reference>`) and is
///   not in the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolvedChain {
    /// Registry hit (alias, legacy alias, bare numeric known, CAIP-2 known).
    Known(Chain),
    /// Namespace-synthesized chain (unknown reference, known namespace).
    Dynamic(Chain),
}

impl ResolvedChain {
    /// Borrow the underlying [`Chain`].
    #[must_use]
    pub const fn chain(&self) -> Chain {
        match self {
            Self::Known(c) | Self::Dynamic(c) => *c,
        }
    }

    /// True for namespace-synthesized chains.
    #[must_use]
    pub const fn is_dynamic(&self) -> bool {
        matches!(self, Self::Dynamic(_))
    }

    /// True for registry hits.
    #[must_use]
    pub const fn is_known(&self) -> bool {
        matches!(self, Self::Known(_))
    }
}

impl Deref for ResolvedChain {
    type Target = Chain;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Known(c) | Self::Dynamic(c) => c,
        }
    }
}

impl AsRef<Chain> for ResolvedChain {
    fn as_ref(&self) -> &Chain {
        match self {
            Self::Known(c) | Self::Dynamic(c) => c,
        }
    }
}

impl From<ResolvedChain> for Chain {
    fn from(r: ResolvedChain) -> Self {
        r.chain()
    }
}

impl fmt::Display for ResolvedChain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let c = self.chain();
        write!(f, "{} ({})", c.name, c.chain_id)
    }
}

/// Resolve `input` through the three levels above.
///
/// Returns `Known` for registry hits and `Dynamic` for synthesized
/// namespace chains. Errors mirror [`parse_chain`] (unknown chain with the
/// supported-chains help text).
///
/// # Errors
///
/// Returns the same `String` error as [`parse_chain`] when no level matches.
pub fn resolve_chain(input: &str) -> Result<ResolvedChain, String> {
    let chain = parse_chain(input)?;
    // Provenance rule: a resolved chain is `Known` iff its `chain_id` is in
    // the registry. `parse_chain` returns registry entries by value (static
    // pointers) and synthesized chains via the interner, so an exact
    // `chain_id` membership test separates the two without reimplementing
    // the three levels here.
    let known = crate::chain::KNOWN_CHAINS.iter().any(|k| k.chain_id == chain.chain_id);
    if known { Ok(ResolvedChain::Known(chain)) } else { Ok(ResolvedChain::Dynamic(chain)) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level1_alias_resolves_to_known() {
        let r = resolve_chain("ethereum").unwrap();
        assert!(r.is_known());
        assert_eq!(r.chain().chain_id, "eip155:1");
    }

    #[test]
    fn level1_legacy_evm_resolves_to_known() {
        let r = resolve_chain("evm").unwrap();
        assert!(r.is_known());
        assert_eq!(r.chain().name, "ethereum");
    }

    #[test]
    fn level1_bare_numeric_known_is_known() {
        let r = resolve_chain("8453").unwrap();
        assert!(r.is_known());
        assert_eq!(r.chain().chain_id, "eip155:8453");
    }

    #[test]
    fn level2_caip2_known_is_known() {
        let r = resolve_chain("eip155:42161").unwrap();
        assert!(r.is_known());
        assert_eq!(r.chain().name, "arbitrum");
    }

    #[test]
    fn level3_unknown_evm_reference_is_dynamic() {
        let r = resolve_chain("eip155:999999").unwrap();
        assert!(r.is_dynamic());
        assert_eq!(r.chain().chain_id, "eip155:999999");
    }

    #[test]
    fn level3_bare_numeric_unknown_is_dynamic() {
        let r = resolve_chain("99999").unwrap();
        assert!(r.is_dynamic());
        assert_eq!(r.chain().chain_id, "eip155:99999");
    }

    #[test]
    fn level3_unknown_solana_reference_is_dynamic() {
        let r = resolve_chain("solana:99999999999999999999999999999999").unwrap();
        assert!(r.is_dynamic());
    }

    #[test]
    fn unknown_chain_errors() {
        assert!(resolve_chain("not-a-chain").is_err());
    }

    #[test]
    fn deref_and_display_cover_both_variants() {
        let known = resolve_chain("base").unwrap();
        assert_eq!(known.name, "base");
        assert!(known.to_string().contains("eip155:8453"));
        let dynamic = resolve_chain("eip155:31337").unwrap();
        assert_eq!(dynamic.chain_type, known.chain_type);
        assert!(dynamic.to_string().contains("eip155:31337"));
        let back: Chain = dynamic.into();
        assert_eq!(back.chain_id, "eip155:31337");
    }
}
