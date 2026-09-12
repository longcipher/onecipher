// Derivation-style convergence for EVM / SVM / TON / BTC (A6, signer side).
//
// `oc-core` owns the shared [`DerivationStyle`] trait, the four style enums,
// and [`ParseDerivationStyleError`] (whose `Display` already lists legal
// tokens for zero-processing CLI errors). This module is the signer-side
// convergence: one `*_path_with_style` helper per family plus a single
// [`derivation_path_for_style`] dispatcher over `ChainType`.
//
// Non-style chains (Cosmos, Tron, Spark, Filecoin, Sui, XRPL, Nano, NEAR)
// have no style axis and always use their default template.

use oc_core::{
    BitcoinDerivationStyle, ChainType, DerivationStyle, EvmDerivationStyle,
    ParseDerivationStyleError, SolanaDerivationStyle, TonDerivationStyle,
};

/// EVM path for `index` under `style` (`bip44` default).
#[must_use]
pub fn evm_path(index: u32, style: EvmDerivationStyle) -> String {
    style.derivation_path(index)
}

/// Solana (SVM) path for `index` under `style` (`phantom` default).
#[must_use]
pub fn solana_path(index: u32, style: SolanaDerivationStyle) -> String {
    style.derivation_path(index)
}

/// TON path for `index` under `style` (version-independent by design).
#[must_use]
pub fn ton_path(index: u32, style: TonDerivationStyle) -> String {
    style.derivation_path(index)
}

/// Bitcoin path for `index` under `style` (`native-segwit` default).
#[must_use]
pub fn bitcoin_path(index: u32, style: BitcoinDerivationStyle) -> String {
    style.derivation_path(index)
}

/// Unified dispatcher: parse `style_str` for `chain` and render `index`.
///
/// Style chains (EVM, Solana, TON, Bitcoin) parse via their axis; all other
/// chains ignore `style_str` (must be empty) and return their default
/// template with `{index}` substituted.
///
/// # Errors
///
/// Returns [`ParseDerivationStyleError`] for unknown style tokens on style
/// chains, or for non-empty `style_str` on chains without an axis.
pub fn derivation_path_for_style(
    chain: ChainType,
    style_str: &str,
    index: u32,
) -> Result<String, ParseDerivationStyleError> {
    match chain {
        ChainType::Evm => Ok(evm_path(index, style_str.parse()?)),
        ChainType::Solana => Ok(solana_path(index, style_str.parse()?)),
        ChainType::Ton => Ok(ton_path(index, style_str.parse()?)),
        ChainType::Bitcoin => Ok(bitcoin_path(index, style_str.parse()?)),
        _ => {
            if style_str.trim().is_empty() {
                Ok(crate::chains::derivation_template_for_chain(chain)
                    .replace("{index}", &index.to_string()))
            } else {
                Err(ParseDerivationStyleError {
                    chain: "style",
                    input: style_str.trim().to_string(),
                    accepted: &[],
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn style_helpers_match_signer_defaults() {
        use crate::traits::ChainSigner;
        let evm = crate::chains::EvmSigner;
        assert_eq!(evm_path(0, EvmDerivationStyle::Bip44), evm.default_derivation_path(0));
        let sol = crate::chains::SolanaSigner;
        assert_eq!(solana_path(0, SolanaDerivationStyle::Phantom), sol.default_derivation_path(0));
        let btc = crate::chains::BitcoinSigner::mainnet();
        assert_eq!(
            bitcoin_path(0, BitcoinDerivationStyle::NativeSegwit),
            btc.default_derivation_path(0)
        );
        let ton = crate::chains::TonSigner;
        assert_eq!(ton_path(0, TonDerivationStyle::V5R1), ton.default_derivation_path(0));
    }

    #[test]
    fn dispatcher_parses_style_chains() {
        assert_eq!(
            derivation_path_for_style(ChainType::Evm, "bip44", 5).unwrap(),
            "m/44'/60'/0'/0/5"
        );
        assert_eq!(
            derivation_path_for_style(ChainType::Evm, "ledger-live", 5).unwrap(),
            "m/44'/60'/5'/0/0"
        );
        assert_eq!(
            derivation_path_for_style(ChainType::Bitcoin, "taproot", 0).unwrap(),
            "m/86'/0'/0'/0/0"
        );
        assert!(derivation_path_for_style(ChainType::Evm, "nope", 0).is_err());
    }

    #[test]
    fn dispatcher_rejects_style_for_axis_less_chains() {
        let path = derivation_path_for_style(ChainType::Tron, "", 2).unwrap();
        assert_eq!(path, "m/44'/195'/0'/0/2");
        let err = derivation_path_for_style(ChainType::Tron, "bip44", 0).unwrap_err();
        assert_eq!(err.chain, "style");
    }
}
