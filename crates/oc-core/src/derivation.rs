// Unified derivation-style axis for Phase2 signer convergence (A6).
//
// Four chain families expose a style axis (different BIP-44 layouts or
// wallet versions that share one key). Each axis is a small `Copy` enum
// implementing the shared [`DerivationStyle`] trait so callers parse,
// list, and render paths uniformly:
//
// | Chain  | Style enum                | Canonical tokens                                        |
// |--------|-----------------------------|---------------------------------------------------------|
// | EVM    | [`EvmDerivationStyle`]      | `bip44`, `ledger-live`                                  |
// | Solana | [`SolanaDerivationStyle`]   | `phantom`, `bip44`                                      |
// | TON    | [`TonDerivationStyle`]      | `v5r1`, `v4r2`                                          |
// | BTC    | [`BitcoinDerivationStyle`]  | `native-segwit`, `nested-segwit`, `taproot`, `legacy`   |
//
// The parse error [`ParseDerivationStyleError`] carries `{chain, input,
// accepted}` and its `Display` already lists the legal tokens, so the CLI
// prints it verbatim with zero post-processing.
//
// This module has no dependencies beyond `core`/`alloc` plus `ChainType`
// for documentation; it never pulls `tokio` (R56-safe).

use std::{fmt, str::FromStr};

/// Parse failure for a derivation style.
///
/// `chain` names the family (`evm`, `solana`, `ton`, `bitcoin`), `input`
/// echoes the rejected token, and `accepted` lists the canonical legal
/// tokens. `Display` renders all three so CLI layers need no formatting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseDerivationStyleError {
    /// Chain family the style was parsed for (e.g. `"evm"`).
    pub chain: &'static str,
    /// Rejected input token (trimmed original).
    pub input: String,
    /// Canonical legal tokens for this chain.
    pub accepted: &'static [&'static str],
}

impl fmt::Display for ParseDerivationStyleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "unknown derivation style '{}' for chain '{}'; accepted: {}",
            self.input,
            self.chain,
            self.accepted.join(", ")
        )
    }
}

impl std::error::Error for ParseDerivationStyleError {}

/// Shared behavior for per-chain derivation styles.
///
/// Implementors are small `Copy` enums; `FromStr` accepts canonical tokens
/// plus documented aliases (case-insensitive, trimmed). `accepted()` must
/// return the same slice carried by the parse error so the error message
/// and the programmatic list cannot drift.
pub trait DerivationStyle:
    Sized + Clone + Copy + PartialEq + Eq + fmt::Display + FromStr<Err = ParseDerivationStyleError>
{
    /// Canonical legal tokens (must match the parse-error `accepted`).
    fn accepted() -> &'static [&'static str];
    /// Path template with a `{index}` placeholder.
    fn derivation_template(&self) -> &'static str;
    /// Render the template for `index`.
    fn derivation_path(&self, index: u32) -> String {
        self.derivation_template().replace("{index}", &index.to_string())
    }
}

/// Normalize a raw style token: trim and lowercase.
fn normalize(input: &str) -> String {
    input.trim().to_lowercase()
}

// ---------------------------------------------------------------------------
// EVM
// ---------------------------------------------------------------------------

/// EVM derivation styles.
///
/// - `Bip44` (default): `m/44'/60'/0'/0/{index}` (MetaMask / standard).
/// - `LedgerLive` (Ledger Live legacy): `m/44'/60'/{index}'/0/0`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EvmDerivationStyle {
    /// Standard BIP-44 (`m/44'/60'/0'/0/{index}`).
    Bip44,
    /// Ledger Live legacy (`m/44'/60'/{index}'/0/0`).
    LedgerLive,
}

/// Canonical EVM tokens.
pub const EVM_ACCEPTED: &[&str] = &["bip44", "ledger-live"];

impl DerivationStyle for EvmDerivationStyle {
    fn accepted() -> &'static [&'static str] {
        EVM_ACCEPTED
    }

    fn derivation_template(&self) -> &'static str {
        match self {
            Self::Bip44 => "m/44'/60'/0'/0/{index}",
            Self::LedgerLive => "m/44'/60'/{index}'/0/0",
        }
    }
}

impl FromStr for EvmDerivationStyle {
    type Err = ParseDerivationStyleError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match normalize(s).as_str() {
            "bip44" | "default" | "standard" | "ethereum" => Ok(Self::Bip44),
            "ledger-live" | "ledgerlive" | "ledger" => Ok(Self::LedgerLive),
            _ => Err(ParseDerivationStyleError {
                chain: "evm",
                input: s.trim().to_string(),
                accepted: EVM_ACCEPTED,
            }),
        }
    }
}

impl fmt::Display for EvmDerivationStyle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bip44 => write!(f, "bip44"),
            Self::LedgerLive => write!(f, "ledger-live"),
        }
    }
}

// ---------------------------------------------------------------------------
// Solana (SVM)
// ---------------------------------------------------------------------------

/// Solana derivation styles.
///
/// - `Phantom` (default, Backpack/Phantom): `m/44'/501'/{index}'/0'`.
/// - `Bip44` (Ledger-style change path): `m/44'/501'/0'/{index}'`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SolanaDerivationStyle {
    /// Phantom/Backpack layout (`m/44'/501'/{index}'/0'`).
    Phantom,
    /// BIP-44 change layout (`m/44'/501'/0'/{index}'`).
    Bip44,
}

/// Canonical Solana tokens.
pub const SOLANA_ACCEPTED: &[&str] = &["phantom", "bip44"];

impl DerivationStyle for SolanaDerivationStyle {
    fn accepted() -> &'static [&'static str] {
        SOLANA_ACCEPTED
    }

    fn derivation_template(&self) -> &'static str {
        match self {
            Self::Phantom => "m/44'/501'/{index}'/0'",
            Self::Bip44 => "m/44'/501'/0'/{index}'",
        }
    }
}

impl FromStr for SolanaDerivationStyle {
    type Err = ParseDerivationStyleError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match normalize(s).as_str() {
            "phantom" | "default" | "backpack" | "standard" => Ok(Self::Phantom),
            "bip44" | "ledger" | "ledger-live" => Ok(Self::Bip44),
            _ => Err(ParseDerivationStyleError {
                chain: "solana",
                input: s.trim().to_string(),
                accepted: SOLANA_ACCEPTED,
            }),
        }
    }
}

impl fmt::Display for SolanaDerivationStyle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Phantom => write!(f, "phantom"),
            Self::Bip44 => write!(f, "bip44"),
        }
    }
}

// ---------------------------------------------------------------------------
// TON
// ---------------------------------------------------------------------------

/// TON wallet-version styles.
///
/// Both styles share one derivation path (`m/44'/607'/{index}'`): the key
/// never changes. The version only selects the wallet-contract code hash
/// used for address encoding (see `TonDisplayConfig` in `oc-signer` for the
/// key/display decoupling). `V5R1` is the current default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TonDerivationStyle {
    /// Wallet v5r1 (default).
    V5R1,
    /// Wallet v4r2 (legacy).
    V4R2,
}

/// Canonical TON tokens.
pub const TON_ACCEPTED: &[&str] = &["v5r1", "v4r2"];

impl DerivationStyle for TonDerivationStyle {
    fn accepted() -> &'static [&'static str] {
        TON_ACCEPTED
    }

    fn derivation_template(&self) -> &'static str {
        // Key path is version-independent by design.
        "m/44'/607'/{index}'"
    }
}

impl FromStr for TonDerivationStyle {
    type Err = ParseDerivationStyleError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match normalize(s).as_str() {
            "v5r1" | "v5" | "default" | "standard" => Ok(Self::V5R1),
            "v4r2" | "v4" | "legacy" => Ok(Self::V4R2),
            _ => Err(ParseDerivationStyleError {
                chain: "ton",
                input: s.trim().to_string(),
                accepted: TON_ACCEPTED,
            }),
        }
    }
}

impl fmt::Display for TonDerivationStyle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V5R1 => write!(f, "v5r1"),
            Self::V4R2 => write!(f, "v4r2"),
        }
    }
}

// ---------------------------------------------------------------------------
// Bitcoin
// ---------------------------------------------------------------------------

/// Bitcoin address-type styles (BIP-44/49/84/86).
///
/// Each style selects a purpose field and an address format. Only
/// `NativeSegwit` (P2WPKH-bech32) is fully implemented by `BitcoinSigner`;
/// the other templates are provided so path derivation converges now and
/// address-format support can follow without changing the parse surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BitcoinDerivationStyle {
    /// Native segwit P2WPKH-bech32 (`m/84'/0'/0'/0/{index}`, default).
    NativeSegwit,
    /// Nested segwit P2SH-P2WPKH (`m/49'/0'/0'/0/{index}`).
    NestedSegwit,
    /// Taproot P2TR (`m/86'/0'/0'/0/{index}`).
    Taproot,
    /// Legacy P2PKH (`m/44'/0'/0'/0/{index}`).
    Legacy,
}

/// Canonical Bitcoin tokens.
pub const BITCOIN_ACCEPTED: &[&str] = &["native-segwit", "nested-segwit", "taproot", "legacy"];

impl DerivationStyle for BitcoinDerivationStyle {
    fn accepted() -> &'static [&'static str] {
        BITCOIN_ACCEPTED
    }

    fn derivation_template(&self) -> &'static str {
        match self {
            Self::NativeSegwit => "m/84'/0'/0'/0/{index}",
            Self::NestedSegwit => "m/49'/0'/0'/0/{index}",
            Self::Taproot => "m/86'/0'/0'/0/{index}",
            Self::Legacy => "m/44'/0'/0'/0/{index}",
        }
    }
}

impl FromStr for BitcoinDerivationStyle {
    type Err = ParseDerivationStyleError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match normalize(s).as_str() {
            "native-segwit" | "nativesegwit" | "bip84" | "bech32" | "default" | "standard" => {
                Ok(Self::NativeSegwit)
            }
            "nested-segwit" | "nestedsegwit" | "bip49" => Ok(Self::NestedSegwit),
            "taproot" | "bip86" | "p2tr" => Ok(Self::Taproot),
            "legacy" | "bip44" | "p2pkh" => Ok(Self::Legacy),
            _ => Err(ParseDerivationStyleError {
                chain: "bitcoin",
                input: s.trim().to_string(),
                accepted: BITCOIN_ACCEPTED,
            }),
        }
    }
}

impl fmt::Display for BitcoinDerivationStyle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NativeSegwit => write!(f, "native-segwit"),
            Self::NestedSegwit => write!(f, "nested-segwit"),
            Self::Taproot => write!(f, "taproot"),
            Self::Legacy => write!(f, "legacy"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evm_parses_canonical_and_aliases() {
        assert_eq!("bip44".parse::<EvmDerivationStyle>().unwrap(), EvmDerivationStyle::Bip44);
        assert_eq!("default".parse::<EvmDerivationStyle>().unwrap(), EvmDerivationStyle::Bip44);
        assert_eq!(
            "LEDGER-LIVE".parse::<EvmDerivationStyle>().unwrap(),
            EvmDerivationStyle::LedgerLive
        );
        assert_eq!("ledger".parse::<EvmDerivationStyle>().unwrap(), EvmDerivationStyle::LedgerLive);
    }

    #[test]
    fn evm_error_carries_legal_tokens() {
        let err = "weird".parse::<EvmDerivationStyle>().unwrap_err();
        assert_eq!(err.chain, "evm");
        assert_eq!(err.input, "weird");
        assert_eq!(err.accepted, EvmDerivationStyle::accepted());
        // CLI prints verbatim: message must contain every legal token.
        let msg = err.to_string();
        for token in EvmDerivationStyle::accepted() {
            assert!(msg.contains(token), "message must list '{token}': {msg}");
        }
    }

    #[test]
    fn evm_templates_match_registry() {
        assert_eq!(EvmDerivationStyle::Bip44.derivation_path(0), "m/44'/60'/0'/0/0");
        assert_eq!(EvmDerivationStyle::LedgerLive.derivation_path(7), "m/44'/60'/7'/0/0");
    }

    #[test]
    fn solana_parses_and_templates() {
        assert_eq!(
            "phantom".parse::<SolanaDerivationStyle>().unwrap(),
            SolanaDerivationStyle::Phantom
        );
        assert_eq!(
            "default".parse::<SolanaDerivationStyle>().unwrap(),
            SolanaDerivationStyle::Phantom
        );
        assert_eq!("bip44".parse::<SolanaDerivationStyle>().unwrap(), SolanaDerivationStyle::Bip44);
        assert_eq!(SolanaDerivationStyle::Phantom.derivation_path(0), "m/44'/501'/0'/0'");
        let err = "x".parse::<SolanaDerivationStyle>().unwrap_err();
        assert_eq!(err.chain, "solana");
        let msg = err.to_string();
        for token in SolanaDerivationStyle::accepted() {
            assert!(msg.contains(token));
        }
    }

    #[test]
    fn ton_styles_share_key_path() {
        // Key/display decoupling: wallet version must not change the key path.
        assert_eq!(
            TonDerivationStyle::V5R1.derivation_template(),
            TonDerivationStyle::V4R2.derivation_template()
        );
        assert_eq!(TonDerivationStyle::V5R1.derivation_path(3), "m/44'/607'/3'");
        assert_eq!("v5".parse::<TonDerivationStyle>().unwrap(), TonDerivationStyle::V5R1);
        assert_eq!("v4r2".parse::<TonDerivationStyle>().unwrap(), TonDerivationStyle::V4R2);
        let err = "v6".parse::<TonDerivationStyle>().unwrap_err();
        assert_eq!(err.chain, "ton");
        assert!(err.to_string().contains("v5r1"));
    }

    #[test]
    fn bitcoin_covers_bip44_49_84_86() {
        assert_eq!(BitcoinDerivationStyle::NativeSegwit.derivation_path(0), "m/84'/0'/0'/0/0");
        assert_eq!(BitcoinDerivationStyle::NestedSegwit.derivation_path(0), "m/49'/0'/0'/0/0");
        assert_eq!(BitcoinDerivationStyle::Taproot.derivation_path(0), "m/86'/0'/0'/0/0");
        assert_eq!(BitcoinDerivationStyle::Legacy.derivation_path(0), "m/44'/0'/0'/0/0");
        assert_eq!(
            "bip84".parse::<BitcoinDerivationStyle>().unwrap(),
            BitcoinDerivationStyle::NativeSegwit
        );
        assert_eq!(
            "bip86".parse::<BitcoinDerivationStyle>().unwrap(),
            BitcoinDerivationStyle::Taproot
        );
        let err = "bip999".parse::<BitcoinDerivationStyle>().unwrap_err();
        assert_eq!(err.chain, "bitcoin");
        let msg = err.to_string();
        for token in BitcoinDerivationStyle::accepted() {
            assert!(msg.contains(token), "missing '{token}' in: {msg}");
        }
    }

    #[test]
    fn display_roundtrips_through_parse() {
        for style in [EvmDerivationStyle::Bip44, EvmDerivationStyle::LedgerLive] {
            assert_eq!(style.to_string().parse::<EvmDerivationStyle>().unwrap(), style);
        }
        for style in [SolanaDerivationStyle::Phantom, SolanaDerivationStyle::Bip44] {
            assert_eq!(style.to_string().parse::<SolanaDerivationStyle>().unwrap(), style);
        }
        for style in [TonDerivationStyle::V5R1, TonDerivationStyle::V4R2] {
            assert_eq!(style.to_string().parse::<TonDerivationStyle>().unwrap(), style);
        }
        for style in [
            BitcoinDerivationStyle::NativeSegwit,
            BitcoinDerivationStyle::NestedSegwit,
            BitcoinDerivationStyle::Taproot,
            BitcoinDerivationStyle::Legacy,
        ] {
            assert_eq!(style.to_string().parse::<BitcoinDerivationStyle>().unwrap(), style);
        }
    }
}
