// Umbrella prelude for Phase2 signer convergence (A12).
//
// One import covers the common signing surface:
//
// ```ignore
// use oc_signer::prelude::*;
// ```
//
// `no_std` builds (`--no-default-features`) only get the heap-light core
// (`Curve`, `ChainSigner`, `SignOutput`, `DeriveError`); everything needing
// OS/threads or `std`-only deps is gated behind `#[cfg(feature = "std")]`.
#[cfg(feature = "std")]
pub use crate::{
    account::{
        BitcoinAccount, CasperAccount, CosmosAccount, EvmAccount, FilecoinAccount, NanoAccount,
        NearAccount, SolanaAccount, SparkAccount, SuiAccount, TonAccount, TronAccount, XrplAccount,
        bitcoin_wif_encode, casper_public_key_hex, casper_tagged_ed25519, casper_tagged_secp256k1,
        nsec_encode,
    },
    chains::{
        BitcoinSigner, COSMOS_HUB, ChainConfig, CosmosSigner, EvmSigner, FilecoinSigner, JUNO,
        NanoSigner, NearSigner, OSMOSIS, STARGAZE, SolanaSigner, SparkSigner, SuiSigner,
        TonDisplayConfig, TonSigner, TronSigner, derivation_template_for_chain, signer_for_chain,
    },
    encoding::{base58check_decode, base58check_encode, double_sha256, hash160},
    hd::HdDeriver,
    mnemonic::{Mnemonic, MnemonicStrength},
    pubkey::{
        DerivedPublicKey, PubkeyError, PublicKeyKind, ed25519_from_private,
        secp256k1_compressed_from_private, secp256k1_uncompressed_from_private,
    },
    secret::{SealedKeypair, SealedPrivateKey, WifString},
    style::{bitcoin_path, derivation_path_for_style, evm_path, solana_path, ton_path},
};
pub use crate::{
    curve::Curve,
    error::{DeriveError, SignerError},
    traits::{ChainSigner, SignOutput},
};
