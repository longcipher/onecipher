pub mod bitcoin;
pub mod cosmos;
pub mod evm;
pub mod filecoin;
pub mod nano;
pub mod near;
pub mod solana;
pub mod spark;
pub mod sui;
pub mod ton;
pub mod tron;
#[cfg(feature = "xrpl")]
pub mod xrpl;

use oc_core::ChainType;

#[cfg(feature = "xrpl")]
pub use self::xrpl::XrplSigner;
pub use self::{
    bitcoin::BitcoinSigner, cosmos::CosmosSigner, evm::EvmSigner, filecoin::FilecoinSigner,
    nano::NanoSigner, near::NearSigner, solana::SolanaSigner, spark::SparkSigner, sui::SuiSigner,
    ton::TonSigner, tron::TronSigner,
};
use crate::traits::ChainSigner;
#[cfg(not(feature = "xrpl"))]
use crate::{
    curve::Curve,
    traits::{SignOutput, SignerError},
};

/// Fail-closed placeholder for a chain whose support was compiled out.
///
/// Every operation returns an error naming the feature that must be enabled.
/// This keeps [`signer_for_chain`] total (it returns `Box<dyn ChainSigner>`,
/// not an `Option`) without introducing a panic on an untrusted input path —
/// `ChainType` can be parsed from a WalletConnect session proposal.
#[cfg(not(feature = "xrpl"))]
#[derive(Debug, Clone, Copy)]
struct UnsupportedSigner {
    chain_type: ChainType,
    feature: &'static str,
}

#[cfg(not(feature = "xrpl"))]
impl UnsupportedSigner {
    fn err<T>(&self) -> Result<T, SignerError> {
        Err(SignerError::SigningFailed(format!(
            "{:?} support is not compiled in; rebuild with `--features {}`",
            self.chain_type, self.feature
        )))
    }
}

#[cfg(not(feature = "xrpl"))]
impl ChainSigner for UnsupportedSigner {
    fn chain_type(&self) -> ChainType {
        self.chain_type
    }

    fn curve(&self) -> Curve {
        Curve::Secp256k1
    }

    fn coin_type(&self) -> u32 {
        self.chain_type.default_coin_type()
    }

    fn derive_address(&self, _private_key: &[u8]) -> Result<String, SignerError> {
        self.err()
    }

    fn sign(&self, _private_key: &[u8], _message: &[u8]) -> Result<SignOutput, SignerError> {
        self.err()
    }

    fn sign_message(
        &self,
        _private_key: &[u8],
        _message: &[u8],
    ) -> Result<SignOutput, SignerError> {
        self.err()
    }

    fn sign_transaction(
        &self,
        _private_key: &[u8],
        _tx_bytes: &[u8],
    ) -> Result<SignOutput, SignerError> {
        self.err()
    }

    /// Kept faithful to the real signer so that path display / account
    /// enumeration still render correctly when the chain is compiled out.
    fn default_derivation_path(&self, index: u32) -> String {
        format!("m/44'/{}'/0'/0/{}", self.coin_type(), index)
    }
}

/// Get a default signer for a given chain type.
pub fn signer_for_chain(chain: ChainType) -> Box<dyn ChainSigner> {
    match chain {
        ChainType::Evm => Box::new(EvmSigner),
        ChainType::Solana => Box::new(SolanaSigner),
        ChainType::Bitcoin => Box::new(BitcoinSigner::mainnet()),
        ChainType::Cosmos => Box::new(CosmosSigner::cosmos_hub()),
        ChainType::Tron => Box::new(TronSigner),
        ChainType::Ton => Box::new(TonSigner),
        ChainType::Spark => Box::new(SparkSigner),
        ChainType::Filecoin => Box::new(FilecoinSigner),
        ChainType::Sui => Box::new(SuiSigner),
        #[cfg(feature = "xrpl")]
        ChainType::Xrpl => Box::new(XrplSigner),
        #[cfg(not(feature = "xrpl"))]
        ChainType::Xrpl => {
            Box::new(UnsupportedSigner { chain_type: ChainType::Xrpl, feature: "xrpl" })
        }
        ChainType::Nano => Box::new(NanoSigner),
        ChainType::Near => Box::new(NearSigner),
    }
}
