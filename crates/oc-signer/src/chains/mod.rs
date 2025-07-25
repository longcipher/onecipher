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
pub mod xrpl;

use oc_core::ChainType;

pub use self::{
    bitcoin::BitcoinSigner, cosmos::CosmosSigner, evm::EvmSigner, filecoin::FilecoinSigner,
    nano::NanoSigner, near::NearSigner, solana::SolanaSigner, spark::SparkSigner, sui::SuiSigner,
    ton::TonSigner, tron::TronSigner, xrpl::XrplSigner,
};
use crate::traits::ChainSigner;

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
        ChainType::Xrpl => Box::new(XrplSigner),
        ChainType::Nano => Box::new(NanoSigner),
        ChainType::Near => Box::new(NearSigner),
    }
}
