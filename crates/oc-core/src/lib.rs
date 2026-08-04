pub mod api_key;
pub mod approval;
pub mod caip;
pub mod chain;
pub mod config;
pub mod error;
pub mod paths;
pub mod policy;
pub mod secret;
/// Hardened-memory types. Requires the `hardened` feature (pulls `oc-crypto`).
#[cfg(feature = "hardened")]
pub mod secure_types;
#[cfg(test)]
mod test_support;
pub mod types;
pub mod wallet_file;

pub use api_key::{ApiKeyFile, SecretPermissions};
pub use approval::{
    ApprovalDecision, DecodedAction, PendingApproval, RiskLevel, RiskReason, RiskSource,
    TokenDelta, TokenDirection, TxSimulation,
};
pub use caip::{AccountId, AssetId, ChainId, ChainIdExt};
pub use chain::{
    ALL_CHAIN_TYPES, Chain, ChainType, KNOWN_CHAINS, default_chain_for_type, parse_chain,
};
pub use config::{Config, WebuiConfig};
pub use error::{OcError, OcErrorCode};
pub use paths::{config_path, home_dir, state_dir, state_path};
pub use policy::{Policy, PolicyAction, PolicyContext, PolicyResult, PolicyRule, TypedDataContext};
pub use secret::{ItemType, SecretIndexEntry, SecretMetadata, SecretPayload};
// Re-exported at the crate root so existing `oc_core::Passphrase` /
// `oc_core::UnlockToken` paths keep working unchanged.
#[cfg(feature = "hardened")]
pub use secure_types::{Passphrase, UnlockToken};
pub use types::*;
pub use wallet_file::*;
