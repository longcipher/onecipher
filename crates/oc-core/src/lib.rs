// Test code may unwrap/expect/panic (workspace lint phase-1 carve-out).
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
pub mod api_key;
pub mod approval;
pub mod approval_log;
pub mod caip;
pub mod chain;
pub mod chain_registry;
pub mod config;
pub mod credential;
pub mod derivation;
pub mod error;
pub mod ipc;
pub mod paths;
pub mod policy;
pub mod pubkey;
pub mod resolve;
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
    SiwxSummary, TokenDelta, TokenDirection, TxSimulation,
};
pub use caip::{AccountId, AssetId, ChainId, ChainIdExt};
pub use chain::{
    ALL_CHAIN_TYPES, Chain, ChainType, KNOWN_CHAINS, default_chain_for_type, parse_chain,
};
pub use config::{Config, WebuiConfig};
pub use credential::{Credential, TOKEN_PREFIX, ct_eq};
pub use derivation::{
    BitcoinDerivationStyle, DerivationStyle, EvmDerivationStyle, ParseDerivationStyleError,
    SolanaDerivationStyle, TonDerivationStyle,
};
pub use error::{OcError, OcErrorCode};
pub use paths::{config_path, home_dir, state_dir, state_path};
pub use policy::{Policy, PolicyAction, PolicyContext, PolicyResult, PolicyRule, TypedDataContext};
pub use pubkey::{DerivedPublicKey, PubkeyError, PublicKeyKind};
pub use resolve::{ResolvedChain, resolve_chain};
pub use secret::{
    AuditOp, AuditTrack, ItemType, SecretEnvelope, SecretIndexEntry, SecretKind, SecretMetadata,
    SecretPayload,
};
// Re-exported at the crate root so existing `oc_core::Passphrase` /
// `oc_core::UnlockToken` paths keep working unchanged.
#[cfg(feature = "hardened")]
pub use secure_types::{Passphrase, UnlockToken};
pub use types::*;
pub use wallet_file::*;
