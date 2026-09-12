// Test code may unwrap/expect/panic (workspace lint phase-1 carve-out).
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
pub mod bridge;
#[cfg(feature = "rpc")]
pub mod broadcast;
pub mod error;
pub mod key_ops;
pub mod key_store;
pub mod migrate;
#[cfg(feature = "rpc")]
pub mod nano_rpc;
#[cfg(feature = "rpc")]
pub mod near_rpc;
pub mod ops;
pub mod policy_store;
#[cfg(any(feature = "rpc", feature = "sui-grpc"))]
mod runtime;
#[cfg(feature = "sui-grpc")]
mod sui_grpc;
pub mod types;

// Re-export the primary API.
pub use error::OcWalletError;
pub use oc_core::SecretPermissions;
pub use ops::*;
pub use types::*;
