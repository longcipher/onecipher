//! Payment primitives.
//!
//! Per R7 / R8 / R35, this crate provides x402 (`exact` + `exact+UserOp` schemes) and MPP (Tempo
//! channel) support. It owns the [`PaymentSettler`] trait (R36) and three Phase 1 implementations:
//!
//! - [`evm::EvmSettler`] — submits EIP-4337 UserOps to a Bundler, sponsors gas via a Paymaster
//!   (mocked in tests).
//! - [`solana::SolanaSettler`] — submits Solana txs directly to an RPC endpoint (no Paymaster;
//!   Agent holds SOL).
//! - [`tempo::TempoSettler`] — opens / streams / closes Tempo MPP channels.
//!
//! # Phase 1 MVP scope
//!
//! Phase 1 ships the trait surface + mock-friendly settler scaffolding. Real
//! Bundler / Paymaster / Tempo / Solana HTTP integration is T19 / T20's job
//! (BLOCKED on T18). The settlers therefore accept injectable trait-based
//! clients; tests wire up mock impls.
//!
//! # Deviation note (R77, AD-02)
//!
//! The spec calls for implementing `x402.rs`, `chains.rs`, `types.rs` from the
//! Open Wallet Standard. These types are implemented from scratch following
//! the spec's interface contract. See the T18 Deviation Note in the task report.

#![deny(unsafe_code)]

pub mod error;
pub mod evm;
pub mod mpp;
pub mod paymaster;
pub mod settler;
pub mod solana;
pub mod tempo;
pub mod types;
pub mod x402;

pub use error::PayError;
pub use evm::{BundlerClient, EvmSettler, PaymasterClient};
pub use mpp::{MppChunk, MppStreamHandle, PayMpp};
// Re-export the bits of `oc-session-key` that callers of `PaymentSettler`
// commonly need — they appear in the trait signature (`payer: &SessionKey`).
pub use oc_session_key::{KeyScheme, PublicKey, SessionPrivateKey};
pub use paymaster::{
    PaymasterClient as PaymasterService, PaymasterError, SponsorMode, SponsorStrategy,
    SponsoredUserOp, UserOperation, UserOperationBuilder,
};
// Re-export `Decimal` so downstream callers don't have to depend on
// `rust_decimal` directly just to spell the amount type.
pub use rust_decimal::Decimal;
pub use settler::PaymentSettler;
pub use solana::{SolanaRpcClient, SolanaSettler};
pub use tempo::{TempoChannelClient, TempoSettler};
pub use types::{Caip19Asset, ChannelId, ChannelState, PaymentReceipt, PaymentScheme, SessionKey};
pub use x402::{
    ExactPlusUserOpScheme, ExactScheme, FacilitatorRequest, FacilitatorResponse,
    PaymentRequirements, X402Scheme,
};

#[cfg(feature = "http")]
pub mod http;

#[cfg(feature = "http")]
pub use http::{
    Account as HttpAccount, DiscoverResult, OcPayHttpError, OcPayHttpErrorCode,
    PayResult as HttpPayResult, PaymentInfo, Protocol, Service, WalletAccess, discover, pay,
};
