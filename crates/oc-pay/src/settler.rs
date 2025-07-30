//! The `PaymentSettler` trait (R36).
//!
//! Unifies EVM / Solana / Tempo payment settlement behind a single async
//! interface. Phase 1 implementations:
//! - [`crate::evm::EvmSettler`]
//! - [`crate::solana::SolanaSettler`]
//! - [`crate::tempo::TempoSettler`]
//!
//! The trait surface mirrors the T18 contract exactly — see the spec excerpt
//! in the crate-level docs.

use async_trait::async_trait;
use rust_decimal::Decimal;

use crate::{
    error::PayError,
    types::{Caip19Asset, ChannelId, PaymentReceipt, PaymentScheme, SessionKey},
};

/// The payment settler trait (R36).
///
/// A `PaymentSettler` knows how to:
/// - settle a one-shot x402 `exact` (or `exact+UserOp`) payment via [`PaymentSettler::pay_exact`],
///   and
/// - open / close an MPP channel via [`PaymentSettler::open_channel`] /
///   [`PaymentSettler::close_channel`].
///
/// Each settler is bound to a single chain (returned by
/// [`PaymentSettler::chain_id`]); cross-chain routing is the caller's job.
/// The set of x402 schemes the settler supports is returned by
/// [`PaymentSettler::supported_schemes`].
///
/// Phase 1 settlers are mockable: they accept trait-based clients
/// ([`crate::evm::BundlerClient`] / [`crate::evm::PaymasterClient`] /
/// [`crate::solana::SolanaRpcClient`] / [`crate::tempo::TempoChannelClient`])
/// so tests can inject mock impls without spinning up real Bundler / Paymaster
/// / Solana / Tempo services. Real HTTP clients live in `oc-netagent` (T19).
#[async_trait]
pub trait PaymentSettler: Send + Sync {
    /// CAIP-2 chain id this settler is bound to (e.g. `"eip155:8453"` or
    /// `"solana:mainnet"`).
    fn chain_id(&self) -> &str;

    /// x402 schemes this settler supports (e.g. `[Exact, ExactPlusUserOp]`
    /// for EVM, `[Exact]` for Solana, `[]` for Tempo which is MPP-only).
    fn supported_schemes(&self) -> &[PaymentScheme];

    /// Settle a one-shot exact payment.
    ///
    /// For [`PaymentScheme::ExactPlusUserOp`] on EVM, this signs a UserOp via
    /// the Key-Agent, submits it to the Bundler, has the Paymaster sponsor
    /// gas, and lets the SCA verify ERC-7715 — returning a receipt with the
    /// tx hash. For [`PaymentScheme::Exact`] on Solana, this signs a Solana
    /// tx and submits it directly to the RPC, returning the signature.
    ///
    /// `amount` is in the asset's smallest on-chain unit (wei / lamports /
    /// token-base-unit) — the settler does not interpret decimals.
    async fn pay_exact(
        &self,
        payer: &SessionKey,
        recipient: &str,
        amount: Decimal,
        asset: Caip19Asset,
    ) -> Result<PaymentReceipt, PayError>;

    /// Open an MPP channel with `recipient` capped at `max_amount`.
    ///
    /// Returns the new [`ChannelId`] on success. The channel can then stream
    /// payments via [`crate::mpp::PayMpp`] and be closed via
    /// [`PaymentSettler::close_channel`].
    async fn open_channel(
        &self,
        payer: &SessionKey,
        recipient: &str,
        max_amount: Decimal,
    ) -> Result<ChannelId, PayError>;

    /// Close an MPP channel and return the final settlement receipt.
    ///
    /// The receipt's `amount` is the total amount streamed through the
    /// channel; `tx_hash` is the on-chain close-tx identifier.
    async fn close_channel(&self, channel_id: &ChannelId) -> Result<PaymentReceipt, PayError>;
}
