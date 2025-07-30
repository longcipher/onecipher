#![deny(unsafe_code)]

//! OneCipher Paymaster — ERC-4337 Paymaster + Bundler client.
//!
//! This crate implements gas abstraction for AI Agent transactions:
//! - **Sponsored**: gas paid by a Verifying Paymaster (off-chain signature)
//! - **PayInUsdc**: user pays gas in USDC (ERC-20 Paymaster)
//! - **Native**: user pays gas in native token (no paymaster)

pub mod client;
pub mod error;
pub mod sponsor;
pub mod user_op;

pub use client::{PaymasterClient, SponsorMode, SponsoredUserOp};
pub use error::PaymasterError;
pub use sponsor::SponsorStrategy;
pub use user_op::{UserOperation, UserOperationBuilder};
