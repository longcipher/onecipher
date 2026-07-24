//! ERC-4337 Paymaster + Bundler client for gasless transactions.
//!
//! - [`PaymasterClient`] — interacts with a Paymaster + Bundler service.
//! - [`SponsorStrategy`] — gas payment mode (Sponsored / PayInUsdc / Native).
//! - [`UserOperation`] / [`UserOperationBuilder`] — ERC-4337 UserOp type.
//! - [`PaymasterError`] — error variants for paymaster operations.

pub mod client;
pub mod error;
pub mod sponsor;
pub mod user_op;

pub use client::{PaymasterClient, SponsorMode, SponsoredUserOp};
pub use error::PaymasterError;
pub use sponsor::SponsorStrategy;
pub use user_op::{UserOperation, UserOperationBuilder};
