//! # oc-siwx — Sign-In with X (CAIP-122)
//!
//! Chain-agnostic core implementing the CAIP-122 Sign-In with X abstract data
//! model: message construction, ABNF parsing, validation, and a synchronous
//! [`SyncVerifier`] trait for chain-specific signature verification.
//!
//! Prefer [`authenticate`] for backend login (fail-fast):
//! 1. size ≤ [`MAX_MESSAGE_BYTES`];
//! 2. reject CR;
//! 3. ABNF parse;
//! 4. [`SiwxMessage::validate`] (`AuthOpts` domain/nonce required, 60s skew);
//! 5. preamble `chain_name` == [`SyncVerifier::CHAIN_NAME`];
//! 6. [`SyncVerifier::validate_address`];
//! 7. [`SyncVerifier::validate_chain_id`];
//! 8. [`SyncVerifier::verify`] over the original bytes.
//!
//! Trailing LF is rejected; trim before [`authenticate`] if a client leaves one.
//!
//! Chain-specific verifiers live in `oc-signer` (`EvmVerifier` /
//! `SolanaVerifier`, pure crypto, no I/O); contract/counterfactual checks
//! (EIP-1271 / ERC-6492) live in `oc-netagent` (`RpcVerifier`).
//!
//! Time uses [`jiff`] (workspace standard); the original RFC 3339 lexical
//! form is preserved verbatim for byte-exact re-hashing.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod auth;
mod error;
mod formatter;
mod message;
pub mod nonce;
mod parser;
mod validate;
mod verifier;

pub use auth::{Authenticated, authenticate};
pub use error::{ChainIdReason, FormatReason, SiwxError};
pub use message::{
    MAX_MESSAGE_BYTES, MAX_REQUEST_ID_BYTES, MAX_RESOURCES, MAX_STATEMENT_BYTES, MAX_URI_BYTES,
    MIN_NONCE_LEN, SiwxMessage, Timestamp, VERSION,
};
pub use validate::{AuthOpts, DEFAULT_CLOCK_SKEW_SECS};
pub use verifier::{
    EVM_CHAIN_NAME, EVM_NAMESPACE, SOLANA_CHAIN_NAME, SOLANA_NAMESPACE, SyncVerifier,
};
