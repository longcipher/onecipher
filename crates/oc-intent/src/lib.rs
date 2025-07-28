#![deny(unsafe_code)]

//! OneCipher Intent Layer — AI Agent Native declarative payment/signing.
//!
//! This crate implements the Intent-based execution model described in
//! `docs/design.md` §6.1. AI Agents submit declarative intents (e.g.
//! "pay 10.5 USDC to 0xABC on Base"), which are:
//!
//! 1. **Simulated** — pre-flight `eth_call` + `eth_estimateGas` to show the user a human-readable
//!    summary before signing.
//! 2. **Confirmed** — user/Passkey confirms the summary.
//! 3. **Executed** — the intent is signed and broadcast (optionally via Paymaster for gasless
//!    transactions).

pub mod error;
pub mod execute;
pub mod rpc;
pub mod schema;
pub mod simulate;

pub use error::IntentError;
pub use execute::execute_intent;
pub use rpc::{CallData, MockRpcClient, RpcClient, RpcError};
pub use schema::{Intent, IntentKind, IntentResult, IntentStatus, IntentSummary, MessageEncoding};
pub use simulate::simulate_intent;
