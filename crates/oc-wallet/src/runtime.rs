//! Process-wide blocking tokio runtime for `oc-wallet`.
//!
//! Several `oc-wallet` functions bridge from sync contexts (CLI commands,
//! library调用) into async HTTP/gRPC clients (`hpx`). Building a fresh
//! `tokio::runtime` on every call is a performance and resource anti-pattern
//! (each `block_on` spins up and tears down a reactor + IO driver thread).
//!
//! Instead we lazily initialize a single process-wide current-thread runtime
//! via `OnceLock` and reuse it for every one-shot `block_on`. This keeps the
//! runtime count at exactly one for the lifetime of the process.

#![cfg(any(feature = "rpc", feature = "sui-grpc"))]

use std::sync::OnceLock;

use tokio::runtime::Runtime;

static WALLET_RT: OnceLock<Runtime> = OnceLock::new();

/// Returns a process-wide single-threaded tokio runtime for blocking
/// sync→async bridges inside `oc-wallet` (RPC broadcast, gRPC calls).
///
/// Created at most once via [`OnceLock`]. Use [`Runtime::block_on`] for
/// one-shot async calls; do NOT store the [`Runtime`] long-term.
pub(crate) fn blocking_runtime() -> &'static Runtime {
    WALLET_RT.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to build oc-wallet blocking runtime")
    })
}
