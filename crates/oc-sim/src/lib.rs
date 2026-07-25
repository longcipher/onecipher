//! EVM transaction simulation backed by [`evm2`].
//!
//! [`simulate_evm_tx`] is the single public entry-point. It decodes a raw
//! hex-encoded transaction, runs it through the evm2 interpreter, and returns
//! a [`TxSimulation`] (reusing the shared type from `oc-core`).

pub mod abi_cache;
pub mod abi_decode;

use oc_core::TxSimulation;

#[derive(Debug, thiserror::Error)]
pub enum SimError {
    #[error("hex decode error: {0}")]
    HexDecode(String),
    #[error("transaction decode error: {0}")]
    TxDecode(String),
    #[error("evm execution error: {0}")]
    Execution(String),
    #[error("simulation not available: {0}")]
    NotAvailable(String),
}

/// Simulate an EVM transaction from its raw hex-encoded bytes.
///
/// The heavy EVM work is offloaded to a blocking thread via
/// [`tokio::task::spawn_blocking`].
pub async fn simulate_evm_tx(raw_tx_hex: &str, chain_id: &str) -> Result<TxSimulation, SimError> {
    let hex = raw_tx_hex.trim().strip_prefix("0x").unwrap_or(raw_tx_hex).to_owned();
    let chain = chain_id.to_owned();

    tokio::task::spawn_blocking(move || simulate_evm_tx_sync(&hex, &chain))
        .await
        .map_err(|e| SimError::Execution(format!("task join error: {e}")))?
}

fn simulate_evm_tx_sync(hex: &str, _chain_id: &str) -> Result<TxSimulation, SimError> {
    let _tx_bytes = hex::decode(hex).map_err(|e| SimError::HexDecode(e.to_string()))?;

    // ponytail: full evm2 execution requires wiring up a database, TxEnv, BlockEnv,
    // chain spec, and precompile set — significant integration work. Stub returns
    // NotAvailable until the database/RPC layer is ready. The dependency is pinned
    // and the API boundary is established; the implementation lands when oc-sim
    // gets an RPC-backed DatabaseRef.
    tracing::warn!("evm2 simulation stub — full execution not yet wired");
    Err(SimError::NotAvailable("evm2 execution pending database/RPC integration".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rejects_bad_hex() {
        let err = simulate_evm_tx("not-hex", "eip155:1").await.unwrap_err();
        assert!(matches!(err, SimError::HexDecode(_)));
    }

    #[tokio::test]
    async fn stub_returns_not_available() {
        let err = simulate_evm_tx("0xdeadbeef", "eip155:1").await.unwrap_err();
        assert!(matches!(err, SimError::NotAvailable(_)));
    }
}
