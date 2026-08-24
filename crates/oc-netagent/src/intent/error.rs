use super::rpc::RpcError;

#[derive(Debug, thiserror::Error)]
pub enum IntentError {
    #[error("RPC error: {0}")]
    Rpc(#[from] RpcError),
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("invalid chain id: {0}")]
    InvalidChain(String),
    #[error("intent expired")]
    Expired,
    #[error("simulation failed: {0}")]
    Simulation(String),
    #[error("execution failed: {0}")]
    Execution(String),
    /// The intent kind is recognized but cannot be simulated/executed yet
    /// (M-04b: fail closed instead of signing a no-op transfer).
    #[error("unsupported intent: {0}")]
    Unsupported(String),
}
