use crate::rpc::RpcError;

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
}
