use crate::error::OcWalletError;

// Hand-written prost message types matching the Sui gRPC proto definitions
// from https://github.com/MystenLabs/sui-apis/tree/main/proto/sui/rpc/v2
//
// Only the minimal types needed for transaction execution are defined here.

#[derive(Clone, PartialEq, prost::Message)]
pub(crate) struct Bcs {
    #[prost(string, optional, tag = "1")]
    pub(crate) name: ::core::option::Option<String>,
    #[prost(bytes = "vec", optional, tag = "2")]
    pub(crate) value: ::core::option::Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub(crate) struct Transaction {
    #[prost(message, optional, tag = "1")]
    pub(crate) bcs: ::core::option::Option<Bcs>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub(crate) struct UserSignature {
    #[prost(message, optional, tag = "1")]
    pub(crate) bcs: ::core::option::Option<Bcs>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub(crate) struct ExecuteTransactionRequest {
    #[prost(message, optional, tag = "1")]
    pub(crate) transaction: ::core::option::Option<Transaction>,
    #[prost(message, repeated, tag = "2")]
    pub(crate) signatures: Vec<UserSignature>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub(crate) struct ExecutedTransaction {
    #[prost(string, optional, tag = "1")]
    pub(crate) digest: ::core::option::Option<String>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub(crate) struct ExecuteTransactionResponse {
    #[prost(message, optional, tag = "1")]
    pub(crate) transaction: ::core::option::Option<ExecutedTransaction>,
}

/// Execute a signed Sui transaction via gRPC.
///
/// `endpoint` is the gRPC endpoint URL (e.g. `https://fullnode.mainnet.sui.io:443`).
/// `tx_bcs` is the BCS-encoded transaction bytes.
/// `sig_bcs` is the Sui wire signature (flag || sig || pubkey).
///
/// Returns the transaction digest on success.
pub(crate) fn execute_transaction(
    endpoint: &str,
    tx_bcs: &[u8],
    sig_bcs: &[u8],
) -> Result<String, OcWalletError> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| OcWalletError::BroadcastFailed(format!("failed to create runtime: {e}")))?;

    rt.block_on(async {
        let channel = tonic::transport::Channel::from_shared(endpoint.to_string())
            .map_err(|e| OcWalletError::BroadcastFailed(format!("invalid endpoint: {e}")))?
            .connect()
            .await
            .map_err(|e| OcWalletError::BroadcastFailed(format!("gRPC connect failed: {e}")))?;

        let mut client = tonic::client::Grpc::new(channel);

        client
            .ready()
            .await
            .map_err(|e| OcWalletError::BroadcastFailed(format!("gRPC not ready: {e}")))?;

        let request = ExecuteTransactionRequest {
            transaction: Some(Transaction {
                bcs: Some(Bcs { name: None, value: Some(tx_bcs.to_vec()) }),
            }),
            signatures: vec![UserSignature {
                bcs: Some(Bcs { name: None, value: Some(sig_bcs.to_vec()) }),
            }],
        };

        let path = tonic::codegen::http::uri::PathAndQuery::from_static(
            "/sui.rpc.v2.TransactionExecutionService/ExecuteTransaction",
        );
        let codec = tonic_prost::ProstCodec::default();

        let response: tonic::Response<ExecuteTransactionResponse> = client
            .unary(tonic::Request::new(request), path, codec)
            .await
            .map_err(|e| OcWalletError::BroadcastFailed(format!("gRPC error: {e}")))?;

        response
            .into_inner()
            .transaction
            .and_then(|t| t.digest)
            .ok_or_else(|| OcWalletError::BroadcastFailed("no digest in gRPC response".into()))
    })
}
