use prost::Message;

use crate::error::OcWalletError;

// Hand-written prost message types matching the Sui gRPC proto definitions
// from https://github.com/MystenLabs/sui-apis/tree/main/proto/sui/rpc/v2
//
// Only the minimal types needed for transaction execution are defined here.
//
// The gRPC transport is hand-rolled over `hpx` (HTTP/2) rather than `tonic`:
// this crate needs exactly one unary RPC, and pulling the whole tonic runtime
// (and its dependency tree) for it was over-engineering. The framing is the
// standard gRPC over HTTP/2 wire format:
//   - POST to `/sui.rpc.v2.TransactionExecutionService/ExecuteTransaction`
//   - request body: 1-byte flag (0 = uncompressed) + 4-byte big-endian length
//     + protobuf message
//   - response body: same framing; the digest lives in `message.transaction.digest`

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
    crate::runtime::blocking_runtime().block_on(async {
        let request = ExecuteTransactionRequest {
            transaction: Some(Transaction {
                bcs: Some(Bcs { name: None, value: Some(tx_bcs.to_vec()) }),
            }),
            signatures: vec![UserSignature {
                bcs: Some(Bcs { name: None, value: Some(sig_bcs.to_vec()) }),
            }],
        };

        // gRPC frame: 1-byte flag (0 = uncompressed) + 4-byte big-endian length + body.
        let msg = request.encode_to_vec();
        let mut frame = Vec::with_capacity(5 + msg.len());
        frame.push(0u8);
        frame.extend_from_slice(&(msg.len() as u32).to_be_bytes());
        frame.extend_from_slice(&msg);

        let client = hpx::Client::new();
        let resp = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            client
                .post(endpoint)
                .header("Content-Type", "application/grpc")
                .header("TE", "trailers")
                .header("Grpc-Encoding", "identity")
                .body(frame)
                .send(),
        )
        .await
        .map_err(|e| OcWalletError::BroadcastFailed(format!("gRPC request timed out: {e}")))?
        .map_err(|e| OcWalletError::BroadcastFailed(format!("gRPC request failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            return Err(OcWalletError::BroadcastFailed(format!(
                "gRPC request failed (HTTP {status})"
            )));
        }

        let bytes = tokio::time::timeout(std::time::Duration::from_secs(30), resp.bytes())
            .await
            .map_err(|e| OcWalletError::BroadcastFailed(format!("gRPC response timed out: {e}")))?
            .map_err(|e| {
                OcWalletError::BroadcastFailed(format!("gRPC response read failed: {e}"))
            })?;

        // trailers-only (gRPC status) responses begin with flag 0x80 + zero length.
        if bytes.len() < 5 {
            return Err(OcWalletError::BroadcastFailed(format!(
                "truncated gRPC response ({} bytes)",
                bytes.len()
            )));
        }

        let flag = bytes[0];
        let len = u32::from_be_bytes(bytes[1..5].try_into().map_err(|e| {
            OcWalletError::BroadcastFailed(format!("invalid gRPC frame length: {e}"))
        })?);
        let end = 5 + len as usize;
        if end > bytes.len() {
            return Err(OcWalletError::BroadcastFailed(format!(
                "truncated gRPC message: frame declares {len} bytes but only {} available",
                bytes.len().saturating_sub(5)
            )));
        }
        if flag != 0 {
            return Err(OcWalletError::BroadcastFailed(format!(
                "unsupported gRPC compression flag: {flag}"
            )));
        }

        let msg_bytes = &bytes[5..end];
        let response = ExecuteTransactionResponse::decode(msg_bytes).map_err(|e| {
            OcWalletError::BroadcastFailed(format!("failed to decode gRPC response: {e}"))
        })?;

        response
            .transaction
            .and_then(|t| t.digest)
            .ok_or_else(|| OcWalletError::BroadcastFailed("no digest in gRPC response".into()))
    })
}
