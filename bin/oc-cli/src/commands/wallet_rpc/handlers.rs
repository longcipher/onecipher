//! Concrete `ledgerflow_*` method implementations for the loopback
//! WalletSigner server.

use base64::Engine;
// Bring `ed25519_dalek::Signer` (the `sign` method) into scope.
use ed25519_dalek::Signer as _;
use oc_signer::ChainSigner;
use serde_json::{Value, json};

use super::state::{KeyInfo, RpcError, SignPaymentParams, SignerState};

/// `ledgerflow_keys` → `[{"alg":"ed25519","public_key":"<b64>"}, ...]`.
pub(crate) fn handle_keys(state: &SignerState) -> Result<Value, RpcError> {
    let mut keys = Vec::new();
    match state.ed25519_pubkey() {
        Ok(pubkey) => keys.push(KeyInfo::new(
            "ed25519",
            base64::engine::general_purpose::STANDARD.encode(&pubkey),
            None,
        )),
        Err(e) => return Err(RpcError::new(-32603, e)),
    }
    match state.secp256k1_pubkey() {
        Ok(pubkey) => keys.push(KeyInfo::new(
            "secp256k1",
            base64::engine::general_purpose::STANDARD.encode(&pubkey),
            None,
        )),
        Err(e) => return Err(RpcError::new(-32603, e)),
    }
    serde_json::to_value(keys).map_err(|e| RpcError::new(-32603, e.to_string()))
}

/// `ledgerflow_sign` — sign a base64 message with the selected key.
pub(crate) fn handle_sign(state: &SignerState, params: &Value) -> Result<Value, RpcError> {
    // Ignore `domain` for actual signing — it only labels what is being signed.
    let msg_b64 = params
        .get("message")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::new(-32602, "missing 'message' (base64)"))?;
    let message = base64::engine::general_purpose::STANDARD
        .decode(msg_b64)
        .map_err(|e| RpcError::new(-32602, format!("invalid base64 message: {e}")))?;

    // Select the curve.
    let key = params.get("key");
    let alg = key
        .and_then(|k| k.get("alg"))
        .and_then(Value::as_str)
        .unwrap_or("ed25519")
        .to_ascii_lowercase();

    let (signature, pubkey) = match alg.as_str() {
        "ed25519" => {
            let secret = state
                .secret_key(oc_core::ChainType::Solana)
                .map_err(|e| RpcError::new(-32603, e))?;
            let bytes: [u8; 32] = secret
                .expose()
                .try_into()
                .map_err(|_| RpcError::new(-32603, "invalid ed25519 key length"))?;
            let pair = ed25519_dalek::SigningKey::from_bytes(&bytes);
            let sig = pair.sign(&message);
            let pubkey = pair.verifying_key().to_bytes().to_vec();
            (sig.to_bytes().to_vec(), pubkey)
        }
        "secp256k1" => {
            let secret =
                state.secret_key(oc_core::ChainType::Evm).map_err(|e| RpcError::new(-32603, e))?;
            let signer = oc_signer::chains::EvmSigner;
            let output = signer
                .sign_message(secret.expose(), &message)
                .map_err(|e| RpcError::new(-32603, format!("signing failed: {e}")))?;
            // 65-byte r||s||v signature (EIP-191 style: v = 27|28).
            let pubkey = SignerState::secp256k1_public_key(secret.expose())
                .map_err(|e| RpcError::new(-32603, e))?;
            (output.signature, pubkey)
        }
        other => return Err(RpcError::new(-32602, format!("unsupported alg: {other}"))),
    };

    serde_json::to_value(json!({
        "signer": {
            "alg": alg,
            "public_key": base64::engine::general_purpose::STANDARD.encode(pubkey),
            "key_id": null,
        },
        "signature": {
            "value": base64::engine::general_purpose::STANDARD.encode(&signature),
            "alg": alg,
        },
    }))
    .map_err(|e| RpcError::new(-32603, e.to_string()))
}

/// `ledgerflow_sign_payment` — build and sign an EIP-1559 EVM payment.
pub(crate) fn handle_sign_payment(state: &SignerState, params: &Value) -> Result<Value, RpcError> {
    let p = serde_json::from_value::<SignPaymentParams>(params.clone())
        .map_err(|e| RpcError::new(-32602, format!("invalid payment params: {e}")))?;

    // Chain ID must be eip155:<n>.
    let chain_ref = p
        .chain_id()
        .strip_prefix("eip155:")
        .ok_or_else(|| RpcError::new(-32602, "chain_id must be eip155:<n>"))?;
    let chain_id = chain_ref
        .parse::<u128>()
        .map_err(|_| RpcError::new(-32602, format!("invalid chain id: {}", p.chain_id())))?;

    // Amount in wei (u128 decimal string).
    let amount = p
        .amount()
        .ok_or_else(|| RpcError::new(-32602, "missing 'amount' (wei, decimal string)"))?
        .parse::<u128>()
        .map_err(|e| RpcError::new(-32602, format!("invalid amount: {e}")))?;

    // Payee (0x + 20 bytes).
    let payee = p.payee().ok_or_else(|| RpcError::new(-32602, "missing 'payee'"))?;
    let payee_bytes = hex::decode(payee.strip_prefix("0x").unwrap_or(payee))
        .map_err(|e| RpcError::new(-32602, format!("invalid payee hex: {e}")))?;
    if payee_bytes.len() != 20 {
        return Err(RpcError::new(-32602, "payee must be a 20-byte address"));
    }

    // Nonce (default 0).
    let nonce = match p.nonce() {
        Some(n) => {
            n.parse::<u128>().map_err(|e| RpcError::new(-32602, format!("invalid nonce: {e}")))?
        }
        None => 0,
    };

    // Decrypt the signing key.
    let secret = state.secret_key(oc_core::ChainType::Evm).map_err(|e| RpcError::new(-32603, e))?;
    let signer = oc_signer::chains::EvmSigner;

    // Build an unsigned EIP-1559 transaction:
    // RLP([chain_id, nonce, max_priority_fee, max_fee, gas_limit, to, value, data, access_list])
    let items: Vec<u8> = [
        oc_signer::rlp::encode_u128(chain_id),
        oc_signer::rlp::encode_u128(nonce),
        oc_signer::rlp::encode_u128(0), // maxPriorityFeePerGas
        oc_signer::rlp::encode_u128(1_000_000_000), // maxFeePerGas = 1 gwei
        oc_signer::rlp::encode_u128(52_000), // gasLimit (self-transfer + margin)
        oc_signer::rlp::encode_bytes(&payee_bytes),
        oc_signer::rlp::encode_u128(amount),
        oc_signer::rlp::encode_bytes(&[]), // data = empty
        oc_signer::rlp::encode_list(&[]),  // accessList = empty
    ]
    .concat();

    let mut unsigned_tx = vec![0x02u8];
    unsigned_tx.extend_from_slice(&oc_signer::rlp::encode_list(&items));

    let output = signer
        .sign_transaction(secret.expose(), &unsigned_tx)
        .map_err(|e| RpcError::new(-32603, format!("signing failed: {e}")))?;
    let signed = signer
        .encode_signed_transaction(&unsigned_tx, &output)
        .map_err(|e| RpcError::new(-32603, format!("tx encoding failed: {e}")))?;

    let raw_transaction = format!("0x{}", hex::encode(&signed));
    serde_json::to_value(json!({ "raw_transaction": raw_transaction, "tx_hash": null }))
        .map_err(|e| RpcError::new(-32603, e.to_string()))
}
