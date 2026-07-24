use std::path::Path;

#[cfg(feature = "rpc")]
use oc_core::{ChainType, Config};
use oc_signer::signer_for_chain;

#[cfg(feature = "rpc")]
use crate::types::SendResult;
use crate::{
    error::OcWalletError,
    ops::{decrypt_signing_key, parse_chain},
};

/// Sign and broadcast a transaction. Returns the transaction hash.
///
/// The `passphrase` parameter accepts either the owner's passphrase or an
/// API token (`oc_key_...`). When a token is provided, policy enforcement
/// occurs before signing.
#[cfg(feature = "rpc")]
pub fn sign_and_send(
    wallet: &str,
    chain: &str,
    tx_hex: &str,
    passphrase: Option<&str>,
    index: Option<u32>,
    rpc_url: Option<&str>,
    vault_path: Option<&Path>,
) -> Result<SendResult, OcWalletError> {
    let credential = passphrase.unwrap_or("");

    let tx_hex_clean = tx_hex.strip_prefix("0x").unwrap_or(tx_hex);
    let tx_bytes = hex::decode(tx_hex_clean)
        .map_err(|e| OcWalletError::InvalidInput(format!("invalid hex transaction: {e}")))?;

    // Agent mode: enforce policies, decrypt key, then sign + broadcast
    if credential.starts_with(crate::key_store::TOKEN_PREFIX) {
        let chain_info = parse_chain(chain)?;
        let (key, _) = crate::key_ops::enforce_policy_and_decrypt_key(
            credential,
            wallet,
            &chain_info,
            &tx_bytes,
            index,
            vault_path,
        )?;
        return sign_encode_and_broadcast(key.expose(), chain, &tx_bytes, rpc_url);
    }

    // Owner mode
    let chain_info = parse_chain(chain)?;
    let key = decrypt_signing_key(
        wallet,
        chain_info.chain_type,
        credential.as_bytes(),
        index,
        vault_path,
    )?;

    sign_encode_and_broadcast(key.expose(), chain, &tx_bytes, rpc_url)
}

/// Sign, encode, and broadcast a transaction using an already-resolved private key.
///
/// This is the shared core of the send-transaction flow. Both the library's
/// [`sign_and_send`] (which resolves keys from the vault) and the CLI (which
/// resolves keys via env vars / stdin prompts) delegate here so the
/// sign → encode → broadcast pipeline is never duplicated.
#[cfg(feature = "rpc")]
pub fn sign_encode_and_broadcast(
    private_key: &[u8],
    chain: &str,
    tx_bytes: &[u8],
    rpc_url: Option<&str>,
) -> Result<SendResult, OcWalletError> {
    let chain = parse_chain(chain)?;
    let signer = signer_for_chain(chain.chain_type);

    // 1. Extract signable portion (strips signature-slot headers for Solana; no-op for others)
    let signable = signer.extract_signable_bytes(tx_bytes)?;

    // 2. Sign
    let output = signer.sign_transaction(private_key, signable)?;

    // 3. Encode the full signed transaction
    let signed_tx = signer.encode_signed_transaction(tx_bytes, &output)?;

    // 4. Resolve RPC URL using exact chain_id
    let rpc = resolve_rpc_url(chain.chain_id, chain.chain_type, rpc_url)?;

    // 5. Broadcast the full signed transaction
    let tx_hash = broadcast(chain.chain_type, &rpc, &signed_tx)?;

    Ok(SendResult { tx_hash })
}

// --- internal helpers ---

/// Resolve the RPC URL: explicit > config override (exact chain_id) > config (namespace) > built-in
/// default.
#[cfg(feature = "rpc")]
fn resolve_rpc_url(
    chain_id: &str,
    chain_type: ChainType,
    explicit: Option<&str>,
) -> Result<String, OcWalletError> {
    if let Some(url) = explicit {
        return Ok(url.to_string());
    }

    let config = Config::load_or_default();
    let defaults = Config::default_rpc();

    // Try exact chain_id match first
    if let Some(url) = config.rpc.get(chain_id) {
        return Ok(url.clone());
    }
    if let Some(url) = defaults.get(chain_id) {
        return Ok(url.clone());
    }

    // Fallback to namespace match
    let namespace = chain_type.namespace();
    for (key, url) in &config.rpc {
        if key.starts_with(namespace) {
            return Ok(url.clone());
        }
    }
    for (key, url) in &defaults {
        if key.starts_with(namespace) {
            return Ok(url.clone());
        }
    }

    Err(OcWalletError::InvalidInput(format!("no RPC URL configured for chain '{chain_id}'")))
}

/// Broadcast a signed transaction via hpx, dispatching per chain type.
#[cfg(feature = "rpc")]
fn broadcast(
    chain: ChainType,
    rpc_url: &str,
    signed_bytes: &[u8],
) -> Result<String, OcWalletError> {
    match chain {
        ChainType::Evm => broadcast_evm(rpc_url, signed_bytes),
        ChainType::Solana => broadcast_solana(rpc_url, signed_bytes),
        ChainType::Bitcoin => broadcast_bitcoin(rpc_url, signed_bytes),
        ChainType::Cosmos => broadcast_cosmos(rpc_url, signed_bytes),
        ChainType::Tron => broadcast_tron(rpc_url, signed_bytes),
        ChainType::Ton => broadcast_ton(rpc_url, signed_bytes),
        ChainType::Spark => {
            Err(OcWalletError::InvalidInput("broadcast not yet supported for Spark".into()))
        }
        ChainType::Filecoin => {
            Err(OcWalletError::InvalidInput("broadcast not yet supported for Filecoin".into()))
        }
        #[cfg(feature = "sui-grpc")]
        ChainType::Sui => broadcast_sui(rpc_url, signed_bytes),
        #[cfg(not(feature = "sui-grpc"))]
        ChainType::Sui => {
            Err(OcWalletError::InvalidInput("sui-grpc feature required for Sui broadcast".into()))
        }
        ChainType::Xrpl => broadcast_xrpl(rpc_url, signed_bytes),
        ChainType::Nano => broadcast_nano(rpc_url, signed_bytes),
        ChainType::Near => crate::near_rpc::broadcast_tx_commit(rpc_url, signed_bytes),
    }
}

#[cfg(feature = "rpc")]
fn broadcast_xrpl(rpc_url: &str, signed_bytes: &[u8]) -> Result<String, OcWalletError> {
    let tx_blob = hex::encode_upper(signed_bytes);
    let body = serde_json::json!({
        "method": "submit",
        "params": [{ "tx_blob": tx_blob }]
    });
    let resp_str = http_post_json(rpc_url, &body.to_string())?;
    let resp: serde_json::Value = serde_json::from_str(&resp_str)?;

    // Surface engine errors before trying to extract the hash.
    let engine_result = resp["result"]["engine_result"].as_str().unwrap_or("");
    if !engine_result.starts_with("tes") {
        let msg = resp["result"]["engine_result_message"].as_str().unwrap_or(engine_result);
        return Err(OcWalletError::BroadcastFailed(format!(
            "XRPL submit failed ({engine_result}): {msg}"
        )));
    }

    resp["result"]["tx_json"]["hash"].as_str().map(|s| s.to_string()).ok_or_else(|| {
        OcWalletError::BroadcastFailed(format!("no hash in XRPL response: {resp_str}"))
    })
}

#[cfg(feature = "rpc")]
fn broadcast_evm(rpc_url: &str, signed_bytes: &[u8]) -> Result<String, OcWalletError> {
    let hex_tx = format!("0x{}", hex::encode(signed_bytes));
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_sendRawTransaction",
        "params": [hex_tx],
        "id": 1
    });
    let resp = http_post_json(rpc_url, &body.to_string())?;
    extract_json_field(&resp, "result")
}

#[cfg(feature = "rpc")]
pub(crate) fn build_solana_rpc_body(signed_bytes: &[u8]) -> serde_json::Value {
    use base64::Engine;
    let b64_tx = base64::engine::general_purpose::STANDARD.encode(signed_bytes);
    serde_json::json!({
        "jsonrpc": "2.0",
        "method": "sendTransaction",
        "params": [b64_tx, {"encoding": "base64"}],
        "id": 1
    })
}

#[cfg(feature = "rpc")]
fn broadcast_solana(rpc_url: &str, signed_bytes: &[u8]) -> Result<String, OcWalletError> {
    let body = build_solana_rpc_body(signed_bytes);
    let resp = http_post_json(rpc_url, &body.to_string())?;
    extract_json_field(&resp, "result")
}

#[cfg(feature = "rpc")]
fn broadcast_bitcoin(rpc_url: &str, signed_bytes: &[u8]) -> Result<String, OcWalletError> {
    let hex_tx = hex::encode(signed_bytes);
    let url = format!("{}/tx", rpc_url.trim_end_matches('/'));
    let resp = http_post_text(&url, "text/plain", &hex_tx)?;
    let tx_hash = resp.trim().to_string();
    if tx_hash.is_empty() {
        return Err(OcWalletError::BroadcastFailed("empty response from broadcast".into()));
    }
    Ok(tx_hash)
}

#[cfg(feature = "rpc")]
fn broadcast_cosmos(rpc_url: &str, signed_bytes: &[u8]) -> Result<String, OcWalletError> {
    use base64::Engine;
    let b64_tx = base64::engine::general_purpose::STANDARD.encode(signed_bytes);
    let url = format!("{}/cosmos/tx/v1beta1/txs", rpc_url.trim_end_matches('/'));
    let body = serde_json::json!({
        "tx_bytes": b64_tx,
        "mode": "BROADCAST_MODE_SYNC"
    });
    let resp = http_post_json(&url, &body.to_string())?;
    let parsed: serde_json::Value = serde_json::from_str(&resp)?;
    parsed["tx_response"]["txhash"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| OcWalletError::BroadcastFailed(format!("no txhash in response: {resp}")))
}

#[cfg(feature = "rpc")]
fn broadcast_tron(rpc_url: &str, signed_bytes: &[u8]) -> Result<String, OcWalletError> {
    let hex_tx = hex::encode(signed_bytes);
    let url = format!("{}/wallet/broadcasthex", rpc_url.trim_end_matches('/'));
    let body = serde_json::json!({ "transaction": hex_tx });
    let resp = http_post_json(&url, &body.to_string())?;
    extract_json_field(&resp, "txid")
}

#[cfg(feature = "rpc")]
fn broadcast_ton(rpc_url: &str, signed_bytes: &[u8]) -> Result<String, OcWalletError> {
    use base64::Engine;
    let b64_boc = base64::engine::general_purpose::STANDARD.encode(signed_bytes);
    let url = format!("{}/sendBoc", rpc_url.trim_end_matches('/'));
    let body = serde_json::json!({ "boc": b64_boc });
    let resp = http_post_json(&url, &body.to_string())?;
    let parsed: serde_json::Value = serde_json::from_str(&resp)?;
    parsed["result"]["hash"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| OcWalletError::BroadcastFailed(format!("no hash in response: {resp}")))
}

#[cfg(feature = "sui-grpc")]
fn broadcast_sui(rpc_url: &str, signed_bytes: &[u8]) -> Result<String, OcWalletError> {
    use oc_signer::chains::sui::WIRE_SIG_LEN;

    if signed_bytes.len() <= WIRE_SIG_LEN {
        return Err(OcWalletError::InvalidInput(
            "signed transaction too short to contain tx + signature".into(),
        ));
    }

    let split = signed_bytes.len() - WIRE_SIG_LEN;
    let tx_part = &signed_bytes[..split];
    let sig_part = &signed_bytes[split..];

    crate::sui_grpc::execute_transaction(rpc_url, tx_part, sig_part)
}

#[cfg(feature = "rpc")]
fn broadcast_nano(rpc_url: &str, signed_bytes: &[u8]) -> Result<String, OcWalletError> {
    const STATE_BLOCK_LEN: usize = 176;
    const SIGNATURE_LEN: usize = 64;
    const SIGNED_BLOCK_LEN: usize = STATE_BLOCK_LEN + SIGNATURE_LEN;

    if signed_bytes.len() != SIGNED_BLOCK_LEN {
        return Err(OcWalletError::InvalidInput(format!(
            "Nano signed block must be {} bytes ({} block + {} sig), got {}",
            SIGNED_BLOCK_LEN,
            STATE_BLOCK_LEN,
            SIGNATURE_LEN,
            signed_bytes.len()
        )));
    }

    let block_bytes = &signed_bytes[..STATE_BLOCK_LEN];
    let signature = &signed_bytes[STATE_BLOCK_LEN..SIGNED_BLOCK_LEN];

    // Extract fields from the 176-byte canonical block
    let account: [u8; 32] = block_bytes[32..64]
        .try_into()
        .map_err(|_| OcWalletError::InvalidInput("invalid account bytes in block".into()))?;
    let previous = &block_bytes[64..96];
    let representative: [u8; 32] = block_bytes[96..128]
        .try_into()
        .map_err(|_| OcWalletError::InvalidInput("invalid representative bytes in block".into()))?;
    let balance_bytes: [u8; 16] = block_bytes[128..144]
        .try_into()
        .map_err(|_| OcWalletError::InvalidInput("invalid balance bytes in block".into()))?;
    let balance = u128::from_be_bytes(balance_bytes);
    let link = &block_bytes[144..STATE_BLOCK_LEN];

    let previous_is_zero = previous == [0u8; 32];

    let account_address = oc_signer::chains::nano::nano_address(&account);

    // Determine block subtype by querying current account balance
    let subtype = if previous_is_zero {
        "open"
    } else {
        match crate::nano_rpc::account_info(rpc_url, &account_address)? {
            Some(info) => {
                let prev_balance: u128 = info.balance.parse().unwrap_or(0);
                if balance < prev_balance { "send" } else { "receive" }
            }
            None => "open",
        }
    };

    let difficulty = match subtype {
        "send" => crate::nano_rpc::SEND_DIFFICULTY,
        _ => crate::nano_rpc::RECEIVE_DIFFICULTY,
    };

    // PoW root: for open blocks, use account pubkey; otherwise use previous hash
    let work_root = if previous_is_zero { hex::encode(account) } else { hex::encode(previous) };

    let work = crate::nano_rpc::work_generate(rpc_url, &work_root, difficulty)?;

    let block_json = serde_json::json!({
        "type": "state",
        "account": account_address,
        "previous": hex::encode(previous),
        "representative": oc_signer::chains::nano::nano_address(&representative),
        "balance": balance.to_string(),
        "link": hex::encode(link),
        "signature": hex::encode(signature),
        "work": work
    });

    crate::nano_rpc::process_block(rpc_url, &block_json, subtype)
}

#[cfg(feature = "rpc")]
pub(crate) fn http_post_json(url: &str, body: &str) -> Result<String, OcWalletError> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| OcWalletError::BroadcastFailed(format!("failed to create runtime: {e}")))?;

    rt.block_on(async {
        let client = hpx::Client::new();
        let resp = client
            .post(url)
            .header("Content-Type", "application/json")
            .body(body.to_string())
            .send()
            .await
            .map_err(|e| OcWalletError::BroadcastFailed(format!("broadcast failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(OcWalletError::BroadcastFailed(format!(
                "broadcast failed (HTTP {status}): {text}"
            )));
        }

        resp.text()
            .await
            .map_err(|e| OcWalletError::BroadcastFailed(format!("broadcast failed: {e}")))
    })
}

#[cfg(feature = "rpc")]
fn http_post_text(url: &str, content_type: &str, body: &str) -> Result<String, OcWalletError> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| OcWalletError::BroadcastFailed(format!("failed to create runtime: {e}")))?;

    rt.block_on(async {
        let client = hpx::Client::new();
        let resp = client
            .post(url)
            .header("Content-Type", content_type)
            .body(body.to_string())
            .send()
            .await
            .map_err(|e| OcWalletError::BroadcastFailed(format!("broadcast failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(OcWalletError::BroadcastFailed(format!(
                "broadcast failed (HTTP {status}): {text}"
            )));
        }

        resp.text()
            .await
            .map_err(|e| OcWalletError::BroadcastFailed(format!("broadcast failed: {e}")))
    })
}

#[cfg(feature = "rpc")]
fn extract_json_field(json_str: &str, field: &str) -> Result<String, OcWalletError> {
    let parsed: serde_json::Value = serde_json::from_str(json_str)?;

    if let Some(error) = parsed.get("error") {
        return Err(OcWalletError::BroadcastFailed(format!("RPC error: {error}")));
    }

    parsed[field].as_str().map(|s| s.to_string()).ok_or_else(|| {
        OcWalletError::BroadcastFailed(format!("no '{field}' in response: {json_str}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "rpc")]
    fn solana_broadcast_body_includes_encoding_param() {
        let dummy_tx = vec![0x01; 100];
        let body = build_solana_rpc_body(&dummy_tx);

        assert_eq!(body["method"], "sendTransaction");
        assert_eq!(
            body["params"][1]["encoding"], "base64",
            "sendTransaction must specify encoding=base64 so Solana RPC \
             does not default to base58"
        );
    }

    #[test]
    #[cfg(feature = "rpc")]
    fn solana_broadcast_body_uses_base64_encoding() {
        use base64::Engine;
        let dummy_tx = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03];
        let body = build_solana_rpc_body(&dummy_tx);

        let encoded = body["params"][0].as_str().unwrap();
        // Must round-trip through base64
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .expect("params[0] should be valid base64");
        assert_eq!(decoded, dummy_tx, "base64 should round-trip to original bytes");
    }

    #[test]
    #[cfg(feature = "rpc")]
    fn solana_broadcast_body_is_not_hex_or_base58() {
        // Use bytes that would produce different strings in hex vs base64
        let dummy_tx = vec![0xFF; 50];
        let body = build_solana_rpc_body(&dummy_tx);

        let encoded = body["params"][0].as_str().unwrap();
        let hex_encoded = hex::encode(&dummy_tx);
        assert_ne!(encoded, hex_encoded, "broadcast should use base64, not hex");
        // base58 never contains '+' or '/' but base64 can
        // More importantly, verify it's NOT valid base58 for these bytes
        assert!(
            encoded.contains('/') || encoded.contains('+') || encoded.ends_with('='),
            "base64 of 0xFF bytes should contain characters absent from base58"
        );
    }

    #[test]
    #[cfg(feature = "rpc")]
    fn solana_broadcast_body_jsonrpc_structure() {
        let body = build_solana_rpc_body(&[0u8; 10]);
        assert_eq!(body["jsonrpc"], "2.0");
        assert_eq!(body["id"], 1);
        assert_eq!(body["method"], "sendTransaction");
        assert!(body["params"].is_array());
        assert_eq!(
            body["params"].as_array().unwrap().len(),
            2,
            "params should have [tx_data, options_object]"
        );
    }

    #[test]
    #[cfg(feature = "rpc")]
    #[ignore = "requires network access to Solana devnet"]
    fn solana_devnet_broadcast_encoding_accepted() {
        // Send a properly-structured Solana transaction to devnet.
        // The account is unfunded so the tx will fail, but the error should
        // NOT be about base58 encoding — proving the encoding fix works.

        // 1. Fetch a recent blockhash from devnet
        let bh_body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "getLatestBlockhash",
            "params": [],
            "id": 1
        });
        let bh_resp =
            http_post_json("https://api.devnet.solana.com", &bh_body.to_string()).unwrap();
        let bh_parsed: serde_json::Value = serde_json::from_str(&bh_resp).unwrap();
        let blockhash_b58 = bh_parsed["result"]["value"]["blockhash"]
            .as_str()
            .expect("devnet should return a blockhash");
        let blockhash = bs58::decode(blockhash_b58).into_vec().unwrap();
        assert_eq!(blockhash.len(), 32);

        // 2. Derive sender pubkey from test key
        let privkey =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap();
        let signing_key =
            ed25519_dalek::SigningKey::from_bytes(&privkey.clone().try_into().unwrap());
        let sender_pubkey = signing_key.verifying_key().to_bytes();

        // 3. Build a minimal SOL transfer message
        let recipient_pubkey = [0x01; 32]; // arbitrary recipient
        let system_program = [0u8; 32]; // 11111..1 in base58 = all zeros

        let mut message = vec![
            1, // num_required_signatures
            0, // num_readonly_signed_accounts
            1, // num_readonly_unsigned_accounts
            3, // num_account_keys (compact-u16)
        ];
        message.extend_from_slice(&sender_pubkey);
        message.extend_from_slice(&recipient_pubkey);
        message.extend_from_slice(&system_program);
        // Recent blockhash
        message.extend_from_slice(&blockhash);
        // Instructions
        message.push(1); // num_instructions (compact-u16)
        message.push(2); // program_id_index (system program)
        message.push(2); // num_accounts
        message.push(0); // from
        message.push(1); // to
        message.push(12); // data_length
        message.extend_from_slice(&2u32.to_le_bytes()); // transfer opcode
        message.extend_from_slice(&1u64.to_le_bytes()); // 1 lamport

        // 4. Build full transaction envelope
        let mut tx_bytes = vec![0x01u8]; // 1 signature slot
        tx_bytes.extend_from_slice(&[0u8; 64]); // placeholder
        tx_bytes.extend_from_slice(&message);

        // 5. Sign + encode + broadcast to devnet
        let result = sign_encode_and_broadcast(
            &privkey,
            "solana",
            &tx_bytes,
            Some("https://api.devnet.solana.com"),
        );

        // 6. Verify we don't get an encoding error
        match result {
            Ok(send_result) => {
                // Unlikely (unfunded) but fine
                assert!(!send_result.tx_hash.is_empty());
            }
            Err(e) => {
                let err_str = format!("{e}");
                assert!(
                    !err_str.contains("base58"),
                    "should not get base58 encoding error: {err_str}"
                );
                assert!(
                    !err_str.contains("InvalidCharacter"),
                    "should not get InvalidCharacter error: {err_str}"
                );
                // We expect errors like "insufficient funds" or simulation failure
            }
        }
    }
}
