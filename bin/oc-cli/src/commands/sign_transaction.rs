use std::fs;

use oc_signer::signer_for_chain;
use oc_walletconnect::WcDappClient;

use crate::{CliError, SignVia, parse_chain};

pub(crate) fn run(
    chain_str: &str,
    wallet_name: &str,
    tx_hex: &str,
    index: u32,
    json_output: bool,
    via: SignVia,
) -> Result<(), CliError> {
    match via {
        SignVia::Local => run_local(chain_str, wallet_name, tx_hex, index, json_output),
        SignVia::Wc => run_wc(tx_hex, json_output),
    }
}

fn run_local(
    chain_str: &str,
    wallet_name: &str,
    tx_hex: &str,
    index: u32,
    json_output: bool,
) -> Result<(), CliError> {
    // Check for API token in passphrase — route through library for policy enforcement
    let passphrase = super::peek_passphrase();
    if passphrase.as_deref().is_some_and(|p| p.starts_with(oc_wallet::key_store::TOKEN_PREFIX)) {
        let result = oc_wallet::sign_transaction(
            wallet_name,
            chain_str,
            tx_hex,
            passphrase.as_deref(),
            Some(index),
            None,
        )?;
        return print_result(&result.signature, result.recovery_id, json_output);
    }

    // Owner mode: resolve key directly (existing behavior)
    let chain = parse_chain(chain_str)?;
    let key = super::resolve_signing_key(wallet_name, chain.chain_type, index)?;

    let tx_hex_clean = tx_hex.strip_prefix("0x").unwrap_or(tx_hex);
    let tx_bytes = hex::decode(tx_hex_clean)
        .map_err(|e| CliError::InvalidArgs(format!("invalid hex transaction: {e}")))?;

    let signer = signer_for_chain(chain.chain_type);
    let signable = signer.extract_signable_bytes(&tx_bytes)?;
    let output = signer.sign_transaction(key.expose(), signable)?;

    print_result(&hex::encode(&output.signature), output.recovery_id, json_output)
}

fn run_wc(tx_hex: &str, json_output: bool) -> Result<(), CliError> {
    // Load stored pairing info
    let base = dirs::data_dir()
        .ok_or_else(|| CliError::InvalidArgs("cannot determine data directory".into()))?;
    let dapp_path = base.join("onecipher").join("wc_dapp.json");

    if !dapp_path.exists() {
        return Err(CliError::InvalidArgs(
            "no WalletConnect pairing found; run `onecipher wc connect <uri>` first".into(),
        ));
    }

    let data = fs::read_to_string(&dapp_path)?;
    let pairing: super::wc::StoredPairing = serde_json::from_str(&data)?;

    // ponytail: tokio runtime created per call; reuse a global if this is hot
    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| CliError::InvalidArgs(format!("tokio runtime: {e}")))?;

    rt.block_on(async {
        let client = WcDappClient::new();
        client.bind_session(pairing.topic.clone()).await;

        let params = serde_json::json!({
            "tx": tx_hex,
        });

        let result = client
            .request("onecipher_signTransaction", params)
            .await
            .map_err(|e| CliError::InvalidArgs(format!("WC request failed: {e}")))?;

        let sig = result["signature"]
            .as_str()
            .ok_or_else(|| CliError::InvalidArgs("WC response missing signature".into()))?;
        let recovery = result["recovery_id"].as_u64().map(|r| r as u8);

        print_result(sig, recovery, json_output)
    })
}

fn print_result(
    signature: &str,
    recovery_id: Option<u8>,
    json_output: bool,
) -> Result<(), CliError> {
    if json_output {
        let obj = serde_json::json!({
            "signature": signature,
            "recovery_id": recovery_id,
        });
        println!("{}", serde_json::to_string_pretty(&obj)?);
    } else {
        println!("{signature}");
    }
    Ok(())
}
