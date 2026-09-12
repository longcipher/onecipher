use oc_signer::{chains::EvmSigner, signer_for_chain};

use crate::{CliError, parse_chain};

pub(crate) fn run(
    chain_str: &str,
    wallet_name: &str,
    message: Option<&str>,
    encoding: &str,
    typed_data: Option<&str>,
    index: u32,
    json_output: bool,
) -> Result<(), CliError> {
    if typed_data.is_none() && message.is_none() {
        return Err(CliError::InvalidArgs("a --message (or --typed-data) is required".into()));
    }

    // Check for API token in passphrase — route through library for policy enforcement
    let passphrase = super::peek_passphrase();
    if passphrase.as_deref().is_some_and(|p| oc_core::Credential::parse(p).is_token()) {
        if let Some(td_json) = typed_data {
            let result = oc_wallet::sign_typed_data(
                wallet_name,
                chain_str,
                td_json,
                passphrase.as_deref(),
                Some(index),
                None,
            )?;
            return print_result(&result.signature, result.recovery_id, json_output);
        }
        let result = oc_wallet::sign_message(
            wallet_name,
            chain_str,
            message.unwrap_or_default(),
            passphrase.as_deref(),
            Some(encoding),
            Some(index),
            None,
        )?;
        return print_result(&result.signature, result.recovery_id, json_output);
    }

    // Owner mode via per-request enclave (default): decrypt→sign→wipe runs
    // in a subprocess; the parent only encodes and forwards.
    if crate::enclave_spawn::signing_enclave_enabled() {
        return run_enclave(
            chain_str,
            wallet_name,
            message,
            encoding,
            typed_data,
            index,
            json_output,
        );
    }

    // Owner mode: resolve key directly (in-process fallback for tests /
    // `OC_ENCLAVE=off` only).
    let chain = parse_chain(chain_str)?;
    let key = super::resolve_signing_key(wallet_name, chain.chain_type, index)?;

    let signer = signer_for_chain(chain.chain_type);

    let output = if let Some(td_json) = typed_data {
        if chain.chain_type != oc_core::ChainType::Evm {
            return Err(CliError::InvalidArgs(
                "--typed-data is only supported for EVM chains".into(),
            ));
        }
        EvmSigner.sign_typed_data(key.expose(), td_json)?
    } else {
        let message = message.unwrap_or_default();
        let msg_bytes = match encoding {
            "utf8" => message.as_bytes().to_vec(),
            "hex" => hex::decode(message)
                .map_err(|e| CliError::InvalidArgs(format!("invalid hex message: {e}")))?,
            _ => {
                return Err(CliError::InvalidArgs(format!(
                    "unsupported encoding: {encoding} (use 'utf8' or 'hex')"
                )))
            }
        };
        signer.sign_message(key.expose(), &msg_bytes)?
    };

    print_result(&hex::encode(&output.signature), output.recovery_id, json_output)
}

/// Owner-mode signing through the per-request enclave child.
///
/// Resolves the owner credential (env passphrase or interactive prompt),
/// forwards one passphrase-mode request, and prints the result. On a decrypt
/// failure with an interactive terminal, prompts once and retries — mirroring
/// `resolve_signing_key`'s try-empty-then-prompt behavior.
fn run_enclave(
    chain_str: &str,
    wallet_name: &str,
    message: Option<&str>,
    encoding: &str,
    typed_data: Option<&str>,
    index: u32,
    json_output: bool,
) -> Result<(), CliError> {
    let chain = parse_chain(chain_str)?;
    let (op, payload_hex, extra_json) = if let Some(td_json) = typed_data {
        if chain.chain_type != oc_core::ChainType::Evm {
            return Err(CliError::InvalidArgs(
                "--typed-data is only supported for EVM chains".into(),
            ));
        }
        (oc_keyagent::enclave::OP_SIGN_TYPED_DATA, String::new(), td_json.to_string())
    } else {
        let message = message.unwrap_or_default();
        let msg_bytes = match encoding {
            "utf8" => message.as_bytes().to_vec(),
            "hex" => hex::decode(message)
                .map_err(|e| CliError::InvalidArgs(format!("invalid hex message: {e}")))?,
            _ => {
                return Err(CliError::InvalidArgs(format!(
                    "unsupported encoding: {encoding} (use 'utf8' or 'hex')"
                )));
            }
        };
        (oc_keyagent::enclave::OP_SIGN_MESSAGE, hex::encode(&msg_bytes), String::new())
    };

    let mut credential = match super::peek_passphrase() {
        Some(p) => zeroize::Zeroizing::new(p),
        None => super::read_passphrase(),
    };
    let mut retried = false;
    loop {
        let mut req = crate::enclave_spawn::fresh_request(op, wallet_name, chain_str);
        req.payload_hex = payload_hex.clone();
        req.extra_json = extra_json.clone();
        req.index = index;
        req.credential_hex =
            Some(crate::enclave_spawn::passphrase_credential_hex(credential.as_str()));
        match crate::enclave_spawn::spawn_enclave(&req) {
            Ok(resp) => {
                let signature =
                    crate::enclave_spawn::response_hex(resp.signature_hex.as_ref(), "signature")
                        .map_err(CliError::KeyAgent)?;
                return print_result(&hex::encode(&signature), resp.recovery_id, json_output);
            }
            Err(e) if e.contains("E_DECRYPT") && !retried && super::is_interactive_stdin() => {
                retried = true;
                credential = super::read_passphrase();
            }
            Err(e) => return Err(CliError::KeyAgent(e)),
        }
    }
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
