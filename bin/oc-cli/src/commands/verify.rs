//! Signature verification (`onecipher verify`).

use crate::CliError;

/// Parsed inputs for [`run`] (keeps the entry point below the clippy
/// argument-count ceiling).
pub(crate) struct VerifyInput<'a> {
    pub(crate) address: &'a str,
    pub(crate) message: Option<&'a str>,
    pub(crate) typed_data: Option<&'a str>,
    pub(crate) typed_data_file: Option<&'a str>,
    pub(crate) hash: Option<&'a str>,
    pub(crate) no_hash: bool,
    pub(crate) signature: &'a str,
    pub(crate) chain: &'a str,
}

/// Entry point for `onecipher verify`.
///
/// Verifies an ECDSA signature over a message, an EIP-712 typed-data payload
/// (`--typed-data` / `--typed-data-file`, hashed per EIP-712 and verified as
/// a raw digest — H-01), or a raw/explicit hash.
pub(crate) fn run(input: VerifyInput<'_>) -> Result<(), CliError> {
    let VerifyInput {
        address,
        message,
        typed_data,
        typed_data_file,
        hash,
        no_hash,
        signature,
        chain,
    } = input;
    let chain_parsed = oc_core::parse_chain(chain)
        .map_err(|e| CliError::InvalidArgs(format!("invalid chain: {e}")))?;
    if chain_parsed.chain_type != oc_core::ChainType::Evm {
        return Err(CliError::InvalidArgs(
            "verify is currently only supported for EVM chains".into(),
        ));
    }

    let sig_bytes = hex::decode(signature.strip_prefix("0x").unwrap_or(signature))
        .map_err(|e| CliError::InvalidArgs(format!("invalid signature hex: {e}")))?;

    // Load typed data from file when requested so both flags share one path.
    let td_from_file: Option<String> = match typed_data_file {
        Some(path) => Some(std::fs::read_to_string(path).map_err(|e| {
            CliError::InvalidArgs(format!("cannot read typed-data file '{path}': {e}"))
        })?),
        None => None,
    };
    let td_json: Option<&str> = typed_data.or(td_from_file.as_deref());

    let signer = oc_signer::signer_for_chain(chain_parsed.chain_type);
    let valid = if let Some(td) = td_json {
        // H-01: EIP-712 signatures are over the typed-data digest itself
        // (no EIP-191 personal_sign wrapping).
        let digest = oc_signer::eip712::parse_typed_data(td)
            .and_then(|td| oc_signer::eip712::hash_typed_data(&td))
            .map_err(|e| CliError::InvalidArgs(format!("invalid EIP-712 typed data: {e}")))?;
        signer.verify_hash(address, &digest, &sig_bytes)?
    } else if let Some(hash_hex) = hash {
        let hash_bytes = hex::decode(hash_hex.strip_prefix("0x").unwrap_or(hash_hex))
            .map_err(|e| CliError::InvalidArgs(format!("invalid hash hex: {e}")))?;
        if no_hash {
            signer.verify_hash(address, &hash_bytes, &sig_bytes)?
        } else {
            signer.verify_message(address, &hash_bytes, &sig_bytes)?
        }
    } else if let Some(msg) = message {
        signer.verify_message(address, msg.as_bytes(), &sig_bytes)?
    } else {
        return Err(CliError::InvalidArgs(
            "one of --message, --typed-data, --typed-data-file, or --hash is required".into(),
        ));
    };

    if valid {
        println!("Signature is valid.");
        Ok(())
    } else {
        println!("Signature is INVALID.");
        Err(CliError::InvalidArgs("signature verification failed".into()))
    }
}
