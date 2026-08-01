use oc_signer::chains::EvmSigner;

use crate::{CliError, parse_chain};

pub(crate) fn run(
    chain_str: &str,
    wallet_name: &str,
    address: &str,
    nonce: &str,
    index: u32,
    json_output: bool,
) -> Result<(), CliError> {
    let chain = parse_chain(chain_str)?;
    if chain.chain_type != oc_core::ChainType::Evm {
        return Err(CliError::InvalidArgs(
            "EIP-7702 authorization signing is only supported for EVM chains".into(),
        ));
    }

    // Extract the eip155 chain ID number
    let auth_chain_id = chain.chain_id.strip_prefix("eip155:").ok_or_else(|| {
        CliError::InvalidArgs(format!(
            "EVM chain '{}' is missing an eip155 reference",
            chain.chain_id
        ))
    })?;

    // Compute the authorization hash
    let evm_signer = EvmSigner;
    let hash = evm_signer.authorization_hash(auth_chain_id, address, nonce)?;

    // Resolve signing key
    let key = super::resolve_signing_key(wallet_name, chain.chain_type, index)?;

    // Sign the hash
    let signer = oc_signer::signer_for_chain(chain.chain_type);
    let output = signer.sign(key.expose(), &hash)?;

    // EIP-7702 convention: v = 27 + recovery_id
    let mut sig_bytes = output.signature;
    if sig_bytes.len() == 65 {
        let v = sig_bytes[64];
        if v < 27 {
            sig_bytes[64] = v + 27;
        }
    }

    if json_output {
        let obj = serde_json::json!({
            "chain_id": chain.chain_id,
            "delegate": address,
            "nonce": nonce,
            "signature": format!("0x{}", hex::encode(&sig_bytes)),
            "authorization_hash": format!("0x{}", hex::encode(hash)),
        });
        println!("{}", serde_json::to_string_pretty(&obj)?);
    } else {
        println!("{}", hex::encode(&sig_bytes));
    }

    Ok(())
}
