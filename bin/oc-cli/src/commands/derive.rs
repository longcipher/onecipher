use oc_core::{ALL_CHAIN_TYPES, default_chain_for_type};
use oc_signer::{HdDeriver, Mnemonic, signer_for_chain};
use zeroize::Zeroize;

use crate::{CliError, parse_chain};

pub(crate) fn run(
    chain_str: Option<&str>,
    index: u32,
    path: Option<&str>,
    count: Option<u32>,
    show_private_key: bool,
) -> Result<(), CliError> {
    let mut mnemonic_str = super::read_mnemonic()?;
    let mnemonic = Mnemonic::from_phrase(&mnemonic_str)?;
    mnemonic_str.zeroize();

    if let Some(cs) = chain_str {
        // Derive for a single chain
        let chain = parse_chain(cs)?;
        let signer = signer_for_chain(chain.chain_type);
        let curve = signer.curve();

        let derive_count = count.unwrap_or(1);
        for i in 0..derive_count {
            let derivation_path = if let Some(p) = path {
                // Replace trailing index in custom path if deriving multiple
                if derive_count > 1 {
                    return Err(CliError::InvalidArgs(
                        "--count is not supported with --path (use --path with different values instead)".into(),
                    ));
                }
                p.to_string()
            } else {
                signer.default_derivation_path(index + i)
            };

            let key =
                HdDeriver::derive_from_mnemonic_cached(&mnemonic, "", &derivation_path, curve)?;
            let address = signer.derive_address(key.expose())?;

            if derive_count > 1 {
                print!("[{}] ", index + i);
            }
            print!("{address}");
            if show_private_key {
                print!("  {}", hex::encode(key.expose()));
            }
            println!();
        }
    } else {
        // Derive for all chains
        for ct in &ALL_CHAIN_TYPES {
            let chain = default_chain_for_type(*ct);
            let signer = signer_for_chain(*ct);
            let path = if let Some(p) = path {
                p.to_string()
            } else {
                signer.default_derivation_path(index)
            };
            let curve = signer.curve();

            let key = HdDeriver::derive_from_mnemonic_cached(&mnemonic, "", &path, curve)?;
            let address = signer.derive_address(key.expose())?;

            print!("{} → {}", chain.chain_id, address);
            if show_private_key {
                print!("  {}", hex::encode(key.expose()));
            }
            println!();
        }
    }

    Ok(())
}
