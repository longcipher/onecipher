use oc_core::{ALL_CHAIN_TYPES, default_chain_for_type};
use oc_signer::{HdDeriver, Mnemonic, signer_for_chain};
use zeroize::Zeroize;

use crate::{CliError, parse_chain};

pub(crate) fn run(chain_str: Option<&str>, index: u32) -> Result<(), CliError> {
    let mut mnemonic_str = super::read_mnemonic()?;
    let mnemonic = Mnemonic::from_phrase(&mnemonic_str)?;
    mnemonic_str.zeroize();

    if let Some(cs) = chain_str {
        // Derive for a single chain
        let chain = parse_chain(cs)?;
        let signer = signer_for_chain(chain.chain_type);
        let path = signer.default_derivation_path(index);
        let curve = signer.curve();

        let key = HdDeriver::derive_from_mnemonic_cached(&mnemonic, "", &path, curve)?;
        let address = signer.derive_address(key.expose())?;

        println!("{address}");
    } else {
        // Derive for all chains
        for ct in &ALL_CHAIN_TYPES {
            let chain = default_chain_for_type(*ct);
            let signer = signer_for_chain(*ct);
            let path = signer.default_derivation_path(index);
            let curve = signer.curve();

            let key = HdDeriver::derive_from_mnemonic_cached(&mnemonic, "", &path, curve)?;
            let address = signer.derive_address(key.expose())?;

            println!("{} → {}", chain.chain_id, address);
        }
    }

    Ok(())
}
