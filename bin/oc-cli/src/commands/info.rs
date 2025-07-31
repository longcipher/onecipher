use oc_core::Config;

use crate::CliError;

pub(crate) fn run() -> Result<(), CliError> {
    let config = Config::default();

    println!("Vault path: {}", config.vault_path.display());
    println!();
    println!("Supported chains:");
    println!("{:<12} {:<10} {:<10}", "Chain", "Namespace", "Coin Type");
    println!("{:<12} {:<10} {:<10}", "-----", "---------", "---------");

    let chains = oc_core::ALL_CHAIN_TYPES;

    for chain in chains {
        println!("{:<12} {:<10} {:<10}", chain, chain.namespace(), chain.default_coin_type());
    }

    Ok(())
}
