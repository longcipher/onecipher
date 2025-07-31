use crate::CliError;

/// Create a new API key for agent access to wallets.
pub(crate) fn create(
    name: &str,
    wallet_names: &[String],
    policy_ids: &[String],
    expires_at: Option<&str>,
) -> Result<(), CliError> {
    if wallet_names.is_empty() {
        return Err(CliError::InvalidArgs("at least one --wallet is required".into()));
    }

    // Resolve wallet names to IDs
    let mut wallet_ids = Vec::with_capacity(wallet_names.len());
    for name_or_id in wallet_names {
        let info = oc_wallet::get_wallet(name_or_id, None)?;
        wallet_ids.push(info.id);
    }

    // Read passphrase (needed to decrypt wallet mnemonics for re-encryption)
    let passphrase = super::read_passphrase();

    let (token, key_file) = oc_wallet::key_ops::create_api_key(
        name,
        &wallet_ids,
        policy_ids,
        &passphrase,
        expires_at,
        None,
    )?;

    println!("API key created: {}", key_file.id);
    println!("Name:            {name}");
    println!("Wallets:         {}", wallet_ids.join(", "));
    if !policy_ids.is_empty() {
        println!("Policies:        {}", policy_ids.join(", "));
    }
    if let Some(exp) = &key_file.expires_at {
        println!("Expires:         {exp}");
    }
    println!();
    eprintln!("TOKEN (shown once — save it now):");
    println!("{token}");

    Ok(())
}

/// List all API keys (tokens are never shown).
pub(crate) fn list() -> Result<(), CliError> {
    let keys = oc_wallet::key_store::list_api_keys(None)?;

    if keys.is_empty() {
        println!("No API keys found.");
        return Ok(());
    }

    for k in &keys {
        println!("ID:       {}", k.id);
        println!("Name:     {}", k.name);
        println!("Wallets:  {}", k.wallet_ids.join(", "));
        println!("Policies: {}", k.policy_ids.join(", "));
        if let Some(ref exp) = k.expires_at {
            println!("Expires:  {exp}");
        }
        println!("Created:  {}", k.created_at);
        println!();
    }

    Ok(())
}

/// Revoke (delete) an API key.
pub(crate) fn revoke(id: &str, confirm: bool) -> Result<(), CliError> {
    if !confirm {
        eprintln!("To revoke an API key, pass --confirm.");
        return Err(CliError::InvalidArgs("--confirm is required to revoke an API key".into()));
    }

    let key = oc_wallet::key_store::load_api_key(id, None)?;
    oc_wallet::key_store::delete_api_key(id, None)?;

    println!("API key revoked: {} ({})", key.id, key.name);
    Ok(())
}
