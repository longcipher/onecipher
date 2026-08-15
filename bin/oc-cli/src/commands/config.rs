use oc_core::Config;

use crate::CliError;

pub(crate) fn show() -> Result<(), CliError> {
    let config_path = oc_core::paths::config_path()?;
    let config_exists = config_path.exists();

    let config = Config::load_or_default();
    let defaults = Config::default_rpc();

    println!("Vault:  {}", config.vault_path.display());
    if config_exists {
        println!("Config: {}", config_path.display());
    } else {
        println!("Config: {} (not found — using defaults)", config_path.display());
    }

    println!();
    println!("RPC endpoints:");

    let mut keys: Vec<&String> = config.rpc.keys().collect();
    keys.sort();

    for key in keys {
        let url = &config.rpc[key];
        let annotation = match defaults.get(key) {
            Some(default_url) if default_url == url => "(default)",
            Some(_) => "(custom)",
            None => "(custom)",
        };
        println!("  {:<40} {} {}", key, url, annotation);
    }

    println!();
    println!("WalletConnect:");
    println!(
        "  {:<40} {}",
        "wc.relay_url",
        if config.wc.relay_url.is_empty() { "(default)" } else { &config.wc.relay_url }
    );
    println!(
        "  {:<40} {}",
        "wc.project_id",
        if config.wc.project_id.is_empty() { "(not set)" } else { &config.wc.project_id }
    );
    if config.wc.trusted_origins.is_empty() {
        println!("  {:<40} (none — deny all session proposals)", "wc.trusted_origins");
    } else {
        println!("  {:<40} {:?}", "wc.trusted_origins", config.wc.trusted_origins);
    }

    Ok(())
}

/// Set a configuration value by dot-separated key path.
///
/// Supported paths:
/// - `vault_path` (string)
/// - `rpc.<chain_id>` (string, e.g. `rpc.eip155:1`)
/// - `webui.enabled` (bool)
/// - `webui.approval_mode` (bool)
/// - `webui.approval_timeout_secs` (u64)
/// - `webui.listen` (string)
/// - `webui.session_timeout_secs` (u64)
/// - `webui.auto_lock_at` (string)
/// - `wc.relay_url` (string)
/// - `wc.project_id` (string)
/// - `wc.trusted_origins` (JSON array of strings, e.g. `["iam.example.com"]`)
pub(crate) fn set(key: &str, value: &str) -> Result<(), CliError> {
    let config_dir = oc_core::paths::state_dir()?;
    let config_path = config_dir.join("config.json");

    // Load existing config as raw JSON, or start from an empty object.
    let mut root: serde_json::Value = if config_path.exists() {
        let contents = std::fs::read_to_string(&config_path).map_err(CliError::Io)?;
        serde_json::from_str(&contents)
            .map_err(|e| CliError::InvalidArgs(format!("invalid config JSON: {e}")))?
    } else {
        serde_json::json!({})
    };

    // Validate the key is a known config path.
    let parts: Vec<&str> = key.splitn(2, '.').collect();
    let new_value = match parts.as_slice() {
        ["rpc", _chain_id] => serde_json::Value::String(value.to_string()),
        ["webui", field] => match *field {
            "enabled" | "approval_mode" => {
                let b = parse_bool(value)?;
                serde_json::Value::Bool(b)
            }
            "approval_timeout_secs" | "session_timeout_secs" => {
                let n: u64 = value
                    .parse()
                    .map_err(|_| CliError::InvalidArgs(format!("'{value}' is not a valid u64")))?;
                serde_json::Value::Number(n.into())
            }
            "listen" | "auto_lock_at" => serde_json::Value::String(value.to_string()),
            _ => {
                return Err(CliError::InvalidArgs(format!(
                    "unknown webui field '{field}'. Valid fields: enabled, approval_mode, approval_timeout_secs, listen, session_timeout_secs, auto_lock_at"
                )));
            }
        },
        ["wc", field] => match *field {
            "relay_url" | "project_id" => serde_json::Value::String(value.to_string()),
            "trusted_origins" => {
                // Accept a JSON array (e.g. `["iam.example.com","x.com"]`) or a
                // comma-separated plain list for convenience.
                let parsed: serde_json::Value = serde_json::from_str(value).map_err(|_| {
                    CliError::InvalidArgs(format!(
                        "'{value}' is not a valid JSON array (e.g. '[\"iam.example.com\"]')"
                    ))
                })?;
                let array = parsed.as_array().ok_or_else(|| {
                    CliError::InvalidArgs(
                        "wc.trusted_origins must be a JSON array of strings (e.g. '[\"iam.example.com\"]')"
                            .into(),
                    )
                })?;
                for item in array {
                    if !item.is_string() {
                        return Err(CliError::InvalidArgs(
                            "wc.trusted_origins must contain only strings".into(),
                        ));
                    }
                }
                parsed
            }
            _ => {
                return Err(CliError::InvalidArgs(format!(
                    "unknown wc field '{field}'. Valid fields: relay_url, project_id, trusted_origins"
                )));
            }
        },
        ["vault_path"] => serde_json::Value::String(value.to_string()),
        _ => {
            return Err(CliError::InvalidArgs(format!(
                "unknown config key '{key}'. Valid top-level keys: vault_path, rpc.<chain>, webui.<field>, wc.<field>"
            )));
        }
    };

    // Navigate the JSON tree and set the value.
    match parts.as_slice() {
        [section, field] => {
            // Ensure the parent object exists.
            if root.get(section).is_none() || !root[section].is_object() {
                root[section] = serde_json::json!({});
            }
            root[section][*field] = new_value;
        }
        [top_key] => {
            root[*top_key] = new_value;
        }
        _ => unreachable!(),
    }

    // Ensure the config directory exists.
    std::fs::create_dir_all(&config_dir).map_err(CliError::Io)?;

    // Write back with pretty formatting.
    let json = serde_json::to_string_pretty(&root)
        .map_err(|e| CliError::InvalidArgs(format!("failed to serialize config: {e}")))?;
    std::fs::write(&config_path, json).map_err(CliError::Io)?;

    println!("Set {key} = {value}");
    println!("Config: {}", config_path.display());

    Ok(())
}

fn parse_bool(s: &str) -> Result<bool, CliError> {
    match s {
        "true" | "1" | "yes" | "on" => Ok(true),
        "false" | "0" | "no" | "off" => Ok(false),
        _ => Err(CliError::InvalidArgs(format!(
            "'{s}' is not a valid boolean (use true/false/yes/no/on/off/1/0)"
        ))),
    }
}
