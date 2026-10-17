use std::path::Path;

use crate::CliError;

pub(crate) fn run_init(
    dir: &Path,
    environment: &str,
    references: &[String],
) -> Result<(), CliError> {
    let bindings = references
        .iter()
        .map(|pair| {
            let (key, raw_reference, _reference) =
                super::env_support::parse_reference_binding(pair)?;
            Ok((key, raw_reference))
        })
        .collect::<Result<Vec<_>, CliError>>()?;

    std::fs::create_dir_all(dir)?;

    let manifest_path = dir.join(super::env_manifest::PROJECT_MANIFEST_RELATIVE_PATH);
    let mut manifest = if manifest_path.exists() {
        super::env_manifest::EnvironmentManifest::load(&manifest_path)?
    } else {
        super::env_manifest::EnvironmentManifest::default()
    };
    manifest.upsert_bindings(environment, &bindings);
    manifest.save(&manifest_path)?;

    let mcp_args = vec![
        "mcp".to_string(),
        "serve".to_string(),
        "--environment".to_string(),
        environment.to_string(),
    ];

    write_json_mcp_config(&dir.join(".mcp.json"), &mcp_args)?;
    write_json_mcp_config(&dir.join(".cursor/mcp.json"), &mcp_args)?;
    write_codex_config(&dir.join(".codex/config.toml"), &mcp_args)?;

    println!(
        "initialized OneCipher plugin config in {} for environment '{}'",
        dir.display(),
        environment
    );
    Ok(())
}

fn write_json_mcp_config(path: &Path, args: &[String]) -> Result<(), CliError> {
    let mut root = if path.exists() {
        serde_json::from_str::<serde_json::Value>(&std::fs::read_to_string(path)?).map_err(|e| {
            CliError::InvalidArgs(format!(
                "failed to parse existing MCP config {}: {e}",
                path.display()
            ))
        })?
    } else {
        serde_json::json!({})
    };

    let root_obj = root.as_object_mut().ok_or_else(|| {
        CliError::InvalidArgs(format!(
            "existing MCP config {} must be a JSON object",
            path.display()
        ))
    })?;
    let servers = root_obj.entry("mcpServers".to_string()).or_insert_with(|| serde_json::json!({}));
    let servers_obj = servers.as_object_mut().ok_or_else(|| {
        CliError::InvalidArgs(format!(
            "existing MCP config {} has non-object mcpServers",
            path.display()
        ))
    })?;
    servers_obj.insert(
        "onecipher".to_string(),
        serde_json::json!({
            "command": "onecipher",
            "args": args,
        }),
    );

    write_regular_file(path, &serde_json::to_vec_pretty(&root)?)?;
    Ok(())
}

fn write_codex_config(path: &Path, args: &[String]) -> Result<(), CliError> {
    let mut root = if path.exists() {
        toml::from_str::<toml::Value>(&std::fs::read_to_string(path)?).map_err(|e| {
            CliError::InvalidArgs(format!(
                "failed to parse existing Codex config {}: {e}",
                path.display()
            ))
        })?
    } else {
        toml::Value::Table(toml::map::Map::new())
    };

    let root_table = root.as_table_mut().ok_or_else(|| {
        CliError::InvalidArgs(format!(
            "existing Codex config {} must be a TOML table",
            path.display()
        ))
    })?;
    let entry = root_table
        .entry("mcp_servers".to_string())
        .or_insert_with(|| toml::Value::Table(toml::map::Map::new()));
    let servers = entry.as_table_mut().ok_or_else(|| {
        CliError::InvalidArgs(format!(
            "existing Codex config {} has non-table mcp_servers",
            path.display()
        ))
    })?;

    let mut onecipher = toml::map::Map::new();
    onecipher.insert("command".to_string(), toml::Value::String("onecipher".to_string()));
    onecipher.insert(
        "args".to_string(),
        toml::Value::Array(args.iter().cloned().map(toml::Value::String).collect()),
    );
    servers.insert("onecipher".to_string(), toml::Value::Table(onecipher));

    let body = toml::to_string_pretty(&root).map_err(|e| {
        CliError::InvalidArgs(format!("failed to render Codex config {}: {e}", path.display()))
    })?;
    write_regular_file(path, body.as_bytes())?;
    Ok(())
}

fn write_regular_file(path: &Path, body: &[u8]) -> Result<(), CliError> {
    let parent = path
        .parent()
        .ok_or_else(|| CliError::InvalidArgs(format!("path has no parent: {}", path.display())))?;
    std::fs::create_dir_all(parent)?;
    oc_core::paths::write_atomic(path, body, oc_core::paths::MODE_REGULAR_FILE)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_writes_manifest_and_configs() {
        let dir = tempfile::tempdir().unwrap();
        run_init(dir.path(), "dev", &["OPENAI_API_KEY=oc://api/openai".to_string()]).unwrap();

        assert!(dir.path().join(".onecipher/environments.toml").exists());
        assert!(dir.path().join(".mcp.json").exists());
        assert!(dir.path().join(".cursor/mcp.json").exists());
        assert!(dir.path().join(".codex/config.toml").exists());

        let claude = std::fs::read_to_string(dir.path().join(".mcp.json")).unwrap();
        assert!(claude.contains("\"serve\""));
        assert!(claude.contains("\"--environment\""));
        assert!(!claude.contains("--manifest"));
    }
}
