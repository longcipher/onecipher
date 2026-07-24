//! SBOM CLI (T41). Generates and verifies CycloneDX SBOM files.
//!
//! - `onecipher sbom generate --output <path>` — generate a CycloneDX SBOM
//! - `onecipher sbom verify --file <path>` — verify a CycloneDX SBOM
//!
//! Generation tries `cargo cyclonedx` first; falls back to a minimal SBOM
//! built from workspace crate names/versions in Cargo.toml.
//!
//! Verification performs basic structural validation of a CycloneDX SBOM JSON file:
//! - File exists and parses as JSON
//! - Top-level `bomFormat` field equals `"CycloneDX"`
//! - Top-level `components` field is an array (may be empty)
//! - Each component has `name`, `version`, and a source identifier (`purl` or `cpe`). The CycloneDX
//!   spec allows either; we accept both.

use std::{fs, path::Path, process::Command};

use serde_json::{json, Value};

use crate::CliError;

/// Entry point for `onecipher sbom verify --file <path>`.
///
/// Reads the JSON file at `file`, parses it, and validates the CycloneDX
/// structural requirements. Returns `Ok(())` on success and a `CliError` on
/// any validation failure (missing file, malformed JSON, missing/invalid
/// CycloneDX fields).
pub(crate) fn verify(file: &str) -> Result<(), CliError> {
    let path = Path::new(file);
    if !path.exists() {
        return Err(CliError::InvalidArgs(format!("SBOM file not found: {file}")));
    }
    let bytes = fs::read(path)?;
    let value: Value = serde_json::from_slice(&bytes)?;

    // bomFormat MUST be "CycloneDX".
    let bom_format = value.get("bomFormat").and_then(|v| v.as_str()).ok_or_else(|| {
        CliError::InvalidArgs("SBOM missing required field `bomFormat`".to_string())
    })?;
    if bom_format != "CycloneDX" {
        return Err(CliError::InvalidArgs(format!(
            "SBOM `bomFormat` must be \"CycloneDX\", got \"{bom_format}\""
        )));
    }

    // `components` MUST be an array.
    let components = value.get("components").and_then(|v| v.as_array()).ok_or_else(|| {
        CliError::InvalidArgs("SBOM missing required field `components` (array)".to_string())
    })?;

    // Each component must have name, version, and a source identifier (purl
    // or cpe). Empty components arrays are valid (e.g. for a workspace with
    // no dependencies — unlikely for OneCipher, but spec-compliant).
    for (idx, comp) in components.iter().enumerate() {
        let name = comp.get("name").and_then(|v| v.as_str()).ok_or_else(|| {
            CliError::InvalidArgs(format!("SBOM component[{idx}] missing `name`"))
        })?;
        let has_version = comp.get("version").and_then(|v| v.as_str()).is_some();
        if !has_version {
            return Err(CliError::InvalidArgs(format!(
                "SBOM component \"{name}\" (index {idx}) missing `version`"
            )));
        }
        let has_source = comp.get("purl").and_then(|v| v.as_str()).is_some() ||
            comp.get("cpe").and_then(|v| v.as_str()).is_some();
        if !has_source {
            return Err(CliError::InvalidArgs(format!(
                "SBOM component \"{name}\" (index {idx}) missing source identifier (`purl` or `cpe`)"
            )));
        }
    }

    println!(
        "SBOM verified: {} ({}) — {} components",
        file,
        value.get("specVersion").and_then(|v| v.as_str()).unwrap_or("?"),
        components.len()
    );
    Ok(())
}

/// Entry point for `onecipher sbom generate --output <path>`.
///
/// Tries `cargo cyclonedx` first. If the tool is not installed, generates a
/// minimal CycloneDX SBOM from workspace crate names and versions read from
/// `Cargo.toml`.
pub(crate) fn generate(output: &str) -> Result<(), CliError> {
    // Try cargo cyclonedx first.
    if Command::new("cargo")
        .args(["cyclonedx", "--help"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
    {
        let status = Command::new("cargo")
            .args(["cyclonedx", "--output-file", output])
            .status()?;
        if status.success() {
            println!("SBOM generated via cargo-cyclonedx: {output}");
            return Ok(());
        }
        eprintln!("cargo cyclonedx failed, falling back to minimal SBOM generation");
    }

    // Fallback: build a minimal CycloneDX SBOM from workspace members.
    let manifest = fs::read_to_string("Cargo.toml")?;
    let doc: toml::Value =
        toml::from_str(&manifest).map_err(|e| CliError::InvalidArgs(format!("Cargo.toml: {e}")))?;

    let workspace_version = doc
        .get("workspace")
        .and_then(|w| w.get("package"))
        .and_then(|p| p.get("version"))
        .and_then(|v| v.as_str())
        .unwrap_or("0.0.0");

    let mut components = Vec::new();
    if let Some(members) = doc
        .get("workspace")
        .and_then(|w| w.get("members"))
        .and_then(|m| m.as_array())
    {
        for member in members {
            let name = member.as_str().unwrap_or_default();
            // Derive crate name from path (last segment, hyphens → underscores for crate name).
            let crate_name = name.rsplit('/').next().unwrap_or(name);
            components.push(json!({
                "type": "library",
                "name": crate_name,
                "version": workspace_version,
                "purl": format!("pkg:cargo/{crate_name}@{workspace_version}")
            }));
        }
    }

    let sbom = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "onecipher",
                "version": workspace_version
            }
        },
        "components": components
    });

    fs::write(output, serde_json::to_string_pretty(&sbom)?)?;
    println!("Minimal SBOM generated: {output} ({} components)", components.len());
    Ok(())
}
