//! SBOM CLI (T41). Verifies CycloneDX SBOM files.
//!
//! `onecipher sbom verify --file <path>`
//!
//! Performs basic structural validation of a CycloneDX SBOM JSON file:
//! - File exists and parses as JSON
//! - Top-level `bomFormat` field equals `"CycloneDX"`
//! - Top-level `components` field is an array (may be empty)
//! - Each component has `name`, `version`, and a source identifier (`purl` or `cpe`). The CycloneDX
//!   spec allows either; we accept both.

use std::{fs, path::Path};

use serde_json::Value;

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
