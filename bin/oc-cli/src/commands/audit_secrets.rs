//! Password security auditing for the secret store.
//!
//! Checks stored passwords for:
//! - **Weak passwords**: length < 12 or missing character classes.
//! - **Duplicate passwords**: same value used across multiple entries.
//! - **Breached passwords**: SHA-1 k-anonymity lookup via HIBP API.
//! - **Old passwords**: entries not updated within the configured max age.

use std::{collections::HashMap, io::Write};

use oc_core::ItemType;
use serde::Serialize;
use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::CliError;

/// Entry point for `onecipher audit secrets`.
pub(crate) fn run(format: &str, max_age: u64, skip_hibp: bool) -> Result<(), CliError> {
    let store = crate::commands::open_secret_store()?;
    let identity = crate::commands::load_age_identity()?;
    let entries = store.list()?;

    let mut total_scanned: usize = 0;
    let mut by_type: HashMap<&'static str, usize> = HashMap::new();

    // Audit findings.
    let mut weak: Vec<WeakFinding> = Vec::new();
    // sha256(password) → list of secret names with that password.
    let mut password_hashes: HashMap<String, Vec<String>> = HashMap::new();
    let mut breached: Vec<String> = Vec::new();
    let mut old: Vec<String> = Vec::new();

    let now = jiff::Timestamp::now();

    for idx_entry in &entries {
        total_scanned += 1;
        *by_type.entry(item_type_label(idx_entry.item_type)).or_insert(0) += 1;

        // Only do password-specific checks for Password entries.
        if idx_entry.item_type != ItemType::Password {
            continue;
        }

        // Check password age (updated_at timestamp).
        if let Ok(updated) = idx_entry.updated_at.parse::<jiff::Timestamp>() {
            let span = now.duration_since(updated);
            let days = span.as_secs() / 86_400;
            if days > i64::try_from(max_age).unwrap_or(i64::MAX) {
                old.push(idx_entry.name.clone());
            }
        }

        // Decrypt to get the actual password value.
        let entry = match store.get(&idx_entry.name) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("audit secrets: cannot read '{}': {e}", idx_entry.name);
                continue;
            }
        };
        let payload = match entry.decrypt(&identity) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("audit secrets: cannot decrypt '{}': {e}", idx_entry.name);
                continue;
            }
        };
        let password = &payload.secret;

        // Strength check.
        if let Some(reason) = check_strength(password) {
            weak.push(WeakFinding { name: idx_entry.name.clone(), reason });
        }

        // Duplicate detection via SHA-256.
        let hash = sha256_hex(password);
        password_hashes.entry(hash).or_default().push(idx_entry.name.clone());

        // HIBP breach check.
        if !skip_hibp {
            if matches!(check_hibp(password), Ok(true)) {
                breached.push(idx_entry.name.clone());
            }
        }
    }

    // Collect duplicate groups (more than one entry sharing the same hash).
    let duplicates: Vec<Vec<String>> =
        password_hashes.into_values().filter(|names| names.len() > 1).collect();

    match format {
        "json" => print_json(&by_type, total_scanned, &weak, &duplicates, &breached, &old),
        _ => print_text(&by_type, total_scanned, &weak, &duplicates, &breached, &old),
    }
}

// ── Strength check ────────────────────────────────────────────────────────

struct WeakFinding {
    name: String,
    reason: String,
}

/// Returns `Some(reason)` if the password is weak, `None` if it passes.
fn check_strength(password: &str) -> Option<String> {
    let len = password.chars().count();
    let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
    let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_special = password.chars().any(|c| !c.is_ascii_alphanumeric());

    if len < 12 {
        return Some(format!("too short ({len} chars, minimum 12)"));
    }
    let mut missing = Vec::new();
    if !has_upper {
        missing.push("uppercase");
    }
    if !has_lower {
        missing.push("lowercase");
    }
    if !has_digit {
        missing.push("digit");
    }
    if !has_special {
        missing.push("special char");
    }
    if !missing.is_empty() {
        return Some(format!("missing: {}", missing.join(", ")));
    }
    None
}

// ── Duplicate detection ───────────────────────────────────────────────────

/// SHA-256 hex digest of a password string.
fn sha256_hex(password: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hex::encode(hasher.finalize())
}

// ── HIBP breach check (k-anonymity) ──────────────────────────────────────

/// Check if a password appears in the HaveIBeenPwned database.
///
/// Uses the k-anonymity range API: SHA-1 the password, send the first 5 hex
/// chars, check if the remaining 35 chars appear in the response.
fn check_hibp(password: &str) -> Result<bool, CliError> {
    use sha1::Digest as Sha1Digest;
    let mut hasher = Sha1::new();
    hasher.update(password.as_bytes());
    let hash = hex::encode_upper(hasher.finalize());
    let prefix = &hash[..5];
    let suffix = &hash[5..];

    let url = format!("https://api.pwnedpasswords.com/range/{prefix}");

    let body = crate::shared_runtime().block_on(async {
        let client = hpx::Client::new();
        let resp = client
            .get(&url)
            .header("Add-Padding", "true")
            .send()
            .await
            .map_err(|e| CliError::InvalidArgs(format!("HIBP request failed: {e}")))?;

        if !resp.status().is_success() {
            return Err(CliError::InvalidArgs(format!(
                "HIBP API returned status {}",
                resp.status().as_u16()
            )));
        }

        resp.text().await.map_err(|e| CliError::InvalidArgs(format!("HIBP read failed: {e}")))
    })?;

    // Each line is "SUFFIX:count". Check if our suffix appears.
    for line in body.lines() {
        if let Some((hex_suffix, _count)) = line.split_once(':') {
            if hex_suffix.trim().eq_ignore_ascii_case(suffix) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

// ── Output ────────────────────────────────────────────────────────────────

fn item_type_label(t: ItemType) -> &'static str {
    match t {
        ItemType::Mnemonic => "mnemonic",
        ItemType::PrivateKey => "private_key",
        ItemType::Password => "password",
        ItemType::Totp => "totp",
        ItemType::Note => "note",
        ItemType::File => "file",
    }
}

fn print_text(
    by_type: &HashMap<&str, usize>,
    total: usize,
    weak: &[WeakFinding],
    duplicates: &[Vec<String>],
    breached: &[String],
    old: &[String],
) -> Result<(), CliError> {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    writeln!(out, "=== Secret Audit Report ===")?;
    writeln!(out)?;
    writeln!(out, "Total secrets scanned: {total}")?;
    writeln!(out, "  By type:")?;
    let mut types: Vec<_> = by_type.iter().collect();
    types.sort_by_key(|(k, _)| *k);
    for (label, count) in &types {
        writeln!(out, "    {label}: {count}")?;
    }
    writeln!(out)?;

    // Weak passwords.
    writeln!(out, "Weak passwords: {}", weak.len())?;
    for w in weak {
        writeln!(out, "  - {} ({})", w.name, w.reason)?;
    }
    writeln!(out)?;

    // Duplicate passwords.
    let dup_count: usize = duplicates.iter().map(|g| g.len()).sum();
    writeln!(out, "Duplicate passwords: {dup_count} entries in {} groups", duplicates.len())?;
    for group in duplicates {
        writeln!(out, "  - {}", group.join(", "))?;
    }
    writeln!(out)?;

    // Breached passwords.
    writeln!(out, "Breached passwords (HIBP): {}", breached.len())?;
    for name in breached {
        writeln!(out, "  - {name}")?;
    }
    writeln!(out)?;

    // Old passwords.
    writeln!(out, "Old passwords: {}", old.len())?;
    for name in old {
        writeln!(out, "  - {name}")?;
    }

    out.flush()?;
    Ok(())
}

#[derive(Serialize)]
struct AuditReport {
    total_scanned: usize,
    by_type: HashMap<String, usize>,
    weak: Vec<JsonWeak>,
    duplicates: Vec<Vec<String>>,
    breached: Vec<String>,
    old: Vec<String>,
}

#[derive(Serialize)]
struct JsonWeak {
    name: String,
    reason: String,
}

fn print_json(
    by_type: &HashMap<&str, usize>,
    total: usize,
    weak: &[WeakFinding],
    duplicates: &[Vec<String>],
    breached: &[String],
    old: &[String],
) -> Result<(), CliError> {
    let report = AuditReport {
        total_scanned: total,
        by_type: by_type.iter().map(|(&k, &v)| (k.to_string(), v)).collect(),
        weak: weak
            .iter()
            .map(|w| JsonWeak { name: w.name.clone(), reason: w.reason.clone() })
            .collect(),
        duplicates: duplicates.to_vec(),
        breached: breached.to_vec(),
        old: old.to_vec(),
    };
    let json = serde_json::to_string_pretty(&report)?;
    println!("{json}");
    Ok(())
}
