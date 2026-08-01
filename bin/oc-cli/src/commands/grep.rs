//! Grep inside decrypted secret content (`onecipher grep`).
//!
//! Decrypts every secret entry and searches the payload fields
//! (`secret`, `notes`, `extra`) for a pattern. Supports both
//! case-insensitive substring matching and regex mode.

use zeroize::Zeroize;

use crate::CliError;

/// A single grep match result.
#[derive(serde::Serialize)]
struct GrepMatch {
    name: String,
    field: String,
    line: String,
    line_number: usize,
    match_start: usize,
    match_end: usize,
}

/// Entry point for `onecipher grep <PATTERN> [--regex] [--json]`.
#[allow(dead_code)]
pub(crate) fn run(pattern: &str, regex: bool, json: bool) -> Result<(), CliError> {
    if pattern.is_empty() {
        return Err(CliError::InvalidArgs("pattern must not be empty".into()));
    }

    let store = super::open_secret_store()?;
    let identity = super::load_age_identity()?;
    let entries = store.list().map_err(|e| CliError::InvalidArgs(e.to_string()))?;

    // Build the matcher.
    let re = if regex {
        Some(
            regex_lite::RegexBuilder::new(pattern)
                .case_insensitive(true)
                .build()
                .map_err(|e| CliError::InvalidArgs(format!("invalid regex: {e}")))?,
        )
    } else {
        None
    };

    let pattern_lower = pattern.to_ascii_lowercase();
    let mut all_matches: Vec<GrepMatch> = Vec::new();

    for index_entry in &entries {
        // Load and decrypt the full entry.
        let entry = match store.get(&index_entry.name) {
            Ok(e) => e,
            Err(_) => continue,
        };
        let mut payload = match entry.decrypt(&identity) {
            Ok(p) => p,
            Err(_) => continue,
        };

        // Search in each field.
        search_field(
            &payload.secret,
            "secret",
            &index_entry.name,
            &re,
            &pattern_lower,
            &mut all_matches,
        );

        if let Some(ref notes) = payload.notes {
            search_field(notes, "notes", &index_entry.name, &re, &pattern_lower, &mut all_matches);
        }

        if let Some(ref extra) = payload.extra {
            let extra_str = serde_json::to_string(extra).unwrap_or_default();
            search_field(
                &extra_str,
                "extra",
                &index_entry.name,
                &re,
                &pattern_lower,
                &mut all_matches,
            );
        }

        // Zeroize decrypted content after each check.
        payload.secret.zeroize();
        if let Some(ref mut n) = payload.notes {
            n.zeroize();
        }
    }

    // Output.
    if all_matches.is_empty() {
        if json {
            println!("[]");
        }
        return Ok(());
    }

    if json {
        let json_str = serde_json::to_string_pretty(&all_matches)?;
        println!("{json_str}");
    } else {
        for m in &all_matches {
            println!(
                "{}:{}:L{}:C{}-C{}: {}",
                m.name, m.field, m.line_number, m.match_start, m.match_end, m.line
            );
        }
    }

    Ok(())
}

/// Search a single field value for matches and append results.
fn search_field(
    value: &str,
    field_name: &str,
    entry_name: &str,
    re: &Option<regex_lite::Regex>,
    pattern_lower: &str,
    matches: &mut Vec<GrepMatch>,
) {
    for (line_idx, line) in value.lines().enumerate() {
        let line_number = line_idx + 1;

        if let Some(re) = re {
            // Regex mode.
            for m in re.find_iter(line) {
                matches.push(GrepMatch {
                    name: entry_name.to_string(),
                    field: field_name.to_string(),
                    line: line.to_string(),
                    line_number,
                    match_start: m.start(),
                    match_end: m.end(),
                });
            }
        } else {
            // Case-insensitive substring mode.
            let line_lower = line.to_ascii_lowercase();
            let mut search_from = 0;
            while let Some(pos) = line_lower[search_from..].find(pattern_lower) {
                let absolute_pos = search_from + pos;
                matches.push(GrepMatch {
                    name: entry_name.to_string(),
                    field: field_name.to_string(),
                    line: line.to_string(),
                    line_number,
                    match_start: absolute_pos,
                    match_end: absolute_pos + pattern_lower.len(),
                });
                search_from = absolute_pos + 1;
            }
        }
    }
}
