//! `onecipher history <name>` — per-secret version history (H3).
//!
//! Displays git commit history for a specific secret entry. Requires the
//! `git` feature and that the vault root is a git repository.

use oc_secret::StoreConfig;

use crate::CliError;

/// `onecipher history <name> [--password] [--limit N] [--json]`
///
/// Show version history of a specific secret. Displays commit hash, author,
/// date, and message for each revision (newest first).
pub(crate) fn run(name: &str, password: bool, limit: usize, json: bool) -> Result<(), CliError> {
    let store_root = super::secret_store_root();
    let config = StoreConfig::new(store_root.clone());
    let abs_path = config.entry_path(name);
    let rel = abs_path
        .strip_prefix(&store_root)
        .map_err(|_| CliError::InvalidArgs("entry path is outside store root".into()))?;
    let file_path = rel.to_string_lossy().to_string();

    let entries = oc_secret::git::file_history_at(&store_root, &file_path)?;

    if entries.is_empty() {
        if json {
            println!("[]");
        } else {
            eprintln!("no history found for '{name}'");
        }
        return Ok(());
    }

    let entries: Vec<_> = entries.into_iter().take(limit).collect();

    if json {
        let json_entries: Vec<serde_json::Value> = entries
            .iter()
            .map(|e| {
                let mut obj = serde_json::json!({
                    "commit": e.oid,
                    "short_commit": e.oid.get(..7).unwrap_or(&e.oid),
                    "author": e.author,
                    "time": e.time,
                    "date": format_timestamp(e.time),
                    "message": e.message.trim(),
                });
                if password {
                    obj["password"] = serde_json::Value::String(
                        "(encrypted — cannot decrypt historical versions)".into(),
                    );
                }
                obj
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&json_entries)?);
    } else {
        if password {
            eprintln!(
                "note: historical passwords are encrypted and cannot be displayed individually"
            );
            eprintln!();
        }
        for e in &entries {
            let short: &str = e.oid.get(..7).unwrap_or(&e.oid);
            let date = format_timestamp(e.time);
            println!("{short}  {date}  {author}  {msg}", author = e.author, msg = e.message.trim());
        }
    }

    Ok(())
}

/// Format a Unix timestamp as a human-readable UTC date string.
fn format_timestamp(ts: i64) -> String {
    jiff::Timestamp::from_second(ts).map_or_else(
        |_| format!("t:{ts}"),
        |t| {
            let zoned = t.to_zoned(jiff::tz::TimeZone::UTC);
            zoned.strftime("%Y-%m-%d %H:%M:%S").to_string()
        },
    )
}
