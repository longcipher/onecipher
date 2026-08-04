//! Audit log CLI (R50, T39). Reads the local JSONL audit log file and
//! filters entries by `--since`, `--agent`, and `--status`.
//!
//! Per R50 / R89 / R90 / R91: `audit list` is a LOCAL operation — there is
//! no `ListAuditLog` RPC on `AgentService` (see `proto/agent.proto`). The
//! CLI reads `~/.onecipher/logs/audit.jsonl` by default; the `OC_AUDIT_LOG`
//! env var overrides the path (used by conformance tests in T39).
//!
//! Each line in the file is one signed `AuditEntry` (see
//! `crates/oc-keyagent/src/audit.rs`). The CLI parses each line as JSON,
//! applies the requested filters, and prints matching entries to stdout in
//! a single human-readable line per entry.
//!
//! Per the T39 design: malformed individual lines are skipped (with a
//! diagnostic on stderr) — they do NOT abort the whole `list` call. File
//! I/O errors (cannot open / cannot read) DO return `Err(CliError)`.

use std::{
    fs::File,
    io::{BufRead, BufReader, Write},
    path::PathBuf,
};

use jiff::{Span, Timestamp};
use serde_json::Value;

use crate::CliError;

/// Entry point for `onecipher audit list`.
///
/// Reads the audit log file, applies the requested filters, and prints
/// matching entries to stdout. Returns `Ok(())` on success (including when
/// individual JSONL lines fail to parse — those are skipped with a
/// diagnostic on stderr, and when the audit log file does not exist yet —
/// treated as an empty log with no entries). Returns `Err(CliError::Io(_))`
/// if the file exists but cannot be read, or `Err(CliError::InvalidArgs(_))`
/// if `--since` is not a valid duration string.
pub(crate) fn list(
    since: Option<&str>,
    agent: Option<&str>,
    status: Option<&str>,
) -> Result<(), CliError> {
    let path = audit_log_path()?;
    // A missing audit log file is treated as an empty log (no entries to
    // print). This matches the UX expectation that `audit list` on a
    // fresh install prints nothing rather than erroring. Other I/O
    // errors (permission denied, etc.) DO propagate as `Err(CliError)`.
    let file = match File::open(&path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    let reader = BufReader::new(file);

    let now = Timestamp::now();
    let since_dt = match since {
        Some(s) => {
            // Convert Span to SignedDuration using 24-hour days (CLI durations
            // are relative, not calendar-aware). jiff's Timestamp can't accept
            // a Span with days directly without a relative reference.
            let span = parse_duration(s)?;
            let dur = span
                .to_duration(jiff::SpanRelativeTo::days_are_24_hours())
                .map_err(|e| CliError::InvalidArgs(format!("invalid --since duration: {e}")))?;
            Some(
                now.checked_sub(dur)
                    .map_err(|e| CliError::InvalidArgs(format!("invalid --since duration: {e}")))?,
            )
        }
        None => None,
    };
    let status_filter = status.map(|s| s.to_lowercase());

    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let entry: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("audit list: skipping malformed line: {e}");
                continue;
            }
        };

        // Filter by --agent (matches `device_id` exactly).
        let device_id = entry.get("device_id").and_then(|v| v.as_str()).unwrap_or("");
        if let Some(a) = agent {
            if device_id != a {
                continue;
            }
        }

        // Filter by --since (entry `timestamp` must be >= `now - duration`).
        if let Some(since_dt) = since_dt {
            let ts = entry.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
            let entry_dt = if let Ok(dt) = ts.parse::<Timestamp>() {
                dt
            } else {
                eprintln!("audit list: skipping entry with unparseable timestamp: {ts}");
                continue;
            };
            if entry_dt < since_dt {
                continue;
            }
        }

        // Filter by --status (case-insensitive match against
        // `payload.status` — "allowed"/"denied" → "ALLOWED"/"DENIED").
        if let Some(ref want) = status_filter {
            let actual = entry
                .get("payload")
                .and_then(|p| p.get("status"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !actual.eq_ignore_ascii_case(want) {
                continue;
            }
        }

        print_entry(&mut out, &entry)?;
    }

    Ok(())
}

/// Resolve the audit log file path.
///
/// Honors the `OC_AUDIT_LOG` env var (used by conformance tests). Defaults
/// to `~/.onecipher/logs/audit.jsonl`.
fn audit_log_path() -> Result<PathBuf, CliError> {
    if let Ok(p) = std::env::var("OC_AUDIT_LOG") {
        if !p.is_empty() {
            return Ok(PathBuf::from(p));
        }
    }
    Ok(oc_core::paths::state_path("logs/audit.jsonl")?)
}

/// Parse a duration string like "24h", "7d", "1h30m", "15m" into a
/// `jiff::Span`. Supported units: `d` (days), `h` (hours), `m`
/// (minutes), `s` (seconds). At least one unit must be present.
fn parse_duration(s: &str) -> Result<Span, CliError> {
    let mut days: i64 = 0;
    let mut hours: i64 = 0;
    let mut minutes: i64 = 0;
    let mut seconds: i64 = 0;
    let mut chars = s.chars().peekable();
    while chars.peek().is_some() {
        // Parse the leading integer.
        let mut num = String::new();
        while let Some(&c) = chars.peek() {
            if c.is_ascii_digit() {
                num.push(c);
                chars.next();
            } else {
                break;
            }
        }
        if num.is_empty() {
            return Err(CliError::InvalidArgs(format!(
                "invalid --since duration: {s:?} (expected a number followed by a unit)"
            )));
        }
        let n: i64 = num.parse().map_err(|_| {
            CliError::InvalidArgs(format!("invalid --since duration: {s:?} (number too large)"))
        })?;

        // Parse the unit (one or more letters).
        let mut unit = String::new();
        while let Some(&c) = chars.peek() {
            if c.is_ascii_alphabetic() {
                unit.push(c);
                chars.next();
            } else {
                break;
            }
        }

        match unit.as_str() {
            "d" => days += n,
            "h" => hours += n,
            "m" => minutes += n,
            "s" => seconds += n,
            other => {
                return Err(CliError::InvalidArgs(format!(
                    "invalid --since duration unit: {other:?} (supported: d, h, m, s)"
                )));
            }
        }
    }

    if days == 0 && hours == 0 && minutes == 0 && seconds == 0 {
        return Err(CliError::InvalidArgs(format!(
            "invalid --since duration: {s:?} (must be non-zero)"
        )));
    }
    Ok(Span::new().days(days).hours(hours).minutes(minutes).seconds(seconds))
}

/// Print one audit entry as a single human-readable line to `out`.
///
/// Fields printed: `device_id`, `seq`, `timestamp`, `event_type`,
/// `session_key_id` ("-" if None), `status` (uppercased from
/// `payload.status`, "-" if missing), `amount_usd` (from payload, "-" if
/// missing). For DENIED entries, `deny_reason` is also printed.
fn print_entry(out: &mut dyn Write, entry: &Value) -> Result<(), CliError> {
    let device_id = entry.get("device_id").and_then(|v| v.as_str()).unwrap_or("");
    let seq = entry.get("seq").and_then(|v| v.as_u64()).unwrap_or(0);
    let timestamp = entry.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
    let event_type = entry.get("event_type").and_then(|v| v.as_str()).unwrap_or("");
    let session_key_id = entry.get("session_key_id").and_then(|v| v.as_str()).unwrap_or("-");
    let payload = entry.get("payload");
    let status_raw = payload.and_then(|p| p.get("status")).and_then(|v| v.as_str()).unwrap_or("-");
    let status_upper = status_raw.to_uppercase();
    let amount_usd = payload.and_then(|p| p.get("amount_usd")).map_or_else(
        || "-".to_string(),
        |v| match v.as_f64() {
            Some(f) => format!("{f:.2}"),
            None => v.to_string(),
        },
    );

    let mut line = format!(
        "device_id={device_id} seq={seq} timestamp={timestamp} event_type={event_type} \
         session_key_id={session_key_id} status={status_upper} amount_usd={amount_usd}"
    );

    // For DENIED entries, expose `deny_reason` (R91).
    if status_upper == "DENIED" {
        let deny_reason =
            payload.and_then(|p| p.get("deny_reason")).and_then(|v| v.as_str()).unwrap_or("-");
        line.push_str(&format!(" deny_reason={deny_reason}"));
    }

    writeln!(out, "{line}")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_duration_supports_all_units() {
        assert_eq!(parse_duration("24h").unwrap(), jiff::SpanFieldwise(Span::new().hours(24)));
        assert_eq!(parse_duration("7d").unwrap(), jiff::SpanFieldwise(Span::new().days(7)));
        assert_eq!(parse_duration("15m").unwrap(), jiff::SpanFieldwise(Span::new().minutes(15)));
        assert_eq!(parse_duration("30s").unwrap(), jiff::SpanFieldwise(Span::new().seconds(30)));
    }

    #[test]
    fn parse_duration_supports_compound() {
        assert_eq!(
            parse_duration("1h30m").unwrap(),
            jiff::SpanFieldwise(Span::new().hours(1).minutes(30))
        );
        assert_eq!(
            parse_duration("2d12h").unwrap(),
            jiff::SpanFieldwise(Span::new().days(2).hours(12))
        );
    }

    #[test]
    fn parse_duration_rejects_garbage() {
        assert!(parse_duration("").is_err());
        assert!(parse_duration("abc").is_err());
        assert!(parse_duration("5").is_err());
        assert!(parse_duration("5x").is_err());
        assert!(parse_duration("0h").is_err());
    }

    #[test]
    fn print_entry_includes_all_seven_fields() {
        let entry = serde_json::json!({
            "device_id": "agent-01",
            "seq": 42,
            "timestamp": "2026-07-18T12:00:00Z",
            "event_type": "pay_x402",
            "session_key_id": "sk-1",
            "payload": {"status": "allowed", "amount_usd": 1.50},
            "prev_hash": "",
            "device_sig": ""
        });
        let mut buf: Vec<u8> = Vec::new();
        print_entry(&mut buf, &entry).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("device_id=agent-01"), "got: {s}");
        assert!(s.contains("seq=42"), "got: {s}");
        assert!(s.contains("timestamp=2026-07-18T12:00:00Z"), "got: {s}");
        assert!(s.contains("event_type=pay_x402"), "got: {s}");
        assert!(s.contains("session_key_id=sk-1"), "got: {s}");
        assert!(s.contains("status=ALLOWED"), "got: {s}");
        assert!(s.contains("amount_usd=1.50"), "got: {s}");
        // ALLOWED entries do NOT print deny_reason.
        assert!(!s.contains("deny_reason"), "got: {s}");
    }

    #[test]
    fn print_entry_denied_includes_deny_reason() {
        let entry = serde_json::json!({
            "device_id": "agent-02",
            "seq": 7,
            "timestamp": "2026-07-18T12:00:00Z",
            "event_type": "pay_x402",
            "session_key_id": null,
            "payload": {"status": "denied", "amount_usd": 9.99, "deny_reason": "RATE_LIMIT_MINUTE"},
            "prev_hash": "",
            "device_sig": ""
        });
        let mut buf: Vec<u8> = Vec::new();
        print_entry(&mut buf, &entry).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("status=DENIED"), "got: {s}");
        assert!(s.contains("deny_reason=RATE_LIMIT_MINUTE"), "got: {s}");
        // session_key_id null → "-"
        assert!(s.contains("session_key_id=-"), "got: {s}");
    }
}
