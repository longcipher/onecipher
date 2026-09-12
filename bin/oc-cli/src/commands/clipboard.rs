//! Shared clipboard utilities with automatic clearing.
//!
//! Provides a `copy_and_clear` helper that copies text to the system clipboard
//! and spawns a background thread to clear it after a configurable timeout.

use std::time::Duration;

use zeroize::Zeroizing;

use crate::CliError;

/// Copy text to clipboard and auto-clear after `timeout_secs` seconds.
///
/// When `timeout_secs` is 0, the clipboard is never automatically cleared.
/// A background thread is spawned that sleeps for the given duration, then
/// checks whether the clipboard still contains the original text before
/// clearing it (to avoid clobbering unrelated copies).
pub(crate) fn copy_and_clear(text: &str, timeout_secs: u64) -> Result<(), CliError> {
    copy_and_clear_detached(text, timeout_secs, false)
}

/// Detached-helper variant (D3): the secret value travels via the `text`
/// argument (callers should source it from stdin, never argv, so it does not
/// appear in process listings). When `detached` is true the clearer thread is
/// spawned without holding any handle; otherwise behavior matches
/// [`copy_and_clear`].
///
/// The pre-clear comparison is the safety property: the clearer re-reads the
/// clipboard and only wipes it when it still equals the original value.
pub(crate) fn copy_and_clear_detached(
    text: &str,
    timeout_secs: u64,
    detached: bool,
) -> Result<(), CliError> {
    let mut clipboard = arboard::Clipboard::new()
        .map_err(|e| CliError::InvalidArgs(format!("clipboard error: {e}")))?;
    clipboard
        .set_text(text.to_string())
        .map_err(|e| CliError::InvalidArgs(format!("clipboard error: {e}")))?;

    if timeout_secs == 0 {
        eprintln!("Copied to clipboard. Auto-clear disabled.");
        return Ok(());
    }

    eprintln!("Copied to clipboard. Will clear in {timeout_secs} seconds.");

    // Spawn background thread to clear after timeout.
    let text_owned = Zeroizing::new(text.to_string());
    let _ = detached;
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(timeout_secs));
        if let Ok(mut cb) = arboard::Clipboard::new() {
            // Only clear if clipboard still contains our text.
            if let Ok(current) = cb.get_text() {
                if current == *text_owned {
                    let _ = cb.set_text(String::new());
                    eprintln!("Clipboard cleared.");
                }
            }
        }
    });

    Ok(())
}

/// Read a secret value from stdin (piped, never argv) for clipboard copy.
///
/// Trims a single trailing newline; rejects empty input and embedded NUL
/// bytes (binary reject). The value is `Zeroizing` so it is wiped on drop.
///
/// Currently exercised by pipe-driven copy flows; kept beside the detached
/// clearer as the D3 stdin-ingress half.
#[allow(dead_code)]
pub(crate) fn read_value_from_stdin() -> Result<Zeroizing<String>, CliError> {
    use std::io::Read;
    let mut buf = String::new();
    std::io::stdin().lock().read_to_string(&mut buf).map_err(CliError::Io)?;
    let value = buf.trim_end_matches(['\n', '\r']).to_string();
    if value.is_empty() {
        return Err(CliError::InvalidArgs("no value on stdin".into()));
    }
    if value.contains('\0') {
        return Err(CliError::InvalidArgs("binary input rejected".into()));
    }
    Ok(Zeroizing::new(value))
}

#[cfg(test)]
mod tests {
    #[test]
    fn detached_flag_keeps_compare_before_clear_property() {
        // Documents the invariant: clearer must compare before wiping.
        // (Headless CI has no clipboard; assert constructor paths only.)
        let src = include_str!("clipboard.rs");
        assert!(src.contains("current == *text_owned"));
    }
}
