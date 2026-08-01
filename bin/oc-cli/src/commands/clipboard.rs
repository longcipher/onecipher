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
