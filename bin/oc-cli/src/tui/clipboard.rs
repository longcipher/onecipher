//! Clipboard helpers with automatic clearing.
//!
//! Secrets copied to the clipboard are automatically cleared after
//! [`CLEAR_AFTER`] to minimise the window of exposure.

use std::time::{Duration, Instant};

use arboard::Clipboard;

/// Duration after which the clipboard is automatically cleared.
const CLEAR_AFTER: Duration = Duration::from_secs(40);

/// Copy text to the clipboard.
///
/// Returns the [`Instant`] at which the clipboard should be cleared
/// (now + 40 seconds). The caller is responsible for calling
/// [`check_and_clear`] periodically.
pub(crate) fn copy_to_clipboard(text: &str) -> Result<Instant, arboard::Error> {
    let mut clipboard = Clipboard::new()?;
    clipboard.set_text(text)?;
    Ok(Instant::now() + CLEAR_AFTER)
}

/// Clear the clipboard by overwriting it with an empty string.
pub(crate) fn clear_clipboard() -> Result<(), arboard::Error> {
    let mut clipboard = Clipboard::new()?;
    clipboard.set_text("")?;
    Ok(())
}

/// Check whether the clipboard should be cleared and clear it if so.
///
/// Returns `Ok(true)` if the clipboard was cleared, `Ok(false)` if the
/// clear time hasn't been reached yet (or is `None`).
pub(crate) fn check_and_clear(clear_at: Option<Instant>) -> Result<bool, arboard::Error> {
    if let Some(at) = clear_at {
        if Instant::now() >= at {
            clear_clipboard()?;
            return Ok(true);
        }
    }
    Ok(false)
}
