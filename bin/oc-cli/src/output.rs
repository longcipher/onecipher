//! Agent-facing JSON single-stream output helpers (Phase 1).
//!
//! Contract: when [`is_json_mode`] holds (`ONECIPHER_JSON_ERRORS=1`), the
//! CLI emits exactly one JSON object per invocation on **stdout** — success
//! payloads are the per-command `--json` objects commands already print,
//! failures go through [`emit_error`] carrying the stable SCREAMING_SNAKE
//! `code` from [`crate::CliError::code`]. Nothing agent-relevant goes to
//! stderr in this mode, so a harness can parse stdout alone without
//! demultiplexing streams.
//!
//! Outside JSON mode the CLI keeps its historical behavior (human text on
//! stdout, `error: ...` on stderr).
//!
//! [`is_json_mode`] also gates interactivity: commands that would block on
//! a TTY prompt, an editor, or a fullscreen TUI must call
//! [`reject_interactive_if_json`] first and fail with an explicit error
//! instead of hanging the agent. Destructive commands gate on an explicit
//! flag via [`require_force`] / [`require_confirm`].

use crate::CliError;

/// Returns `true` when agent JSON mode is active.
///
/// Active whenever `ONECIPHER_JSON_ERRORS` is set (any value, matching the
/// historical `main` check). In this mode errors are single JSON objects
/// on stdout and interactive prompts are refused (see
/// [`crate::commands::is_interactive_stdin`]).
pub(crate) fn is_json_mode() -> bool {
    std::env::var("ONECIPHER_JSON_ERRORS").is_ok()
}

/// Emit a failure envelope (e.g. [`crate::CliError::to_envelope`]) as a
/// single JSON object on stdout (never stderr — agents parse one stream
/// only).
pub(crate) fn emit_error(envelope: &serde_json::Value) {
    println!("{envelope}");
}

/// Refuse interactive commands under JSON mode.
///
/// Returns an [`CliError::InvalidArgs`] error naming `cmd` when
/// [`is_json_mode`] holds, so agents get an explicit, parseable refusal
/// instead of a hung prompt. Returns `Ok(())` otherwise.
pub(crate) fn reject_interactive_if_json(cmd: &str) -> Result<(), CliError> {
    if is_json_mode() {
        return Err(CliError::InvalidArgs(format!(
            "'{cmd}' is interactive and cannot run with ONECIPHER_JSON_ERRORS=1"
        )));
    }
    Ok(())
}

/// Require an explicit `--force` flag before a destructive action.
///
/// Returns `Ok(())` when `force` is set; otherwise returns an
/// [`CliError::InvalidArgs`] error naming the refused `action`.
pub(crate) fn require_force(force: bool, action: &str) -> Result<(), CliError> {
    if force {
        Ok(())
    } else {
        Err(CliError::InvalidArgs(format!(
            "refusing to {action} without --force (destructive action)"
        )))
    }
}

/// Require an explicit `--confirm` flag before a destructive action.
///
/// Same contract as [`require_force`] for commands whose flag is spelled
/// `--confirm` (wallet / policy / key deletion predate the `--force`
/// convention; both spellings stay accepted on their own commands).
pub(crate) fn require_confirm(confirm: bool, action: &str) -> Result<(), CliError> {
    if confirm {
        Ok(())
    } else {
        Err(CliError::InvalidArgs(format!(
            "refusing to {action} without --confirm (destructive action)"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_mode_tracks_env_var() {
        use crate::test_util::{remove_env, set_env};
        let _lock =
            crate::test_util::HOME_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        remove_env("ONECIPHER_JSON_ERRORS");
        assert!(!is_json_mode());
        set_env("ONECIPHER_JSON_ERRORS", "1");
        assert!(is_json_mode());
        remove_env("ONECIPHER_JSON_ERRORS");
        assert!(!is_json_mode());
    }

    #[test]
    fn interactive_rejected_only_in_json_mode() {
        use crate::test_util::{remove_env, set_env};
        let _lock =
            crate::test_util::HOME_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        remove_env("ONECIPHER_JSON_ERRORS");
        assert!(reject_interactive_if_json("tui").is_ok());
        set_env("ONECIPHER_JSON_ERRORS", "1");
        let err = reject_interactive_if_json("tui").unwrap_err();
        assert!(err.to_string().contains("tui"));
        assert_eq!(err.code(), "INVALID_ARGS");
        remove_env("ONECIPHER_JSON_ERRORS");
    }

    #[test]
    fn force_and_confirm_gates() {
        assert!(require_force(true, "delete x").is_ok());
        assert!(require_force(false, "delete x").is_err());
        assert!(require_confirm(true, "delete x").is_ok());
        assert!(require_confirm(false, "delete x").is_err());
    }
}
