//! Loopback CLI capability token.
//!
//! The `onecipher webui …` CLI bridge (approvals, auth) talks to the daemon's
//! HTTP API from the same user account, but it cannot run a WebAuthn ceremony.
//! Instead the daemon persists a random capability token at
//! `~/.onecipher/webui_cli.token` (mode 0600) and accepts it via the
//! `x-oc-cli-token` header on protected routes — including state-changing
//! ones such as `/api/approvals/{id}/decision`.
//!
//! Trust model: the server binds loopback only (R12c), so possession of the
//! token file implies same-user shell access — at which point the wallet is
//! already reachable. The token exists so that *other local processes* and
//! drive-by browser tabs (CSRF-style POSTs) cannot invoke protected routes.
//!
//! Lifetime: the daemon reads the token once at startup and caches the
//! expected value; the CLI re-reads the file per invocation. Rotating or
//! deleting the file therefore takes effect for new CLI processes only after
//! a daemon restart.

use std::path::{Path, PathBuf};

/// Header carrying the CLI capability token.
pub const CLI_TOKEN_HEADER: &str = "x-oc-cli-token";

/// File name of the persisted token inside the state dir.
const TOKEN_FILE: &str = "webui_cli.token";

/// Path of the persisted CLI token file.
fn token_path(state_dir: &Path) -> PathBuf {
    state_dir.join(TOKEN_FILE)
}

/// Read the persisted CLI token, if present.
pub fn load_cli_token(state_dir: &Path) -> Option<String> {
    let raw = std::fs::read_to_string(token_path(state_dir)).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() { None } else { Some(trimmed.to_string()) }
}

/// Return the persisted CLI token, generating and persisting a fresh one
/// (mode 0600) when absent or empty. Best-effort callers log failures.
pub fn ensure_cli_token(state_dir: &Path) -> std::io::Result<String> {
    if let Some(existing) = load_cli_token(state_dir) {
        return Ok(existing);
    }
    // Two UUIDv4 values = 244 bits of randomness; hex-encoded for a clean
    // single-line header value. `uuid` is already an oc-webui dependency.
    let token = format!("{}{}", uuid::Uuid::new_v4().simple(), uuid::Uuid::new_v4().simple());
    oc_core::paths::write_atomic_private(&token_path(state_dir), token.as_bytes())?;
    Ok(token)
}

/// Whether a presented token matches the stored one. Timing side channels are
/// out of scope for a loopback-only server whose threat model already assumes
/// same-user access.
pub fn token_matches(stored: &str, candidate: &str) -> bool {
    stored == candidate
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_then_load_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let generated = ensure_cli_token(dir.path()).unwrap();
        assert_eq!(generated.len(), 64);
        assert_eq!(load_cli_token(dir.path()).as_deref(), Some(generated.as_str()));
        // Idempotent — second call returns the same token.
        assert_eq!(ensure_cli_token(dir.path()).unwrap(), generated);
    }

    #[test]
    fn missing_file_does_not_match() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!token_matches("stored", "anything"));
        assert!(load_cli_token(dir.path()).is_none());
    }

    #[test]
    fn wrong_candidate_rejected_and_exact_match_accepted() {
        assert!(!token_matches("stored-token", "wrong"));
        assert!(token_matches("stored-token", "stored-token"));
        // The daemon caches the trimmed file content and the CLI trims the
        // header value, so neither side carries whitespace in practice — a
        // padded candidate must not match.
        assert!(!token_matches("stored-token", " stored-token "));
    }

    #[tokio::test]
    async fn empty_file_regenerates() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(TOKEN_FILE), b"").unwrap();
        let regenerated = ensure_cli_token(dir.path()).unwrap();
        assert_ne!(regenerated, "");
    }
}
