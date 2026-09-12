//! BSD `sysexits(3)` exit statuses for the OneCipher CLI.
//!
//! Phase 1 agents parse both the stdout JSON envelope (`code`, stable
//! SCREAMING_SNAKE from [`crate::CliError::code`]) and the process exit
//! status. Every [`crate::CliError`] variant maps to one of the statuses
//! below instead of a flat `1`, so scripts can distinguish usage errors
//! from missing inputs, permission denials, and internal failures without
//! parsing stderr.
//!
//! Only the subset the CLI can actually produce is exported:
//!
//! | Constant | Value | Meaning |
//! |---|---|---|
//! | [`EX_USAGE`] | 64 | Command-line usage error |
//! | [`EX_DATAERR`] | 65 | Input data incorrect |
//! | [`EX_NOINPUT`] | 66 | Cannot open input (wallet/secret/key not found) |
//! | [`EX_SOFTWARE`] | 70 | Internal software error |
//! | [`EX_CANTCREAT`] | 73 | Cannot create output (already exists / not writable) |
//! | [`EX_NOPERM`] | 77 | Permission denied (policy / expired key / bad passphrase) |

/// Command-line usage error (bad flags, missing required argument).
pub(crate) const EX_USAGE: i32 = 64;
/// Input data incorrect (bad mnemonic, bad chain, malformed JSON payload).
pub(crate) const EX_DATAERR: i32 = 65;
/// Cannot open input (unknown wallet, secret, or API key).
pub(crate) const EX_NOINPUT: i32 = 66;
/// Internal software error (vault, signer, daemon, or network failure).
pub(crate) const EX_SOFTWARE: i32 = 70;
/// Cannot create output (name already taken, file not writable).
pub(crate) const EX_CANTCREAT: i32 = 73;
/// Permission denied (policy denial, expired key, wrong passphrase).
pub(crate) const EX_NOPERM: i32 = 77;

/// Map a stable SCREAMING_SNAKE error `code` (see [`crate::CliError::code`])
/// to a BSD `sysexits(3)` status.
///
/// I/O errors are handled by the caller ([`crate::CliError::exit_code`]),
/// which inspects the [`std::io::ErrorKind`]: `NotFound` maps to
/// [`EX_NOINPUT`], `PermissionDenied` to [`EX_NOPERM`], anything else to
/// [`EX_CANTCREAT`]. Every other code has a fixed mapping below; mixed-cause
/// categories (secret store, wallet) map to their most common case.
pub(crate) fn exit_code_for(code: &str) -> i32 {
    match code {
        // 64: the caller misused the CLI.
        "INVALID_ARGS" => EX_USAGE,
        // 65: the caller supplied well-formed but incorrect data.
        "INVALID_INPUT" |
        "CAIP_PARSE_ERROR" |
        "CHAIN_NOT_SUPPORTED" |
        "MNEMONIC_ERROR" |
        "HD_ERROR" |
        "JSON_ERROR" |
        "AMBIGUOUS_WALLET" => EX_DATAERR,
        // 66: the named input does not exist.
        "WALLET_NOT_FOUND" | "API_KEY_NOT_FOUND" | "SECRET_STORE_ERROR" => EX_NOINPUT,
        // 73: the requested output cannot be created.
        "WALLET_NAME_EXISTS" => EX_CANTCREAT,
        // 77: the operation is not permitted.
        "POLICY_DENIED" | "API_KEY_EXPIRED" | "INVALID_PASSPHRASE" => EX_NOPERM,
        // 70: everything else is an internal failure.
        _ => EX_SOFTWARE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usage_errors_map_to_64() {
        assert_eq!(exit_code_for("INVALID_ARGS"), 64);
    }

    #[test]
    fn data_errors_map_to_65() {
        for code in [
            "INVALID_INPUT",
            "CAIP_PARSE_ERROR",
            "CHAIN_NOT_SUPPORTED",
            "MNEMONIC_ERROR",
            "HD_ERROR",
            "JSON_ERROR",
            "AMBIGUOUS_WALLET",
        ] {
            assert_eq!(exit_code_for(code), 65, "code {code}");
        }
    }

    #[test]
    fn missing_inputs_map_to_66() {
        for code in ["WALLET_NOT_FOUND", "API_KEY_NOT_FOUND", "SECRET_STORE_ERROR"] {
            assert_eq!(exit_code_for(code), 66, "code {code}");
        }
    }

    #[test]
    fn permission_errors_map_to_77() {
        for code in ["POLICY_DENIED", "API_KEY_EXPIRED", "INVALID_PASSPHRASE"] {
            assert_eq!(exit_code_for(code), 77, "code {code}");
        }
    }

    #[test]
    fn creation_conflicts_map_to_73() {
        assert_eq!(exit_code_for("WALLET_NAME_EXISTS"), 73);
    }

    #[test]
    fn internal_failures_map_to_70() {
        for code in [
            "WALLET_ERROR",
            "VAULT_ERROR",
            "SIGNER_ERROR",
            "CRYPTO_ERROR",
            "BROADCAST_FAILED",
            "MIGRATION_ERROR",
            "GIT_ERROR",
            "RECIPIENT_ERROR",
            "NET_AGENT_UNAVAILABLE",
            "DAEMON_INIT_FAILED",
            "KEY_AGENT_ERROR",
        ] {
            assert_eq!(exit_code_for(code), 70, "code {code}");
        }
    }

    #[test]
    fn unknown_codes_fail_closed_to_70() {
        assert_eq!(exit_code_for("SOMETHING_NEW"), 70);
    }
}
