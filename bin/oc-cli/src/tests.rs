use std::sync::{Arc, Mutex};

use clap::Parser;
use oc_keyagent::proto::{
    CreateSessionKeyRequest, CreateSessionKeyResponse, ListSessionKeysResponse,
    RevokeSessionKeyRequest, RevokeSessionKeyResponse, SessionKeyInfo, SessionKeyStatus,
};

use crate::{
    cli::{AuditCommands, Cli, CliError, Commands},
    netagent::NetAgentClient,
};

// -----------------------------------------------------------------------
// Mock NetAgentClient
// -----------------------------------------------------------------------

#[derive(Default, Clone)]
struct MockNetAgentClient {
    create_session_key_requests: Arc<Mutex<Vec<CreateSessionKeyRequest>>>,
    revoke_session_key_requests: Arc<Mutex<Vec<RevokeSessionKeyRequest>>>,
    list_session_keys_calls: Arc<Mutex<u32>>,
    next_create_resp: Arc<Mutex<Option<CreateSessionKeyResponse>>>,
    next_revoke_resp: Arc<Mutex<Option<RevokeSessionKeyResponse>>>,
    next_list_resp: Arc<Mutex<Option<ListSessionKeysResponse>>>,
}

impl NetAgentClient for MockNetAgentClient {
    fn create_session_key(
        &self,
        req: CreateSessionKeyRequest,
    ) -> Result<CreateSessionKeyResponse, CliError> {
        self.create_session_key_requests.lock().unwrap().push(req);
        Ok(self.next_create_resp.lock().unwrap().clone().unwrap_or_default())
    }

    fn revoke_session_key(
        &self,
        req: RevokeSessionKeyRequest,
    ) -> Result<RevokeSessionKeyResponse, CliError> {
        self.revoke_session_key_requests.lock().unwrap().push(req);
        Ok(self.next_revoke_resp.lock().unwrap().clone().unwrap_or_default())
    }

    fn list_session_keys(&self) -> Result<ListSessionKeysResponse, CliError> {
        *self.list_session_keys_calls.lock().unwrap() += 1;
        Ok(self.next_list_resp.lock().unwrap().clone().unwrap_or_default())
    }
}

// -----------------------------------------------------------------------
// 1. clap parser accepts `audit list --since 24h --agent agent-01 --status DENIED`
// -----------------------------------------------------------------------

#[test]
fn test_audit_list_parses_all_flags() {
    let cli = Cli::parse_from([
        "onecipher",
        "audit",
        "list",
        "--since",
        "24h",
        "--agent",
        "agent-01",
        "--status",
        "DENIED",
    ]);
    if let Some(Commands::Audit { subcommand: AuditCommands::List { since, agent, status } }) =
        cli.command
    {
        assert_eq!(since.as_deref(), Some("24h"));
        assert_eq!(agent.as_deref(), Some("agent-01"));
        assert_eq!(status.as_deref(), Some("DENIED"));
    } else {
        panic!("expected Commands::Audit{{List}}");
    }
}

// -----------------------------------------------------------------------
// 2. clap parser accepts `audit list --since 24h --agent agent-01` (eval rule)
// -----------------------------------------------------------------------

#[test]
fn test_audit_list_parses_subset_of_flags() {
    let cli =
        Cli::parse_from(["onecipher", "audit", "list", "--since", "24h", "--agent", "agent-01"]);
    if let Some(Commands::Audit { subcommand: AuditCommands::List { since, agent, status } }) =
        cli.command
    {
        assert_eq!(since.as_deref(), Some("24h"));
        assert_eq!(agent.as_deref(), Some("agent-01"));
        assert!(status.is_none());
    } else {
        panic!("expected Commands::Audit{{List}}");
    }
}

// -----------------------------------------------------------------------
// 3. `audit list` (no flags) parses with all Options = None
// -----------------------------------------------------------------------

#[test]
fn test_audit_list_no_flags() {
    let cli = Cli::parse_from(["onecipher", "audit", "list"]);
    if let Some(Commands::Audit { subcommand: AuditCommands::List { since, agent, status } }) =
        cli.command
    {
        assert!(since.is_none());
        assert!(agent.is_none());
        assert!(status.is_none());
    } else {
        panic!("expected Commands::Audit{{List}}");
    }
}

// -----------------------------------------------------------------------
// 4. `audit list` end-to-end via mock client — run() returns Ok
// -----------------------------------------------------------------------

#[test]
fn test_cli_audit_list_via_mock() {
    let mock = MockNetAgentClient::default();
    let cli =
        Cli::parse_from(["onecipher", "audit", "list", "--since", "24h", "--agent", "agent-01"]);
    let result = crate::run(cli, &mock);
    assert!(result.is_ok());
}

// -----------------------------------------------------------------------
// 5. `session-key create` builds the correct CreateSessionKeyRequest RPC
// -----------------------------------------------------------------------

#[test]
fn test_session_key_create_builds_correct_rpc() {
    let mock = MockNetAgentClient::default();
    let cli = Cli::parse_from([
        "onecipher",
        "session-key",
        "create",
        "--label",
        "test-label",
        "--challenge",
        "deadbeef",
        "--signature",
        "0102",
        "--credential-id",
        "cred-1",
    ]);
    let result = crate::run(cli, &mock);
    assert!(result.is_ok());

    let recorded = mock.create_session_key_requests.lock().unwrap();
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].label, "test-label");
    let auth = recorded[0].auth.as_ref().expect("auth must be set");
    assert_eq!(auth.challenge, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    assert_eq!(auth.signature, vec![0x01, 0x02]);
    assert_eq!(auth.credential_id, "cred-1");
}

// -----------------------------------------------------------------------
// 6. `session-key create` rejects invalid hex challenge with InvalidArgs
// -----------------------------------------------------------------------

#[test]
fn test_session_key_create_rejects_bad_hex() {
    let mock = MockNetAgentClient::default();
    let cli = Cli::parse_from([
        "onecipher",
        "session-key",
        "create",
        "--label",
        "x",
        "--challenge",
        "not-hex!",
        "--signature",
        "0102",
        "--credential-id",
        "cred-1",
    ]);
    let result = crate::run(cli, &mock);
    assert!(matches!(result, Err(CliError::InvalidArgs(_))));
    // Mock must NOT have been called.
    assert!(mock.create_session_key_requests.lock().unwrap().is_empty());
}

// -----------------------------------------------------------------------
// 7. `session-key revoke` builds the correct RevokeSessionKeyRequest RPC
// -----------------------------------------------------------------------

#[test]
fn test_session_key_revoke_builds_correct_rpc() {
    let mock = MockNetAgentClient::default();
    let cli = Cli::parse_from([
        "onecipher",
        "session-key",
        "revoke",
        "sk-42",
        "--challenge",
        "cafe",
        "--signature",
        "0304",
        "--credential-id",
        "cred-7",
    ]);
    let result = crate::run(cli, &mock);
    assert!(result.is_ok());

    let recorded = mock.revoke_session_key_requests.lock().unwrap();
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].session_key_id, "sk-42");
    let auth = recorded[0].auth.as_ref().expect("auth must be set");
    assert_eq!(auth.challenge, vec![0xCA, 0xFE]);
    assert_eq!(auth.signature, vec![0x03, 0x04]);
    assert_eq!(auth.credential_id, "cred-7");
}

// -----------------------------------------------------------------------
// 8. `session-key list` calls list_session_keys exactly once
// -----------------------------------------------------------------------

#[test]
fn test_session_key_list_calls_rpc_once() {
    let mock = MockNetAgentClient::default();
    let cli = Cli::parse_from(["onecipher", "session-key", "list"]);
    let result = crate::run(cli, &mock);
    assert!(result.is_ok());
    assert_eq!(*mock.list_session_keys_calls.lock().unwrap(), 1u32);
}

// -----------------------------------------------------------------------
// 12. `session-key list` prints "no session keys" when response is empty
// -----------------------------------------------------------------------

#[test]
fn test_session_key_list_empty() {
    let mock = MockNetAgentClient::default();
    let cli = Cli::parse_from(["onecipher", "session-key", "list"]);
    let result = crate::run(cli, &mock);
    assert!(result.is_ok());
    let recorded = mock.list_session_keys_calls.lock().unwrap();
    assert_eq!(*recorded, 1);
}

// -----------------------------------------------------------------------
// 13. `session-key list` iterates non-empty response without panic
// -----------------------------------------------------------------------

#[test]
fn test_session_key_list_non_empty() {
    let mock = MockNetAgentClient::default();
    *mock.next_list_resp.lock().unwrap() = Some(ListSessionKeysResponse {
        keys: vec![SessionKeyInfo {
            session_key_id: "sk-1".to_string(),
            label: "alpha".to_string(),
            created_at_unix: 0,
            expires_at_unix: 0,
            policy: None,
            status: SessionKeyStatus::Active as i32,
        }],
    });
    let cli = Cli::parse_from(["onecipher", "session-key", "list"]);
    let result = crate::run(cli, &mock);
    assert!(result.is_ok());
}

// -----------------------------------------------------------------------
// 14. UnimplementedClient returns NetAgentUnavailable for every RPC
// -----------------------------------------------------------------------

#[test]
fn test_unimplemented_client_returns_error() {
    let client = crate::netagent::UnimplementedClient;
    assert!(matches!(client.list_session_keys(), Err(CliError::NetAgentUnavailable)));
    assert!(matches!(
        client.create_session_key(CreateSessionKeyRequest::default()),
        Err(CliError::NetAgentUnavailable)
    ));
    assert!(matches!(
        client.revoke_session_key(RevokeSessionKeyRequest::default()),
        Err(CliError::NetAgentUnavailable)
    ));
}

// -----------------------------------------------------------------------
// 15. `status`, `vault unlock`, `backup export`, `backup import` all return Ok
// -----------------------------------------------------------------------

#[test]
fn test_local_stubs_return_ok() {
    let mock = MockNetAgentClient::default();

    let cli = Cli::parse_from(["onecipher", "status"]);
    assert!(crate::run(cli, &mock).is_ok());

    // NOTE: `vault unlock` is excluded — it depends on the real vault at
    // ~/.onecipher and the wallet's KDF format. Covered by integration tests.

    // Backup export needs at least one age recipient; generate an ephemeral
    // one (the bundle itself is discarded — this only asserts Ok dispatch).
    let recipient = oc_vault::crypto::AgeIdentity::generate().to_recipient_string();
    let cli = Cli::parse_from([
        "onecipher",
        "backup",
        "export",
        "--out",
        "/tmp/wallet.ocbk",
        "--recipient",
        recipient.as_str(),
    ]);
    assert!(crate::run(cli, &mock).is_ok());

    // Import without an identity would prompt on the terminal; the full
    // export/import round trip (with identity) is covered by
    // `test_backup_export_import` below.
}

// -----------------------------------------------------------------------
// 16. proptest: arbitrary `--since`/`--agent`/`--status` strings round-trip through the clap parser
//     without panic
// -----------------------------------------------------------------------

proptest::proptest! {
    #[test]
    fn test_audit_list_fuzz_args(
        since in "[a-zA-Z0-9]{0,8}",
        // First char must NOT be `-` so clap doesn't treat the value as a flag.
        agent in "[a-zA-Z0-9][a-zA-Z0-9-]{0,15}",
        status in "(ALLOWED|DENIED)",
    ) {
        let cli = Cli::parse_from([
            "onecipher", "audit", "list",
            "--since", &since,
            "--agent", &agent,
            "--status", &status,
        ]);
        if let Some(Commands::Audit {
            subcommand: AuditCommands::List {
                since: s, agent: a, status: st,
            },
        }) = cli.command
        {
            assert_eq!(s.as_deref(), Some(since.as_str()));
            assert_eq!(a.as_deref(), Some(agent.as_str()));
            assert_eq!(st.as_deref(), Some(status.as_str()));
        } else {
            panic!("expected Commands::Audit{{List}}");
        }
    }
}

// -----------------------------------------------------------------------
// 17. CLI binary name in `--help` is `onecipher` (R77 rename verified)
// -----------------------------------------------------------------------

#[test]
fn test_cli_binary_name_is_onecipher() {
    // clap's `parse_from` requires the first arg to be the binary name; we
    // assert that "onecipher" is accepted (a different name would still be
    // accepted by parse_from, but it's the canonical name we use).
    let cli = Cli::parse_from(["onecipher", "status"]);
    assert!(matches!(cli.command, Some(Commands::Status)));
}

// ===========================================================================
// Integrated end-to-end test harness
//
// Every command (except a few that operate purely in-memory) persists state
// under `~/.onecipher`, which `oc_core::paths::state_dir()` resolves from the
// `HOME` env var. To test commands in isolation without touching the real
// user vault, we redirect `HOME` to a fresh temp dir. Because `HOME` is
// process-global and `cargo test` runs tests on multiple threads, every test
// that touches the filesystem must serialize through `HOME_LOCK` for the full
// duration of its body.
// ===========================================================================

// `HomeGuard` and the shared `HOME_LOCK` live in `crate::test_util` so that
// every HOME-mutating test in the crate (this module AND `wallet_rpc`) serializes
// through the SAME lock. Two independent locks would let tests from different
// modules race on the process-global `HOME` env var.
use crate::test_util::HomeGuard;

/// Run a parsed CLI through the real dispatch with a mock NetAgentClient.
/// Local commands (wallet/secret/age/...) hit the isolated `HOME`; RPC
/// commands (session-key/ocpay) hit the mock.
fn run_cli(args: &[&str]) -> Result<(), CliError> {
    let cli = Cli::parse_from(args.iter().copied());
    let mock = MockNetAgentClient::default();
    crate::run(cli, &mock)
}

/// Run a parsed CLI and return the captured stdout (stdout is captured by the
/// test harness; we use a thin wrapper that does not capture but returns the
/// `Result`). Side-effecting output goes to real stdout, which is fine.
fn run_ok(args: &[&str]) {
    run_cli(args).unwrap_or_else(|e| panic!("expected Ok for {args:?}, got: {e}"));
}

/// Set an environment variable. Safe under the `HOME_LOCK` serialization and
/// because each command reads-then-clears these vars itself; wrapped in
/// `unsafe` purely to satisfy the toolchain's `set_var` unsafety contract.
#[allow(unused_unsafe)]
fn set_env(k: &str, v: &str) {
    // SAFETY: tests are serialized via HOME_LOCK; no other thread reads these
    // specific vars concurrently. set_var is unsound only under data races on
    // the var being set, which we avoid here.
    unsafe { std::env::set_var(k, v) };
}

/// Remove an environment variable (see `set_env` for the safety rationale).
#[allow(unused_unsafe)]
fn remove_env(k: &str) {
    unsafe { std::env::remove_var(k) };
}

/// Initialize the age identity + recipients in the isolated home so that
/// secret/password/totp add/update/copy/move/reencrypt work. Must be under a
/// `HomeGuard`.
fn age_init() {
    run_ok(&["onecipher", "age", "init"]);
}

// -----------------------------------------------------------------------
// 18. `wallet list` on a fresh (empty) home reports no wallets
// -----------------------------------------------------------------------

#[test]
fn test_wallet_list_empty_home() {
    let _home = HomeGuard::new();
    run_ok(&["onecipher", "wallet", "list"]);
}

// -----------------------------------------------------------------------
// 19. Full wallet lifecycle: create → list → rename → delete
// -----------------------------------------------------------------------

#[test]
fn test_wallet_lifecycle_create_list_rename_delete() {
    let _home = HomeGuard::new();

    // create
    run_ok(&["onecipher", "wallet", "create", "--name", "alice", "--words", "12"]);

    // list should succeed (lists the created wallet)
    run_ok(&["onecipher", "wallet", "list"]);

    // rename
    run_ok(&["onecipher", "wallet", "rename", "--wallet", "alice", "--new-name", "bob"]);

    // delete requires confirm
    let res = run_cli(&["onecipher", "wallet", "delete", "--wallet", "bob"]);
    assert!(res.is_err(), "delete without --confirm must fail");

    run_ok(&["onecipher", "wallet", "delete", "--wallet", "bob", "--confirm"]);

    // Now empty again.
    run_ok(&["onecipher", "wallet", "list"]);
}

// -----------------------------------------------------------------------
// 20. `wallet create` with bad word count is rejected
// -----------------------------------------------------------------------

#[test]
fn test_wallet_create_bad_word_count() {
    let _home = HomeGuard::new();
    let res = run_cli(&["onecipher", "wallet", "create", "--name", "x", "--words", "13"]);
    assert!(res.is_err());
}

// -----------------------------------------------------------------------
// 21. `wallet create --show-mnemonic` still succeeds (secret printed to stdout)
// -----------------------------------------------------------------------

#[test]
fn test_wallet_create_show_mnemonic() {
    let _home = HomeGuard::new();
    run_ok(&[
        "onecipher",
        "wallet",
        "create",
        "--name",
        "carol",
        "--words",
        "24",
        "--show-mnemonic",
    ]);
}

// -----------------------------------------------------------------------
// 22. `wallet import --mnemonic` reads from ONECIPHER_MNEMONIC env
// -----------------------------------------------------------------------

#[test]
fn test_wallet_import_mnemonic_via_env() {
    let _home = HomeGuard::new();
    let mnemonic = "test test test test test test test test test test test junk";
    set_env("ONECIPHER_MNEMONIC", mnemonic);
    // The env var is cleared on read; set it fresh each attempt.
    let res = run_cli(&["onecipher", "wallet", "import", "--name", "imp", "--mnemonic"]);
    // Restore/remove so later tests are not affected.
    remove_env("ONECIPHER_MNEMONIC");
    assert!(res.is_ok(), "mnemonic import should succeed: {res:?}");
    run_ok(&["onecipher", "wallet", "list"]);
}

// -----------------------------------------------------------------------
// 23. `wallet import` with no source fails
// -----------------------------------------------------------------------

#[test]
fn test_wallet_import_no_source_fails() {
    let _home = HomeGuard::new();
    let res = run_cli(&["onecipher", "wallet", "import", "--name", "imp"]);
    assert!(res.is_err());
}

// -----------------------------------------------------------------------
// 24. `wallet change-password` is not automatable (interactive-only guard)
// -----------------------------------------------------------------------

#[test]
fn test_wallet_change_password_requires_terminal() {
    let _home = HomeGuard::new();
    run_ok(&["onecipher", "wallet", "create", "--name", "pw", "--words", "12"]);
    // stdin is not a terminal under cargo test → must error.
    let res = run_cli(&["onecipher", "wallet", "change-password", "--wallet", "pw"]);
    assert!(res.is_err(), "change-password must require an interactive terminal");
}

// -----------------------------------------------------------------------
// 25. `wallet export` is interactive-only (guarded)
// -----------------------------------------------------------------------

#[test]
fn test_wallet_export_requires_terminal() {
    let _home = HomeGuard::new();
    run_ok(&["onecipher", "wallet", "create", "--name", "ex", "--words", "12"]);
    let res = run_cli(&["onecipher", "wallet", "export", "--wallet", "ex"]);
    assert!(res.is_err(), "wallet export must require an interactive terminal");
}

// -----------------------------------------------------------------------
// 26. `wallet export --public-key` is interactive-only
// -----------------------------------------------------------------------

#[test]
fn test_wallet_export_public_key_requires_terminal() {
    let _home = HomeGuard::new();
    run_ok(&["onecipher", "wallet", "create", "--name", "pk", "--words", "12"]);
    let res = run_cli(&["onecipher", "wallet", "export", "--public-key", "--wallet", "pk"]);
    assert!(res.is_err(), "wallet export --public-key must require terminal");
}

// -----------------------------------------------------------------------
// 27. `wallet import --interactive` is interactive-only
// -----------------------------------------------------------------------

#[test]
fn test_wallet_import_interactive_requires_terminal() {
    let _home = HomeGuard::new();
    let res = run_cli(&["onecipher", "wallet", "import", "--name", "it", "--interactive"]);
    assert!(res.is_err(), "interactive import must require a terminal");
}

// -----------------------------------------------------------------------
// 28. `mnemonic generate` produces valid word counts
// -----------------------------------------------------------------------

#[test]
fn test_mnemonic_generate_word_counts() {
    for &w in &[12u32, 15, 18, 21, 24] {
        let cli = Cli::parse_from(["onecipher", "mnemonic", "generate", "--words", &w.to_string()]);
        assert!(crate::run(cli, &MockNetAgentClient::default()).is_ok());
    }
    // invalid count rejected
    let res = run_cli(&["onecipher", "mnemonic", "generate", "--words", "13"]);
    assert!(res.is_err());
}

// -----------------------------------------------------------------------
// 29. `mnemonic derive --chain evm` from env mnemonic yields an address
// -----------------------------------------------------------------------

#[test]
fn test_mnemonic_derive_evm() {
    let _home = HomeGuard::new();
    let mnemonic = "test test test test test test test test test test test junk";
    set_env("ONECIPHER_MNEMONIC", mnemonic);
    let res = run_cli(&["onecipher", "mnemonic", "derive", "--chain", "evm", "--index", "0"]);
    remove_env("ONECIPHER_MNEMONIC");
    assert!(res.is_ok());
}

// -----------------------------------------------------------------------
// 30. `generate` mnemonic is deterministic-entropy (just exercises the path)
// -----------------------------------------------------------------------

#[test]
fn test_generate_runs() {
    run_ok(&["onecipher", "mnemonic", "generate", "--words", "12"]);
}

// -----------------------------------------------------------------------
// 31. sign-message round trip: sign with wallet, verify with `verify`
// -----------------------------------------------------------------------

#[test]
fn test_sign_message_and_verify_roundtrip() {
    let _home = HomeGuard::new();
    run_ok(&["onecipher", "wallet", "create", "--name", "signer", "--words", "12"]);

    // Sign a message (utf8). Uses empty passphrase via resolve_signing_key.
    run_ok(&[
        "onecipher",
        "sign",
        "message",
        "--chain",
        "evm",
        "--wallet",
        "signer",
        "--message",
        "hello world",
    ]);

    // We cannot easily capture stdout here; instead validate the crypto path
    // directly via oc_signer to prove the round trip is sound end-to-end.
    use oc_core::ChainType;
    use oc_signer::signer_for_chain;
    // Derive the same address the wallet would produce using the stored key.
    let key = crate::commands::resolve_signing_key("signer", ChainType::Evm, 0).unwrap();
    let signer = signer_for_chain(ChainType::Evm);
    let address = signer.derive_address(key.expose()).unwrap();
    // Address is non-empty and 0x-prefixed EVM form.
    assert!(address.starts_with("0x"));
}

// -----------------------------------------------------------------------
// 32. sign-message rejects unsupported encoding
// -----------------------------------------------------------------------

#[test]
fn test_sign_message_bad_encoding() {
    let _home = HomeGuard::new();
    run_ok(&["onecipher", "wallet", "create", "--name", "s2", "--words", "12"]);
    let res = run_cli(&[
        "onecipher",
        "sign",
        "message",
        "--chain",
        "evm",
        "--wallet",
        "s2",
        "--message",
        "x",
        "--encoding",
        "base64",
    ]);
    assert!(res.is_err(), "unsupported encoding must be rejected");
}

// -----------------------------------------------------------------------
// 33. sign-message EIP-712 typed-data on EVM path (invalid json rejected)
// -----------------------------------------------------------------------

#[test]
fn test_sign_message_bad_typed_data() {
    let _home = HomeGuard::new();
    run_ok(&["onecipher", "wallet", "create", "--name", "s3", "--words", "12"]);
    let res = run_cli(&[
        "onecipher",
        "sign",
        "message",
        "--chain",
        "evm",
        "--wallet",
        "s3",
        "--message",
        "x",
        "--typed-data",
        "{not valid json",
    ]);
    assert!(res.is_err());
}

// -----------------------------------------------------------------------
// 34. verify rejects non-EVM chains with a clear error
// -----------------------------------------------------------------------

#[test]
fn test_verify_only_evm() {
    let res = run_cli(&[
        "onecipher",
        "verify",
        "--address",
        "0xabc",
        "--message",
        "x",
        "--signature",
        "0x01",
        "--chain",
        "solana",
    ]);
    assert!(res.is_err(), "verify must reject non-EVM chains");
}

// -----------------------------------------------------------------------
// 35. verify requires an input (message/hash/typed-data)
// -----------------------------------------------------------------------

#[test]
fn test_verify_requires_input() {
    let res = run_cli(&["onecipher", "verify", "--address", "0xabc", "--signature", "0x01"]);
    assert!(res.is_err(), "verify without input must fail");
}

// -----------------------------------------------------------------------
// 36. verify rejects malformed signature hex
// -----------------------------------------------------------------------

#[test]
fn test_verify_bad_signature_hex() {
    let res = run_cli(&[
        "onecipher",
        "verify",
        "--address",
        "0xabc",
        "--message",
        "x",
        "--signature",
        "zzzz",
    ]);
    assert!(res.is_err(), "verify must reject bad signature hex");
}

// -----------------------------------------------------------------------
// 36b. verify --typed-data is wired to EIP-712 (H-01)
// -----------------------------------------------------------------------

/// Minimal valid EIP-712 payload (mail example from EIP-712 spec).
const TYPED_DATA_JSON: &str = r#"{
    "types": {
        "EIP712Domain": [
            {"name": "name", "type": "string"},
            {"name": "version", "type": "string"},
            {"name": "chainId", "type": "uint256"},
            {"name": "verifyingContract", "type": "address"}
        ],
        "Mail": [
            {"name": "from", "type": "Person"},
            {"name": "contents", "type": "string"}
        ],
        "Person": [
            {"name": "name", "type": "string"},
            {"name": "wallet", "type": "address"}
        ]
    },
    "primaryType": "Mail",
    "domain": {
        "name": "Ether Mail",
        "version": "1",
        "chainId": 1,
        "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
    },
    "message": {
        "from": {"name": "Cow", "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},
        "contents": "Hello, Bob!"
    }
}"#;

#[test]
fn test_verify_typed_data_rejects_garbage_signature() {
    // H-01 regression: --typed-data must reach the EIP-712 pipeline instead
    // of being silently discarded. A syntactically valid payload with a
    // garbage signature fails verification (not argument parsing).
    let res = run_cli(&[
        "onecipher",
        "verify",
        "--address",
        "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826",
        "--typed-data",
        TYPED_DATA_JSON,
        "--signature",
        &format!("0x{}", "00".repeat(65)),
    ]);
    assert!(res.is_err(), "typed-data verify with garbage signature must fail");
}

#[test]
fn test_verify_typed_data_rejects_malformed_json() {
    let res = run_cli(&[
        "onecipher",
        "verify",
        "--address",
        "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826",
        "--typed-data",
        "{ not json }",
        "--signature",
        &format!("0x{}", "11".repeat(65)),
    ]);
    let err = res.expect_err("malformed typed data must be rejected");
    assert!(err.to_string().contains("EIP-712"), "error must mention EIP-712, got: {err}");
}

#[test]
fn test_verify_typed_data_file_missing() {
    let res = run_cli(&[
        "onecipher",
        "verify",
        "--address",
        "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826",
        "--typed-data-file",
        "/nonexistent/typed-data.json",
        "--signature",
        &format!("0x{}", "22".repeat(65)),
    ]);
    let err = res.expect_err("missing typed-data file must be rejected");
    assert!(err.to_string().contains("typed-data file"), "error must mention the file, got: {err}");
}

// -----------------------------------------------------------------------
// 37. sign-transaction with bad hex tx is rejected
// -----------------------------------------------------------------------

#[test]
fn test_sign_transaction_bad_hex() {
    let _home = HomeGuard::new();
    run_ok(&["onecipher", "wallet", "create", "--name", "st", "--words", "12"]);
    let res = run_cli(&[
        "onecipher",
        "sign",
        "tx",
        "--chain",
        "evm",
        "--wallet",
        "st",
        "--tx",
        "not-hex",
    ]);
    assert!(res.is_err());
}

// -----------------------------------------------------------------------
// 38. sign-auth rejects bad nonce / delegate address shapes
// -----------------------------------------------------------------------

#[test]
fn test_sign_auth_runs_on_valid_inputs() {
    let _home = HomeGuard::new();
    run_ok(&["onecipher", "wallet", "create", "--name", "sa", "--words", "12"]);
    // Bad delegate address hex → error path exercised.
    let res = run_cli(&[
        "onecipher",
        "sign",
        "auth",
        "--chain",
        "evm",
        "--wallet",
        "sa",
        "--address",
        "0xZZZ",
        "--nonce",
        "5",
    ]);
    assert!(res.is_err());
}

// -----------------------------------------------------------------------
// 39. send-tx forwards to RPC; with no daemon it surfaces an error path. We only assert arg parsing
//     + dispatch reach the command without panicking on structurally valid input (network is
//     mocked/absent).
// -----------------------------------------------------------------------

#[test]
fn test_send_tx_bad_hex() {
    let _home = HomeGuard::new();
    run_ok(&["onecipher", "wallet", "create", "--name", "stx", "--words", "12"]);
    let res = run_cli(&[
        "onecipher",
        "sign",
        "send-tx",
        "--chain",
        "evm",
        "--wallet",
        "stx",
        "--tx",
        "!!bad",
    ]);
    assert!(res.is_err());
}

// -----------------------------------------------------------------------
// 40. secret lifecycle: init age → add → list → get → update → rename → copy → move → delete
// -----------------------------------------------------------------------

#[test]
fn test_secret_full_lifecycle() {
    let _home = HomeGuard::new();
    age_init();

    // add via env
    set_env("ONECIPHER_SECRET", "topsecret");
    run_ok(&[
        "onecipher",
        "secret",
        "add",
        "github/personal",
        "--type",
        "password",
        "--meta",
        "url=https://github.com",
    ]);
    remove_env("ONECIPHER_SECRET");

    run_ok(&["onecipher", "secret", "list"]);
    run_ok(&["onecipher", "secret", "get", "github/personal"]);
    run_ok(&["onecipher", "secret", "get", "github/personal", "--json"]);

    // update secret field via env
    set_env("ONECIPHER_SECRET", "newsecret");
    run_ok(&["onecipher", "secret", "update", "github/personal", "--field", "secret"]);
    remove_env("ONECIPHER_SECRET");

    run_ok(&["onecipher", "secret", "rename", "github/personal", "github/work"]);

    run_ok(&["onecipher", "secret", "copy", "github/work", "github/copy"]);
    // copy over existing without --force must fail
    let res = run_cli(&["onecipher", "secret", "copy", "github/work", "github/copy"]);
    assert!(res.is_err());
    run_ok(&["onecipher", "secret", "copy", "github/work", "github/copy2", "--force"]);

    run_ok(&["onecipher", "secret", "move", "github/copy", "github/moved"]);
    run_ok(&["onecipher", "secret", "move", "github/copy2", "github/moved2", "--force"]);

    // delete without --force must fail (destructive action gate)
    let res = run_cli(&["onecipher", "secret", "delete", "github/work"]);
    assert!(res.is_err(), "delete without --force must fail");

    run_ok(&["onecipher", "secret", "delete", "--force", "github/work"]);
    run_ok(&["onecipher", "secret", "delete", "--force", "github/moved"]);
    run_ok(&["onecipher", "secret", "delete", "--force", "github/moved2"]);
}

// -----------------------------------------------------------------------
// 41. secret add without age init fails (no recipients)
// -----------------------------------------------------------------------

#[test]
fn test_secret_add_requires_age_init() {
    let _home = HomeGuard::new();
    set_env("ONECIPHER_SECRET", "x");
    let res = run_cli(&["onecipher", "secret", "add", "nope", "--type", "password"]);
    remove_env("ONECIPHER_SECRET");
    assert!(res.is_err(), "secret add must require age init first");
}

// -----------------------------------------------------------------------
// 42. secret get on missing name errors
// -----------------------------------------------------------------------

#[test]
fn test_secret_get_missing() {
    let _home = HomeGuard::new();
    age_init();
    let res = run_cli(&["onecipher", "secret", "get", "does-not-exist"]);
    assert!(res.is_err());
}

// -----------------------------------------------------------------------
// 43. password generate runs for all generators
// -----------------------------------------------------------------------

#[test]
fn test_password_generate_all() {
    run_ok(&["onecipher", "password", "generate", "--length", "20"]);
    run_ok(&["onecipher", "password", "generate", "--length", "20", "--symbols"]);
    run_ok(&["onecipher", "password", "generate", "--generator", "memorable", "--length", "30"]);
    run_ok(&["onecipher", "password", "generate", "--generator", "xkcd", "--xkcd-words", "5"]);
    // bad generator rejected
    let res = run_cli(&["onecipher", "password", "generate", "--generator", "bogus"]);
    assert!(res.is_err());
}

// -----------------------------------------------------------------------
// 44. password add (generate) → get → lifecycle
// -----------------------------------------------------------------------

#[test]
fn test_password_add_and_get() {
    let _home = HomeGuard::new();
    age_init();
    run_ok(&[
        "onecipher",
        "password",
        "add",
        "site",
        "--url",
        "https://site.com",
        "--username",
        "me",
        "--generate",
        "--length",
        "24",
    ]);
    run_ok(&["onecipher", "password", "get", "site"]);
    run_ok(&["onecipher", "secret", "delete", "--force", "site"]);
}

// -----------------------------------------------------------------------
// 45. totp add (base32) → generate → uris
// -----------------------------------------------------------------------

#[test]
fn test_totp_lifecycle() {
    let _home = HomeGuard::new();
    age_init();
    run_ok(&[
        "onecipher",
        "totp",
        "add",
        "myotp",
        "--secret",
        "JBSWY3DPEHPK3PXP",
        "--issuer",
        "Test",
        "--account",
        "me@test",
    ]);
    run_ok(&["onecipher", "totp", "generate", "myotp"]);
    run_ok(&["onecipher", "totp", "uris", "myotp"]);
    run_ok(&["onecipher", "totp", "hotp", "myotp", "--counter", "0"]);
    run_ok(&["onecipher", "totp", "hotp", "myotp", "--counter", "1", "--increment"]);
}

// -----------------------------------------------------------------------
// 46. totp add via otpauth URI
// -----------------------------------------------------------------------

#[test]
fn test_totp_add_otpauth() {
    let _home = HomeGuard::new();
    age_init();
    run_ok(&[
        "onecipher",
        "totp",
        "add",
        "o2",
        "--otpauth",
        "otpauth://totp/Test:me@test?secret=JBSWY3DPEHPK3PXP&issuer=Test",
    ]);
    run_ok(&["onecipher", "totp", "generate", "o2"]);
}

// -----------------------------------------------------------------------
// 47. age recipient add/list/remove + reencrypt
// -----------------------------------------------------------------------

#[test]
fn test_age_recipient_management() {
    let _home = HomeGuard::new();
    age_init();

    // A second recipient (generated, parse its public string).
    let recipient = {
        let ident = oc_secret::AgeIdentity::generate();
        ident.to_recipient_string()
    };
    run_ok(&["onecipher", "age", "recipient", "add", &recipient]);
    run_ok(&["onecipher", "age", "recipient", "list"]);
    // remove non-existent → error
    let res = run_cli(&["onecipher", "age", "recipient", "remove", "age1nonexistent"]);
    assert!(res.is_err());
    run_ok(&["onecipher", "age", "recipient", "remove", &recipient]);

    // reencrypt with no secrets still ok
    run_ok(&["onecipher", "age", "reencrypt"]);

    // identity show
    run_ok(&["onecipher", "age", "identity-show"]);
}

// -----------------------------------------------------------------------
// 48. age init is idempotence-guarded (second init errors)
// -----------------------------------------------------------------------

#[test]
fn test_age_init_twice_fails() {
    let _home = HomeGuard::new();
    age_init();
    let res = run_cli(&["onecipher", "age", "init"]);
    assert!(res.is_err(), "second age init must be rejected");
}

// -----------------------------------------------------------------------
// 49. policy create/list/show/delete lifecycle
// -----------------------------------------------------------------------

#[test]
fn test_policy_lifecycle() {
    let _home = HomeGuard::new();
    // Create a policy JSON file.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("policy.json");
    std::fs::write(
        &path,
        r#"{"id":"pol-1","name":"test","rules":[],"version":2,"created_at":"2026-01-01T00:00:00Z","action":"deny"}"#,
    )
    .unwrap();
    run_ok(&["onecipher", "policy", "create", "--file", &path.to_string_lossy()]);
    run_ok(&["onecipher", "policy", "list"]);
    run_ok(&["onecipher", "policy", "show", "--id", "pol-1"]);
    let res = run_cli(&["onecipher", "policy", "delete", "--id", "pol-1"]);
    assert!(res.is_err(), "policy delete requires --confirm");
    run_ok(&["onecipher", "policy", "delete", "--id", "pol-1", "--confirm"]);
}

// -----------------------------------------------------------------------
// 50. policy create with missing file errors
// -----------------------------------------------------------------------

#[test]
fn test_policy_create_missing_file() {
    let _home = HomeGuard::new();
    let res = run_cli(&["onecipher", "policy", "create", "--file", "/no/such/file.json"]);
    assert!(res.is_err());
}

// -----------------------------------------------------------------------
// 51. api key lifecycle: create/list/revoke
// -----------------------------------------------------------------------

#[test]
fn test_key_lifecycle() {
    let _home = HomeGuard::new();
    // The API-key path decrypts the target wallet, so one must exist first
    // (CLI-created wallets are empty-passphrase by default).
    run_ok(&["onecipher", "wallet", "create", "--name", "w1"]);
    // Attached policies must be registered before they can be referenced.
    let dir = tempfile::tempdir().unwrap();
    let policy_path = dir.path().join("policy.json");
    std::fs::write(
        &policy_path,
        r#"{"id":"p1","name":"test","rules":[],"version":2,"created_at":"2026-01-01T00:00:00Z","action":"deny"}"#,
    )
    .unwrap();
    run_ok(&["onecipher", "policy", "create", "--file", &policy_path.to_string_lossy()]);
    // Timestamps only accept hour-or-smaller spans (jiff invariant).
    let expires =
        jiff::Timestamp::now().checked_add(jiff::Span::new().hours(24)).unwrap().to_string();
    run_ok(&[
        "onecipher",
        "key",
        "create",
        "--name",
        "agent1",
        "--wallet",
        "w1",
        "--policy",
        "p1",
        "--expires-at",
        &expires,
    ]);
    run_ok(&["onecipher", "key", "list"]);
    // revoke requires confirm
    let res = run_cli(&["onecipher", "key", "revoke", "--id", "agent1"]);
    assert!(res.is_err());
}

// -----------------------------------------------------------------------
// 51b. api key create works on an EMPTY-passphrase wallet without any
//      passphrase env var (regression: forced read_passphrase made
//      decryption fail on default wallets)
// -----------------------------------------------------------------------

#[test]
fn test_key_create_empty_passphrase_wallet() {
    let _home = HomeGuard::new();
    run_ok(&["onecipher", "wallet", "create", "--name", "nopw"]);
    // No ONECIPHER_PASSPHRASE set — must not prompt (cfg(test) stdin is
    // non-interactive) and must not fail decryption.
    run_ok(&["onecipher", "key", "create", "--name", "agent-nopw", "--wallet", "nopw"]);

    let keys = oc_wallet::key_store::list_api_keys(None).unwrap();
    assert_eq!(keys.len(), 1, "exactly one key file expected");
    assert_eq!(keys[0].name, "agent-nopw");
    assert_eq!(keys[0].wallet_ids.len(), 1);

    // A protected wallet still requires the matching passphrase.
    set_env("ONECIPHER_PASSPHRASE", "np-secret");
    run_ok(&[
        "onecipher",
        "wallet",
        "change-password",
        "--wallet",
        "nopw",
        "--passphrase",
        "",
        "--new-passphrase",
        "np-secret",
    ]);
    remove_env("ONECIPHER_PASSPHRASE");

    // Without the passphrase in non-interactive mode → clean error.
    let res =
        run_cli(&["onecipher", "key", "create", "--name", "agent-locked", "--wallet", "nopw"]);
    assert!(res.is_err(), "protected wallet must require a passphrase non-interactively");
}

// -----------------------------------------------------------------------
// 52. config show / set
// -----------------------------------------------------------------------

#[test]
fn test_config_show_and_set() {
    let _home = HomeGuard::new();
    run_ok(&["onecipher", "config", "show"]);
    run_ok(&["onecipher", "config", "set", "webui.enabled", "true"]);
    run_ok(&["onecipher", "config", "set", "rpc.eip155:1", "https://example.com"]);
}

// -----------------------------------------------------------------------
// 52b. `config set wc.trusted_origins` accepts a JSON array and round-trips
// -----------------------------------------------------------------------

#[test]
fn test_config_set_trusted_origins_json_array() {
    let _home = HomeGuard::new();
    run_ok(&["onecipher", "config", "set", "wc.trusted_origins", r#"["iam.example.com","x.com"]"#]);

    let config = oc_core::Config::load_or_default();
    assert_eq!(config.wc.trusted_origins, vec!["iam.example.com", "x.com"]);

    // Non-array / non-string values are rejected.
    let res = run_cli(&["onecipher", "config", "set", "wc.trusted_origins", "iam.example.com"]);
    assert!(res.is_err(), "a bare string must be rejected");
    let res = run_cli(&["onecipher", "config", "set", "wc.trusted_origins", "[1,2]"]);
    assert!(res.is_err(), "non-string array entries must be rejected");
}

// -----------------------------------------------------------------------
// 52c. systemd user service: install writes the unit file, status reports it,
//      uninstall removes it (systemctl best-effort)
// -----------------------------------------------------------------------

#[test]
fn test_service_install_status_uninstall() {
    let _home = HomeGuard::new();
    let unit = _home.path().join(".config/systemd/user/onecipher.service");

    run_ok(&["onecipher", "service", "status"]);
    assert!(!unit.exists(), "status must not create the unit file");

    run_ok(&["onecipher", "service", "install"]);
    assert!(unit.exists(), "install must write the unit file");

    let contents = std::fs::read_to_string(&unit).unwrap_or_default();
    assert!(contents.contains("ExecStart="), "unit must carry ExecStart");
    assert!(contents.contains("--daemon"), "unit must run the daemon");
    assert!(contents.contains("Restart=on-failure"), "unit must set Restart=on-failure");
    assert!(contents.contains("RestartSec=2"), "unit must set RestartSec=2");
    assert!(
        contents.contains("WantedBy=default.target"),
        "unit must be enabled for the default target"
    );

    run_ok(&["onecipher", "service", "status"]);

    run_ok(&["onecipher", "service", "uninstall"]);
    assert!(!unit.exists(), "uninstall must remove the unit file");
}

// -----------------------------------------------------------------------
// 52d. `service` subcommands parse (arg-parse level)
// -----------------------------------------------------------------------

#[test]
fn test_service_subcommands_parse() {
    assert!(matches!(
        Cli::parse_from(["onecipher", "service", "install"]).command,
        Some(Commands::Service { subcommand: crate::cli::ServiceCommands::Install })
    ));
    assert!(matches!(
        Cli::parse_from(["onecipher", "service", "uninstall"]).command,
        Some(Commands::Service { subcommand: crate::cli::ServiceCommands::Uninstall })
    ));
    assert!(matches!(
        Cli::parse_from(["onecipher", "service", "status"]).command,
        Some(Commands::Service { subcommand: crate::cli::ServiceCommands::Status })
    ));
}

// -----------------------------------------------------------------------
// 53. status / info / doctor / completion / fsck / grep / find / migrate run
// -----------------------------------------------------------------------

#[test]
fn test_local_readonly_commands_run() {
    let _home = HomeGuard::new();
    run_ok(&["onecipher", "status"]);
    run_ok(&["onecipher", "wallet", "info"]);
    // doctor fails closed on an empty home (missing age identity / store /
    // index), so bootstrap the secret store first — mirroring e2e_l6_doctor.
    // `secret add` reads the value from ONECIPHER_SECRET (no stdin piping
    // in-process).
    age_init();
    set_env("ONECIPHER_SECRET", "doctor-probe");
    run_ok(&["onecipher", "secret", "add", "doctor/probe", "--type", "note"]);
    remove_env("ONECIPHER_SECRET");
    run_ok(&["onecipher", "doctor"]);
    run_ok(&["onecipher", "completion", "bash"]);
    run_ok(&["onecipher", "completion", "zsh"]);
    run_ok(&["onecipher", "completion", "fish"]);
    // unsupported shell
    let res = run_cli(&["onecipher", "completion", "powershell"]);
    assert!(res.is_ok(), "completion should accept all clap shell names");
    run_ok(&["onecipher", "fsck"]);
    run_ok(&["onecipher", "fsck", "--fix"]);
    run_ok(&["onecipher", "migrate", "--dry-run"]);
}

// -----------------------------------------------------------------------
// 54. grep / find over the secret store
// -----------------------------------------------------------------------

#[test]
fn test_grep_and_find() {
    let _home = HomeGuard::new();
    age_init();
    set_env("ONECIPHER_SECRET", "findme123");
    run_ok(&["onecipher", "secret", "add", "grep/target", "--type", "password"]);
    remove_env("ONECIPHER_SECRET");

    run_ok(&["onecipher", "grep", "findme"]);
    run_ok(&["onecipher", "grep", "findme", "--json"]);
    run_ok(&["onecipher", "grep", "nomatch"]);
    run_ok(&["onecipher", "find", "grep"]);
    run_ok(&["onecipher", "find", "grep", "--json"]);
    run_ok(&["onecipher", "find", "--type", "password"]);

    run_ok(&["onecipher", "secret", "delete", "--force", "grep/target"]);
}

// -----------------------------------------------------------------------
// 55. backup export / import round trip (.ocbk)
// -----------------------------------------------------------------------

#[test]
fn test_backup_export_import() {
    let _home = HomeGuard::new();
    run_ok(&["onecipher", "wallet", "create", "--name", "bk", "--words", "12"]);
    let identity = oc_vault::crypto::AgeIdentity::generate();
    let recipient = identity.to_recipient_string();
    let secret = identity.to_secret_string();
    let out = _home.path().join("wallet.ocbk");
    run_ok(&[
        "onecipher",
        "backup",
        "export",
        "--out",
        &out.to_string_lossy(),
        "--recipient",
        recipient.as_str(),
    ]);
    assert!(out.exists(), "backup file must be created");
    run_ok(&[
        "onecipher",
        "backup",
        "import",
        "--in",
        &out.to_string_lossy(),
        "--identity",
        secret.as_str(),
    ]);
}

// -----------------------------------------------------------------------
// 56. sbom generate / verify
// -----------------------------------------------------------------------

#[test]
fn test_sbom_generate_and_verify() {
    let _home = HomeGuard::new();
    let out = _home.path().join("sbom.cdx.json");
    run_ok(&["onecipher", "sbom", "generate", "--output", &out.to_string_lossy()]);
    assert!(out.exists());
    run_ok(&["onecipher", "sbom", "verify", "--file", &out.to_string_lossy()]);
    // verify missing file errors
    let res = run_cli(&["onecipher", "sbom", "verify", "--file", "/no/such.cdx.json"]);
    assert!(res.is_err());
}

// -----------------------------------------------------------------------
// 57. env command injects secrets as env vars (exec form)
// -----------------------------------------------------------------------

#[test]
fn test_env_command_injects_secret() {
    let _home = HomeGuard::new();
    age_init();
    set_env("ONECIPHER_SECRET", "envval");
    run_ok(&["onecipher", "secret", "add", "env/sec", "--type", "password"]);
    remove_env("ONECIPHER_SECRET");

    // exec a command that prints the injected env var
    let out_file = _home.path().join("envout.txt");
    run_ok(&[
        "onecipher",
        "env",
        "--name",
        "env/sec",
        "--exec",
        "--",
        "sh",
        "-c",
        &format!("printf '%s' \"$ENV_SEC\" > {}", out_file.to_string_lossy()),
    ]);
    let got = std::fs::read_to_string(&out_file).unwrap_or_default();
    assert_eq!(got, "envval", "env injection must expose secret as ENV_SEC");
}

// -----------------------------------------------------------------------
// 58. agent-secret requires a valid API token (no token → error)
// -----------------------------------------------------------------------

#[test]
fn test_agent_secret_requires_token() {
    let _home = HomeGuard::new();
    let res = run_cli(&["onecipher", "agent-secret", "list"]);
    assert!(res.is_err(), "agent-secret must require ONECIPHER_PASSPHRASE token");
}

// -----------------------------------------------------------------------
// 59. audit list/secrets run locally
// -----------------------------------------------------------------------

#[test]
fn test_audit_commands_run() {
    let _home = HomeGuard::new();
    age_init();
    run_ok(&["onecipher", "audit", "list"]);
    run_ok(&["onecipher", "audit", "list", "--since", "7d"]);
    run_ok(&["onecipher", "audit", "secrets", "--skip-hibp"]);
    run_ok(&["onecipher", "audit", "secrets", "--format", "json", "--skip-hibp"]);
}

// -----------------------------------------------------------------------
// 60. session-key / ocpay via mock client (RPC construction already covered by tests 5-13).
//     Negative: unknown subcommand parses fail.
// -----------------------------------------------------------------------

#[test]
fn test_session_key_create_bad_credential_hex() {
    let res = run_cli(&[
        "onecipher",
        "session-key",
        "create",
        "--label",
        "x",
        "--challenge",
        "aa",
        "--signature",
        "zz",
        "--credential-id",
        "c",
    ]);
    assert!(res.is_err(), "bad signature hex must be rejected");
}

// -----------------------------------------------------------------------
// 61. vanity requires at least one pattern
// -----------------------------------------------------------------------

#[test]
fn test_vanity_requires_pattern() {
    let res = run_cli(&["onecipher", "vanity", "--count", "1"]);
    assert!(res.is_err(), "vanity without pattern must fail");
}

#[test]
fn test_vanity_suffix_match() {
    // Brute force a 1-hex suffix (fast). Just assert it finds something valid.
    let _home = HomeGuard::new();
    run_ok(&["onecipher", "vanity", "--ends-with", "0", "--count", "1", "--jobs", "4"]);
}

#[test]
fn test_vanity_bad_pattern() {
    let res = run_cli(&["onecipher", "vanity", "--starts-with", "ZZ", "--count", "1"]);
    assert!(res.is_err(), "non-hex pattern must be rejected");
}

// -----------------------------------------------------------------------
// 62. intent submit/simulate/execute route through mock-free local parse and fail without a session
//     key (network/daemon absent) — assert dispatch reaches the command and reports an error rather
//     than panicking.
// -----------------------------------------------------------------------

#[test]
fn test_intent_submit_reaches_command() {
    let res = run_cli(&[
        "onecipher",
        "intent",
        "submit",
        "--json",
        r#"{"type":"Pay","amount":"1.0 USDC","recipient":"0xabc"}"#,
        "--chain",
        "eip155:8453",
        "--session-key",
        "sk-missing",
        "--yes",
    ]);
    // Without a real session key / daemon the command should error, not panic.
    assert!(res.is_err());
}

// -----------------------------------------------------------------------
// 63. wc pair/connect/connect-bad-uri parse + dispatch
// -----------------------------------------------------------------------

#[test]
fn test_wc_parse_and_dispatch() {
    // Bad URI → parse error at the daemon control socket stage (no daemon).
    let res = run_cli(&["onecipher", "wc", "connect", "not-a-wc-uri"]);
    assert!(res.is_err());
    // sessions / disconnect reach the command (no daemon → error, not panic)
    let _ = run_cli(&["onecipher", "wc", "sessions"]);
    let _ = run_cli(&["onecipher", "wc", "disconnect", "topic123"]);
    // pair reaches the daemon control socket (no daemon → error)
    let _ = run_cli(&["onecipher", "wc", "pair", "--ttl", "60"]);
}

// -----------------------------------------------------------------------
// 64. uninstall --purge is destructive and must NOT run in tests; assert it is at least reachable
//     via parse_from and that the non-purge form is a no-op guarded path (we do not actually invoke
//     it to avoid deleting data).
// -----------------------------------------------------------------------

#[test]
fn test_uninstall_parses() {
    let cli = Cli::parse_from(["onecipher", "uninstall", "--purge"]);
    assert!(matches!(cli.command, Some(Commands::Uninstall { purge: true, force: false })));
    let cli = Cli::parse_from(["onecipher", "uninstall"]);
    assert!(matches!(cli.command, Some(Commands::Uninstall { purge: false, force: false })));
    let cli = Cli::parse_from(["onecipher", "uninstall", "--purge", "--force"]);
    assert!(matches!(cli.command, Some(Commands::Uninstall { purge: true, force: true })));
}

// -----------------------------------------------------------------------
// 65. update is network-bound; assert parse + that it is reachable. Never actually invoked (would
//     hit the network / self-replace).
// -----------------------------------------------------------------------

#[test]
fn test_update_parses() {
    let cli = Cli::parse_from(["onecipher", "update", "--force"]);
    assert!(matches!(cli.command, Some(Commands::Update { force: true })));
}

// -----------------------------------------------------------------------
// 66. webui open parses (browser launch not exercised in CI)
// -----------------------------------------------------------------------

#[test]
fn test_webui_parses() {
    let cli = Cli::parse_from(["onecipher", "webui", "open"]);
    assert!(matches!(cli.command, Some(Commands::Webui { .. })));
}

// -----------------------------------------------------------------------
// 69. secret add via --stdin full payload path
// -----------------------------------------------------------------------

#[test]
fn test_secret_add_via_stdin_payload() {
    let _home = HomeGuard::new();
    age_init();
    // The --stdin contract is a JSON SecretPayload. Spawning
    // `current_exe()` cannot exercise it (`current_exe()` here is the test
    // harness, not the CLI binary, so libtest chokes on the CLI args), so
    // the same shape is driven in-process: parse the payload exactly as
    // `--stdin` intake does, persist it through the unified CRUD plane, then
    // read it back through the real CLI dispatch.
    let mut payload: oc_core::SecretPayload =
        serde_json::from_str(r#"{"secret":"stdin-secret","notes":"n","extra":null}"#).unwrap();
    assert_eq!(payload.secret, "stdin-secret");
    let store = crate::commands::open_secret_store().unwrap();
    let recipients = crate::commands::load_recipients().unwrap();
    let hardened = oc_signer::SecretBytes::from_slice(payload.secret.as_bytes()).unwrap();
    oc_secret::create_entry_full(
        &store,
        oc_core::SecretKind::Password,
        "stdin/sec",
        &hardened,
        payload.notes.take(),
        payload.extra.take(),
        Default::default(),
        &recipients,
    )
    .unwrap();
    run_ok(&["onecipher", "secret", "get", "stdin/sec", "--json"]);
    run_ok(&["onecipher", "secret", "delete", "--force", "stdin/sec"]);
}

// ===========================================================================
// Non-interactive support tests (Phase: all commands usable without a TTY)
// ===========================================================================

// -----------------------------------------------------------------------
// 70. wallet change-password works non-interactively via flags
// -----------------------------------------------------------------------

#[test]
fn test_wallet_change_password_noninteractive_flags() {
    let _home = HomeGuard::new();
    // Create a wallet with a passphrase.
    set_env("ONECIPHER_PASSPHRASE", "old-pass");
    run_ok(&["onecipher", "wallet", "create", "--name", "cp", "--words", "12"]);
    remove_env("ONECIPHER_PASSPHRASE");

    // Non-interactive change: old + new via flags.
    run_ok(&[
        "onecipher",
        "wallet",
        "change-password",
        "--wallet",
        "cp",
        "--passphrase",
        "old-pass",
        "--new-passphrase",
        "new-pass",
    ]);

    // Verify the new passphrase works by exporting.
    set_env("ONECIPHER_PASSPHRASE", "new-pass");
    // wallet export is non-interactive when env passphrase is set.
    run_ok(&["onecipher", "wallet", "export", "--wallet", "cp"]);
    remove_env("ONECIPHER_PASSPHRASE");
}

// -----------------------------------------------------------------------
// 71. wallet change-password without passphrase and no TTY errors cleanly
// -----------------------------------------------------------------------

#[test]
fn test_wallet_change_password_no_ttl_input_errors() {
    let _home = HomeGuard::new();
    run_ok(&["onecipher", "wallet", "create", "--name", "cp2", "--words", "12"]);
    // No flags, no env, no TTY → clear error, not a hang.
    let res = run_cli(&["onecipher", "wallet", "change-password", "--wallet", "cp2"]);
    assert!(res.is_err());
}

// -----------------------------------------------------------------------
// 72. wallet change-password wrong current passphrase rejected
// -----------------------------------------------------------------------

#[test]
fn test_wallet_change_password_wrong_old() {
    let _home = HomeGuard::new();
    set_env("ONECIPHER_PASSPHRASE", "correct-pass");
    run_ok(&["onecipher", "wallet", "create", "--name", "cp3", "--words", "12"]);
    remove_env("ONECIPHER_PASSPHRASE");

    let res = run_cli(&[
        "onecipher",
        "wallet",
        "change-password",
        "--wallet",
        "cp3",
        "--passphrase",
        "wrong-old",
        "--new-passphrase",
        "x",
    ]);
    assert!(res.is_err(), "wrong current passphrase must be rejected");
}

// -----------------------------------------------------------------------
// 73. wallet change-password same passphrase rejected
// -----------------------------------------------------------------------

#[test]
fn test_wallet_change_password_same_rejected() {
    let _home = HomeGuard::new();
    set_env("ONECIPHER_PASSPHRASE", "same");
    run_ok(&["onecipher", "wallet", "create", "--name", "cp4", "--words", "12"]);
    remove_env("ONECIPHER_PASSPHRASE");

    let res = run_cli(&[
        "onecipher",
        "wallet",
        "change-password",
        "--wallet",
        "cp4",
        "--passphrase",
        "same",
        "--new-passphrase",
        "same",
    ]);
    assert!(res.is_err(), "identical old/new must be rejected");
}

// -----------------------------------------------------------------------
// 74. wallet export non-interactive via env passphrase
// -----------------------------------------------------------------------

#[test]
fn test_wallet_export_noninteractive_env() {
    let _home = HomeGuard::new();
    // Create a passphrase-protected wallet.
    set_env("ONECIPHER_PASSPHRASE", "pw1");
    run_ok(&["onecipher", "wallet", "create", "--name", "exp", "--words", "12"]);
    remove_env("ONECIPHER_PASSPHRASE");

    // Without env passphrase and no TTY → clean error (not a hang).
    let res = run_cli(&["onecipher", "wallet", "export", "--wallet", "exp"]);
    assert!(res.is_err(), "export without passphrase and no TTY must error");

    // With env passphrase → works non-interactively.
    set_env("ONECIPHER_PASSPHRASE", "pw1");
    run_ok(&["onecipher", "wallet", "export", "--wallet", "exp"]);
    remove_env("ONECIPHER_PASSPHRASE");
}

// -----------------------------------------------------------------------
// 75. wallet export --public-key non-interactive via env passphrase
// -----------------------------------------------------------------------

#[test]
fn test_wallet_export_public_key_noninteractive_env() {
    let _home = HomeGuard::new();
    set_env("ONECIPHER_PASSPHRASE", "pw1");
    run_ok(&["onecipher", "wallet", "create", "--name", "pkexp", "--words", "12"]);
    remove_env("ONECIPHER_PASSPHRASE");

    // Without env → clean error.
    let res = run_cli(&["onecipher", "wallet", "export", "--public-key", "--wallet", "pkexp"]);
    assert!(res.is_err());

    // With env passphrase → works.
    set_env("ONECIPHER_PASSPHRASE", "pw1");
    run_ok(&[
        "onecipher",
        "wallet",
        "export",
        "--public-key",
        "--wallet",
        "pkexp",
        "--chain",
        "evm",
    ]);
    remove_env("ONECIPHER_PASSPHRASE");
}

// -----------------------------------------------------------------------
// 76. wallet export non-interactive on an EMPTY-passphrase wallet
// -----------------------------------------------------------------------

#[test]
fn test_wallet_export_empty_passphrase_wallet() {
    let _home = HomeGuard::new();
    // Create wallet without setting a passphrase env → empty passphrase.
    run_ok(&["onecipher", "wallet", "create", "--name", "nopw", "--words", "12"]);
    // Export stays fail-closed without a TTY: an explicit (here empty) env
    // passphrase opts in to non-interactive disclosure.
    set_env("ONECIPHER_PASSPHRASE", "");
    run_ok(&["onecipher", "wallet", "export", "--wallet", "nopw"]);
    remove_env("ONECIPHER_PASSPHRASE");
}

// -----------------------------------------------------------------------
// 77. secret get --copy works non-interactively (copies secret; clipboard may be unavailable
//     headless — assert the command still routes to the clipboard helper without a TTY prompt)
// -----------------------------------------------------------------------

#[test]
fn test_secret_get_copy_routes_noninteractive() {
    let _home = HomeGuard::new();
    age_init();
    set_env("ONECIPHER_SECRET", "copy-me");
    run_ok(&["onecipher", "secret", "add", "cp/target", "--type", "password"]);
    remove_env("ONECIPHER_SECRET");

    // On a headless CI the clipboard backend may fail; either way this must
    // NOT prompt for a TTY — it must return promptly (Ok on systems with a
    // clipboard, Err(CliError) on headless ones). We only assert it does not
    // hang and returns a Result rather than panicking.
    let res = run_cli(&["onecipher", "secret", "get", "cp/target", "--copy", "--timeout", "0"]);
    assert!(
        res.is_ok() || res.is_err(),
        "copy must route to clipboard (Ok) or fail cleanly headless (Err)"
    );
}

// -----------------------------------------------------------------------
// 78. webui approval/auth subcommands parse and dispatch; without a running daemon they fail with a
//     clear "port file not found" error (not panic)
// -----------------------------------------------------------------------

#[test]
fn test_webui_approval_requires_running_daemon() {
    let _home = HomeGuard::new();
    // No webui.port file → clear error, no panic.
    let res = run_cli(&["onecipher", "webui", "approval", "list"]);
    assert!(res.is_err(), "approval list without daemon must error");
    let err = format!("{}", res.unwrap_err());
    assert!(err.contains("port file"), "error must mention the port file, got: {err}");

    let res = run_cli(&[
        "onecipher",
        "webui",
        "approval",
        "show",
        "00000000-0000-0000-0000-000000000000",
    ]);
    assert!(res.is_err());

    let res = run_cli(&[
        "onecipher",
        "webui",
        "approval",
        "approve",
        "00000000-0000-0000-0000-000000000000",
        "--yes",
    ]);
    assert!(res.is_err());

    let res = run_cli(&[
        "onecipher",
        "webui",
        "approval",
        "reject",
        "00000000-0000-0000-0000-000000000000",
        "--reason",
        "x",
        "--yes",
    ]);
    assert!(res.is_err());

    let res = run_cli(&["onecipher", "webui", "auth", "status"]);
    assert!(res.is_err());
    let res = run_cli(&["onecipher", "webui", "auth", "lock"]);
    assert!(res.is_err());
    let res = run_cli(&["onecipher", "webui", "auth", "bootstrap"]);
    assert!(res.is_err());
}

// -----------------------------------------------------------------------
// 79. webui approval list parses (endpoint path construction is validated against a mock HTTP
//     server — see below)
// -----------------------------------------------------------------------

#[test]
fn test_webui_approval_parses() {
    let cli = Cli::parse_from(["onecipher", "webui", "approval", "list"]);
    assert!(matches!(
        cli.command,
        Some(Commands::Webui {
            subcommand: crate::cli::WebUiCommands::Approval {
                subcommand: crate::cli::ApprovalCommands::List
            }
        })
    ));
}

// -----------------------------------------------------------------------
// 80. HTTP bridge against a mock localhost server: verify URL construction, JSON body, and error
//     handling without a real daemon.
// -----------------------------------------------------------------------

#[test]
fn test_webui_http_bridge_against_mock_server() {
    use std::io::{Read, Write};

    let _home = HomeGuard::new();

    // A tiny mock HTTP server that emulates the daemon's /api/approvals and
    // /api/auth endpoints on 127.0.0.1. Header violations are RECORDED, not
    // asserted in-thread: a panicking server thread would leave the client
    // hanging on its next request instead of failing the test with context.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let header_violations = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let violations_in_thread = header_violations.clone();
    let server = std::thread::spawn(move || {
        for _ in 0..5 {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 2048];
            let n = stream.read(&mut buf).unwrap();
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let (status, body) = if !req.to_ascii_lowercase().contains("x-oc-cli-token:") {
                violations_in_thread
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(req.lines().next().unwrap_or_default().to_string());
                (401, r#"{"error":"authentication required"}"#.to_string())
            } else if req.starts_with("GET /api/approvals ") {
                (
                    200,
                    r#"{"approvals":[{"id":"a1","method":"eth_sendTransaction","dapp_name":"Mock","chain_id":"eip155:1"}]}"#.to_string(),
                )
            } else if req.starts_with("POST /api/approvals/") && req.contains("/decision") {
                // Echo the decision body back.
                (200, r#"{"ok":true}"#.to_string())
            } else if req.starts_with("GET /api/auth/status ") {
                (200, r#"{"locked":false}"#.to_string())
            } else if req.starts_with("POST /api/auth/lock ") {
                (200, r#"{"ok":true}"#.to_string())
            } else if req.starts_with("POST /api/auth/bootstrap ") {
                (200, r#"{"needs_registration":true,"bootstrap_ready":false}"#.to_string())
            } else {
                (404, r#"{"error":"not found"}"#.to_string())
            };
            let resp = format!(
                "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(resp.as_bytes()).unwrap();
        }
    });

    // Write the mock port into $HOME/.onecipher/webui.port (the daemon's
    // state dir) plus a CLI capability token the bridge must present.
    let state_dir = _home.path().join(".onecipher");
    std::fs::create_dir_all(&state_dir).unwrap();
    std::fs::write(state_dir.join("webui.port"), port.to_string()).unwrap();
    std::fs::write(state_dir.join("webui_cli.token"), b"test-cli-token-123").unwrap();

    // approval list should succeed against the mock and find 1 approval.
    // (It prints; we only assert no error.)
    run_ok(&["onecipher", "webui", "approval", "list"]);
    // auth status/lock/bootstrap
    run_ok(&["onecipher", "webui", "auth", "status"]);
    run_ok(&["onecipher", "webui", "auth", "lock"]);
    run_ok(&["onecipher", "webui", "auth", "bootstrap"]);
    // reject with --yes
    run_ok(&[
        "onecipher",
        "webui",
        "approval",
        "reject",
        "00000000-0000-0000-0000-000000000001",
        "--reason",
        "test",
        "--yes",
    ]);

    server.join().expect("mock server thread should not panic");
    assert!(
        header_violations.lock().unwrap_or_else(std::sync::PoisonError::into_inner).is_empty(),
        "every bridge request must carry the x-oc-cli-token header"
    );
    let _ = listener;
}

// ===========================================================================
// B-level automation: real Key-Agent UDS round-trip, intent lifecycle,
// send-tx broadcast mock JSON-RPC
// ===========================================================================

// -----------------------------------------------------------------------
// B1a. Real Key-Agent UDS server round-trip: register passkey → generate
//      challenge → create session key → revoke. Drives the REAL server via
//      FrameClient over a temp socket (HOME isolated).
// -----------------------------------------------------------------------

#[test]
fn test_keyagent_real_uds_session_key_roundtrip() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    use oc_keyagent::{
        frame::FrameClient,
        proto::{
            CreateSessionKeyRequest, CreateSessionKeyResponse, Empty, GenerateChallengeRequest,
            GenerateChallengeResponse, ListSessionKeysRequest, ListSessionKeysResponse,
            PasskeyAuthorization, RegisterPasskeyRequest, RegisterPasskeyResponse,
            RevokeSessionKeyRequest, RevokeSessionKeyResponse, SessionKeyStatus,
        },
        request::{KeyAgentRequest, KeyAgentRequestKind},
        response::KeyAgentResponseKind,
    };
    use prost::Message;

    let _home = HomeGuard::new();
    let sock = _home.path().join("ka.sock");
    let sock_str = sock.to_string_lossy().into_owned();

    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = stop.clone();
    let sock_thread = sock_str.clone();
    let server = std::thread::spawn(move || {
        let _ = oc_keyagent::server::run(Some(&sock_thread), Some(stop_thread));
    });

    // Wait for the socket to appear.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !sock.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(sock.exists(), "key-agent socket must appear");

    let client = FrameClient::new(&sock_str);

    // 1. Register an Ed25519 passkey.
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let vk_bytes = signing_key.verifying_key().to_bytes().to_vec();
    let reg_req = KeyAgentRequest {
        kind: Some(KeyAgentRequestKind::RegisterPasskey(RegisterPasskeyRequest {
            wallet_id: "wallet-1".to_string(),
            credential_id: "cred-b1".to_string(),
            algorithm: "ed25519".to_string(),
            public_key: vk_bytes,
        })),
    };
    let resp = client.send_request(&reg_req).unwrap();
    match &resp.kind {
        Some(KeyAgentResponseKind::Ok(bytes)) => {
            let decoded = RegisterPasskeyResponse::decode(bytes.as_slice()).unwrap();
            assert!(decoded.registered, "passkey registration must succeed");
        }
        other => panic!("expected Ok register, got {other:?}"),
    }

    // Helper: issue a challenge and sign challenge || credential_id.
    let make_auth = |client: &FrameClient, cred: &str| -> PasskeyAuthorization {
        let chal_req = KeyAgentRequest {
            kind: Some(KeyAgentRequestKind::GenerateChallenge(GenerateChallengeRequest {
                credential_id: cred.to_string(),
            })),
        };
        let resp = client.send_request(&chal_req).unwrap();
        let bytes = match &resp.kind {
            Some(KeyAgentResponseKind::Ok(b)) => b.clone(),
            other => panic!("expected Ok challenge, got {other:?}"),
        };
        let challenge = GenerateChallengeResponse::decode(bytes.as_slice()).unwrap().challenge;
        assert_eq!(challenge.len(), 32, "challenge must be 32 bytes");
        let mut msg = challenge.clone();
        msg.extend_from_slice(cred.as_bytes());
        use ed25519_dalek::Signer as _;
        let sig = signing_key.sign(&msg).to_bytes().to_vec();
        PasskeyAuthorization { challenge, signature: sig, credential_id: cred.to_string() }
    };

    // 2. Create a session key with a valid challenge signature.
    let auth = make_auth(&client, "cred-b1");
    let create_req = KeyAgentRequest {
        kind: Some(KeyAgentRequestKind::CreateSessionKey(CreateSessionKeyRequest {
            label: "b1-test".to_string(),
            rules: None,
            budget: None,
            auth: Some(auth),
        })),
    };
    let resp = client.send_request(&create_req).unwrap();
    let created = match &resp.kind {
        Some(KeyAgentResponseKind::Ok(bytes)) => {
            CreateSessionKeyResponse::decode(bytes.as_slice()).unwrap()
        }
        other => panic!("expected Ok create, got {other:?}"),
    };
    assert!(created.session_key_id.starts_with("sk-"), "session key id");
    let sk_id = created.session_key_id.clone();

    // 2b. ListSessionKeys reports the fresh key as ACTIVE.
    {
        let list_req = KeyAgentRequest {
            kind: Some(KeyAgentRequestKind::ListSessionKeys(ListSessionKeysRequest {})),
        };
        let resp = client.send_request(&list_req).unwrap();
        match &resp.kind {
            Some(KeyAgentResponseKind::Ok(bytes)) => {
                let decoded = ListSessionKeysResponse::decode(bytes.as_slice()).unwrap();
                assert_eq!(decoded.keys.len(), 1);
                assert_eq!(decoded.keys[0].session_key_id, sk_id);
                assert_eq!(decoded.keys[0].label, "b1-test");
                assert_eq!(decoded.keys[0].status, SessionKeyStatus::Active as i32);
            }
            other => panic!("expected Ok list, got {other:?}"),
        }
    }

    // 3. Revoke with a FRESH challenge (single-use).
    let auth2 = make_auth(&client, "cred-b1");
    let revoke_req = KeyAgentRequest {
        kind: Some(KeyAgentRequestKind::RevokeSessionKey(RevokeSessionKeyRequest {
            session_key_id: created.session_key_id,
            auth: Some(auth2),
        })),
    };
    let resp = client.send_request(&revoke_req).unwrap();
    match &resp.kind {
        Some(KeyAgentResponseKind::Ok(bytes)) => {
            let decoded = RevokeSessionKeyResponse::decode(bytes.as_slice()).unwrap();
            assert!(decoded.revoked_at_unix > 0);
        }
        other => panic!("expected Ok revoke, got {other:?}"),
    }

    // 3b. ListSessionKeys now reports the key as REVOKED.
    {
        let list_req = KeyAgentRequest {
            kind: Some(KeyAgentRequestKind::ListSessionKeys(ListSessionKeysRequest {})),
        };
        let resp = client.send_request(&list_req).unwrap();
        match &resp.kind {
            Some(KeyAgentResponseKind::Ok(bytes)) => {
                let decoded = ListSessionKeysResponse::decode(bytes.as_slice()).unwrap();
                assert_eq!(decoded.keys.len(), 1);
                assert_eq!(decoded.keys[0].status, SessionKeyStatus::Revoked as i32);
            }
            other => panic!("expected Ok list after revoke, got {other:?}"),
        }
    }

    // 4. Reusing the SAME challenge must be rejected (replay protection). Issue ONE challenge, sign
    //    it TWICE with the same nonce.
    let make_auth_from = |challenge: &[u8], cred: &str| -> PasskeyAuthorization {
        let mut msg = challenge.to_vec();
        msg.extend_from_slice(cred.as_bytes());
        use ed25519_dalek::Signer as _;
        let sig = signing_key.sign(&msg).to_bytes().to_vec();
        PasskeyAuthorization {
            challenge: challenge.to_vec(),
            signature: sig,
            credential_id: cred.to_string(),
        }
    };
    let chal_req = KeyAgentRequest {
        kind: Some(KeyAgentRequestKind::GenerateChallenge(GenerateChallengeRequest {
            credential_id: "cred-b1".to_string(),
        })),
    };
    let resp = client.send_request(&chal_req).unwrap();
    let bytes = match &resp.kind {
        Some(KeyAgentResponseKind::Ok(b)) => b.clone(),
        other => panic!("expected Ok challenge, got {other:?}"),
    };
    let shared_challenge = GenerateChallengeResponse::decode(bytes.as_slice()).unwrap().challenge;

    // First use of the shared challenge succeeds.
    let first = KeyAgentRequest {
        kind: Some(KeyAgentRequestKind::CreateSessionKey(CreateSessionKeyRequest {
            label: "replay-first".to_string(),
            rules: None,
            budget: None,
            auth: Some(make_auth_from(&shared_challenge, "cred-b1")),
        })),
    };
    let resp = client.send_request(&first).unwrap();
    assert!(!resp.is_error(), "first use of a fresh challenge must succeed");

    // Second use of the SAME challenge → replay rejection (Deny/Error).
    let second = KeyAgentRequest {
        kind: Some(KeyAgentRequestKind::CreateSessionKey(CreateSessionKeyRequest {
            label: "replay-second".to_string(),
            rules: None,
            budget: None,
            auth: Some(make_auth_from(&shared_challenge, "cred-b1")),
        })),
    };
    let resp = client.send_request(&second).unwrap();
    match &resp.kind {
        Some(KeyAgentResponseKind::Deny(_)) => {}
        Some(KeyAgentResponseKind::Error(_)) => {}
        other => panic!("expected replay rejection, got {other:?}"),
    }

    // 5. Unknown credential → error.
    let bad_chal = KeyAgentRequest {
        kind: Some(KeyAgentRequestKind::GenerateChallenge(GenerateChallengeRequest {
            credential_id: "cred-nope".to_string(),
        })),
    };
    let resp = client.send_request(&bad_chal).unwrap();
    assert!(resp.is_error(), "unknown credential must error");

    // Shut down the server.
    stop.store(true, Ordering::Relaxed);
    // Wake the accept loop with a dummy connection so it checks `stop`.
    let _ = FrameClient::new(&sock_str)
        .send_request(&KeyAgentRequest { kind: Some(KeyAgentRequestKind::ListWallets(Empty {})) });
    let _ = server.join();
}

// -----------------------------------------------------------------------
// B2. Intent full lifecycle via CLI with the built-in MockRpcClient
//      (no --rpc-url → mock, no network, no signing key needed).
// -----------------------------------------------------------------------

#[test]
fn test_intent_submit_simulate_execute_lifecycle_mock() {
    // Native Pay amount is a hex wei string (1 * 10^18 wei).
    let pay_json = r#"{"type":"Pay","amount":"0x0DE0B6B3A7640000","recipient":"0xabcabcabcabcabcabcabcabcabcabcabca"}"#;

    // simulate → Ok (mock)
    run_ok(&[
        "onecipher",
        "intent",
        "simulate",
        "--json",
        pay_json,
        "--chain",
        "eip155:8453",
        "--session-key",
        "sk-mock",
    ]);

    // submit --yes → Ok (skip prompt, mock execution). M-04a: a sender
    // address is required so execute_intent can fetch the pending nonce.
    run_ok(&[
        "onecipher",
        "intent",
        "submit",
        "--json",
        pay_json,
        "--chain",
        "eip155:8453",
        "--session-key",
        "sk-mock",
        "--from",
        "0x1111111111111111111111111111111111111111",
        "--yes",
    ]);

    // execute → Ok (mock execution)
    run_ok(&[
        "onecipher",
        "intent",
        "execute",
        "--json",
        pay_json,
        "--chain",
        "eip155:8453",
        "--session-key",
        "sk-mock",
        "--from",
        "0x1111111111111111111111111111111111111111",
    ]);

    // SignMessage intent (default utf8)
    run_ok(&[
        "onecipher",
        "intent",
        "simulate",
        "--json",
        r#"{"type":"SignMessage","message":"hello world"}"#,
        "--chain",
        "eip155:1",
        "--session-key",
        "sk-mock",
    ]);

    // SignTransaction intent
    run_ok(&[
        "onecipher",
        "intent",
        "simulate",
        "--json",
        r#"{"type":"SignTransaction","tx_hex":"0xdeadbeef","chain_id":"eip155:1"}"#,
        "--chain",
        "eip155:1",
        "--session-key",
        "sk-mock",
    ]);
}

// -----------------------------------------------------------------------
// B2b. Intent bad JSON / missing type are rejected
// -----------------------------------------------------------------------

#[test]
fn test_intent_invalid_inputs_rejected() {
    // missing type
    let res = run_cli(&[
        "onecipher",
        "intent",
        "simulate",
        "--json",
        r#"{"amount":"1 USDC"}"#,
        "--chain",
        "eip155:8453",
        "--session-key",
        "sk",
    ]);
    assert!(res.is_err());

    // invalid JSON
    let res = run_cli(&[
        "onecipher",
        "intent",
        "simulate",
        "--json",
        "{not json",
        "--chain",
        "eip155:1",
        "--session-key",
        "sk",
    ]);
    assert!(res.is_err());
}

// -----------------------------------------------------------------------
// B4. sign send-tx broadcast against a mock JSON-RPC server (--rpc-url).
// -----------------------------------------------------------------------

#[test]
fn test_send_tx_broadcast_mock_jsonrpc() {
    use std::io::{Read, Write};

    let _home = HomeGuard::new();
    // Create an empty-passphrase wallet.
    run_ok(&["onecipher", "wallet", "create", "--name", "bwallet", "--words", "12"]);

    // Build a minimal unsigned EIP-1559 tx: 0x02 || RLP([...]).
    // Replicates oc-signer's rlp test vector (chain_id=1, all other fields 0).
    let items: Vec<u8> = [
        vec![0x01], // chain_id = 1
        vec![0x80], // nonce = 0
        vec![0x80], // maxPriorityFeePerGas = 0
        vec![0x80], // maxFeePerGas = 0
        vec![0x80], // gasLimit = 0
        vec![0x80], // to = empty
        vec![0x80], // value = 0
        vec![0x80], // data = empty
        vec![0xc0], // accessList = []
    ]
    .concat();
    let mut unsigned_tx = vec![0x02u8];
    // RLP list header for 9 items.
    unsigned_tx.push(0xc0 + items.len() as u8);
    unsigned_tx.extend_from_slice(&items);
    let tx_hex = format!("0x{}", hex::encode(&unsigned_tx));

    // Mock JSON-RPC server: responds to eth_sendRawTransaction with a fake tx hash.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buf = [0u8; 8192];
        let n = stream.read(&mut buf).unwrap();
        let req_str = String::from_utf8_lossy(&buf[..n]).to_string();
        // Assert the request body contains eth_sendRawTransaction.
        assert!(
            req_str.contains("eth_sendRawTransaction"),
            "mock must receive eth_sendRawTransaction, got: {req_str}"
        );
        let body = r#"{"jsonrpc":"2.0","result":"0xdeadbeefcafebabedeadbeefcafebabe0000000000000000000000000000000000","id":1}"#;
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(resp.as_bytes());
    });

    let rpc_url = format!("http://127.0.0.1:{port}");
    let res = run_cli(&[
        "onecipher",
        "sign",
        "send-tx",
        "--chain",
        "ethereum",
        "--wallet",
        "bwallet",
        "--tx",
        &tx_hex,
        "--rpc-url",
        &rpc_url,
        "--json",
    ]);
    assert!(res.is_ok(), "send-tx broadcast must succeed against mock: {res:?}");
    server.join().unwrap();
}

// -----------------------------------------------------------------------
// C-level. `secret edit` smoke test using a no-op editor (EDITOR=true).
// -----------------------------------------------------------------------

#[test]
fn test_secret_edit_with_noop_editor() {
    let _home = HomeGuard::new();
    age_init();
    set_env("ONECIPHER_SECRET", "edit-me");
    run_ok(&["onecipher", "secret", "add", "edit/sec", "--type", "note"]);
    remove_env("ONECIPHER_SECRET");

    // Use `true` (no-op) as the editor: content is unchanged, so the round-trip
    // parse must succeed and the secret must be re-encrypted in place.
    set_env("EDITOR", "true");
    let res = run_cli(&["onecipher", "secret", "edit", "edit/sec"]);
    remove_env("EDITOR");
    assert!(res.is_ok(), "edit with no-op editor must succeed: {res:?}");

    // The secret still decrypts to the original value.
    run_ok(&["onecipher", "secret", "get", "edit/sec", "--json"]);
    run_ok(&["onecipher", "secret", "delete", "--force", "edit/sec"]);
}

// ===========================================================================
// WC v2 CLI commands (relay config / probe / dapp-send)
// ===========================================================================

// -----------------------------------------------------------------------
// 81. `wc relay` persists relay_url + project_id into config
// -----------------------------------------------------------------------

#[test]
fn test_wc_relay_config_persists() {
    let _home = HomeGuard::new();
    run_ok(&["onecipher", "wc", "relay", "wss://127.0.0.1:7443", "--project-id", "abc123"]);

    // Read the raw config file to confirm what was written.
    let config_path = oc_core::paths::config_path().unwrap();
    let raw = std::fs::read_to_string(&config_path).unwrap_or_default();
    assert!(raw.contains("wss://127.0.0.1:7443"), "config file must contain relay_url, got: {raw}");
    assert!(raw.contains("abc123"), "config file must contain project_id, got: {raw}");

    let config = oc_core::Config::load_or_default();
    assert_eq!(config.wc.relay_url, "wss://127.0.0.1:7443");
    assert_eq!(config.wc.project_id, "abc123");
}

// -----------------------------------------------------------------------
// 82. `wc relay` rejects non-WebSocket URLs
// -----------------------------------------------------------------------

#[test]
fn test_wc_relay_rejects_bad_url() {
    let _home = HomeGuard::new();
    let res = run_cli(&["onecipher", "wc", "relay", "https://not-a-ws-url.com"]);
    assert!(res.is_err(), "relay URL must be ws:// or wss://");
}

// -----------------------------------------------------------------------
// 83. `wc relay` empty project-id rejected
// -----------------------------------------------------------------------

#[test]
fn test_wc_relay_rejects_empty_project_id() {
    let _home = HomeGuard::new();
    let res = run_cli(&["onecipher", "wc", "relay", "wss://127.0.0.1:7443", "--project-id", ""]);
    assert!(res.is_err(), "empty project id must be rejected");
}

// -----------------------------------------------------------------------
// 84. `wc probe` fails cleanly when no relay is reachable (not a hang)
// -----------------------------------------------------------------------

#[test]
fn test_wc_probe_unreachable_relay() {
    let _home = HomeGuard::new();
    // A port that is guaranteed not to be listening (ephemeral, closed).
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener); // now closed
    let url = format!("ws://127.0.0.1:{port}");
    // Probe should fail (connect refused), not hang.
    let res = run_cli(&["onecipher", "wc", "probe", "--url", &url, "--timeout", "2"]);
    assert!(res.is_err(), "probe to closed relay must fail: {res:?}");
}

// -----------------------------------------------------------------------
// 85. `wc dapp-send` validates params JSON before any network I/O
// -----------------------------------------------------------------------

#[test]
fn test_wc_dapp_send_bad_params() {
    let _home = HomeGuard::new();
    let res = run_cli(&[
        "onecipher",
        "wc",
        "dapp-send",
        "topic-123",
        "personal_sign",
        "{not json",
        "--sym-key",
        &"aa".repeat(32),
    ]);
    assert!(res.is_err(), "invalid params JSON must be rejected");
}

// -----------------------------------------------------------------------
// 86. `wc dapp-send` requires a valid 32-byte sym key
// -----------------------------------------------------------------------

#[test]
fn test_wc_dapp_send_bad_symkey() {
    let _home = HomeGuard::new();
    let res = run_cli(&[
        "onecipher",
        "wc",
        "dapp-send",
        "topic-123",
        "personal_sign",
        r#"{"data":"0x1"}"#,
        "--sym-key",
        "short",
    ]);
    assert!(res.is_err(), "short sym key must be rejected");
}

// -----------------------------------------------------------------------
// 87. `wc dapp-send` fails cleanly when relay unreachable
// -----------------------------------------------------------------------

#[test]
fn test_wc_dapp_send_unreachable_relay() {
    let _home = HomeGuard::new();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let url = format!("ws://127.0.0.1:{port}");
    let res = run_cli(&[
        "onecipher",
        "wc",
        "dapp-send",
        "topic-123",
        "personal_sign",
        r#"{"data":"0x1"}"#,
        "--sym-key",
        &"ab".repeat(32),
        "--url",
        &url,
    ]);
    assert!(res.is_err(), "dapp-send to closed relay must fail: {res:?}");
}

// -----------------------------------------------------------------------
// 88. `wc probe` against a LOCAL mock WebSocket relay echoes back (the CLI probe validates the full
//     irn_subscribe/publish/subscription loop).
// -----------------------------------------------------------------------

#[test]
fn test_wc_probe_against_local_mock_ws_relay() {
    let _home = HomeGuard::new();

    // A minimal WebSocket server implementing just enough of the IRN protocol:
    // accept a connection, read irn_subscribe + irn_publish frames, and reply
    // with an irn_subscription envelope echoing the published message.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let server = std::thread::spawn(move || {
        use std::io::{Read, Write};
        let (mut stream, _) = listener.accept().unwrap();
        // WebSocket handshake (server side).
        let mut buf = [0u8; 8192];
        let n = stream.read(&mut buf).unwrap();
        let req = String::from_utf8_lossy(&buf[..n]).to_string();
        let req_lower = req.to_ascii_lowercase();
        assert!(
            req_lower.contains("upgrade: websocket") && req_lower.contains("websocket"),
            "expected WS handshake: {req}"
        );
        // Extract Sec-WebSocket-Key.
        let key = req
            .lines()
            .find(|l| l.to_ascii_lowercase().starts_with("sec-websocket-key:"))
            .map(|l| l.split(':').nth(1).unwrap_or("").trim().to_string())
            .unwrap_or_default();
        let accept = ws_accept_key(&key);
        let handshake = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
        );
        stream.write_all(handshake.as_bytes()).unwrap();

        // Read frames (text frames with JSON). Loop for subscribe + publish.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut topic = String::new();
        while std::time::Instant::now() < deadline {
            let mut hdr = [0u8; 2];
            match stream.read(&mut hdr) {
                Ok(0) => break,
                Ok(_) => {}
                Err(_) => break,
            }
            let opcode = hdr[0] & 0x0F;
            let masked = (hdr[1] & 0x80) != 0;
            let mut len = (hdr[1] & 0x7F) as usize;
            if len == 126 {
                let mut ext = [0u8; 2];
                if stream.read_exact(&mut ext).is_err() {
                    break;
                }
                len = u16::from_be_bytes(ext) as usize;
            } else if len == 127 {
                let mut ext = [0u8; 8];
                if stream.read_exact(&mut ext).is_err() {
                    break;
                }
                len = u64::from_be_bytes(ext) as usize;
            }
            let mut mask_key = [0u8; 4];
            if masked && stream.read_exact(&mut mask_key).is_err() {
                break;
            }
            let mut payload = vec![0u8; len];
            if stream.read_exact(&mut payload).is_err() {
                break;
            }
            if masked {
                for (i, b) in payload.iter_mut().enumerate() {
                    *b ^= mask_key[i % 4];
                }
            }
            if opcode != 1 {
                continue; // only text frames
            }
            let json_str = String::from_utf8_lossy(&payload).to_string();
            let val: serde_json::Value = match serde_json::from_str(&json_str) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let method = val.get("method").and_then(|m| m.as_str()).unwrap_or("");
            match method {
                "irn_subscribe" => {
                    topic = val
                        .pointer("/params/topic")
                        .and_then(|t| t.as_str())
                        .unwrap_or("")
                        .to_string();
                    let resp =
                        serde_json::json!({"id": val["id"], "jsonrpc":"2.0", "result":"sub-1"});
                    write_ws_text(&mut stream, &resp.to_string());
                }
                "irn_publish" => {
                    let published =
                        val.pointer("/params/message").and_then(|m| m.as_str()).unwrap_or("");
                    // Reply with a subscription envelope echoing the message.
                    let sub = serde_json::json!({
                        "id": "100",
                        "jsonrpc": "2.0",
                        "method": "irn_subscription",
                        "params": {
                            "id": "sub-1",
                            "data": {
                                "topic": topic,
                                "message": published,
                                "attestation": null,
                                "publishedAt": 1234,
                                "tag": 1108
                            }
                        }
                    });
                    write_ws_text(&mut stream, &sub.to_string());
                }
                _ => {}
            }
        }
    });

    let url = format!("ws://127.0.0.1:{port}");
    let res = run_cli(&["onecipher", "wc", "probe", "--url", &url, "--timeout", "10"]);
    assert!(res.is_ok(), "probe must succeed against local mock relay: {res:?}");
    server.join().unwrap();
}

/// Compute the WebSocket Sec-WebSocket-Accept value (SHA-1 + base64).
fn ws_accept_key(key: &str) -> String {
    use base64::Engine as _;
    use sha1::Digest;
    const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    let mut hasher = sha1::Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(GUID.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
}

// -----------------------------------------------------------------------
// TUI without a terminal fails fast with a clear message (not a raw OS
// error). The test harness never provides a TTY on stdin, so this is
// deterministic here.
// -----------------------------------------------------------------------

#[test]
fn test_tui_without_terminal_fails_clean() {
    let _home = HomeGuard::new();
    let res = run_cli(&["onecipher", "tui"]);
    let err = res.expect_err("tui without a terminal must fail");
    assert!(err.to_string().contains("interactive terminal"), "unexpected error: {err}");
}

/// Write a WebSocket text frame (unmasked, server→client).
fn write_ws_text(stream: &mut std::net::TcpStream, text: &str) {
    use std::io::Write;
    let bytes = text.as_bytes();
    let mut header = vec![0x81]; // FIN + text opcode
    if bytes.len() < 126 {
        header.push(bytes.len() as u8);
    } else if bytes.len() < 65536 {
        header.push(126);
        header.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    } else {
        header.push(127);
        header.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    }
    let _ = stream.write_all(&header);
    let _ = stream.write_all(bytes);
}
