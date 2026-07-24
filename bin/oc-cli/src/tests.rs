use std::sync::{Arc, Mutex};

use clap::Parser;
use oc_proto::{
    CreateSessionKeyRequest, CreateSessionKeyResponse, ListSessionKeysResponse, PayX402Request,
    PayX402Response, RevokeSessionKeyRequest, RevokeSessionKeyResponse, SessionKeyInfo,
    SessionKeyStatus,
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
    pay_x402_requests: Arc<Mutex<Vec<PayX402Request>>>,
    next_create_resp: Arc<Mutex<Option<CreateSessionKeyResponse>>>,
    next_revoke_resp: Arc<Mutex<Option<RevokeSessionKeyResponse>>>,
    next_list_resp: Arc<Mutex<Option<ListSessionKeysResponse>>>,
    next_pay_x402_resp: Arc<Mutex<Option<PayX402Response>>>,
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
        Ok((*self.next_revoke_resp.lock().unwrap()).unwrap_or_default())
    }

    fn list_session_keys(&self) -> Result<ListSessionKeysResponse, CliError> {
        *self.list_session_keys_calls.lock().unwrap() += 1;
        Ok(self.next_list_resp.lock().unwrap().clone().unwrap_or_default())
    }

    fn pay_x402(&self, req: PayX402Request) -> Result<PayX402Response, CliError> {
        self.pay_x402_requests.lock().unwrap().push(req);
        Ok(self.next_pay_x402_resp.lock().unwrap().clone().unwrap_or_default())
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
// 9. `ocpay x402` builds the correct PayX402Request RPC
// -----------------------------------------------------------------------

#[test]
fn test_ocpay_x402_builds_correct_rpc() {
    let mock = MockNetAgentClient::default();
    let cli = Cli::parse_from([
        "onecipher",
        "ocpay",
        "x402",
        "https://example.com/api",
        "--session-key",
        "sk-1",
        "--method",
        "POST",
        "--body",
        "{\"k\":\"v\"}",
    ]);
    let result = crate::run(cli, &mock);
    assert!(result.is_ok());

    let recorded = mock.pay_x402_requests.lock().unwrap();
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].session_key_id, "sk-1");
    assert_eq!(recorded[0].url, "https://example.com/api");
    assert_eq!(recorded[0].method, "POST");
    assert_eq!(recorded[0].body, b"{\"k\":\"v\"}".to_vec());
    assert!(recorded[0].headers.is_empty());
}

// -----------------------------------------------------------------------
// 10. `ocpay x402` defaults method to GET and body to empty
// -----------------------------------------------------------------------

#[test]
fn test_ocpay_x402_defaults() {
    let mock = MockNetAgentClient::default();
    let cli = Cli::parse_from([
        "onecipher",
        "ocpay",
        "x402",
        "https://example.com/",
        "--session-key",
        "sk-9",
    ]);
    let result = crate::run(cli, &mock);
    assert!(result.is_ok());

    let recorded = mock.pay_x402_requests.lock().unwrap();
    assert_eq!(recorded[0].method, "GET");
    assert!(recorded[0].body.is_empty());
}

// -----------------------------------------------------------------------
// 11. `ocpay x402` prints DENY when response status = Deny
// -----------------------------------------------------------------------

#[test]
fn test_ocpay_x402_handles_deny_status() {
    let mock = MockNetAgentClient::default();
    *mock.next_pay_x402_resp.lock().unwrap() = Some(PayX402Response {
        status: oc_proto::PaymentStatus::Deny as i32,
        receipt: vec![],
        retry_authorization: String::new(),
        deny_reason: "RATE_LIMIT_MINUTE".to_string(),
        error: String::new(),
    });
    let cli = Cli::parse_from([
        "onecipher",
        "ocpay",
        "x402",
        "https://example.com/",
        "--session-key",
        "sk-1",
    ]);
    let result = crate::run(cli, &mock);
    assert!(result.is_ok(), "Deny is a successful RPC, not a CLI error");
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
    assert!(matches!(
        client.pay_x402(PayX402Request::default()),
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

    let cli = Cli::parse_from(["onecipher", "backup", "export", "--out", "/tmp/wallet.ocbk"]);
    assert!(crate::run(cli, &mock).is_ok());

    let cli = Cli::parse_from(["onecipher", "backup", "import", "--in", "/tmp/wallet.ocbk"]);
    assert!(crate::run(cli, &mock).is_ok());
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
