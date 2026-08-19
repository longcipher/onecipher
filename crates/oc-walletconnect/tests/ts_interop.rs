//! Official TypeScript `@walletconnect/sign-client` interop test (L4).
//!
//! This is the strongest interop gate: it drives a REAL official dApp client
//! (`@walletconnect/sign-client`) against our Rust wallet role, through a real
//! relay. It is `#[ignore]`d by default because it requires:
//!
//! - a running relay (set `OC_TEST_RELAY`, e.g. `wss://127.0.0.1:7443`)
//! - `node` + `@walletconnect/sign-client` installed in `tests/ts/` (`npm i
//!   @walletconnect/sign-client` there)
//! - a `projectId` if using the cloud relay (set `OC_WC_PROJECT_ID`)
//!
//! ## Setup
//!
//! ```bash
//! mkdir -p crates/oc-walletconnect/tests/ts
//! cd crates/oc-walletconnect/tests/ts
//! npm init -y && npm i @walletconnect/sign-client
//! cd -
//! ```
//!
//! ## Run
//!
//! ```bash
//! OC_TEST_RELAY=wss://127.0.0.1:7443 \
//!   cargo test -p oc-walletconnect --features test-utils \
//!     --test ts_interop -- --ignored
//! ```
//!
//! The test:
//! 1. Starts our wallet server (connected to the relay, trusted origins include `localhost`).
//! 2. Runs a Node script that:
//!    - creates a `SignClient` (dApp),
//!    - generates a pairing URI,
//!    - passes the URI back to the test,
//! 3. The test injects the URI into our wallet server (add_pairing).
//! 4. The Node dApp calls `client.pair({uri})`, receives `session_proposal`, auto-approves, and
//!    sends a `personal_sign` session request.
//! 5. Our wallet signs/echoes; the Node dApp asserts the response.

use std::{
    io::{Read, Write},
    process::{Command, Stdio},
};

/// Return the path to the node script.
fn ts_script() -> &'static str {
    concat!(env!("CARGO_MANIFEST_DIR"), "/tests/ts/interop.mjs")
}

/// Return the relay URL, panicking if unset.
fn test_relay_url() -> String {
    std::env::var("OC_TEST_RELAY")
        .unwrap_or_else(|_| panic!("OC_TEST_RELAY must be set to a running relay WSS URL"))
}

/// Spawn a node child process and return (stdin_writer, stdout_reader).
/// The child is intentionally not waited on: the test communicates over its
/// stdio pipes and relies on dropping them to close the process.
#[allow(clippy::zombie_processes)]
fn spawn_node(script: &str) -> (std::process::ChildStdin, std::process::ChildStdout) {
    let mut child = Command::new("node")
        .arg(script)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("failed to spawn node (is node installed? did you npm install in tests/ts?)");
    let stdin = child.stdin.take().expect("child stdin");
    let stdout = child.stdout.take().expect("child stdout");
    (stdin, stdout)
}

/// The interop test itself — wallet role in-process, dApp is the official TS
/// sign-client spawned as a child process.
#[tokio::test]
#[ignore = "requires node + @walletconnect/sign-client + a running relay"]
async fn ts_sign_client_full_pairing_and_request() {
    use oc_walletconnect::wallet_server::{
        HandlerResult, WalletMethodHandler, WcWalletConfig, WcWalletServer,
    };
    use serde_json::Value;

    #[derive(Clone, Default)]
    struct EchoHandler;
    impl WalletMethodHandler for EchoHandler {
        fn handle<'a>(
            &'a self,
            method: &str,
            params: Value,
            _: &str,
            _dapp_name: Option<&str>,
            _dapp_origin: Option<&str>,
        ) -> HandlerResult<'a> {
            let method = method.to_string();
            Box::pin(async move {
                // The official client will call eth_requestAccounts / personal_sign.
                Ok(serde_json::json!({
                    "method": method,
                    "params": params,
                    "result": "0x0123456789abcdef"
                }))
            })
        }
    }

    let url = test_relay_url();

    // ---- Wallet server ----
    let mut server = WcWalletServer::new(
        WcWalletConfig {
            relay_url: url.clone(),
            relay_protocol: "irn".into(),
            trusted_origins: vec!["localhost".into(), "127.0.0.1".into()],
        },
        EchoHandler,
    );
    let handle = server.session_handle();
    let server_task = tokio::spawn(async move { server.run(None).await });

    // Give the server time to connect.
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;

    // ---- Spawn the TS dApp ----
    let (mut node_stdin, mut node_stdout) = spawn_node(ts_script());

    // The script prints "URI <wc:...>" on stdout, then waits for input "APPROVE".
    // Read until we have the URI line.
    let mut buf = [0u8; 4096];
    let mut collected = String::new();
    let uri = loop {
        let n = node_stdout.read(&mut buf).expect("read from node");
        assert_ne!(n, 0, "node exited before printing URI");
        collected.push_str(&String::from_utf8_lossy(&buf[..n]));
        if let Some(pos) = collected.find("URI ") {
            let line = collected[pos + 4..].lines().next().unwrap_or("").to_string();
            if line.starts_with("wc:") {
                break line.trim().to_string();
            }
        }
        assert!(collected.len() <= 65536, "node output too long, no URI found: {collected}");
    };
    assert!(uri.starts_with("wc:"), "expected pairing URI, got: {uri}");

    // ---- Inject the pairing into our wallet server ----
    let pairing = oc_walletconnect::PairingUri::parse(&uri).expect("parse URI");
    handle.add_pairing(&pairing, 3600).await.expect("add pairing");

    // Tell the node dApp to approve the proposal and send a request.
    node_stdin.write_all(b"APPROVE\n").expect("write approve to node");
    node_stdin.flush().ok();

    // The node dApp sends a personal_sign request; our wallet echoes; node
    // prints "RESULT <json>" on success or "ERROR <msg>".
    let mut result = String::new();
    loop {
        let n = node_stdout.read(&mut buf).expect("read from node");
        if n == 0 {
            break;
        }
        result.push_str(&String::from_utf8_lossy(&buf[..n]));
        if result.contains("RESULT ") || result.contains("ERROR ") {
            break;
        }
        assert!(result.len() <= 65536, "node output too long: {result}");
    }

    // Shut down the node child.
    drop(node_stdin);
    drop(node_stdout);

    server_task.abort();

    assert!(!result.contains("ERROR "), "TS dApp reported failure: {result}");
    assert!(result.contains("RESULT "), "TS dApp did not print RESULT, got: {result}");
    // The result should contain our echo ("result": "0x0123...").
    assert!(
        result.contains("0x0123456789abcdef"),
        "TS dApp response missing wallet result: {result}"
    );
}
