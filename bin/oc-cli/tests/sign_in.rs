//! Binary-level tests for `onecipher sign-in` (CAIP-122).
//!
//! Drives the real `onecipher` binary with an isolated `HOME`. No network,
//! no daemon: `message` / `parse` / `nonce` are pure-local; `verify` without
//! `--rpc-url` is pure crypto (signatures are produced in-test via
//! `oc-signer`, the same crate the wallet uses).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    path::{Path, PathBuf},
    process::{Command, Output},
};

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_onecipher"))
}

fn run(home: &Path, args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        .env("HOME", home)
        .env("ONECIPHER_NO_DAEMON", "1")
        .output()
        .expect("spawn onecipher")
}

fn stdout(out: &Output) -> String {
    String::from_utf8(out.stdout.clone()).expect("utf8 stdout")
}

fn fresh_home() -> tempfile::TempDir {
    tempfile::tempdir().expect("temp home")
}

#[test]
fn sign_in_nonce_defaults_to_17_alnum() {
    let home = fresh_home();
    let out = run(home.path(), &["sign-in", "nonce"]);
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let nonce = stdout(&out);
    let nonce = nonce.trim_end_matches(['\r', '\n']);
    assert_eq!(nonce.len(), 17, "nonce: {nonce}");
    assert!(nonce.chars().all(|c| c.is_ascii_alphanumeric()), "nonce: {nonce}");
}

#[test]
fn sign_in_message_parse_roundtrip() {
    let home = fresh_home();
    let out = run(
        home.path(),
        &[
            "sign-in",
            "message",
            "--chain",
            "eip155:1",
            "--domain",
            "example.com",
            "--address",
            "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23",
            "--uri",
            "https://example.com/login",
            "--statement",
            "Sign in",
            "--nonce",
            "testnonce12345678",
            "--issued-at",
            "2024-01-01T00:00:00Z",
        ],
    );
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let text = stdout(&out);
    assert!(text.contains("wants you to sign in with your Ethereum account:"));
    assert!(text.contains("Chain ID: 1"));

    let msg_file = home.path().join("msg.txt");
    std::fs::write(&msg_file, &text).expect("write message");
    let out = run(
        home.path(),
        &["sign-in", "parse", "--message-file", msg_file.to_str().unwrap(), "--json"],
    );
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let parsed: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("json");
    assert_eq!(parsed["domain"], "example.com");
    assert_eq!(parsed["chain_id"], "1");
    assert_eq!(parsed["chain_name"], "Ethereum");
    assert_eq!(parsed["nonce"], "testnonce12345678");
}

#[test]
fn sign_in_verify_evm_roundtrip() {
    use oc_signer::ChainSigner;

    // Fixed test key (web3.js documentation vector).
    let privkey = hex::decode("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318")
        .expect("privkey");
    let signer = oc_signer::chains::EvmSigner;
    let address = signer.derive_address(&privkey).expect("address");

    let msg = oc_siwx::SiwxMessage::new(
        "example.com",
        &address,
        "https://example.com/login",
        "1",
        "testnonce12345678",
    )
    .expect("message");
    let text = msg.to_sign_string("Ethereum");
    let sig = signer.sign_message(&privkey, text.as_bytes()).expect("sign");
    let sig_hex = format!("0x{}", hex::encode(&sig.signature));

    let home = fresh_home();
    let msg_file = home.path().join("evm.txt");
    std::fs::write(&msg_file, &text).expect("write message");
    let out = run(
        home.path(),
        &[
            "sign-in",
            "verify",
            "--message-file",
            msg_file.to_str().unwrap(),
            "--signature",
            &sig_hex,
            "--domain",
            "example.com",
            "--nonce",
            "testnonce12345678",
        ],
    );
    assert!(
        out.status.success(),
        "verify must succeed, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout(&out).contains("valid"));

    // Wrong domain binding fails closed with a non-zero exit.
    let out = run(
        home.path(),
        &[
            "sign-in",
            "verify",
            "--message-file",
            msg_file.to_str().unwrap(),
            "--signature",
            &sig_hex,
            "--domain",
            "evil.com",
            "--nonce",
            "testnonce12345678",
        ],
    );
    assert!(!out.status.success(), "wrong domain must fail");
}

#[test]
fn sign_in_verify_solana_roundtrip_base58() {
    use oc_signer::ChainSigner;

    let privkey = hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        .expect("privkey");
    let signer = oc_signer::chains::SolanaSigner;
    let address = signer.derive_address(&privkey).expect("address");

    let msg = oc_siwx::SiwxMessage::new(
        "example.com",
        &address,
        "https://example.com/login",
        "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
        "testnonce12345678",
    )
    .expect("message");
    let text = msg.to_sign_string("Solana");
    let sig = signer.sign_message(&privkey, text.as_bytes()).expect("sign");
    // Solana tooling passes base58 signatures: the CLI accepts them.
    let sig_b58 = bs58::encode(&sig.signature).into_string();

    let home = fresh_home();
    let msg_file = home.path().join("sol.txt");
    std::fs::write(&msg_file, &text).expect("write message");
    let out = run(
        home.path(),
        &[
            "sign-in",
            "verify",
            "--message-file",
            msg_file.to_str().unwrap(),
            "--signature",
            &sig_b58,
            "--domain",
            "example.com",
            "--nonce",
            "testnonce12345678",
            "--chain",
            "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
        ],
    );
    assert!(
        out.status.success(),
        "solana verify must succeed, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}
