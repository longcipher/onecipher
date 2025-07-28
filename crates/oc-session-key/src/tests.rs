//! Unit tests for `oc-session-key`.
//!
//! Per R56, this crate MUST NOT depend on tokio — not even as a dev-dep. Async
//! tests are driven by `futures::executor::block_on` instead of `#[tokio::test]`,
//! keeping `cargo tree -p oc-session-key --all-targets` tokio-free.

use std::sync::Arc;

use oc_crypto::HardenedBytes;
use oc_policy::{BudgetAllocation, PolicyRulesV2, PolicyV2};

use crate::{
    GrantReceipt, SessionKeyError, SessionKeyProvider, Signature,
    evm::EvmSessionKeyProvider,
    real::{
        EvmSessionKeyProvider as RealEvmSessionKeyProvider, MockEvmBundlerClient, MockEvmRpcClient,
        MockSolanaRpcClient, SolanaSessionKeyProvider as RealSolanaSessionKeyProvider,
        derive_session_key_id,
    },
    rpc::MockRpcClient,
    solana::SolanaSessionKeyProvider,
    types::{KeyScheme, OwnerKey, PublicKey, SessionPrivateKey, SignPayload},
};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Well-known secp256k1 test private key (from oc-signer's test suite).
const EVM_PRIV_HEX: &str = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";

/// RFC 8032 ed25519 Test Vector 1 private key (from oc-signer's test suite).
const SOL_PRIV_HEX: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

fn evm_priv_bytes() -> Vec<u8> {
    hex::decode(EVM_PRIV_HEX).unwrap()
}

fn sol_priv_bytes() -> Vec<u8> {
    hex::decode(SOL_PRIV_HEX).unwrap()
}

fn evm_owner_key(chain_id: &str) -> OwnerKey {
    OwnerKey {
        raw: HardenedBytes::from_slice(&evm_priv_bytes()).unwrap(),
        chain_id: chain_id.to_string(),
    }
}

fn sol_owner_key(chain_id: &str) -> OwnerKey {
    OwnerKey {
        raw: HardenedBytes::from_slice(&sol_priv_bytes()).unwrap(),
        chain_id: chain_id.to_string(),
    }
}

fn evm_session_priv() -> SessionPrivateKey {
    SessionPrivateKey {
        raw: HardenedBytes::from_slice(&evm_priv_bytes()).unwrap(),
        scheme: KeyScheme::Secp256k1Evm,
    }
}

fn sol_session_priv() -> SessionPrivateKey {
    SessionPrivateKey {
        raw: HardenedBytes::from_slice(&sol_priv_bytes()).unwrap(),
        scheme: KeyScheme::Ed25519Solana,
    }
}

fn evm_pubkey() -> PublicKey {
    // 33-byte compressed pubkey (mock — content is irrelevant for the mock RPC path).
    PublicKey { bytes: vec![0x02; 33], scheme: KeyScheme::Secp256k1Evm }
}

fn sol_pubkey() -> PublicKey {
    // 32-byte ed25519 pubkey (mock).
    PublicKey { bytes: vec![0x01; 32], scheme: KeyScheme::Ed25519Solana }
}

fn test_policy(session_key_id: &str, expiry: u64) -> PolicyV2 {
    PolicyV2 {
        version: 2,
        session_key_id: session_key_id.to_string(),
        device_id: "dev-test".to_string(),
        rules: PolicyRulesV2 {
            max_single_amount_usd: 10.0,
            max_daily_amount_usd: 100.0,
            max_monthly_amount_usd: 1000.0,
            expiry_unix: expiry,
            rate_limit_per_minute: 10,
            rate_limit_per_hour: 100,
            cooldown_after_denial_sec: 0,
            asset_whitelist: vec!["USDC".to_string()],
            chain_whitelist: vec!["eip155:8453".to_string()],
            contract_whitelist: vec!["0xABC".to_string()],
            payment_protocols: vec!["x402".to_string()],
        },
        budget_allocation: BudgetAllocation {
            allocated_usd: 50.0,
            allocated_at_unix: 0,
            parent_total_usd: 1000.0,
            parent_session_id: "parent".to_string(),
        },
    }
}

// ---------------------------------------------------------------------------
// EVM provider tests
// ---------------------------------------------------------------------------

#[test]
fn test_evm_grant_returns_receipt_with_merkle_root() {
    futures::executor::block_on(async {
        let rpc = MockRpcClient::ok();
        let provider = EvmSessionKeyProvider::new(
            "eip155:8453",
            "0x0123456789012345678901234567890123456789",
            Box::new(rpc),
        );
        let owner = evm_owner_key("eip155:8453");
        let pubkey = evm_pubkey();
        let policy = test_policy("sk-test", 999_999_999);

        let receipt = provider.grant(&owner, &pubkey, &policy).await.expect("grant should succeed");

        match receipt {
            GrantReceipt::Evm { tx_hash, merkle_root, sca_address } => {
                assert!(tx_hash.starts_with("0x"), "tx_hash should be 0x-prefixed: {tx_hash}");
                assert!(
                    merkle_root.starts_with("0x"),
                    "merkle_root should be 0x-prefixed: {merkle_root}"
                );
                // SHA-256 → 32 bytes → 64 hex chars + "0x" prefix.
                assert_eq!(
                    merkle_root.len(),
                    66,
                    "merkle_root should be 0x + 64 hex chars: {merkle_root}"
                );
                assert_eq!(
                    sca_address, "0x0123456789012345678901234567890123456789",
                    "sca_address should match provider config"
                );
            }
            other => panic!("expected GrantReceipt::Evm, got {other:?}"),
        }
    });
}

#[test]
fn test_evm_grant_chain_mismatch_fails() {
    futures::executor::block_on(async {
        let rpc = MockRpcClient::ok();
        let provider = EvmSessionKeyProvider::new(
            "eip155:8453",
            "0x0123456789012345678901234567890123456789",
            Box::new(rpc),
        );
        // Owner key on a different chain → ChainMismatch.
        let owner = evm_owner_key("eip155:1");
        let pubkey = evm_pubkey();
        let policy = test_policy("sk-test", 999_999_999);

        let err =
            provider.grant(&owner, &pubkey, &policy).await.expect_err("chain mismatch should fail");
        match err {
            SessionKeyError::ChainMismatch { expected, actual } => {
                assert_eq!(expected, "eip155:8453");
                assert_eq!(actual, "eip155:1");
            }
            other => panic!("expected ChainMismatch, got {other:?}"),
        }
    });
}

#[test]
fn test_evm_verify_active_returns_true_when_rpc_returns_nonzero() {
    futures::executor::block_on(async {
        let mut rpc = MockRpcClient::ok();
        rpc.evm_view_response = Ok(vec![0x01]);
        let provider = EvmSessionKeyProvider::new(
            "eip155:8453",
            "0x0123456789012345678901234567890123456789",
            Box::new(rpc),
        );
        let active = provider.verify_active("sk-test").await.expect("verify_active should succeed");
        assert!(active, "non-zero byte should mean active");
    });
}

#[test]
fn test_evm_verify_active_returns_false_when_rpc_returns_zero() {
    futures::executor::block_on(async {
        let mut rpc = MockRpcClient::ok();
        rpc.evm_view_response = Ok(vec![0x00]);
        let provider = EvmSessionKeyProvider::new(
            "eip155:8453",
            "0x0123456789012345678901234567890123456789",
            Box::new(rpc),
        );
        let active = provider.verify_active("sk-test").await.expect("verify_active should succeed");
        assert!(!active, "zero byte should mean inactive");
    });
}

#[test]
fn test_evm_revoke_sends_tx() {
    futures::executor::block_on(async {
        let rpc = MockRpcClient::ok();
        let counters = rpc.counters();
        let provider = EvmSessionKeyProvider::new(
            "eip155:8453",
            "0x0123456789012345678901234567890123456789",
            Box::new(rpc),
        );
        let owner = evm_owner_key("eip155:8453");

        provider.revoke(&owner, "sk-test").await.expect("revoke should succeed");

        assert_eq!(counters.evm_tx(), 1, "revoke should send exactly one EVM tx");
    });
}

#[test]
fn test_evm_sign_with_message_returns_signature() {
    futures::executor::block_on(async {
        let rpc = MockRpcClient::ok();
        let provider = EvmSessionKeyProvider::new(
            "eip155:8453",
            "0x0123456789012345678901234567890123456789",
            Box::new(rpc),
        );
        let priv_key = evm_session_priv();
        let payload = SignPayload::Message { bytes: b"hello session key".to_vec() };

        let sig = provider.sign_with(&priv_key, &payload).await.expect("sign_with should succeed");

        match sig {
            Signature::Evm { hex } => {
                assert!(hex.starts_with("0x"), "signature should be 0x-prefixed: {hex}");
                // EVM signature is 65 bytes (r||s||v) → 130 hex chars + "0x".
                assert_eq!(
                    hex.len(),
                    132,
                    "EVM signature should be 0x + 130 hex chars (65 bytes): {hex}"
                );
            }
            other => panic!("expected Signature::Evm, got {other:?}"),
        }
    });
}

// ---------------------------------------------------------------------------
// Solana provider tests
// ---------------------------------------------------------------------------

#[test]
fn test_solana_grant_returns_solana_receipt() {
    futures::executor::block_on(async {
        let rpc = MockRpcClient::ok();
        let provider = SolanaSessionKeyProvider::new(
            "solana:devnet",
            "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEf",
            Box::new(rpc),
        );
        let owner = sol_owner_key("solana:devnet");
        let pubkey = sol_pubkey();
        let policy = test_policy("sk-sol", 999_999_999);

        let receipt = provider.grant(&owner, &pubkey, &policy).await.expect("grant should succeed");

        match receipt {
            GrantReceipt::Solana { session_tokens_account, program_id, slot } => {
                assert!(
                    !session_tokens_account.is_empty(),
                    "session_tokens_account should be non-empty"
                );
                assert_eq!(
                    program_id, "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEf",
                    "program_id should match provider config"
                );
                assert_eq!(slot, 0, "mock slot should be 0");
            }
            other => panic!("expected GrantReceipt::Solana, got {other:?}"),
        }
    });
}

#[test]
fn test_solana_verify_active_returns_true_when_account_exists() {
    futures::executor::block_on(async {
        let mut rpc = MockRpcClient::ok();
        rpc.solana_account_response = Ok(Some(vec![0x01, 0x02, 0x03]));
        let provider = SolanaSessionKeyProvider::new(
            "solana:devnet",
            "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEf",
            Box::new(rpc),
        );
        let active = provider.verify_active("sk-sol").await.expect("verify_active should succeed");
        assert!(active, "Some(account) should mean active");
    });
}

#[test]
fn test_solana_verify_active_returns_false_when_account_missing() {
    futures::executor::block_on(async {
        let mut rpc = MockRpcClient::ok();
        rpc.solana_account_response = Ok(None);
        let provider = SolanaSessionKeyProvider::new(
            "solana:devnet",
            "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEf",
            Box::new(rpc),
        );
        let active = provider.verify_active("sk-sol").await.expect("verify_active should succeed");
        assert!(!active, "None should mean inactive");
    });
}

#[test]
fn test_solana_revoke_sends_tx() {
    futures::executor::block_on(async {
        let rpc = MockRpcClient::ok();
        let counters = rpc.counters();
        let provider = SolanaSessionKeyProvider::new(
            "solana:devnet",
            "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEf",
            Box::new(rpc),
        );
        let owner = sol_owner_key("solana:devnet");

        provider.revoke(&owner, "sk-sol").await.expect("revoke should succeed");

        assert_eq!(counters.solana_tx(), 1, "revoke should send exactly one Solana tx");
    });
}

#[test]
fn test_solana_sign_with_message_returns_base58_signature() {
    futures::executor::block_on(async {
        let rpc = MockRpcClient::ok();
        let provider = SolanaSessionKeyProvider::new(
            "solana:devnet",
            "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEf",
            Box::new(rpc),
        );
        let priv_key = sol_session_priv();
        let payload = SignPayload::Message { bytes: b"hello solana session key".to_vec() };

        let sig = provider.sign_with(&priv_key, &payload).await.expect("sign_with should succeed");

        match sig {
            Signature::Solana { base58 } => {
                // ed25519 signature is 64 bytes → base58-encoded (non-empty, decodes to 64 bytes).
                assert!(!base58.is_empty(), "base58 signature should be non-empty");
                let decoded =
                    bs58::decode(&base58).into_vec().expect("base58 signature should decode");
                assert_eq!(decoded.len(), 64, "ed25519 signature should decode to 64 bytes");
            }
            other => panic!("expected Signature::Solana, got {other:?}"),
        }
    });
}

#[test]
fn test_solana_sign_with_transaction_payload_fails() {
    futures::executor::block_on(async {
        let rpc = MockRpcClient::ok();
        let provider = SolanaSessionKeyProvider::new(
            "solana:devnet",
            "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEf",
            Box::new(rpc),
        );
        let priv_key = sol_session_priv();
        // Transaction payload is NOT supported for Solana in Phase 1.
        let payload = SignPayload::Transaction { chain_id: 8453, raw_hex: "deadbeef".to_string() };

        let err = provider
            .sign_with(&priv_key, &payload)
            .await
            .expect_err("Transaction payload should be rejected for Solana");
        match err {
            SessionKeyError::InvalidPayload(msg) => {
                assert!(msg.contains("Solana"), "error should mention Solana: {msg}");
            }
            other => panic!("expected InvalidPayload, got {other:?}"),
        }
    });
}

// ---------------------------------------------------------------------------
// Trait object test
// ---------------------------------------------------------------------------

#[test]
fn test_trait_object_box_dyn() {
    futures::executor::block_on(async {
        // Both providers must be usable as Box<dyn SessionKeyProvider>.
        let evm: Box<dyn SessionKeyProvider> = Box::new(EvmSessionKeyProvider::new(
            "eip155:8453",
            "0x0123456789012345678901234567890123456789",
            Box::new(MockRpcClient::ok()),
        ));
        let sol: Box<dyn SessionKeyProvider> = Box::new(SolanaSessionKeyProvider::new(
            "solana:devnet",
            "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEf",
            Box::new(MockRpcClient::ok()),
        ));

        assert_eq!(evm.chain_id(), "eip155:8453");
        assert_eq!(sol.chain_id(), "solana:devnet");

        // Drive an async call through the trait object to confirm dynamic dispatch works.
        let evm_active = evm
            .verify_active("sk-evm")
            .await
            .expect("evm verify_active via trait object should succeed");
        assert!(evm_active, "mock returns non-zero → active");

        let sol_active = sol
            .verify_active("sk-sol")
            .await
            .expect("solana verify_active via trait object should succeed");
        assert!(sol_active, "mock returns Some(account) → active");
    });
}

// ---------------------------------------------------------------------------
// Merkle root determinism
// ---------------------------------------------------------------------------

#[test]
fn test_merkle_root_deterministic() {
    let policy = test_policy("sk-deterministic", 1_800_000_000);
    let root1 = EvmSessionKeyProvider::compute_merkle_root(&policy)
        .expect("compute_merkle_root should succeed");
    let root2 = EvmSessionKeyProvider::compute_merkle_root(&policy)
        .expect("compute_merkle_root should succeed");
    assert_eq!(root1, root2, "same policy must produce the same merkle root (deterministic)");
}

#[test]
fn test_merkle_root_differs_for_different_policies() {
    let policy_a = test_policy("sk-a", 1_800_000_000);
    let policy_b = test_policy("sk-b", 1_800_000_000);
    let root_a = EvmSessionKeyProvider::compute_merkle_root(&policy_a)
        .expect("compute_merkle_root should succeed for policy A");
    let root_b = EvmSessionKeyProvider::compute_merkle_root(&policy_b)
        .expect("compute_merkle_root should succeed for policy B");
    assert_ne!(root_a, root_b, "different policies must produce different merkle roots");
}

// ===========================================================================
// Phase 2 — real providers (`crate::real`)
// ===========================================================================

/// Build a real EVM provider backed by mock RPC + bundler clients.
fn real_evm_provider(
    rpc: MockEvmRpcClient,
    bundler: MockEvmBundlerClient,
) -> RealEvmSessionKeyProvider {
    RealEvmSessionKeyProvider::new(Arc::new(rpc), Arc::new(bundler), "eip155:8453")
        .with_sca_address("0x0123456789012345678901234567890123456789")
}

/// Build a real Solana provider backed by a mock RPC client.
fn real_solana_provider(rpc: MockSolanaRpcClient) -> RealSolanaSessionKeyProvider {
    RealSolanaSessionKeyProvider::new(
        Arc::new(rpc),
        "solana:devnet",
        "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEf",
    )
}

// ---------------------------------------------------------------------------
// derive_session_key_id
// ---------------------------------------------------------------------------

#[test]
fn test_derive_session_key_id_format() {
    let id = derive_session_key_id(&[0x02; 33], "eip155:8453");
    assert!(id.starts_with("sk-eip155-0x"), "id should start with sk-eip155-0x: {id}");
    // 8 bytes → 16 hex chars after "sk-eip155-0x".
    assert_eq!(
        id.len(),
        "sk-eip155-0x".len() + 16,
        "id should be sk-{{namespace}}-0x{{16 hex chars}}: {id}"
    );
}

#[test]
fn test_derive_session_key_id_solana_namespace() {
    let id = derive_session_key_id(&[0x01; 32], "solana:mainnet");
    assert!(id.starts_with("sk-solana-0x"), "solana namespace should appear in id: {id}");
}

#[test]
fn test_derive_session_key_id_deterministic() {
    let id1 = derive_session_key_id(&[0x02; 33], "eip155:8453");
    let id2 = derive_session_key_id(&[0x02; 33], "eip155:8453");
    assert_eq!(id1, id2, "same inputs must yield the same session key id");
}

#[test]
fn test_derive_session_key_id_differs_for_different_pubkeys() {
    let id1 = derive_session_key_id(&[0x02; 33], "eip155:8453");
    let id2 = derive_session_key_id(&[0x03; 33], "eip155:8453");
    assert_ne!(id1, id2, "different pubkeys must yield different ids");
}

#[test]
fn test_derive_session_key_id_differs_for_different_chains() {
    let id1 = derive_session_key_id(&[0x02; 33], "eip155:8453");
    let id2 = derive_session_key_id(&[0x02; 33], "eip155:1");
    assert_ne!(id1, id2, "different chains must yield different ids");
}

// ---------------------------------------------------------------------------
// Real EVM provider
// ---------------------------------------------------------------------------

#[test]
fn test_real_evm_grant_returns_receipt_via_bundler() {
    futures::executor::block_on(async {
        let rpc = MockEvmRpcClient::ok();
        let bundler = MockEvmBundlerClient::ok();
        let bundler_counters = bundler.counters();
        let provider = real_evm_provider(rpc, bundler);
        let owner = evm_owner_key("eip155:8453");
        let pubkey = evm_pubkey();
        let policy = test_policy("sk-real-evm", 999_999_999);

        let receipt = provider
            .grant(&owner, &pubkey, &policy)
            .await
            .expect("real grant should succeed via bundler");

        match receipt {
            GrantReceipt::Evm { tx_hash, merkle_root, sca_address } => {
                assert!(
                    tx_hash.starts_with("0x"),
                    "tx_hash should be 0x-prefixed (bundler hash): {tx_hash}"
                );
                assert!(
                    merkle_root.starts_with("0x") && merkle_root.len() == 66,
                    "merkle_root should be 0x + 64 hex chars: {merkle_root}"
                );
                assert_eq!(
                    sca_address, "0x0123456789012345678901234567890123456789",
                    "sca_address should match with_sca_address config"
                );
            }
            other => panic!("expected GrantReceipt::Evm, got {other:?}"),
        }
        assert_eq!(
            bundler_counters.send_user_op(),
            1,
            "grant should submit exactly one UserOp to the bundler"
        );
    });
}

#[test]
fn test_real_evm_grant_chain_mismatch_fails() {
    futures::executor::block_on(async {
        let provider = real_evm_provider(MockEvmRpcClient::ok(), MockEvmBundlerClient::ok());
        let owner = evm_owner_key("eip155:1");
        let pubkey = evm_pubkey();
        let policy = test_policy("sk-real-evm", 999_999_999);

        let err =
            provider.grant(&owner, &pubkey, &policy).await.expect_err("chain mismatch should fail");
        match err {
            SessionKeyError::ChainMismatch { expected, actual } => {
                assert_eq!(expected, "eip155:8453");
                assert_eq!(actual, "eip155:1");
            }
            other => panic!("expected ChainMismatch, got {other:?}"),
        }
    });
}

#[test]
fn test_real_evm_verify_active_true_when_eth_call_nonzero() {
    futures::executor::block_on(async {
        let mut rpc = MockEvmRpcClient::ok();
        rpc.eth_call_response = Ok(vec![0x00, 0x00, 0x01]);
        let provider = real_evm_provider(rpc, MockEvmBundlerClient::ok());
        let active = provider
            .verify_active("sk-eip155-0xdeadbeef")
            .await
            .expect("verify_active should succeed");
        assert!(active, "non-zero last byte should mean active");
    });
}

#[test]
fn test_real_evm_verify_active_false_when_eth_call_zero() {
    futures::executor::block_on(async {
        let mut rpc = MockEvmRpcClient::ok();
        rpc.eth_call_response = Ok(vec![0x00, 0x00, 0x00]);
        let provider = real_evm_provider(rpc, MockEvmBundlerClient::ok());
        let active = provider
            .verify_active("sk-eip155-0xdeadbeef")
            .await
            .expect("verify_active should succeed");
        assert!(!active, "zero last byte should mean inactive");
    });
}

#[test]
fn test_real_evm_verify_active_false_when_empty_return() {
    futures::executor::block_on(async {
        let mut rpc = MockEvmRpcClient::ok();
        rpc.eth_call_response = Ok(vec![]);
        let provider = real_evm_provider(rpc, MockEvmBundlerClient::ok());
        let active = provider
            .verify_active("sk-eip155-0xdeadbeef")
            .await
            .expect("verify_active should succeed");
        assert!(!active, "empty return should mean inactive");
    });
}

#[test]
fn test_real_evm_revoke_sends_transaction() {
    futures::executor::block_on(async {
        let rpc = MockEvmRpcClient::ok();
        let counters = rpc.counters();
        let provider = real_evm_provider(rpc, MockEvmBundlerClient::ok());
        let owner = evm_owner_key("eip155:8453");

        provider.revoke(&owner, "sk-eip155-0xdeadbeef").await.expect("revoke should succeed");

        assert_eq!(
            counters.send_transaction(),
            1,
            "revoke should send exactly one transaction via send_transaction"
        );
    });
}

#[test]
fn test_real_evm_revoke_chain_mismatch_fails() {
    futures::executor::block_on(async {
        let provider = real_evm_provider(MockEvmRpcClient::ok(), MockEvmBundlerClient::ok());
        let owner = evm_owner_key("eip155:1");

        let err = provider
            .revoke(&owner, "sk-eip155-0xdeadbeef")
            .await
            .expect_err("chain mismatch should fail");
        assert!(
            matches!(err, SessionKeyError::ChainMismatch { .. }),
            "expected ChainMismatch, got {err:?}"
        );
    });
}

#[test]
fn test_real_evm_sign_with_message_returns_signature() {
    futures::executor::block_on(async {
        let provider = real_evm_provider(MockEvmRpcClient::ok(), MockEvmBundlerClient::ok());
        let priv_key = evm_session_priv();
        let payload = SignPayload::Message { bytes: b"hello real session key".to_vec() };

        let sig = provider.sign_with(&priv_key, &payload).await.expect("sign_with should succeed");

        match sig {
            Signature::Evm { hex } => {
                assert!(hex.starts_with("0x"), "signature should be 0x-prefixed: {hex}");
                // EVM signature is 65 bytes (r||s||v) → 130 hex chars + "0x".
                assert_eq!(
                    hex.len(),
                    132,
                    "EVM signature should be 0x + 130 hex chars (65 bytes): {hex}"
                );
            }
            other => panic!("expected Signature::Evm, got {other:?}"),
        }
    });
}

#[test]
fn test_real_evm_merkle_root_deterministic() {
    let policy = test_policy("sk-real-merkle", 1_800_000_000);
    let root1 = RealEvmSessionKeyProvider::compute_merkle_root(&policy)
        .expect("compute_merkle_root should succeed");
    let root2 = RealEvmSessionKeyProvider::compute_merkle_root(&policy)
        .expect("compute_merkle_root should succeed");
    assert_eq!(root1, root2, "same policy must produce the same merkle root");
}

#[test]
fn test_real_evm_grant_without_sca_derives_from_owner() {
    futures::executor::block_on(async {
        // No with_sca_address — provider must derive a stand-in SCA from owner.
        let provider = RealEvmSessionKeyProvider::new(
            Arc::new(MockEvmRpcClient::ok()),
            Arc::new(MockEvmBundlerClient::ok()),
            "eip155:8453",
        );
        let owner = evm_owner_key("eip155:8453");
        let pubkey = evm_pubkey();
        let policy = test_policy("sk-no-sca", 999_999_999);

        let receipt = provider
            .grant(&owner, &pubkey, &policy)
            .await
            .expect("grant should succeed with owner-derived SCA");

        match receipt {
            GrantReceipt::Evm { sca_address, .. } => {
                assert!(
                    sca_address.starts_with("0x"),
                    "derived SCA should be 0x-prefixed: {sca_address}"
                );
                // EVM address is 20 bytes → 40 hex chars + "0x".
                assert_eq!(
                    sca_address.len(),
                    42,
                    "derived SCA should be 0x + 40 hex chars: {sca_address}"
                );
            }
            other => panic!("expected GrantReceipt::Evm, got {other:?}"),
        }
    });
}

// ---------------------------------------------------------------------------
// Real Solana provider
// ---------------------------------------------------------------------------

#[test]
fn test_real_solana_grant_returns_receipt_with_slot() {
    futures::executor::block_on(async {
        let rpc = MockSolanaRpcClient::ok();
        let provider = real_solana_provider(rpc);
        let owner = sol_owner_key("solana:devnet");
        let pubkey = sol_pubkey();
        let policy = test_policy("sk-real-sol", 999_999_999);

        let receipt =
            provider.grant(&owner, &pubkey, &policy).await.expect("real grant should succeed");

        match receipt {
            GrantReceipt::Solana { session_tokens_account, program_id, slot } => {
                assert!(
                    !session_tokens_account.is_empty(),
                    "session_tokens_account should be non-empty"
                );
                assert_eq!(
                    program_id, "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEf",
                    "program_id should match provider config"
                );
                assert_eq!(slot, 123_456, "slot should come from get_slot mock");
            }
            other => panic!("expected GrantReceipt::Solana, got {other:?}"),
        }
    });
}

#[test]
fn test_real_solana_grant_chain_mismatch_fails() {
    futures::executor::block_on(async {
        let provider = real_solana_provider(MockSolanaRpcClient::ok());
        let owner = sol_owner_key("solana:mainnet");
        let pubkey = sol_pubkey();
        let policy = test_policy("sk-real-sol", 999_999_999);

        let err =
            provider.grant(&owner, &pubkey, &policy).await.expect_err("chain mismatch should fail");
        match err {
            SessionKeyError::ChainMismatch { expected, actual } => {
                assert_eq!(expected, "solana:devnet");
                assert_eq!(actual, "solana:mainnet");
            }
            other => panic!("expected ChainMismatch, got {other:?}"),
        }
    });
}

#[test]
fn test_real_solana_verify_active_true_when_account_exists() {
    futures::executor::block_on(async {
        let mut rpc = MockSolanaRpcClient::ok();
        rpc.get_account_response = Ok(Some(vec![0x01, 0x02, 0x03]));
        let provider = real_solana_provider(rpc);
        let active = provider
            .verify_active("sk-solana-0xdeadbeef")
            .await
            .expect("verify_active should succeed");
        assert!(active, "Some(account) should mean active");
    });
}

#[test]
fn test_real_solana_verify_active_false_when_account_missing() {
    futures::executor::block_on(async {
        let mut rpc = MockSolanaRpcClient::ok();
        rpc.get_account_response = Ok(None);
        let provider = real_solana_provider(rpc);
        let active = provider
            .verify_active("sk-solana-0xdeadbeef")
            .await
            .expect("verify_active should succeed");
        assert!(!active, "None should mean inactive");
    });
}

#[test]
fn test_real_solana_revoke_sends_transaction() {
    futures::executor::block_on(async {
        let rpc = MockSolanaRpcClient::ok();
        let counters = rpc.counters();
        let provider = real_solana_provider(rpc);
        let owner = sol_owner_key("solana:devnet");

        provider.revoke(&owner, "sk-solana-0xdeadbeef").await.expect("revoke should succeed");

        assert_eq!(
            counters.send_transaction(),
            1,
            "revoke should send exactly one Solana transaction"
        );
    });
}

#[test]
fn test_real_solana_sign_with_message_returns_base58_signature() {
    futures::executor::block_on(async {
        let provider = real_solana_provider(MockSolanaRpcClient::ok());
        let priv_key = sol_session_priv();
        let payload = SignPayload::Message { bytes: b"hello real solana session key".to_vec() };

        let sig = provider.sign_with(&priv_key, &payload).await.expect("sign_with should succeed");

        match sig {
            Signature::Solana { base58 } => {
                assert!(!base58.is_empty(), "base58 signature should be non-empty");
                let decoded =
                    bs58::decode(&base58).into_vec().expect("base58 signature should decode");
                assert_eq!(decoded.len(), 64, "ed25519 signature should decode to 64 bytes");
            }
            other => panic!("expected Signature::Solana, got {other:?}"),
        }
    });
}

#[test]
fn test_real_solana_sign_with_transaction_payload_fails() {
    futures::executor::block_on(async {
        let provider = real_solana_provider(MockSolanaRpcClient::ok());
        let priv_key = sol_session_priv();
        let payload = SignPayload::Transaction { chain_id: 8453, raw_hex: "deadbeef".to_string() };

        let err = provider
            .sign_with(&priv_key, &payload)
            .await
            .expect_err("Transaction payload should be rejected for Solana");
        match err {
            SessionKeyError::InvalidPayload(msg) => {
                assert!(msg.contains("Solana"), "error should mention Solana: {msg}");
            }
            other => panic!("expected InvalidPayload, got {other:?}"),
        }
    });
}

// ---------------------------------------------------------------------------
// Real providers as trait objects
// ---------------------------------------------------------------------------

#[test]
fn test_real_providers_as_box_dyn_trait_objects() {
    futures::executor::block_on(async {
        let evm: Box<dyn SessionKeyProvider> =
            Box::new(real_evm_provider(MockEvmRpcClient::ok(), MockEvmBundlerClient::ok()));
        let sol: Box<dyn SessionKeyProvider> =
            Box::new(real_solana_provider(MockSolanaRpcClient::ok()));

        assert_eq!(evm.chain_id(), "eip155:8453");
        assert_eq!(sol.chain_id(), "solana:devnet");

        let evm_active = evm
            .verify_active("sk-eip155-0xdeadbeef")
            .await
            .expect("evm verify_active via trait object should succeed");
        assert!(evm_active, "mock eth_call returns non-zero → active");

        let sol_active = sol
            .verify_active("sk-solana-0xdeadbeef")
            .await
            .expect("solana verify_active via trait object should succeed");
        assert!(sol_active, "mock get_account returns Some → active");
    });
}

// ---------------------------------------------------------------------------
// Mock counters
// ---------------------------------------------------------------------------

#[test]
fn test_mock_evm_counters_record_calls() {
    futures::executor::block_on(async {
        let rpc = MockEvmRpcClient::ok();
        let rpc_counters = rpc.counters();
        let bundler = MockEvmBundlerClient::ok();
        let bundler_counters = bundler.counters();
        let provider = real_evm_provider(rpc, bundler);
        let owner = evm_owner_key("eip155:8453");
        let pubkey = evm_pubkey();
        let policy = test_policy("sk-counters", 999_999_999);

        // grant → 1 bundler call.
        let _ = provider.grant(&owner, &pubkey, &policy).await;
        // verify_active → 1 eth_call.
        let _ = provider.verify_active("sk-counters").await;
        // revoke → 1 send_transaction.
        let _ = provider.revoke(&owner, "sk-counters").await;

        assert_eq!(bundler_counters.send_user_op(), 1, "grant should call bundler once");
        assert_eq!(rpc_counters.eth_call(), 1, "verify_active should call eth_call once");
        assert_eq!(rpc_counters.send_transaction(), 1, "revoke should call send_transaction once");
    });
}

#[test]
fn test_mock_solana_counters_record_calls() {
    futures::executor::block_on(async {
        let rpc = MockSolanaRpcClient::ok();
        let counters = rpc.counters();
        let provider = real_solana_provider(rpc);
        let owner = sol_owner_key("solana:devnet");
        let pubkey = sol_pubkey();
        let policy = test_policy("sk-sol-counters", 999_999_999);

        // grant → 1 send_transaction + 1 get_slot.
        let _ = provider.grant(&owner, &pubkey, &policy).await;
        // verify_active → 1 get_account.
        let _ = provider.verify_active("sk-sol-counters").await;
        // revoke → 1 send_transaction.
        let _ = provider.revoke(&owner, "sk-sol-counters").await;

        // grant (1) + revoke (1) = 2 send_transaction calls.
        assert_eq!(
            counters.send_transaction(),
            2,
            "grant + revoke should each call send_transaction"
        );
        assert_eq!(counters.get_account(), 1, "verify_active should call get_account once");
    });
}

// ---------------------------------------------------------------------------
// Phase 1 + Phase 2 coexistence
// ---------------------------------------------------------------------------

#[test]
fn test_phase1_and_phase2_providers_coexist() {
    futures::executor::block_on(async {
        // Phase 1 (mock-based, single RpcClient trait) and Phase 2 (real,
        // split EvmRpcClient + EvmBundlerClient traits) must both compile and
        // work as Box<dyn SessionKeyProvider>.
        let phase1: Box<dyn SessionKeyProvider> = Box::new(EvmSessionKeyProvider::new(
            "eip155:8453",
            "0x0123456789012345678901234567890123456789",
            Box::new(MockRpcClient::ok()),
        ));
        let phase2: Box<dyn SessionKeyProvider> =
            Box::new(real_evm_provider(MockEvmRpcClient::ok(), MockEvmBundlerClient::ok()));

        assert_eq!(phase1.chain_id(), "eip155:8453");
        assert_eq!(phase2.chain_id(), "eip155:8453");

        let owner = evm_owner_key("eip155:8453");
        let pubkey = evm_pubkey();
        let policy = test_policy("sk-coexist", 999_999_999);

        let r1 =
            phase1.grant(&owner, &pubkey, &policy).await.expect("Phase 1 grant should succeed");
        let r2 =
            phase2.grant(&owner, &pubkey, &policy).await.expect("Phase 2 grant should succeed");

        assert!(matches!(r1, GrantReceipt::Evm { .. }), "Phase 1 should return Evm receipt");
        assert!(matches!(r2, GrantReceipt::Evm { .. }), "Phase 2 should return Evm receipt");
    });
}
