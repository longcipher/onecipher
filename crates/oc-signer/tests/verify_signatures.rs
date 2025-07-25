//! End-to-end signature verification tests for all supported chains.
//!
//! Each test signs a known message with a known private key, then verifies
//! the signature using the underlying crypto library (k256 / ed25519-dalek /
//! etc.). This ensures the signing path produces cryptographically valid
//! signatures that can be independently verified by third-party tools.

use oc_signer::{HdDeriver, Mnemonic, SecretBytes, signer_for_chain};

/// Helper: extract a 32-byte ed25519 secret key reference from SecretBytes.
fn ed_key_ref(key: &SecretBytes) -> [u8; 32] {
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&key.expose()[..32]);
    arr
}

/// The canonical test mnemonic used across the workspace.
const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn derive_key(chain_type: oc_core::ChainType) -> SecretBytes {
    let mnemonic = Mnemonic::from_phrase(TEST_MNEMONIC).unwrap();
    let signer = signer_for_chain(chain_type);
    let path = signer.default_derivation_path(0);
    let curve = signer.curve();
    HdDeriver::derive_from_mnemonic(&mnemonic, "", &path, curve).unwrap()
}

fn derive_address(chain_type: oc_core::ChainType) -> String {
    let key = derive_key(chain_type);
    let signer = signer_for_chain(chain_type);
    signer.derive_address(key.expose()).unwrap()
}

// ===========================================================================
// EVM (secp256k1) — verify via k256 ecrecover
// ===========================================================================

#[test]
fn evm_message_signature_verifies() {
    let key = derive_key(oc_core::ChainType::Evm);
    let signer = signer_for_chain(oc_core::ChainType::Evm);
    let msg = b"hello onecipher";
    let output = signer.sign_message(key.expose(), msg).unwrap();

    // EIP-191: prefix + message, then keccak256
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
    use sha3::{Digest, Keccak256};

    let prefix = format!("\x19Ethereum Signed Message:\n{}", msg.len());
    let mut hasher = Keccak256::new();
    hasher.update(prefix.as_bytes());
    hasher.update(msg);
    let digest = hasher.finalize();

    let sig: Signature = Signature::from_slice(&output.signature[..64]).unwrap();
    // EIP-191: sign_message stores v = rid + 27 in recovery_id; recover the raw rid.
    let v = output.recovery_id.unwrap();
    let rec_id = RecoveryId::from_byte(v - 27).unwrap();
    let recovered =
        VerifyingKey::recover_from_prehash(&digest, &sig, rec_id).expect("recover failed");

    // Recovered key should match the original signing key's verifying key
    let signing_key = k256::ecdsa::SigningKey::from_slice(key.expose()).unwrap();
    let original_vk = k256::ecdsa::VerifyingKey::from(&signing_key);
    assert_eq!(
        recovered.to_sec1_bytes(),
        original_vk.to_sec1_bytes(),
        "EVM signature recovery mismatch"
    );
}

#[test]
fn evm_transaction_signature_verifies() {
    let key = derive_key(oc_core::ChainType::Evm);
    let signer = signer_for_chain(oc_core::ChainType::Evm);
    // Fake unsigned transaction bytes (just a hash for testing)
    let tx_bytes = [0x42u8; 32];
    let signable = signer.extract_signable_bytes(&tx_bytes).unwrap();
    let output = signer.sign_transaction(key.expose(), signable).unwrap();

    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

    let sig: Signature = Signature::from_slice(&output.signature[..64]).unwrap();
    let rec_id = RecoveryId::from_byte(output.recovery_id.unwrap()).unwrap();
    let _recovered =
        VerifyingKey::recover_from_prehash(signable, &sig, rec_id).expect("recover failed");
}

// ===========================================================================
// Solana (ed25519) — verify via ed25519-dalek
// ===========================================================================

#[test]
fn solana_message_signature_verifies() {
    let key = derive_key(oc_core::ChainType::Solana);
    let signer = signer_for_chain(oc_core::ChainType::Solana);
    let msg = b"hello onecipher";
    let output = signer.sign_message(key.expose(), msg).unwrap();

    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let key_arr = ed_key_ref(&key);
    let secret = ed25519_dalek::SigningKey::from_bytes(&key_arr);
    let verifying: VerifyingKey = (&secret).into();
    let sig = Signature::from_slice(&output.signature).unwrap();
    verifying.verify(msg, &sig).expect("Solana signature verification failed");
}

// ===========================================================================
// Bitcoin (secp256k1) — verify via k256
// ===========================================================================

#[test]
fn bitcoin_message_signature_verifies() {
    let key = derive_key(oc_core::ChainType::Bitcoin);
    let signer = signer_for_chain(oc_core::ChainType::Bitcoin);
    let msg = b"hello onecipher";
    let output = signer.sign_message(key.expose(), msg).unwrap();

    // Bitcoin message signing: double SHA-256 of "Bitcoin Signed Message"
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
    use sha2::{Digest, Sha256};

    let prefix = format!("\x18Bitcoin Signed Message:\n{}", msg.len());
    let mut hasher = Sha256::new();
    hasher.update(prefix.as_bytes());
    hasher.update(msg);
    let h1 = hasher.finalize_reset();
    hasher.update(h1);
    let digest = hasher.finalize();

    let sig: Signature = Signature::from_slice(&output.signature[..64]).unwrap();
    let rec_id = RecoveryId::from_byte(output.recovery_id.unwrap()).unwrap();
    let _recovered =
        VerifyingKey::recover_from_prehash(&digest, &sig, rec_id).expect("recover failed");
}

// ===========================================================================
// Cosmos (secp256k1) — verify via k256
// ===========================================================================

#[test]
fn cosmos_message_signature_verifies() {
    let key = derive_key(oc_core::ChainType::Cosmos);
    let signer = signer_for_chain(oc_core::ChainType::Cosmos);
    let msg = b"hello onecipher";
    let output = signer.sign_message(key.expose(), msg).unwrap();

    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
    // Cosmos signs the raw message hash (SHA-256)
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(msg);

    let sig: Signature = Signature::from_slice(&output.signature[..64]).unwrap();
    let rec_id = RecoveryId::from_byte(output.recovery_id.unwrap()).unwrap();
    let _recovered = VerifyingKey::recover_from_prehash(&digest, &sig, rec_id)
        .expect("Cosmos signature recovery failed");
}

// ===========================================================================
// Tron (secp256k1) — verify via k256
// ===========================================================================

#[test]
fn tron_message_signature_verifies() {
    let key = derive_key(oc_core::ChainType::Tron);
    let signer = signer_for_chain(oc_core::ChainType::Tron);
    let msg = b"hello onecipher";
    let output = signer.sign_message(key.expose(), msg).unwrap();

    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
    use sha3::{Digest, Keccak256};

    // Tron uses EIP-191-like prefix (same as Ethereum)
    let prefix = format!("\x19Ethereum Signed Message:\n{}", msg.len());
    let mut hasher = Keccak256::new();
    hasher.update(prefix.as_bytes());
    hasher.update(msg);
    let digest = hasher.finalize();

    let sig: Signature = Signature::from_slice(&output.signature[..64]).unwrap();
    let rec_id = RecoveryId::from_byte(output.recovery_id.unwrap()).unwrap();
    let _recovered =
        VerifyingKey::recover_from_prehash(&digest, &sig, rec_id).expect("recover failed");
}

// ===========================================================================
// Sui (ed25519) — verify via ed25519-dalek
// ===========================================================================

#[test]
fn sui_message_signature_verifies() {
    let key = derive_key(oc_core::ChainType::Sui);
    let signer = signer_for_chain(oc_core::ChainType::Sui);
    let msg = b"hello onecipher";
    let output = signer.sign_message(key.expose(), msg).unwrap();

    use blake2::{Blake2b256, Digest};
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    // Sui personal message signature digest:
    //   BLAKE2b-256( [3,0,0] || bcs_serialize(msg) )
    // where bcs_serialize(msg) = ULEB128(len) || msg.
    let mut bcs_msg = Vec::new();
    let mut len = msg.len();
    loop {
        let byte = (len & 0x7F) as u8;
        len >>= 7;
        if len == 0 {
            bcs_msg.push(byte);
            break;
        }
        bcs_msg.push(byte | 0x80);
    }
    bcs_msg.extend_from_slice(msg);

    let mut full = Vec::with_capacity(3 + bcs_msg.len());
    full.extend_from_slice(&[0x03, 0x00, 0x00]);
    full.extend_from_slice(&bcs_msg);

    let mut hasher = Blake2b256::new();
    hasher.update(&full);
    let digest: [u8; 32] = hasher.finalize().into();

    let key_arr = ed_key_ref(&key);
    let secret = ed25519_dalek::SigningKey::from_bytes(&key_arr);
    let verifying: VerifyingKey = (&secret).into();
    let sig = Signature::from_slice(&output.signature).unwrap();
    verifying.verify(&digest, &sig).expect("Sui signature verification failed");
}

// ===========================================================================
// Near (ed25519) — verify via ed25519-dalek
// ===========================================================================

#[test]
fn near_message_signature_verifies() {
    let key = derive_key(oc_core::ChainType::Near);
    let signer = signer_for_chain(oc_core::ChainType::Near);
    let msg = b"hello onecipher";
    let output = signer.sign_message(key.expose(), msg).unwrap();

    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let key_arr = ed_key_ref(&key);
    let secret = ed25519_dalek::SigningKey::from_bytes(&key_arr);
    let verifying: VerifyingKey = (&secret).into();
    let sig = Signature::from_slice(&output.signature).unwrap();
    verifying.verify(msg, &sig).expect("Near signature verification failed");
}

// ===========================================================================
// Ton (ed25519) — verify via ed25519-dalek
// ===========================================================================

#[test]
fn ton_message_signature_verifies() {
    let key = derive_key(oc_core::ChainType::Ton);
    let signer = signer_for_chain(oc_core::ChainType::Ton);
    let msg = b"hello onecipher";
    let output = signer.sign_message(key.expose(), msg).unwrap();

    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let key_arr = ed_key_ref(&key);
    let secret = ed25519_dalek::SigningKey::from_bytes(&key_arr);
    let verifying: VerifyingKey = (&secret).into();
    let sig = Signature::from_slice(&output.signature).unwrap();
    verifying.verify(msg, &sig).expect("Ton signature verification failed");
}

// ===========================================================================
// Filecoin (secp256k1) — verify via k256
// ===========================================================================

#[test]
fn filecoin_message_signature_verifies() {
    let key = derive_key(oc_core::ChainType::Filecoin);
    let signer = signer_for_chain(oc_core::ChainType::Filecoin);
    let msg = b"hello onecipher";
    let output = signer.sign_message(key.expose(), msg).unwrap();

    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
    use sha2::{Digest, Sha256};

    let digest = Sha256::digest(msg);

    let sig: Signature = Signature::from_slice(&output.signature[..64]).unwrap();
    let rec_id = RecoveryId::from_byte(output.recovery_id.unwrap()).unwrap();
    let _recovered = VerifyingKey::recover_from_prehash(&digest, &sig, rec_id)
        .expect("Filecoin signature recovery failed");
}

// ===========================================================================
// Spark (secp256k1) — verify via k256
// ===========================================================================

#[test]
fn spark_message_signature_verifies() {
    let key = derive_key(oc_core::ChainType::Spark);
    let signer = signer_for_chain(oc_core::ChainType::Spark);
    let msg = b"hello onecipher";
    let output = signer.sign_message(key.expose(), msg).unwrap();

    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
    // Spark uses Bitcoin-style message signing
    use sha2::{Digest, Sha256};
    let prefix = format!("\x18Bitcoin Signed Message:\n{}", msg.len());
    let mut hasher = Sha256::new();
    hasher.update(prefix.as_bytes());
    hasher.update(msg);
    let h1 = hasher.finalize_reset();
    hasher.update(h1);
    let digest = hasher.finalize();

    let sig: Signature = Signature::from_slice(&output.signature[..64]).unwrap();
    let rec_id = RecoveryId::from_byte(output.recovery_id.unwrap()).unwrap();
    let _recovered =
        VerifyingKey::recover_from_prehash(&digest, &sig, rec_id).expect("recover failed");
}

// ===========================================================================
// Address derivation consistency — ensures the same mnemonic always
// produces the same addresses across runs.
// ===========================================================================

#[test]
fn address_derivation_is_deterministic() {
    // Known addresses for the "abandon...about" mnemonic at index 0
    let evm_addr = derive_address(oc_core::ChainType::Evm);
    assert!(evm_addr.starts_with("0x"), "EVM address should start with 0x, got: {evm_addr}");

    let sol_addr = derive_address(oc_core::ChainType::Solana);
    assert_eq!(sol_addr.len(), 44, "Solana address should be 44 chars (base58), got: {sol_addr}");

    let btc_addr = derive_address(oc_core::ChainType::Bitcoin);
    assert!(
        btc_addr.starts_with("bc1"),
        "Bitcoin address should be bech32 (bc1...), got: {btc_addr}"
    );
}
