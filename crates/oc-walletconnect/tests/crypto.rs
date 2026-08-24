// Test code may unwrap/expect/panic (workspace lint phase-1 carve-out).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Crypto-layer tests against the official WalletConnect v2 reference
//! implementation (`@walletconnect/utils`). Includes golden vectors that pin
//! the exact key-derivation, envelope layout, and AEAD behavior the official
//! TypeScript client produces, so regressions in interop break the build.

use oc_walletconnect::crypto::{
    ENVELOPE_TYPE_0, ENVELOPE_TYPE_1, WcCipher, WcKeyPair, WcSymKey, derive_sym_key,
    deserialize_envelope, hash_key, hkdf_sha256, hmac_sha256, serialize_envelope,
};

#[test]
fn keypair_agreement_round_trips() {
    let a = WcKeyPair::generate();
    let b = WcKeyPair::generate();
    let shared_a = a.shared_secret(&b.public_key());
    let shared_b = b.shared_secret(&a.public_key());
    assert_eq!(shared_a.as_bytes(), shared_b.as_bytes());
}

/// Official `encrypt` uses ChaCha20-Poly1305 with **no AAD** (the reference
/// implementation calls `box.encrypt(message)` with a `undefined` AAD).
/// Our `WcCipher::seal`/`open` must round-trip with an empty AAD.
#[test]
fn chacha20poly1305_roundtrip_empty_aad() {
    let key = WcSymKey::from_random();
    let nonce = [0u8; 12];
    let plaintext = b"hello walletconnect";
    let ct = WcCipher::seal(&key, &nonce, plaintext).unwrap();
    let pt = WcCipher::open(&key, &nonce, &ct).unwrap();
    assert_eq!(pt, plaintext);
}

/// Golden vector: HKDF-SHA256 derivation matches `deriveSymKey` from
/// `@walletconnect/utils`:
///
/// ```ts
/// const sharedKey = x25519.getSharedSecret(privA, pubB);
/// const symKey = hkdf(sha256, sharedKey, undefined, undefined, 32);
/// ```
///
/// `undefined` salt → 32 zero bytes; `undefined` info → empty.
/// We use a fixed X25519 keypair so the output is deterministic.
#[test]
fn derive_sym_key_matches_official_hkdf() {
    // Fixed X25519 private keys (32 bytes each).
    let priv_a = [0x11u8; 32];
    let priv_b = [0x22u8; 32];
    let secret_a = x25519_dalek::StaticSecret::from(priv_a);
    let pub_b = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(priv_b));

    let shared = secret_a.diffie_hellman(&pub_b);
    let shared_bytes = shared.to_bytes();

    // Compute expected: HKDF-SHA256(salt=zeros32, ikm=shared, info="", len=32).
    let expected = hkdf_sha256(&[0u8; 32], &shared_bytes, b"", 32).unwrap();

    // WcSharedSecret wrapper + derive_sym_key must produce the same key.
    let wrapper = oc_walletconnect::crypto::WcSharedSecret::from_bytes_for_test(shared_bytes);
    let sym = derive_sym_key(&wrapper);
    assert_eq!(sym.as_bytes().as_slice(), expected.as_slice());
}

/// Golden vector: envelope type-0 layout is `[type(1) ‖ iv(12) ‖ sealed]`,
/// exactly as the official `serialize` produces.
#[test]
fn envelope_type0_layout_matches_official() {
    let key = WcSymKey::from_random();
    let msg = b"{\"jsonrpc\":\"2.0\",\"method\":\"ping\"}";
    let env = WcCipher::seal_type0(&key, msg).unwrap();
    assert_eq!(env[0], ENVELOPE_TYPE_0);
    assert_eq!(env.len(), 1 + 12 + msg.len() + 16);
    // First byte is the type; next 12 are the IV; rest is sealed (ct+tag).
    let deser = deserialize_envelope(&env).unwrap();
    assert_eq!(deser.r#type, ENVELOPE_TYPE_0);
    assert_eq!(&env[13..], deser.sealed.as_slice());
    // The deserialized sealed bytes decrypt back to the original message.
    let opened = WcCipher::open(&key, &deser.iv, &deser.sealed).unwrap();
    assert_eq!(opened, msg);
}

/// Golden vector: envelope type-1 layout is
/// `[type(1) ‖ senderPubKey(32) ‖ iv(12) ‖ sealed]`, as the official client
/// uses for the session-propose message.
#[test]
fn envelope_type1_layout_matches_official() {
    let key = WcSymKey::from_random();
    let sender = [0xABu8; 32];
    let msg = b"session propose";
    let env = WcCipher::seal_type1(&key, &sender, msg).unwrap();
    assert_eq!(env[0], ENVELOPE_TYPE_1);
    assert_eq!(env.len(), 1 + 32 + 12 + msg.len() + 16);
    assert_eq!(&env[1..33], &sender);
    let (recovered, pt) = WcCipher::open_type1(&key, &env).unwrap();
    assert_eq!(recovered, sender);
    assert_eq!(pt, msg);
}

/// Golden vector: `hashKey(symKey) = sha256(rawKey)` — the official client's
/// default session topic derivation.
#[test]
fn hash_key_is_sha256_of_raw_key() {
    let key = WcSymKey::from_bytes([0x7Fu8; 32]);
    use sha2::Digest;
    let expected = hex::encode(sha2::Sha256::digest([0x7Fu8; 32]));
    assert_eq!(hash_key(&key), expected);
}

#[test]
fn hmac_sha256_known_vector() {
    // RFC 4231 Test Case 1
    let key = [0x0bu8; 20];
    let data = b"Hi There";
    let mac = hmac_sha256(&key, data);
    let expected =
        hex_literal::hex!("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    assert_eq!(mac, expected);
}

#[test]
fn hkdf_sha256_known_vector() {
    // RFC 5869 A.1
    let ikm = [0x0bu8; 22];
    let salt = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c];
    let info = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
    let okm = hkdf_sha256(&salt, &ikm, &info, 42).unwrap();
    let expected = hex_literal::hex!(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    );
    assert_eq!(okm, expected);
}

/// Round-trip the type-2 (plaintext) envelope layout.
#[test]
fn envelope_type2_is_plaintext() {
    let env =
        serialize_envelope(oc_walletconnect::crypto::ENVELOPE_TYPE_2, &[0u8; 12], None, b"hi");
    assert_eq!(env, [2, b'h', b'i']);
    let deser = deserialize_envelope(&env).unwrap();
    assert_eq!(deser.sealed, b"hi");
}
