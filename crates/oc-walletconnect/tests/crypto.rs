use oc_walletconnect::crypto::{WcCipher, WcKeyPair, WcSymKey, hkdf_sha256, hmac_sha256};

#[test]
fn keypair_agreement_round_trips() {
    let a = WcKeyPair::generate();
    let b = WcKeyPair::generate();
    let shared_a = a.shared_secret(&b.public_key());
    let shared_b = b.shared_secret(&a.public_key());
    assert_eq!(shared_a.as_bytes(), shared_b.as_bytes());
}

#[test]
fn chacha20poly1305_roundtrip() {
    let key = WcSymKey::from_random();
    let nonce = [0u8; 12];
    let aad = b"wc-2.0";
    let plaintext = b"hello walletconnect";
    let ct = WcCipher::seal(&key, &nonce, aad, plaintext).unwrap();
    let pt = WcCipher::open(&key, &nonce, aad, &ct).unwrap();
    assert_eq!(pt, plaintext);
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
    let okm = hkdf_sha256(&salt, &ikm, &info, 42);
    let expected = hex_literal::hex!(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    );
    assert_eq!(okm, expected);
}
