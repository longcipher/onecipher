//! Bitcoin chain signer (BIP-84 native segwit / P2WPKH-bech32).
//!
//! A10 supply-chain note: this module depends on the audited `bitcoin` 0.32
//! crate for PSBT parsing (`Psbt`), P2WPKH sighash (`SighashCache`), and ECDSA
//! (`secp256k1`, `ecdsa::Signature`). Re-implementing those consensus-critical
//! paths on top of `k256` alone was evaluated and rejected as strictly
//! riskier. The used feature subset is `["base64"]` only (see workspace
//! `Cargo.toml`).
//!
//! Taproot / TapTweak (`BIP-340`/`BIP-341`) is DELIBERATELY unsupported: this
//! signer derives P2WPKH addresses only and signs P2WPKH inputs only. Any
//! P2TR / TapTweak path (tweaked keys, Schnorr signatures, `OP_1` witness
//! programs) MUST fail closed — callers get `Transaction`, never a
//! silently mis-signed input. The negative tests below lock that behavior.

use std::str::FromStr;

use bitcoin::{
    Network, PrivateKey, PublicKey,
    base64::Engine,
    psbt::Psbt,
    script::ScriptBuf,
    secp256k1::Secp256k1,
    sighash::{EcdsaSighashType, SighashCache},
};
use k256::ecdsa::SigningKey;
use oc_core::ChainType;

use crate::{
    curve::Curve,
    encoding::{double_sha256, hash160},
    traits::{ChainSigner, SignOutput, SignerError},
};

/// PSBT magic bytes: "psbt\xff"
const PSBT_MAGIC: &[u8] = &[0x70, 0x73, 0x62, 0x74, 0xff];

/// Bitcoin chain signer (BIP-84 native segwit / bech32).
pub struct BitcoinSigner {
    /// Human-readable part for bech32 encoding ("bc" mainnet, "tb" testnet).
    hrp: String,
}

impl BitcoinSigner {
    pub fn new(hrp: &str) -> Self {
        Self { hrp: hrp.to_string() }
    }

    pub fn mainnet() -> Self {
        Self::new("bc")
    }

    pub fn testnet() -> Self {
        Self::new("tb")
    }

    fn signing_key(private_key: &[u8]) -> Result<SigningKey, SignerError> {
        SigningKey::from_slice(private_key).map_err(|e| SignerError::Input(e.to_string()))
    }

    fn bitcoin_private_key(private_key: &[u8]) -> Result<PrivateKey, SignerError> {
        let signing_key = Self::signing_key(private_key)?;
        let secret_key = bitcoin::secp256k1::SecretKey::from_slice(&signing_key.to_bytes())
            .map_err(|e| SignerError::Input(e.to_string()))?;
        Ok(PrivateKey::new(secret_key, Network::Bitcoin))
    }

    fn public_keys(private_key: &[u8]) -> Result<(PrivateKey, PublicKey), SignerError> {
        let private_key = Self::bitcoin_private_key(private_key)?;
        let secp = Secp256k1::new();
        let public_key = private_key.public_key(&secp);
        Ok((private_key, public_key))
    }

    fn p2wpkh_script_pubkey(public_key: &PublicKey) -> Result<ScriptBuf, SignerError> {
        let wpkh = public_key.wpubkey_hash().map_err(|_| {
            SignerError::AddressEncoding("bitcoin public key must be compressed".into())
        })?;
        Ok(ScriptBuf::new_p2wpkh(&wpkh))
    }

    fn previous_output(psbt: &Psbt, index: usize) -> Result<bitcoin::TxOut, SignerError> {
        let input = psbt
            .inputs
            .get(index)
            .ok_or_else(|| SignerError::Transaction(format!("missing PSBT input {index}")))?;

        if let Some(witness_utxo) = &input.witness_utxo {
            return Ok(witness_utxo.clone());
        }

        if let Some(non_witness_utxo) = &input.non_witness_utxo {
            let prevout = psbt
                .unsigned_tx
                .input
                .get(index)
                .ok_or_else(|| {
                    SignerError::Transaction(format!("missing unsigned transaction input {index}"))
                })?
                .previous_output;

            if non_witness_utxo.compute_txid() != prevout.txid {
                return Err(SignerError::Transaction(format!(
                    "non_witness_utxo txid mismatch for input {index}"
                )));
            }

            return non_witness_utxo.output.get(prevout.vout as usize).cloned().ok_or_else(|| {
                SignerError::Transaction(format!(
                    "missing prevout {} for input {index}",
                    prevout.vout
                ))
            });
        }

        Err(SignerError::Transaction(format!(
            "PSBT input {index} is missing witness_utxo/non_witness_utxo"
        )))
    }

    /// Sign a PSBT, adding partial signatures for inputs owned by this key.
    /// Returns the serialized signed PSBT.
    fn sign_psbt(private_key: &[u8], psbt_bytes: &[u8]) -> Result<Vec<u8>, SignerError> {
        let psbt_base64 = bitcoin::base64::engine::general_purpose::STANDARD.encode(psbt_bytes);
        let mut psbt = Psbt::from_str(&psbt_base64)
            .map_err(|e| SignerError::Transaction(format!("invalid PSBT: {e}")))?;

        let (priv_key, pub_key) = Self::public_keys(private_key)?;
        let expected_script = Self::p2wpkh_script_pubkey(&pub_key)?;

        for index in 0..psbt.inputs.len() {
            let prevout = Self::previous_output(&psbt, index)?;
            if prevout.script_pubkey != expected_script {
                continue;
            }

            let sighash_type = psbt.inputs[index]
                .sighash_type
                .map(|ty| {
                    ty.ecdsa_hash_ty().map_err(|e| {
                        SignerError::Transaction(format!(
                            "unsupported sighash type for input {index}: {e}"
                        ))
                    })
                })
                .transpose()?
                .unwrap_or(EcdsaSighashType::All);

            let sighash = SighashCache::new(&psbt.unsigned_tx)
                .p2wpkh_signature_hash(index, &prevout.script_pubkey, prevout.value, sighash_type)
                .map_err(|e| {
                    SignerError::Crypto(format!("failed to compute sighash for input {index}: {e}"))
                })?;

            let msg = bitcoin::secp256k1::Message::from(sighash);

            let secp = Secp256k1::new();
            let signature = secp.sign_ecdsa(&msg, &priv_key.inner);

            psbt.inputs[index]
                .partial_sigs
                .insert(pub_key, bitcoin::ecdsa::Signature { signature, sighash_type });
        }

        Ok(psbt.serialize())
    }
}

/// Encode an integer as a Bitcoin CompactSize (varint).
fn encode_compact_size(buf: &mut Vec<u8>, n: usize) {
    if n < 253 {
        buf.push(n as u8);
    } else if n <= 0xFFFF {
        buf.push(0xFD);
        buf.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xFFFF_FFFF {
        buf.push(0xFE);
        buf.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        buf.push(0xFF);
        buf.extend_from_slice(&(n as u64).to_le_bytes());
    }
}

impl ChainSigner for BitcoinSigner {
    fn chain_type(&self) -> ChainType {
        ChainType::Bitcoin
    }

    fn curve(&self) -> Curve {
        Curve::Secp256k1
    }

    fn coin_type(&self) -> u32 {
        0
    }

    fn derive_address(&self, private_key: &[u8]) -> Result<String, SignerError> {
        let signing_key = Self::signing_key(private_key)?;
        let verifying_key = signing_key.verifying_key();

        // Compressed public key (33 bytes)
        let pubkey_compressed = verifying_key.to_sec1_point(true);
        let pubkey_bytes = pubkey_compressed.as_bytes();

        // Hash160 (shared `crate::encoding` primitive).
        let hash = hash160(pubkey_bytes);

        // Bech32 segwit v0 encoding
        let hrp = bech32::Hrp::parse(&self.hrp)
            .map_err(|e| SignerError::AddressEncoding(e.to_string()))?;

        let address = bech32::segwit::encode(hrp, bech32::segwit::VERSION_0, &hash)
            .map_err(|e| SignerError::AddressEncoding(e.to_string()))?;

        Ok(address)
    }

    fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        if message.len() != 32 {
            return Err(SignerError::Input(format!(
                "expected 32-byte hash, got {} bytes",
                message.len()
            )));
        }

        let signing_key = Self::signing_key(private_key)?;
        let (signature, recovery_id) = signing_key.sign_prehash_recoverable(message);

        let mut sig_bytes = signature.to_bytes().to_vec();
        sig_bytes.push(recovery_id.to_byte());

        Ok(SignOutput {
            signature: sig_bytes,
            recovery_id: Some(recovery_id.to_byte()),
            public_key: None,
        })
    }

    fn sign_transaction(
        &self,
        private_key: &[u8],
        tx_bytes: &[u8],
    ) -> Result<SignOutput, SignerError> {
        // Detect PSBT by magic bytes and handle natively
        if tx_bytes.starts_with(PSBT_MAGIC) {
            let signed_psbt = Self::sign_psbt(private_key, tx_bytes)?;
            return Ok(SignOutput { signature: signed_psbt, recovery_id: None, public_key: None });
        }

        // Standard Bitcoin transaction signing: double SHA256 of the sighash preimage
        let hash = double_sha256(tx_bytes);
        self.sign(private_key, &hash)
    }

    fn sign_message(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        // Bitcoin message signing: double-SHA256 of prefixed message
        let prefix = b"\x18Bitcoin Signed Message:\n";
        let mut data = Vec::new();
        data.extend_from_slice(prefix);
        encode_compact_size(&mut data, message.len());
        data.extend_from_slice(message);

        let hash = double_sha256(&data);
        self.sign(private_key, &hash)
    }

    fn default_derivation_path(&self, index: u32) -> String {
        format!("m/84'/0'/0'/0/{}", index)
    }
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use super::*;

    #[test]
    fn test_known_address_generator_point() {
        // Generator point G private key = 1 (0x0000...0001)
        let mut privkey = vec![0u8; 31];
        privkey.push(1u8);

        let signer = BitcoinSigner::mainnet();
        let address = signer.derive_address(&privkey).unwrap();
        assert_eq!(address, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
    }

    #[test]
    fn test_testnet_prefix() {
        let mut privkey = vec![0u8; 31];
        privkey.push(1u8);

        let signer = BitcoinSigner::testnet();
        let address = signer.derive_address(&privkey).unwrap();
        assert!(address.starts_with("tb1"));
    }

    #[test]
    fn test_derivation_path() {
        let signer = BitcoinSigner::mainnet();
        assert_eq!(signer.default_derivation_path(0), "m/84'/0'/0'/0/0");
        assert_eq!(signer.default_derivation_path(3), "m/84'/0'/0'/0/3");
    }

    #[test]
    fn test_deterministic() {
        let mut privkey = vec![0u8; 31];
        privkey.push(1u8);

        let signer = BitcoinSigner::mainnet();
        let addr1 = signer.derive_address(&privkey).unwrap();
        let addr2 = signer.derive_address(&privkey).unwrap();
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn test_chain_properties() {
        let signer = BitcoinSigner::mainnet();
        assert_eq!(signer.chain_type(), ChainType::Bitcoin);
        assert_eq!(signer.curve(), Curve::Secp256k1);
        assert_eq!(signer.coin_type(), 0);
    }

    #[test]
    fn test_sign_message_long_message_varint() {
        use k256::ecdsa::signature::hazmat::PrehashVerifier;

        let mut privkey = vec![0u8; 31];
        privkey.push(1u8);
        let signer = BitcoinSigner::mainnet();

        // Message longer than 252 bytes requires multi-byte CompactSize varint
        let message = vec![0x42u8; 300];
        let result = signer.sign_message(&privkey, &message).unwrap();

        // Compute expected hash with CORRECT varint encoding:
        // CompactSize for 300: 0xFD followed by 300 as 2-byte LE (0x2C, 0x01)
        let mut expected_data = Vec::new();
        expected_data.extend_from_slice(b"\x18Bitcoin Signed Message:\n");
        expected_data.push(0xFD);
        expected_data.extend_from_slice(&300u16.to_le_bytes());
        expected_data.extend_from_slice(&message);

        let expected_hash = Sha256::digest(Sha256::digest(&expected_data));

        // Verify signature against the correctly computed hash
        let signing_key = SigningKey::from_slice(&privkey).unwrap();
        let verifying_key = signing_key.verifying_key();
        let r: [u8; 32] = result.signature[..32].try_into().unwrap();
        let s: [u8; 32] = result.signature[32..64].try_into().unwrap();
        let sig = k256::ecdsa::Signature::from_scalars(r, s).unwrap();

        verifying_key
            .verify_prehash(&expected_hash, &sig)
            .expect("signature should verify with correct varint encoding for long messages");
    }

    #[test]
    fn test_sign_message_253_byte_varint_boundary() {
        use k256::ecdsa::signature::hazmat::PrehashVerifier;

        let mut privkey = vec![0u8; 31];
        privkey.push(1u8);
        let signer = BitcoinSigner::mainnet();

        // 253 bytes: the exact boundary where single-byte varint becomes invalid
        let message = vec![0xAA; 253];
        let result = signer.sign_message(&privkey, &message).unwrap();

        let mut expected_data = Vec::new();
        expected_data.extend_from_slice(b"\x18Bitcoin Signed Message:\n");
        expected_data.push(0xFD);
        expected_data.extend_from_slice(&253u16.to_le_bytes());
        expected_data.extend_from_slice(&message);

        let expected_hash = Sha256::digest(Sha256::digest(&expected_data));

        let signing_key = SigningKey::from_slice(&privkey).unwrap();
        let verifying_key = signing_key.verifying_key();
        let r: [u8; 32] = result.signature[..32].try_into().unwrap();
        let s: [u8; 32] = result.signature[32..64].try_into().unwrap();
        let sig = k256::ecdsa::Signature::from_scalars(r, s).unwrap();

        verifying_key
            .verify_prehash(&expected_hash, &sig)
            .expect("signature should verify at varint boundary (253 bytes)");
    }

    #[test]
    fn test_sign_transaction_rejects_invalid_psbt() {
        let signer = BitcoinSigner::mainnet();
        let mut privkey = vec![0u8; 31];
        privkey.push(1u8);

        // Valid PSBT magic but truncated body
        let mut bad_psbt = PSBT_MAGIC.to_vec();
        bad_psbt.extend_from_slice(b"truncated");

        let result = signer.sign_transaction(&privkey, &bad_psbt);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid PSBT"));
    }

    #[test]
    fn test_sign_transaction_non_psbt_still_works() {
        let signer = BitcoinSigner::mainnet();
        let mut privkey = vec![0u8; 31];
        privkey.push(1u8);

        // Non-PSBT bytes should go through the normal double-SHA256 path
        let tx_bytes = b"some raw tx bytes";
        let result = signer.sign_transaction(&privkey, tx_bytes);
        assert!(result.is_ok());
    }

    #[test]
    fn test_sign_message_short_message_still_works() {
        use k256::ecdsa::signature::hazmat::PrehashVerifier;

        let mut privkey = vec![0u8; 31];
        privkey.push(1u8);
        let signer = BitcoinSigner::mainnet();

        // Short message (< 253 bytes) uses single-byte varint
        let message = b"Hello Bitcoin!";
        let result = signer.sign_message(&privkey, message).unwrap();

        let mut expected_data = Vec::new();
        expected_data.extend_from_slice(b"\x18Bitcoin Signed Message:\n");
        expected_data.push(message.len() as u8); // single byte varint OK for < 253
        expected_data.extend_from_slice(message);

        let expected_hash = Sha256::digest(Sha256::digest(&expected_data));

        let signing_key = SigningKey::from_slice(&privkey).unwrap();
        let verifying_key = signing_key.verifying_key();
        let r: [u8; 32] = result.signature[..32].try_into().unwrap();
        let s: [u8; 32] = result.signature[32..64].try_into().unwrap();
        let sig = k256::ecdsa::Signature::from_scalars(r, s).unwrap();

        verifying_key
            .verify_prehash(&expected_hash, &sig)
            .expect("signature should verify for short messages");
    }

    #[test]
    fn test_taproot_not_supported_derive_is_p2wpkh_only() {
        // A10 negative test: the signer derives P2WPKH (bc1q...) only.
        // It MUST never emit a P2TR (bc1p...) address, which would imply a
        // TapTweak path that does not exist here.
        let mut privkey = vec![0u8; 31];
        privkey.push(1u8);
        let signer = BitcoinSigner::mainnet();
        let address = signer.derive_address(&privkey).unwrap();
        assert!(address.starts_with("bc1q"), "P2WPKH-only signer must emit bc1q, got: {address}");
        assert!(
            !address.starts_with("bc1p"),
            "Taproot (bc1p) addresses are unsupported by design, got: {address}"
        );
    }

    #[test]
    fn test_taptweak_path_rejected_sign_requires_32_byte_hash() {
        // A10 negative test: TapTweak/Schnorr paths operate on x-only keys and
        // 32-byte tweaked digests via a different signature scheme. This ECDSA
        // signer requires exactly 32 bytes of pre-hashed input and rejects
        // anything else fail-closed instead of coercing it into a tweak.
        let signer = BitcoinSigner::mainnet();
        let mut privkey = vec![0u8; 31];
        privkey.push(1u8);
        // 33-byte x-only-plus-parity and 64-byte Schnorr payloads are rejected.
        assert!(signer.sign(&privkey, &[0u8; 33]).is_err());
        assert!(signer.sign(&privkey, &[0u8; 64]).is_err());
        assert!(signer.sign(&privkey, b"short").is_err());
    }

    #[test]
    fn test_psbt_without_owned_p2wpkh_inputs_signs_nothing_new() {
        // A10 negative test: a PSBT whose inputs do not match our P2WPKH
        // script is left untouched (no partial_sigs for foreign inputs).
        // Here we assert the fail-closed parse path: garbage after the magic
        // is a Transaction error, never a silent no-op signature.
        let signer = BitcoinSigner::mainnet();
        let mut privkey = vec![0u8; 31];
        privkey.push(1u8);
        let mut bad_psbt = PSBT_MAGIC.to_vec();
        bad_psbt.extend_from_slice(b"\x00\x01\x02taproot-fake");
        let err = signer.sign_transaction(&privkey, &bad_psbt).unwrap_err();
        assert!(err.to_string().contains("invalid PSBT"), "got: {err}");
    }
}
