use std::path::Path;

use oc_core::{
    ALL_CHAIN_TYPES, ChainType, EncryptedWallet, KeyType, WalletAccount, default_chain_for_type,
};
use oc_signer::{
    CryptoEnvelope, CryptoError, Curve, HdDeriver, Mnemonic, MnemonicStrength, SecretBytes,
    decrypt, encrypt, signer_for_chain,
};

use crate::{
    error::OcWalletError,
    types::{AccountInfo, SignResult, WalletInfo},
};

/// Convert an EncryptedWallet to the binding-friendly WalletInfo.
fn wallet_to_info(w: &EncryptedWallet) -> WalletInfo {
    WalletInfo {
        id: w.id.clone(),
        name: w.name.clone(),
        accounts: w
            .accounts
            .iter()
            .map(|a| AccountInfo {
                chain_id: a.chain_id.clone(),
                address: a.address.clone(),
                derivation_path: a.derivation_path.clone(),
            })
            .collect(),
        created_at: w.created_at.clone(),
    }
}

pub(crate) fn parse_chain(s: &str) -> Result<oc_core::Chain, OcWalletError> {
    oc_core::parse_chain(s).map_err(OcWalletError::InvalidInput)
}

/// Derive accounts for all chain families from a mnemonic at the given index.
fn derive_all_accounts(
    mnemonic: &Mnemonic,
    index: u32,
) -> Result<Vec<WalletAccount>, OcWalletError> {
    let mut accounts = Vec::with_capacity(ALL_CHAIN_TYPES.len());
    for ct in &ALL_CHAIN_TYPES {
        let chain = default_chain_for_type(*ct);
        let signer = signer_for_chain(*ct);
        let path = signer.default_derivation_path(index);
        let curve = signer.curve();
        let key = HdDeriver::derive_from_mnemonic(mnemonic, "", &path, curve)?;
        let address = signer.derive_address(key.expose())?;
        let account_id = format!("{}:{}", chain.chain_id, address);
        accounts.push(WalletAccount {
            account_id,
            address,
            chain_id: chain.chain_id.to_string(),
            derivation_path: path,
        });
    }
    Ok(accounts)
}

/// A key pair: one key per curve.
/// Private key material is mlocked + zeroized on drop via HardenedBytes.
struct KeyPair {
    secp256k1: SecretBytes,
    ed25519: SecretBytes,
}

impl KeyPair {
    /// Get the key for a given curve.
    fn key_for_curve(&self, curve: oc_signer::Curve) -> &[u8] {
        match curve {
            oc_signer::Curve::Secp256k1 => self.secp256k1.expose(),
            oc_signer::Curve::Ed25519 => self.ed25519.expose(),
        }
    }

    /// Serialize to JSON bytes for encryption.
    fn to_json_bytes(&self) -> Vec<u8> {
        let obj = serde_json::json!({
            "secp256k1": hex::encode(self.secp256k1.expose()),
            "ed25519": hex::encode(self.ed25519.expose()),
        });
        obj.to_string().into_bytes()
    }

    /// Deserialize from JSON bytes after decryption.
    fn from_json_bytes(bytes: &[u8]) -> Result<Self, OcWalletError> {
        let s = String::from_utf8(bytes.to_vec())
            .map_err(|_| OcWalletError::InvalidInput("invalid key pair data".into()))?;
        let obj: serde_json::Value = serde_json::from_str(&s)?;
        let secp = obj["secp256k1"]
            .as_str()
            .ok_or_else(|| OcWalletError::InvalidInput("missing secp256k1 key".into()))?;
        let ed = obj["ed25519"]
            .as_str()
            .ok_or_else(|| OcWalletError::InvalidInput("missing ed25519 key".into()))?;
        let secp_bytes = hex::decode(secp)
            .map_err(|e| OcWalletError::InvalidInput(format!("invalid secp256k1 hex: {e}")))?;
        let ed_bytes = hex::decode(ed)
            .map_err(|e| OcWalletError::InvalidInput(format!("invalid ed25519 hex: {e}")))?;
        Ok(Self {
            secp256k1: SecretBytes::from_vec(secp_bytes).map_err(CryptoError::from)?,
            ed25519: SecretBytes::from_vec(ed_bytes).map_err(CryptoError::from)?,
        })
    }
}

/// Derive accounts for all chain families using a key pair (one key per curve).
fn derive_all_accounts_from_keys(keys: &KeyPair) -> Result<Vec<WalletAccount>, OcWalletError> {
    let mut accounts = Vec::with_capacity(ALL_CHAIN_TYPES.len());
    for ct in &ALL_CHAIN_TYPES {
        let signer = signer_for_chain(*ct);
        let key = keys.key_for_curve(signer.curve());
        let address = signer.derive_address(key)?;
        let chain = default_chain_for_type(*ct);
        accounts.push(WalletAccount {
            account_id: format!("{}:{}", chain.chain_id, address),
            address,
            chain_id: chain.chain_id.to_string(),
            derivation_path: String::new(),
        });
    }
    Ok(accounts)
}

pub(crate) fn secret_to_signing_key(
    secret: &SecretBytes,
    key_type: &KeyType,
    chain_type: ChainType,
    index: Option<u32>,
) -> Result<SecretBytes, OcWalletError> {
    match key_type {
        KeyType::Mnemonic => {
            // Use the SecretBytes directly as a &str to avoid un-zeroized String copies.
            let phrase = std::str::from_utf8(secret.expose()).map_err(|_| {
                OcWalletError::InvalidInput("wallet contains invalid UTF-8 mnemonic".into())
            })?;
            let mnemonic = Mnemonic::from_phrase(phrase)?;
            let signer = signer_for_chain(chain_type);
            let path = signer.default_derivation_path(index.unwrap_or(0));
            let curve = signer.curve();
            Ok(HdDeriver::derive_from_mnemonic_cached(&mnemonic, "", &path, curve)?)
        }
        KeyType::PrivateKey => {
            // JSON key pair — extract the right key for this chain's curve
            let keys = KeyPair::from_json_bytes(secret.expose())?;
            let signer = signer_for_chain(chain_type);
            Ok(SecretBytes::from_slice(keys.key_for_curve(signer.curve()))
                .map_err(CryptoError::from)?)
        }
    }
}

/// Generate a new BIP-39 mnemonic phrase.
pub fn generate_mnemonic(words: u32) -> Result<String, OcWalletError> {
    let strength = match words {
        12 => MnemonicStrength::Words12,
        15 => MnemonicStrength::Words15,
        18 => MnemonicStrength::Words18,
        21 => MnemonicStrength::Words21,
        24 => MnemonicStrength::Words24,
        _ => return Err(OcWalletError::InvalidInput("words must be 12, 15, 18, 21, or 24".into())),
    };

    let mnemonic = Mnemonic::generate(strength)?;
    let phrase = mnemonic.phrase()?;
    String::from_utf8(phrase.expose().to_vec())
        .map_err(|e| OcWalletError::InvalidInput(format!("invalid UTF-8 in mnemonic: {e}")))
}

/// Derive an address from a mnemonic phrase for the given chain.
pub fn derive_address(
    mnemonic_phrase: &str,
    chain: &str,
    index: Option<u32>,
) -> Result<String, OcWalletError> {
    let chain = parse_chain(chain)?;
    let mnemonic = Mnemonic::from_phrase(mnemonic_phrase)?;
    let signer = signer_for_chain(chain.chain_type);
    let path = signer.default_derivation_path(index.unwrap_or(0));
    let curve = signer.curve();

    let key = HdDeriver::derive_from_mnemonic(&mnemonic, "", &path, curve)?;
    let address = signer.derive_address(key.expose())?;
    Ok(address)
}

/// Create a new universal wallet: generates mnemonic, derives addresses for all chains,
/// encrypts, and saves to vault.
pub fn create_wallet(
    name: &str,
    words: Option<u32>,
    passphrase: Option<&str>,
    vault_path: Option<&Path>,
) -> Result<WalletInfo, OcWalletError> {
    let passphrase = passphrase.unwrap_or("");
    let words = words.unwrap_or(12);
    let strength = match words {
        12 => MnemonicStrength::Words12,
        15 => MnemonicStrength::Words15,
        18 => MnemonicStrength::Words18,
        21 => MnemonicStrength::Words21,
        24 => MnemonicStrength::Words24,
        _ => return Err(OcWalletError::InvalidInput("words must be 12, 15, 18, 21, or 24".into())),
    };

    if oc_vault::wallet_name_exists(name, vault_path)? {
        return Err(OcWalletError::WalletNameExists(name.to_string()));
    }

    let mnemonic = Mnemonic::generate(strength)?;
    let accounts = derive_all_accounts(&mnemonic, 0)?;

    let phrase = mnemonic.phrase()?;
    let crypto_envelope = encrypt(phrase.expose(), passphrase.as_bytes())?;
    let crypto_json = serde_json::to_value(&crypto_envelope)?;

    let wallet_id = uuid::Uuid::new_v4().to_string();

    let wallet =
        EncryptedWallet::new(wallet_id, name.to_string(), accounts, crypto_json, KeyType::Mnemonic);

    oc_vault::save_encrypted_wallet(&wallet, vault_path)?;
    Ok(wallet_to_info(&wallet))
}

/// Import a wallet from a mnemonic phrase. Derives addresses for all chains.
pub fn import_wallet_mnemonic(
    name: &str,
    mnemonic_phrase: &str,
    passphrase: Option<&str>,
    index: Option<u32>,
    vault_path: Option<&Path>,
) -> Result<WalletInfo, OcWalletError> {
    let passphrase = passphrase.unwrap_or("");
    let index = index.unwrap_or(0);

    if oc_vault::wallet_name_exists(name, vault_path)? {
        return Err(OcWalletError::WalletNameExists(name.to_string()));
    }

    let mnemonic = Mnemonic::from_phrase(mnemonic_phrase)?;
    let accounts = derive_all_accounts(&mnemonic, index)?;

    let phrase = mnemonic.phrase()?;
    let crypto_envelope = encrypt(phrase.expose(), passphrase.as_bytes())?;
    let crypto_json = serde_json::to_value(&crypto_envelope)?;

    let wallet_id = uuid::Uuid::new_v4().to_string();

    let wallet =
        EncryptedWallet::new(wallet_id, name.to_string(), accounts, crypto_json, KeyType::Mnemonic);

    oc_vault::save_encrypted_wallet(&wallet, vault_path)?;
    Ok(wallet_to_info(&wallet))
}

/// Decode a hex-encoded key, stripping an optional `0x` prefix.
fn decode_hex_key(hex_str: &str) -> Result<Vec<u8>, OcWalletError> {
    let trimmed = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    hex::decode(trimmed)
        .map_err(|e| OcWalletError::InvalidInput(format!("invalid hex private key: {e}")))
}

/// Import a wallet from a hex-encoded private key.
/// The `chain` parameter specifies which chain the key originates from (e.g. "evm", "solana").
/// A random key is generated for the other curve so all 6 chains are supported.
///
/// Alternatively, provide both `secp256k1_key_hex` and `ed25519_key_hex` to supply
/// explicit keys for each curve. When both are given, `private_key_hex` and `chain`
/// are ignored. When only one curve key is given alongside `private_key_hex`, it
/// overrides the random generation for that curve.
pub fn import_wallet_private_key(
    name: &str,
    private_key_hex: &str,
    chain: Option<&str>,
    passphrase: Option<&str>,
    vault_path: Option<&Path>,
    secp256k1_key_hex: Option<&str>,
    ed25519_key_hex: Option<&str>,
) -> Result<WalletInfo, OcWalletError> {
    let passphrase = passphrase.unwrap_or("");

    if oc_vault::wallet_name_exists(name, vault_path)? {
        return Err(OcWalletError::WalletNameExists(name.to_string()));
    }

    let keys = if let (Some(secp_hex), Some(ed_hex)) = (secp256k1_key_hex, ed25519_key_hex) {
        // Both curve keys explicitly provided — use them directly
        KeyPair {
            secp256k1: SecretBytes::from_vec(decode_hex_key(secp_hex)?)
                .map_err(CryptoError::from)?,
            ed25519: SecretBytes::from_vec(decode_hex_key(ed_hex)?).map_err(CryptoError::from)?,
        }
    } else {
        // Existing single-key behavior
        let key_bytes = decode_hex_key(private_key_hex)?;

        // Determine curve from the source chain (default: secp256k1)
        let source_curve = match chain {
            Some(c) => {
                let parsed = parse_chain(c)?;
                signer_for_chain(parsed.chain_type).curve()
            }
            None => oc_signer::Curve::Secp256k1,
        };

        // Build key pair: provided key for its curve, random 32 bytes for the other
        let mut other_key = vec![0u8; 32];
        getrandom::fill(&mut other_key).map_err(|e| {
            OcWalletError::InvalidInput(format!("failed to generate random key: {e}"))
        })?;

        match source_curve {
            oc_signer::Curve::Secp256k1 => KeyPair {
                secp256k1: SecretBytes::from_vec(key_bytes).map_err(CryptoError::from)?,
                ed25519: match ed25519_key_hex {
                    Some(h) => {
                        SecretBytes::from_vec(decode_hex_key(h)?).map_err(CryptoError::from)?
                    }
                    None => SecretBytes::from_vec(other_key).map_err(CryptoError::from)?,
                },
            },
            oc_signer::Curve::Ed25519 => KeyPair {
                secp256k1: match secp256k1_key_hex {
                    Some(h) => {
                        SecretBytes::from_vec(decode_hex_key(h)?).map_err(CryptoError::from)?
                    }
                    None => SecretBytes::from_vec(other_key).map_err(CryptoError::from)?,
                },
                ed25519: SecretBytes::from_vec(key_bytes).map_err(CryptoError::from)?,
            },
        }
    };

    let accounts = derive_all_accounts_from_keys(&keys)?;

    let payload = keys.to_json_bytes();
    let crypto_envelope = encrypt(&payload, passphrase.as_bytes())?;
    let crypto_json = serde_json::to_value(&crypto_envelope)?;

    let wallet_id = uuid::Uuid::new_v4().to_string();

    let wallet = EncryptedWallet::new(
        wallet_id,
        name.to_string(),
        accounts,
        crypto_json,
        KeyType::PrivateKey,
    );

    oc_vault::save_encrypted_wallet(&wallet, vault_path)?;
    Ok(wallet_to_info(&wallet))
}

/// List all wallets in the vault.
pub fn list_wallets(vault_path: Option<&Path>) -> Result<Vec<WalletInfo>, OcWalletError> {
    let wallets = oc_vault::list_encrypted_wallets(vault_path)?;
    Ok(wallets.iter().map(wallet_to_info).collect())
}

/// Get a single wallet by name or ID.
pub fn get_wallet(
    name_or_id: &str,
    vault_path: Option<&Path>,
) -> Result<WalletInfo, OcWalletError> {
    let wallet = oc_vault::load_wallet_by_name_or_id(name_or_id, vault_path)?;
    Ok(wallet_to_info(&wallet))
}

/// Delete a wallet from the vault.
pub fn delete_wallet(name_or_id: &str, vault_path: Option<&Path>) -> Result<(), OcWalletError> {
    let wallet = oc_vault::load_wallet_by_name_or_id(name_or_id, vault_path)?;
    oc_vault::delete_wallet_file(&wallet.id, vault_path)?;
    Ok(())
}

/// Export a wallet's secret.
///
/// Mnemonic wallets return the phrase. Private key wallets return JSON with
/// both keys.
///
/// The decrypted secret is returned as [`SecretBytes`] (a type alias for
/// `oc_crypto::HardenedBytes`) so the material stays memory-hardened (mlock +
/// `MADV_DONTDUMP` + zeroize on drop). Callers that need a `&str` should use
/// `std::str::from_utf8(secret.expose())` and handle the UTF-8 error.
pub fn export_wallet(
    name_or_id: &str,
    passphrase: Option<&str>,
    vault_path: Option<&Path>,
) -> Result<SecretBytes, OcWalletError> {
    let passphrase = passphrase.unwrap_or("");
    let wallet = oc_vault::load_wallet_by_name_or_id(name_or_id, vault_path)?;
    let envelope: CryptoEnvelope = serde_json::from_value(wallet.crypto)?;
    let secret = decrypt(&envelope, passphrase.as_bytes())?;
    // Return the HardenedBytes directly — do not copy the decrypted mnemonic /
    // key material into an un-hardened String. Callers obtain &str via
    // `std::str::from_utf8(secret.expose())` when needed.
    Ok(secret)
}

/// Rename a wallet.
pub fn rename_wallet(
    name_or_id: &str,
    new_name: &str,
    vault_path: Option<&Path>,
) -> Result<(), OcWalletError> {
    let mut wallet = oc_vault::load_wallet_by_name_or_id(name_or_id, vault_path)?;

    if wallet.name == new_name {
        return Ok(());
    }

    if oc_vault::wallet_name_exists(new_name, vault_path)? {
        return Err(OcWalletError::WalletNameExists(new_name.to_string()));
    }

    wallet.name = new_name.to_string();
    oc_vault::save_encrypted_wallet(&wallet, vault_path)?;
    Ok(())
}

fn decode_hash_hex(hash_hex: &str) -> Result<Vec<u8>, OcWalletError> {
    let hash_hex = hash_hex.strip_prefix("0x").unwrap_or(hash_hex);
    let hash = hex::decode(hash_hex)
        .map_err(|e| OcWalletError::InvalidInput(format!("invalid hex hash: {e}")))?;

    if hash.len() != 32 {
        return Err(OcWalletError::InvalidInput(format!(
            "raw hash signing requires exactly 32 bytes, got {}",
            hash.len()
        )));
    }

    Ok(hash)
}

fn sign_hash_with_credential(
    wallet: &str,
    chain: &oc_core::Chain,
    policy_bytes: &[u8],
    hash_bytes: &[u8],
    credential: &str,
    index: Option<u32>,
    vault_path: Option<&Path>,
) -> Result<SignResult, OcWalletError> {
    let signer = signer_for_chain(chain.chain_type);
    if signer.curve() != Curve::Secp256k1 {
        return Err(OcWalletError::InvalidInput(
            "raw hash signing is only supported for secp256k1-backed chains".into(),
        ));
    }

    if hash_bytes.len() != 32 {
        return Err(OcWalletError::InvalidInput(format!(
            "raw hash signing requires exactly 32 bytes, got {}",
            hash_bytes.len()
        )));
    }

    if credential.starts_with(crate::key_store::TOKEN_PREFIX) {
        return crate::key_ops::sign_hash_with_api_key(
            credential,
            wallet,
            chain,
            policy_bytes,
            hash_bytes,
            index,
            vault_path,
        );
    }

    let key =
        decrypt_signing_key(wallet, chain.chain_type, credential.as_bytes(), index, vault_path)?;
    let output = signer.sign(key.expose(), hash_bytes)?;

    Ok(SignResult { signature: hex::encode(&output.signature), recovery_id: output.recovery_id })
}

/// Sign a transaction. Returns hex-encoded signature.
///
/// The `passphrase` parameter accepts either the owner's passphrase or an
/// API token (`oc_key_...`). When a token is provided, policy enforcement
/// kicks in and the mnemonic is decrypted via HKDF instead of argon2id.
pub fn sign_transaction(
    wallet: &str,
    chain: &str,
    tx_hex: &str,
    passphrase: Option<&str>,
    index: Option<u32>,
    vault_path: Option<&Path>,
) -> Result<SignResult, OcWalletError> {
    let credential = passphrase.unwrap_or("");

    let tx_hex_clean = tx_hex.strip_prefix("0x").unwrap_or(tx_hex);
    let tx_bytes = hex::decode(tx_hex_clean)
        .map_err(|e| OcWalletError::InvalidInput(format!("invalid hex transaction: {e}")))?;

    // Agent mode: token-based signing with policy enforcement
    if credential.starts_with(crate::key_store::TOKEN_PREFIX) {
        let chain = parse_chain(chain)?;
        return crate::key_ops::sign_with_api_key(
            credential, wallet, &chain, &tx_bytes, index, vault_path,
        );
    }

    // Owner mode: existing passphrase-based signing (unchanged)
    let chain = parse_chain(chain)?;
    let key =
        decrypt_signing_key(wallet, chain.chain_type, credential.as_bytes(), index, vault_path)?;
    let signer = signer_for_chain(chain.chain_type);
    let signable = signer.extract_signable_bytes(&tx_bytes)?;
    let output = signer.sign_transaction(key.expose(), signable)?;

    Ok(SignResult { signature: hex::encode(&output.signature), recovery_id: output.recovery_id })
}

/// Sign a raw 32-byte hash using the secp256k1 key for the selected chain.
///
/// The `passphrase` parameter accepts either the owner's passphrase or an
/// API token (`oc_key_...`). Raw hash signing is only supported on
/// secp256k1-backed chains.
pub fn sign_hash(
    wallet: &str,
    chain: &str,
    hash_hex: &str,
    passphrase: Option<&str>,
    index: Option<u32>,
    vault_path: Option<&Path>,
) -> Result<SignResult, OcWalletError> {
    let credential = passphrase.unwrap_or("");
    let chain = parse_chain(chain)?;
    let hash = decode_hash_hex(hash_hex)?;

    sign_hash_with_credential(wallet, &chain, &hash, &hash, credential, index, vault_path)
}

/// Sign an EIP-7702 authorization tuple.
///
/// This computes `keccak256(0x05 || rlp([eip155_chain_id(chain), address, nonce]))`
/// and signs the resulting digest via [`sign_hash`].
pub fn sign_authorization(
    wallet: &str,
    chain: &str,
    address: &str,
    nonce: &str,
    passphrase: Option<&str>,
    index: Option<u32>,
    vault_path: Option<&Path>,
) -> Result<SignResult, OcWalletError> {
    let credential = passphrase.unwrap_or("");
    let chain = parse_chain(chain)?;
    if chain.chain_type != ChainType::Evm {
        return Err(OcWalletError::InvalidInput(
            "EIP-7702 authorization signing is only supported for EVM chains".into(),
        ));
    }

    let authorization_chain_id = chain.chain_id.strip_prefix("eip155:").ok_or_else(|| {
        OcWalletError::InvalidInput(format!(
            "EVM chain '{}' is missing an eip155 reference",
            chain.chain_id
        ))
    })?;

    let evm_signer = oc_signer::chains::EvmSigner;
    let payload = evm_signer.authorization_payload(authorization_chain_id, address, nonce)?;
    let hash = evm_signer.authorization_hash(authorization_chain_id, address, nonce)?;

    sign_hash_with_credential(wallet, &chain, &payload, &hash, credential, index, vault_path)
}

/// Sign a message. Returns hex-encoded signature.
///
/// The `passphrase` parameter accepts either the owner's passphrase or an
/// API token (`oc_key_...`).
pub fn sign_message(
    wallet: &str,
    chain: &str,
    message: &str,
    passphrase: Option<&str>,
    encoding: Option<&str>,
    index: Option<u32>,
    vault_path: Option<&Path>,
) -> Result<SignResult, OcWalletError> {
    let credential = passphrase.unwrap_or("");

    let encoding = encoding.unwrap_or("utf8");
    let msg_bytes = match encoding {
        "utf8" => message.as_bytes().to_vec(),
        "hex" => hex::decode(message)
            .map_err(|e| OcWalletError::InvalidInput(format!("invalid hex message: {e}")))?,
        _ => {
            return Err(OcWalletError::InvalidInput(format!(
                "unsupported encoding: {encoding} (use 'utf8' or 'hex')"
            )));
        }
    };

    // Agent mode
    if credential.starts_with(crate::key_store::TOKEN_PREFIX) {
        let chain = parse_chain(chain)?;
        return crate::key_ops::sign_message_with_api_key(
            credential, wallet, &chain, &msg_bytes, index, vault_path,
        );
    }

    // Owner mode
    let chain = parse_chain(chain)?;
    let key =
        decrypt_signing_key(wallet, chain.chain_type, credential.as_bytes(), index, vault_path)?;
    let signer = signer_for_chain(chain.chain_type);
    let output = signer.sign_message(key.expose(), &msg_bytes)?;

    Ok(SignResult { signature: hex::encode(&output.signature), recovery_id: output.recovery_id })
}

/// Sign EIP-712 typed structured data. Returns hex-encoded signature.
/// Only supported for EVM chains.
///
/// Accepts either the owner's passphrase or an API token (`oc_key_...`).
/// When a token is provided, policy enforcement occurs before signing.
pub fn sign_typed_data(
    wallet: &str,
    chain: &str,
    typed_data_json: &str,
    passphrase: Option<&str>,
    index: Option<u32>,
    vault_path: Option<&Path>,
) -> Result<SignResult, OcWalletError> {
    let credential = passphrase.unwrap_or("");
    let chain = parse_chain(chain)?;

    if chain.chain_type != oc_core::ChainType::Evm {
        return Err(OcWalletError::InvalidInput(
            "EIP-712 typed data signing is only supported for EVM chains".into(),
        ));
    }

    if credential.starts_with(crate::key_store::TOKEN_PREFIX) {
        return crate::key_ops::sign_typed_data_with_api_key(
            credential,
            wallet,
            &chain,
            typed_data_json,
            index,
            vault_path,
        );
    }

    let key =
        decrypt_signing_key(wallet, chain.chain_type, credential.as_bytes(), index, vault_path)?;
    let evm_signer = oc_signer::chains::EvmSigner;
    let output = evm_signer.sign_typed_data(key.expose(), typed_data_json)?;

    Ok(SignResult { signature: hex::encode(&output.signature), recovery_id: output.recovery_id })
}

/// Decrypt a wallet and return the private key for the given chain.
///
/// This is the single code path for resolving a credential into key material.
/// Both the library's high-level signing functions and the CLI delegate here.
pub fn decrypt_signing_key(
    wallet_name_or_id: &str,
    chain_type: ChainType,
    passphrase: &[u8],
    index: Option<u32>,
    vault_path: Option<&Path>,
) -> Result<SecretBytes, OcWalletError> {
    let wallet = oc_vault::load_wallet_by_name_or_id(wallet_name_or_id, vault_path)?;
    let envelope: CryptoEnvelope = serde_json::from_value(wallet.crypto)?;
    let secret = decrypt(&envelope, passphrase)?;
    secret_to_signing_key(&secret, &wallet.key_type, chain_type, index)
}

// Re-export broadcast functions for backward compatibility.
#[cfg(feature = "rpc")]
pub use crate::broadcast::{sign_and_send, sign_encode_and_broadcast};

#[cfg(test)]
mod tests {
    use oc_core::OcError;

    use super::*;

    // ---- helpers ----

    /// Build a private-key wallet directly in the vault, bypassing
    /// `import_wallet_private_key` (which touches all chains including TON).
    fn save_privkey_wallet(
        name: &str,
        privkey_hex: &str,
        passphrase: &str,
        vault: &Path,
    ) -> WalletInfo {
        let key_bytes = hex::decode(privkey_hex).unwrap();

        // Generate a random ed25519 key for the other curve
        let mut ed_key = vec![0u8; 32];
        getrandom::fill(&mut ed_key).unwrap();

        let keys = KeyPair {
            secp256k1: SecretBytes::from_vec(key_bytes).unwrap(),
            ed25519: SecretBytes::from_vec(ed_key).unwrap(),
        };
        let accounts = derive_all_accounts_from_keys(&keys).unwrap();
        let payload = keys.to_json_bytes();
        let crypto_envelope = encrypt(&payload, passphrase.as_bytes()).unwrap();
        let crypto_json = serde_json::to_value(&crypto_envelope).unwrap();
        let wallet = EncryptedWallet::new(
            uuid::Uuid::new_v4().to_string(),
            name.to_string(),
            accounts,
            crypto_json,
            KeyType::PrivateKey,
        );
        oc_vault::save_encrypted_wallet(&wallet, Some(vault)).unwrap();
        wallet_to_info(&wallet)
    }

    const TEST_PRIVKEY: &str = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";

    fn save_allowed_chains_policy(vault: &Path, id: &str, chain_ids: Vec<String>) {
        let policy = oc_core::Policy {
            id: id.to_string(),
            name: format!("{id} policy"),
            version: 1,
            created_at: "2026-03-22T00:00:00Z".to_string(),
            rules: vec![oc_core::PolicyRule::AllowedChains { chain_ids }],
            executable: None,
            config: None,
            action: oc_core::PolicyAction::Deny,
        };

        crate::policy_store::save_policy(&policy, Some(vault)).unwrap();
    }

    // ================================================================
    // 1. MNEMONIC GENERATION
    // ================================================================

    #[test]
    fn mnemonic_12_words() {
        let phrase = generate_mnemonic(12).unwrap();
        assert_eq!(phrase.split_whitespace().count(), 12);
    }

    #[test]
    fn mnemonic_24_words() {
        let phrase = generate_mnemonic(24).unwrap();
        assert_eq!(phrase.split_whitespace().count(), 24);
    }

    #[test]
    fn mnemonic_invalid_word_count() {
        assert!(generate_mnemonic(0).is_err());
        assert!(generate_mnemonic(13).is_err());
        assert!(generate_mnemonic(16).is_err());
        assert!(generate_mnemonic(25).is_err());
    }

    #[test]
    fn mnemonic_is_unique_each_call() {
        let a = generate_mnemonic(12).unwrap();
        let b = generate_mnemonic(12).unwrap();
        assert_ne!(a, b, "two generated mnemonics should differ");
    }

    // ================================================================
    // 2. ADDRESS DERIVATION
    // ================================================================

    #[test]
    fn derive_address_all_chains() {
        let phrase = generate_mnemonic(12).unwrap();
        let chains =
            ["evm", "solana", "bitcoin", "cosmos", "tron", "ton", "sui", "xrpl", "nano", "near"];
        for chain in &chains {
            let addr = derive_address(&phrase, chain, None).unwrap();
            assert!(!addr.is_empty(), "address should be non-empty for {chain}");
        }
    }

    #[test]
    fn derive_address_evm_format() {
        let phrase = generate_mnemonic(12).unwrap();
        let addr = derive_address(&phrase, "evm", None).unwrap();
        assert!(addr.starts_with("0x"), "EVM address should start with 0x");
        assert_eq!(addr.len(), 42, "EVM address should be 42 chars");
    }

    #[test]
    fn derive_address_deterministic() {
        let phrase = generate_mnemonic(12).unwrap();
        let a = derive_address(&phrase, "evm", None).unwrap();
        let b = derive_address(&phrase, "evm", None).unwrap();
        assert_eq!(a, b, "same mnemonic should produce same address");
    }

    #[test]
    fn derive_address_different_index() {
        let phrase = generate_mnemonic(12).unwrap();
        let a = derive_address(&phrase, "evm", Some(0)).unwrap();
        let b = derive_address(&phrase, "evm", Some(1)).unwrap();
        assert_ne!(a, b, "different indices should produce different addresses");
    }

    #[test]
    fn derive_address_invalid_chain() {
        let phrase = generate_mnemonic(12).unwrap();
        assert!(derive_address(&phrase, "nonexistent", None).is_err());
    }

    #[test]
    fn derive_address_invalid_mnemonic() {
        assert!(derive_address("not a valid mnemonic phrase at all", "evm", None).is_err());
    }

    // ================================================================
    // 3. MNEMONIC WALLET LIFECYCLE (create → export → import → sign)
    // ================================================================

    #[test]
    fn mnemonic_wallet_create_export_reimport() {
        let v1 = tempfile::tempdir().unwrap();
        let v2 = tempfile::tempdir().unwrap();

        // Create
        let w1 = create_wallet("w1", None, None, Some(v1.path())).unwrap();
        assert!(!w1.accounts.is_empty());

        // Export mnemonic
        let phrase_bytes = export_wallet("w1", None, Some(v1.path())).unwrap();
        let phrase = std::str::from_utf8(phrase_bytes.expose()).unwrap();
        assert_eq!(phrase.split_whitespace().count(), 12);

        // Re-import into fresh vault
        let w2 = import_wallet_mnemonic("w2", phrase, None, None, Some(v2.path())).unwrap();

        // Addresses must match exactly
        assert_eq!(w1.accounts.len(), w2.accounts.len());
        for (a1, a2) in w1.accounts.iter().zip(w2.accounts.iter()) {
            assert_eq!(a1.chain_id, a2.chain_id);
            assert_eq!(a1.address, a2.address, "address mismatch for {}", a1.chain_id);
        }
    }

    #[test]
    fn mnemonic_wallet_sign_message_all_chains() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();
        create_wallet("multi-sign", None, None, Some(vault)).unwrap();

        // XRPL and Nano are excluded because their signers explicitly do not
        // support generic off-chain message signing without a defined convention.
        // NEAR's V1 sign_message is raw ed25519 (NEP-413 follow-up tracked).
        let chains = ["evm", "solana", "bitcoin", "cosmos", "tron", "ton", "spark", "sui", "near"];
        for chain in &chains {
            let result =
                sign_message("multi-sign", chain, "test msg", None, None, None, Some(vault));
            assert!(result.is_ok(), "sign_message should work for {chain}: {:?}", result.err());
            let sig = result.unwrap();
            assert!(!sig.signature.is_empty(), "signature should be non-empty for {chain}");
        }
    }

    #[test]
    fn mnemonic_wallet_sign_tx_all_chains() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();
        create_wallet("tx-sign", None, None, Some(vault)).unwrap();

        let generic_tx_hex = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        // Solana requires a properly formatted serialized transaction:
        // [0x01 num_sigs] [64 zero bytes for sig slot] [message bytes...]
        let mut solana_tx = vec![0x01u8]; // 1 signature slot
        solana_tx.extend_from_slice(&[0u8; 64]); // placeholder signature
        solana_tx.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // message payload
        let solana_tx_hex = hex::encode(&solana_tx);

        // NEAR transactions have no envelope; the borsh-encoded Transaction
        // bytes ARE the signable payload. Any non-empty bytes exercise the
        // sha256 -> ed25519 pipeline.
        let near_tx_hex = "42".repeat(80);

        // XRPL signing decodes the tx to inject SigningPubKey, so it needs a real
        // binary-encoded *unsigned* transaction (no SigningPubKey/TxnSignature).
        let xrpl_tx_hex = "12000024000000016140000000000F424068400000000000000C8114AFF3C2E33458B30714CA16FFEE19952DD35C17C883145720939C1336A7356A70ED861D5934345C6B6360";

        let chains =
            ["evm", "solana", "bitcoin", "cosmos", "tron", "ton", "spark", "sui", "xrpl", "near"];
        for chain in &chains {
            let tx = if *chain == "solana" {
                &solana_tx_hex
            } else if *chain == "near" {
                &near_tx_hex
            } else if *chain == "xrpl" {
                xrpl_tx_hex
            } else {
                generic_tx_hex
            };
            let result = sign_transaction("tx-sign", chain, tx, None, None, Some(vault));
            assert!(result.is_ok(), "sign_transaction should work for {chain}: {:?}", result.err());
        }
    }

    #[test]
    fn mnemonic_wallet_signing_is_deterministic() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();
        create_wallet("det-sign", None, None, Some(vault)).unwrap();

        let s1 = sign_message("det-sign", "evm", "hello", None, None, None, Some(vault)).unwrap();
        let s2 = sign_message("det-sign", "evm", "hello", None, None, None, Some(vault)).unwrap();
        assert_eq!(s1.signature, s2.signature, "same message should produce same signature");
    }

    #[test]
    fn mnemonic_wallet_different_messages_produce_different_sigs() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();
        create_wallet("diff-msg", None, None, Some(vault)).unwrap();

        let s1 = sign_message("diff-msg", "evm", "hello", None, None, None, Some(vault)).unwrap();
        let s2 = sign_message("diff-msg", "evm", "world", None, None, None, Some(vault)).unwrap();
        assert_ne!(s1.signature, s2.signature);
    }

    // ================================================================
    // 4. PRIVATE KEY WALLET LIFECYCLE
    // ================================================================

    #[test]
    fn privkey_wallet_sign_message() {
        let dir = tempfile::tempdir().unwrap();
        save_privkey_wallet("pk-sign", TEST_PRIVKEY, "", dir.path());

        let sig =
            sign_message("pk-sign", "evm", "hello", None, None, None, Some(dir.path())).unwrap();
        assert!(!sig.signature.is_empty());
        assert!(sig.recovery_id.is_some());
    }

    #[test]
    fn privkey_wallet_sign_transaction() {
        let dir = tempfile::tempdir().unwrap();
        save_privkey_wallet("pk-tx", TEST_PRIVKEY, "", dir.path());

        let tx = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        let sig = sign_transaction("pk-tx", "evm", tx, None, None, Some(dir.path())).unwrap();
        assert!(!sig.signature.is_empty());
    }

    #[test]
    fn privkey_wallet_export_returns_json() {
        let dir = tempfile::tempdir().unwrap();
        save_privkey_wallet("pk-export", TEST_PRIVKEY, "", dir.path());

        let exported = export_wallet("pk-export", None, Some(dir.path())).unwrap();
        let exported_str = std::str::from_utf8(exported.expose()).unwrap();
        let obj: serde_json::Value = serde_json::from_str(exported_str).unwrap();
        assert_eq!(
            obj["secp256k1"].as_str().unwrap(),
            TEST_PRIVKEY,
            "exported secp256k1 key should match original"
        );
        assert!(obj["ed25519"].as_str().is_some(), "should have ed25519 key");
    }

    #[test]
    fn privkey_wallet_signing_is_deterministic() {
        let dir = tempfile::tempdir().unwrap();
        save_privkey_wallet("pk-det", TEST_PRIVKEY, "", dir.path());

        let s1 = sign_message("pk-det", "evm", "test", None, None, None, Some(dir.path())).unwrap();
        let s2 = sign_message("pk-det", "evm", "test", None, None, None, Some(dir.path())).unwrap();
        assert_eq!(s1.signature, s2.signature);
    }

    #[test]
    fn privkey_and_mnemonic_wallets_produce_different_sigs() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();

        create_wallet("mn-w", None, None, Some(vault)).unwrap();
        save_privkey_wallet("pk-w", TEST_PRIVKEY, "", vault);

        let mn_sig = sign_message("mn-w", "evm", "hello", None, None, None, Some(vault)).unwrap();
        let pk_sig = sign_message("pk-w", "evm", "hello", None, None, None, Some(vault)).unwrap();
        assert_ne!(
            mn_sig.signature, pk_sig.signature,
            "different keys should produce different signatures"
        );
    }

    #[test]
    fn privkey_wallet_import_via_api() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();

        let info = import_wallet_private_key(
            "pk-api",
            TEST_PRIVKEY,
            Some("evm"),
            None,
            Some(vault),
            None,
            None,
        )
        .unwrap();
        assert!(!info.accounts.is_empty(), "should derive at least one account");

        // Should be able to sign
        let sig = sign_message("pk-api", "evm", "hello", None, None, None, Some(vault)).unwrap();
        assert!(!sig.signature.is_empty());

        // Export should return JSON key pair with original key
        let exported = export_wallet("pk-api", None, Some(vault)).unwrap();
        let exported_str = std::str::from_utf8(exported.expose()).unwrap();
        let obj: serde_json::Value = serde_json::from_str(exported_str).unwrap();
        assert_eq!(obj["secp256k1"].as_str().unwrap(), TEST_PRIVKEY);
    }

    #[test]
    fn privkey_wallet_import_both_curve_keys() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();

        let secp_key = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
        let ed_key = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

        let info = import_wallet_private_key(
            "pk-both",
            "",   // ignored when both curve keys provided
            None, // chain ignored too
            None,
            Some(vault),
            Some(secp_key),
            Some(ed_key),
        )
        .unwrap();

        assert_eq!(
            info.accounts.len(),
            ALL_CHAIN_TYPES.len(),
            "should have one account per chain type"
        );

        // Sign on EVM (secp256k1)
        let sig = sign_message("pk-both", "evm", "hello", None, None, None, Some(vault)).unwrap();
        assert!(!sig.signature.is_empty());

        // Sign on Solana (ed25519)
        let sig =
            sign_message("pk-both", "solana", "hello", None, None, None, Some(vault)).unwrap();
        assert!(!sig.signature.is_empty());

        // Export should return both keys
        let exported = export_wallet("pk-both", None, Some(vault)).unwrap();
        let exported_str = std::str::from_utf8(exported.expose()).unwrap();
        let obj: serde_json::Value = serde_json::from_str(exported_str).unwrap();
        assert_eq!(obj["secp256k1"].as_str().unwrap(), secp_key);
        assert_eq!(obj["ed25519"].as_str().unwrap(), ed_key);
    }

    // ================================================================
    // 5. PASSPHRASE PROTECTION
    // ================================================================

    #[test]
    fn passphrase_protected_mnemonic_wallet() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();

        create_wallet("pass-mn", None, Some("s3cret"), Some(vault)).unwrap();

        // Sign with correct passphrase
        let sig = sign_message("pass-mn", "evm", "hello", Some("s3cret"), None, None, Some(vault))
            .unwrap();
        assert!(!sig.signature.is_empty());

        // Export with correct passphrase
        let phrase_bytes = export_wallet("pass-mn", Some("s3cret"), Some(vault)).unwrap();
        let phrase = std::str::from_utf8(phrase_bytes.expose()).unwrap();
        assert_eq!(phrase.split_whitespace().count(), 12);

        // Wrong passphrase should fail
        assert!(
            sign_message("pass-mn", "evm", "hello", Some("wrong"), None, None, Some(vault))
                .is_err()
        );
        assert!(export_wallet("pass-mn", Some("wrong"), Some(vault)).is_err());

        // No passphrase should fail (defaults to empty string, which is wrong)
        assert!(sign_message("pass-mn", "evm", "hello", None, None, None, Some(vault)).is_err());
    }

    #[test]
    fn passphrase_protected_privkey_wallet() {
        let dir = tempfile::tempdir().unwrap();
        save_privkey_wallet("pass-pk", TEST_PRIVKEY, "mypass", dir.path());

        // Correct passphrase
        let sig =
            sign_message("pass-pk", "evm", "hello", Some("mypass"), None, None, Some(dir.path()))
                .unwrap();
        assert!(!sig.signature.is_empty());

        let exported = export_wallet("pass-pk", Some("mypass"), Some(dir.path())).unwrap();
        let exported_str = std::str::from_utf8(exported.expose()).unwrap();
        let obj: serde_json::Value = serde_json::from_str(exported_str).unwrap();
        assert_eq!(obj["secp256k1"].as_str().unwrap(), TEST_PRIVKEY);

        // Wrong passphrase
        assert!(
            sign_message("pass-pk", "evm", "hello", Some("wrong"), None, None, Some(dir.path()))
                .is_err()
        );
        assert!(export_wallet("pass-pk", Some("wrong"), Some(dir.path())).is_err());
    }

    // ================================================================
    // 6. SIGNATURE VERIFICATION (prove signatures are cryptographically valid)
    // ================================================================

    #[test]
    fn evm_signature_is_recoverable() {
        use sha3::Digest;
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();

        let info = create_wallet("verify-evm", None, None, Some(vault)).unwrap();
        let evm_addr = info
            .accounts
            .iter()
            .find(|a| a.chain_id.starts_with("eip155:"))
            .unwrap()
            .address
            .clone();

        let sig = sign_message("verify-evm", "evm", "hello world", None, None, None, Some(vault))
            .unwrap();

        // EVM personal_sign: keccak256("\x19Ethereum Signed Message:\n" + len + msg)
        let msg = b"hello world";
        let prefix = format!("\x19Ethereum Signed Message:\n{}", msg.len());
        let mut prefixed = prefix.into_bytes();
        prefixed.extend_from_slice(msg);

        let hash = sha3::Keccak256::digest(&prefixed);
        let sig_bytes = hex::decode(&sig.signature).unwrap();
        assert_eq!(sig_bytes.len(), 65, "EVM signature should be 65 bytes (r + s + v)");

        // Recover public key from signature (v is 27 or 28 per EIP-191)
        let v = sig_bytes[64];
        assert!(v == 27 || v == 28, "EIP-191 v byte should be 27 or 28, got {v}");
        let recid = k256::ecdsa::RecoveryId::try_from(v - 27).unwrap();
        let ecdsa_sig = k256::ecdsa::Signature::from_slice(&sig_bytes[..64]).unwrap();
        let recovered_key =
            k256::ecdsa::VerifyingKey::recover_from_prehash(&hash, &ecdsa_sig, recid).unwrap();

        // Derive address from recovered key and compare
        let pubkey_bytes = recovered_key.to_sec1_point(false);
        let pubkey_hash = sha3::Keccak256::digest(&pubkey_bytes.as_bytes()[1..]);
        let recovered_addr = format!("0x{}", hex::encode(&pubkey_hash[12..]));

        // Compare case-insensitively (EIP-55 checksum)
        assert_eq!(
            recovered_addr.to_lowercase(),
            evm_addr.to_lowercase(),
            "recovered address should match wallet's EVM address"
        );
    }

    // ================================================================
    // 7. ERROR HANDLING
    // ================================================================

    #[test]
    fn error_nonexistent_wallet() {
        let dir = tempfile::tempdir().unwrap();
        assert!(get_wallet("nope", Some(dir.path())).is_err());
        assert!(export_wallet("nope", None, Some(dir.path())).is_err());
        assert!(sign_message("nope", "evm", "x", None, None, None, Some(dir.path())).is_err());
        assert!(delete_wallet("nope", Some(dir.path())).is_err());
    }

    #[test]
    fn error_duplicate_wallet_name() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();
        create_wallet("dup", None, None, Some(vault)).unwrap();
        assert!(create_wallet("dup", None, None, Some(vault)).is_err());
    }

    #[test]
    fn error_invalid_private_key_hex() {
        let dir = tempfile::tempdir().unwrap();
        assert!(
            import_wallet_private_key(
                "bad",
                "not-hex",
                Some("evm"),
                None,
                Some(dir.path()),
                None,
                None,
            )
            .is_err()
        );
    }

    #[test]
    fn error_invalid_chain_for_signing() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();
        create_wallet("chain-err", None, None, Some(vault)).unwrap();
        assert!(
            sign_message("chain-err", "fakecoin", "hi", None, None, None, Some(vault)).is_err()
        );
    }

    #[test]
    fn error_invalid_tx_hex() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();
        create_wallet("hex-err", None, None, Some(vault)).unwrap();
        assert!(
            sign_transaction("hex-err", "evm", "not-valid-hex!", None, None, Some(vault)).is_err()
        );
    }

    // ================================================================
    // 8. WALLET MANAGEMENT
    // ================================================================

    #[test]
    fn list_wallets_empty_vault() {
        let dir = tempfile::tempdir().unwrap();
        let wallets = list_wallets(Some(dir.path())).unwrap();
        assert!(wallets.is_empty());
    }

    #[test]
    fn get_wallet_by_name_and_id() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();
        let info = create_wallet("lookup", None, None, Some(vault)).unwrap();

        let by_name = get_wallet("lookup", Some(vault)).unwrap();
        assert_eq!(by_name.id, info.id);

        let by_id = get_wallet(&info.id, Some(vault)).unwrap();
        assert_eq!(by_id.name, "lookup");
    }

    #[test]
    fn rename_wallet_works() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();
        let info = create_wallet("before", None, None, Some(vault)).unwrap();

        rename_wallet("before", "after", Some(vault)).unwrap();

        assert!(get_wallet("before", Some(vault)).is_err());
        let after = get_wallet("after", Some(vault)).unwrap();
        assert_eq!(after.id, info.id);
    }

    #[test]
    fn rename_to_existing_name_fails() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();
        create_wallet("a", None, None, Some(vault)).unwrap();
        create_wallet("b", None, None, Some(vault)).unwrap();
        assert!(rename_wallet("a", "b", Some(vault)).is_err());
    }

    #[test]
    fn delete_wallet_removes_from_list() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();
        create_wallet("del-me", None, None, Some(vault)).unwrap();
        assert_eq!(list_wallets(Some(vault)).unwrap().len(), 1);

        delete_wallet("del-me", Some(vault)).unwrap();
        assert_eq!(list_wallets(Some(vault)).unwrap().len(), 0);
    }

    // ================================================================
    // 9. MESSAGE ENCODING
    // ================================================================

    #[test]
    fn sign_message_hex_encoding() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();
        create_wallet("hex-enc", None, None, Some(vault)).unwrap();

        // "hello" in hex
        let sig =
            sign_message("hex-enc", "evm", "68656c6c6f", None, Some("hex"), None, Some(vault))
                .unwrap();
        assert!(!sig.signature.is_empty());

        // Should match utf8 encoding of the same bytes
        let sig2 =
            sign_message("hex-enc", "evm", "hello", None, Some("utf8"), None, Some(vault)).unwrap();
        assert_eq!(
            sig.signature, sig2.signature,
            "hex and utf8 encoding of same bytes should produce same signature"
        );
    }

    #[test]
    fn sign_message_invalid_encoding() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();
        create_wallet("bad-enc", None, None, Some(vault)).unwrap();
        assert!(
            sign_message("bad-enc", "evm", "hello", None, Some("base64"), None, Some(vault))
                .is_err()
        );
    }

    // ================================================================
    // 10. MULTI-WALLET VAULT
    // ================================================================

    #[test]
    fn multiple_wallets_coexist() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();

        create_wallet("w1", None, None, Some(vault)).unwrap();
        create_wallet("w2", None, None, Some(vault)).unwrap();
        save_privkey_wallet("w3", TEST_PRIVKEY, "", vault);

        let wallets = list_wallets(Some(vault)).unwrap();
        assert_eq!(wallets.len(), 3);

        // All can sign independently
        let s1 = sign_message("w1", "evm", "test", None, None, None, Some(vault)).unwrap();
        let s2 = sign_message("w2", "evm", "test", None, None, None, Some(vault)).unwrap();
        let s3 = sign_message("w3", "evm", "test", None, None, None, Some(vault)).unwrap();

        // All signatures should be different (different keys)
        assert_ne!(s1.signature, s2.signature);
        assert_ne!(s1.signature, s3.signature);
        assert_ne!(s2.signature, s3.signature);

        // Delete one, others survive
        delete_wallet("w2", Some(vault)).unwrap();
        assert_eq!(list_wallets(Some(vault)).unwrap().len(), 2);
        assert!(sign_message("w1", "evm", "test", None, None, None, Some(vault)).is_ok());
        assert!(sign_message("w3", "evm", "test", None, None, None, Some(vault)).is_ok());
    }

    // ================================================================
    // 11. BUG REGRESSION: CLI send_transaction broadcasts raw signature
    // ================================================================

    #[test]
    fn signed_tx_must_differ_from_raw_signature() {
        // BUG TEST: The CLI's send_transaction.rs broadcasts `output.signature`
        // (raw 65-byte sig) instead of encoding the full signed transaction via
        // signer.encode_signed_transaction(). This test proves the two are different
        // — broadcasting the raw signature sends garbage to the RPC node.
        //
        // The library's sign_and_send correctly calls encode_signed_transaction
        // before broadcast (ops.rs:481), but the CLI skips this step
        // (send_transaction.rs:43).

        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();
        save_privkey_wallet("send-bug", TEST_PRIVKEY, "", vault);

        // Build a minimal unsigned EIP-1559 transaction
        let items: Vec<u8> = [
            oc_signer::rlp::encode_bytes(&[1]),          // chain_id = 1
            oc_signer::rlp::encode_bytes(&[]),           // nonce = 0
            oc_signer::rlp::encode_bytes(&[1]),          // maxPriorityFeePerGas
            oc_signer::rlp::encode_bytes(&[100]),        // maxFeePerGas
            oc_signer::rlp::encode_bytes(&[0x52, 0x08]), // gasLimit = 21000
            oc_signer::rlp::encode_bytes(&[0xDE, 0xAD]), // to (truncated)
            oc_signer::rlp::encode_bytes(&[]),           // value = 0
            oc_signer::rlp::encode_bytes(&[]),           // data
            oc_signer::rlp::encode_list(&[]),            // accessList
        ]
        .concat();

        let mut unsigned_tx = vec![0x02u8];
        unsigned_tx.extend_from_slice(&oc_signer::rlp::encode_list(&items));
        let tx_hex = hex::encode(&unsigned_tx);

        // Sign the transaction via the library
        let sign_result =
            sign_transaction("send-bug", "evm", &tx_hex, None, None, Some(vault)).unwrap();
        let raw_signature = hex::decode(&sign_result.signature).unwrap();

        // Now encode the full signed transaction (what the library does correctly)
        let key = decrypt_signing_key("send-bug", ChainType::Evm, b"", None, Some(vault)).unwrap();
        let signer = signer_for_chain(ChainType::Evm);
        let output = signer.sign_transaction(key.expose(), &unsigned_tx).unwrap();
        let full_signed_tx = signer.encode_signed_transaction(&unsigned_tx, &output).unwrap();

        // The raw signature (65 bytes) and the full signed tx are completely different.
        // Broadcasting the raw signature (as the CLI does) would always fail.
        assert_eq!(raw_signature.len(), 65, "raw EVM signature should be 65 bytes (r || s || v)");
        assert!(
            full_signed_tx.len() > raw_signature.len(),
            "full signed tx ({} bytes) must be larger than raw signature ({} bytes)",
            full_signed_tx.len(),
            raw_signature.len()
        );
        assert_ne!(
            raw_signature, full_signed_tx,
            "raw signature and full signed transaction must differ — \
             broadcasting the raw signature (as CLI send_transaction.rs:43 does) is wrong"
        );

        // The full signed tx should start with the EIP-1559 type byte
        assert_eq!(
            full_signed_tx[0], 0x02,
            "full signed EIP-1559 tx must start with type byte 0x02"
        );
    }

    // ================================================================
    // CHARACTERIZATION TESTS: lock down current signing behavior before refactoring
    // ================================================================

    #[test]
    fn char_create_wallet_sign_transaction_with_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();
        create_wallet("char-pass-tx", None, Some("secret"), Some(vault)).unwrap();

        let tx = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        let sig =
            sign_transaction("char-pass-tx", "evm", tx, Some("secret"), None, Some(vault)).unwrap();
        assert!(!sig.signature.is_empty());
        assert!(sig.recovery_id.is_some());
    }

    #[test]
    fn char_create_wallet_sign_transaction_empty_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();
        create_wallet("char-empty-tx", None, None, Some(vault)).unwrap();

        let tx = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        let sig =
            sign_transaction("char-empty-tx", "evm", tx, Some(""), None, Some(vault)).unwrap();
        assert!(!sig.signature.is_empty());
    }

    #[test]
    fn char_no_passphrase_none_none_sign_transaction() {
        // Most common real-world flow: create wallet with no passphrase (None),
        // sign with no passphrase (None). Both default to "".
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();
        create_wallet("char-none-none", None, None, Some(vault)).unwrap();

        let tx = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        let sig = sign_transaction("char-none-none", "evm", tx, None, None, Some(vault)).unwrap();
        assert!(!sig.signature.is_empty());
        assert!(sig.recovery_id.is_some());
    }

    #[test]
    fn char_no_passphrase_none_none_sign_message() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();
        create_wallet("char-none-msg", None, None, Some(vault)).unwrap();

        let sig =
            sign_message("char-none-msg", "evm", "hello", None, None, None, Some(vault)).unwrap();
        assert!(!sig.signature.is_empty());
    }

    #[test]
    fn char_no_passphrase_none_none_export() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();
        create_wallet("char-none-exp", None, None, Some(vault)).unwrap();

        let phrase_bytes = export_wallet("char-none-exp", None, Some(vault)).unwrap();
        let phrase = std::str::from_utf8(phrase_bytes.expose()).unwrap();
        assert_eq!(phrase.split_whitespace().count(), 12);
    }

    #[test]
    fn char_empty_passphrase_none_and_some_empty_are_equivalent() {
        // Verify that None and Some("") produce identical behavior for both
        // create and sign — they must be interchangeable.
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();

        // Create with None (defaults to "")
        create_wallet("char-equiv", None, None, Some(vault)).unwrap();

        let tx = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

        // All four combinations of None/Some("") must produce the same signature
        let sig_none = sign_transaction("char-equiv", "evm", tx, None, None, Some(vault)).unwrap();
        let sig_empty =
            sign_transaction("char-equiv", "evm", tx, Some(""), None, Some(vault)).unwrap();

        assert_eq!(
            sig_none.signature, sig_empty.signature,
            "passphrase=None and passphrase=Some(\"\") must produce identical signatures"
        );

        // Same for sign_message
        let msg_none =
            sign_message("char-equiv", "evm", "test", None, None, None, Some(vault)).unwrap();
        let msg_empty =
            sign_message("char-equiv", "evm", "test", Some(""), None, None, Some(vault)).unwrap();

        assert_eq!(
            msg_none.signature, msg_empty.signature,
            "sign_message: None and Some(\"\") must be equivalent"
        );

        // Export with both
        let export_none = export_wallet("char-equiv", None, Some(vault)).unwrap();
        let export_empty = export_wallet("char-equiv", Some(""), Some(vault)).unwrap();
        assert_eq!(
            export_none.expose(),
            export_empty.expose(),
            "export_wallet: None and Some(\"\") must return the same mnemonic"
        );
    }

    #[test]
    fn char_create_with_some_empty_sign_with_none() {
        // Create with explicit Some(""), sign with None — should work
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();
        create_wallet("char-some-none", None, Some(""), Some(vault)).unwrap();

        let tx = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        let sig = sign_transaction("char-some-none", "evm", tx, None, None, Some(vault)).unwrap();
        assert!(!sig.signature.is_empty());
    }

    #[test]
    fn char_no_passphrase_wallet_rejects_nonempty_passphrase() {
        // A wallet created without passphrase must NOT be decryptable with a
        // random passphrase — this verifies the empty string is actually used
        // as the encryption key, not bypassed.
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();
        create_wallet("char-no-pass-reject", None, None, Some(vault)).unwrap();

        let result = sign_message(
            "char-no-pass-reject",
            "evm",
            "test",
            Some("some-random-passphrase"),
            None,
            None,
            Some(vault),
        );
        assert!(result.is_err(), "non-empty passphrase on empty-passphrase wallet should fail");
        match result.unwrap_err() {
            OcWalletError::Crypto(_) => {} // Expected: decryption failure
            other => panic!("expected Crypto error, got: {other}"),
        }
    }

    #[test]
    fn char_sign_transaction_wrong_passphrase_returns_crypto_error() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();
        create_wallet("char-wrong-pass", None, Some("correct"), Some(vault)).unwrap();

        let tx = "deadbeef";
        let result =
            sign_transaction("char-wrong-pass", "evm", tx, Some("wrong"), None, Some(vault));
        assert!(result.is_err());
        match result.unwrap_err() {
            OcWalletError::Crypto(_) => {} // Expected
            other => panic!("expected Crypto error, got: {other}"),
        }
    }

    #[test]
    fn char_sign_transaction_nonexistent_wallet_returns_wallet_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let result = sign_transaction("ghost", "evm", "deadbeef", None, None, Some(dir.path()));
        assert!(result.is_err());
        match result.unwrap_err() {
            OcWalletError::WalletNotFound(name) => assert_eq!(name, "ghost"),
            other => panic!("expected WalletNotFound, got: {other}"),
        }
    }

    #[test]
    #[cfg(feature = "rpc")]
    fn char_sign_and_send_invalid_rpc_returns_broadcast_failed() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();
        create_wallet("char-rpc-fail", None, None, Some(vault)).unwrap();

        // Build a minimal unsigned EIP-1559 transaction
        let items: Vec<u8> = [
            oc_signer::rlp::encode_bytes(&[1]),          // chain_id = 1
            oc_signer::rlp::encode_bytes(&[]),           // nonce = 0
            oc_signer::rlp::encode_bytes(&[1]),          // maxPriorityFeePerGas
            oc_signer::rlp::encode_bytes(&[100]),        // maxFeePerGas
            oc_signer::rlp::encode_bytes(&[0x52, 0x08]), // gasLimit = 21000
            oc_signer::rlp::encode_bytes(&[0xDE, 0xAD]), // to (truncated)
            oc_signer::rlp::encode_bytes(&[]),           // value = 0
            oc_signer::rlp::encode_bytes(&[]),           // data
            oc_signer::rlp::encode_list(&[]),            // accessList
        ]
        .concat();
        let mut unsigned_tx = vec![0x02u8];
        unsigned_tx.extend_from_slice(&oc_signer::rlp::encode_list(&items));
        let tx_hex = hex::encode(&unsigned_tx);

        let result = sign_and_send(
            "char-rpc-fail",
            "evm",
            &tx_hex,
            None,
            None,
            Some("http://127.0.0.1:1"), // unreachable RPC
            Some(vault),
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            OcWalletError::BroadcastFailed(_) => {} // Expected
            other => panic!("expected BroadcastFailed, got: {other}"),
        }
    }

    #[test]
    fn char_create_sign_rename_sign_with_new_name() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();
        create_wallet("orig-name", None, None, Some(vault)).unwrap();

        // Sign with original name
        let sig1 = sign_message("orig-name", "evm", "test", None, None, None, Some(vault)).unwrap();
        assert!(!sig1.signature.is_empty());

        // Rename
        rename_wallet("orig-name", "new-name", Some(vault)).unwrap();

        // Old name no longer works
        assert!(sign_message("orig-name", "evm", "test", None, None, None, Some(vault)).is_err());

        // Sign with new name — should produce same signature (same key)
        let sig2 = sign_message("new-name", "evm", "test", None, None, None, Some(vault)).unwrap();
        assert_eq!(
            sig1.signature, sig2.signature,
            "renamed wallet should produce identical signatures"
        );
    }

    #[test]
    fn char_create_sign_delete_sign_returns_wallet_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();
        create_wallet("del-me-char", None, None, Some(vault)).unwrap();

        // Sign succeeds
        let sig =
            sign_message("del-me-char", "evm", "test", None, None, None, Some(vault)).unwrap();
        assert!(!sig.signature.is_empty());

        // Delete
        delete_wallet("del-me-char", Some(vault)).unwrap();

        // Sign after delete fails with WalletNotFound
        let result = sign_message("del-me-char", "evm", "test", None, None, None, Some(vault));
        assert!(result.is_err());
        match result.unwrap_err() {
            OcWalletError::WalletNotFound(name) => assert_eq!(name, "del-me-char"),
            other => panic!("expected WalletNotFound, got: {other}"),
        }
    }

    #[test]
    fn char_import_sign_export_reimport_sign_deterministic() {
        let v1 = tempfile::tempdir().unwrap();
        let v2 = tempfile::tempdir().unwrap();

        // Import with known mnemonic
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        import_wallet_mnemonic("char-det", phrase, None, None, Some(v1.path())).unwrap();

        // Sign in vault 1
        let sig1 =
            sign_message("char-det", "evm", "determinism test", None, None, None, Some(v1.path()))
                .unwrap();

        // Export
        let exported = export_wallet("char-det", None, Some(v1.path())).unwrap();
        let exported_str = std::str::from_utf8(exported.expose()).unwrap();
        assert_eq!(exported_str.trim(), phrase);

        // Re-import into vault 2
        import_wallet_mnemonic("char-det-2", exported_str, None, None, Some(v2.path())).unwrap();

        // Sign in vault 2 — must produce identical signature
        let sig2 = sign_message(
            "char-det-2",
            "evm",
            "determinism test",
            None,
            None,
            None,
            Some(v2.path()),
        )
        .unwrap();

        assert_eq!(
            sig1.signature, sig2.signature,
            "import→sign→export→reimport→sign must produce identical signatures"
        );
    }

    #[test]
    fn char_import_private_key_sign_valid() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();

        import_wallet_private_key(
            "char-pk",
            TEST_PRIVKEY,
            Some("evm"),
            None,
            Some(vault),
            None,
            None,
        )
        .unwrap();

        let sig = sign_transaction("char-pk", "evm", "deadbeef", None, None, Some(vault)).unwrap();
        assert!(!sig.signature.is_empty());
        assert!(sig.recovery_id.is_some());
    }

    #[test]
    fn char_sign_message_all_chain_families() {
        // Verify sign_message works for every chain family (EVM, Solana, Bitcoin, Cosmos, Tron,
        // TON, Sui)
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();
        create_wallet("char-all-chains", None, None, Some(vault)).unwrap();

        let chains = [
            ("evm", true),
            ("solana", false),
            ("bitcoin", true),
            ("cosmos", true),
            ("tron", true),
            ("ton", false),
            ("sui", false),
        ];
        for (chain, has_recovery_id) in &chains {
            let result =
                sign_message("char-all-chains", chain, "hello", None, None, None, Some(vault));
            assert!(result.is_ok(), "sign_message failed for {chain}: {:?}", result.err());
            let sig = result.unwrap();
            assert!(!sig.signature.is_empty(), "signature empty for {chain}");
            if *has_recovery_id {
                assert!(sig.recovery_id.is_some(), "expected recovery_id for {chain}");
            }
        }
    }

    #[test]
    fn char_sign_typed_data_evm_valid_signature() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();
        create_wallet("char-typed", None, None, Some(vault)).unwrap();

        let typed_data = r#"{
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"}
                ],
                "Test": [{"name": "value", "type": "uint256"}]
            },
            "primaryType": "Test",
            "domain": {"name": "TestDapp", "version": "1", "chainId": "1"},
            "message": {"value": "42"}
        }"#;

        let result = sign_typed_data("char-typed", "evm", typed_data, None, None, Some(vault));
        assert!(result.is_ok(), "sign_typed_data failed: {:?}", result.err());

        let sig = result.unwrap();
        let sig_bytes = hex::decode(&sig.signature).unwrap();
        assert_eq!(sig_bytes.len(), 65, "EIP-712 signature should be 65 bytes");

        // v should be 27 or 28 per EIP-712 convention
        let v = sig_bytes[64];
        assert!(v == 27 || v == 28, "EIP-712 v should be 27 or 28, got {v}");
    }

    // ================================================================
    // CHARACTERIZATION TESTS (wave 2): refactoring-path edge cases
    // ================================================================

    #[test]
    fn char_sign_with_nonzero_account_index() {
        // The `index` parameter flows through decrypt_signing_key → HD derivation.
        // Verify that index=0 and index=1 produce different signatures via the public API.
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();
        create_wallet("char-idx", None, None, Some(vault)).unwrap();

        let tx = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

        let sig0 = sign_transaction("char-idx", "evm", tx, None, Some(0), Some(vault)).unwrap();
        let sig1 = sign_transaction("char-idx", "evm", tx, None, Some(1), Some(vault)).unwrap();

        assert_ne!(
            sig0.signature, sig1.signature,
            "index 0 and index 1 must produce different signatures (different derived keys)"
        );

        // Index 0 should match the default (None)
        let sig_default = sign_transaction("char-idx", "evm", tx, None, None, Some(vault)).unwrap();
        assert_eq!(
            sig0.signature, sig_default.signature,
            "index=0 should match index=None (default)"
        );
    }

    #[test]
    fn char_sign_with_nonzero_index_sign_message() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();
        create_wallet("char-idx-msg", None, None, Some(vault)).unwrap();

        let sig0 =
            sign_message("char-idx-msg", "evm", "hello", None, None, Some(0), Some(vault)).unwrap();
        let sig1 =
            sign_message("char-idx-msg", "evm", "hello", None, None, Some(1), Some(vault)).unwrap();

        assert_ne!(
            sig0.signature, sig1.signature,
            "different account indices should yield different signatures"
        );
    }

    #[test]
    fn char_sign_transaction_0x_prefix_stripped() {
        // sign_transaction strips "0x" prefix from tx_hex. Verify both forms produce
        // the same signature.
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();
        create_wallet("char-0x", None, None, Some(vault)).unwrap();

        let tx_no_prefix = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        let tx_with_prefix = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

        let sig1 =
            sign_transaction("char-0x", "evm", tx_no_prefix, None, None, Some(vault)).unwrap();
        let sig2 =
            sign_transaction("char-0x", "evm", tx_with_prefix, None, None, Some(vault)).unwrap();

        assert_eq!(
            sig1.signature, sig2.signature,
            "0x-prefixed and bare hex should produce identical signatures"
        );
    }

    #[test]
    fn char_24_word_mnemonic_wallet_lifecycle() {
        // Verify 24-word mnemonics work identically to 12-word through the full lifecycle.
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();

        let info = create_wallet("char-24w", Some(24), None, Some(vault)).unwrap();
        assert!(!info.accounts.is_empty());

        // Export → verify 24 words
        let phrase_bytes = export_wallet("char-24w", None, Some(vault)).unwrap();
        let phrase = std::str::from_utf8(phrase_bytes.expose()).unwrap();
        assert_eq!(phrase.split_whitespace().count(), 24, "should be a 24-word mnemonic");

        // Sign transaction
        let tx = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        let sig = sign_transaction("char-24w", "evm", tx, None, None, Some(vault)).unwrap();
        assert!(!sig.signature.is_empty());

        // Sign message on multiple chains
        for chain in &["evm", "solana", "bitcoin", "cosmos"] {
            let result = sign_message("char-24w", chain, "test", None, None, None, Some(vault));
            assert!(
                result.is_ok(),
                "24-word wallet sign_message failed for {chain}: {:?}",
                result.err()
            );
        }

        // Re-import into separate vault → deterministic
        let v2 = tempfile::tempdir().unwrap();
        import_wallet_mnemonic("char-24w-2", phrase, None, None, Some(v2.path())).unwrap();
        let sig2 = sign_transaction("char-24w-2", "evm", tx, None, None, Some(v2.path())).unwrap();
        assert_eq!(
            sig.signature, sig2.signature,
            "reimported 24-word wallet must produce identical signature"
        );
    }

    #[test]
    fn char_concurrent_signing() {
        // Multiple threads signing with the same wallet must all succeed.
        // Relevant because agent signing will involve concurrent callers.
        use std::{sync::Arc, thread};

        let dir = tempfile::tempdir().unwrap();
        let vault_path = Arc::new(dir.path().to_path_buf());
        create_wallet("char-conc", None, None, Some(&vault_path)).unwrap();

        let handles: Vec<_> = (0..8)
            .map(|i| {
                let vp = Arc::clone(&vault_path);
                thread::spawn(move || {
                    let msg = format!("thread-{i}");
                    let result = sign_message(
                        "char-conc",
                        "evm",
                        &msg,
                        None,
                        None,
                        None,
                        Some(vp.as_path()),
                    );
                    assert!(
                        result.is_ok(),
                        "concurrent sign_message failed in thread {i}: {:?}",
                        result.err()
                    );
                    result.unwrap()
                })
            })
            .collect();

        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        // All signatures should be non-empty
        for (i, sig) in results.iter().enumerate() {
            assert!(!sig.signature.is_empty(), "thread {i} produced empty signature");
        }

        // Different messages → different signatures
        for i in 0..results.len() {
            for j in (i + 1)..results.len() {
                assert_ne!(
                    results[i].signature, results[j].signature,
                    "threads {i} and {j} should produce different signatures (different messages)"
                );
            }
        }
    }

    #[test]
    fn char_evm_sign_transaction_recoverable() {
        // Verify that EVM transaction signatures are ecrecover-compatible:
        // recover the public key from the signature and compare to the wallet's address.
        use sha3::Digest;

        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();
        let info = create_wallet("char-tx-recover", None, None, Some(vault)).unwrap();
        let evm_addr = info
            .accounts
            .iter()
            .find(|a| a.chain_id.starts_with("eip155:"))
            .unwrap()
            .address
            .clone();

        let tx_hex = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        let sig =
            sign_transaction("char-tx-recover", "evm", tx_hex, None, None, Some(vault)).unwrap();

        let sig_bytes = hex::decode(&sig.signature).unwrap();
        assert_eq!(sig_bytes.len(), 65);

        // EVM sign_transaction: keccak256(tx_bytes) then ecdsaSign
        let tx_bytes = hex::decode(tx_hex).unwrap();
        let hash = sha3::Keccak256::digest(&tx_bytes);

        let v = sig_bytes[64];
        let recid = k256::ecdsa::RecoveryId::try_from(v).unwrap();
        let ecdsa_sig = k256::ecdsa::Signature::from_slice(&sig_bytes[..64]).unwrap();
        let recovered_key =
            k256::ecdsa::VerifyingKey::recover_from_prehash(&hash, &ecdsa_sig, recid).unwrap();

        // Derive address from recovered key
        let pubkey_bytes = recovered_key.to_sec1_point(false);
        let pubkey_hash = sha3::Keccak256::digest(&pubkey_bytes.as_bytes()[1..]);
        let recovered_addr = format!("0x{}", hex::encode(&pubkey_hash[12..]));

        assert_eq!(
            recovered_addr.to_lowercase(),
            evm_addr.to_lowercase(),
            "recovered address from tx signature should match wallet's EVM address"
        );
    }

    #[test]
    fn char_solana_extract_signable_through_sign_path() {
        // Verify that the full Solana signing pipeline (extract_signable → sign → encode)
        // works correctly through the library's sign_encode_and_broadcast path (minus broadcast).
        // This locks down the Solana-specific header stripping that could regress during
        // signing path unification.
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();
        create_wallet("char-sol-sig", None, None, Some(vault)).unwrap();

        // Build a minimal Solana serialized tx: [1 sig slot] [64 zero bytes] [message]
        let message_payload = b"test solana message payload 1234";
        let mut tx_bytes = vec![0x01u8]; // 1 signature slot
        tx_bytes.extend_from_slice(&[0u8; 64]); // placeholder signature
        tx_bytes.extend_from_slice(message_payload);
        let tx_hex = hex::encode(&tx_bytes);

        // sign_transaction goes through: hex decode → decrypt key → signer.sign_transaction(key,
        // tx_bytes) For Solana, sign_transaction signs the raw bytes (callers must
        // pre-extract). But sign_and_send does: extract_signable → sign → encode →
        // broadcast. Verify the raw sign_transaction path works:
        let sig =
            sign_transaction("char-sol-sig", "solana", &tx_hex, None, None, Some(vault)).unwrap();
        assert_eq!(
            hex::decode(&sig.signature).unwrap().len(),
            64,
            "Solana signature should be 64 bytes (Ed25519)"
        );
        assert!(sig.recovery_id.is_none(), "Ed25519 has no recovery ID");

        // Now verify the sign_encode_and_broadcast pipeline (minus actual broadcast)
        // by manually calling the signer's extract/sign/encode chain:
        let key =
            decrypt_signing_key("char-sol-sig", ChainType::Solana, b"", None, Some(vault)).unwrap();
        let signer = signer_for_chain(ChainType::Solana);

        let signable = signer.extract_signable_bytes(&tx_bytes).unwrap();
        assert_eq!(
            signable, message_payload,
            "extract_signable_bytes should return only the message portion"
        );

        let output = signer.sign_transaction(key.expose(), signable).unwrap();
        let signed_tx = signer.encode_signed_transaction(&tx_bytes, &output).unwrap();

        // The signature should be at bytes 1..65 in the signed tx
        assert_eq!(&signed_tx[1..65], &output.signature[..]);
        // Message portion should be unchanged
        assert_eq!(&signed_tx[65..], message_payload);
        // Total length unchanged
        assert_eq!(signed_tx.len(), tx_bytes.len());

        // Verify the signature is valid
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&key.expose().try_into().unwrap());
        let verifying_key = signing_key.verifying_key();
        let ed_sig = ed25519_dalek::Signature::from_bytes(&output.signature.try_into().unwrap());
        verifying_key
            .verify_strict(message_payload, &ed_sig)
            .expect("Solana signature should verify against extracted message");
    }

    #[test]
    fn char_library_encodes_before_broadcast() {
        // The library's sign_and_send correctly calls encode_signed_transaction
        // before broadcasting (unlike a raw sign_transaction call).
        // This test verifies the library path by showing that:
        // 1. sign_transaction returns a raw 65-byte signature
        // 2. The library's internal pipeline produces a full RLP-encoded signed tx
        // 3. They are fundamentally different
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();
        create_wallet("char-encode", None, None, Some(vault)).unwrap();

        // Minimal EIP-1559 tx
        let items: Vec<u8> = [
            oc_signer::rlp::encode_bytes(&[1]),          // chain_id
            oc_signer::rlp::encode_bytes(&[]),           // nonce
            oc_signer::rlp::encode_bytes(&[1]),          // maxPriorityFeePerGas
            oc_signer::rlp::encode_bytes(&[100]),        // maxFeePerGas
            oc_signer::rlp::encode_bytes(&[0x52, 0x08]), // gasLimit = 21000
            oc_signer::rlp::encode_bytes(&[0xDE, 0xAD]), // to
            oc_signer::rlp::encode_bytes(&[]),           // value
            oc_signer::rlp::encode_bytes(&[]),           // data
            oc_signer::rlp::encode_list(&[]),            // accessList
        ]
        .concat();
        let mut unsigned_tx = vec![0x02u8];
        unsigned_tx.extend_from_slice(&oc_signer::rlp::encode_list(&items));
        let tx_hex = hex::encode(&unsigned_tx);

        // Path A: sign_transaction (returns raw signature)
        let raw_sig =
            sign_transaction("char-encode", "evm", &tx_hex, None, None, Some(vault)).unwrap();
        let raw_sig_bytes = hex::decode(&raw_sig.signature).unwrap();

        // Path B: the internal pipeline (what sign_and_send uses)
        let key =
            decrypt_signing_key("char-encode", ChainType::Evm, b"", None, Some(vault)).unwrap();
        let signer = signer_for_chain(ChainType::Evm);
        let output = signer.sign_transaction(key.expose(), &unsigned_tx).unwrap();
        let full_signed_tx = signer.encode_signed_transaction(&unsigned_tx, &output).unwrap();

        // Raw sig is 65 bytes (r || s || v)
        assert_eq!(raw_sig_bytes.len(), 65);

        // Full signed tx is RLP-encoded with type byte prefix
        assert!(full_signed_tx.len() > 65);
        assert_eq!(full_signed_tx[0], 0x02, "should preserve EIP-1559 type byte");

        // They must be completely different
        assert_ne!(raw_sig_bytes, full_signed_tx);

        // The full signed tx should contain the r and s values from the signature
        // somewhere in its RLP encoding (not at the same offsets)
        let r_bytes = &raw_sig_bytes[..32];
        let _s_bytes = &raw_sig_bytes[32..64];

        // Verify r bytes appear in the full signed tx (they'll be RLP-encoded)
        let full_hex = hex::encode(&full_signed_tx);
        let r_hex = hex::encode(r_bytes);
        assert!(full_hex.contains(&r_hex), "full signed tx should contain the r component");
    }

    // ================================================================
    // EIP-712 TYPED DATA SIGNING
    // ================================================================

    #[test]
    fn sign_typed_data_rejects_non_evm_chain() {
        let tmp = tempfile::tempdir().unwrap();
        let vault = tmp.path();

        let w = save_privkey_wallet("typed-data-test", TEST_PRIVKEY, "pass", vault);

        let typed_data = r#"{
            "types": {
                "EIP712Domain": [{"name": "name", "type": "string"}],
                "Test": [{"name": "value", "type": "uint256"}]
            },
            "primaryType": "Test",
            "domain": {"name": "Test"},
            "message": {"value": "1"}
        }"#;

        let result = sign_typed_data(&w.id, "solana", typed_data, Some("pass"), None, Some(vault));
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("only supported for EVM"),
            "expected EVM-only error, got: {err_msg}"
        );
    }

    #[test]
    fn sign_typed_data_evm_succeeds() {
        let tmp = tempfile::tempdir().unwrap();
        let vault = tmp.path();

        let w = save_privkey_wallet("typed-data-evm", TEST_PRIVKEY, "pass", vault);

        let typed_data = r#"{
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"}
                ],
                "Test": [{"name": "value", "type": "uint256"}]
            },
            "primaryType": "Test",
            "domain": {"name": "TestDapp", "version": "1", "chainId": "1"},
            "message": {"value": "42"}
        }"#;

        let result = sign_typed_data(&w.id, "evm", typed_data, Some("pass"), None, Some(vault));
        assert!(result.is_ok(), "sign_typed_data failed: {:?}", result.err());

        let sign_result = result.unwrap();
        assert!(!sign_result.signature.is_empty(), "signature should not be empty");
        assert!(sign_result.recovery_id.is_some(), "recovery_id should be present for EVM");
    }

    // ================================================================
    // RAW HASH + EIP-7702 AUTHORIZATION SIGNING
    // ================================================================

    #[test]
    fn sign_hash_owner_path_matches_direct_signer() {
        let tmp = tempfile::tempdir().unwrap();
        let vault = tmp.path();
        let wallet = save_privkey_wallet("hash-owner", TEST_PRIVKEY, "pass", vault);
        let hash_hex = "11".repeat(32);

        let api_result =
            sign_hash(&wallet.id, "base", &hash_hex, Some("pass"), None, Some(vault)).unwrap();

        let key =
            decrypt_signing_key(&wallet.id, ChainType::Evm, b"pass", None, Some(vault)).unwrap();
        let signer = signer_for_chain(ChainType::Evm);
        let direct = signer.sign(key.expose(), &hex::decode(&hash_hex).unwrap()).unwrap();

        assert_eq!(api_result.signature, hex::encode(&direct.signature));
        assert_eq!(api_result.recovery_id, direct.recovery_id);
    }

    #[test]
    fn sign_authorization_owner_path_matches_sign_hash() {
        let tmp = tempfile::tempdir().unwrap();
        let vault = tmp.path();
        let wallet = save_privkey_wallet("auth-owner", TEST_PRIVKEY, "pass", vault);

        let auth_result = sign_authorization(
            &wallet.id,
            "base",
            "0x1111111111111111111111111111111111111111",
            "7",
            Some("pass"),
            None,
            Some(vault),
        )
        .unwrap();

        let hash = oc_signer::chains::EvmSigner
            .authorization_hash("8453", "0x1111111111111111111111111111111111111111", "7")
            .unwrap();

        let hash_result =
            sign_hash(&wallet.id, "base", &hex::encode(hash), Some("pass"), None, Some(vault))
                .unwrap();

        assert_eq!(auth_result.signature, hash_result.signature);
        assert_eq!(auth_result.recovery_id, hash_result.recovery_id);
    }

    #[test]
    fn sign_hash_rejects_non_secp256k1_chains() {
        let tmp = tempfile::tempdir().unwrap();
        let vault = tmp.path();
        let wallet = create_wallet("hash-solana", None, None, Some(vault)).unwrap();

        let err = sign_hash(&wallet.id, "solana", &"11".repeat(32), Some(""), None, Some(vault))
            .unwrap_err();

        match err {
            OcWalletError::InvalidInput(msg) => {
                assert!(msg.contains("secp256k1-backed chains"));
            }
            other => panic!("expected InvalidInput, got: {other}"),
        }
    }

    #[test]
    fn sign_authorization_rejects_non_evm_chains() {
        let tmp = tempfile::tempdir().unwrap();
        let vault = tmp.path();
        let wallet = create_wallet("auth-tron", None, None, Some(vault)).unwrap();

        let err = sign_authorization(
            &wallet.id,
            "tron",
            "0x1111111111111111111111111111111111111111",
            "7",
            Some(""),
            None,
            Some(vault),
        )
        .unwrap_err();

        match err {
            OcWalletError::InvalidInput(msg) => {
                assert!(msg.contains("only supported for EVM chains"));
            }
            other => panic!("expected InvalidInput, got: {other}"),
        }
    }

    #[test]
    fn sign_hash_api_key_path_obeys_policy() {
        let tmp = tempfile::tempdir().unwrap();
        let vault = tmp.path();
        let wallet = create_wallet("hash-agent", None, None, Some(vault)).unwrap();
        save_allowed_chains_policy(vault, "base-only-hash", vec!["eip155:8453".to_string()]);

        let (token, _) = crate::key_ops::create_api_key(
            "hash-agent-key",
            std::slice::from_ref(&wallet.id),
            &["base-only-hash".to_string()],
            "",
            None,
            Some(vault),
        )
        .unwrap();

        let allowed =
            sign_hash(&wallet.id, "base", &"22".repeat(32), Some(&token), None, Some(vault));
        assert!(allowed.is_ok(), "allowed sign_hash failed: {:?}", allowed.err());

        let denied =
            sign_hash(&wallet.id, "ethereum", &"22".repeat(32), Some(&token), None, Some(vault));
        match denied.unwrap_err() {
            OcWalletError::Core(OcError::PolicyDenied { reason, .. }) => {
                assert!(reason.contains("not in allowlist"));
            }
            other => panic!("expected PolicyDenied, got: {other}"),
        }
    }

    #[test]
    fn sign_authorization_api_key_path_matches_allowed_sign_hash() {
        let tmp = tempfile::tempdir().unwrap();
        let vault = tmp.path();
        let wallet = create_wallet("auth-agent", None, None, Some(vault)).unwrap();
        save_allowed_chains_policy(vault, "base-only-auth", vec!["eip155:8453".to_string()]);

        let (token, _) = crate::key_ops::create_api_key(
            "auth-agent-key",
            std::slice::from_ref(&wallet.id),
            &["base-only-auth".to_string()],
            "",
            None,
            Some(vault),
        )
        .unwrap();

        let auth_result = sign_authorization(
            &wallet.id,
            "base",
            "0x1111111111111111111111111111111111111111",
            "7",
            Some(&token),
            None,
            Some(vault),
        )
        .unwrap();

        let hash = oc_signer::chains::EvmSigner
            .authorization_hash("8453", "0x1111111111111111111111111111111111111111", "7")
            .unwrap();

        let hash_result =
            sign_hash(&wallet.id, "base", &hex::encode(hash), Some(&token), None, Some(vault))
                .unwrap();

        assert_eq!(auth_result.signature, hash_result.signature);
        assert_eq!(auth_result.recovery_id, hash_result.recovery_id);
    }

    #[cfg(unix)]
    #[test]
    fn sign_authorization_api_key_policy_receives_authorization_payload() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let vault = tmp.path();
        let wallet = create_wallet("auth-raw-hex", None, None, Some(vault)).unwrap();
        let address = "0x1111111111111111111111111111111111111111";
        let nonce = "7";
        let payload = hex::encode(
            oc_signer::chains::EvmSigner.authorization_payload("8453", address, nonce).unwrap(),
        );

        let script = vault.join("check-auth-payload.sh");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nif grep -q '\"raw_hex\":\"{payload}\"'; then\n  echo '{{\"allow\": true}}'\nelse\n  echo '{{\"allow\": false, \"reason\": \"unexpected raw_hex\"}}'\nfi\n"
            ),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

        let policy = oc_core::Policy {
            id: "auth-payload-only".to_string(),
            name: "auth payload only".to_string(),
            version: 1,
            created_at: "2026-03-22T00:00:00Z".to_string(),
            rules: vec![],
            executable: Some(script.display().to_string()),
            config: None,
            action: oc_core::PolicyAction::Deny,
        };
        crate::policy_store::save_policy(&policy, Some(vault)).unwrap();

        let (token, _) = crate::key_ops::create_api_key(
            "auth-payload-agent",
            std::slice::from_ref(&wallet.id),
            &["auth-payload-only".to_string()],
            "",
            None,
            Some(vault),
        )
        .unwrap();

        let auth_result =
            sign_authorization(&wallet.id, "base", address, nonce, Some(&token), None, Some(vault))
                .unwrap();
        assert!(!auth_result.signature.is_empty());

        let hash = oc_signer::chains::EvmSigner.authorization_hash("8453", address, nonce).unwrap();
        let err =
            sign_hash(&wallet.id, "base", &hex::encode(hash), Some(&token), None, Some(vault))
                .unwrap_err();

        match err {
            OcWalletError::Core(OcError::PolicyDenied { reason, .. }) => {
                assert!(reason.contains("unexpected raw_hex"));
            }
            other => panic!("expected PolicyDenied, got: {other}"),
        }
    }

    // ================================================================
    // OWNER-MODE REGRESSION: prove the credential branch doesn't alter
    // existing behavior for any passphrase variant.
    // ================================================================

    #[test]
    fn regression_owner_path_identical_to_direct_signer() {
        // Proves that sign_transaction via the library produces the exact
        // same signature as calling decrypt_signing_key → signer directly.
        // If the credential branch accidentally altered the owner path,
        // these would diverge.
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();
        create_wallet("reg-owner", None, None, Some(vault)).unwrap();

        let tx_hex = "deadbeefcafebabe";

        // Path A: through the public sign_transaction API (has credential branch)
        let api_result =
            sign_transaction("reg-owner", "evm", tx_hex, None, None, Some(vault)).unwrap();

        // Path B: direct signer call (no credential branch)
        let key = decrypt_signing_key("reg-owner", ChainType::Evm, b"", None, Some(vault)).unwrap();
        let signer = signer_for_chain(ChainType::Evm);
        let tx_bytes = hex::decode(tx_hex).unwrap();
        let direct_output = signer.sign_transaction(key.expose(), &tx_bytes).unwrap();

        assert_eq!(
            api_result.signature,
            hex::encode(&direct_output.signature),
            "library API and direct signer must produce identical signatures"
        );
        assert_eq!(api_result.recovery_id, direct_output.recovery_id, "recovery_id must match");
    }

    #[test]
    fn regression_owner_passphrase_not_confused_with_token() {
        // Prove that a non-token passphrase never enters the agent path.
        // If it did, it would fail with ApiKeyNotFound (no such token hash).
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();
        create_wallet("reg-pass", Some(12), Some("hunter2"), Some(vault)).unwrap();

        let tx_hex = "deadbeef";

        // Signing with the correct passphrase must succeed
        let result =
            sign_transaction("reg-pass", "evm", tx_hex, Some("hunter2"), None, Some(vault));
        assert!(result.is_ok(), "owner-mode signing failed: {:?}", result.err());

        // Signing with empty passphrase must fail with CryptoError (wrong passphrase),
        // NOT with ApiKeyNotFound (which would mean it entered the agent path)
        let bad = sign_transaction("reg-pass", "evm", tx_hex, Some(""), None, Some(vault));
        assert!(bad.is_err());
        match bad.unwrap_err() {
            OcWalletError::Crypto(_) => {} // correct: argon2id decryption failed
            other => panic!("expected Crypto error for wrong passphrase, got: {other}"),
        }

        // Signing with None must also fail with CryptoError
        let none_result = sign_transaction("reg-pass", "evm", tx_hex, None, None, Some(vault));
        assert!(none_result.is_err());
        match none_result.unwrap_err() {
            OcWalletError::Crypto(_) => {}
            other => panic!("expected Crypto error for None passphrase, got: {other}"),
        }
    }

    #[test]
    fn regression_sign_message_owner_path_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();
        create_wallet("reg-msg", None, None, Some(vault)).unwrap();

        // Through the public API
        let api_result =
            sign_message("reg-msg", "evm", "hello", None, None, None, Some(vault)).unwrap();

        // Direct signer
        let key = decrypt_signing_key("reg-msg", ChainType::Evm, b"", None, Some(vault)).unwrap();
        let signer = signer_for_chain(ChainType::Evm);
        let direct = signer.sign_message(key.expose(), b"hello").unwrap();

        assert_eq!(
            api_result.signature,
            hex::encode(&direct.signature),
            "sign_message owner path must match direct signer"
        );
    }

    // ================================================================
    // SOLANA SIGN_TRANSACTION EXTRACTION (Issue 2)
    // ================================================================

    #[test]
    fn solana_sign_transaction_extracts_signable_bytes() {
        // After the fix, sign_transaction should automatically extract
        // the message portion from a full Solana transaction envelope.
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();
        create_wallet("sol-extract", None, None, Some(vault)).unwrap();

        let message_payload = b"test solana message for extraction";
        let mut full_tx = vec![0x01u8]; // 1 sig slot
        full_tx.extend_from_slice(&[0u8; 64]); // placeholder signature
        full_tx.extend_from_slice(message_payload);
        let tx_hex = hex::encode(&full_tx);

        // sign_transaction through the public API (should now extract first)
        let sig_result =
            sign_transaction("sol-extract", "solana", &tx_hex, None, None, Some(vault)).unwrap();
        let sig_bytes = hex::decode(&sig_result.signature).unwrap();

        // Verify the signature is over the MESSAGE portion, not the full tx
        let key =
            decrypt_signing_key("sol-extract", ChainType::Solana, b"", None, Some(vault)).unwrap();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&key.expose().try_into().unwrap());
        let verifying_key = signing_key.verifying_key();
        let ed_sig = ed25519_dalek::Signature::from_bytes(&sig_bytes.try_into().unwrap());

        verifying_key
            .verify_strict(message_payload, &ed_sig)
            .expect("sign_transaction should sign the message portion, not the full envelope");
    }

    #[test]
    fn solana_sign_transaction_full_tx_matches_extracted_sign() {
        // Signing a full Solana tx via sign_transaction should produce the
        // same signature as manually extracting then signing.
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();
        create_wallet("sol-match", None, None, Some(vault)).unwrap();

        let message_payload = b"matching signatures test";
        let mut full_tx = vec![0x01u8];
        full_tx.extend_from_slice(&[0u8; 64]);
        full_tx.extend_from_slice(message_payload);
        let tx_hex = hex::encode(&full_tx);

        // Path A: through public sign_transaction API
        let api_sig =
            sign_transaction("sol-match", "solana", &tx_hex, None, None, Some(vault)).unwrap();

        // Path B: manual extract + sign
        let key =
            decrypt_signing_key("sol-match", ChainType::Solana, b"", None, Some(vault)).unwrap();
        let signer = signer_for_chain(ChainType::Solana);
        let signable = signer.extract_signable_bytes(&full_tx).unwrap();
        let direct = signer.sign_transaction(key.expose(), signable).unwrap();

        assert_eq!(
            api_sig.signature,
            hex::encode(&direct.signature),
            "sign_transaction API and manual extract+sign must produce the same signature"
        );
    }

    #[test]
    fn evm_sign_transaction_unaffected_by_extraction() {
        // Regression: EVM's extract_signable_bytes is a no-op, so the fix
        // should not change EVM signing behavior.
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();
        create_wallet("evm-regress", None, None, Some(vault)).unwrap();

        let items: Vec<u8> = [
            oc_signer::rlp::encode_bytes(&[1]),
            oc_signer::rlp::encode_bytes(&[]),
            oc_signer::rlp::encode_bytes(&[1]),
            oc_signer::rlp::encode_bytes(&[100]),
            oc_signer::rlp::encode_bytes(&[0x52, 0x08]),
            oc_signer::rlp::encode_bytes(&[0xDE, 0xAD]),
            oc_signer::rlp::encode_bytes(&[]),
            oc_signer::rlp::encode_bytes(&[]),
            oc_signer::rlp::encode_list(&[]),
        ]
        .concat();
        let mut unsigned_tx = vec![0x02u8];
        unsigned_tx.extend_from_slice(&oc_signer::rlp::encode_list(&items));
        let tx_hex = hex::encode(&unsigned_tx);

        // Sign twice — should be deterministic and work fine
        let sig1 =
            sign_transaction("evm-regress", "evm", &tx_hex, None, None, Some(vault)).unwrap();
        let sig2 =
            sign_transaction("evm-regress", "evm", &tx_hex, None, None, Some(vault)).unwrap();
        assert_eq!(sig1.signature, sig2.signature);
        assert_eq!(hex::decode(&sig1.signature).unwrap().len(), 65);
    }
}
