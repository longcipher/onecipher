use serde::{Deserialize, Serialize};

use crate::chain::ChainType;

/// The keyfile format version written by this build.
pub const CURRENT_VERSION: u32 = 2;

/// The highest keyfile format version this build knows how to interpret.
///
/// # Forward-compatibility policy
///
/// Every wallet file carries an explicit version field (`oc_version`; legacy
/// v1 files used `lws_version`, and both names are accepted). Versions at or
/// below this constant are loaded normally, including older layouts handled
/// through serde aliases and deprecated optional fields. Versions above this
/// constant are rejected before any semantic processing with
/// [`WalletFileError::UnsupportedVersion`]: a newer writer may attach
/// different meaning to existing fields, so silently loading such a file
/// could misinterpret user data. When a new format version is introduced,
/// teach this crate to read it first, then bump this constant.
pub const MAX_SUPPORTED_VERSION: u32 = CURRENT_VERSION;

/// The full on-disk wallet file format (extended Ethereum Keystore v3).
/// Written to `~/.onecipher/wallets/<id>.json`.
///
/// Deserialization validates the keyfile version against
/// [`MAX_SUPPORTED_VERSION`] before the value is returned to any caller
/// (see the manual [`Deserialize`] impl below).
#[derive(Debug, Clone, Serialize)]
pub struct EncryptedWallet {
    #[serde(alias = "lws_version")]
    pub oc_version: u32,
    pub id: String,
    pub name: String,
    pub created_at: String,
    /// Deprecated in v2. Kept for backward compat when deserializing v1 wallets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_type: Option<ChainType>,
    pub accounts: Vec<WalletAccount>,
    pub crypto: serde_json::Value,
    pub key_type: KeyType,
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub metadata: serde_json::Value,
}

/// An account entry within an encrypted wallet file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletAccount {
    pub account_id: String,
    pub address: String,
    pub chain_id: String,
    pub derivation_path: String,
}

/// Type of key material stored in the ciphertext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyType {
    Mnemonic,
    /// Multi-curve key pair: encrypted JSON `{"secp256k1":"hex","ed25519":"hex"}`.
    /// Supports all 6 chains.
    PrivateKey,
}

impl EncryptedWallet {
    pub fn new(
        id: String,
        name: String,
        accounts: Vec<WalletAccount>,
        crypto: serde_json::Value,
        key_type: KeyType,
    ) -> Self {
        Self {
            oc_version: CURRENT_VERSION,
            id,
            name,
            created_at: jiff::Timestamp::now().to_string(),
            chain_type: None,
            accounts,
            crypto,
            key_type,
            metadata: serde_json::Value::Null,
        }
    }

    /// Rejects keyfile versions this build does not know how to interpret.
    ///
    /// See the forward-compatibility policy on [`MAX_SUPPORTED_VERSION`].
    pub fn validate_version(version: u32) -> Result<(), WalletFileError> {
        if version > MAX_SUPPORTED_VERSION {
            return Err(WalletFileError::UnsupportedVersion {
                found: version,
                max_supported: MAX_SUPPORTED_VERSION,
            });
        }
        Ok(())
    }
}

/// Errors raised while loading a wallet keyfile.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WalletFileError {
    /// The file declares a keyfile version newer than
    /// [`MAX_SUPPORTED_VERSION`], written by a newer OneCipher build whose
    /// field semantics this build cannot reason about.
    #[error(
        "unsupported wallet file version {found} (this build supports up to \
         {max_supported}); upgrade OneCipher to open this wallet"
    )]
    UnsupportedVersion {
        /// The `oc_version` value found in the file.
        found: u32,
        /// The highest version this build supports ([`MAX_SUPPORTED_VERSION`]).
        max_supported: u32,
    },
}

/// Private serde mirror of [`EncryptedWallet`], used by the manual
/// [`Deserialize`] implementation so the version check runs before the parsed
/// value ever reaches a caller. Keep its fields and serde attributes in sync
/// with [`EncryptedWallet`].
#[derive(Deserialize)]
struct EncryptedWalletFields {
    #[serde(alias = "lws_version")]
    oc_version: u32,
    id: String,
    name: String,
    created_at: String,
    /// Deprecated in v2. Kept for backward compat when deserializing v1 wallets.
    #[serde(default)]
    chain_type: Option<ChainType>,
    accounts: Vec<WalletAccount>,
    crypto: serde_json::Value,
    key_type: KeyType,
    #[serde(default)]
    metadata: serde_json::Value,
}

impl<'de> Deserialize<'de> for EncryptedWallet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let fields = EncryptedWalletFields::deserialize(deserializer)?;
        Self::validate_version(fields.oc_version).map_err(serde::de::Error::custom)?;
        Ok(Self {
            oc_version: fields.oc_version,
            id: fields.id,
            name: fields.name,
            created_at: fields.created_at,
            chain_type: fields.chain_type,
            accounts: fields.accounts,
            crypto: fields.crypto,
            key_type: fields.key_type,
            metadata: fields.metadata,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_wallet() -> EncryptedWallet {
        EncryptedWallet::new(
            "test-id".to_string(),
            "test-wallet".to_string(),
            vec![WalletAccount {
                account_id: "eip155:1:0xabc".to_string(),
                address: "0xabc".to_string(),
                chain_id: "eip155:1".to_string(),
                derivation_path: "m/44'/60'/0'/0/0".to_string(),
            }],
            serde_json::json!({"cipher": "aes-256-gcm"}),
            KeyType::Mnemonic,
        )
    }

    #[test]
    fn test_serde_roundtrip() {
        let wallet = dummy_wallet();
        let json = serde_json::to_string_pretty(&wallet).unwrap();
        let deserialized: EncryptedWallet = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, "test-id");
        assert_eq!(deserialized.name, "test-wallet");
        assert_eq!(deserialized.oc_version, 2);
        assert!(deserialized.chain_type.is_none());
    }

    #[test]
    fn test_key_type_serde() {
        let json = serde_json::to_string(&KeyType::Mnemonic).unwrap();
        assert_eq!(json, "\"mnemonic\"");
        let json = serde_json::to_string(&KeyType::PrivateKey).unwrap();
        assert_eq!(json, "\"private_key\"");
    }

    #[test]
    fn test_v2_no_chain_type_field() {
        let wallet = dummy_wallet();
        let json = serde_json::to_value(&wallet).unwrap();
        assert!(json.get("chain_type").is_none(), "v2 wallets should not serialize chain_type");
    }

    #[test]
    fn test_matches_spec_format() {
        let wallet = dummy_wallet();
        let json = serde_json::to_value(&wallet).unwrap();
        for key in ["oc_version", "id", "name", "created_at", "accounts", "crypto", "key_type"] {
            assert!(json.get(key).is_some(), "missing key: {key}");
        }
    }

    #[test]
    fn test_metadata_omitted_when_null() {
        let wallet = dummy_wallet();
        let json = serde_json::to_value(&wallet).unwrap();
        assert!(json.get("metadata").is_none());
    }

    #[test]
    fn test_v1_backward_compat() {
        // Simulate a v1 wallet JSON with chain_type field
        let v1_json = serde_json::json!({
            "lws_version": 1,
            "id": "old-id",
            "name": "old-wallet",
            "created_at": "2024-01-01T00:00:00Z",
            "chain_type": "evm",
            "accounts": [{
                "account_id": "eip155:1:0xabc",
                "address": "0xabc",
                "chain_id": "eip155:1",
                "derivation_path": "m/44'/60'/0'/0/0"
            }],
            "crypto": {"cipher": "aes-256-gcm"},
            "key_type": "mnemonic"
        });
        let wallet: EncryptedWallet = serde_json::from_value(v1_json).unwrap();
        assert_eq!(wallet.oc_version, 1);
        assert_eq!(wallet.chain_type, Some(ChainType::Evm));
    }

    #[test]
    fn test_current_version_loads() {
        let wallet = dummy_wallet();
        let json = serde_json::to_string(&wallet).unwrap();
        let back: EncryptedWallet = serde_json::from_str(&json).unwrap();
        assert_eq!(back.oc_version, CURRENT_VERSION);
        assert_eq!(CURRENT_VERSION, MAX_SUPPORTED_VERSION);
    }

    #[test]
    fn test_previous_version_loads_via_modern_field_name() {
        // current-1 spelled with the modern `oc_version` field name must also
        // load; the legacy `lws_version` alias path is covered by
        // `test_v1_backward_compat` above.
        let mut json = serde_json::to_value(dummy_wallet()).unwrap();
        json["oc_version"] = serde_json::json!(CURRENT_VERSION - 1);
        let back: EncryptedWallet = serde_json::from_value(json).unwrap();
        assert_eq!(back.oc_version, CURRENT_VERSION - 1);
    }

    #[test]
    fn test_future_version_rejected_with_typed_error() {
        let mut json = serde_json::to_value(dummy_wallet()).unwrap();
        json["oc_version"] = serde_json::json!(CURRENT_VERSION + 5);
        let err = serde_json::from_value::<EncryptedWallet>(json)
            .expect_err("future keyfile versions must be rejected");
        assert!(
            err.to_string().contains("unsupported wallet file version"),
            "unexpected error: {err}"
        );
        // The typed error itself carries found/max_supported.
        assert_eq!(
            EncryptedWallet::validate_version(CURRENT_VERSION + 5),
            Err(WalletFileError::UnsupportedVersion {
                found: CURRENT_VERSION + 5,
                max_supported: MAX_SUPPORTED_VERSION,
            })
        );
    }

    #[test]
    fn test_missing_version_field_rejected() {
        // No default exists for the version field: a file with neither
        // `oc_version` nor the legacy `lws_version` alias is malformed and
        // fails deserialization (existing alias logic).
        let mut json = serde_json::to_value(dummy_wallet()).unwrap();
        json.as_object_mut().unwrap().remove("oc_version");
        assert!(serde_json::from_value::<EncryptedWallet>(json).is_err());
    }
}
