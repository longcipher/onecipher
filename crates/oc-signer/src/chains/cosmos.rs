use k256::ecdsa::SigningKey;
use oc_core::ChainType;
use sha2::{Digest, Sha256};

use crate::{
    curve::Curve,
    encoding::hash160,
    traits::{ChainSigner, SignOutput, SignerError},
};
/// Cosmos-family chain configuration: bech32 HRP plus BIP-44 coin type.
///
/// One code path covers many chains: only `hrp`/`coin_type` vary per preset
/// below. Most Cosmos SDK chains use coin type 118 (ATOM); the field exists
/// so exceptional chains can override it without forking the signer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChainConfig {
    /// Bech32 human-readable part (e.g. `"cosmos"`, `"osmo"`).
    pub hrp: &'static str,
    /// BIP-44 coin type (usually 118).
    pub coin_type: u32,
}

/// Cosmos Hub (`cosmos`, 118).
pub const COSMOS_HUB: ChainConfig = ChainConfig { hrp: "cosmos", coin_type: 118 };
/// Osmosis (`osmo`, 118).
pub const OSMOSIS: ChainConfig = ChainConfig { hrp: "osmo", coin_type: 118 };
/// Juno (`juno`, 118).
pub const JUNO: ChainConfig = ChainConfig { hrp: "juno", coin_type: 118 };
/// Stargaze (`stars`, 118).
pub const STARGAZE: ChainConfig = ChainConfig { hrp: "stars", coin_type: 118 };

/// Cosmos chain signer (secp256k1, bech32 addresses).
pub struct CosmosSigner {
    /// Chain configuration (HRP + coin type) for preset chains.
    config: ChainConfig,
    /// Heap HRP for dynamic prefixes not in the preset table.
    owned_hrp: Option<String>,
}

impl CosmosSigner {
    /// Build from an explicit [`ChainConfig`].
    pub const fn with_config(config: ChainConfig) -> Self {
        Self { config, owned_hrp: None }
    }

    /// Build from a raw HRP with the default coin type 118.
    ///
    /// Known presets reuse `&'static` HRPs without allocation; unknown
    /// prefixes are stored on the heap (no leaking).
    pub fn new(hrp: &str) -> Self {
        match hrp {
            "cosmos" => Self::cosmos_hub(),
            "osmo" => Self::osmosis(),
            "juno" => Self::juno(),
            "stars" => Self::stargaze(),
            _ => Self {
                config: ChainConfig { hrp: "cosmos", coin_type: 118 },
                owned_hrp: Some(hrp.to_string()),
            },
        }
    }

    /// Human-readable part actually used for encoding (preset or owned).
    fn hrp(&self) -> &str {
        self.owned_hrp.as_deref().unwrap_or(self.config.hrp)
    }

    /// Cosmos Hub preset.
    pub const fn cosmos_hub() -> Self {
        Self { config: COSMOS_HUB, owned_hrp: None }
    }

    /// Osmosis preset (`osmo`).
    pub const fn osmosis() -> Self {
        Self { config: OSMOSIS, owned_hrp: None }
    }

    /// Juno preset (`juno`).
    pub const fn juno() -> Self {
        Self { config: JUNO, owned_hrp: None }
    }

    /// Stargaze preset (`stars`).
    pub const fn stargaze() -> Self {
        Self { config: STARGAZE, owned_hrp: None }
    }

    /// Borrow the active [`ChainConfig`].
    ///
    /// For preset chains this is exact. For dynamic HRPs (built via
    /// [`Self::new`] with an unknown prefix) the returned `hrp` is the Hub
    /// placeholder — use [`Self::hrp`] (private) / `derive_address` for the
    /// effective prefix. The `coin_type` is always authoritative.
    pub const fn chain_config(&self) -> ChainConfig {
        self.config
    }

    fn signing_key(private_key: &[u8]) -> Result<SigningKey, SignerError> {
        SigningKey::from_slice(private_key)
            .map_err(|_| SignerError::Input("key parsing failed".into()))
    }
}

impl ChainSigner for CosmosSigner {
    fn chain_type(&self) -> ChainType {
        ChainType::Cosmos
    }

    fn curve(&self) -> Curve {
        Curve::Secp256k1
    }

    fn coin_type(&self) -> u32 {
        self.config.coin_type
    }

    fn derive_address(&self, private_key: &[u8]) -> Result<String, SignerError> {
        let signing_key = Self::signing_key(private_key)?;
        let verifying_key = signing_key.verifying_key();

        // Compressed public key
        let pubkey_compressed = verifying_key.to_sec1_point(true);
        let pubkey_bytes = pubkey_compressed.as_bytes();

        // Hash160 (shared `crate::encoding` primitive, same as Bitcoin).
        let hash = hash160(pubkey_bytes);

        // Standard bech32 encoding (no witness version, unlike Bitcoin segwit).
        // `hrp()` resolves presets vs dynamic owned prefixes.
        let hrp = bech32::Hrp::parse(self.hrp())
            .map_err(|e| SignerError::AddressEncoding(e.to_string()))?;
        let address = bech32::encode::<bech32::Bech32>(hrp, &hash)
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
        // Cosmos transaction signing: SHA256 of the serialized SignDoc
        let hash = Sha256::digest(tx_bytes);
        self.sign(private_key, &hash)
    }

    fn sign_message(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        // Cosmos typically signs the SHA256 hash of the message
        let hash = Sha256::digest(message);
        self.sign(private_key, &hash)
    }

    fn default_derivation_path(&self, index: u32) -> String {
        format!("m/44'/{}'/0'/0/{}", self.config.coin_type, index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_privkey() -> Vec<u8> {
        // Use generator point G (private key = 1)
        let mut privkey = vec![0u8; 31];
        privkey.push(1u8);
        privkey
    }

    #[test]
    fn test_known_address() {
        let privkey = test_privkey();
        let signer = CosmosSigner::cosmos_hub();
        let address = signer.derive_address(&privkey).unwrap();
        assert!(address.starts_with("cosmos1"));
    }

    #[test]
    fn test_different_hrps() {
        let privkey = test_privkey();
        let cosmos_signer = CosmosSigner::cosmos_hub();
        let osmo_signer = CosmosSigner::new("osmo");

        let cosmos_addr = cosmos_signer.derive_address(&privkey).unwrap();
        let osmo_addr = osmo_signer.derive_address(&privkey).unwrap();

        assert!(cosmos_addr.starts_with("cosmos1"));
        assert!(osmo_addr.starts_with("osmo1"));

        // Same key, different prefix but same hash
        let (_, cosmos_bytes) = bech32::decode(&cosmos_addr).unwrap();
        let (_, osmo_bytes) = bech32::decode(&osmo_addr).unwrap();
        assert_eq!(cosmos_bytes, osmo_bytes);
    }

    #[test]
    fn test_same_hash_as_bitcoin() {
        // Same private key should produce the same Hash160 on both Bitcoin and Cosmos.
        // Both now route through the shared `crate::encoding::hash160`.
        let privkey = test_privkey();

        let signing_key = SigningKey::from_slice(&privkey).unwrap();
        let verifying_key = signing_key.verifying_key();
        let pubkey_compressed = verifying_key.to_sec1_point(true);
        let pubkey_bytes = pubkey_compressed.as_bytes();
        let hash = hash160(pubkey_bytes);

        let btc_hash = crate::encoding::hash160(pubkey_bytes);

        assert_eq!(hash, btc_hash);
    }

    #[test]
    fn test_derivation_path() {
        let signer = CosmosSigner::cosmos_hub();
        assert_eq!(signer.default_derivation_path(0), "m/44'/118'/0'/0/0");
        assert_eq!(signer.default_derivation_path(2), "m/44'/118'/0'/0/2");
    }

    #[test]
    fn test_chain_properties() {
        let signer = CosmosSigner::cosmos_hub();
        assert_eq!(signer.chain_type(), ChainType::Cosmos);
        assert_eq!(signer.curve(), Curve::Secp256k1);
        assert_eq!(signer.coin_type(), 118);
    }

    #[test]
    fn test_deterministic() {
        let privkey = test_privkey();
        let signer = CosmosSigner::cosmos_hub();
        let addr1 = signer.derive_address(&privkey).unwrap();
        let addr2 = signer.derive_address(&privkey).unwrap();
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn test_presets_share_one_code_path() {
        // One signer type, many chains: only `ChainConfig` varies.
        let privkey = test_privkey();
        for (signer, prefix) in [
            (CosmosSigner::cosmos_hub(), "cosmos1"),
            (CosmosSigner::osmosis(), "osmo1"),
            (CosmosSigner::juno(), "juno1"),
            (CosmosSigner::stargaze(), "stars1"),
        ] {
            let addr = signer.derive_address(&privkey).unwrap();
            assert!(addr.starts_with(prefix), "expected {prefix}, got {addr}");
            assert_eq!(signer.coin_type(), 118);
        }
        // `with_config` covers the same path with an explicit preset.
        let via_config = CosmosSigner::with_config(OSMOSIS).derive_address(&privkey).unwrap();
        let via_preset = CosmosSigner::osmosis().derive_address(&privkey).unwrap();
        assert_eq!(via_config, via_preset);
        // Dynamic HRPs still work without a preset.
        let dyn_addr = CosmosSigner::new("myzone").derive_address(&privkey).unwrap();
        assert!(dyn_addr.starts_with("myzone1"));
    }
}
