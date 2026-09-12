// Unified per-chain `Account` newtype paradigm (A9).
//
// Every chain exposes an `XxxAccount` that wraps its address string and
// implements the same surface:
//
// - `Deref<Target = str>` + `AsRef<str>` so accounts pass directly to address-taking APIs
//   (`&account[..]`, `fn foo(s: &str)`).
// - `From<String>` + `From<&str>` for ergonomic construction (extras defaulted; see below).
// - `into_derived_account(private_key) -> Result<Self, DeriveError>` — the complete constructor
//   that derives the address (and any extras) from a 32-byte private key via the chain signer.
// - `Display` renders the address (the `Deref` target).
//
// Extra-field retention (never silently dropped):
//
// | Account          | Extra retained                          |
// |------------------|-----------------------------------------|
// | `BitcoinAccount` | `wif` (Wallet Import Format, base58check `0x80\|\|key\|\|0x01`) |
// | `SparkAccount`   | `wif` (same encoding, Bitcoin L2 reuses the key) |
// | `SolanaAccount`  | `keypair` (64-byte `seed\|\|pubkey`, secret redacted in `Debug`) |
// | `NearAccount`    | `nsec` (bech32 `nsec` encoding of the 32-byte seed for tooling interop) |
// | `SuiAccount`     | `public_key` (32-byte ed25519, plus `tagged_public_key()` with `0x00` flag) |
// | `CasperAccount`  | tag separation: `public_key_hex` (no tag) vs `tagged_ed25519` (`01` + hex) |
// | others           | address only (no extra)                 |
//
// The table mirrors the CONTRIBUTING `Account` type-table idea: one row per
// chain, address newtype plus chain-specific extras. Secrets (`wif`,
// `keypair`, `nsec`) are redacted in `Debug`; addresses are public.
//
// This module uses only signer primitives (no `tokio`, R56-safe).

use std::{fmt, ops::Deref};

use crate::{
    chains::{
        BitcoinSigner, CosmosSigner, EvmSigner, FilecoinSigner, NanoSigner, NearSigner,
        SparkSigner, SuiSigner, TonSigner, TronSigner,
    },
    error::DeriveError,
    traits::ChainSigner,
};

// ---------------------------------------------------------------------------
// Shared helpers (extras)
// ---------------------------------------------------------------------------

/// Encode a 32-byte secp256k1 private key as mainnet compressed WIF.
///
/// WIF = base58check(`0x80 || key || 0x01`). The trailing `0x01` marks the
/// public key as compressed (P2WPKH always uses compressed keys).
///
/// # Errors
///
/// Returns [`DeriveError::Input`] when `private_key.len() != 32`.
pub fn bitcoin_wif_encode(private_key: &[u8]) -> Result<String, DeriveError> {
    if private_key.len() != 32 {
        return Err(DeriveError::Input(format!(
            "expected 32-byte private key for WIF, got {}",
            private_key.len()
        )));
    }
    let mut payload = Vec::with_capacity(34);
    payload.push(0x80);
    payload.extend_from_slice(private_key);
    payload.push(0x01);
    Ok(crate::encoding::base58check_encode(&payload))
}

/// Encode a 32-byte ed25519 seed as bech32 `nsec` (Nostr-style tooling interop).
///
/// The encoding is bech32 with HRP `nsec` over the raw 32 bytes. It carries
/// the SECRET (not the address); callers must treat it like a private key.
/// Provided so ed25519-family accounts (`NearAccount`) can round-trip through
/// `nsec`-aware tooling without inventing a second secret format.
///
/// # Errors
///
/// Returns [`DeriveError::Input`] when `seed.len() != 32`, or
/// [`DeriveError::AddressEncoding`] when bech32 encoding fails.
pub fn nsec_encode(seed: &[u8]) -> Result<String, DeriveError> {
    if seed.len() != 32 {
        return Err(DeriveError::Input(format!(
            "expected 32-byte seed for nsec, got {}",
            seed.len()
        )));
    }
    let hrp = bech32::Hrp::parse("nsec")
        .map_err(|e| DeriveError::AddressEncoding(format!("bad nsec HRP: {e}")))?;
    bech32::encode::<bech32::Bech32>(hrp, seed)
        .map_err(|e| DeriveError::AddressEncoding(format!("nsec encode failed: {e}")))
}

/// Casper ed25519 tag separation: raw public-key hex (NO tag).
///
/// Returns lowercase hex of the 32-byte ed25519 public key.
#[must_use]
pub fn casper_public_key_hex(pubkey: &[u8; 32]) -> String {
    hex::encode(pubkey)
}

/// Casper ed25519 tagged form: `01` + hex (WITH tag).
///
/// The leading `01` is the Casper public-key tag for ed25519 (secp256k1 uses
/// `02`). Tagged forms are what Casper JSON-RPC and account-hash derivation
/// consume; untagged hex is for display/comparison only.
#[must_use]
pub fn casper_tagged_ed25519(pubkey: &[u8; 32]) -> String {
    format!("01{}", hex::encode(pubkey))
}

/// Casper secp256k1 tagged form: `02` + hex of the 33-byte compressed key.
#[must_use]
pub fn casper_tagged_secp256k1(compressed: &[u8]) -> String {
    format!("02{}", hex::encode(compressed))
}

// ---------------------------------------------------------------------------
// Macro for address-only newtypes (EVM, Cosmos, Tron, Filecoin, XRPL)
// ---------------------------------------------------------------------------

macro_rules! address_only_account {
    ($name:ident, $signer:expr, $doc:expr) => {
        #[doc = $doc]
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub struct $name(pub String);

        impl $name {
            /// Derive from a private key via the chain signer.
            ///
            /// # Errors
            ///
            /// Forwards [`DeriveError`] from address derivation.
            pub fn into_derived_account(private_key: &[u8]) -> Result<Self, DeriveError> {
                let addr = $signer.derive_address(private_key)?;
                Ok(Self(addr))
            }

            /// Borrow the address.
            #[must_use]
            pub fn address(&self) -> &str {
                &self.0
            }
        }

        impl Deref for $name {
            type Target = str;
            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl From<String> for $name {
            fn from(s: String) -> Self {
                Self(s)
            }
        }

        impl From<&str> for $name {
            fn from(s: &str) -> Self {
                Self(s.to_string())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
}

address_only_account!(
    EvmAccount,
    EvmSigner,
    "EVM account (EIP-55 checksummed `0x...`). No extra fields."
);
address_only_account!(
    CosmosAccount,
    CosmosSigner::cosmos_hub(),
    "Cosmos Hub account (`cosmos1...`). Multi-chain via `ChainConfig` (see `cosmos.rs`); this newtype defaults to Hub."
);
address_only_account!(
    TronAccount,
    TronSigner,
    "Tron account (Base58Check `T...`). No extra fields."
);
address_only_account!(FilecoinAccount, FilecoinSigner, "Filecoin `f1` account. No extra fields.");

// XRPL needs feature-gated construction: `XrplSigner` only exists with
// `--features xrpl`. Route through `signer_for_chain` (which returns a
// fail-closed placeholder when compiled out) so `XrplAccount` exists in all
// builds and `into_derived_account` errors cleanly when unsupported.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct XrplAccount(pub String);

impl XrplAccount {
    /// Derive from a private key via the XRPL signer (or fail closed when
    /// the `xrpl` cargo feature is off).
    ///
    /// # Errors
    ///
    /// Forwards [`DeriveError`] from address derivation (including the
    /// feature-off placeholder error).
    pub fn into_derived_account(private_key: &[u8]) -> Result<Self, DeriveError> {
        let signer = crate::chains::signer_for_chain(oc_core::ChainType::Xrpl);
        Ok(Self(signer.derive_address(private_key)?))
    }

    /// Borrow the address.
    #[must_use]
    pub fn address(&self) -> &str {
        &self.0
    }
}

impl Deref for XrplAccount {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<str> for XrplAccount {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl From<String> for XrplAccount {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for XrplAccount {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl fmt::Display for XrplAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// Bitcoin / Spark (WIF extra)
// ---------------------------------------------------------------------------

macro_rules! wif_account {
    ($name:ident, $signer:expr, $doc:expr) => {
        #[doc = $doc]
        #[derive(Clone, PartialEq, Eq, Hash)]
        pub struct $name {
            /// On-chain address (public).
            pub address: String,
            /// Wallet Import Format (SECRET, redacted in `Debug`).
            pub wif: String,
        }

        impl $name {
            /// Derive address + WIF from a 32-byte private key.
            ///
            /// # Errors
            ///
            /// Returns [`DeriveError`] for bad keys or encoding failures.
            pub fn into_derived_account(private_key: &[u8]) -> Result<Self, DeriveError> {
                let address = $signer.derive_address(private_key)?;
                let wif = bitcoin_wif_encode(private_key)?;
                Ok(Self { address, wif })
            }

            /// Borrow the address.
            #[must_use]
            pub fn address(&self) -> &str {
                &self.address
            }
        }

        impl Deref for $name {
            type Target = str;
            fn deref(&self) -> &Self::Target {
                &self.address
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.address
            }
        }

        impl From<String> for $name {
            fn from(address: String) -> Self {
                Self { address, wif: String::new() }
            }
        }

        impl From<&str> for $name {
            fn from(s: &str) -> Self {
                Self { address: s.to_string(), wif: String::new() }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.address)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($name))
                    .field("address", &self.address)
                    .field("wif", &"[REDACTED]")
                    .finish()
            }
        }
    };
}

wif_account!(
    BitcoinAccount,
    BitcoinSigner::mainnet(),
    "Bitcoin P2WPKH account (`bc1q...`) retaining `wif` (compressed mainnet WIF)."
);
wif_account!(
    SparkAccount,
    SparkSigner,
    "Spark account (`spark:...`) retaining `wif` (same key as Bitcoin, Bitcoin L2)."
);

// ---------------------------------------------------------------------------
// Solana (keypair extra)
// ---------------------------------------------------------------------------

/// Solana account (base58 pubkey) retaining the 64-byte `keypair`
/// (`seed || pubkey`, secret redacted in `Debug`).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SolanaAccount {
    /// Base58-encoded ed25519 public key (public).
    pub address: String,
    /// 64-byte keypair `seed || pubkey` (SECRET, redacted in `Debug`).
    pub keypair: [u8; 64],
}

impl SolanaAccount {
    /// Derive address + keypair from a 32-byte seed.
    ///
    /// # Errors
    ///
    /// Returns [`DeriveError::Input`] for non-32-byte seeds.
    pub fn into_derived_account(private_key: &[u8]) -> Result<Self, DeriveError> {
        let seed: [u8; 32] = private_key.try_into().map_err(|_| {
            DeriveError::Input(format!("expected 32 bytes, got {}", private_key.len()))
        })?;
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        let pk = sk.verifying_key();
        let address = bs58::encode(pk.as_bytes()).into_string();
        let mut keypair = [0u8; 64];
        keypair[..32].copy_from_slice(&seed);
        keypair[32..].copy_from_slice(pk.as_bytes());
        Ok(Self { address, keypair })
    }

    /// Borrow the address.
    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }
}

impl Deref for SolanaAccount {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.address
    }
}

impl AsRef<str> for SolanaAccount {
    fn as_ref(&self) -> &str {
        &self.address
    }
}

impl From<String> for SolanaAccount {
    fn from(address: String) -> Self {
        Self { address, keypair: [0u8; 64] }
    }
}

impl From<&str> for SolanaAccount {
    fn from(s: &str) -> Self {
        Self { address: s.to_string(), keypair: [0u8; 64] }
    }
}

impl fmt::Display for SolanaAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.address)
    }
}

impl fmt::Debug for SolanaAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SolanaAccount")
            .field("address", &self.address)
            .field("keypair", &"[REDACTED; 64 bytes]")
            .finish()
    }
}

// ---------------------------------------------------------------------------
// TON (public-key extra; display decoupling lives in `ton.rs`)
// ---------------------------------------------------------------------------

/// TON account (wallet v5r1 `UQ...` by default) retaining the 32-byte ed25519
/// public key. Display variants (testnet/bounceable/workchain) are handled by
/// `TonDisplayConfig` in `ton.rs` and never change this key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TonAccount {
    /// User-friendly address (public).
    pub address: String,
    /// 32-byte ed25519 public key (public).
    pub public_key: [u8; 32],
}

impl TonAccount {
    /// Derive address + public key from a 32-byte seed.
    ///
    /// # Errors
    ///
    /// Forwards [`DeriveError`] from the TON signer.
    pub fn into_derived_account(private_key: &[u8]) -> Result<Self, DeriveError> {
        let signer = TonSigner;
        let address = signer.derive_address(private_key)?;
        let seed: [u8; 32] = private_key.try_into().map_err(|_| {
            DeriveError::Input(format!("expected 32 bytes, got {}", private_key.len()))
        })?;
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        Ok(Self { address, public_key: *sk.verifying_key().as_bytes() })
    }

    /// Borrow the address.
    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }
}

impl Deref for TonAccount {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.address
    }
}

impl AsRef<str> for TonAccount {
    fn as_ref(&self) -> &str {
        &self.address
    }
}

impl From<String> for TonAccount {
    fn from(address: String) -> Self {
        Self { address, public_key: [0u8; 32] }
    }
}

impl From<&str> for TonAccount {
    fn from(s: &str) -> Self {
        Self { address: s.to_string(), public_key: [0u8; 32] }
    }
}

impl fmt::Display for TonAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.address)
    }
}

// ---------------------------------------------------------------------------
// Sui (public-key + tagged extras)
// ---------------------------------------------------------------------------

/// Sui account (`0x...` BLAKE2b-256) retaining the 32-byte ed25519 public key.
///
/// `tagged_public_key()` returns the wire form `00 || pubkey` (the `0x00`
/// ed25519 flag is Sui's analogue of Casper's `01`/`02` tags).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SuiAccount {
    /// Sui address (public).
    pub address: String,
    /// 32-byte ed25519 public key (public).
    pub public_key: [u8; 32],
}

impl SuiAccount {
    /// Derive address + public key from a 32-byte seed.
    ///
    /// # Errors
    ///
    /// Forwards [`DeriveError`] from the Sui signer.
    pub fn into_derived_account(private_key: &[u8]) -> Result<Self, DeriveError> {
        let signer = SuiSigner;
        let address = signer.derive_address(private_key)?;
        let seed: [u8; 32] = private_key.try_into().map_err(|_| {
            DeriveError::Input(format!("expected 32 bytes, got {}", private_key.len()))
        })?;
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        Ok(Self { address, public_key: *sk.verifying_key().as_bytes() })
    }

    /// Tagged wire form `00 || pubkey` (flag + key).
    #[must_use]
    pub fn tagged_public_key(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(33);
        v.push(0x00);
        v.extend_from_slice(&self.public_key);
        v
    }

    /// Borrow the address.
    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }
}

impl Deref for SuiAccount {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.address
    }
}

impl AsRef<str> for SuiAccount {
    fn as_ref(&self) -> &str {
        &self.address
    }
}

impl From<String> for SuiAccount {
    fn from(address: String) -> Self {
        Self { address, public_key: [0u8; 32] }
    }
}

impl From<&str> for SuiAccount {
    fn from(s: &str) -> Self {
        Self { address: s.to_string(), public_key: [0u8; 32] }
    }
}

impl fmt::Display for SuiAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.address)
    }
}

// ---------------------------------------------------------------------------
// Nano / Near
// ---------------------------------------------------------------------------

/// Nano account (`nano_...`) retaining the 32-byte public key (Blake2b-512 domain).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NanoAccount {
    /// Nano address (public).
    pub address: String,
    /// 32-byte public key in the Nano/Blake2b-512 domain (public).
    pub public_key: [u8; 32],
}

impl NanoAccount {
    /// Derive address + public key from a 32-byte seed.
    ///
    /// # Errors
    ///
    /// Forwards [`DeriveError`] from the Nano signer.
    pub fn into_derived_account(private_key: &[u8]) -> Result<Self, DeriveError> {
        let signer = NanoSigner;
        let address = signer.derive_address(private_key)?;
        // Re-derive the verifying key via the signer path (Nano uses
        // Blake2b-512 expansion, NOT plain ed25519).
        let vk = NanoSigner::verifying_key_for_account(private_key)?;
        Ok(Self { address, public_key: vk })
    }

    /// Borrow the address.
    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }
}

impl Deref for NanoAccount {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.address
    }
}

impl AsRef<str> for NanoAccount {
    fn as_ref(&self) -> &str {
        &self.address
    }
}

impl From<String> for NanoAccount {
    fn from(address: String) -> Self {
        Self { address, public_key: [0u8; 32] }
    }
}

impl From<&str> for NanoAccount {
    fn from(s: &str) -> Self {
        Self { address: s.to_string(), public_key: [0u8; 32] }
    }
}

impl fmt::Display for NanoAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.address)
    }
}

/// NEAR implicit account (64-char lowercase hex pubkey) retaining the public
/// key plus `nsec` (bech32 `nsec` secret encoding for tooling interop).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct NearAccount {
    /// Implicit account ID = lowercase hex pubkey (public).
    pub address: String,
    /// 32-byte ed25519 public key (public).
    pub public_key: [u8; 32],
    /// bech32 `nsec` encoding of the 32-byte seed (SECRET, redacted in `Debug`).
    pub nsec: String,
}

impl NearAccount {
    /// Derive address + public key + `nsec` from a 32-byte seed.
    ///
    /// # Errors
    ///
    /// Returns [`DeriveError`] for bad keys or `nsec` encoding failures.
    pub fn into_derived_account(private_key: &[u8]) -> Result<Self, DeriveError> {
        let signer = NearSigner;
        let address = signer.derive_address(private_key)?;
        let seed: [u8; 32] = private_key.try_into().map_err(|_| {
            DeriveError::Input(format!("expected 32 bytes, got {}", private_key.len()))
        })?;
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        let public_key = *sk.verifying_key().as_bytes();
        let nsec = nsec_encode(&seed)?;
        Ok(Self { address, public_key, nsec })
    }

    /// Borrow the address.
    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }
}

impl Deref for NearAccount {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.address
    }
}

impl AsRef<str> for NearAccount {
    fn as_ref(&self) -> &str {
        &self.address
    }
}

impl From<String> for NearAccount {
    fn from(address: String) -> Self {
        Self { address, public_key: [0u8; 32], nsec: String::new() }
    }
}

impl From<&str> for NearAccount {
    fn from(s: &str) -> Self {
        Self { address: s.to_string(), public_key: [0u8; 32], nsec: String::new() }
    }
}

impl fmt::Display for NearAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.address)
    }
}

impl fmt::Debug for NearAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NearAccount")
            .field("address", &self.address)
            .field("public_key", &hex::encode(self.public_key))
            .field("nsec", &"[REDACTED]")
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Casper tag separation (A11)
// ---------------------------------------------------------------------------

/// Casper-style account demonstrating tag separation.
///
/// - `public_key_hex`: 32-byte ed25519 public key as lowercase hex (NO tag).
/// - `tagged_ed25519`: `01` + hex (WITH ed25519 tag, what Casper JSON-RPC consumes).
///
/// `Deref`/`AsRef<str>`/`Display` all target the untagged
/// `public_key_hex`; tagged forms are explicit method calls so a bare hex
/// can never be mistaken for a tagged key. The secp256k1 analogue
/// (`02` + 33-byte compressed hex) is covered by
/// [`casper_tagged_secp256k1`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CasperAccount {
    /// Untagged 32-byte ed25519 public-key hex (no tag).
    pub public_key_hex: String,
    /// Tagged `01` + hex (with ed25519 tag).
    pub tagged_ed25519: String,
}

impl CasperAccount {
    /// Build from a 32-byte ed25519 public key.
    #[must_use]
    pub fn from_ed25519_pubkey(pubkey: &[u8; 32]) -> Self {
        Self {
            public_key_hex: casper_public_key_hex(pubkey),
            tagged_ed25519: casper_tagged_ed25519(pubkey),
        }
    }

    /// Derive from a 32-byte ed25519 seed (SHA-512 domain, like Solana).
    ///
    /// # Errors
    ///
    /// Returns [`DeriveError::Input`] for non-32-byte seeds.
    pub fn into_derived_account(private_key: &[u8]) -> Result<Self, DeriveError> {
        let seed: [u8; 32] = private_key.try_into().map_err(|_| {
            DeriveError::Input(format!("expected 32 bytes, got {}", private_key.len()))
        })?;
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        Ok(Self::from_ed25519_pubkey(sk.verifying_key().as_bytes()))
    }

    /// Borrow the untagged hex.
    #[must_use]
    pub fn public_key_hex_str(&self) -> &str {
        &self.public_key_hex
    }
}

impl Deref for CasperAccount {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.public_key_hex
    }
}

impl AsRef<str> for CasperAccount {
    fn as_ref(&self) -> &str {
        &self.public_key_hex
    }
}

impl From<String> for CasperAccount {
    fn from(public_key_hex: String) -> Self {
        // `From` cannot know the tag without the raw bytes; the tagged form
        // is recomputed only when it is a valid 32-byte hex, otherwise left
        // empty so `into_derived_account`/`from_ed25519_pubkey` remain the
        // complete constructors.
        let tagged_ed25519 = hex::decode(public_key_hex.trim())
            .ok()
            .and_then(|b| b.try_into().ok())
            .map(|arr: [u8; 32]| casper_tagged_ed25519(&arr))
            .unwrap_or_default();
        Self { public_key_hex, tagged_ed25519 }
    }
}

impl From<&str> for CasperAccount {
    fn from(s: &str) -> Self {
        Self::from(s.to_string())
    }
}

impl fmt::Display for CasperAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.public_key_hex)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rfc_seed() -> Vec<u8> {
        hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").unwrap()
    }

    fn seed_one() -> Vec<u8> {
        let mut v = vec![0u8; 31];
        v.push(1u8);
        v
    }

    #[test]
    fn evm_account_deref_asref_from_and_derive() {
        let acc = EvmAccount::into_derived_account(&seed_one()).unwrap();
        assert!(acc.starts_with("0x"));
        // Deref + AsRef<str> target the address.
        let via_deref: &str = &acc;
        assert_eq!(via_deref, acc.address());
        assert_eq!(acc.as_ref() as &str, acc.address());
        // From.
        let from_string = EvmAccount::from(acc.address().to_string());
        let from_str = EvmAccount::from(acc.address());
        assert_eq!(from_string.address(), from_str.address());
        assert_eq!(format!("{acc}"), acc.address());
    }

    #[test]
    fn bitcoin_account_retains_wif() {
        let acc = BitcoinAccount::into_derived_account(&seed_one()).unwrap();
        assert!(acc.starts_with("bc1q"));
        assert_ne!(acc.wif, "");
        // Verified vector: privkey `0x00..01` (compressed) mainnet WIF.
        // Payload `80 || key || 01` with double-SHA256 checksum (checked by
        // decoding below); the bech32 address for the same key is
        // `bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4`.
        assert_eq!(acc.wif, "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn");
        // WIF payload must be `0x80 || key || 0x01`.
        let decoded = crate::encoding::base58check_decode(&acc.wif).unwrap();
        assert_eq!(decoded.len(), 34);
        assert_eq!(decoded[0], 0x80);
        assert_eq!(&decoded[1..33], seed_one().as_slice());
        assert_eq!(decoded[33], 0x01);
        // Deref/Display target the address, never the WIF.
        assert_eq!(&*acc, acc.address);
        assert_eq!(format!("{acc}"), acc.address);
        // Debug redacts the secret.
        assert!(!format!("{acc:?}").contains(&acc.wif));
        // From defaults WIF to empty (complete ctor is `into_derived_account`).
        let bare = BitcoinAccount::from(acc.address);
        assert_eq!(bare.wif, "");
    }

    #[test]
    fn spark_account_reuses_bitcoin_wif() {
        let btc = BitcoinAccount::into_derived_account(&seed_one()).unwrap();
        let spark = SparkAccount::into_derived_account(&seed_one()).unwrap();
        assert!(spark.address.starts_with("spark:"));
        assert_eq!(spark.wif, btc.wif);
    }

    #[test]
    fn solana_account_retains_keypair() {
        let acc = SolanaAccount::into_derived_account(&rfc_seed()).unwrap();
        assert_eq!(acc.keypair.len(), 64);
        assert_eq!(&acc.keypair[..32], &rfc_seed()[..]);
        // Address is base58(pubkey) = last 32 of keypair.
        let decoded = bs58::decode(&acc.address).into_vec().unwrap();
        assert_eq!(decoded, &acc.keypair[32..]);
        assert_eq!(&*acc, acc.address);
        assert!(!format!("{acc:?}").contains(&hex::encode(rfc_seed())));
    }

    #[test]
    fn near_account_retains_nsec() {
        let acc = NearAccount::into_derived_account(&rfc_seed()).unwrap();
        assert_eq!(acc.address.len(), 64);
        assert!(acc.nsec.starts_with("nsec1"));
        // `nsec` decodes back to the seed (bech32 round-trip).
        let (_, data) = bech32::decode(&acc.nsec).unwrap();
        assert_eq!(data, rfc_seed());
        assert!(!format!("{acc:?}").contains(&acc.nsec));
    }

    #[test]
    fn sui_tagged_form_has_flag() {
        let acc = SuiAccount::into_derived_account(&rfc_seed()).unwrap();
        assert!(acc.address.starts_with("0x"));
        let tagged = acc.tagged_public_key();
        assert_eq!(tagged.len(), 33);
        assert_eq!(tagged[0], 0x00);
        assert_eq!(&tagged[1..], &acc.public_key);
    }

    #[test]
    fn casper_tag_separation() {
        let pubkey = [0xABu8; 32];
        let acc = CasperAccount::from_ed25519_pubkey(&pubkey);
        // Untagged has no prefix; tagged has `01`.
        assert!(!acc.public_key_hex.starts_with("01") || acc.public_key_hex.len() != 66);
        assert_eq!(acc.public_key_hex.len(), 64);
        assert!(acc.tagged_ed25519.starts_with("01"));
        assert_eq!(acc.tagged_ed25519.len(), 66);
        // Deref/Display target the untagged form.
        assert_eq!(&*acc, acc.public_key_hex);
        assert_eq!(format!("{acc}"), acc.public_key_hex);
        // secp256k1 analogue uses `02`.
        let tagged_secp = casper_tagged_secp256k1(&[0x02u8; 33]);
        assert!(tagged_secp.starts_with("02"));
    }

    #[test]
    fn ton_and_nano_derive() {
        let ton = TonAccount::into_derived_account(&rfc_seed()).unwrap();
        assert!(ton.starts_with("UQ"));
        assert_ne!(ton.public_key, [0u8; 32]);
        let nano = NanoAccount::into_derived_account(&rfc_seed()).unwrap();
        assert!(nano.starts_with("nano_"));
    }

    #[test]
    fn cosmos_tron_filecoin_xrpl_derive() {
        assert!(CosmosAccount::into_derived_account(&seed_one()).unwrap().starts_with("cosmos1"));
        assert!(TronAccount::into_derived_account(&seed_one()).unwrap().starts_with('T'));
        assert!(FilecoinAccount::into_derived_account(&seed_one()).unwrap().starts_with("f1"));
    }
}
