// Unified age envelope seam.
//
// Wallet files, API-token wallet copies and `.ocbk` backup bundles all flow
// through the age operations in [`envelope`]: scrypt passphrases for owner /
// device secrets, X25519 recipients for token copies and backups.
pub mod envelope;

pub use envelope::{
    AGE_CIPHER, AgeEnvelope, AgeIdentity, CryptoError, decrypt_with_identity,
    decrypt_with_passphrase, encrypt_to_recipients, encrypt_with_passphrase, token_identity,
    token_recipient,
};
