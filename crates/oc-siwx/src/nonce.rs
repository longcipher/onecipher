//! Cryptographically secure nonce generation for replay-attack prevention.

use rand::RngExt;

use crate::{SiwxError, message::MIN_NONCE_LEN};

/// Default nonce length (17 characters, matching the SIWE reference suite).
pub const DEFAULT_LEN: usize = 17;

/// Generates a random alphanumeric nonce of the given `len`.
///
/// Requires `len` `>=` [`MIN_NONCE_LEN`].
pub fn generate(len: usize) -> Result<String, SiwxError> {
    if len < MIN_NONCE_LEN {
        return Err(SiwxError::InvalidNonce {
            reason: format!("length must be at least {MIN_NONCE_LEN}, got {len}"),
        });
    }
    Ok(random_alnum(len))
}

/// Generates a random alphanumeric nonce with [`DEFAULT_LEN`] length.
#[must_use]
pub fn generate_default() -> String {
    const {
        assert!(DEFAULT_LEN >= MIN_NONCE_LEN, "DEFAULT_LEN must be >= MIN_NONCE_LEN");
    }
    random_alnum(DEFAULT_LEN)
}

#[allow(clippy::indexing_slicing, reason = "idx in 0..62 indexes [u8; 62]")]
fn random_alnum(len: usize) -> String {
    const ALPHABET: &[u8; 62] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::rng();
    (0..len)
        .map(|_| {
            let idx = rng.random_range(0..62);
            ALPHABET[idx] as char
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_has_correct_length() {
        assert_eq!(generate(8).expect("ok").len(), 8);
        assert_eq!(generate(32).expect("ok").len(), 32);
    }

    #[test]
    fn nonce_is_alphanumeric() {
        let n = generate(100).expect("ok");
        assert!(n.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn default_nonce_is_17() {
        assert_eq!(generate_default().len(), 17);
    }

    #[test]
    fn short_length_errors() {
        assert!(matches!(generate(0).unwrap_err(), SiwxError::InvalidNonce { .. }));
        assert!(matches!(generate(7).unwrap_err(), SiwxError::InvalidNonce { .. }));
    }
}
