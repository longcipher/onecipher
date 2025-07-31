//! TOTP (RFC 6238) code generation from otpauth URIs or raw base32 secrets.
//!
//! Uses the `totp-rs` crate. Per R56, no async runtime is involved — TOTP
//! generation is a pure CPU operation (HMAC-SHA1 over the current time
//! counter).

use totp_rs::{Algorithm, TOTP, TotpUrlError};

/// Errors returned by TOTP operations.
#[derive(Debug, thiserror::Error)]
pub enum TotpError {
    #[error("invalid otpauth URI: {0}")]
    InvalidUri(String),
    #[error("invalid base32 secret: {0}")]
    InvalidSecret(String),
    #[error("TOTP generation failed: {0}")]
    Generation(String),
}

impl From<TotpUrlError> for TotpError {
    fn from(e: TotpUrlError) -> Self {
        Self::InvalidUri(e.to_string())
    }
}

/// Default TOTP parameters: SHA-1, 6 digits, 30-second step.
const DEFAULT_DIGITS: usize = 6;
const DEFAULT_STEP: u64 = 30;
const DEFAULT_SKEW: u8 = 1;

/// Generate the current TOTP code from an `otpauth://` URI.
///
/// The URI must follow the standard format:
/// `otpauth://totp/<issuer>:<account>?secret=<base32>&issuer=<issuer>&digits=6&period=30`
pub fn generate_totp(otpauth_uri: &str) -> Result<String, TotpError> {
    let totp = TOTP::from_url(otpauth_uri)?;
    totp.generate_current().map_err(|e| TotpError::Generation(e.to_string()))
}

/// Generate the current TOTP code from a raw base32-encoded secret.
///
/// Uses default parameters: SHA-1 algorithm, 6 digits, 30-second step.
/// The `issuer` and `account` are informational and stored in the TOTP
/// struct for URI generation.
pub fn generate_totp_from_secret(
    base32_secret: &str,
    issuer: &str,
    account: &str,
) -> Result<String, TotpError> {
    let secret = base32_decode(base32_secret)
        .map_err(|e| TotpError::InvalidSecret(format!("base32 decode failed: {e}")))?;
    let totp = TOTP::new(
        Algorithm::SHA1,
        DEFAULT_DIGITS,
        DEFAULT_SKEW,
        DEFAULT_STEP,
        secret,
        Some(issuer.to_string()),
        account.to_string(),
    )?;
    totp.generate_current().map_err(|e| TotpError::Generation(e.to_string()))
}

/// Build an `otpauth://` URI from a base32 secret, issuer, and account name.
///
/// The resulting URI can be used to generate TOTP codes via
/// [`generate_totp`] or imported into authenticator apps.
pub fn build_otpauth_uri(secret: &str, issuer: &str, account: &str) -> Result<String, TotpError> {
    let decoded = base32_decode(secret)
        .map_err(|e| TotpError::InvalidSecret(format!("base32 decode failed: {e}")))?;
    let totp = TOTP::new(
        Algorithm::SHA1,
        DEFAULT_DIGITS,
        DEFAULT_SKEW,
        DEFAULT_STEP,
        decoded,
        Some(issuer.to_string()),
        account.to_string(),
    )?;
    Ok(totp.get_url())
}

/// Decode a base32-encoded string (RFC 4648, no padding required).
///
/// `totp-rs` uses `constant_time_eq`'s base32 under the hood, but we do a
/// manual uppercase + strip-padding approach for robustness.
fn base32_decode(input: &str) -> Result<Vec<u8>, &'static str> {
    let upper = input.to_ascii_uppercase();
    let stripped = upper.trim_end_matches('=');
    let mut bits: u32 = 0;
    let mut bit_count: u32 = 0;
    let mut output = Vec::with_capacity(stripped.len() * 5 / 8);

    for c in stripped.chars() {
        let val = match c {
            'A'..='Z' => (c as u32) - ('A' as u32),
            '2'..='7' => (c as u32) - ('2' as u32) + 26,
            _ => return Err("invalid base32 character"),
        };
        bits = (bits << 5) | val;
        bit_count += 5;
        if bit_count >= 8 {
            bit_count -= 8;
            output.push((bits >> bit_count) as u8);
            bits &= (1 << bit_count) - 1;
        }
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vector from RFC 6238: secret "12345678901234567890" (ASCII),
    // base32-encoded as "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".
    const TEST_SECRET_BASE32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    const TEST_ISSUER: &str = "TestIssuer";
    const TEST_ACCOUNT: &str = "test@example.com";

    #[test]
    fn generate_from_secret_returns_six_digit_code() {
        let code =
            generate_totp_from_secret(TEST_SECRET_BASE32, TEST_ISSUER, TEST_ACCOUNT).unwrap();
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn build_uri_and_generate_round_trip() {
        let uri = build_otpauth_uri(TEST_SECRET_BASE32, TEST_ISSUER, TEST_ACCOUNT).unwrap();
        assert!(uri.starts_with("otpauth://totp/"));
        assert!(uri.contains("secret="));
        assert!(uri.contains(TEST_ISSUER));

        // Should be able to generate from the built URI.
        let code = generate_totp(&uri).unwrap();
        assert_eq!(code.len(), 6);
    }

    #[test]
    fn generate_from_invalid_secret_fails() {
        let result = generate_totp_from_secret("not-valid-base32!", "i", "a");
        assert!(matches!(result, Err(TotpError::InvalidSecret(_))));
    }

    #[test]
    fn generate_from_invalid_uri_fails() {
        let result = generate_totp("https://example.com/not-otpauth");
        assert!(matches!(result, Err(TotpError::InvalidUri(_))));
    }

    #[test]
    fn base32_decode_rfc_vector() {
        // "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" decodes to "12345678901234567890"
        let decoded = base32_decode(TEST_SECRET_BASE32).unwrap();
        assert_eq!(decoded, b"12345678901234567890");
    }

    #[test]
    fn base32_decode_handles_lowercase() {
        let lower = TEST_SECRET_BASE32.to_ascii_lowercase();
        let decoded = base32_decode(&lower).unwrap();
        assert_eq!(decoded, b"12345678901234567890");
    }

    #[test]
    fn base32_decode_handles_padding() {
        let padded = format!("{TEST_SECRET_BASE32}===");
        let decoded = base32_decode(&padded).unwrap();
        assert_eq!(decoded, b"12345678901234567890");
    }

    #[test]
    fn consecutive_codes_may_differ() {
        // Just verify we can call generate twice without error.
        let code1 =
            generate_totp_from_secret(TEST_SECRET_BASE32, TEST_ISSUER, TEST_ACCOUNT).unwrap();
        let code2 =
            generate_totp_from_secret(TEST_SECRET_BASE32, TEST_ISSUER, TEST_ACCOUNT).unwrap();
        // Both should be 6-digit strings (they'll be equal within the same 30s window).
        assert_eq!(code1.len(), 6);
        assert_eq!(code2.len(), 6);
    }
}
