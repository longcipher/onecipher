//! TOTP (RFC 6238) and HOTP (RFC 4226) code generation from otpauth URIs
//! or raw base32 secrets.
//!
//! Uses the `totp-rs` crate. Per R56, no async runtime is involved — OTP
//! generation is a pure CPU operation (HMAC-SHA1 over a counter).

use totp_rs::{Algorithm, TOTP, TotpUrlError};

/// Errors returned by OTP operations.
#[derive(Debug, thiserror::Error)]
pub enum TotpError {
    #[error("invalid otpauth URI: {0}")]
    InvalidUri(String),
    #[error("invalid base32 secret: {0}")]
    InvalidSecret(String),
    #[error("OTP generation failed: {0}")]
    Generation(String),
    #[error("HOTP error: {0}")]
    Hotp(String),
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

/// Generate an HOTP code (RFC 4226) from an `otpauth://` URI and a counter.
///
/// The URI must follow the standard format:
/// `otpauth://hotp/<issuer>:<account>?secret=<base32>&issuer=<issuer>&digits=6&counter=0`
///
/// HOTP differs from TOTP in that the counter is caller-managed rather than
/// derived from the system clock.
pub fn generate_hotp(otpauth_uri: &str, counter: u64) -> Result<String, TotpError> {
    let (algorithm, digits, secret) = parse_hotp_uri(otpauth_uri)?;
    generate_hotp_code(&algorithm, digits, &secret, counter)
}

/// Generate an HOTP code from a raw base32-encoded secret and a counter.
///
/// Uses default parameters: SHA-1 algorithm, 6 digits.
pub fn generate_hotp_from_secret(base32_secret: &str, counter: u64) -> Result<String, TotpError> {
    let secret = base32_decode(base32_secret)
        .map_err(|e| TotpError::InvalidSecret(format!("base32 decode failed: {e}")))?;
    generate_hotp_code(&Algorithm::SHA1, DEFAULT_DIGITS, &secret, counter)
}

/// Build an `otpauth://` URI for an HOTP secret from a base32 secret,
/// issuer, account name, and initial counter.
///
/// The resulting URI follows the `otpauth://hotp/` format and can be
/// imported into authenticator apps that support HOTP.
pub fn build_hotp_otpauth_uri(
    secret: &str,
    issuer: &str,
    account: &str,
    counter: u64,
) -> Result<String, TotpError> {
    let decoded = base32_decode(secret)
        .map_err(|e| TotpError::InvalidSecret(format!("base32 decode failed: {e}")))?;
    let secret_b32 = base32_encode(&decoded);
    // Minimal percent-encoding for the issuer/account in the label.
    let account_enc = percent_encode(account);
    let issuer_enc = percent_encode(issuer);
    Ok(format!(
        "otpauth://hotp/{issuer_enc}:{account_enc}?secret={secret_b32}&issuer={issuer_enc}&digits={DEFAULT_DIGITS}&counter={counter}"
    ))
}

/// Core HOTP code generation (RFC 4226, Section 5.3).
///
/// Implements the HOTP algorithm by reusing `totp-rs` internals with
/// `step = 1`, making `TOTP::generate(counter)` equivalent to HOTP since
/// the time-divided-by-step simplifies to just the counter value.
fn generate_hotp_code(
    algorithm: &Algorithm,
    digits: usize,
    secret: &[u8],
    counter: u64,
) -> Result<String, TotpError> {
    // step=1 and skew=0: `generate(time)` computes HMAC over `time / 1 = time`,
    // which is exactly the HOTP counter as a big-endian u64.
    let totp = TOTP::new_unchecked(
        *algorithm,
        digits,
        0, // skew: not meaningful for HOTP
        1, // step: 1 so counter maps directly
        secret.to_vec(),
        None,
        String::new(),
    );
    Ok(totp.generate(counter))
}

/// Parse an `otpauth://hotp/` URI into its component parts.
///
/// Returns `(algorithm, digits, secret_bytes)`.
///
/// Does manual parsing to avoid depending on the `url` crate directly
/// (it is a transitive dependency via `totp-rs` but not re-exported).
fn parse_hotp_uri(uri: &str) -> Result<(Algorithm, usize, Vec<u8>), TotpError> {
    // Strip scheme: otpauth://hotp/...
    let rest = uri
        .strip_prefix("otpauth://")
        .ok_or_else(|| TotpError::InvalidUri(format!("expected otpauth:// scheme in: {uri}")))?;

    let (host_part, path_and_query) = rest
        .split_once('/')
        .ok_or_else(|| TotpError::InvalidUri(format!("invalid otpauth URI: {uri}")))?;

    if host_part != "hotp" {
        return Err(TotpError::InvalidUri(format!(
            "expected otpauth://hotp/, got otpauth://{host_part}/"
        )));
    }

    // Split off query string.
    let (_label, query) = match path_and_query.split_once('?') {
        Some((l, q)) => (l, q),
        None => {
            return Err(TotpError::InvalidUri(
                "missing query parameters (secret is required)".into(),
            ));
        }
    };

    let mut algorithm = Algorithm::SHA1;
    let mut digits = DEFAULT_DIGITS;
    let mut secret = Vec::new();

    for pair in query.split('&') {
        let (key, value) = match pair.split_once('=') {
            Some((k, v)) => (k, percent_decode(v)),
            None => continue,
        };

        match key {
            "algorithm" => {
                algorithm = match value.to_uppercase().as_str() {
                    "SHA1" => Algorithm::SHA1,
                    "SHA256" => Algorithm::SHA256,
                    "SHA512" => Algorithm::SHA512,
                    other => {
                        return Err(TotpError::InvalidUri(format!(
                            "unsupported algorithm: {other}"
                        )));
                    }
                };
            }
            "digits" => {
                digits = value
                    .parse::<usize>()
                    .map_err(|_| TotpError::InvalidUri(format!("invalid digits: {value}")))?;
            }
            "secret" => {
                secret = base32_decode(&value)
                    .map_err(|e| TotpError::InvalidSecret(format!("base32 decode failed: {e}")))?;
            }
            "counter" => {
                // Counter is consumed externally; validate only.
                let _: u64 = value
                    .parse()
                    .map_err(|_| TotpError::InvalidUri(format!("invalid counter: {value}")))?;
            }
            _ => {}
        }
    }

    if secret.is_empty() {
        return Err(TotpError::InvalidSecret("missing 'secret' query parameter".into()));
    }

    Ok((algorithm, digits, secret))
}

/// Minimal percent-decoding for URI query values.
fn percent_decode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.bytes();
    while let Some(b) = chars.next() {
        if b == b'%' {
            let hi = chars.next().unwrap_or(b'0');
            let lo = chars.next().unwrap_or(b'0');
            let val = hex_val(hi) << 4 | hex_val(lo);
            result.push(val as char);
        } else if b == b'+' {
            result.push(' ');
        } else {
            result.push(b as char);
        }
    }
    result
}

/// Minimal percent-encoding for URI path/label components.
///
/// Encodes only characters that are reserved in the otpauth label
/// (`:`, `@`, `%`, `?`, `#`, `/`) and non-ASCII bytes.
fn percent_encode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                result.push(b as char);
            }
            _ => {
                result.push('%');
                result.push(HEX_TABLE[(b >> 4) as usize] as char);
                result.push(HEX_TABLE[(b & 0x0f) as usize] as char);
            }
        }
    }
    result
}

const HEX_TABLE: &[u8; 16] = b"0123456789ABCDEF";

fn hex_val(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

/// Encode bytes to base32 (RFC 4648, no padding).
fn base32_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut output = String::with_capacity((data.len() * 8).div_ceil(5));
    let mut bits: u32 = 0;
    let mut bit_count: u32 = 0;
    for &byte in data {
        bits = (bits << 8) | u32::from(byte);
        bit_count += 8;
        while bit_count >= 5 {
            bit_count -= 5;
            output.push(ALPHABET[((bits >> bit_count) & 0x1f) as usize] as char);
            bits &= (1 << bit_count) - 1;
        }
    }
    if bit_count > 0 {
        output.push(ALPHABET[((bits << (5 - bit_count)) & 0x1f) as usize] as char);
    }
    output
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

    // HOTP tests — RFC 4226 test vectors use secret "12345678901234567890" (ASCII).

    #[test]
    fn hotp_from_secret_returns_six_digit_code() {
        let code = generate_hotp_from_secret(TEST_SECRET_BASE32, 0).unwrap();
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn hotp_rfc4226_test_vector_counter_0() {
        // RFC 4226 Appendix D, counter 0 → 755224
        let code = generate_hotp_from_secret(TEST_SECRET_BASE32, 0).unwrap();
        assert_eq!(code, "755224");
    }

    #[test]
    fn hotp_rfc4226_test_vector_counter_1() {
        // RFC 4226 Appendix D, counter 1 → 287082
        let code = generate_hotp_from_secret(TEST_SECRET_BASE32, 1).unwrap();
        assert_eq!(code, "287082");
    }

    #[test]
    fn hotp_different_counters_produce_different_codes() {
        let code0 = generate_hotp_from_secret(TEST_SECRET_BASE32, 0).unwrap();
        let code1 = generate_hotp_from_secret(TEST_SECRET_BASE32, 1).unwrap();
        assert_ne!(code0, code1);
    }

    #[test]
    fn hotp_from_uri_round_trip() {
        let uri = build_hotp_otpauth_uri(TEST_SECRET_BASE32, TEST_ISSUER, TEST_ACCOUNT, 0).unwrap();
        assert!(uri.starts_with("otpauth://hotp/"));
        assert!(uri.contains("secret="));
        assert!(uri.contains("counter=0"));

        let code = generate_hotp(&uri, 0).unwrap();
        assert_eq!(code, "755224");
    }

    #[test]
    fn hotp_from_invalid_uri_fails() {
        let result = generate_hotp("https://example.com/not-otpauth", 0);
        assert!(matches!(result, Err(TotpError::InvalidUri(_))));
    }

    #[test]
    fn hotp_totp_uri_rejected() {
        // An otpauth://totp/ URI should not be accepted as HOTP.
        let uri =
            "otpauth://totp/TestIssuer:test@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let result = generate_hotp(uri, 0);
        assert!(matches!(result, Err(TotpError::InvalidUri(_))));
    }
}
