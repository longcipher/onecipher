//! TOTP (RFC 6238) and HOTP (RFC 4226) code generation from otpauth URIs
//! or raw base32 secrets.
//!
//! This module is the single source of truth for OTP: URI building, parsing,
//! code generation and verification all live here, and the CLI only passes
//! arguments through. Short real-world seeds (80/96-bit, below the RFC
//! 128-bit recommendation) are accepted via the lenient RFC 6238 core with
//! bare-base32 defaults (SHA-1, 6 digits, 30s period) — no caller needs a
//! local fallback.
//!
//! Uses the `totp-rs` crate for the strict path. Per R56, no async runtime
//! is involved — OTP generation is a pure CPU operation (HMAC over a counter).

// The dependency `totp-rs` also exposes a `TotpError` type; rename it on import
// to avoid a clash with the local `TotpError` defined below.
use totp_rs::{Algorithm, Builder, Totp, TotpError as TotpRsError};
use zeroize::Zeroizing;

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

impl From<TotpRsError> for TotpError {
    fn from(e: TotpRsError) -> Self {
        Self::InvalidUri(e.to_string())
    }
}

/// Default TOTP parameters: SHA-1, 6 digits, 30-second step.
const DEFAULT_DIGITS: usize = 6;
const DEFAULT_STEP: u64 = 30;
const DEFAULT_SKEW: u8 = 1;

/// Seeds below this length (128 bits) take the lenient RFC 6238 core with
/// bare-base32 defaults instead of the strict `totp-rs` builder, so
/// real-world 80/96-bit secrets are accepted rather than refused.
const STRICT_MIN_SEED_LEN: usize = 16;

/// Generate the current TOTP code from an `otpauth://` URI.
///
/// The URI must follow the standard format:
/// `otpauth://totp/<issuer>:<account>?secret=<base32>&issuer=<issuer>&digits=6&period=30`
///
/// Lenient: explicit `algorithm=` / `digits=` / `period=` parameters are
/// honored, absent ones take the bare-seed defaults (SHA-1, 6 digits, 30s),
/// and short (<128-bit) but otherwise well-formed seeds are accepted.
pub fn generate_totp(otpauth_uri: &str) -> Result<String, TotpError> {
    if let Ok(totp) = Totp::from_url(otpauth_uri) {
        return Ok(totp.generate_current().to_string());
    }
    // Strict parser rejected the URI (typically a short seed): retry through
    // the lenient core, which reports the real problem for garbage input.
    let now = unix_now()?;
    generate_totp_at(otpauth_uri, now)
}

/// Generate the current TOTP code from a raw base32-encoded secret.
///
/// Uses default parameters: SHA-1 algorithm, 6 digits, 30-second step.
/// The `issuer` and `account` are informational and stored in the TOTP
/// struct for URI generation. Short (80/96-bit) seeds are accepted via the
/// lenient core.
pub fn generate_totp_from_secret(
    base32_secret: &str,
    issuer: &str,
    account: &str,
) -> Result<String, TotpError> {
    let mut secret = base32_decode(base32_secret)
        .map_err(|e| TotpError::InvalidSecret(format!("base32 decode failed: {e}")))?;
    if secret.len() < STRICT_MIN_SEED_LEN {
        let now = unix_now()?;
        return generate_counter_code(&secret, Algorithm::SHA1, DEFAULT_DIGITS, now / DEFAULT_STEP);
    }
    let totp = Builder::new()
        .with_algorithm(Algorithm::SHA1)
        .with_digits(DEFAULT_DIGITS as u8)
        .with_skew(u16::from(DEFAULT_SKEW))
        .with_step_duration(DEFAULT_STEP)
        // Single ownership-release boundary into totp-rs (see `take_seed`).
        .with_secret(take_seed(&mut secret))
        .with_issuer(Some(issuer.to_string()))
        .with_account_name(account.to_string())
        .build()
        .map_err(|e| TotpError::Generation(e.to_string()))?;
    Ok(totp.generate_current().to_string())
}

/// Build an `otpauth://` URI from a base32 secret, issuer, and account name.
///
/// The resulting URI can be used to generate TOTP codes via
/// [`generate_totp`] or imported into authenticator apps. Always pins SHA-1
/// / 6 digits / 30s period (the bare-base32 defaults); short (80/96-bit)
/// seeds are accepted.
pub fn build_otpauth_uri(secret: &str, issuer: &str, account: &str) -> Result<String, TotpError> {
    let normalized = normalize_base32_secret(secret)?;
    let decoded = base32_decode(&normalized)
        .map_err(|e| TotpError::InvalidSecret(format!("base32 decode failed: {e}")))?;
    if decoded.len() >= STRICT_MIN_SEED_LEN {
        let mut owned = decoded;
        let totp = Builder::new()
            .with_algorithm(Algorithm::SHA1)
            .with_digits(DEFAULT_DIGITS as u8)
            .with_skew(u16::from(DEFAULT_SKEW))
            .with_step_duration(DEFAULT_STEP)
            // Single ownership-release boundary into totp-rs (see `take_seed`).
            .with_secret(take_seed(&mut owned))
            .with_issuer(Some(issuer.to_string()))
            .with_account_name(account.to_string())
            .build()
            .map_err(|e| TotpError::Generation(e.to_string()))?;
        return totp.to_url().map_err(|e| TotpError::Generation(e.to_string()));
    }
    // Short seed: build locally with the same pinned parameters.
    Ok(build_lenient_uri(&normalized, issuer, account))
}

/// Normalize user-supplied base32: uppercase, strip padding and whitespace,
/// reject invalid characters and empty seeds. Returns the canonical form
/// stored in `otpauth://` URIs.
pub fn normalize_base32_secret(input: &str) -> Result<String, TotpError> {
    let compact: String = input.chars().filter(|c| !c.is_whitespace() && *c != '=').collect();
    if compact.is_empty() {
        return Err(TotpError::InvalidSecret("empty base32 secret".to_string()));
    }
    let upper = compact.to_ascii_uppercase();
    if !upper.chars().all(|c| matches!(c, 'A'..='Z' | '2'..='7')) {
        return Err(TotpError::InvalidSecret("invalid base32 character".to_string()));
    }
    let decoded = base32_decode(&upper)
        .map_err(|e| TotpError::InvalidSecret(format!("base32 decode failed: {e}")))?;
    if decoded.is_empty() {
        return Err(TotpError::InvalidSecret("empty base32 secret".to_string()));
    }
    Ok(upper)
}

/// Best-effort extraction of issuer and account from an `otpauth://` URI.
///
/// The standard label format is `<issuer>:<account>` (or a bare account).
/// Also checks the `issuer=` query parameter as a fallback. Returns
/// `(Some(issuer), Some(account))` when both can be extracted, otherwise
/// whatever is available.
pub fn extract_issuer_account(uri: &str) -> (Option<String>, Option<String>) {
    let label = uri
        .strip_prefix("otpauth://")
        .and_then(|rest| rest.split_once('/'))
        .and_then(|(_, path_query)| path_query.split('?').next())
        .unwrap_or("");

    let (issuer, account) = if let Some((iss, acc)) = label.split_once(':') {
        (Some(iss.to_string()), Some(acc.to_string()))
    } else if !label.is_empty() {
        (None, Some(label.to_string()))
    } else {
        (None, None)
    };

    let issuer = issuer.or_else(|| {
        uri.split('?').nth(1).and_then(|query| {
            query.split('&').find_map(|kv| kv.strip_prefix("issuer=").map(|s| s.to_string()))
        })
    });

    (issuer, account)
}

/// Generate an HOTP code (RFC 4226) from an `otpauth://` URI and a counter.
///
/// The URI must follow the standard format:
/// `otpauth://hotp/<issuer>:<account>?secret=<base32>&issuer=<issuer>&digits=6&counter=0`
///
/// HOTP differs from TOTP in that the counter is caller-managed rather than
/// derived from the system clock.
///
/// Lenient: an `otpauth://totp/` URI (what `totp add` stores) is also
/// accepted — the counter runs over the same seed with the URI's parameters.
pub fn generate_hotp(otpauth_uri: &str, counter: u64) -> Result<String, TotpError> {
    match parse_hotp_uri(otpauth_uri) {
        Ok((algorithm, digits, mut secret)) => {
            generate_hotp_code(&algorithm, digits, &mut secret, counter)
        }
        Err(TotpError::InvalidUri(_)) => generate_hotp_from_totp_uri(otpauth_uri, counter),
        Err(other) => Err(other),
    }
}

/// Generate an HOTP code (RFC 4226 counter mode) from an `otpauth://totp/`
/// URI and a counter.
///
/// Parses the totp URI with bare-seed defaults (SHA-1, 6 digits, 30s; the
/// period is ignored) and runs counter mode over the seed. Used when the
/// strict HOTP parser rejects the stored URI — always the case for
/// `totp add` entries (totp scheme) — and for short seeds.
pub fn generate_hotp_from_totp_uri(otpauth_uri: &str, counter: u64) -> Result<String, TotpError> {
    let params = parse_totp_params(otpauth_uri)?;
    if !(6..=8).contains(&params.digits) {
        return Err(TotpError::InvalidUri(format!(
            "unsupported digits: {} (expected 6-8)",
            params.digits
        )));
    }
    generate_counter_code(&params.seed, params.algorithm, params.digits, counter)
}

/// Deterministic TOTP core (RFC 6238 section 4): the counter derives from an
/// explicit unix timestamp instead of the clock, so tests pin vectors exactly.
///
/// Honors explicit `algorithm=` / `digits=` / `period=` URI parameters;
/// absent ones take the bare-seed defaults. Short seeds are accepted.
pub fn generate_totp_at(otpauth_uri: &str, now_secs: u64) -> Result<String, TotpError> {
    let params = parse_totp_params(otpauth_uri)?;
    if !(6..=8).contains(&params.digits) {
        return Err(TotpError::InvalidUri(format!(
            "unsupported digits: {} (expected 6-8)",
            params.digits
        )));
    }
    if params.period == 0 {
        return Err(TotpError::InvalidUri("period must not be zero".to_string()));
    }
    generate_counter_code(&params.seed, params.algorithm, params.digits, now_secs / params.period)
}

/// Verify a TOTP code against an `otpauth://` URI, accepting codes from
/// `allowed_skew_steps` steps on either side of the current step.
///
/// Returns `Ok(true)` on match, `Ok(false)` on mismatch (wrong code is not
/// an error). Short seeds are accepted.
pub fn verify_totp(
    otpauth_uri: &str,
    code: &str,
    allowed_skew_steps: u64,
) -> Result<bool, TotpError> {
    let now = unix_now()?;
    verify_totp_at(otpauth_uri, code, allowed_skew_steps, now)
}

/// Deterministic [`verify_totp`] with an explicit timestamp (for tests).
pub fn verify_totp_at(
    otpauth_uri: &str,
    code: &str,
    allowed_skew_steps: u64,
    now_secs: u64,
) -> Result<bool, TotpError> {
    let params = parse_totp_params(otpauth_uri)?;
    if !(6..=8).contains(&params.digits) {
        return Err(TotpError::InvalidUri(format!(
            "unsupported digits: {} (expected 6-8)",
            params.digits
        )));
    }
    if params.period == 0 {
        return Err(TotpError::InvalidUri("period must not be zero".to_string()));
    }
    let want = code.trim();
    let counter = now_secs / params.period;
    let start = counter.saturating_sub(allowed_skew_steps);
    let end = counter.saturating_add(allowed_skew_steps);
    let mut step = start;
    loop {
        let candidate = generate_counter_code(&params.seed, params.algorithm, params.digits, step)?;
        if candidate.as_str() == want {
            return Ok(true);
        }
        if step == end {
            break;
        }
        step = step.saturating_add(1);
    }
    Ok(false)
}

/// Generate an HOTP code from a raw base32-encoded secret and a counter.
///
/// Uses default parameters: SHA-1 algorithm, 6 digits.
pub fn generate_hotp_from_secret(base32_secret: &str, counter: u64) -> Result<String, TotpError> {
    let mut secret = base32_decode(base32_secret)
        .map_err(|e| TotpError::InvalidSecret(format!("base32 decode failed: {e}")))?;
    generate_hotp_code(&Algorithm::SHA1, DEFAULT_DIGITS, &mut secret, counter)
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
    secret: &mut Zeroizing<Vec<u8>>,
    counter: u64,
) -> Result<String, TotpError> {
    // step=1 and skew=0: `generate(time)` computes HMAC over `time / 1 = time`,
    // which is exactly the HOTP counter as a big-endian u64.
    let totp = Builder::new()
        .with_algorithm(*algorithm)
        .with_digits(digits as u8)
        .with_skew(0u16) // skew: not meaningful for HOTP
        .with_step_duration(1) // step: 1 so counter maps directly
        // Single ownership-release boundary into totp-rs (see `take_seed`);
        // also removes the previous extra plaintext copy via `to_vec`.
        .with_secret(take_seed(secret))
        .build_noncompliant();
    Ok(totp.generate(counter).to_string())
}

/// Parse an `otpauth://hotp/` URI into its component parts.
///
/// Returns `(algorithm, digits, secret_bytes)`; the decoded seed is wrapped
/// in [`Zeroizing`] and must be released only via [`take_seed`] at the
/// `totp-rs` builder boundary.
///
/// Does manual parsing to avoid depending on the `url` crate directly
/// (it is a transitive dependency via `totp-rs` but not re-exported).
fn parse_hotp_uri(uri: &str) -> Result<(Algorithm, usize, Zeroizing<Vec<u8>>), TotpError> {
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
    let mut secret = Zeroizing::new(Vec::new());

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

/// Parsed `otpauth://totp/` parameters for the lenient core.
struct TotpParams {
    seed: Zeroizing<Vec<u8>>,
    algorithm: Algorithm,
    digits: usize,
    period: u64,
}

/// Parse `otpauth://totp/` query parameters into seed, algorithm, digits and
/// period. Missing parameters take the bare-seed defaults (SHA-1, 6 digits,
/// 30s). Rejects non-totp schemes and missing/empty secrets. Short seeds are
/// accepted: length is the caller's concern, not the parser's.
fn parse_totp_params(uri: &str) -> Result<TotpParams, TotpError> {
    let rest = uri
        .strip_prefix("otpauth://")
        .ok_or_else(|| TotpError::InvalidUri(format!("expected otpauth:// scheme in: {uri}")))?;
    let (host, path_query) = rest
        .split_once('/')
        .ok_or_else(|| TotpError::InvalidUri(format!("invalid otpauth URI: {uri}")))?;
    if host != "totp" {
        return Err(TotpError::InvalidUri(format!(
            "expected otpauth://totp/, got otpauth://{host}/"
        )));
    }
    let query = path_query.split_once('?').map(|(_, q)| q).ok_or_else(|| {
        TotpError::InvalidUri("missing query parameters (secret is required)".to_string())
    })?;

    let mut algorithm = Algorithm::SHA1;
    let mut digits = DEFAULT_DIGITS;
    let mut period = DEFAULT_STEP;
    let mut seed: Option<Zeroizing<Vec<u8>>> = None;
    for pair in query.split('&') {
        let Some((key, value)) = pair.split_once('=') else { continue };
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
            "period" => {
                period = value
                    .parse::<u64>()
                    .map_err(|_| TotpError::InvalidUri(format!("invalid period: {value}")))?;
            }
            "secret" => {
                seed =
                    Some(base32_decode(&percent_decode(value)).map_err(|e| {
                        TotpError::InvalidSecret(format!("base32 decode failed: {e}"))
                    })?);
            }
            _ => {}
        }
    }
    let seed = seed.filter(|s| !s.is_empty()).ok_or_else(|| {
        TotpError::InvalidSecret("missing or empty 'secret' query parameter".to_string())
    })?;
    Ok(TotpParams { seed, algorithm, digits, period })
}

/// HOTP core (RFC 4226 section 5.3) over an explicit counter: HMAC over the
/// big-endian counter followed by dynamic truncation. Shared by the TOTP and
/// HOTP lenient paths.
fn generate_counter_code(
    seed: &[u8],
    algorithm: Algorithm,
    digits: usize,
    counter: u64,
) -> Result<String, TotpError> {
    let digest = hmac_digest(algorithm, seed, &counter.to_be_bytes())?;
    truncate_code(&digest, digits)
}

/// HMAC dispatch over the supported hash functions.
///
/// Infallible in practice (`Hmac::new_from_slice` accepts any key length);
/// the `Result` only forwards the constructor's typed error.
fn hmac_digest(algorithm: Algorithm, key: &[u8], message: &[u8]) -> Result<Vec<u8>, TotpError> {
    use hmac::{KeyInit, Mac};
    match algorithm {
        Algorithm::SHA1 => {
            let mut mac = hmac::Hmac::<sha1::Sha1>::new_from_slice(key)
                .map_err(|e| TotpError::Generation(format!("HMAC init failed: {e}")))?;
            mac.update(message);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        Algorithm::SHA256 => {
            let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(key)
                .map_err(|e| TotpError::Generation(format!("HMAC init failed: {e}")))?;
            mac.update(message);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        Algorithm::SHA512 => {
            let mut mac = hmac::Hmac::<sha2::Sha512>::new_from_slice(key)
                .map_err(|e| TotpError::Generation(format!("HMAC init failed: {e}")))?;
            mac.update(message);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        // `totp_rs::Algorithm` is non-exhaustive (future hash support).
        _ => Err(TotpError::Generation("unsupported OTP hash algorithm".to_string())),
    }
}

/// Dynamic truncation (RFC 4226 section 5.3): offset from the low nibble of
/// the last hash byte, 31-bit code, zero-padded to `digits`.
fn truncate_code(hash: &[u8], digits: usize) -> Result<String, TotpError> {
    if !(6..=8).contains(&digits) {
        return Err(TotpError::InvalidUri(format!("unsupported digits: {digits} (expected 6-8)")));
    }
    if hash.len() < 20 {
        return Err(TotpError::Generation("HMAC output too short".to_string()));
    }
    let offset = (hash[hash.len() - 1] & 0x0f) as usize;
    if offset + 4 > hash.len() {
        return Err(TotpError::Generation("truncation offset out of range".to_string()));
    }
    let code = ((u32::from(hash[offset]) & 0x7f) << 24) |
        (u32::from(hash[offset + 1]) << 16) |
        (u32::from(hash[offset + 2]) << 8) |
        u32::from(hash[offset + 3]);
    let modulo = 10u32.pow(digits as u32);
    Ok(format!("{:0width$}", code % modulo, width = digits))
}

/// Build an `otpauth://totp/` URI with pinned bare-seed defaults, without
/// the strict builder's 128-bit length floor.
///
/// `normalized_secret` must already be canonical (see
/// [`normalize_base32_secret`]).
fn build_lenient_uri(normalized_secret: &str, issuer: &str, account: &str) -> String {
    format!(
        "otpauth://totp/{}:{}?secret={normalized_secret}&issuer={}&digits={DEFAULT_DIGITS}&period={DEFAULT_STEP}",
        percent_encode(issuer),
        percent_encode(account),
        percent_encode(issuer),
    )
}

/// Current unix timestamp in seconds for TOTP counters.
fn unix_now() -> Result<u64, TotpError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| TotpError::Generation(format!("system clock before epoch: {e}")))
}

/// Minimal percent-decoding for URI query values.
///
/// Decoded octets are accumulated into a byte buffer and interpreted as UTF-8
/// only once, at the end. Decoding byte-at-a-time via `char::from(u8)` would
/// map each octet to the Latin-1 code point of the same value, corrupting any
/// multi-byte UTF-8 sequence (e.g. a CJK or emoji issuer/account label).
///
/// Malformed escapes are handled leniently (a truncated `%` tail and non-hex
/// digits both decode as if the missing nibbles were `0`), matching the
/// previous behaviour. Byte sequences that are not valid UTF-8 are replaced
/// with U+FFFD.
fn percent_decode(s: &str) -> String {
    let mut buf: Vec<u8> = Vec::with_capacity(s.len());
    let mut bytes = s.bytes();
    while let Some(b) = bytes.next() {
        if b == b'%' {
            let hi = bytes.next().unwrap_or(b'0');
            let lo = bytes.next().unwrap_or(b'0');
            buf.push(hex_val(hi) << 4 | hex_val(lo));
        } else if b == b'+' {
            buf.push(b' ');
        } else {
            buf.push(b);
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
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

/// Release a decoded OTP seed from its [`Zeroizing`] guard at the single
/// ownership-transfer boundary into `totp-rs`.
///
/// `Builder::with_secret` takes ownership of a plain `Vec<u8>`, so the
/// guarded buffer must be handed over rather than copied. [`std::mem::take`]
/// swaps an empty vector into the guard (making its later drop a no-op) and
/// yields the original buffer for the builder to consume. Do not copy or
/// clone the seed out of its guard anywhere else.
fn take_seed(secret: &mut Zeroizing<Vec<u8>>) -> Vec<u8> {
    std::mem::take(&mut *secret)
}

/// Decode a base32-encoded string (RFC 4648, no padding required).
///
/// The decoded seed is returned in a [`Zeroizing`] buffer that is wiped on
/// drop. Callers pass it into `totp-rs` only through [`take_seed`].
///
/// `totp-rs` uses `constant_time_eq`'s base32 under the hood, but we do a
/// manual uppercase + strip-padding approach for robustness.
fn base32_decode(input: &str) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    let upper = input.to_ascii_uppercase();
    let stripped = upper.trim_end_matches('=');
    let mut bits: u32 = 0;
    let mut bit_count: u32 = 0;
    let mut output = Zeroizing::new(Vec::with_capacity(stripped.len() * 5 / 8));

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
        assert_eq!(decoded.as_slice(), b"12345678901234567890".as_slice());
    }

    #[test]
    fn base32_decode_handles_lowercase() {
        let lower = TEST_SECRET_BASE32.to_ascii_lowercase();
        let decoded = base32_decode(&lower).unwrap();
        assert_eq!(decoded.as_slice(), b"12345678901234567890".as_slice());
    }

    #[test]
    fn base32_decode_handles_padding() {
        let padded = format!("{TEST_SECRET_BASE32}===");
        let decoded = base32_decode(&padded).unwrap();
        assert_eq!(decoded.as_slice(), b"12345678901234567890".as_slice());
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
    fn hotp_accepts_totp_uri_via_counter_mode() {
        // Unified handling plane: an otpauth://totp/ URI (what `totp add`
        // stores) is accepted as HOTP — the counter runs over the same seed.
        let uri =
            "otpauth://totp/TestIssuer:test@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        assert_eq!(generate_hotp(uri, 0).unwrap(), "755224");
        assert_eq!(generate_hotp(uri, 1).unwrap(), "287082");
    }

    /// Regression: decoding byte-at-a-time via `char::from(u8)` mapped each
    /// octet to the Latin-1 code point of the same value, so a multi-byte
    /// UTF-8 sequence came back mojibake'd ("中文" decoded as "ä¸­æ\u{96}\u{87}").
    #[test]
    fn percent_decode_multibyte_utf8() {
        assert_eq!(percent_decode("%E4%B8%AD%E6%96%87"), "中文");
        assert_eq!(percent_decode("%F0%9F%94%91"), "🔑");
        assert_eq!(percent_decode("caf%C3%A9"), "café");
    }

    #[test]
    fn percent_decode_ascii_and_plus() {
        assert_eq!(percent_decode("Alice%20Smith"), "Alice Smith");
        assert_eq!(percent_decode("a+b"), "a b");
        assert_eq!(percent_decode("plain"), "plain");
        assert_eq!(percent_decode(""), "");
    }

    #[test]
    fn percent_decode_roundtrips_percent_encode() {
        for original in ["中文用户@example.com", "test@example.com", "Ünïcodé Iss:uer", "🔑/key"]
        {
            assert_eq!(percent_decode(&percent_encode(original)), original);
        }
    }

    /// A truncated escape must stay lenient rather than panicking — the parser
    /// runs on untrusted URI input.
    #[test]
    fn percent_decode_malformed_escape_is_lenient() {
        let _ = percent_decode("%");
        let _ = percent_decode("%A");
        let _ = percent_decode("%ZZ");
        assert_eq!(percent_decode("ok%"), "ok\0");
    }

    /// Bytes that are not valid UTF-8 become U+FFFD instead of corrupting the
    /// surrounding text.
    #[test]
    fn percent_decode_invalid_utf8_is_replaced() {
        assert_eq!(percent_decode("%FF"), "\u{FFFD}");
        assert_eq!(percent_decode("a%FFb"), "a\u{FFFD}b");
    }

    // RFC 6238 Appendix B seeds (ASCII, 8-digit codes expected).
    const RFC6238_SHA1_SEED: &[u8] = b"12345678901234567890";
    const RFC6238_SHA256_SEED: &[u8] = b"12345678901234567890123456789012";
    const RFC6238_SHA512_SEED: &[u8] =
        b"1234567890123456789012345678901234567890123456789012345678901234";

    fn rfc6238_uri(seed: &[u8], algorithm: &str) -> String {
        format!(
            "otpauth://totp/Test:alice?secret={}&issuer=Test&algorithm={algorithm}&digits=8&period=30",
            base32_encode(seed)
        )
    }

    #[test]
    fn rfc6238_sha1_vectors() {
        // RFC 6238 Appendix B, SHA-1, 8 digits. Counter = floor(time / 30).
        let uri = rfc6238_uri(RFC6238_SHA1_SEED, "SHA1");
        for (time, want) in [
            (59u64, "94287082"),
            (1_111_111_109, "07081804"),
            (1_111_111_111, "14050471"),
            (1_234_567_890, "89005924"),
            (2_000_000_000, "69279037"),
            (20_000_000_000, "65353130"),
        ] {
            assert_eq!(generate_totp_at(&uri, time).unwrap(), want, "T={time}");
        }
    }

    #[test]
    fn rfc6238_sha256_vectors() {
        let uri = rfc6238_uri(RFC6238_SHA256_SEED, "SHA256");
        for (time, want) in [
            (59u64, "46119246"),
            (1_111_111_109, "68084774"),
            (1_111_111_111, "67062674"),
            (1_234_567_890, "91819424"),
            (2_000_000_000, "90698825"),
            (20_000_000_000, "77737706"),
        ] {
            assert_eq!(generate_totp_at(&uri, time).unwrap(), want, "T={time}");
        }
    }

    #[test]
    fn rfc6238_sha512_vectors() {
        let uri = rfc6238_uri(RFC6238_SHA512_SEED, "SHA512");
        for (time, want) in [
            (59u64, "90693936"),
            (1_111_111_109, "25091201"),
            (1_111_111_111, "99943326"),
            (1_234_567_890, "93441116"),
            (2_000_000_000, "38618901"),
            (20_000_000_000, "47863826"),
        ] {
            assert_eq!(generate_totp_at(&uri, time).unwrap(), want, "T={time}");
        }
    }

    #[test]
    fn rfc6238_sha1_matches_rfc4226_counter_vectors() {
        // T=0s -> counter 0 -> 755224; T=59s -> counter 1 -> 287082.
        let uri = format!(
            "otpauth://totp/Test:alice?secret={TEST_SECRET_BASE32}&issuer=Test&digits=6&period=30"
        );
        assert_eq!(generate_totp_at(&uri, 0).unwrap(), "755224");
        assert_eq!(generate_totp_at(&uri, 59).unwrap(), "287082");
    }

    // 80-bit ("1234567890") and 96-bit ("123456789012") real-world-style seeds.
    const SHORT80_B32: &str = "GEZDGNBVGY3TQOJQ";
    const SHORT96_B32: &str = "GEZDGNBVGY3TQOJQGEZA";

    #[test]
    fn lenient_api_accepts_80_and_96_bit_seeds() {
        for short in [SHORT80_B32, SHORT96_B32] {
            let decoded = base32_decode(short).unwrap();
            assert!(decoded.len() < STRICT_MIN_SEED_LEN, "test seed must stay short");
            // Bare-secret generation with defaults.
            let code = generate_totp_from_secret(short, TEST_ISSUER, TEST_ACCOUNT).unwrap();
            assert_eq!(code.len(), 6);
            assert!(code.chars().all(|c| c.is_ascii_digit()));
            // URI build pins SHA-1 / 6 digits / 30s and feeds generation.
            let uri = build_otpauth_uri(short, TEST_ISSUER, TEST_ACCOUNT).unwrap();
            assert!(uri.contains("digits=6"));
            assert!(uri.contains("period=30"));
            let code = generate_totp(&uri).unwrap();
            assert_eq!(code.len(), 6);
            // Counter mode over the totp-scheme URI (what `totp add` stores).
            let hotp = generate_hotp(&uri, 0).unwrap();
            assert_eq!(hotp.len(), 6);
            assert!(hotp.chars().all(|c| c.is_ascii_digit()));
        }
    }

    #[test]
    fn hotp_over_totp_uri_matches_rfc4226_vectors() {
        let uri = format!("otpauth://totp/Test:alice?secret={TEST_SECRET_BASE32}&issuer=Test");
        assert_eq!(generate_hotp(&uri, 0).unwrap(), "755224");
        assert_eq!(generate_hotp(&uri, 1).unwrap(), "287082");
    }

    #[test]
    fn verify_accepts_current_and_skewed_codes() {
        let uri = format!(
            "otpauth://totp/Test:alice?secret={TEST_SECRET_BASE32}&issuer=Test&digits=6&period=30"
        );
        let code = generate_totp_at(&uri, 59).unwrap();
        assert!(verify_totp_at(&uri, &code, 0, 59).unwrap());
        // Adjacent step accepted only with skew.
        assert!(!verify_totp_at(&uri, &code, 0, 89).unwrap());
        assert!(verify_totp_at(&uri, &code, 1, 89).unwrap());
        assert!(!verify_totp_at(&uri, "000000", 1, 59).unwrap());
    }

    #[test]
    fn normalize_base32_canonicalizes_input() {
        assert_eq!(normalize_base32_secret("jbswy3dp ehpk3pxp====").unwrap(), "JBSWY3DPEHPK3PXP");
        assert!(normalize_base32_secret("not-valid-base32!!!").is_err());
        assert!(normalize_base32_secret("").is_err());
        assert!(normalize_base32_secret("==== ").is_err());
    }

    #[test]
    fn extract_issuer_account_from_full_uri() {
        let uri = "otpauth://totp/TestIssuer:test@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=TestIssuer&digits=6&period=30";
        let (issuer, account) = extract_issuer_account(uri);
        assert_eq!(issuer.as_deref(), Some("TestIssuer"));
        assert_eq!(account.as_deref(), Some("test@example.com"));
    }

    #[test]
    fn extract_issuer_account_query_fallback() {
        let uri = "otpauth://totp/test@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=QueryIssuer";
        let (issuer, account) = extract_issuer_account(uri);
        assert_eq!(issuer.as_deref(), Some("QueryIssuer"));
        assert_eq!(account.as_deref(), Some("test@example.com"));
    }
}
