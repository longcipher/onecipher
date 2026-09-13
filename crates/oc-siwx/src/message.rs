//! CAIP-122 abstract data model.
//!
//! [`SiwxMessage`] is the chain-agnostic struct mirroring the CAIP-122 data
//! model. Parsing lives in [`crate::parser`], formatting in
//! [`crate::formatter`], validation in [`crate::validate`].
//!
//! Time handling uses [`jiff::Timestamp`] (the workspace standard) instead of
//! the `time` crate; the original RFC 3339 lexical form is still preserved
//! verbatim so re-hashing stays byte-exact.

use std::str::FromStr;

use iri_string::{spec::UriSpec, types::UriString, validate::authority};

use crate::{
    error::{ChainIdReason, FormatReason, SiwxError},
    parser::PREAMBLE_MID,
};

/// CAIP-122 message version (EIP-4361 / CAIP-122 mandate `"1"`).
pub const VERSION: &str = "1";

/// Minimum nonce length.
pub const MIN_NONCE_LEN: usize = 8;

/// Maximum accepted signing-message size in bytes (denial-of-service bound).
pub const MAX_MESSAGE_BYTES: usize = 16_384;

/// Maximum number of entries in the `Resources` list.
pub const MAX_RESOURCES: usize = 32;

/// Maximum accepted `statement` size in bytes.
pub const MAX_STATEMENT_BYTES: usize = 4_096;

/// Maximum accepted `request_id` size in bytes.
pub const MAX_REQUEST_ID_BYTES: usize = 128;

/// Maximum accepted URI size in bytes (`uri` and each resource).
pub const MAX_URI_BYTES: usize = 2_048;

/// RFC 3339 `date-time` that preserves the original lexical form.
///
/// [`Eq`] requires the same original string **and** the same instant. A
/// builder `2021-09-30T16:25:24Z` is not equal to a parsed
/// `2021-09-30T16:25:24.000Z`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Timestamp {
    parsed: jiff::Timestamp,
    original: String,
}

impl Timestamp {
    /// Parse an RFC 3339 date-time, keeping `s` verbatim as the original.
    ///
    /// The value must contain `T`/`t` (space separators are rejected) and a
    /// timezone `Z`/`z`/`±HH:MM`. Fractional seconds are allowed and not
    /// normalized.
    pub fn parse(s: &str) -> Result<Self, SiwxError> {
        if !s.contains('T') && !s.contains('t') {
            return Err(SiwxError::InvalidTimestamp {
                reason: "must contain T date-time separator".to_owned(),
            });
        }
        if !has_rfc3339_timezone(s) {
            return Err(SiwxError::InvalidTimestamp {
                reason: "must have timezone Z or ±HH:MM".to_owned(),
            });
        }
        let parsed = jiff::Timestamp::from_str(s)
            .map_err(|e| SiwxError::InvalidTimestamp { reason: e.to_string() })?;
        Ok(Self { parsed, original: s.to_owned() })
    }

    /// Build from an instant. `original` is `t` formatted as RFC 3339.
    pub fn from_instant(t: jiff::Timestamp) -> Result<Self, SiwxError> {
        let original = t.to_string();
        // Round-trip sanity: the formatted form must parse back to the same
        // instant (guards against future Display format changes).
        let reparsed = jiff::Timestamp::from_str(&original)
            .map_err(|e| SiwxError::InvalidTimestamp { reason: e.to_string() })?;
        if reparsed != t {
            return Err(SiwxError::InvalidTimestamp {
                reason: "timestamp round-trip mismatch".to_owned(),
            });
        }
        Ok(Self { parsed: t, original })
    }

    /// Instant represented by this timestamp.
    #[must_use]
    pub const fn datetime(&self) -> jiff::Timestamp {
        self.parsed
    }

    /// Original RFC 3339 lexical form (formatter input).
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.original
    }
}

impl serde::Serialize for Timestamp {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.original)
    }
}

impl<'de> serde::Deserialize<'de> for Timestamp {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <String as serde::Deserialize>::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// Application-JSON DTO. [`TryFrom`] runs the same `check_*` path as builders.
#[derive(serde::Deserialize)]
struct SiwxMessageDto {
    #[serde(default)]
    scheme: Option<String>,
    domain: String,
    address: String,
    #[serde(default)]
    statement: Option<String>,
    uri: String,
    version: String,
    chain_id: String,
    #[serde(default)]
    chain_name: Option<String>,
    nonce: String,
    issued_at: Timestamp,
    #[serde(default)]
    expiration_time: Option<Timestamp>,
    #[serde(default)]
    not_before: Option<Timestamp>,
    #[serde(default)]
    request_id: Option<String>,
    #[serde(default)]
    resources: Vec<String>,
}

/// CAIP-122 Sign-In with X message.
///
/// Chain-agnostic; chain-specific verification lives in `oc-signer`
/// (`EvmVerifier` / `SolanaVerifier`) and, for contract/counterfactual
/// accounts, in `oc-netagent` (`RpcVerifier`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "SiwxMessageDto")]
pub struct SiwxMessage {
    /// Optional scheme for the preamble (`"{scheme}://{domain} wants you…"`).
    #[serde(default)]
    scheme: Option<String>,

    /// Authority requesting the signing.
    domain: String,

    /// Blockchain address performing the signing (CAIP-10 `account_address`
    /// segment — does **not** include the CAIP-2 chain id prefix).
    address: String,

    /// Human-readable assertion. When present, non-empty RFC 3986 `reserved` /
    /// `unreserved` / SP (no HT, CR, LF, other CTL, or non-ASCII).
    #[serde(default)]
    statement: Option<String>,

    /// URI referring to the resource that is the subject of the signing.
    uri: String,

    /// Current version of the message (always [`VERSION`]).
    version: String,

    /// Chain identifier — the `reference` segment of a CAIP-2 chain id.
    ///
    /// For EIP-155 chains this is the decimal chain id (e.g. `"1"`).
    /// For Solana this is the genesis hash.
    chain_id: String,

    /// Preamble chain label (`"Ethereum"`, `"Solana"`).
    ///
    /// Set by parse; [`Self::new`] leaves this `None`. Formatting still takes
    /// the verifier chain name as an argument, not this field.
    #[serde(default)]
    chain_name: Option<String>,

    /// Randomised token to prevent replay attacks (≥ [`MIN_NONCE_LEN`]).
    nonce: String,

    /// Issuance time (original lexical form preserved).
    issued_at: Timestamp,

    /// Expiration time.
    #[serde(default)]
    expiration_time: Option<Timestamp>,

    /// Earliest valid time.
    #[serde(default)]
    not_before: Option<Timestamp>,

    /// System-specific request identifier.
    #[serde(default)]
    request_id: Option<String>,

    /// List of URI resources.
    #[serde(default)]
    resources: Vec<String>,
}

impl TryFrom<SiwxMessageDto> for SiwxMessage {
    type Error = SiwxError;

    fn try_from(dto: SiwxMessageDto) -> Result<Self, Self::Error> {
        let scheme = dto.scheme.map(|s| check_scheme(&s)).transpose()?;
        let domain = check_domain(&dto.domain)?;
        if dto.address.is_empty() {
            return Err(SiwxError::InvalidAddress { reason: "empty".to_owned() });
        }
        if let Some(ref statement) = dto.statement {
            check_statement(statement)?;
        }
        let uri = check_uri(&dto.uri)?;
        if dto.version != VERSION {
            return Err(SiwxError::InvalidFormat { reason: FormatReason::VersionNotOne });
        }
        if dto.chain_id.is_empty() {
            return Err(SiwxError::InvalidChainId { reason: ChainIdReason::Empty });
        }
        let nonce = check_nonce_shape(&dto.nonce)?;
        let request_id = dto.request_id.map(|rid| check_request_id(&rid)).transpose()?;
        let resources = check_resources(dto.resources)?;
        Ok(Self {
            scheme,
            domain,
            address: dto.address,
            statement: dto.statement,
            uri,
            version: dto.version,
            chain_id: dto.chain_id,
            chain_name: dto.chain_name,
            nonce,
            issued_at: dto.issued_at,
            expiration_time: dto.expiration_time,
            not_before: dto.not_before,
            request_id,
            resources,
        })
    }
}

impl SiwxMessage {
    /// Create a message with the mandatory CAIP-122 / EIP-4361 fields.
    ///
    /// `version` is fixed to [`VERSION`]. `issued_at` defaults to now;
    /// override with [`Self::with_issued_at`].
    pub fn new(
        domain: impl Into<String>,
        address: impl Into<String>,
        uri: impl Into<String>,
        chain_id: impl Into<String>,
        nonce: impl Into<String>,
    ) -> Result<Self, SiwxError> {
        let domain = check_domain(&domain.into())?;
        let address = address.into();
        if address.is_empty() {
            return Err(SiwxError::InvalidAddress { reason: "empty".to_owned() });
        }
        let uri = check_uri(&uri.into())?;
        let chain_id = chain_id.into();
        if chain_id.is_empty() {
            return Err(SiwxError::InvalidChainId { reason: ChainIdReason::Empty });
        }
        let nonce = check_nonce_shape(&nonce.into())?;

        Ok(Self {
            scheme: None,
            domain,
            address,
            uri,
            version: VERSION.to_owned(),
            chain_id,
            chain_name: None,
            nonce,
            statement: None,
            issued_at: Timestamp::from_instant(jiff::Timestamp::now())?,
            expiration_time: None,
            not_before: None,
            request_id: None,
            resources: Vec::new(),
        })
    }

    /// Assemble a message from ABNF-parsed, already-checked fields.
    #[allow(clippy::too_many_arguments, reason = "mirrors the parsed field set")]
    pub(crate) const fn from_parsed(
        scheme: Option<String>,
        domain: String,
        address: String,
        statement: Option<String>,
        uri: String,
        version: String,
        chain_id: String,
        chain_name: Option<String>,
        nonce: String,
        issued_at: Timestamp,
        expiration_time: Option<Timestamp>,
        not_before: Option<Timestamp>,
        request_id: Option<String>,
        resources: Vec<String>,
    ) -> Self {
        Self {
            scheme,
            domain,
            address,
            statement,
            uri,
            version,
            chain_id,
            chain_name,
            nonce,
            issued_at,
            expiration_time,
            not_before,
            request_id,
            resources,
        }
    }

    /// Set the optional preamble scheme (e.g. `"https"`).
    pub fn with_scheme(mut self, scheme: impl Into<String>) -> Result<Self, SiwxError> {
        self.scheme = Some(check_scheme(&scheme.into())?);
        Ok(self)
    }

    /// Set the human-readable statement.
    pub fn with_statement(mut self, statement: impl Into<String>) -> Result<Self, SiwxError> {
        let statement = statement.into();
        check_statement(&statement)?;
        self.statement = Some(statement);
        Ok(self)
    }

    /// Replace the nonce.
    pub fn with_nonce(mut self, nonce: impl Into<String>) -> Result<Self, SiwxError> {
        self.nonce = check_nonce_shape(&nonce.into())?;
        Ok(self)
    }

    /// Set the issuance time from an instant.
    pub fn with_issued_at(mut self, t: jiff::Timestamp) -> Result<Self, SiwxError> {
        self.issued_at = Timestamp::from_instant(t)?;
        Ok(self)
    }

    /// Set the expiration time from an instant.
    pub fn with_expiration_time(mut self, t: jiff::Timestamp) -> Result<Self, SiwxError> {
        self.expiration_time = Some(Timestamp::from_instant(t)?);
        Ok(self)
    }

    /// Set the not-before time from an instant.
    pub fn with_not_before(mut self, t: jiff::Timestamp) -> Result<Self, SiwxError> {
        self.not_before = Some(Timestamp::from_instant(t)?);
        Ok(self)
    }

    /// Set the issuance time from an RFC 3339 string, preserving `s` verbatim.
    pub fn with_issued_at_raw(mut self, s: &str) -> Result<Self, SiwxError> {
        self.issued_at = Timestamp::parse(s)?;
        Ok(self)
    }

    /// Set the expiration time from an RFC 3339 string, preserving verbatim.
    pub fn with_expiration_time_raw(mut self, s: &str) -> Result<Self, SiwxError> {
        self.expiration_time = Some(Timestamp::parse(s)?);
        Ok(self)
    }

    /// Set the not-before time from an RFC 3339 string, preserving verbatim.
    pub fn with_not_before_raw(mut self, s: &str) -> Result<Self, SiwxError> {
        self.not_before = Some(Timestamp::parse(s)?);
        Ok(self)
    }

    /// Set the request id (`*pchar`, max [`MAX_REQUEST_ID_BYTES`]).
    pub fn with_request_id(mut self, rid: impl Into<String>) -> Result<Self, SiwxError> {
        self.request_id = Some(check_request_id(&rid.into())?);
        Ok(self)
    }

    /// Set the resources list (≤ [`MAX_RESOURCES`] URIs).
    pub fn with_resources<I, S>(mut self, resources: I) -> Result<Self, SiwxError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.resources = check_resources(resources.into_iter().map(Into::into))?;
        Ok(self)
    }

    /// Optional scheme from the preamble.
    #[must_use]
    pub fn scheme(&self) -> Option<&str> {
        self.scheme.as_deref()
    }

    /// Authority requesting the signing.
    #[must_use]
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Blockchain address performing the signing (CAIP-10 `account_address`).
    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }

    /// Human-readable assertion, if present.
    #[must_use]
    pub fn statement(&self) -> Option<&str> {
        self.statement.as_deref()
    }

    /// URI that is the subject of the signing.
    #[must_use]
    pub fn uri(&self) -> &str {
        &self.uri
    }

    /// Message version (always [`VERSION`]).
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// CAIP-2 chain id `reference` segment.
    #[must_use]
    pub fn chain_id(&self) -> &str {
        &self.chain_id
    }

    /// Preamble chain label parsed from the signing string.
    ///
    /// [`Self::new`] leaves this unset.
    #[must_use]
    pub fn chain_name(&self) -> Option<&str> {
        self.chain_name.as_deref()
    }

    /// Anti-replay nonce.
    #[must_use]
    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    /// Issuance instant.
    #[must_use]
    pub const fn issued_at(&self) -> jiff::Timestamp {
        self.issued_at.datetime()
    }

    /// Original lexical form of `issued-at`.
    #[must_use]
    pub fn issued_at_raw(&self) -> &str {
        self.issued_at.as_str()
    }

    /// Expiration instant, if set.
    #[must_use]
    pub fn expiration_time(&self) -> Option<jiff::Timestamp> {
        self.expiration_time.as_ref().map(Timestamp::datetime)
    }

    /// Original lexical form of `expiration-time`, if set.
    #[must_use]
    pub fn expiration_time_raw(&self) -> Option<&str> {
        self.expiration_time.as_ref().map(Timestamp::as_str)
    }

    /// Not-before instant, if set.
    #[must_use]
    pub fn not_before(&self) -> Option<jiff::Timestamp> {
        self.not_before.as_ref().map(Timestamp::datetime)
    }

    /// Original lexical form of `not-before`, if set.
    #[must_use]
    pub fn not_before_raw(&self) -> Option<&str> {
        self.not_before.as_ref().map(Timestamp::as_str)
    }

    /// System-specific request identifier, if set.
    #[must_use]
    pub fn request_id(&self) -> Option<&str> {
        self.request_id.as_deref()
    }

    /// URI resources.
    #[must_use]
    pub fn resources(&self) -> &[String] {
        &self.resources
    }

    /// CAIP-10 account id `{namespace}:{chain_id}:{address}`.
    ///
    /// `namespace` must match `[-a-z0-9]{3,8}`. `address` must match
    /// `[-.%a-zA-Z0-9]{1,128}`. `chain_id` is interpolated as stored (Solana
    /// genesis hashes exceed CAIP-2 `{1,32}` and are intentionally not
    /// length-checked).
    pub fn caip10(&self, namespace: &str) -> Result<String, SiwxError> {
        if !is_caip2_namespace(namespace) {
            return Err(SiwxError::InvalidAddress {
                reason: "CAIP-10 namespace must be [-a-z0-9]{3,8}".to_owned(),
            });
        }
        if !is_caip10_address(&self.address) {
            return Err(SiwxError::InvalidAddress {
                reason: "CAIP-10 address must be [-.%a-zA-Z0-9]{1,128}".to_owned(),
            });
        }
        Ok(format!("{namespace}:{}:{}", self.chain_id, self.address))
    }

    #[cfg(test)]
    pub(crate) fn set_chain_name(&mut self, chain_name: Option<String>) {
        self.chain_name = chain_name;
    }
}

pub(crate) fn check_scheme(scheme: &str) -> Result<String, SiwxError> {
    if scheme.is_empty() {
        return Err(SiwxError::InvalidScheme { reason: "empty" });
    }
    if !scheme.as_bytes().first().is_some_and(u8::is_ascii_alphabetic) {
        return Err(SiwxError::InvalidScheme { reason: "must start with ASCII letter" });
    }
    if !scheme.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.') {
        return Err(SiwxError::InvalidScheme {
            reason: "must be ASCII alphanumeric, '+', '-', or '.'",
        });
    }
    Ok(scheme.to_owned())
}

pub(crate) fn check_domain(domain: &str) -> Result<String, SiwxError> {
    if domain.is_empty() {
        return Err(SiwxError::InvalidDomain { reason: "empty" });
    }
    if domain.contains(PREAMBLE_MID) {
        return Err(SiwxError::InvalidDomain { reason: "preamble marker" });
    }
    // Strict RFC 3986 authority check (`iri-string`: pure parsing, no I/O —
    // R56-safe). Empty authority is valid in `iri-string` (`file:///`); the
    // empty case is rejected above, so any accept here is a real authority.
    // NOTE: the lenient `url` crate must NOT be used here — it auto-encodes
    // spaces, which would accept malformed resource lines the official SIWE
    // vectors require us to reject.
    authority::<UriSpec>(domain)
        .map_err(|_| SiwxError::InvalidDomain { reason: "not RFC 3986 authority" })?;
    Ok(domain.to_owned())
}

pub(crate) fn check_statement(statement: &str) -> Result<(), SiwxError> {
    if statement.is_empty() {
        return Err(SiwxError::InvalidStatement { reason: "empty" });
    }
    if statement.len() > MAX_STATEMENT_BYTES {
        return Err(SiwxError::InvalidStatement { reason: "exceeds maximum size" });
    }
    if !statement.chars().all(is_statement_char) {
        return Err(SiwxError::InvalidStatement { reason: "must be reserved / unreserved / SP" });
    }
    Ok(())
}

pub(crate) fn check_uri(uri: &str) -> Result<String, SiwxError> {
    if uri.len() > MAX_URI_BYTES {
        return Err(SiwxError::InvalidUri {
            reason: format!("exceeds maximum size of {MAX_URI_BYTES} bytes, got {}", uri.len()),
        });
    }
    UriString::try_from(uri).map_err(|e| SiwxError::InvalidUri { reason: e.to_string() })?;
    Ok(uri.to_owned())
}

pub(crate) fn check_request_id(rid: &str) -> Result<String, SiwxError> {
    if rid.len() > MAX_REQUEST_ID_BYTES {
        return Err(SiwxError::InvalidRequestId { reason: "exceeds maximum size" });
    }
    if !is_pchar_string(rid) {
        return Err(SiwxError::InvalidRequestId { reason: "must be pchar" });
    }
    Ok(rid.to_owned())
}

pub(crate) fn check_resources(
    resources: impl IntoIterator<Item = impl AsRef<str>>,
) -> Result<Vec<String>, SiwxError> {
    let resources: Vec<String> = resources.into_iter().map(|uri| uri.as_ref().to_owned()).collect();
    if resources.len() > MAX_RESOURCES {
        return Err(SiwxError::TooManyResources { count: resources.len(), max: MAX_RESOURCES });
    }
    for uri in &resources {
        check_uri(uri)?;
    }
    Ok(resources)
}

/// Validate nonce length and charset (≥ 8 alphanumeric).
pub(crate) fn check_nonce_shape(nonce: &str) -> Result<String, SiwxError> {
    if nonce.len() < MIN_NONCE_LEN {
        return Err(SiwxError::InvalidNonce {
            reason: format!("must be at least {MIN_NONCE_LEN} characters, got {}", nonce.len()),
        });
    }
    if !nonce.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(SiwxError::InvalidNonce { reason: "must be ASCII alphanumeric".to_owned() });
    }
    Ok(nonce.to_owned())
}

fn is_caip2_namespace(s: &str) -> bool {
    (3..=8).contains(&s.len()) &&
        s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn is_caip10_address(s: &str) -> bool {
    (1..=128).contains(&s.len()) &&
        s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'%'))
}

const fn has_rfc3339_timezone(s: &str) -> bool {
    match s.as_bytes() {
        [.., b'Z' | b'z'] => true,
        [.., b'+' | b'-', h1, h2, b':', m1, m2]
            if h1.is_ascii_digit() &&
                h2.is_ascii_digit() &&
                m1.is_ascii_digit() &&
                m2.is_ascii_digit() =>
        {
            true
        }
        _ => false,
    }
}

const fn is_statement_char(c: char) -> bool {
    matches!(
        c,
        'A'..='Z'
            | 'a'..='z'
            | '0'..='9'
            | '-'
            | '.'
            | '_'
            | '~'
            | ':'
            | '/'
            | '?'
            | '#'
            | '['
            | ']'
            | '@'
            | '!'
            | '$'
            | '&'
            | '\''
            | '('
            | ')'
            | '*'
            | '+'
            | ','
            | ';'
            | '='
            | ' '
    )
}

const fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

const fn is_sub_delim(b: u8) -> bool {
    matches!(b, b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'=')
}

fn is_pchar_string(s: &str) -> bool {
    let mut bytes = s.as_bytes().iter().copied();
    while let Some(c) = bytes.next() {
        if is_unreserved(c) || is_sub_delim(c) || c == b':' || c == b'@' {
            continue;
        }
        if c == b'%' {
            let h1 = bytes.next();
            let h2 = bytes.next();
            if h1.is_some_and(|h| h.is_ascii_hexdigit()) &&
                h2.is_some_and(|h| h.is_ascii_hexdigit())
            {
                continue;
            }
        }
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(s: &str) -> jiff::Timestamp {
        s.parse().expect("test timestamp")
    }

    #[test]
    fn new_rejects_empty_mandatory_fields() {
        assert!(matches!(
            SiwxMessage::new("", "a", "https://d.com", "1", "testnonce12345678").unwrap_err(),
            SiwxError::InvalidDomain { .. }
        ));
        assert!(matches!(
            SiwxMessage::new("d.com", "", "https://d.com", "1", "testnonce12345678").unwrap_err(),
            SiwxError::InvalidAddress { .. }
        ));
        assert!(matches!(
            SiwxMessage::new("d.com", "a", "https://d.com", "", "testnonce12345678").unwrap_err(),
            SiwxError::InvalidChainId { reason: ChainIdReason::Empty }
        ));
    }

    #[test]
    fn new_rejects_short_nonce() {
        assert!(matches!(
            SiwxMessage::new("d.com", "a", "https://d.com", "1", "short").unwrap_err(),
            SiwxError::InvalidNonce { .. }
        ));
    }

    #[test]
    fn timestamp_parse_requires_t_and_zone() {
        assert!(Timestamp::parse("2024-01-01 00:00:00Z").is_err());
        assert!(Timestamp::parse("2024-01-01T00:00:00").is_err());
        assert!(Timestamp::parse("2024-01-01T00:00:00Z").is_ok());
        assert!(Timestamp::parse("2024-01-01T00:00:00+00:00").is_ok());
    }

    #[test]
    fn timestamp_equality_requires_same_lexical_form() {
        let a = Timestamp::parse("2021-09-30T16:25:24Z").expect("a");
        let b = Timestamp::parse("2021-09-30T16:25:24.000Z").expect("b");
        assert_eq!(a.datetime(), b.datetime());
        assert_ne!(a, b);
    }

    #[test]
    fn domain_rejects_preamble_injection() {
        let evil = format!("evil.com{}Ethereum", PREAMBLE_MID);
        assert!(matches!(
            SiwxMessage::new(evil, "a", "https://d.com", "1", "testnonce12345678").unwrap_err(),
            SiwxError::InvalidDomain { .. }
        ));
    }

    #[test]
    fn uri_rejects_garbage() {
        assert!(matches!(
            SiwxMessage::new("d.com", "a", "not a uri :::", "1", "testnonce12345678").unwrap_err(),
            SiwxError::InvalidUri { .. }
        ));
    }

    #[test]
    fn caip10_format() {
        let msg = SiwxMessage::new("d.com", "addr1", "https://d.com", "1", "testnonce12345678")
            .expect("valid")
            .with_issued_at(ts("2024-01-01T00:00:00Z"))
            .expect("iat");
        assert_eq!(msg.caip10("eip155").expect("caip10"), "eip155:1:addr1");
        assert!(msg.caip10("BAD").is_err());
    }
}
