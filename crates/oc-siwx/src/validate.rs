//! Field- and temporal-level validation of [`SiwxMessage`].

use crate::{
    error::{ChainIdReason, FormatReason, SiwxError},
    message::{
        SiwxMessage, VERSION, check_domain, check_nonce_shape, check_request_id, check_resources,
        check_scheme, check_statement, check_uri,
    },
};

/// Default leeway for `expiration_time`, `not_before`, and `max_issued_age`.
pub const DEFAULT_CLOCK_SKEW_SECS: i64 = 60;

/// Binding and temporal options for authentication / validation.
///
/// `domain` and `nonce` are **required** so callers cannot skip replay and
/// origin binding by accident. Multi-chain deployments should also set
/// [`Self::with_chain_id`].
#[derive(Debug, Clone)]
pub struct AuthOpts {
    domain: String,
    nonce: String,
    scheme: Option<String>,
    uri: Option<String>,
    chain_id: Option<String>,
    request_id: Option<String>,
    timestamp: Option<jiff::Timestamp>,
    clock_skew_secs: i64,
    max_issued_age_secs: Option<i64>,
}

impl AuthOpts {
    /// Create opts that bind `domain` and `nonce` (60s default skew).
    #[must_use]
    pub fn new(domain: impl Into<String>, nonce: impl Into<String>) -> Self {
        Self {
            domain: domain.into(),
            nonce: nonce.into(),
            scheme: None,
            uri: None,
            chain_id: None,
            request_id: None,
            timestamp: None,
            clock_skew_secs: DEFAULT_CLOCK_SKEW_SECS,
            max_issued_age_secs: None,
        }
    }

    /// Require [`SiwxMessage::scheme`] to equal `scheme`.
    #[must_use]
    pub fn with_scheme(mut self, scheme: impl Into<String>) -> Self {
        self.scheme = Some(scheme.into());
        self
    }

    /// Require [`SiwxMessage::uri`] to equal `uri`.
    #[must_use]
    pub fn with_uri(mut self, uri: impl Into<String>) -> Self {
        self.uri = Some(uri.into());
        self
    }

    /// Require [`SiwxMessage::chain_id`] to equal `chain_id`.
    #[must_use]
    pub fn with_chain_id(mut self, chain_id: impl Into<String>) -> Self {
        self.chain_id = Some(chain_id.into());
        self
    }

    /// Require [`SiwxMessage::request_id`] to equal `id`.
    #[must_use]
    pub fn with_request_id(mut self, id: impl Into<String>) -> Self {
        self.request_id = Some(id.into());
        self
    }

    /// Override the temporal evaluation point (tests / clock injection).
    ///
    /// Does not change clock skew: the default 60s leeway still applies.
    #[must_use]
    pub const fn with_timestamp(mut self, t: jiff::Timestamp) -> Self {
        self.timestamp = Some(t);
        self
    }

    /// Override clock skew (seconds) applied to expiration / not-before / age.
    #[must_use]
    pub const fn with_clock_skew_secs(mut self, secs: i64) -> Self {
        self.clock_skew_secs = secs;
        self
    }

    /// Reject messages whose `issued_at` is older than `age_secs`.
    /// Future `issued_at` is never treated as stale.
    #[must_use]
    pub const fn with_max_issued_age_secs(mut self, age_secs: i64) -> Self {
        self.max_issued_age_secs = Some(age_secs);
        self
    }

    /// Evaluation instant (override or now).
    #[must_use]
    pub fn now(&self) -> jiff::Timestamp {
        self.timestamp.unwrap_or_else(jiff::Timestamp::now)
    }
}

impl SiwxMessage {
    /// Validate field shapes, protocol rules, bindings, and temporal window.
    pub fn validate(&self, opts: &AuthOpts) -> Result<(), SiwxError> {
        self.check_required_shapes()?;
        check_uri(self.uri())?;
        if let Some(s) = self.statement() {
            check_statement(s)?;
        }
        if let Some(rid) = self.request_id() {
            check_request_id(rid)?;
        }
        check_resources(self.resources())?;
        self.check_domain_binding(&opts.domain)?;
        self.check_nonce_binding(&opts.nonce)?;
        self.check_scheme_binding(opts.scheme.as_deref())?;
        self.check_uri_binding(opts.uri.as_deref())?;
        self.check_chain_id_binding(opts.chain_id.as_deref())?;
        self.check_request_id_binding(opts.request_id.as_deref())?;
        self.check_temporal_window(opts)?;
        Ok(())
    }

    fn check_required_shapes(&self) -> Result<(), SiwxError> {
        if let Some(scheme) = self.scheme() {
            check_scheme(scheme)?;
        }
        check_domain(self.domain())?;
        if self.address().is_empty() {
            return Err(SiwxError::InvalidAddress { reason: "empty".to_owned() });
        }
        if self.version() != VERSION {
            return Err(SiwxError::InvalidFormat { reason: FormatReason::VersionNotOne });
        }
        if self.chain_id().is_empty() {
            return Err(SiwxError::InvalidChainId { reason: ChainIdReason::Empty });
        }
        check_nonce_shape(self.nonce())?;
        Ok(())
    }

    fn check_domain_binding(&self, expected: &str) -> Result<(), SiwxError> {
        if expected != self.domain() {
            return Err(SiwxError::DomainMismatch {
                expected: expected.to_owned(),
                actual: self.domain().to_owned(),
            });
        }
        Ok(())
    }

    fn check_nonce_binding(&self, expected: &str) -> Result<(), SiwxError> {
        if expected != self.nonce() {
            return Err(SiwxError::NonceMismatch {
                expected: expected.to_owned(),
                actual: self.nonce().to_owned(),
            });
        }
        Ok(())
    }

    fn check_scheme_binding(&self, expected: Option<&str>) -> Result<(), SiwxError> {
        if let Some(expected) = expected &&
            self.scheme() != Some(expected)
        {
            return Err(SiwxError::SchemeMismatch {
                expected: Some(expected.to_owned()),
                actual: self.scheme().map(str::to_owned),
            });
        }
        Ok(())
    }

    fn check_uri_binding(&self, expected: Option<&str>) -> Result<(), SiwxError> {
        if let Some(expected) = expected &&
            expected != self.uri()
        {
            return Err(SiwxError::UriMismatch {
                expected: expected.to_owned(),
                actual: self.uri().to_owned(),
            });
        }
        Ok(())
    }

    fn check_chain_id_binding(&self, expected: Option<&str>) -> Result<(), SiwxError> {
        if let Some(expected) = expected &&
            expected != self.chain_id()
        {
            return Err(SiwxError::ChainIdMismatch {
                expected: expected.to_owned(),
                actual: self.chain_id().to_owned(),
            });
        }
        Ok(())
    }

    fn check_request_id_binding(&self, expected: Option<&str>) -> Result<(), SiwxError> {
        if let Some(expected) = expected &&
            self.request_id() != Some(expected)
        {
            return Err(SiwxError::RequestIdMismatch {
                expected: Some(expected.to_owned()),
                actual: self.request_id().map(str::to_owned),
            });
        }
        Ok(())
    }

    fn check_temporal_window(&self, opts: &AuthOpts) -> Result<(), SiwxError> {
        let now = opts.now();
        let skew = jiff::SignedDuration::from_secs(opts.clock_skew_secs);
        // `duration_since` returns a (possibly negative) `SignedDuration`;
        // all comparisons below are exact and infallible.
        if let Some(exp) = self.expiration_time() &&
            now.duration_since(exp) > skew
        {
            return Err(SiwxError::Expired);
        }
        if let Some(nbf) = self.not_before() &&
            nbf.duration_since(now) > skew
        {
            return Err(SiwxError::NotYetValid);
        }
        if let Some(max_age_secs) = opts.max_issued_age_secs {
            let max_age = jiff::SignedDuration::from_secs(max_age_secs);
            let issued = self.issued_at();
            // Future issued_at never fails: only evaluate age when
            // `issued - now <= skew`.
            if issued.duration_since(now) <= skew && now.duration_since(issued) - skew > max_age {
                return Err(SiwxError::StaleIssuedAt);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(s: &str) -> jiff::Timestamp {
        s.parse().expect("test timestamp")
    }

    fn base() -> SiwxMessage {
        SiwxMessage::new("d.com", "a", "https://d.com", "1", "testnonce12345678")
            .expect("valid")
            .with_issued_at(ts("2024-01-01T00:00:00Z"))
            .expect("issued_at")
    }

    fn opts_for(msg: &SiwxMessage) -> AuthOpts {
        AuthOpts::new(msg.domain(), msg.nonce())
    }

    #[test]
    fn matching_opts_accept_message() {
        let msg = base();
        msg.validate(&opts_for(&msg)).expect("matching opts are valid");
    }

    #[test]
    fn expired_message_is_rejected() {
        let msg = base().with_expiration_time(ts("2020-01-01T00:00:00Z")).expect("expiration");
        let opts = opts_for(&msg).with_timestamp(ts("2021-01-01T00:00:00Z"));
        let err = msg.validate(&opts).unwrap_err();
        assert!(matches!(err, SiwxError::Expired));
    }

    #[test]
    fn expiration_at_now_is_still_valid() {
        let exp = ts("2024-01-01T00:00:00Z");
        let msg = base().with_expiration_time(exp).expect("expiration");
        let opts = opts_for(&msg).with_timestamp(exp).with_clock_skew_secs(0);
        msg.validate(&opts).expect("now == exp is valid");
    }

    #[test]
    fn expiration_within_skew_is_valid() {
        let msg = base().with_expiration_time(ts("2024-01-01T00:00:00Z")).expect("expiration");
        let opts = opts_for(&msg).with_timestamp(ts("2024-01-01T00:01:00Z"));
        msg.validate(&opts).expect("now == exp + default 60s skew is valid");
    }

    #[test]
    fn expiration_past_skew_is_expired() {
        let msg = base().with_expiration_time(ts("2024-01-01T00:00:00Z")).expect("expiration");
        let opts = opts_for(&msg).with_timestamp(ts("2024-01-01T00:01:01Z"));
        let err = msg.validate(&opts).unwrap_err();
        assert!(matches!(err, SiwxError::Expired));
    }

    #[test]
    fn not_before_in_future_is_rejected() {
        let msg = base().with_not_before(ts("2099-01-01T00:00:00Z")).expect("not_before");
        let opts = opts_for(&msg).with_timestamp(ts("2024-06-01T00:00:00Z"));
        let err = msg.validate(&opts).unwrap_err();
        assert!(matches!(err, SiwxError::NotYetValid));
    }

    #[test]
    fn domain_mismatch_is_rejected() {
        let msg = base();
        let opts = AuthOpts::new("good.com", msg.nonce());
        let err = msg.validate(&opts).unwrap_err();
        assert!(matches!(err, SiwxError::DomainMismatch { .. }));
    }

    #[test]
    fn nonce_mismatch_is_rejected() {
        let msg = base();
        let opts = AuthOpts::new(msg.domain(), "othernonce12345678");
        let err = msg.validate(&opts).unwrap_err();
        assert!(matches!(err, SiwxError::NonceMismatch { .. }));
    }

    #[test]
    fn max_issued_age_rejects_stale_message() {
        let msg = base().with_issued_at(ts("2020-01-01T00:00:00Z")).expect("issued_at");
        let opts = opts_for(&msg)
            .with_timestamp(ts("2020-01-02T00:00:00Z"))
            .with_max_issued_age_secs(3600);
        let err = msg.validate(&opts).unwrap_err();
        assert!(matches!(err, SiwxError::StaleIssuedAt));
    }

    #[test]
    fn future_issued_at_is_not_stale() {
        let msg = base().with_issued_at(ts("2024-01-02T00:00:00Z")).expect("issued_at");
        let opts = opts_for(&msg)
            .with_timestamp(ts("2024-01-01T00:00:00Z"))
            .with_max_issued_age_secs(3600);
        msg.validate(&opts).expect("future issued-at must not be treated as stale");
    }
}
