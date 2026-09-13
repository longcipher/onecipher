//! End-to-end authentication: size → CR → parse → validate → chain name →
//! address → chain id → verify original bytes.

use crate::{
    SiwxError, SiwxMessage, message::MAX_MESSAGE_BYTES, validate::AuthOpts, verifier::SyncVerifier,
};

/// Successful authentication result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authenticated {
    message: SiwxMessage,
}

impl Authenticated {
    /// Parsed and verified CAIP-122 message.
    #[must_use]
    pub const fn message(&self) -> &SiwxMessage {
        &self.message
    }

    /// Signer address from the verified message.
    #[must_use]
    pub fn address(&self) -> &str {
        self.message.address()
    }

    /// CAIP-10 account id `{namespace}:{chain_id}:{address}`.
    pub fn caip10(&self, namespace: &str) -> Result<String, SiwxError> {
        self.message.caip10(namespace)
    }
}

/// Parse `raw_message`, validate fields, bind preamble chain name, then verify
/// `signature` over the original `raw_message` bytes.
///
/// Steps (fail-fast):
/// 1. Reject oversize input ([`MAX_MESSAGE_BYTES`]).
/// 2. Reject CR during parse.
/// 3. Parse `raw_message` into [`SiwxMessage`] (ABNF; trailing LF rejected).
/// 4. [`SiwxMessage::validate`] with `opts` (domain + nonce required).
/// 5. Require `chain_name == V::CHAIN_NAME`.
/// 6. `V::validate_address`.
/// 7. `V::validate_chain_id`.
/// 8. `V::verify` over the original `raw_message` bytes (never re-serialized).
///
/// Callers that must accept a leftover LF should `trim_end_matches('\n')`
/// before calling; the library does not trim.
pub fn authenticate<V: SyncVerifier>(
    verifier: &V,
    raw_message: &str,
    signature: &[u8],
    opts: &AuthOpts,
) -> Result<Authenticated, SiwxError> {
    if raw_message.len() > MAX_MESSAGE_BYTES {
        return Err(SiwxError::MessageTooLarge { len: raw_message.len(), max: MAX_MESSAGE_BYTES });
    }

    let message: SiwxMessage = raw_message.parse()?;
    message.validate(opts)?;
    if message.chain_name() != Some(V::CHAIN_NAME) {
        return Err(SiwxError::ChainNameMismatch {
            expected: V::CHAIN_NAME.to_owned(),
            actual: message.chain_name().map(str::to_owned),
        });
    }
    V::validate_address(message.address())?;
    V::validate_chain_id(message.chain_id())?;

    verifier.verify(&message, raw_message, signature)?;

    Ok(Authenticated { message })
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    use super::*;
    use crate::{ChainIdReason, FormatReason};

    struct AcceptingVerifier;

    impl SyncVerifier for AcceptingVerifier {
        const CHAIN_NAME: &'static str = "Ethereum";
        const NAMESPACE: &'static str = "eip155";

        fn verify(
            &self,
            _message: &SiwxMessage,
            _raw_message: &str,
            _signature: &[u8],
        ) -> Result<(), SiwxError> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct RecordingVerifier {
        verify_calls: AtomicUsize,
        last_raw: Mutex<Option<String>>,
    }

    impl SyncVerifier for RecordingVerifier {
        const CHAIN_NAME: &'static str = "Ethereum";
        const NAMESPACE: &'static str = "eip155";

        fn verify(
            &self,
            _message: &SiwxMessage,
            raw_message: &str,
            _signature: &[u8],
        ) -> Result<(), SiwxError> {
            self.verify_calls.fetch_add(1, Ordering::SeqCst);
            *self.last_raw.lock().expect("last_raw mutex") = Some(raw_message.to_owned());
            Ok(())
        }
    }

    struct RejectingChainId {
        verify_calls: AtomicUsize,
    }

    impl SyncVerifier for RejectingChainId {
        const CHAIN_NAME: &'static str = "Ethereum";
        const NAMESPACE: &'static str = "eip155";

        fn validate_chain_id(_chain_id: &str) -> Result<(), SiwxError> {
            Err(SiwxError::InvalidChainId { reason: ChainIdReason::NotDecimal })
        }

        fn verify(
            &self,
            _message: &SiwxMessage,
            _raw_message: &str,
            _signature: &[u8],
        ) -> Result<(), SiwxError> {
            self.verify_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    fn ts(s: &str) -> jiff::Timestamp {
        s.parse().expect("test timestamp")
    }

    fn sample_msg() -> SiwxMessage {
        SiwxMessage::new("example.com", "addr1", "https://example.com", "1", "testnonce12345678")
            .expect("valid")
            .with_issued_at(ts("2024-01-01T00:00:00Z"))
            .expect("issued_at")
    }

    #[test]
    fn authenticate_accepts_self_generated_message() {
        let msg = sample_msg();
        let raw = AcceptingVerifier::format_message(&msg);
        let opts = AuthOpts::new(msg.domain(), msg.nonce());
        let auth = authenticate(&AcceptingVerifier, &raw, &[], &opts).expect("authenticate");
        assert_eq!(auth.message().domain(), "example.com");
        assert_eq!(auth.address(), "addr1");
        assert_eq!(auth.message().chain_name(), Some("Ethereum"));
        assert_eq!(auth.caip10("eip155").expect("caip10"), "eip155:1:addr1");
    }

    #[test]
    fn authenticate_rejects_trailing_newline() {
        let msg = sample_msg();
        let mut raw = AcceptingVerifier::format_message(&msg);
        raw.push('\n');
        let opts = AuthOpts::new(msg.domain(), msg.nonce());
        let err = authenticate(&AcceptingVerifier, &raw, &[], &opts).expect_err("trailing LF");
        assert!(
            matches!(err, SiwxError::InvalidFormat { reason: FormatReason::UnexpectedTrailing }),
            "got {err:?}"
        );
    }

    #[test]
    fn authenticate_rejects_domain_mismatch() {
        let msg = sample_msg();
        let raw = AcceptingVerifier::format_message(&msg);
        let opts = AuthOpts::new("other.com", msg.nonce());
        let err = authenticate(&AcceptingVerifier, &raw, &[], &opts).expect_err("domain");
        assert!(matches!(err, SiwxError::DomainMismatch { .. }), "got {err:?}");
    }

    #[test]
    fn authenticate_rejects_oversize_message() {
        let padding = "x".repeat(MAX_MESSAGE_BYTES + 1);
        let err =
            authenticate(&AcceptingVerifier, &padding, &[], &AuthOpts::new("d.com", "n12345678"))
                .expect_err("oversize");
        assert!(
            matches!(
                err,
                SiwxError::MessageTooLarge {
                    len,
                    max: MAX_MESSAGE_BYTES,
                } if len == MAX_MESSAGE_BYTES + 1
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn authenticate_rejects_solana_preamble_for_ethereum_verifier() {
        let msg = sample_msg();
        let raw = msg.to_sign_string("Solana");
        let opts = AuthOpts::new(msg.domain(), msg.nonce());
        let verifier = RecordingVerifier::default();
        let err = authenticate(&verifier, &raw, &[], &opts).expect_err("chain name");
        assert!(
            matches!(
                err,
                SiwxError::ChainNameMismatch {
                    ref expected,
                    actual: Some(ref actual),
                } if expected == "Ethereum" && actual == "Solana"
            ),
            "got {err:?}"
        );
        assert_eq!(
            verifier.verify_calls.load(Ordering::SeqCst),
            0,
            "verify must not run on chain name mismatch"
        );
    }

    #[test]
    fn authenticate_rejects_invalid_chain_id_before_verify() {
        let msg = sample_msg();
        let raw = msg.to_sign_string("Ethereum");
        let opts = AuthOpts::new(msg.domain(), msg.nonce());
        let verifier = RejectingChainId { verify_calls: AtomicUsize::new(0) };
        let err = authenticate(&verifier, &raw, &[], &opts).expect_err("chain id");
        assert!(
            matches!(err, SiwxError::InvalidChainId { reason: ChainIdReason::NotDecimal }),
            "got {err:?}"
        );
        assert_eq!(
            verifier.verify_calls.load(Ordering::SeqCst),
            0,
            "verify must not run on invalid chain id"
        );
    }

    #[test]
    fn authenticate_verifies_original_bytes_not_reformatted() {
        let msg = sample_msg();
        let mut raw = msg.to_sign_string("Ethereum");
        raw.push_str("\nResources:");

        let parsed: SiwxMessage = raw.parse().expect("empty Resources: footer parses");
        let reformatted = RecordingVerifier::format_message(&parsed);
        assert_ne!(reformatted, raw, "formatter omits empty Resources: footer");
        assert!(
            parsed.resources().is_empty(),
            "empty Resources: must parse as no resources, got {:?}",
            parsed.resources()
        );

        let verifier = RecordingVerifier::default();
        let opts = AuthOpts::new(msg.domain(), msg.nonce());
        authenticate(&verifier, &raw, &[], &opts).expect("original bytes authenticate");
        assert_eq!(verifier.verify_calls.load(Ordering::SeqCst), 1);
        let captured = verifier.last_raw.lock().expect("last_raw mutex");
        assert_eq!(captured.as_deref(), Some(raw.as_str()));
        assert_ne!(captured.as_deref(), Some(reformatted.as_str()));
    }
}
