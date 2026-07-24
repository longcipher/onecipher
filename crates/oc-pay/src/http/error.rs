use thiserror::Error;

/// Error codes for programmatic handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OcPayHttpErrorCode {
    /// HTTP transport error (DNS, TLS, timeout).
    HttpTransport,
    /// Server returned an unexpected HTTP status.
    HttpStatus,
    /// Protocol-level error (malformed 402, bad header encoding).
    ProtocolMalformed,
    /// Could not detect which payment protocol to use.
    ProtocolUnknown,
    /// Wallet not found or inaccessible.
    WalletNotFound,
    /// Key decryption or signing failed.
    SigningFailed,
    /// No supported chain/network in the payment requirements.
    UnsupportedChain,
    /// Discovery API error.
    DiscoveryFailed,
    /// Invalid input (e.g. unsupported HTTP method).
    InvalidInput,
}

#[derive(Debug, Error)]
#[error("[{code:?}] {message}")]
pub struct OcPayHttpError {
    pub code: OcPayHttpErrorCode,
    pub message: String,
}

impl OcPayHttpError {
    pub fn new(code: OcPayHttpErrorCode, message: impl Into<String>) -> Self {
        Self { code, message: message.into() }
    }
}

impl From<hpx::Error> for OcPayHttpError {
    fn from(e: hpx::Error) -> Self {
        Self::new(OcPayHttpErrorCode::HttpTransport, e.to_string())
    }
}

impl From<serde_json::Error> for OcPayHttpError {
    fn from(e: serde_json::Error) -> Self {
        Self::new(OcPayHttpErrorCode::ProtocolMalformed, format!("json: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_formatting() {
        let err = OcPayHttpError::new(OcPayHttpErrorCode::HttpTransport, "timeout");
        assert_eq!(err.to_string(), "[HttpTransport] timeout");
    }

    #[test]
    fn error_new_sets_code_and_message() {
        let err = OcPayHttpError::new(OcPayHttpErrorCode::InvalidInput, "bad method");
        assert_eq!(err.code, OcPayHttpErrorCode::InvalidInput);
        assert_eq!(err.message, "bad method");
    }

    #[test]
    fn error_from_serde_json() {
        let json_err = serde_json::from_str::<serde_json::Value>("not json").unwrap_err();
        let err: OcPayHttpError = json_err.into();
        assert_eq!(err.code, OcPayHttpErrorCode::ProtocolMalformed);
        assert!(err.message.contains("json"));
    }

    #[test]
    fn error_codes_are_distinct() {
        assert_ne!(OcPayHttpErrorCode::HttpTransport, OcPayHttpErrorCode::HttpStatus);
        assert_ne!(OcPayHttpErrorCode::ProtocolMalformed, OcPayHttpErrorCode::ProtocolUnknown);
    }

    #[test]
    fn error_is_debug() {
        let err = OcPayHttpError::new(OcPayHttpErrorCode::DiscoveryFailed, "test");
        let dbg = format!("{err:?}");
        assert!(dbg.contains("DiscoveryFailed"));
    }

    #[test]
    fn error_implements_std_error() {
        let err: &dyn std::error::Error =
            &OcPayHttpError::new(OcPayHttpErrorCode::WalletNotFound, "no wallet");
        assert!(err.source().is_none());
    }
}
