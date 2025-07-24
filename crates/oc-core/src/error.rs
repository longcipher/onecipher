use serde::{Serialize, Serializer};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OcErrorCode {
    WalletNotFound,
    ChainNotSupported,
    InvalidPassphrase,
    InvalidInput,
    CaipParseError,
    PolicyDenied,
    ApiKeyNotFound,
    ApiKeyExpired,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum OcError {
    #[error("wallet not found: {id}")]
    WalletNotFound { id: String },

    #[error("chain not supported: {chain}")]
    ChainNotSupported { chain: String },

    #[error("invalid passphrase")]
    InvalidPassphrase,

    #[error("invalid input: {message}")]
    InvalidInput { message: String },

    #[error("CAIP parse error: {message}")]
    CaipParseError { message: String },

    #[error("policy denied: {reason}")]
    PolicyDenied { policy_id: String, reason: String },

    #[error("API key not found")]
    ApiKeyNotFound,

    #[error("API key expired: {id}")]
    ApiKeyExpired { id: String },
}

impl OcError {
    pub const fn code(&self) -> OcErrorCode {
        match self {
            Self::WalletNotFound { .. } => OcErrorCode::WalletNotFound,
            Self::ChainNotSupported { .. } => OcErrorCode::ChainNotSupported,
            Self::InvalidPassphrase => OcErrorCode::InvalidPassphrase,
            Self::InvalidInput { .. } => OcErrorCode::InvalidInput,
            Self::CaipParseError { .. } => OcErrorCode::CaipParseError,
            Self::PolicyDenied { .. } => OcErrorCode::PolicyDenied,
            Self::ApiKeyNotFound => OcErrorCode::ApiKeyNotFound,
            Self::ApiKeyExpired { .. } => OcErrorCode::ApiKeyExpired,
        }
    }
}

#[derive(Serialize)]
struct ErrorPayload {
    code: OcErrorCode,
    message: String,
}

impl Serialize for OcError {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let payload = ErrorPayload { code: self.code(), message: self.to_string() };
        payload.serialize(serializer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_code_mapping_wallet_not_found() {
        let err = OcError::WalletNotFound { id: "abc".to_string() };
        assert_eq!(err.code(), OcErrorCode::WalletNotFound);
    }

    #[test]
    fn test_code_mapping_all_variants() {
        assert_eq!(
            OcError::ChainNotSupported { chain: "x".into() }.code(),
            OcErrorCode::ChainNotSupported
        );
        assert_eq!(OcError::InvalidPassphrase.code(), OcErrorCode::InvalidPassphrase);
        assert_eq!(OcError::InvalidInput { message: "x".into() }.code(), OcErrorCode::InvalidInput);
        assert_eq!(
            OcError::CaipParseError { message: "x".into() }.code(),
            OcErrorCode::CaipParseError
        );
        assert_eq!(
            OcError::PolicyDenied { policy_id: "x".into(), reason: "x".into() }.code(),
            OcErrorCode::PolicyDenied
        );
        assert_eq!(OcError::ApiKeyNotFound.code(), OcErrorCode::ApiKeyNotFound);
        assert_eq!(OcError::ApiKeyExpired { id: "x".into() }.code(), OcErrorCode::ApiKeyExpired);
    }

    #[test]
    fn test_display_output() {
        let err = OcError::WalletNotFound { id: "abc-123".to_string() };
        assert_eq!(err.to_string(), "wallet not found: abc-123");
    }

    #[test]
    fn test_json_serialization_shape() {
        let err = OcError::WalletNotFound { id: "abc-123".to_string() };
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "WALLET_NOT_FOUND");
        assert_eq!(json["message"], "wallet not found: abc-123");
    }

    #[test]
    fn test_caip_parse_error_serialization() {
        let err = OcError::CaipParseError { message: "bad format".to_string() };
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "CAIP_PARSE_ERROR");
        assert!(json["message"].as_str().unwrap().contains("bad format"));
    }

    #[test]
    fn test_policy_denied_serialization() {
        let err = OcError::PolicyDenied {
            policy_id: "spending-limit".into(),
            reason: "exceeded daily limit".into(),
        };
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "POLICY_DENIED");
        assert!(json["message"].as_str().unwrap().contains("exceeded daily limit"));
    }

    #[test]
    fn test_api_key_not_found_serialization() {
        let err = OcError::ApiKeyNotFound;
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "API_KEY_NOT_FOUND");
    }

    #[test]
    fn test_api_key_expired_serialization() {
        let err = OcError::ApiKeyExpired { id: "key-123".into() };
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "API_KEY_EXPIRED");
        assert!(json["message"].as_str().unwrap().contains("key-123"));
    }
}
