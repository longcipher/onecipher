#[derive(Debug, thiserror::Error)]
pub enum PaymasterError {
    #[error("paymaster service error: {0}")]
    Service(String),
    #[error("bundler error: {0}")]
    Bundler(String),
    #[error("invalid user operation: {0}")]
    InvalidUserOp(String),
    #[error("sponsorship rejected: {0}")]
    Rejected(String),
    #[error("network error: {0}")]
    Network(String),
    #[error("timeout")]
    Timeout,
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;

    #[test]
    fn display_formats_match() {
        assert_eq!(PaymasterError::Service("x".into()).to_string(), "paymaster service error: x");
        assert_eq!(PaymasterError::Bundler("y".into()).to_string(), "bundler error: y");
        assert_eq!(
            PaymasterError::InvalidUserOp("z".into()).to_string(),
            "invalid user operation: z"
        );
        assert_eq!(PaymasterError::Rejected("r".into()).to_string(), "sponsorship rejected: r");
        assert_eq!(PaymasterError::Network("n".into()).to_string(), "network error: n");
        assert_eq!(PaymasterError::Timeout.to_string(), "timeout");
    }

    #[test]
    fn variants_are_constructible() {
        let _ = PaymasterError::Service("a".into());
        let _ = PaymasterError::Bundler("b".into());
        let _ = PaymasterError::InvalidUserOp("c".into());
        let _ = PaymasterError::Rejected("d".into());
        let _ = PaymasterError::Network("e".into());
        let _ = PaymasterError::Timeout;
    }

    #[test]
    fn implements_std_error_trait() {
        let err: &dyn std::error::Error = &PaymasterError::Timeout;
        assert_eq!(err.to_string(), "timeout");
    }

    #[test]
    fn variants_have_no_source() {
        assert!(PaymasterError::Service("x".into()).source().is_none());
        assert!(PaymasterError::Timeout.source().is_none());
    }
}
