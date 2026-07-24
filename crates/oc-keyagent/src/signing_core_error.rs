use thiserror::Error;

#[derive(Debug, Error)]
pub enum SigningCoreError {
    #[error("key agent error: {0}")]
    KeyAgent(String),
    #[error("policy denied: {0}")]
    PolicyDenied(String),
    #[error("vault error: {0}")]
    Vault(String),
    #[error("signer error: {0}")]
    Signer(String),
    #[error("passkey error: {0}")]
    Passkey(String),
    #[error("audit error: {0}")]
    Audit(String),
    #[error("invalid input: {0}")]
    InvalidInput(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_key_agent() {
        let err = SigningCoreError::KeyAgent("timeout".into());
        assert_eq!(err.to_string(), "key agent error: timeout");
    }

    #[test]
    fn display_policy_denied() {
        let err = SigningCoreError::PolicyDenied("rate limit".into());
        assert_eq!(err.to_string(), "policy denied: rate limit");
    }

    #[test]
    fn display_vault() {
        let err = SigningCoreError::Vault("locked".into());
        assert_eq!(err.to_string(), "vault error: locked");
    }

    #[test]
    fn display_signer() {
        let err = SigningCoreError::Signer("bad key".into());
        assert_eq!(err.to_string(), "signer error: bad key");
    }

    #[test]
    fn display_passkey() {
        let err = SigningCoreError::Passkey("invalid".into());
        assert_eq!(err.to_string(), "passkey error: invalid");
    }

    #[test]
    fn display_audit() {
        let err = SigningCoreError::Audit("corrupt".into());
        assert_eq!(err.to_string(), "audit error: corrupt");
    }

    #[test]
    fn display_invalid_input() {
        let err = SigningCoreError::InvalidInput("HOME not set".into());
        assert_eq!(err.to_string(), "invalid input: HOME not set");
    }

    #[test]
    fn implements_std_error() {
        let err: &dyn std::error::Error = &SigningCoreError::KeyAgent("x".into());
        assert!(err.source().is_none());
    }

    #[test]
    fn is_debug() {
        let err = SigningCoreError::PolicyDenied("test".into());
        let dbg = format!("{err:?}");
        assert!(dbg.contains("PolicyDenied"));
    }
}
