/// How gas should be sponsored for a UserOp.
pub use crate::sponsor::SponsorStrategy as SponsorMode;
use crate::{error::PaymasterError, sponsor::SponsorStrategy, user_op::UserOperation};

/// A UserOp that has been sponsored and submitted to the bundler.
#[derive(Debug, Clone)]
pub struct SponsoredUserOp {
    pub user_op: UserOperation,
    pub tx_hash: String,
    pub sponsor_strategy: SponsorStrategy,
}

/// Client for interacting with a Paymaster + Bundler service (Pimlico, Stackup, etc.).
pub struct PaymasterClient {
    bundler_url: String,
    paymaster_url: String,
    // Stored for future HTTP integration (Stage 3).
    #[allow(dead_code)]
    api_key: String,
}

impl PaymasterClient {
    /// Create a new PaymasterClient.
    pub fn new(
        bundler_url: impl Into<String>,
        paymaster_url: impl Into<String>,
        api_key: impl Into<String>,
    ) -> Self {
        Self {
            bundler_url: bundler_url.into(),
            paymaster_url: paymaster_url.into(),
            api_key: api_key.into(),
        }
    }

    /// Create from environment variables.
    pub fn from_env() -> Result<Self, PaymasterError> {
        let bundler_url = std::env::var("OC_BUNDLER_URL")
            .map_err(|_| PaymasterError::Service("OC_BUNDLER_URL not set".to_string()))?;
        let paymaster_url = std::env::var("OC_PAYMASTER_URL")
            .map_err(|_| PaymasterError::Service("OC_PAYMASTER_URL not set".to_string()))?;
        let api_key = std::env::var("OC_PAYMASTER_API_KEY").unwrap_or_default();
        Ok(Self::new(bundler_url, paymaster_url, api_key))
    }

    /// Sponsor a UserOp and submit it to the bundler.
    ///
    /// This is a mock implementation — real HTTP calls would use hpx.
    /// For now, it returns a mock tx hash.
    pub async fn sponsor_user_op(
        &self,
        user_op: &UserOperation,
        mode: SponsorMode,
    ) -> Result<SponsoredUserOp, PaymasterError> {
        // 1. Request sponsorship from the Paymaster service
        let paymaster_and_data = self.request_sponsorship(user_op, &mode).await?;

        // 2. Attach paymaster data
        let sponsored = user_op.clone().with_paymaster(paymaster_and_data);

        // 3. Submit to bundler
        let tx_hash = self.submit_to_bundler(&sponsored).await?;

        Ok(SponsoredUserOp { user_op: sponsored, tx_hash, sponsor_strategy: mode })
    }

    /// Request paymaster sponsorship (mock — returns a dummy paymasterAndData).
    // Async signature preserved for future HTTP integration (Stage 3).
    #[allow(clippy::unused_async_trait_impl)]
    async fn request_sponsorship(
        &self,
        _user_op: &UserOperation,
        mode: &SponsorMode,
    ) -> Result<String, PaymasterError> {
        match mode {
            SponsorMode::Native => Ok("0x".to_string()),
            SponsorMode::Sponsored => {
                // Mock: paymaster address + validity timestamp + signature
                Ok(format!("0x{}{}", "0".repeat(40), "0".repeat(130)))
            }
            SponsorMode::PayInUsdc => {
                // Mock: paymaster address + token approval data
                Ok(format!("0x{}{}", "0".repeat(40), "0".repeat(64)))
            }
        }
    }

    /// Submit a UserOp to the bundler (mock — returns a dummy tx hash).
    // Async signature preserved for future HTTP integration (Stage 3).
    #[allow(clippy::unused_async_trait_impl)]
    async fn submit_to_bundler(&self, _user_op: &UserOperation) -> Result<String, PaymasterError> {
        // Mock: return a dummy tx hash
        Ok(format!("0x{}", "0".repeat(64)))
    }

    /// Get the bundler URL.
    pub fn bundler_url(&self) -> &str {
        &self.bundler_url
    }

    /// Get the paymaster URL.
    pub fn paymaster_url(&self) -> &str {
        &self.paymaster_url
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;

    const SENDER: &str = "0x1234567890abcdef1234567890abcdef12345678";

    fn client() -> PaymasterClient {
        PaymasterClient::new(
            "https://bundler.example.com",
            "https://paymaster.example.com",
            "test-key",
        )
    }

    #[test]
    fn new_stores_urls_and_key() {
        let c = client();
        assert_eq!(c.bundler_url(), "https://bundler.example.com");
        assert_eq!(c.paymaster_url(), "https://paymaster.example.com");
    }

    #[tokio::test]
    async fn sponsor_native_mode_returns_empty_paymaster() {
        let c = client();
        let op = UserOperation::builder(SENDER).build();
        let result = c.sponsor_user_op(&op, SponsorMode::Native).await;
        let sponsored = result.expect("native sponsor ok");
        assert_eq!(sponsored.user_op.paymaster_and_data, "0x");
        assert_eq!(sponsored.sponsor_strategy, SponsorMode::Native);
        // mock tx hash: 0x + 64 hex chars
        assert_eq!(sponsored.tx_hash.len(), 2 + 64);
        assert!(sponsored.tx_hash.starts_with("0x"));
    }

    #[tokio::test]
    async fn sponsor_sponsored_mode_attaches_paymaster_data() {
        let c = client();
        let op = UserOperation::builder(SENDER).build();
        let sponsored = c.sponsor_user_op(&op, SponsorMode::Sponsored).await.expect("sponsored ok");
        // sponsored paymaster_and_data should be longer than the native "0x"
        assert_ne!(sponsored.user_op.paymaster_and_data, "0x");
        assert!(sponsored.user_op.paymaster_and_data.starts_with("0x"));
    }

    #[tokio::test]
    async fn sponsor_payin_usdc_mode_attaches_paymaster_data() {
        let c = client();
        let op = UserOperation::builder(SENDER).build();
        let sponsored =
            c.sponsor_user_op(&op, SponsorMode::PayInUsdc).await.expect("usdc sponsor ok");
        assert_ne!(sponsored.user_op.paymaster_and_data, "0x");
        assert_eq!(sponsored.sponsor_strategy, SponsorMode::PayInUsdc);
    }

    #[tokio::test]
    async fn sponsor_preserves_user_op_fields() {
        let c = client();
        let op = UserOperation::builder(SENDER).nonce("0x99").call_data("0xcafe").build();
        let sponsored = c.sponsor_user_op(&op, SponsorMode::Native).await.expect("ok");
        assert_eq!(sponsored.user_op.sender, SENDER);
        assert_eq!(sponsored.user_op.nonce, "0x99");
        assert_eq!(sponsored.user_op.call_data, "0xcafe");
    }

    #[test]
    fn from_env_fails_without_vars() {
        // Ensure no env vars leak in (unset for this test).
        // SAFETY of test isolation: tests in the same process share env; we only
        // assert that *when unset* from_env errors. We do not set/unset here to
        // avoid interfering with other tests.
        if std::env::var("OC_BUNDLER_URL").is_err() {
            assert!(PaymasterClient::from_env().is_err());
        }
    }

    #[test]
    fn error_is_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(PaymasterError::Timeout);
        assert_eq!(err.to_string(), "timeout");
    }

    #[test]
    fn error_variants_have_no_source() {
        assert!(PaymasterError::Service("x".into()).source().is_none());
    }

    #[tokio::test]
    async fn sponsored_user_op_has_correct_strategy_for_all_modes() {
        let c = client();
        let op = UserOperation::builder(SENDER).build();
        for mode in [SponsorMode::Native, SponsorMode::Sponsored, SponsorMode::PayInUsdc] {
            let result = c.sponsor_user_op(&op, mode.clone()).await.unwrap();
            assert_eq!(result.sponsor_strategy, mode);
        }
    }

    #[tokio::test]
    async fn tx_hash_format_is_0x_plus_64_hex_chars() {
        let c = client();
        let op = UserOperation::builder(SENDER).build();
        for mode in [SponsorMode::Native, SponsorMode::Sponsored, SponsorMode::PayInUsdc] {
            let result = c.sponsor_user_op(&op, mode).await.unwrap();
            assert!(result.tx_hash.starts_with("0x"));
            assert_eq!(result.tx_hash.len(), 66);
        }
    }
}
