use serde::{Deserialize, Serialize};

/// How gas should be paid for a UserOp.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum SponsorStrategy {
    /// Gas sponsored for free (Verifying Paymaster with off-chain signature).
    Sponsored,
    /// User pays gas in USDC (ERC-20 Paymaster, 1 USDC = X gas units).
    PayInUsdc,
    /// User pays gas in native token (no paymaster).
    #[default]
    Native,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_native() {
        assert_eq!(SponsorStrategy::default(), SponsorStrategy::Native);
    }

    #[test]
    fn variants_are_distinct() {
        assert_ne!(SponsorStrategy::Sponsored, SponsorStrategy::Native);
        assert_ne!(SponsorStrategy::PayInUsdc, SponsorStrategy::Native);
        assert_ne!(SponsorStrategy::Sponsored, SponsorStrategy::PayInUsdc);
    }

    #[test]
    fn serde_roundtrip() {
        for strat in
            [SponsorStrategy::Sponsored, SponsorStrategy::PayInUsdc, SponsorStrategy::Native]
        {
            let json = serde_json::to_string(&strat).expect("serialize");
            let back: SponsorStrategy = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(strat, back);
        }
    }

    #[test]
    fn serde_json_shape_is_string() {
        let json = serde_json::to_string(&SponsorStrategy::Sponsored).unwrap();
        assert_eq!(json, r#""Sponsored""#);
    }

    #[test]
    fn deserialize_from_string() {
        let s: SponsorStrategy = serde_json::from_str(r#""PayInUsdc""#).unwrap();
        assert_eq!(s, SponsorStrategy::PayInUsdc);
    }

    #[test]
    fn deserialize_invalid_variant_fails() {
        let result: Result<SponsorStrategy, _> = serde_json::from_str(r#""Invalid""#);
        assert!(result.is_err());
    }

    #[test]
    fn clone_preserves_value() {
        let a = SponsorStrategy::Sponsored;
        let b = a.clone();
        assert_eq!(a, b);
    }
}
