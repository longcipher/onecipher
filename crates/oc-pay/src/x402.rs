//! Minimal x402 types (Phase 1 MVP).
//!
//! Per the T18 deviation note, the Open Wallet Standard's `ows-pay` types are
//! not vendored, so this module defines the minimum x402 types `oc-pay` needs
//! to express the `exact` / `exact+UserOp` schemes and the facilitator request
//! / response envelope. Real x402 wire-format compliance (matching the x402
//! spec's JSON schema exactly, supporting `upto` / `aggr_deferred`, etc.) is
//! T19's job.

use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};

use crate::{
    error::PayError,
    types::{Caip19Asset, PaymentScheme},
};

/// x402 payment-requirements block, sent by the resource server in a 402
/// response and echoed back in the facilitator request.
///
/// Phase 1 carries only the fields the settlers need to pick a scheme and an
/// asset. Real x402 carries `description`, `max_timeout_seconds`, `mimeType`,
/// `resource`, etc.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentRequirements {
    /// CAIP-19 asset the server demands payment in.
    pub asset: Caip19Asset,
    /// Amount demanded, in the asset's smallest on-chain unit.
    pub amount: Decimal,
    /// Scheme the server will accept (`exact` or `exact+userop`).
    pub scheme: PaymentScheme,
    /// Payee address (CAIP-10 or Tempo peer id).
    pub payee: String,
    /// Optional URL of the x402 facilitator that will verify / settle the
    /// payment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub facilitator_url: Option<String>,
}

/// Payload sent to the x402 facilitator's `verify` endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FacilitatorRequest {
    /// The payment-requirements block from the 402 response.
    pub requirements: PaymentRequirements,
    /// The payer's settlement payload — scheme-specific:
    /// - `exact`: a signed EVM tx or Solana tx (hex / base58 string).
    /// - `exact+userop`: a signed EIP-4337 UserOp (hex string).
    pub payment_payload: PaymentPayload,
}

/// Response from the x402 facilitator's `verify` / `settle` endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FacilitatorResponse {
    /// `true` if the facilitator verified / settled the payment.
    pub ok: bool,
    /// Human-readable error message when `ok == false`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// On-chain settlement tx hash / signature (set when `ok == true` and the
    /// facilitator actually settled).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<String>,
}

/// Scheme-specific payload carried in a [`FacilitatorRequest`].
///
/// Phase 1 carries the payload as an opaque string — the settler knows how to
/// interpret it based on [`PaymentRequirements::scheme`]. Real x402 uses a
/// structured `kind` + `data` JSON object.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PaymentPayload {
    /// Signed EVM tx (`0x`-prefixed hex) — used by `exact` on EVM chains.
    Exact { raw_hex: String },
    /// Signed EIP-4337 UserOp (hex string) — used by `exact+userop`.
    #[serde(rename = "exact+userop")]
    ExactPlusUserOp { user_op_hex: String },
}

/// Marker trait for an x402 scheme handler.
///
/// Phase 1 keeps this minimal — the settlers consume `PaymentScheme` directly
/// and produce / verify payloads inline. The trait exists so future phases can
/// plug in scheme-specific verify / settle logic without touching the
/// settlers.
pub trait X402Scheme: Send + Sync {
    /// The [`PaymentScheme`] variant this handler implements.
    fn scheme(&self) -> PaymentScheme;

    /// Validate that a [`PaymentPayload`] matches this scheme.
    fn validate_payload(&self, payload: &PaymentPayload) -> Result<(), PayError>;
}

/// Handler for the `exact` scheme.
#[derive(Debug, Default, Clone, Copy)]
pub struct ExactScheme;

impl X402Scheme for ExactScheme {
    fn scheme(&self) -> PaymentScheme {
        PaymentScheme::Exact
    }

    fn validate_payload(&self, payload: &PaymentPayload) -> Result<(), PayError> {
        match payload {
            PaymentPayload::Exact { raw_hex } => {
                if raw_hex.is_empty() {
                    return Err(PayError::InvalidRecipient("exact payload is empty".into()));
                }
                Ok(())
            }
            other => {
                Err(PayError::InvalidRecipient(format!("exact scheme rejects {:?} payload", other)))
            }
        }
    }
}

/// Handler for the `exact+userop` scheme.
#[derive(Debug, Default, Clone, Copy)]
pub struct ExactPlusUserOpScheme;

impl X402Scheme for ExactPlusUserOpScheme {
    fn scheme(&self) -> PaymentScheme {
        PaymentScheme::ExactPlusUserOp
    }

    fn validate_payload(&self, payload: &PaymentPayload) -> Result<(), PayError> {
        match payload {
            PaymentPayload::ExactPlusUserOp { user_op_hex } => {
                if user_op_hex.is_empty() {
                    return Err(PayError::InvalidRecipient("exact+userop payload is empty".into()));
                }
                Ok(())
            }
            other => Err(PayError::InvalidRecipient(format!(
                "exact+userop scheme rejects {:?} payload",
                other
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payment_requirements_serde_roundtrip() {
        let req = PaymentRequirements {
            asset: Caip19Asset::unchecked("eip155:8453/slip44:60"),
            amount: Decimal::from(42),
            scheme: PaymentScheme::ExactPlusUserOp,
            payee: "0xpayee".into(),
            facilitator_url: Some("https://facilitator.example/verify".into()),
        };
        let json = serde_json::to_string(&req).unwrap();
        let req2: PaymentRequirements = serde_json::from_str(&json).unwrap();
        assert_eq!(req, req2);
    }

    #[test]
    fn test_payment_payload_tagged_serde() {
        let p = PaymentPayload::ExactPlusUserOp { user_op_hex: "deadbeef".into() };
        let json = serde_json::to_string(&p).unwrap();
        assert!(json.contains("\"exact+userop\""));
        let p2: PaymentPayload = serde_json::from_str(&json).unwrap();
        match p2 {
            PaymentPayload::ExactPlusUserOp { user_op_hex } => {
                assert_eq!(user_op_hex, "deadbeef");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_exact_scheme_validates_exact_payload() {
        let s = ExactScheme;
        let p = PaymentPayload::Exact { raw_hex: "0xdead".into() };
        assert!(s.validate_payload(&p).is_ok());
    }

    #[test]
    fn test_exact_scheme_rejects_userop_payload() {
        let s = ExactScheme;
        let p = PaymentPayload::ExactPlusUserOp { user_op_hex: "dead".into() };
        assert!(s.validate_payload(&p).is_err());
    }

    #[test]
    fn test_exact_scheme_rejects_empty_payload() {
        let s = ExactScheme;
        let p = PaymentPayload::Exact { raw_hex: String::new() };
        assert!(s.validate_payload(&p).is_err());
    }

    #[test]
    fn test_exact_plus_userop_scheme_validates_userop_payload() {
        let s = ExactPlusUserOpScheme;
        let p = PaymentPayload::ExactPlusUserOp { user_op_hex: "deadbeef".into() };
        assert!(s.validate_payload(&p).is_ok());
    }

    #[test]
    fn test_exact_plus_userop_scheme_rejects_exact_payload() {
        let s = ExactPlusUserOpScheme;
        let p = PaymentPayload::Exact { raw_hex: "0xdead".into() };
        assert!(s.validate_payload(&p).is_err());
    }
}
