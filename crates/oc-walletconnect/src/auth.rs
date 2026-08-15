//! WalletConnect v2 Auth protocol (generic, protocol-level).
//!
//! The WC v2 Auth protocol lets a dApp request a **one-time** sign-in
//! signature on a *pairing* topic — no session negotiation is required. The
//! wallet builds an EIP-4361 (SIWE) message from the dApp's params, the user
//! approves it, and the signature is returned over the relay.
//!
//! This module is deliberately signer-agnostic: it only **builds** and
//! **parses** auth request params and serializes the EIP-4361 message text.
//! Signing stays in `oc-keyagent` (via the Net-Agent's method router), so the
//! protocol crate has no private-key dependency.
//!
//! # EIP-4361 (Sign-In with Ethereum)
//!
//! ```text
//! ${domain} wants you to sign in with your account:
//! ${address}
//!
//! ${statement}
//!
//! URI: ${uri}
//! Version: ${version}
//! Chain ID: ${chain-id}
//! Nonce: ${nonce}
//! Issued At: ${issued-at}
//! Expiration Time: ${expiration-time}
//! Not Before: ${not-before}
//! Request ID: ${request-id}
//! Resources:
//! - ${resource-1}
//! - ${resource-2}
//! ```
//!
//! For non-EVM chains (chain-id cannot be expressed as a decimal integer) the
//! raw CAIP-2 string is used in the `Chain ID:` field instead.

use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use thiserror::Error;

/// Errors produced while building or parsing WC v2 Auth requests.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthError {
    #[error("missing required field: {0}")]
    MissingField(&'static str),
    #[error("invalid value for {field}: {message}")]
    InvalidValue { field: &'static str, message: String },
    #[error("unsupported auth type: {0}")]
    UnsupportedType(String),
    #[error("unsupported chain: {0}")]
    UnsupportedChain(String),
}

/// Supported WC v2 Auth request types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthType {
    /// EIP-4361 (SIWE) message signing — the default for EVM chains.
    Eip4361,
    /// Plain EIP-191 message signing (`aud || "\n" || nonce`, or a raw
    /// `message` field when present).
    Eip191,
}

impl AuthType {
    /// Parse an auth `type` string, rejecting unknown values.
    pub fn parse(s: &str) -> Result<Self, AuthError> {
        match s {
            "eip4361" => Ok(Self::Eip4361),
            "eip191" => Ok(Self::Eip191),
            other => Err(AuthError::UnsupportedType(other.to_string())),
        }
    }
}

/// Params of a `wc_authRequest` (per the WC v2 Auth spec).
///
/// Field names match the wire format exactly (camelCase). `resources`,
/// `version`, `issued_at`, `expiration_time` and `request_id` are optional
/// EIP-4361 extensions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthRequestParams {
    /// Request type: `eip4361` (default) or `eip191`.
    #[serde(default = "default_auth_type")]
    pub r#type: AuthType,
    /// CAIP-2 chain id the dApp wants the signature for (e.g. `eip155:1`).
    #[serde(rename = "chainId")]
    pub chain_id: String,
    /// Audience URI (the dApp's origin) — becomes the EIP-4361 `URI:` field.
    pub aud: String,
    /// Domain the message is scoped to — becomes the EIP-4361 domain line.
    pub domain: String,
    /// Server-issued single-use nonce.
    pub nonce: String,
    /// Optional human-readable statement appended to the message.
    #[serde(default)]
    pub statement: String,
    /// Optional list of resource URIs the dApp references.
    #[serde(default)]
    pub resources: Vec<String>,
    /// EIP-4361 version (defaults to `1`).
    #[serde(default = "default_version")]
    pub version: String,
    /// EIP-4361 `Issued At` timestamp (RFC 3339).
    #[serde(default, rename = "issuedAt")]
    pub issued_at: String,
    /// EIP-4361 `Expiration Time` timestamp (RFC 3339).
    #[serde(default, rename = "expirationTime")]
    pub expiration_time: String,
    /// EIP-4361 `Request ID` (opaque, echoed back verbatim).
    #[serde(default, rename = "requestId")]
    pub request_id: String,
}

fn default_auth_type() -> AuthType {
    AuthType::Eip4361
}

fn default_version() -> String {
    "1".to_string()
}

impl AuthRequestParams {
    /// Validate the required fields are present and well-formed.
    ///
    /// Returns an error naming the first missing/invalid field. Optional
    /// fields (statement, resources, issued_at, expiration_time, request_id)
    /// may be empty.
    pub fn validate(&self) -> Result<(), AuthError> {
        if self.chain_id.is_empty() {
            return Err(AuthError::MissingField("chainId"));
        }
        if self.aud.is_empty() {
            return Err(AuthError::MissingField("aud"));
        }
        if self.domain.is_empty() {
            return Err(AuthError::MissingField("domain"));
        }
        if self.nonce.is_empty() {
            return Err(AuthError::MissingField("nonce"));
        }
        if self.nonce.len() < 8 {
            return Err(AuthError::InvalidValue {
                field: "nonce",
                message: "must be at least 8 characters (single-use, unpredictable)".into(),
            });
        }
        if self.version.is_empty() {
            return Err(AuthError::MissingField("version"));
        }
        Ok(())
    }
}

/// Build an EIP-4361 (SIWE) message for `address` from the auth request
/// params.
///
/// The `Chain ID:` field is the decimal chain id for EVM chains
/// (`eip155:<n>`) and the raw CAIP-2 string for every other chain namespace.
///
/// # Errors
///
/// Returns [`AuthError::MissingField`] / [`AuthError::InvalidValue`] when a
/// required field is absent or malformed, and [`AuthError::UnsupportedChain`]
/// for EVM chain ids whose decimal part cannot be parsed.
pub fn build_siwe_message(address: &str, params: &AuthRequestParams) -> Result<String, AuthError> {
    params.validate()?;
    if address.is_empty() {
        return Err(AuthError::MissingField("address"));
    }

    let chain_id = chain_id_field(&params.chain_id)?;

    let mut msg = String::new();
    msg.push_str(&params.domain);
    msg.push_str(" wants you to sign in with your account:\n");
    msg.push_str(address);
    msg.push('\n');

    // Optional statement: preceded by a blank line and followed by one.
    if !params.statement.is_empty() {
        msg.push('\n');
        msg.push_str(&params.statement);
        msg.push('\n');
    }
    // Blank line separating the header from the fields.
    msg.push('\n');

    msg.push_str("URI: ");
    msg.push_str(&params.aud);
    msg.push_str("\nVersion: ");
    msg.push_str(&params.version);
    msg.push_str("\nChain ID: ");
    msg.push_str(&chain_id);
    msg.push_str("\nNonce: ");
    msg.push_str(&params.nonce);
    msg.push_str("\nIssued At: ");
    let issued_at = if params.issued_at.is_empty() {
        crate::session::now_rfc3339()
    } else {
        params.issued_at.clone()
    };
    msg.push_str(&issued_at);

    if !params.expiration_time.is_empty() {
        msg.push_str("\nExpiration Time: ");
        msg.push_str(&params.expiration_time);
    }
    if !params.request_id.is_empty() {
        msg.push_str("\nRequest ID: ");
        msg.push_str(&params.request_id);
    }
    if !params.resources.is_empty() {
        msg.push_str("\nResources:");
        for r in &params.resources {
            msg.push_str("\n- ");
            msg.push_str(r);
        }
    }

    Ok(msg)
}

/// EIP-4361 message hash — `keccak256(message)`, the value that is signed.
pub fn eip4361_hash(message: &str) -> [u8; 32] {
    Keccak256::digest(message.as_bytes()).into()
}

/// Resolve the EIP-4361 `Chain ID:` field from a CAIP-2 chain id.
///
/// `eip155:1` → `"1"`; any other namespace keeps the CAIP-2 string as-is.
fn chain_id_field(caip2: &str) -> Result<String, AuthError> {
    if let Some(ns) = caip2.split_once(':') {
        if ns.0 == "eip155" {
            // The decimal part must be a valid u64 for EVM chains.
            let decimal: u64 = ns.1.parse().map_err(|_| AuthError::InvalidValue {
                field: "chainId",
                message: format!("'{caip2}' has a non-numeric eip155 reference"),
            })?;
            return Ok(decimal.to_string());
        }
        return Ok(caip2.to_string());
    }
    Err(AuthError::InvalidValue {
        field: "chainId",
        message: format!("'{caip2}' is not a CAIP-2 chain id"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_params() -> AuthRequestParams {
        AuthRequestParams {
            r#type: AuthType::Eip4361,
            chain_id: "eip155:1".into(),
            aud: "https://service.invalid/login".into(),
            domain: "service.invalid".into(),
            nonce: "a1b2c3d4e5f6".into(),
            statement: "Sign in to the example service.".into(),
            resources: vec!["https://service.invalid/terms".into()],
            version: "1".into(),
            issued_at: "2021-09-30T16:25:24Z".into(),
            expiration_time: "2021-09-30T16:26:24Z".into(),
            request_id: "request-123".into(),
        }
    }

    #[test]
    fn exact_siwe_message_format() {
        let msg = build_siwe_message("0x1234", &sample_params()).unwrap();
        let expected = "service.invalid wants you to sign in with your account:\n\
            0x1234\n\
            \n\
            Sign in to the example service.\n\
            \n\
            URI: https://service.invalid/login\n\
            Version: 1\n\
            Chain ID: 1\n\
            Nonce: a1b2c3d4e5f6\n\
            Issued At: 2021-09-30T16:25:24Z\n\
            Expiration Time: 2021-09-30T16:26:24Z\n\
            Request ID: request-123\n\
            Resources:\n\
            - https://service.invalid/terms";
        assert_eq!(msg, expected);
    }

    #[test]
    fn siwe_message_without_optionals() {
        let params = AuthRequestParams {
            statement: String::new(),
            resources: Vec::new(),
            expiration_time: String::new(),
            request_id: String::new(),
            ..sample_params()
        };
        let msg = build_siwe_message("0x1234", &params).unwrap();
        let expected = "service.invalid wants you to sign in with your account:\n\
            0x1234\n\
            \n\
            URI: https://service.invalid/login\n\
            Version: 1\n\
            Chain ID: 1\n\
            Nonce: a1b2c3d4e5f6\n\
            Issued At: 2021-09-30T16:25:24Z";
        assert_eq!(msg, expected);
    }

    #[test]
    fn non_evm_chain_uses_caip2_string() {
        let params = AuthRequestParams {
            chain_id: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp".into(),
            ..sample_params()
        };
        let msg = build_siwe_message("addr", &params).unwrap();
        assert!(msg.contains("Chain ID: solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp\n"));
    }

    #[test]
    fn invalid_evm_chain_reference_rejected() {
        let params =
            AuthRequestParams { chain_id: "eip155:not-a-number".into(), ..sample_params() };
        assert!(matches!(
            build_siwe_message("0x1", &params),
            Err(AuthError::InvalidValue { field: "chainId", .. })
        ));
    }

    #[test]
    fn validate_requires_required_fields() {
        assert_eq!(sample_params().validate(), Ok(()));

        let mut p = sample_params();
        p.chain_id.clear();
        assert_eq!(p.validate(), Err(AuthError::MissingField("chainId")));

        let mut p = sample_params();
        p.nonce.clear();
        assert_eq!(p.validate(), Err(AuthError::MissingField("nonce")));

        let mut p = sample_params();
        p.nonce = "short".into();
        assert!(matches!(p.validate(), Err(AuthError::InvalidValue { field: "nonce", .. })));
    }

    #[test]
    fn auth_type_parsing() {
        assert_eq!(AuthType::parse("eip4361"), Ok(AuthType::Eip4361));
        assert_eq!(AuthType::parse("eip191"), Ok(AuthType::Eip191));
        assert!(matches!(AuthType::parse("solana"), Err(AuthError::UnsupportedType(_))));
    }

    #[test]
    fn request_params_serde_roundtrip() {
        let json = serde_json::to_value(&sample_params()).unwrap();
        let parsed: AuthRequestParams = serde_json::from_value(json).unwrap();
        assert_eq!(parsed, sample_params());
    }

    #[test]
    fn request_params_defaults_type_and_version() {
        // `type` and `version` are optional on the wire and default when absent.
        let json = serde_json::json!({
            "chainId": "eip155:1",
            "aud": "https://x.invalid",
            "domain": "x.invalid",
            "nonce": "abcdefgh12345678"
        });
        let parsed: AuthRequestParams = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.r#type, AuthType::Eip4361);
        assert_eq!(parsed.version, "1");
        assert!(parsed.statement.is_empty());
    }

    #[test]
    fn eip4361_hash_matches_known_vector() {
        // keccak256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
        let hash = eip4361_hash("");
        assert_eq!(
            hex::encode(hash),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
        // Deterministic across calls.
        assert_eq!(eip4361_hash("abc"), eip4361_hash("abc"));
        let _ = eip4361_hash("a different message");
    }
}
