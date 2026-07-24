use base64::{Engine, engine::general_purpose::STANDARD as B64};

use super::{
    chains,
    error::{OcPayHttpError, OcPayHttpErrorCode},
    types::{
        Eip3009Authorization, Eip3009Payload, PayResult, PaymentInfo, PaymentPayload,
        PaymentPayloadV1, PaymentPayloadV2, PaymentRequirements, Protocol, X402Response,
    },
    wallet::WalletAccess,
};

const HEADER_PAYMENT_REQUIRED: &str = "x-payment-required";
const HEADER_PAYMENT_REQUIRED_V2: &str = "payment-required";
const HEADER_PAYMENT: &str = "X-PAYMENT";
const HEADER_PAYMENT_V2: &str = "payment-signature";

/// Handle x402 payment for a 402 response we already received.
pub(crate) async fn handle_x402(
    wallet: &dyn WalletAccess,
    url: &str,
    method: &str,
    req_body: Option<&str>,
    resp_headers: &hpx::header::HeaderMap,
    body_402: &str,
) -> Result<PayResult, OcPayHttpError> {
    let (x402_version, resource, requirements) = parse_requirements(resp_headers, body_402)?;
    let (req, network) = pick_payment_option(wallet, &requirements)?;

    let (payload, payment_info) =
        build_signed_payment(wallet, req, &network, x402_version, resource)?;

    let payload_json = serde_json::to_string(&payload)?;
    let payload_b64 = B64.encode(payload_json.as_bytes());

    let client = hpx::Client::new();
    let retry = build_request(&client, url, method, req_body, Some(&payload_b64))?.send().await?;

    let status = retry.status().as_u16();
    let response_body = retry.text().await.unwrap_or_default();

    Ok(PayResult {
        protocol: Protocol::X402,
        status,
        body: response_body,
        payment: Some(payment_info),
    })
}

// ---------------------------------------------------------------------------
// Scheme dispatch
// ---------------------------------------------------------------------------

/// Build a signed payment payload, dispatching on the scheme.
fn build_signed_payment(
    wallet: &dyn WalletAccess,
    req: &PaymentRequirements,
    network: &str,
    x402_version: u32,
    resource: Option<serde_json::Value>,
) -> Result<(PaymentPayload, PaymentInfo), OcPayHttpError> {
    match req.scheme.as_str() {
        "exact" => build_evm_exact(wallet, req, network, x402_version, resource),
        scheme => Err(OcPayHttpError::new(
            OcPayHttpErrorCode::ProtocolUnknown,
            format!("unsupported payment scheme: {scheme}"),
        )),
    }
}

/// Build an EVM "exact" (EIP-3009 TransferWithAuthorization) payment.
fn build_evm_exact(
    wallet: &dyn WalletAccess,
    req: &PaymentRequirements,
    network: &str,
    x402_version: u32,
    resource: Option<serde_json::Value>,
) -> Result<(PaymentPayload, PaymentInfo), OcPayHttpError> {
    let account = wallet.account(network)?;

    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let valid_after = now.saturating_sub(5);
    let valid_before = now + req.max_timeout_seconds;

    let mut nonce_bytes = [0u8; 32];
    getrandom::fill(&mut nonce_bytes)
        .map_err(|e| OcPayHttpError::new(OcPayHttpErrorCode::SigningFailed, format!("rng: {e}")))?;
    let nonce_hex = format!("0x{}", hex::encode(nonce_bytes));

    let token_name = req.extra.get("name").and_then(|v| v.as_str()).unwrap_or("USD Coin");
    let token_version = req.extra.get("version").and_then(|v| v.as_str()).unwrap_or("2");

    let chain_id_num = oc_core::parse_chain(network)
        .map_err(|err| OcPayHttpError::new(OcPayHttpErrorCode::ProtocolMalformed, err))?
        .evm_chain_id_u64()
        .map_err(|err| OcPayHttpError::new(OcPayHttpErrorCode::ProtocolMalformed, err))?;

    let typed_data_json = serde_json::json!({
        "types": {
            "EIP712Domain": [
                { "name": "name", "type": "string" },
                { "name": "version", "type": "string" },
                { "name": "chainId", "type": "uint256" },
                { "name": "verifyingContract", "type": "address" }
            ],
            "TransferWithAuthorization": [
                { "name": "from", "type": "address" },
                { "name": "to", "type": "address" },
                { "name": "value", "type": "uint256" },
                { "name": "validAfter", "type": "uint256" },
                { "name": "validBefore", "type": "uint256" },
                { "name": "nonce", "type": "bytes32" }
            ]
        },
        "primaryType": "TransferWithAuthorization",
        "domain": {
            "name": token_name,
            "version": token_version,
            "chainId": chain_id_num.to_string(),
            "verifyingContract": req.asset
        },
        "message": {
            "from": account.address,
            "to": req.pay_to,
            "value": req.amount,
            "validAfter": valid_after.to_string(),
            "validBefore": valid_before.to_string(),
            "nonce": &nonce_hex
        }
    })
    .to_string();

    let signature = wallet.sign_payload(&req.scheme, network, &typed_data_json)?;

    let eip3009 = Eip3009Payload {
        signature,
        authorization: Eip3009Authorization {
            from: account.address,
            to: req.pay_to.clone(),
            value: req.amount.clone(),
            valid_after: valid_after.to_string(),
            valid_before: valid_before.to_string(),
            nonce: nonce_hex,
        },
    };

    let inner = serde_json::to_value(eip3009)?;
    let payload = if x402_version >= 2 {
        PaymentPayload::V2(PaymentPayloadV2 {
            x402_version,
            accepted: req.clone(),
            resource,
            payload: inner,
        })
    } else {
        PaymentPayload::V1(PaymentPayloadV1 {
            x402_version,
            scheme: req.scheme.clone(),
            network: req.network.clone(),
            payload: inner,
        })
    };

    let amount_display = super::discovery::format_usdc(&req.amount);
    let payment_info = PaymentInfo {
        amount: amount_display,
        network: chains::display_name(network).to_string(),
        token: "USDC".to_string(),
    };

    Ok((payload, payment_info))
}

// ---------------------------------------------------------------------------
// Requirement parsing & chain selection
// ---------------------------------------------------------------------------

fn parse_requirements(
    headers: &hpx::header::HeaderMap,
    body_text: &str,
) -> Result<(u32, Option<serde_json::Value>, Vec<PaymentRequirements>), OcPayHttpError> {
    for header_name in &[HEADER_PAYMENT_REQUIRED_V2, HEADER_PAYMENT_REQUIRED] {
        if let Some(header_val) = headers.get(*header_name) {
            if let Ok(header_str) = header_val.to_str() {
                if let Ok(decoded) = B64.decode(header_str) {
                    if let Ok(parsed) = serde_json::from_slice::<X402Response>(&decoded) {
                        if !parsed.accepts.is_empty() {
                            let version = match *header_name {
                                HEADER_PAYMENT_REQUIRED_V2 => parsed.x402_version.unwrap_or(2),
                                _ => parsed.x402_version.unwrap_or(1),
                            };
                            return Ok((version, parsed.resource, parsed.accepts));
                        }
                    }
                }
            }
        }
    }

    let parsed: X402Response = serde_json::from_str(body_text).map_err(|e| {
        OcPayHttpError::new(
            OcPayHttpErrorCode::ProtocolMalformed,
            format!("failed to parse x402 402 response: {e}"),
        )
    })?;

    if parsed.accepts.is_empty() {
        return Err(OcPayHttpError::new(
            OcPayHttpErrorCode::ProtocolMalformed,
            "402 response has empty accepts",
        ));
    }

    Ok((parsed.x402_version.unwrap_or(1), parsed.resource, parsed.accepts))
}

/// Payment schemes we know how to handle.
const SUPPORTED_SCHEMES: &[&str] = &["exact"];

fn is_gateway_batched(req: &PaymentRequirements) -> bool {
    req.extra
        .get("name")
        .and_then(|v| v.as_str())
        .is_some_and(|name| name == "GatewayWalletBatched")
}

fn parsed_amount(req: &PaymentRequirements) -> Option<u128> {
    req.amount.parse().ok()
}

/// Pick the first payment option whose scheme we support and whose
/// network the wallet supports. Returns the requirement and its
/// resolved CAIP-2 network string.
fn pick_payment_option<'a>(
    wallet: &dyn WalletAccess,
    requirements: &'a [PaymentRequirements],
) -> Result<(&'a PaymentRequirements, String), OcPayHttpError> {
    let supported = wallet.supported_chains();
    let mut candidates = Vec::new();

    for req in requirements {
        if !SUPPORTED_SCHEMES.contains(&req.scheme.as_str()) {
            continue;
        }

        // GatewayWalletBatched requires a pre-funded gateway wallet, which
        // this client does not currently manage.
        if is_gateway_batched(req) {
            continue;
        }

        let chain_type = match chains::resolve_chain_type(&req.network) {
            Some(ct) => ct,
            None => continue,
        };

        if !supported.contains(&chain_type) {
            continue;
        }

        // Resolve to CAIP-2 if the server sent a human name.
        let network = match oc_core::parse_chain(&req.network) {
            Ok(c) => c.chain_id.to_string(),
            Err(_) => req.network.clone(), /* Already CAIP-2 (unknown to registry but namespace
                                            * matched). */
        };

        candidates.push((req, network));
    }

    if let Some((_, first_network)) = candidates.first() {
        let mut best = &candidates[0];
        for candidate in candidates.iter().skip(1) {
            if candidate.1 != *first_network {
                break;
            }

            let current = parsed_amount(candidate.0);
            let best_amount = parsed_amount(best.0);
            if current.zip(best_amount).is_some_and(|(a, b)| a < b) {
                best = candidate;
            }
        }

        return Ok((best.0, best.1.clone()));
    }

    let networks: Vec<_> = requirements.iter().map(|r| r.network.as_str()).collect();
    Err(OcPayHttpError::new(
        OcPayHttpErrorCode::UnsupportedChain,
        format!(
            "no supported chain in 402 response (networks: {networks:?}, wallet supports: {supported:?})"
        ),
    ))
}

pub(crate) fn build_request(
    client: &hpx::Client,
    url: &str,
    method: &str,
    body: Option<&str>,
    payment_header: Option<&str>,
) -> Result<hpx::RequestBuilder, OcPayHttpError> {
    let mut req = match method.to_uppercase().as_str() {
        "GET" => client.get(url),
        "POST" => client.post(url),
        "PUT" => client.put(url),
        "DELETE" => client.delete(url),
        "PATCH" => client.patch(url),
        other => {
            return Err(OcPayHttpError::new(
                OcPayHttpErrorCode::InvalidInput,
                format!("unsupported HTTP method: {other}"),
            ))
        }
    };

    if let Some(b) = body {
        req = req.header("content-type", "application/json").body(b.to_string());
    }

    if let Some(payment) = payment_header {
        req = req.header(HEADER_PAYMENT, payment).header(HEADER_PAYMENT_V2, payment);
    }

    Ok(req)
}

// ---------------------------------------------------------------------------
// WWW-Authenticate header parsing (x402 scheme)
// ---------------------------------------------------------------------------

/// Payment requirements parsed from an x402 `WWW-Authenticate` header.
#[derive(Debug, Clone, PartialEq)]
pub struct X402PaymentRequirements {
    /// Maximum payment amount (in the asset's smallest unit or USD, depending
    /// on the spec).
    pub max_amount: f64,
    /// CAIP-19 asset identifier (e.g. `eip155:8453/erc20:0x8335...`).
    pub asset: String,
    /// CAIP-2 chain identifier (e.g. `eip155:8453`).
    pub chain_id: String,
    /// Recipient address the payment should be sent to.
    pub recipient: String,
    /// Payment scheme (e.g. `exact`, `exact-plus-userop`).
    pub scheme: String,
    /// Raw `WWW-Authenticate` header value, kept for debugging.
    pub raw_header: String,
}

/// Errors that can arise while parsing an x402 `WWW-Authenticate` header.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum X402ParseError {
    /// Header does not use the `x402` scheme.
    #[error("not an x402 header: {0}")]
    NotX402(String),
    /// A required field is missing from the header.
    #[error("missing required field: {0}")]
    MissingField(String),
    /// A field was present but could not be parsed.
    #[error("invalid field '{0}': {1}")]
    InvalidField(String, String),
}

/// Parse a `WWW-Authenticate` header value for x402 payment requirements.
///
/// Example header:
/// `x402 realm="x402", maxamount=0.01, asset="eip155:8453/erc20:0x8335...", chain_id="eip155:8453",
/// recipient="0xABC...", scheme="exact"`
pub fn parse_www_authenticate(header: &str) -> Result<X402PaymentRequirements, X402ParseError> {
    let header = header.trim();

    // Must start with the `x402` scheme (case-insensitive).
    if !header.to_lowercase().starts_with("x402") {
        return Err(X402ParseError::NotX402(header.to_string()));
    }

    // Parse key=value pairs, handling quoted and unquoted values.
    let params = parse_auth_params(&header[4..])?;

    let max_amount = params
        .get("maxamount")
        .ok_or_else(|| X402ParseError::MissingField("maxamount".to_string()))?
        .parse::<f64>()
        .map_err(|e| X402ParseError::InvalidField("maxamount".to_string(), e.to_string()))?;

    let asset = params
        .get("asset")
        .ok_or_else(|| X402ParseError::MissingField("asset".to_string()))?
        .clone();

    // `chain_id` may be derived from the CAIP-19 asset (the prefix before
    // `/`) or specified explicitly.
    let chain_id =
        params.get("chain_id").cloned().unwrap_or_else(|| derive_chain_id_from_asset(&asset));

    let recipient = params
        .get("recipient")
        .ok_or_else(|| X402ParseError::MissingField("recipient".to_string()))?
        .clone();

    let scheme = params.get("scheme").cloned().unwrap_or_else(|| "exact".to_string());

    Ok(X402PaymentRequirements {
        max_amount,
        asset,
        chain_id,
        recipient,
        scheme,
        raw_header: header.to_string(),
    })
}

/// Derive a CAIP-2 `chain_id` from a CAIP-19 asset identifier.
///
/// CAIP-19 format: `{chain_id}/{asset_namespace}:{asset_reference}`
/// Example: `eip155:8453/erc20:0x8335...` -> `eip155:8453`.
fn derive_chain_id_from_asset(asset: &str) -> String {
    match asset.find('/') {
        Some(idx) => asset[..idx].to_string(),
        None => asset.to_string(),
    }
}

/// Parse authentication parameters from a header value.
///
/// Handles both quoted (`"value"`) and unquoted values, tolerating extra
/// whitespace and commas between parameters.
fn parse_auth_params(s: &str) -> Result<std::collections::HashMap<String, String>, X402ParseError> {
    let mut params = std::collections::HashMap::new();
    let mut chars = s.chars().peekable();

    while chars.peek().is_some() {
        // Skip whitespace and commas separating parameters.
        while chars.peek().is_some_and(|c| c.is_whitespace() || *c == ',') {
            chars.next();
        }
        if chars.peek().is_none() {
            break;
        }

        // Read the key (until `=` or whitespace).
        let mut key = String::new();
        while chars.peek().is_some_and(|c| *c != '=' && !c.is_whitespace()) {
            if let Some(c) = chars.next() {
                key.push(c);
            }
        }

        // Skip whitespace between key and `=`.
        while chars.peek().is_some_and(|c| c.is_whitespace()) {
            chars.next();
        }

        // A parameter must be followed by `=`; skip bare tokens otherwise.
        if chars.peek() != Some(&'=') {
            while chars.peek().is_some_and(|c| *c != ',' && !c.is_whitespace()) {
                chars.next();
            }
            continue;
        }
        chars.next(); // consume `=`

        // Skip whitespace between `=` and value.
        while chars.peek().is_some_and(|c| c.is_whitespace()) {
            chars.next();
        }

        // Read the value — quoted or unquoted.
        let value = if chars.peek() == Some(&'"') {
            chars.next(); // consume opening quote
            let mut val = String::new();
            while chars.peek().is_some_and(|c| *c != '"') {
                if let Some(c) = chars.next() {
                    val.push(c);
                }
            }
            chars.next(); // consume closing quote
            val
        } else {
            let mut val = String::new();
            while chars.peek().is_some_and(|c| *c != ',' && !c.is_whitespace()) {
                if let Some(c) = chars.next() {
                    val.push(c);
                }
            }
            val
        };

        if !key.is_empty() {
            params.insert(key, value);
        }
    }

    Ok(params)
}

/// Extract payment requirements from an HTTP response's headers.
///
/// Looks for the `WWW-Authenticate` header (case-insensitive) and parses it.
pub fn parse_payment_requirements_from_headers(
    headers: &[(String, String)],
) -> Result<X402PaymentRequirements, X402ParseError> {
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("www-authenticate") {
            return parse_www_authenticate(value);
        }
    }
    Err(X402ParseError::MissingField("WWW-Authenticate header".to_string()))
}

#[cfg(test)]
mod www_authenticate_tests {
    use super::*;

    fn approx(a: f64, b: f64) -> bool {
        (a - b).abs() < 1e-9
    }

    // -----------------------------------------------------------------------
    // parse_www_authenticate
    // -----------------------------------------------------------------------

    #[test]
    fn parse_complete_header_with_all_fields() {
        let header = r#"x402 realm="x402", maxamount=0.01, asset="eip155:8453/erc20:0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", chain_id="eip155:8453", recipient="0xABC123", scheme="exact""#;
        let req = parse_www_authenticate(header).unwrap();
        assert!(approx(req.max_amount, 0.01));
        assert_eq!(req.asset, "eip155:8453/erc20:0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913");
        assert_eq!(req.chain_id, "eip155:8453");
        assert_eq!(req.recipient, "0xABC123");
        assert_eq!(req.scheme, "exact");
        assert_eq!(req.raw_header, header);
    }

    #[test]
    fn parse_header_derives_chain_id_from_asset() {
        let header = r#"x402 maxamount=1.0, asset="eip155:8453/erc20:0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", recipient="0xABC123""#;
        let req = parse_www_authenticate(header).unwrap();
        assert!(approx(req.max_amount, 1.0));
        assert_eq!(req.chain_id, "eip155:8453");
        assert_eq!(req.scheme, "exact"); // defaulted
    }

    #[test]
    fn parse_header_with_unquoted_values() {
        let header = r"x402 maxamount=0.5, asset=eip155:1/erc20:0xToken, recipient=0xRecipient, scheme=exact";
        let req = parse_www_authenticate(header).unwrap();
        assert!(approx(req.max_amount, 0.5));
        assert_eq!(req.asset, "eip155:1/erc20:0xToken");
        assert_eq!(req.chain_id, "eip155:1");
        assert_eq!(req.recipient, "0xRecipient");
        assert_eq!(req.scheme, "exact");
    }

    #[test]
    fn reject_non_x402_header() {
        let header = r#"Basic realm="foo", maxamount=0.01"#;
        let err = parse_www_authenticate(header).unwrap_err();
        assert_eq!(err, X402ParseError::NotX402(header.to_string()));
    }

    #[test]
    fn reject_missing_maxamount() {
        let header = r#"x402 asset="eip155:8453/erc20:0x8335", recipient="0xABC""#;
        let err = parse_www_authenticate(header).unwrap_err();
        assert_eq!(err, X402ParseError::MissingField("maxamount".to_string()));
    }

    #[test]
    fn reject_missing_asset() {
        let header = r#"x402 maxamount=0.01, recipient="0xABC""#;
        let err = parse_www_authenticate(header).unwrap_err();
        assert_eq!(err, X402ParseError::MissingField("asset".to_string()));
    }

    #[test]
    fn reject_missing_recipient() {
        let header = r#"x402 maxamount=0.01, asset="eip155:8453/erc20:0x8335""#;
        let err = parse_www_authenticate(header).unwrap_err();
        assert_eq!(err, X402ParseError::MissingField("recipient".to_string()));
    }

    #[test]
    fn handle_extra_whitespace() {
        let header = r#"x402   realm="x402"  ,  maxamount=0.01  ,  asset="eip155:8453/erc20:0x8335" , recipient="0xABC""#;
        let req = parse_www_authenticate(header).unwrap();
        assert!(approx(req.max_amount, 0.01));
        assert_eq!(req.asset, "eip155:8453/erc20:0x8335");
        assert_eq!(req.recipient, "0xABC");
    }

    #[test]
    fn handle_multiple_commas() {
        let header =
            r#"x402 ,, maxamount=0.01,, asset="eip155:8453/erc20:0x8335",, recipient="0xABC","#;
        let req = parse_www_authenticate(header).unwrap();
        assert!(approx(req.max_amount, 0.01));
        assert_eq!(req.asset, "eip155:8453/erc20:0x8335");
        assert_eq!(req.recipient, "0xABC");
    }

    #[test]
    fn parse_header_case_insensitive_scheme_prefix() {
        let header = r#"X402 maxamount=0.01, asset="eip155:8453/erc20:0x8335", recipient="0xABC""#;
        let req = parse_www_authenticate(header).unwrap();
        assert!(approx(req.max_amount, 0.01));
        assert_eq!(req.recipient, "0xABC");
    }

    #[test]
    fn parse_header_trims_leading_trailing_whitespace() {
        let header =
            r#"   x402 maxamount=0.01, asset="eip155:8453/erc20:0x8335", recipient="0xABC"   "#;
        let req = parse_www_authenticate(header).unwrap();
        assert_eq!(req.recipient, "0xABC");
        assert_eq!(req.raw_header, header.trim());
    }

    #[test]
    fn reject_invalid_maxamount() {
        let header =
            r#"x402 maxamount=not-a-number, asset="eip155:8453/erc20:0x8335", recipient="0xABC""#;
        let err = parse_www_authenticate(header).unwrap_err();
        assert!(matches!(err, X402ParseError::InvalidField(field, _) if field == "maxamount"));
    }

    // -----------------------------------------------------------------------
    // parse_payment_requirements_from_headers
    // -----------------------------------------------------------------------

    #[test]
    fn parse_from_headers_finds_www_authenticate() {
        let headers: Vec<(String, String)> = vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            (
                "WWW-Authenticate".to_string(),
                r#"x402 maxamount=0.01, asset="eip155:8453/erc20:0x8335", recipient="0xABC""#
                    .to_string(),
            ),
        ];
        let req = parse_payment_requirements_from_headers(&headers).unwrap();
        assert!(approx(req.max_amount, 0.01));
        assert_eq!(req.recipient, "0xABC");
    }

    #[test]
    fn parse_from_headers_case_insensitive_name() {
        let headers: Vec<(String, String)> = vec![(
            "www-authenticate".to_string(),
            r#"x402 maxamount=2.0, asset="eip155:1/slip44:60", recipient="0xDef""#.to_string(),
        )];
        let req = parse_payment_requirements_from_headers(&headers).unwrap();
        assert!(approx(req.max_amount, 2.0));
        assert_eq!(req.recipient, "0xDef");
    }

    #[test]
    fn parse_from_headers_missing_errors() {
        let headers: Vec<(String, String)> =
            vec![("Content-Type".to_string(), "application/json".to_string())];
        let err = parse_payment_requirements_from_headers(&headers).unwrap_err();
        assert_eq!(err, X402ParseError::MissingField("WWW-Authenticate header".to_string()));
    }

    // -----------------------------------------------------------------------
    // derive_chain_id_from_asset
    // -----------------------------------------------------------------------

    #[test]
    fn derive_chain_id_from_caip19() {
        assert_eq!(derive_chain_id_from_asset("eip155:8453/erc20:0x8335"), "eip155:8453");
    }

    #[test]
    fn derive_chain_id_no_slash_returns_input() {
        assert_eq!(derive_chain_id_from_asset("eip155:8453"), "eip155:8453");
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        sync::mpsc,
        thread,
        time::Duration,
    };

    use base64::{Engine, engine::general_purpose::STANDARD as B64};
    use hpx::header::HeaderMap;
    use oc_core::ChainType;

    use super::*;

    fn base_requirement() -> PaymentRequirements {
        PaymentRequirements {
            scheme: "exact".into(),
            network: "eip155:8453".into(),
            amount: "10000".into(),
            asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913".into(),
            pay_to: "0x1234567890abcdef1234567890abcdef12345678".into(),
            max_timeout_seconds: 60,
            extra: serde_json::json!({"name": "USD Coin", "version": "2"}),
            description: Some("test service".into()),
            resource: None,
        }
    }

    fn read_headers(stream: &mut std::net::TcpStream) -> String {
        stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();

        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    buf.extend_from_slice(&chunk[..n]);
                    if buf.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                Err(err)
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    break;
                }
                Err(err) => panic!("failed to read request: {err}"),
            }
        }

        String::from_utf8(buf).unwrap()
    }

    fn header_value(request: &str, header_name: &str) -> String {
        request
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case(header_name).then(|| value.trim().to_string())
            })
            .unwrap_or_else(|| panic!("missing header {header_name} in request:\n{request}"))
    }

    fn decode_payment_payload(encoded: &str) -> PaymentPayload {
        let decoded = B64.decode(encoded).unwrap();
        serde_json::from_slice(&decoded).unwrap()
    }

    fn spawn_x402_flow_server(
        payment_header_name: &str,
        payment_header_value: String,
    ) -> (String, mpsc::Receiver<String>, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = mpsc::channel();
        let header_name = payment_header_name.to_string();

        let handle = thread::spawn(move || {
            let (mut initial_stream, _) = listener.accept().unwrap();
            let _initial_request = read_headers(&mut initial_stream);
            let first_response = format!(
                "HTTP/1.1 402 Payment Required\r\nContent-Length: 0\r\nConnection: close\r\n{header_name}: {payment_header_value}\r\n\r\n"
            );
            initial_stream.write_all(first_response.as_bytes()).unwrap();

            let (mut retry_stream, _) = listener.accept().unwrap();
            let retry_request = read_headers(&mut retry_stream);
            tx.send(retry_request).unwrap();

            let second_response =
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
            retry_stream.write_all(second_response.as_bytes()).unwrap();
        });

        (format!("http://{addr}"), rx, handle)
    }

    // -----------------------------------------------------------------------
    // Mock wallets
    // -----------------------------------------------------------------------

    struct EvmWallet;
    impl WalletAccess for EvmWallet {
        fn supported_chains(&self) -> Vec<ChainType> {
            vec![ChainType::Evm]
        }
        fn account(&self, _network: &str) -> Result<super::super::wallet::Account, OcPayHttpError> {
            Ok(super::super::wallet::Account {
                address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".into(),
            })
        }
        fn sign_payload(
            &self,
            _scheme: &str,
            _network: &str,
            _payload: &str,
        ) -> Result<String, OcPayHttpError> {
            Ok("0xdeadbeef".into())
        }
    }

    struct SolanaWallet;
    impl WalletAccess for SolanaWallet {
        fn supported_chains(&self) -> Vec<ChainType> {
            vec![ChainType::Solana]
        }
        fn account(&self, _network: &str) -> Result<super::super::wallet::Account, OcPayHttpError> {
            Ok(super::super::wallet::Account {
                address: "So11111111111111111111111111111111111111112".into(),
            })
        }
        fn sign_payload(
            &self,
            _scheme: &str,
            _network: &str,
            _payload: &str,
        ) -> Result<String, OcPayHttpError> {
            Ok("0xdeadbeef".into())
        }
    }

    struct MultiWallet;
    impl WalletAccess for MultiWallet {
        fn supported_chains(&self) -> Vec<ChainType> {
            vec![ChainType::Evm, ChainType::Solana]
        }
        fn account(&self, _network: &str) -> Result<super::super::wallet::Account, OcPayHttpError> {
            Ok(super::super::wallet::Account {
                address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".into(),
            })
        }
        fn sign_payload(
            &self,
            _scheme: &str,
            _network: &str,
            _payload: &str,
        ) -> Result<String, OcPayHttpError> {
            Ok("0xdeadbeef".into())
        }
    }

    // -----------------------------------------------------------------------
    // build_request
    // -----------------------------------------------------------------------

    #[test]
    fn build_request_valid_methods() {
        let client = hpx::Client::new();
        for method in &["GET", "POST", "PUT", "DELETE", "PATCH"] {
            let result = build_request(&client, "https://example.com", method, None, None);
            assert!(result.is_ok(), "method {method} should be valid");
        }
    }

    #[test]
    fn build_request_case_insensitive() {
        let client = hpx::Client::new();
        for method in &["get", "Post", "pUT", "dElEtE", "patch"] {
            let result = build_request(&client, "https://example.com", method, None, None);
            assert!(result.is_ok(), "method {method} should be valid (case-insensitive)");
        }
    }

    #[test]
    fn build_request_invalid_method() {
        let client = hpx::Client::new();
        let result = build_request(&client, "https://example.com", "FOOBAR", None, None);
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert_eq!(err.code, OcPayHttpErrorCode::InvalidInput);
        assert!(err.message.contains("FOOBAR"));
    }

    #[test]
    fn build_request_head_is_invalid() {
        let client = hpx::Client::new();
        let result = build_request(&client, "https://example.com", "HEAD", None, None);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // parse_requirements
    // -----------------------------------------------------------------------

    #[test]
    fn parse_requirements_from_body() {
        let headers = HeaderMap::new();
        let body = serde_json::json!({
            "accepts": [{
                "scheme": "exact",
                "network": "eip155:8453",
                "amount": "10000",
                "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                "payTo": "0xabc",
                "maxTimeoutSeconds": 30
            }]
        })
        .to_string();

        let (_, _, reqs) = parse_requirements(&headers, &body).unwrap();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].scheme, "exact");
        assert_eq!(reqs[0].network, "eip155:8453");
    }

    #[test]
    fn parse_requirements_from_header() {
        let x402 = serde_json::json!({
            "accepts": [{
                "scheme": "exact",
                "network": "eip155:8453",
                "amount": "5000",
                "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                "payTo": "0xdef"
            }]
        });
        let encoded = B64.encode(serde_json::to_string(&x402).unwrap().as_bytes());

        let mut headers = HeaderMap::new();
        headers.insert("x-payment-required", encoded.parse().unwrap());

        let (_, _, reqs) = parse_requirements(&headers, "not json").unwrap();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].pay_to, "0xdef");
    }

    #[test]
    fn parse_requirements_header_fallback_to_body() {
        let mut headers = HeaderMap::new();
        headers.insert("x-payment-required", "not-valid-base64!!!".parse().unwrap());

        let body = serde_json::json!({
            "accepts": [{
                "scheme": "exact",
                "network": "eip155:8453",
                "amount": "1000",
                "asset": "0xaaa",
                "payTo": "0xbbb"
            }]
        })
        .to_string();

        let (_, _, reqs) = parse_requirements(&headers, &body).unwrap();
        assert_eq!(reqs[0].pay_to, "0xbbb");
    }

    #[test]
    fn parse_requirements_from_v2_header() {
        let x402 = serde_json::json!({
            "accepts": [{
                "scheme": "exact",
                "network": "eip155:8453",
                "amount": "5000",
                "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                "payTo": "0xv2"
            }]
        });
        let encoded = B64.encode(serde_json::to_string(&x402).unwrap().as_bytes());

        let mut headers = HeaderMap::new();
        headers.insert("payment-required", encoded.parse().unwrap());

        let (_, _, reqs) = parse_requirements(&headers, "not json").unwrap();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].pay_to, "0xv2");
    }

    #[test]
    fn parse_requirements_v2_header_defaults_version_to_2() {
        let x402 = serde_json::json!({
            "accepts": [{
                "scheme": "exact",
                "network": "eip155:8453",
                "amount": "5000",
                "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                "payTo": "0xv2"
            }]
        });
        let encoded = B64.encode(serde_json::to_string(&x402).unwrap().as_bytes());

        let mut headers = HeaderMap::new();
        headers.insert("payment-required", encoded.parse().unwrap());

        let (version, _, reqs) = parse_requirements(&headers, "not json").unwrap();
        assert_eq!(version, 2);
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].pay_to, "0xv2");
    }

    #[test]
    fn v2_header_without_version_builds_v2_payment_payload() {
        let x402 = serde_json::json!({
            "accepts": [{
                "scheme": "exact",
                "network": "eip155:8453",
                "amount": "5000",
                "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                "payTo": "0xv2",
                "extra": {
                    "name": "USD Coin",
                    "version": "2"
                }
            }]
        });
        let encoded = B64.encode(serde_json::to_string(&x402).unwrap().as_bytes());

        let mut headers = HeaderMap::new();
        headers.insert("payment-required", encoded.parse().unwrap());

        let (version, resource, reqs) = parse_requirements(&headers, "not json").unwrap();
        let (req, network) = pick_payment_option(&EvmWallet, &reqs).unwrap();
        let (payload, _) =
            build_signed_payment(&EvmWallet, req, &network, version, resource).unwrap();

        match payload {
            PaymentPayload::V2(v2) => {
                assert_eq!(v2.x402_version, 2);
                assert_eq!(v2.accepted.pay_to, "0xv2");
            }
            PaymentPayload::V1(_) => panic!("expected v2 payload for payment-required header"),
        }
    }

    #[test]
    fn parse_requirements_v2_header_takes_priority_over_v1() {
        let x402_v2 = serde_json::json!({
            "accepts": [{"scheme": "exact", "network": "eip155:8453", "amount": "1", "asset": "0xaaa", "payTo": "0xv2"}]
        });
        let x402_v1 = serde_json::json!({
            "accepts": [{"scheme": "exact", "network": "eip155:8453", "amount": "1", "asset": "0xaaa", "payTo": "0xv1"}]
        });
        let mut headers = HeaderMap::new();
        headers.insert(
            "payment-required",
            B64.encode(serde_json::to_string(&x402_v2).unwrap().as_bytes()).parse().unwrap(),
        );
        headers.insert(
            "x-payment-required",
            B64.encode(serde_json::to_string(&x402_v1).unwrap().as_bytes()).parse().unwrap(),
        );

        let (_, _, reqs) = parse_requirements(&headers, "not json").unwrap();
        assert_eq!(reqs[0].pay_to, "0xv2");
    }

    #[test]
    fn build_request_sends_both_payment_headers() {
        let client = hpx::Client::new();
        let req = build_request(&client, "https://example.com", "GET", None, Some("payload123"))
            .unwrap()
            .build()
            .unwrap();
        let headers = req.headers();
        assert_eq!(headers.get("X-PAYMENT").unwrap(), "payload123");
        assert_eq!(headers.get("payment-signature").unwrap(), "payload123");
    }

    #[test]
    fn parse_requirements_empty_accepts_errors() {
        let headers = HeaderMap::new();
        let body = r#"{"accepts":[]}"#;
        let err = parse_requirements(&headers, body).unwrap_err();
        assert_eq!(err.code, OcPayHttpErrorCode::ProtocolMalformed);
    }

    #[test]
    fn parse_requirements_bad_json_errors() {
        let headers = HeaderMap::new();
        let err = parse_requirements(&headers, "this is not json").unwrap_err();
        assert_eq!(err.code, OcPayHttpErrorCode::ProtocolMalformed);
    }

    // -----------------------------------------------------------------------
    // pick_payment_option
    // -----------------------------------------------------------------------

    #[test]
    fn pick_evm_by_caip2() {
        let reqs = vec![base_requirement()];
        let (req, network) = pick_payment_option(&EvmWallet, &reqs).unwrap();
        assert_eq!(req.network, "eip155:8453");
        assert_eq!(network, "eip155:8453");
    }

    #[test]
    fn pick_evm_by_name() {
        let mut req = base_requirement();
        req.network = "base".into();
        let reqs = [req];
        let (_, network) = pick_payment_option(&EvmWallet, &reqs).unwrap();
        // Human name resolved to CAIP-2.
        assert_eq!(network, "eip155:8453");
    }

    #[test]
    fn pick_skips_unsupported_namespace() {
        let mut req = base_requirement();
        req.network = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp".into();
        let reqs = [req];
        let err = pick_payment_option(&EvmWallet, &reqs).unwrap_err();
        assert_eq!(err.code, OcPayHttpErrorCode::UnsupportedChain);
    }

    #[test]
    fn pick_solana_with_solana_wallet() {
        let mut req = base_requirement();
        req.network = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp".into();
        let reqs = [req];
        let (_, network) = pick_payment_option(&SolanaWallet, &reqs).unwrap();
        assert!(network.starts_with("solana:"));
    }

    #[test]
    fn pick_multi_wallet_prefers_first() {
        let evm_req = base_requirement();
        let mut sol_req = base_requirement();
        sol_req.network = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp".into();
        let reqs = [sol_req, evm_req];
        let (_, network) = pick_payment_option(&MultiWallet, &reqs).unwrap();
        assert!(network.starts_with("solana:"));
    }

    #[test]
    fn pick_prefers_cheapest_option_within_first_supported_network() {
        let expensive = base_requirement();
        let mut cheap = base_requirement();
        cheap.amount = "1000".into();
        let reqs = [expensive, cheap];
        let (req, network) = pick_payment_option(&EvmWallet, &reqs).unwrap();
        assert_eq!(network, "eip155:8453");
        assert_eq!(req.amount, "1000");
    }

    #[test]
    fn pick_skips_gateway_batched_offer() {
        let mut gateway = base_requirement();
        gateway.amount = "100".into();
        gateway.extra = serde_json::json!({
            "name": "GatewayWalletBatched",
            "version": "1"
        });

        let mut regular = base_requirement();
        regular.amount = "1000".into();

        let reqs = [gateway, regular];
        let (req, _) = pick_payment_option(&EvmWallet, &reqs).unwrap();
        assert_eq!(req.amount, "1000");
        assert_eq!(req.extra["name"], "USD Coin");
    }

    #[test]
    fn pick_unknown_namespace_errors() {
        let mut req = base_requirement();
        req.network = "foochain:1".into();
        let reqs = [req];
        let err = pick_payment_option(&EvmWallet, &reqs).unwrap_err();
        assert_eq!(err.code, OcPayHttpErrorCode::UnsupportedChain);
    }

    #[test]
    fn pick_unsupported_scheme_skipped() {
        let mut req = base_requirement();
        req.scheme = "subscription".into();
        let reqs = [req];
        let err = pick_payment_option(&EvmWallet, &reqs).unwrap_err();
        assert_eq!(err.code, OcPayHttpErrorCode::UnsupportedChain);
    }

    #[test]
    fn pick_unknown_evm_chain_still_works() {
        // Chain not in KNOWN_CHAINS but namespace is recognized.
        let mut req = base_requirement();
        req.network = "eip155:999999".into();
        let reqs = [req];
        let (_, network) = pick_payment_option(&EvmWallet, &reqs).unwrap();
        assert_eq!(network, "eip155:999999");
    }

    // -----------------------------------------------------------------------
    // build_evm_exact
    // -----------------------------------------------------------------------

    #[test]
    fn build_evm_exact_produces_valid_payload() {
        let req = base_requirement();
        let (payload, info) = build_evm_exact(&EvmWallet, &req, "eip155:8453", 1, None).unwrap();

        let v1 = match &payload {
            PaymentPayload::V1(p) => p,
            PaymentPayload::V2(_) => panic!("expected V1"),
        };
        assert_eq!(v1.scheme, "exact");
        assert_eq!(v1.network, "eip155:8453");
        assert_eq!(v1.x402_version, 1);

        assert!(v1.payload.get("signature").is_some());
        assert!(v1.payload.get("authorization").is_some());
        let auth = &v1.payload["authorization"];
        assert_eq!(auth["from"], "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
        assert_eq!(auth["to"], req.pay_to);
        assert_eq!(auth["value"], req.amount);

        assert_eq!(info.network, "base");
        assert_eq!(info.token, "USDC");
    }

    #[test]
    fn build_evm_exact_produces_valid_v2_payload() {
        let req = base_requirement();
        let resource = serde_json::json!({
            "url": "https://example.com/api",
            "description": "test",
            "mimeType": "application/json"
        });
        let (payload, _) =
            build_evm_exact(&EvmWallet, &req, "eip155:8453", 2, Some(resource.clone())).unwrap();

        let v2 = match &payload {
            PaymentPayload::V2(p) => p,
            PaymentPayload::V1(_) => panic!("expected V2"),
        };
        assert_eq!(v2.x402_version, 2);
        assert_eq!(v2.accepted.scheme, req.scheme);
        assert_eq!(v2.accepted.network, req.network);
        assert_eq!(v2.accepted.pay_to, req.pay_to);
        assert_eq!(v2.resource, Some(resource));

        assert!(v2.payload.get("signature").is_some());
        let auth = &v2.payload["authorization"];
        assert_eq!(auth["from"], "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
        assert_eq!(auth["to"], req.pay_to);
        assert_eq!(auth["value"], req.amount);
    }

    #[test]
    fn build_evm_exact_v2_with_no_resource() {
        let req = base_requirement();
        let (payload, _) = build_evm_exact(&EvmWallet, &req, "eip155:8453", 2, None).unwrap();

        let v2 = match &payload {
            PaymentPayload::V2(p) => p,
            PaymentPayload::V1(_) => panic!("expected V2"),
        };
        assert_eq!(v2.x402_version, 2);
        assert!(v2.resource.is_none());
    }

    #[test]
    fn build_evm_exact_v2_omits_null_requirement_fields() {
        let mut req = base_requirement();
        req.extra = serde_json::Value::Null;
        req.description = None;
        req.resource = None;

        let (payload, _) = build_evm_exact(&EvmWallet, &req, "eip155:8453", 2, None).unwrap();
        let encoded = serde_json::to_value(payload).unwrap();
        let accepted = &encoded["accepted"];

        assert!(accepted.get("extra").is_none());
        assert!(accepted.get("description").is_none());
        assert!(accepted.get("resource").is_none());
    }

    #[test]
    fn build_evm_exact_fails_for_non_numeric_chain_id() {
        let req = base_requirement();
        let err = build_evm_exact(&EvmWallet, &req, "solana:mainnet", 1, None).unwrap_err();
        assert_eq!(err.code, OcPayHttpErrorCode::ProtocolMalformed);
    }

    // -----------------------------------------------------------------------
    // parse → pick roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn parse_and_pick_roundtrip() {
        let body = serde_json::json!({
            "x402Version": 1,
            "accepts": [{
                "scheme": "exact",
                "network": "base",
                "maxAmountRequired": "10000",
                "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                "payTo": "0x7d9d1821d15B9e0b8Ab98A058361233E255E405D",
                "maxTimeoutSeconds": 120,
                "extra": {"name": "USD Coin", "version": "2"}
            }]
        })
        .to_string();

        let headers = HeaderMap::new();
        let (_, _, reqs) = parse_requirements(&headers, &body).unwrap();
        let (req, network) = pick_payment_option(&EvmWallet, &reqs).unwrap();
        assert_eq!(req.pay_to, "0x7d9d1821d15B9e0b8Ab98A058361233E255E405D");
        assert_eq!(network, "eip155:8453"); // "base" resolved to CAIP-2
    }

    #[test]
    fn mock_wallet_satisfies_trait() {
        let wallet = EvmWallet;
        assert_eq!(wallet.supported_chains(), vec![ChainType::Evm]);
        let account = wallet.account("eip155:8453").unwrap();
        assert!(account.address.starts_with("0x"));
        let sig = wallet.sign_payload("exact", "eip155:8453", "{}").unwrap();
        assert_eq!(sig, "0xdeadbeef");
    }

    #[tokio::test]
    async fn pay_retries_v1_flow_with_v1_payload() {
        let x402 = serde_json::json!({
            "accepts": [{
                "scheme": "exact",
                "network": "eip155:8453",
                "amount": "5000",
                "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                "payTo": "0xv1",
                "extra": {
                    "name": "USD Coin",
                    "version": "2"
                }
            }]
        });
        let encoded = B64.encode(serde_json::to_string(&x402).unwrap().as_bytes());
        let (url, rx, handle) = spawn_x402_flow_server("x-payment-required", encoded);

        let result = super::super::pay(&EvmWallet, &url, "GET", None).await.unwrap();
        let retry_request = rx.recv_timeout(Duration::from_secs(3)).unwrap();
        handle.join().unwrap();

        assert_eq!(result.status, 200);
        assert_eq!(result.body, "ok");

        let x_payment = header_value(&retry_request, "X-PAYMENT");
        let payment_signature = header_value(&retry_request, "payment-signature");
        assert_eq!(x_payment, payment_signature);

        match decode_payment_payload(&x_payment) {
            PaymentPayload::V1(v1) => {
                assert_eq!(v1.x402_version, 1);
                assert_eq!(v1.network, "eip155:8453");
                assert_eq!(v1.payload["authorization"]["to"], "0xv1");
            }
            PaymentPayload::V2(_) => panic!("expected v1 payload for x-payment-required flow"),
        }
    }

    #[tokio::test]
    async fn pay_retries_v2_flow_with_v2_payload_without_explicit_version() {
        let resource = serde_json::json!({
            "uri": "https://api.example.com/paid"
        });
        let x402 = serde_json::json!({
            "resource": resource,
            "accepts": [{
                "scheme": "exact",
                "network": "eip155:8453",
                "amount": "5000",
                "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                "payTo": "0xv2",
                "extra": {
                    "name": "USD Coin",
                    "version": "2"
                }
            }]
        });
        let encoded = B64.encode(serde_json::to_string(&x402).unwrap().as_bytes());
        let (url, rx, handle) = spawn_x402_flow_server("payment-required", encoded);

        let result = super::super::pay(&EvmWallet, &url, "GET", None).await.unwrap();
        let retry_request = rx.recv_timeout(Duration::from_secs(3)).unwrap();
        handle.join().unwrap();

        assert_eq!(result.status, 200);
        assert_eq!(result.body, "ok");

        let x_payment = header_value(&retry_request, "X-PAYMENT");
        let payment_signature = header_value(&retry_request, "payment-signature");
        assert_eq!(x_payment, payment_signature);

        match decode_payment_payload(&payment_signature) {
            PaymentPayload::V2(v2) => {
                assert_eq!(v2.x402_version, 2);
                assert_eq!(v2.accepted.pay_to, "0xv2");
                assert_eq!(
                    v2.resource,
                    Some(serde_json::json!({"uri": "https://api.example.com/paid"}))
                );
            }
            PaymentPayload::V1(_) => panic!("expected v2 payload for payment-required flow"),
        }
    }
}
