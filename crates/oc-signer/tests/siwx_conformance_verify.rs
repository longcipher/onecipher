//! Official SpruceID SIWE verify harness (EIP-191 EOAs).
//!
//! `verification_positive.json` / `verification_negative.json` are field
//! objects plus a hex signature (not ABNF strings). Messages are rebuilt with
//! `*_raw` timestamp setters so subsecond originals hash correctly.
//! Vectors: see `vectors/SOURCE.txt`.
//!
//! Skips (not covered by these two files):
//! - contract signatures (EIP-1271) — need RPC (`oc-netagent`).
//! - ERC-6492 magic suffix — needs RPC.
//! - Non-65-byte signatures — contract/counterfactual territory.

#![allow(
    unused_crate_dependencies,
    reason = "integration test crate links lib deps it does not use"
)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[cfg(test)]
mod tests {
    use oc_signer::EvmVerifier;
    use oc_siwx::{AuthOpts, SiwxError, SiwxMessage, SyncVerifier, authenticate};
    use serde_json::Value;

    const POSITIVE: &str = include_str!("vectors/verification_positive.json");
    const NEGATIVE: &str = include_str!("vectors/verification_negative.json");

    /// ERC-6492 magic suffix (`0x6492` repeated 16 times).
    const ERC6492_MAGIC: [u8; 32] = [
        0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64,
        0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92,
        0x64, 0x92,
    ];

    #[derive(Debug)]
    enum Skip {
        Eip6492,
        NeedsRpc,
    }

    fn field_string(fields: &Value, key: &str) -> Option<String> {
        match fields.get(key)? {
            Value::String(s) => Some(s.clone()),
            Value::Number(n) => Some(n.to_string()),
            _ => None,
        }
    }

    fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
        hex::decode(s.strip_prefix("0x").unwrap_or(s)).map_err(|e| e.to_string())
    }

    fn is_eip6492(sig: &[u8]) -> bool {
        sig.len() >= 32 && sig.ends_with(&ERC6492_MAGIC)
    }

    fn rebuild(fields: &Value) -> Result<SiwxMessage, SiwxError> {
        let mut msg = SiwxMessage::new(
            field_string(fields, "domain").unwrap_or_default(),
            field_string(fields, "address").unwrap_or_default(),
            field_string(fields, "uri").unwrap_or_default(),
            field_string(fields, "chainId").unwrap_or_default(),
            field_string(fields, "nonce").unwrap_or_default(),
        )?;
        if let Some(s) = fields.get("statement").and_then(Value::as_str) {
            msg = msg.with_statement(s)?;
        }
        if let Some(s) = fields.get("issuedAt").and_then(Value::as_str) {
            msg = msg.with_issued_at_raw(s)?;
        }
        if let Some(s) = fields.get("expirationTime").and_then(Value::as_str) {
            msg = msg.with_expiration_time_raw(s)?;
        }
        if let Some(s) = fields.get("notBefore").and_then(Value::as_str) {
            msg = msg.with_not_before_raw(s)?;
        }
        if let Some(s) = fields.get("requestId").and_then(Value::as_str) {
            msg = msg.with_request_id(s)?;
        }
        if let Some(rs) = fields.get("resources").and_then(Value::as_array) {
            let list: Vec<String> =
                rs.iter().filter_map(|v| v.as_str().map(str::to_owned)).collect();
            msg = msg.with_resources(list)?;
        }
        Ok(msg)
    }

    fn opts_from_vector(fields: &Value) -> AuthOpts {
        let domain = fields
            .get("domainBinding")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| field_string(fields, "domain"))
            .unwrap();
        let nonce = fields
            .get("matchNonce")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| field_string(fields, "nonce"))
            .unwrap();
        let mut opts = AuthOpts::new(domain, nonce).with_clock_skew_secs(0);
        if let Some(t) = fields.get("time").and_then(Value::as_str) {
            let ts: jiff::Timestamp = t.parse().expect("vector time");
            opts = opts.with_timestamp(ts);
        }
        opts
    }

    fn authenticate_vector(fields: &Value) -> Result<Result<(), SiwxError>, Skip> {
        let msg = match rebuild(fields) {
            Ok(m) => m,
            Err(e) => return Ok(Err(e)),
        };
        let sig_hex = fields.get("signature").and_then(Value::as_str).unwrap();
        let sig = match decode_hex(sig_hex) {
            Ok(s) => s,
            Err(e) => {
                return Ok(Err(SiwxError::InvalidSignature { reason: e }));
            }
        };
        if is_eip6492(&sig) {
            return Err(Skip::Eip6492);
        }
        if sig.len() != 65 {
            return Err(Skip::NeedsRpc);
        }
        let raw = EvmVerifier::format_message(&msg);
        let opts = opts_from_vector(fields);
        Ok(authenticate(&EvmVerifier::new(), &raw, &sig, &opts).map(|_| ()))
    }

    fn load_cases(raw: &str) -> serde_json::Map<String, Value> {
        let parsed: Value = serde_json::from_str(raw).unwrap();
        parsed.as_object().cloned().unwrap()
    }

    #[test]
    fn official_verification_positive() {
        let cases = load_cases(POSITIVE);
        assert!(!cases.is_empty(), "positive vectors must not be empty");
        for (name, fields) in cases {
            let result = authenticate_vector(&fields);
            assert!(
                matches!(result, Err(Skip::Eip6492 | Skip::NeedsRpc) | Ok(Ok(()))),
                "positive case {name:?} failed: {result:?}"
            );
        }
    }

    #[test]
    fn official_expired_message_positive_is_ok() {
        let cases = load_cases(POSITIVE);
        let fields = cases.get("expired message").unwrap();
        let result = authenticate_vector(fields);
        assert!(
            matches!(result, Ok(Ok(()))),
            "official expired message (time=2020, issuedAt=2022, exp=2021) must Ok, got {result:?}"
        );
    }

    #[test]
    fn official_verification_negative() {
        let cases = load_cases(NEGATIVE);
        assert!(!cases.is_empty(), "negative vectors must not be empty");
        for (name, fields) in cases {
            let result = authenticate_vector(&fields);
            assert!(
                matches!(result, Err(Skip::Eip6492 | Skip::NeedsRpc) | Ok(Err(_))),
                "negative case {name:?} unexpectedly succeeded"
            );
        }
    }
}
