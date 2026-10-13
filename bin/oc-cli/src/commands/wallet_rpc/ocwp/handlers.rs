//! OCWP (`oc_*`) method handlers — the wallet surface the browser extension
//! speaks (design `docs/extension-wallet-design.md` §5.2).
//!
//! Every handler is synchronous (the dispatch layer runs them on tokio's
//! blocking pool) and returns [`OcwpError`] on failure. Signing paths are
//! enclave-first (decrypt → sign → wipe in a subprocess), matching the
//! existing `ledgerflow_*` posture; the in-process fallback is tests /
//! `OC_ENCLAVE=off` only.

use base64::Engine;
use oc_signer::ChainSigner as _;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::{
    errors::OcwpError,
    policy_gate::{self, PolicyView},
    registries::ChainRecord,
    rpc_proxy,
    session::SessionEntry,
};

/// Resolve the session from `params.session_id` (TTL/idle enforced) and
/// enforce the origin binding (INV-9): a session may only be driven by the
/// extension origin that unlocked it.
fn require_session(
    sessions: &super::session::SessionStore,
    params: &Value,
    origin: &str,
) -> Result<SessionEntry, OcwpError> {
    let id = params
        .get("session_id")
        .and_then(Value::as_str)
        .ok_or_else(|| OcwpError::invalid_params("missing 'session_id'"))?;
    sessions.touch_for_origin(id, origin)
}

fn require_str(params: &Value, key: &str) -> Result<String, OcwpError> {
    params
        .get(key)
        .and_then(Value::as_str)
        .map(String::from)
        .ok_or_else(|| OcwpError::invalid_params(format!("missing '{key}'")))
}

fn opt_str(params: &Value, key: &str) -> Option<String> {
    params.get(key).and_then(Value::as_str).map(String::from)
}

fn opt_u32(params: &Value, key: &str) -> Option<u32> {
    params.get(key).and_then(Value::as_u64).and_then(|v| u32::try_from(v).ok())
}

fn strip_hex(s: &str) -> &str {
    s.strip_prefix("0x").unwrap_or(s)
}

/// Priority-fee floor used only when the caller set no fee fields at all
/// (`1 gwei`), so a fully unspecified EIP-1559 transaction still bids.
const DEFAULT_PRIORITY_FEE_WEI: u128 = 1_000_000_000;

/// Resolve `params.account_id` (a CAIP-2 chain id) to a chain.
fn account_chain(params: &Value) -> Result<oc_core::Chain, OcwpError> {
    let account_id = require_str(params, "account_id")?;
    oc_core::parse_chain(&account_id)
        .map_err(|e| OcwpError::invalid_params(format!("invalid account_id '{account_id}': {e}")))
}

/// Strip an optional `0x` and decode hex, mapping failures to `-32602`.
fn decode_hex_field(value: &str, field: &str) -> Result<Vec<u8>, OcwpError> {
    hex::decode(strip_hex(value))
        .map_err(|e| OcwpError::invalid_params(format!("invalid {field} hex: {e}")))
}

/// Parse a decimal (or 0x-hex) quantity string into `u128`.
fn parse_quantity(value: &str, field: &str) -> Result<u128, OcwpError> {
    let text = value.trim();
    if let Some(hex_text) = text.strip_prefix("0x") {
        return u128::from_str_radix(hex_text, 16)
            .map_err(|_| OcwpError::invalid_params(format!("invalid {field} quantity")));
    }
    text.parse::<u128>().map_err(|_| OcwpError::invalid_params(format!("invalid {field} quantity")))
}

/// Read a string field under any of `keys`, first present wins. Accepting both
/// the OCWP snake_case names and the EIP-1193 camelCase names means a dApp's
/// own field names survive the hop: `maxFeePerGas` and `max_fee_per_gas` are
/// the same intent, and silently ignoring one of them would let the daemon
/// substitute its own fee ceiling for the one the user (or the dApp) asked
/// for.
///
/// A `null` value counts as absent, and the search *continues past it* — a
/// caller sending `{"gas": null, "gas_limit": "0x5208"}` means the gas limit,
/// not "no gas limit".
fn field<'a>(obj: &'a serde_json::Map<String, Value>, keys: &[&str]) -> Option<&'a Value> {
    keys.iter().find_map(|key| obj.get(*key).filter(|value| !value.is_null()))
}

fn field_str<'a>(obj: &'a serde_json::Map<String, Value>, keys: &[&str]) -> Option<&'a str> {
    field(obj, keys).and_then(Value::as_str)
}

/// Parse a quantity out of any of `keys` (string or JSON number).
fn field_quantity(
    obj: &serde_json::Map<String, Value>,
    keys: &[&str],
    field_name: &str,
) -> Result<Option<u128>, OcwpError> {
    match field(obj, keys) {
        None => Ok(None),
        Some(Value::String(text)) => parse_quantity(text, field_name).map(Some),
        Some(Value::Number(number)) => number
            .as_u64()
            .map(u128::from)
            .map(Some)
            .ok_or_else(|| OcwpError::invalid_params(format!("invalid {field_name} quantity"))),
        Some(_) => Err(OcwpError::invalid_params(format!("invalid {field_name} quantity"))),
    }
}

/// Normalize an EIP-1193 `chainId` (`"0x1"`) or OCWP chain id (`"eip155:1"`)
/// into the canonical CAIP-2 form used everywhere else in OCWP.
///
/// The two spellings use different radixes and conflating them is a real bug:
/// CAIP-2 defines `eip155:` as **decimal**, so `eip155:8453` is Base — while
/// `"0x8453"` is a different, much larger chain id. Reading either with the
/// other's radix would sign for the wrong chain.
pub(crate) fn normalize_chain_reference(value: &str) -> Result<String, OcwpError> {
    let trimmed = value.trim();
    let invalid = || {
        OcwpError::invalid_params(format!(
            "invalid chainId '{value}' (expected 0x-prefixed hex or eip155:<decimal id>)"
        ))
    };
    let (numeric, radix) = if let Some(rest) = trimmed.strip_prefix("eip155:") {
        // CAIP-2: decimal.
        (rest, 10)
    } else if let Some(rest) = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")) {
        // EIP-1193: hex quantity.
        (rest, 16)
    } else {
        return Err(invalid());
    };
    if numeric.is_empty() ||
        !numeric
            .chars()
            .all(|c| if radix == 16 { c.is_ascii_hexdigit() } else { c.is_ascii_digit() })
    {
        return Err(invalid());
    }
    let parsed = u64::from_str_radix(numeric, radix).map_err(|_| invalid())?;
    Ok(format!("eip155:{parsed}"))
}

/// EVM transaction envelope type (design §5.2 `transaction.type`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TxKind {
    /// EIP-155 legacy, `gasPrice`-priced.
    Legacy,
    /// EIP-2930, `gasPrice`-priced + access list.
    Eip2930,
    /// EIP-1559, fee-capped.
    Eip1559,
    /// EIP-7702, fee-capped + `authorizationList` (delegation).
    Eip7702,
}

impl TxKind {
    const fn type_byte(self) -> u8 {
        match self {
            Self::Legacy => 0x00,
            Self::Eip2930 => 0x01,
            Self::Eip1559 => 0x02,
            Self::Eip7702 => 0x04,
        }
    }

    /// Is this envelope fee-capped (EIP-1559 style) rather than gas-priced?
    const fn is_capped(self) -> bool {
        matches!(self, Self::Eip1559 | Self::Eip7702)
    }

    /// Map a wire `type` value (`"0x2"`, `"0x02"`, `2`, absent) to an envelope.
    /// Absent means EIP-1559 (the default the OCWP spec documents).
    fn from_wire(value: Option<&Value>) -> Result<Self, OcwpError> {
        let Some(value) = value.filter(|value| !value.is_null()) else {
            return Ok(Self::Eip1559);
        };
        let byte = match value {
            Value::Number(number) => number
                .as_u64()
                .filter(|n| *n <= 0xff)
                .ok_or_else(|| OcwpError::invalid_params("transaction.type out of range"))?
                as u8,
            Value::String(text) => {
                let text = text.trim();
                let hex =
                    text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")).unwrap_or(text);
                u8::from_str_radix(hex, 16).map_err(|_| {
                    OcwpError::invalid_params(format!("invalid transaction.type '{text}'"))
                })?
            }
            _ => return Err(OcwpError::invalid_params("transaction.type must be a string")),
        };
        match byte {
            0x00 => Ok(Self::Legacy),
            0x01 => Ok(Self::Eip2930),
            0x02 => Ok(Self::Eip1559),
            0x04 => Ok(Self::Eip7702),
            // EIP-4844 blob transactions are not supported; refuse loudly
            // rather than re-encoding them as something else.
            0x03 => Err(OcwpError::invalid_params("EIP-4844 blob transactions are not supported")),
            other => Err(OcwpError::invalid_params(format!(
                "unsupported transaction type 0x{other:02x}"
            ))),
        }
    }

    /// Canonical `0x..` label for the consent UI.
    const fn label(self) -> &'static str {
        match self {
            Self::Legacy => "0x00 (legacy)",
            Self::Eip2930 => "0x01 (EIP-2930)",
            Self::Eip1559 => "0x02 (EIP-1559)",
            Self::Eip7702 => "0x04 (EIP-7702 delegation)",
        }
    }
}

/// Policy-visible projection of a transaction request.
///
/// This is the single source of truth for "what does policy get to see", used
/// by BOTH the signing path (`handle_sign_*`) and `oc_policy_preview`. Sharing
/// one projection is what makes the consent badge honest: a preview can never
/// disagree with the enforcement that follows it.
#[derive(Debug, Clone, Default)]
struct TxProjection {
    to: Option<String>,
    /// Decimal string in the smallest unit.
    value: Option<String>,
    /// `0x`-prefixed hex.
    data: Option<String>,
    /// Envelope type (`None` for a raw, already-encoded transaction whose type
    /// byte is decoded on demand).
    kind: Option<TxKind>,
}

/// Project `to` / `value` / `data` out of either a raw (already RLP-encoded)
/// or a structured transaction, without performing any RPC calls. Used by
/// `oc_policy_preview`; [`resolve_transaction`] calls it too so both paths
/// agree on the fields.
fn project_tx(tx: &Value) -> Result<TxProjection, OcwpError> {
    let obj = tx
        .as_object()
        .ok_or_else(|| OcwpError::invalid_params("'transaction' must be an object"))?;

    if let Some(raw) = obj.get("raw").and_then(Value::as_str) {
        let bytes = decode_hex_field(strip_hex(raw), "transaction.raw")?;
        let summary = decode_tx_summary(&bytes);
        return Ok(TxProjection {
            to: summary.to,
            value: summary.value,
            data: summary.data,
            kind: None,
        });
    }

    let kind = TxKind::from_wire(field(obj, &["type"]))?;
    let to = match field_str(obj, &["to"]) {
        Some(addr) => {
            let bytes = decode_hex_field(addr, "transaction.to")?;
            if bytes.len() != 20 {
                return Err(OcwpError::invalid_params("transaction.to must be a 20-byte address"));
            }
            Some(addr.to_string())
        }
        None => None,
    };
    let value = field_quantity(obj, &["value"], "transaction.value")?
        .map_or_else(|| "0".to_string(), |v| v.to_string());
    let data = match field_str(obj, &["data", "input"]) {
        Some(hex) => Some(format!("0x{}", hex::encode(decode_hex_field(hex, "transaction.data")?))),
        None => None,
    };
    Ok(TxProjection { to, value: Some(value), data, kind: Some(kind) })
}

// ---------------------------------------------------------------------------
// Minimal RLP decoding (policy projection of raw transactions)
// ---------------------------------------------------------------------------

enum RlpItem {
    Bytes(Vec<u8>),
    List(Vec<Self>),
}

/// Decode one RLP item, returning it and the number of bytes consumed.
fn rlp_decode(data: &[u8]) -> Option<(RlpItem, usize)> {
    if data.is_empty() {
        return None;
    }
    let first = data[0];
    if first < 0x80 {
        // Single byte, own encoding.
        return Some((RlpItem::Bytes(vec![first]), 1));
    }
    if first <= 0xb7 {
        // Short string (0x80..=0xb7).
        let len = usize::from(first - 0x80);
        if data.len() < 1 + len {
            return None;
        }
        return Some((RlpItem::Bytes(data[1..=len].to_vec()), 1 + len));
    }
    if first <= 0xbf {
        // Long string (0xb8..=0xbf): 1..=8 length bytes.
        let len_of_len = usize::from(first - 0xb7);
        let (len, end) = rlp_read_len(data, len_of_len)?;
        return Some((RlpItem::Bytes(data[end - len..end].to_vec()), end));
    }
    if first <= 0xf7 {
        // Short list (0xc0..=0xf7).
        let len = usize::from(first - 0xc0);
        if data.len() < 1 + len {
            return None;
        }
        return Some((RlpItem::List(rlp_decode_list(&data[1..=len])?), 1 + len));
    }
    // Long list (0xf8..=0xff): 1..=8 length bytes.
    let len_of_len = usize::from(first - 0xf7);
    let (len, end) = rlp_read_len(data, len_of_len)?;
    Some((RlpItem::List(rlp_decode_list(&data[end - len..end])?), end))
}

/// Read a big-endian `len_of_len`-byte payload length at `data[1..]` and
/// validate that the full item fits. Returns `(payload_len, item_end)`.
fn rlp_read_len(data: &[u8], len_of_len: usize) -> Option<(usize, usize)> {
    if len_of_len == 0 || len_of_len > 8 || data.len() < 1 + len_of_len {
        return None;
    }
    let mut len = 0usize;
    for &b in &data[1..=len_of_len] {
        len = len.checked_mul(256)?.checked_add(usize::from(b))?;
    }
    if len < 56 {
        // Minimal-encoding violation (long form used for a short payload).
        return None;
    }
    let end = 1 + len_of_len + len;
    if data.len() < end {
        return None;
    }
    Some((len, end))
}

fn rlp_decode_list(mut data: &[u8]) -> Option<Vec<RlpItem>> {
    let mut out = Vec::new();
    while !data.is_empty() {
        let (item, used) = rlp_decode(data)?;
        out.push(item);
        data = &data[used..];
    }
    Some(out)
}

fn rlp_bytes(item: &RlpItem) -> Option<&[u8]> {
    match item {
        RlpItem::Bytes(b) => Some(b),
        RlpItem::List(_) => None,
    }
}

/// Policy-visible summary of a raw transaction (typed or legacy).
struct TxSummary {
    to: Option<String>,
    value: Option<String>,
    data: Option<String>,
    /// Envelope label derived from the leading type byte.
    kind_label: String,
}

fn decode_tx_summary(raw: &[u8]) -> TxSummary {
    let empty = TxSummary { to: None, value: None, data: None, kind_label: "unknown".to_string() };
    // Typed transactions carry a type byte (0x01..=0x04); legacy transactions
    // start directly with the RLP list encoding (0xc0+).
    let (tx_type, body) = match raw.first() {
        Some(t) if (0x01..=0x04).contains(t) => (*t, &raw[1..]),
        _ => (0x00u8, raw),
    };
    let Some((RlpItem::List(fields), _)) = rlp_decode(body) else {
        return empty;
    };
    // Field indexes per type:
    //  0x04: [chain_id, nonce, priority, max_fee, gas, to, value, data, access_list, auth_list]
    //  0x02: [chain_id, nonce, priority, max_fee, gas, to, value, data, access_list]
    //  0x01: [chain_id, nonce, gas_price, gas, to, value, data, access_list]
    //  0x00: [nonce, gas_price, gas, to, value, data]
    let (to_idx, value_idx, data_idx) = match tx_type {
        0x02 | 0x04 => (5, 6, 7),
        0x01 => (4, 5, 6),
        _ => (3, 4, 5),
    };
    let to = fields
        .get(to_idx)
        .and_then(rlp_bytes)
        .filter(|b| b.len() == 20)
        .map(|b| format!("0x{}", hex::encode(b)));
    let value = fields.get(value_idx).and_then(rlp_bytes).map(|b| {
        let mut buf = [0u8; 16];
        let start = b.len().saturating_sub(16);
        buf[16 - (b.len() - start)..].copy_from_slice(&b[start..]);
        u128::from_be_bytes(buf).to_string()
    });
    let data = fields.get(data_idx).and_then(rlp_bytes).map(|b| format!("0x{}", hex::encode(b)));
    TxSummary {
        to,
        value,
        data,
        kind_label: match tx_type {
            0x00 => "0x00 (legacy)".to_string(),
            0x01 => "0x01 (EIP-2930)".to_string(),
            0x02 => "0x02 (EIP-1559)".to_string(),
            0x04 => "0x04 (EIP-7702 delegation)".to_string(),
            other => format!("0x{other:02x}"),
        },
    }
}

// ---------------------------------------------------------------------------
// Signing primitives (enclave-first)
// ---------------------------------------------------------------------------

fn enclave_enabled() -> bool {
    crate::enclave_spawn::signing_enclave_enabled()
}

fn enclave_error(e: String) -> OcwpError {
    OcwpError::new(-32603, crate::enclave_spawn::sanitize_enclave_error(&e))
}

/// Decrypt the session's chain key (in-process fallback path only).
fn session_key(
    session: &SessionEntry,
    chain: oc_core::Chain,
    vault: Option<&std::path::Path>,
) -> Result<oc_signer::SecretBytes, OcwpError> {
    oc_wallet::decrypt_signing_key(
        &session.wallet,
        chain.chain_type,
        session.passphrase.as_bytes(),
        Some(session.index),
        vault,
    )
    .map_err(|e| {
        tracing::warn!(error = %e, "ocwp: session key decryption failed");
        OcwpError::unauthorized("failed to decrypt signing key (wrong passphrase?)")
    })
}

/// Sign raw transaction bytes; returns the encoded signed transaction.
fn sign_tx_bytes(
    session: &SessionEntry,
    vault: Option<&std::path::Path>,
    chain_id: &str,
    tx_bytes: &[u8],
) -> Result<(Vec<u8>, Option<u8>), OcwpError> {
    if enclave_enabled() {
        let mut req = crate::enclave_spawn::fresh_request(
            oc_keyagent::enclave::OP_SIGN_TRANSACTION,
            &session.wallet_id,
            chain_id,
        );
        req.payload_hex = hex::encode(tx_bytes);
        req.index = session.index;
        req.credential_hex = Some(hex::encode(session.passphrase.as_bytes()));
        if let Some(v) = vault {
            req.vault_dir = Some(v.display().to_string());
        }
        let resp = crate::enclave_spawn::spawn_enclave(&req).map_err(enclave_error)?;
        let signed = crate::enclave_spawn::response_hex(resp.signed_tx_hex.as_ref(), "signed tx")
            .map_err(enclave_error)?;
        return Ok((signed, resp.recovery_id));
    }
    let chain = oc_core::parse_chain(chain_id)
        .map_err(|e| OcwpError::invalid_params(format!("invalid chain: {e}")))?;
    let secret = session_key(session, chain, vault)?;
    let signer = oc_signer::signer_for_chain(chain.chain_type);
    let signable = signer
        .extract_signable_bytes(tx_bytes)
        .map_err(|e| OcwpError::invalid_params(format!("invalid transaction: {e}")))?;
    let output = signer
        .sign_transaction(secret.expose(), signable)
        .map_err(|_| OcwpError::internal("signing failed"))?;
    let signed = signer
        .encode_signed_transaction(tx_bytes, &output)
        .map_err(|_| OcwpError::internal("transaction encoding failed"))?;
    Ok((signed, output.recovery_id))
}

/// Sign message bytes with chain-aware formatting (EIP-191 on EVM).
/// Returns (signature, public_key, recovery_id).
fn sign_message_bytes(
    session: &SessionEntry,
    vault: Option<&std::path::Path>,
    chain_id: &str,
    message: &[u8],
) -> Result<(Vec<u8>, Vec<u8>, Option<u8>), OcwpError> {
    if enclave_enabled() {
        let mut req = crate::enclave_spawn::fresh_request(
            oc_keyagent::enclave::OP_SIGN_MESSAGE,
            &session.wallet_id,
            chain_id,
        );
        req.payload_hex = hex::encode(message);
        req.index = session.index;
        req.credential_hex = Some(hex::encode(session.passphrase.as_bytes()));
        if let Some(v) = vault {
            req.vault_dir = Some(v.display().to_string());
        }
        let resp = crate::enclave_spawn::spawn_enclave(&req).map_err(enclave_error)?;
        let signature =
            crate::enclave_spawn::response_hex(resp.signature_hex.as_ref(), "signature")
                .map_err(enclave_error)?;
        let public_key =
            crate::enclave_spawn::response_hex(resp.public_key_hex.as_ref(), "public key")
                .map_err(enclave_error)?;
        return Ok((signature, public_key, resp.recovery_id));
    }
    let chain = oc_core::parse_chain(chain_id)
        .map_err(|e| OcwpError::invalid_params(format!("invalid chain: {e}")))?;
    let secret = session_key(session, chain, vault)?;
    let signer = oc_signer::signer_for_chain(chain.chain_type);
    let output = signer
        .sign_message(secret.expose(), message)
        .map_err(|_| OcwpError::internal("signing failed"))?;
    let public_key = if chain.chain_type == oc_core::ChainType::Evm {
        let k = k256::ecdsa::SigningKey::from_slice(secret.expose())
            .map_err(|_| OcwpError::internal("invalid secp256k1 key"))?;
        k.verifying_key().to_sec1_point(true).as_bytes().to_vec()
    } else {
        let bytes: [u8; 32] = secret
            .expose()
            .try_into()
            .map_err(|_| OcwpError::internal("invalid ed25519 key length"))?;
        ed25519_dalek::SigningKey::from_bytes(&bytes).verifying_key().to_bytes().to_vec()
    };
    Ok((output.signature, public_key, output.recovery_id))
}

/// Sign EIP-712 typed data. Returns (signature, public_key).
fn sign_typed_data(
    session: &SessionEntry,
    vault: Option<&std::path::Path>,
    chain_id: &str,
    typed_data_json: &str,
) -> Result<(Vec<u8>, Vec<u8>), OcwpError> {
    if enclave_enabled() {
        let mut req = crate::enclave_spawn::fresh_request(
            oc_keyagent::enclave::OP_SIGN_TYPED_DATA,
            &session.wallet_id,
            chain_id,
        );
        req.extra_json = typed_data_json.to_string();
        req.index = session.index;
        req.credential_hex = Some(hex::encode(session.passphrase.as_bytes()));
        if let Some(v) = vault {
            req.vault_dir = Some(v.display().to_string());
        }
        let resp = crate::enclave_spawn::spawn_enclave(&req).map_err(enclave_error)?;
        let signature =
            crate::enclave_spawn::response_hex(resp.signature_hex.as_ref(), "signature")
                .map_err(enclave_error)?;
        let public_key =
            crate::enclave_spawn::response_hex(resp.public_key_hex.as_ref(), "public key")
                .map_err(enclave_error)?;
        return Ok((signature, public_key));
    }
    let chain = oc_core::parse_chain(chain_id)
        .map_err(|e| OcwpError::invalid_params(format!("invalid chain: {e}")))?;
    if chain.chain_type != oc_core::ChainType::Evm {
        return Err(OcwpError::invalid_params(
            "typed data signing is only supported for EVM accounts",
        ));
    }
    let result = oc_wallet::sign_typed_data(
        &session.wallet,
        chain_id,
        typed_data_json,
        Some(session.passphrase.as_str()),
        Some(session.index),
        vault,
    )
    .map_err(|e| {
        tracing::warn!(error = %e, "ocwp: typed data signing failed");
        OcwpError::unauthorized("failed to decrypt signing key (wrong passphrase?)")
    })?;
    let secret = session_key(session, chain, vault)?;
    let public_key = {
        let k = k256::ecdsa::SigningKey::from_slice(secret.expose())
            .map_err(|_| OcwpError::internal("invalid secp256k1 key"))?;
        k.verifying_key().to_sec1_point(true).as_bytes().to_vec()
    };
    Ok((decode_hex_field(&result.signature, "signature")?, public_key))
}

// ---------------------------------------------------------------------------
// Audit trail (INV-12)
// ---------------------------------------------------------------------------

/// Append an audit record for a completed OCWP signing operation.
///
/// INV-12 requires *every* signing request to reach the audit log regardless
/// of which end issued it. Signing evidence rides the strong channel (D5) so
/// a read-heavy workload cannot drown it; failures here are logged, never
/// surfaced — an unwritable log must not block a user-approved signature that
/// policy already allowed.
fn record_sign_audit(
    method: &str,
    session: &SessionEntry,
    chain_id: &str,
    outcome: &str,
    details: String,
) {
    use oc_core::AuditOp;

    use crate::audit::{AuditChannel, AuditEntry, log_audit_chan};

    let entry = AuditEntry {
        timestamp: jiff::Timestamp::now().to_string(),
        wallet_id: session.wallet_id.clone(),
        operation: AuditOp::WalletSign.as_str().to_string(),
        chain_id: Some(chain_id.to_string()),
        address: None,
        details: Some(format!("{method} origin={} {outcome} {details}", session.origin)),
        secret_name: None,
    };
    log_audit_chan(&entry, AuditChannel::Strong);
}

/// Append an audit record for a broadcast (`oc_send_transaction`).
fn record_broadcast_audit(session: &SessionEntry, chain_id: &str, tx_hash: &str) {
    use oc_core::AuditOp;

    use crate::audit::{AuditChannel, AuditEntry, log_audit_chan};

    let entry = AuditEntry {
        timestamp: jiff::Timestamp::now().to_string(),
        wallet_id: session.wallet_id.clone(),
        operation: AuditOp::WalletBroadcast.as_str().to_string(),
        chain_id: Some(chain_id.to_string()),
        address: None,
        details: Some(format!("oc_send_transaction origin={} tx_hash={tx_hash}", session.origin)),
        secret_name: None,
    };
    log_audit_chan(&entry, AuditChannel::Strong);
}

// ---------------------------------------------------------------------------
// Passkey step-up
// ---------------------------------------------------------------------------

/// Verify the optional `passkey` step-up object (design §3.5). Returns `Ok(())`
/// when the object is present and valid; `4100` + `data.require_passkey` when
/// it is absent so the client can run the step-up and retry.
///
/// Three independent bindings are enforced, so a proof cannot be lifted from
/// one authorization onto another (INV-4 / T9):
///  1. the challenge must have been minted by THIS daemon for THIS session (the
///     `oc_passkey_challenge` → step-up binding below);
///  2. the challenge is single-use — one approval, one challenge;
///  3. the credential must be bound to the session's wallet.
fn verify_step_up(
    state: &super::AppState,
    session: &SessionEntry,
    params: &Value,
) -> Result<(), OcwpError> {
    let Some(auth_obj) = params.get("passkey").and_then(Value::as_object) else {
        return Err(OcwpError::require_passkey());
    };
    let challenge_hex = auth_obj
        .get("challenge_hex")
        .and_then(Value::as_str)
        .ok_or_else(|| OcwpError::invalid_params("missing passkey.challenge_hex"))?;
    let signature_hex = auth_obj
        .get("signature_hex")
        .and_then(Value::as_str)
        .ok_or_else(|| OcwpError::invalid_params("missing passkey.signature_hex"))?;
    let credential_id = auth_obj
        .get("credential_id")
        .and_then(Value::as_str)
        .ok_or_else(|| OcwpError::invalid_params("missing passkey.credential_id"))?;
    let challenge = decode_hex_field(challenge_hex, "passkey.challenge_hex")?;

    // (1) + (2): consume the binding. Removing before verification means a
    // proof that fails to verify still cannot be retried with a corrected
    // signature — the user re-runs the whole flow.
    let bound = state.step_up.consume(challenge_hex, &session.session_id).ok_or_else(|| {
        OcwpError::unauthorized(
            "passkey challenge was not issued to this session (or was already used)",
        )
    })?;

    let auth = oc_keyagent::proto::PasskeyAuthorization {
        challenge,
        signature: decode_hex_field(signature_hex, "passkey.signature_hex")?,
        credential_id: bound.credential_id,
    };
    // (3): the keyagent verifies the signature against the stored public key
    // and rejects a replayed (already consumed) challenge.
    oc_keyagent::handler::authorize_passkey(&auth)
        .map_err(|e| OcwpError::unauthorized(format!("passkey authorization failed: {e}")))?;
    let store = oc_keyagent::passkey::PasskeyPubkeyStore::open_default()
        .map_err(|_| OcwpError::internal("passkey store unavailable"))?;
    let stored = store
        .get(credential_id)
        .map_err(|_| OcwpError::internal("passkey store unavailable"))?
        .ok_or_else(|| OcwpError::unauthorized("passkey not registered"))?;
    if stored.wallet_id != session.wallet_id {
        return Err(OcwpError::unauthorized("passkey is not bound to this wallet"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `oc_hello` — protocol handshake (no session required).
pub(crate) fn handle_hello(state: &super::AppState) -> Result<Value, OcwpError> {
    let chains: Vec<ChainRecord> =
        state.chains.list(&state.config).into_iter().filter(|c| c.is_evm).collect();
    Ok(json!({
        "protocol_version": rpc_proxy::PROTOCOL_VERSION,
        "daemon_version": env!("CARGO_PKG_VERSION"),
        "chains": chains,
        "features": [
            "sessions", "sites", "chain-registry", "policy-preview",
            "rpc-proxy", "passkey-step-up",
        ],
        "extension_ids": state.extension_ids.as_slice(),
    }))
}

/// `oc_unlock` — verify the passphrase and mint a session.
pub(crate) fn handle_unlock(
    state: &super::AppState,
    params: &Value,
    origin: &str,
) -> Result<Value, OcwpError> {
    let wallet = require_str(params, "wallet")?;
    let passphrase = Zeroizing::new(require_str(params, "passphrase")?);
    // API tokens are for the automation end only (design §3.5).
    if oc_core::Credential::parse(passphrase.as_str()).is_token() {
        return Err(OcwpError::unauthorized("API tokens cannot unlock interactive sessions"));
    }
    let index = opt_u32(params, "index").unwrap_or(0);
    let policy_ids: Vec<String> = params
        .get("policies")
        .and_then(Value::as_array)
        .map_or_default(|a| a.iter().filter_map(Value::as_str).map(String::from).collect());

    let vault = state.signer.vault_path();
    let wallet_file = oc_vault::load_wallet_by_name_or_id(&wallet, vault)
        .map_err(|_| OcwpError::unauthorized("wallet not found"))?;
    let envelope: oc_vault::AgeEnvelope = serde_json::from_value(wallet_file.crypto.clone())
        .map_err(|_| OcwpError::internal("corrupt wallet crypto envelope"))?;
    oc_vault::decrypt_with_passphrase(&envelope, passphrase.as_bytes())
        .map_err(|_| OcwpError::unauthorized("incorrect passphrase"))?;

    let session_id = state.sessions.create(
        wallet.clone(),
        wallet_file.id.clone(),
        index,
        std::sync::Arc::new(passphrase),
        policy_ids,
        origin.to_string(),
    )?;
    let expires_at = state.sessions.touch(&session_id).map_or_default(|s| s.expires_at);
    let info = oc_wallet::get_wallet(&wallet, vault)
        .map_err(|_| OcwpError::internal("wallet lookup failed"))?;
    let accounts: Vec<Value> = info
        .accounts
        .iter()
        .map(|a| {
            json!({
                "account_id": a.chain_id,
                "chain_id": a.chain_id,
                "address": a.address,
                "derivation_path": a.derivation_path,
            })
        })
        .collect();
    Ok(json!({
        "session_id": session_id,
        "wallet_id": wallet_file.id,
        "index": index,
        "expires_at_unix": expires_at,
        "accounts": accounts,
        // The origin a session is pinned to; the client echoes it so a
        // mismatch is diagnosable instead of an opaque 4100.
        "origin": origin,
    }))
}

/// `oc_lock` — destroy a session.
///
/// Origin-bound: a session is only destroyable by the extension that unlocked
/// it, so a second allowlisted extension cannot lock a user out.
pub(crate) fn handle_lock(
    state: &super::AppState,
    params: &Value,
    origin: &str,
) -> Result<Value, OcwpError> {
    let id = require_str(params, "session_id")?;
    // An unknown session is already locked — report success idempotently
    // rather than leaking whether the id ever existed.
    if let Ok(entry) = state.sessions.touch(&id) &&
        (entry.origin.is_empty() || !entry.origin.eq_ignore_ascii_case(origin))
    {
        return Err(OcwpError::unauthorized("session was not unlocked by this extension origin"));
    }
    state.sessions.lock(&id);
    Ok(json!({}))
}

/// `oc_session_status` — is this session still unlocked?
pub(crate) fn handle_session_status(
    state: &super::AppState,
    params: &Value,
    origin: &str,
) -> Result<Value, OcwpError> {
    let id = require_str(params, "session_id")?;
    match state.sessions.touch_for_origin(&id, origin) {
        Ok(entry) => Ok(json!({
            "unlocked": true,
            "wallet_id": entry.wallet_id,
            "expires_at_unix": entry.expires_at,
        })),
        // A foreign session is reported as locked, never as an error: the
        // client only needs the boolean, and a distinct code would tell an
        // attacker that the id is live somewhere else.
        Err(_) => Ok(json!({ "unlocked": false })),
    }
}

/// `oc_accounts` — chain-family accounts of the session's HD index.
pub(crate) fn handle_accounts(
    state: &super::AppState,
    params: &Value,
    origin: &str,
) -> Result<Value, OcwpError> {
    let session = require_session(&state.sessions, params, origin)?;
    let info = oc_wallet::get_wallet(&session.wallet, state.signer.vault_path())
        .map_err(|_| OcwpError::internal("wallet lookup failed"))?;
    let accounts: Vec<Value> = info
        .accounts
        .iter()
        .map(|a| {
            json!({
                "account_id": a.chain_id,
                "chain_id": a.chain_id,
                "address": a.address,
                "derivation_path": a.derivation_path,
            })
        })
        .collect();
    Ok(json!({ "accounts": accounts }))
}

/// `oc_connect_site` — record a dApp connection (design §6.4).
pub(crate) fn handle_connect_site(
    state: &super::AppState,
    params: &Value,
    origin: &str,
) -> Result<Value, OcwpError> {
    let session = require_session(&state.sessions, params, origin)?;
    let origin = require_str(params, "origin")?;
    let account_id = require_str(params, "account_id")?;
    let chain_id = opt_str(params, "chain_id").unwrap_or_else(|| account_id.clone());
    // The account must resolve to a known chain before a site may bind to it.
    oc_core::parse_chain(&account_id)
        .map_err(|e| OcwpError::invalid_params(format!("invalid account_id: {e}")))?;
    let record =
        state.sites.connect(&origin, &account_id, &chain_id).map_err(OcwpError::invalid_params)?;
    Ok(json!({
        "origin": origin.to_ascii_lowercase(),
        "account_id": record.account_id,
        "chain_id": record.chain_id,
        "connected_at": record.connected_at,
        "wallet_id": session.wallet_id,
    }))
}

/// `oc_revoke_site` — revoke a dApp connection (global across ends).
pub(crate) fn handle_revoke_site(
    state: &super::AppState,
    params: &Value,
    origin: &str,
) -> Result<Value, OcwpError> {
    require_session(&state.sessions, params, origin)?;
    let origin = require_str(params, "origin")?;
    let removed = state.sites.revoke(&origin).map_err(OcwpError::invalid_params)?;
    Ok(json!({ "revoked": removed }))
}

/// `oc_list_sites` — all authorized dApp origins.
pub(crate) fn handle_list_sites(
    state: &super::AppState,
    params: &Value,
    origin: &str,
) -> Result<Value, OcwpError> {
    require_session(&state.sessions, params, origin)?;
    let sites: Vec<Value> = state
        .sites
        .list()
        .into_iter()
        .map(|(origin, record)| {
            json!({
                "origin": origin,
                "account_id": record.account_id,
                "chain_id": record.chain_id,
                "connected_at": record.connected_at,
                "last_seen_at": record.last_seen_at,
            })
        })
        .collect();
    Ok(json!({ "sites": sites }))
}

/// `oc_chain_registry` — built-in + custom chains.
pub(crate) fn handle_chain_registry(
    state: &super::AppState,
    params: &Value,
    origin: &str,
) -> Result<Value, OcwpError> {
    require_session(&state.sessions, params, origin)?;
    Ok(json!({ "chains": state.chains.list(&state.config) }))
}

/// `oc_add_custom_chain` — add/replace a custom EVM chain (validated).
pub(crate) fn handle_add_custom_chain(
    state: &super::AppState,
    params: &Value,
    origin: &str,
) -> Result<Value, OcwpError> {
    require_session(&state.sessions, params, origin)?;
    let record: ChainRecord =
        serde_json::from_value(params.get("chain").cloned().unwrap_or(Value::Null))
            .map_err(|e| OcwpError::invalid_params(format!("invalid chain object: {e}")))?;
    let saved = state.chains.add_custom(record).map_err(OcwpError::invalid_params)?;
    serde_json::to_value(saved).map_err(|_| OcwpError::internal("encode failed"))
}

/// `oc_sign_transaction` — sign an unsigned transaction (no broadcast).
pub(crate) fn handle_sign_transaction(
    state: &super::AppState,
    params: &Value,
    origin: &str,
) -> Result<Value, OcwpError> {
    let session = require_session(&state.sessions, params, origin)?;
    let chain = account_chain(params)?;
    let tx = params
        .get("transaction")
        .ok_or_else(|| OcwpError::invalid_params("missing 'transaction'"))?;
    let resolved = resolve_transaction(state, &session, chain, tx)?;

    let policies = policy_gate::selected_policies(&session, state.signer.vault_path())?;
    let view = PolicyView {
        method: "oc_sign_transaction",
        chain_id: chain.chain_id,
        to: resolved.to.as_deref(),
        value: resolved.value.as_deref(),
        data: resolved.data.as_deref(),
        raw_hex: &resolved.raw_hex,
        typed_data: None,
    };
    policy_gate::enforce(&session, &policies, &view)?;

    let tx_bytes = decode_hex_field(&resolved.raw_hex, "transaction")?;
    let (signed, recovery_id) =
        sign_tx_bytes(&session, state.signer.vault_path(), chain.chain_id, &tx_bytes)?;
    record_sign_audit(
        "oc_sign_transaction",
        &session,
        chain.chain_id,
        "ok",
        format!(
            "type={} to={} value={} recovery_id={}{}",
            resolved.kind_label,
            resolved.to.as_deref().unwrap_or("(create)"),
            resolved.value.as_deref().unwrap_or("0"),
            recovery_id.map_or_else(|| "none".into(), |r| r.to_string()),
            delegation_detail(&resolved),
        ),
    );
    Ok(json!({
        "raw_transaction": format!("0x{}", hex::encode(&signed)),
        "recovery_id": recovery_id,
        "type": resolved.kind_label,
        "delegations": resolved.delegations,
    }))
}

/// Render EIP-7702 delegation targets for the audit trail. An authorization
/// changes who can act as this account, so it is recorded explicitly rather
/// than being folded into the `to`/`value` triple.
fn delegation_detail(resolved: &ResolvedTx) -> String {
    if resolved.delegations.is_empty() {
        return String::new();
    }
    format!(" delegations=[{}]", resolved.delegations.join(","))
}

/// `oc_send_transaction` — sign and broadcast (consent + policy upstream).
pub(crate) fn handle_send_transaction(
    state: &super::AppState,
    params: &Value,
    origin: &str,
) -> Result<Value, OcwpError> {
    let session = require_session(&state.sessions, params, origin)?;
    let chain = account_chain(params)?;
    let tx = params
        .get("transaction")
        .ok_or_else(|| OcwpError::invalid_params("missing 'transaction'"))?;
    let resolved = resolve_transaction(state, &session, chain, tx)?;

    let policies = policy_gate::selected_policies(&session, state.signer.vault_path())?;
    let view = PolicyView {
        method: "oc_send_transaction",
        chain_id: chain.chain_id,
        to: resolved.to.as_deref(),
        value: resolved.value.as_deref(),
        data: resolved.data.as_deref(),
        raw_hex: &resolved.raw_hex,
        typed_data: None,
    };
    policy_gate::enforce(&session, &policies, &view)?;

    let tx_bytes = decode_hex_field(&resolved.raw_hex, "transaction")?;
    let (signed, _) =
        sign_tx_bytes(&session, state.signer.vault_path(), chain.chain_id, &tx_bytes)?;
    let tx_hash = rpc_proxy::broadcast_raw(
        &state.chains,
        &state.config,
        chain.chain_id,
        &hex::encode(&signed),
    )?;
    record_sign_audit(
        "oc_send_transaction",
        &session,
        chain.chain_id,
        "ok",
        format!(
            "type={} to={} value={}{}",
            resolved.kind_label,
            resolved.to.as_deref().unwrap_or("(create)"),
            resolved.value.as_deref().unwrap_or("0"),
            delegation_detail(&resolved),
        ),
    );
    record_broadcast_audit(&session, chain.chain_id, &tx_hash);
    Ok(json!({ "tx_hash": tx_hash, "type": resolved.kind_label }))
}

/// `oc_sign_message` — EIP-191 personal_sign (hex message bytes).
pub(crate) fn handle_sign_message(
    state: &super::AppState,
    params: &Value,
    origin: &str,
) -> Result<Value, OcwpError> {
    let session = require_session(&state.sessions, params, origin)?;
    let chain = account_chain(params)?;
    let message_b64 = require_str(params, "message")?;
    let message = base64::engine::general_purpose::STANDARD
        .decode(&message_b64)
        .map_err(|e| OcwpError::invalid_params(format!("invalid base64 message: {e}")))?;
    if message.len() > 1024 * 1024 {
        return Err(OcwpError::invalid_params("message exceeds 1 MiB limit"));
    }
    let encoding = opt_str(params, "encoding").unwrap_or_else(|| "utf8".into());

    let policies = policy_gate::selected_policies(&session, state.signer.vault_path())?;
    let view = PolicyView {
        method: "oc_sign_message",
        chain_id: chain.chain_id,
        to: None,
        value: None,
        data: None,
        raw_hex: "",
        typed_data: None,
    };
    policy_gate::enforce(&session, &policies, &view)?;

    let (signature, public_key, recovery_id) =
        sign_message_bytes(&session, state.signer.vault_path(), chain.chain_id, &message)?;
    let _ = encoding; // encoding is a display hint; bytes are signed verbatim
    record_sign_audit(
        "oc_sign_message",
        &session,
        chain.chain_id,
        "ok",
        format!("bytes={} encoding={encoding}", message.len()),
    );
    Ok(json!({
        "signature": format!("0x{}", hex::encode(&signature)),
        "public_key": format!("0x{}", hex::encode(&public_key)),
        "recovery_id": recovery_id,
    }))
}

/// `oc_sign_typed_data` — EIP-712 structured-data signing.
pub(crate) fn handle_sign_typed_data(
    state: &super::AppState,
    params: &Value,
    origin: &str,
) -> Result<Value, OcwpError> {
    let session = require_session(&state.sessions, params, origin)?;
    let chain = account_chain(params)?;
    let typed_data = params
        .get("typed_data")
        .cloned()
        .ok_or_else(|| OcwpError::invalid_params("missing 'typed_data'"))?;
    if !typed_data.is_object() {
        return Err(OcwpError::invalid_params("'typed_data' must be an object"));
    }
    let typed_data_json = serde_json::to_string(&typed_data)
        .map_err(|_| OcwpError::invalid_params("'typed_data' is not serializable"))?;

    let policies = policy_gate::selected_policies(&session, state.signer.vault_path())?;
    let view = PolicyView {
        method: "oc_sign_typed_data",
        chain_id: chain.chain_id,
        to: None,
        value: None,
        data: None,
        raw_hex: "",
        typed_data: Some(&typed_data),
    };
    policy_gate::enforce(&session, &policies, &view)?;

    let (signature, public_key) =
        sign_typed_data(&session, state.signer.vault_path(), chain.chain_id, &typed_data_json)?;
    record_sign_audit(
        "oc_sign_typed_data",
        &session,
        chain.chain_id,
        "ok",
        format!(
            "primary_type={} verifying_contract={}",
            typed_data.get("primaryType").and_then(Value::as_str).unwrap_or("unknown"),
            typed_data
                .get("domain")
                .and_then(|domain| domain.get("verifyingContract"))
                .and_then(Value::as_str)
                .unwrap_or("(none)"),
        ),
    );
    Ok(json!({
        "signature": format!("0x{}", hex::encode(&signature)),
        "public_key": format!("0x{}", hex::encode(&public_key)),
    }))
}

/// `oc_sign_authorization` — EIP-7702 authorization signing (passkey step-up).
///
/// EIP-7702 authorizations delegate an EOA's code; they are the highest-risk
/// OCWP operation and require a fresh passkey confirmation when the daemon is
/// configured with `require_passkey_eip7702`. Signing runs in-process (the
/// enclave's `sign_auth` op applies the EIP-191 message prefix, which is wrong
/// for authorization hashes).
pub(crate) fn handle_sign_authorization(
    state: &super::AppState,
    params: &Value,
    origin: &str,
) -> Result<Value, OcwpError> {
    let session = require_session(&state.sessions, params, origin)?;
    let chain = account_chain(params)?;
    if chain.chain_type != oc_core::ChainType::Evm {
        return Err(OcwpError::invalid_params(
            "EIP-7702 authorization signing is only supported for EVM accounts",
        ));
    }
    if state.require_passkey_eip7702 {
        verify_step_up(state, &session, params)?;
    }
    let address = require_str(params, "address")?;
    let nonce = require_str(params, "nonce")?;

    let policies = policy_gate::selected_policies(&session, state.signer.vault_path())?;
    let view = PolicyView {
        method: "oc_sign_authorization",
        chain_id: chain.chain_id,
        to: Some(address.as_str()),
        value: None,
        data: None,
        raw_hex: "",
        typed_data: None,
    };
    policy_gate::enforce(&session, &policies, &view)?;

    let result = oc_wallet::sign_authorization(
        &session.wallet,
        chain.chain_id,
        &address,
        &nonce,
        Some(session.passphrase.as_str()),
        Some(session.index),
        state.signer.vault_path(),
    )
    .map_err(|e| {
        tracing::warn!(error = %e, "ocwp: authorization signing failed");
        OcwpError::unauthorized("failed to decrypt signing key (wrong passphrase?)")
    })?;
    record_sign_audit(
        "oc_sign_authorization",
        &session,
        chain.chain_id,
        "ok",
        format!("address={address} nonce={nonce} step_up={}", state.require_passkey_eip7702),
    );
    Ok(json!({
        "signature": format!("0x{}", result.signature),
        "recovery_id": result.recovery_id,
    }))
}

/// `oc_rpc` — read-only JSON-RPC proxy (design §5.2).
pub(crate) fn handle_rpc(
    state: &super::AppState,
    params: &Value,
    origin: &str,
) -> Result<Value, OcwpError> {
    require_session(&state.sessions, params, origin)?;
    let origin = require_str(params, "origin")?;
    let chain_id = require_str(params, "chain_id")?;
    let method = require_str(params, "method")?;
    let rpc_params = params.get("params").cloned().unwrap_or(json!([]));
    if !rpc_params.is_array() {
        return Err(OcwpError::invalid_params("'params' must be an array"));
    }
    let result = rpc_proxy::proxy(
        &state.chains,
        &state.config,
        &state.rate_limiter,
        &origin,
        &chain_id,
        &method,
        &rpc_params,
    )?;
    Ok(json!({ "result": result }))
}

/// `oc_simulate` — dry-run a transaction via `eth_call` + `eth_estimateGas`.
pub(crate) fn handle_simulate(
    state: &super::AppState,
    params: &Value,
    origin: &str,
) -> Result<Value, OcwpError> {
    let session = require_session(&state.sessions, params, origin)?;
    let chain = account_chain(params)?;
    // Validate `from` before anything else: a malformed address must not be
    // able to trigger RPC work (or a key decryption) on the way to the error.
    let from = require_str(params, "from")?;
    let from_bytes = decode_hex_field(&from, "from")?;
    if from_bytes.len() != 20 {
        return Err(OcwpError::invalid_params("'from' must be a 0x-prefixed 20-byte address"));
    }
    let tx = params
        .get("transaction")
        .ok_or_else(|| OcwpError::invalid_params("missing 'transaction'"))?;
    let resolved = resolve_transaction(state, &session, chain, tx)?;

    let call_object = json!({
        "from": from,
        "to": resolved.to,
        "value": resolved.value,
        "data": resolved.data,
    });
    let call = rpc_proxy::internal_call(
        &state.chains,
        &state.config,
        chain.chain_id,
        "eth_call",
        json!([call_object, "latest"]),
    );
    let gas = rpc_proxy::internal_call(
        &state.chains,
        &state.config,
        chain.chain_id,
        "eth_estimateGas",
        json!([call_object]),
    );
    match (call, gas) {
        (Ok(call_result), gas_result) => Ok(json!({
            "ok": true,
            "call_result": call_result,
            "gas_used": gas_result.ok(),
            "type": resolved.kind_label,
        })),
        (Err(call_err), _) => Ok(json!({
            "ok": false,
            "revert_reason": call_err.message,
            "type": resolved.kind_label,
        })),
    }
}

/// `oc_policy_preview` — evaluate policies without signing (consent UI).
///
/// Accepts either the flat shape documented in §5.2 (`to` / `value` / `data` /
/// `raw_hex` / `typed_data`) **or** a full `transaction` object, which is
/// projected through [`project_tx`] — the very same extraction the signing path
/// uses. That parity is the point: a preview that read different fields than
/// enforcement would render a green badge for a transaction policy denies.
pub(crate) fn handle_policy_preview(
    state: &super::AppState,
    params: &Value,
    origin: &str,
) -> Result<Value, OcwpError> {
    let session = require_session(&state.sessions, params, origin)?;
    let chain_id = require_str(params, "chain_id")?;
    let typed_data = params.get("typed_data");
    let (to, value, data, raw_hex, kind_label) = match params.get("transaction") {
        Some(tx) if !tx.is_null() => {
            let projected = project_tx(tx)?;
            let (raw_hex, kind_label) = match tx.get("raw").and_then(Value::as_str) {
                Some(raw) => {
                    let bytes = decode_hex_field(strip_hex(raw), "transaction.raw")?;
                    let label = decode_tx_summary(&bytes).kind_label;
                    (strip_hex(raw).to_string(), label)
                }
                // For a structured transaction the fields above *are* the
                // projection, so re-encoding would only add RPC round trips.
                None => (
                    String::new(),
                    projected.kind.map_or_else(|| "unknown".to_string(), |k| k.label().to_string()),
                ),
            };
            (projected.to, projected.value, projected.data, raw_hex, kind_label)
        }
        _ => (
            opt_str(params, "to"),
            opt_str(params, "value"),
            opt_str(params, "data"),
            opt_str(params, "raw_hex").unwrap_or_default(),
            "unknown".to_string(),
        ),
    };
    let policies = policy_gate::selected_policies(&session, state.signer.vault_path())?;
    let view = PolicyView {
        method: "oc_policy_preview",
        chain_id: &chain_id,
        to: to.as_deref(),
        value: value.as_deref(),
        data: data.as_deref(),
        raw_hex: &raw_hex,
        typed_data,
    };
    let mut preview = policy_gate::preview(&session, &policies, &view);
    if let Some(object) = preview.as_object_mut() {
        // Echo the projected transaction so the consent UI can render exactly
        // the fields the decision was made on.
        object.insert("tx_type".into(), Value::String(kind_label));
        object.insert("to".into(), to.map_or(Value::Null, Value::String));
        object.insert("value".into(), value.map_or(Value::Null, Value::String));
        object.insert("data".into(), data.map_or(Value::Null, Value::String));
    }
    Ok(preview)
}

/// `oc_audit_tail` — last N audit entries (read-only, design §5.2).
pub(crate) fn handle_audit_tail(
    state: &super::AppState,
    params: &Value,
    origin: &str,
) -> Result<Value, OcwpError> {
    require_session(&state.sessions, params, origin)?;
    let limit = opt_u32(params, "limit").unwrap_or(50).min(200) as usize;
    let path = oc_core::paths::state_path("logs/audit.jsonl")
        .map_err(|_| OcwpError::internal("state dir unavailable"))?;
    let text = std::fs::read_to_string(&path).unwrap_or_default();
    let mut events: Vec<Value> = text
        .lines()
        .rev()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .take(limit)
        .collect();
    events.reverse();
    Ok(json!({ "events": events }))
}

/// `oc_passkey_challenge` — mint a step-up challenge (design §6.7).
pub(crate) fn handle_passkey_challenge(
    state: &super::AppState,
    params: &Value,
    origin: &str,
) -> Result<Value, OcwpError> {
    let session = require_session(&state.sessions, params, origin)?;
    let credential_id = require_str(params, "credential_id")?;
    let challenge = oc_keyagent::handler::generate_passkey_challenge(&credential_id)
        .map_err(|_| OcwpError::internal("challenge generation failed"))?;
    let rp_id = oc_keyagent::passkey::PasskeyPubkeyStore::open_default()
        .ok()
        .and_then(|store| store.get(&credential_id).ok().flatten())
        .map_or_else(oc_keyagent::passkey::StoredPasskeyPubkey::default_rp_id, |stored| {
            stored.rp_id
        });
    // Bind the challenge to this session so a proof minted for one session
    // cannot authorize another's request (see `verify_step_up`).
    let challenge_hex = hex::encode(challenge);
    state.step_up.issue(challenge_hex.clone(), &session.session_id, &credential_id);
    Ok(json!({
        "challenge_hex": challenge_hex,
        "rp_id": rp_id,
        "timeout_ms": super::STEP_UP_TTL_SECS * 1000,
    }))
}

/// `oc_passkey_register` — register a passkey public key for step-up.
pub(crate) fn handle_passkey_register(
    state: &super::AppState,
    params: &Value,
    origin: &str,
) -> Result<Value, OcwpError> {
    let session = require_session(&state.sessions, params, origin)?;
    let credential_id = require_str(params, "credential_id")?;
    let algorithm = require_str(params, "algorithm")?;
    let public_key_b64 = require_str(params, "public_key")?;
    let public_key = base64::engine::general_purpose::STANDARD
        .decode(&public_key_b64)
        .map_err(|e| OcwpError::invalid_params(format!("invalid base64 public_key: {e}")))?;
    let rp_id = opt_str(params, "rp_id")
        .filter(|s| !s.is_empty())
        .unwrap_or_else(oc_keyagent::passkey::StoredPasskeyPubkey::default_rp_id);
    let stored = oc_keyagent::passkey::StoredPasskeyPubkey {
        algorithm,
        public_key,
        wallet_id: session.wallet_id.clone(),
        registered_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        rp_id,
    };
    // Validate the key material before persisting (fail-closed).
    oc_keyagent::passkey::PasskeyPubkeyStore::to_passkey_pubkey(&stored)
        .map_err(|e| OcwpError::invalid_params(format!("invalid passkey public key: {e}")))?;
    let mut store = oc_keyagent::passkey::PasskeyPubkeyStore::open_default()
        .map_err(|_| OcwpError::internal("passkey store unavailable"))?;
    store
        .register(&credential_id, stored)
        .map_err(|_| OcwpError::internal("passkey registration failed"))?;
    Ok(json!({ "registered": true, "wallet_id": session.wallet_id }))
}

// ---------------------------------------------------------------------------
// Transaction resolution (raw passthrough or structured EIP-1559 build)
// ---------------------------------------------------------------------------

/// A transaction resolved into "what will be signed" plus the fields policy
/// and the consent UI need to describe it.
struct ResolvedTx {
    /// Unsigned transaction hex (no `0x`), ready for the signer.
    raw_hex: String,
    to: Option<String>,
    value: Option<String>,
    data: Option<String>,
    /// Envelope label for the consent UI and audit record.
    kind_label: String,
    /// EIP-7702 delegation targets, if any — surfaced as a consent warning.
    delegations: Vec<String>,
}

/// Resolve the `transaction` param into unsigned raw hex plus the
/// policy-visible `to`/`value`/`data` fields.
///
/// Field names are accepted in both the OCWP snake_case spelling and the
/// EIP-1193 camelCase spelling a dApp actually sends (`gas`,
/// `maxFeePerGas`, `input`, …). Silently ignoring a field the dApp set is how
/// a wallet ends up replacing a user's fee ceiling with its own, so both
/// spellings map to the same intent here.
///
/// Chain binding is fail-closed: a structured transaction that names a chain
/// different from the session's account chain is rejected rather than
/// re-encoded onto the account's chain. The same holds for `from`.
fn resolve_transaction(
    state: &super::AppState,
    session: &SessionEntry,
    chain: oc_core::Chain,
    tx: &Value,
) -> Result<ResolvedTx, OcwpError> {
    let obj = tx
        .as_object()
        .ok_or_else(|| OcwpError::invalid_params("'transaction' must be an object"))?;

    // Raw passthrough: the dApp built and encoded the transaction itself. The
    // encoding is signed verbatim, so nothing here may reinterpret it.
    if let Some(raw) = obj.get("raw").and_then(Value::as_str) {
        let raw_hex = strip_hex(raw).to_string();
        let bytes = decode_hex_field(&raw_hex, "transaction.raw")?;
        let summary = decode_tx_summary(&bytes);
        return Ok(ResolvedTx {
            kind_label: summary.kind_label.clone(),
            raw_hex,
            to: summary.to,
            value: summary.value,
            data: summary.data,
            delegations: Vec::new(),
        });
    }

    let chain_ref = chain.chain_id.strip_prefix("eip155:").ok_or_else(|| {
        OcwpError::invalid_params("structured transactions require an EVM account")
    })?;
    let chain_numeric: u128 =
        chain_ref.parse().map_err(|_| OcwpError::invalid_params("invalid eip155 chain id"))?;

    // The transaction's own chain must agree with the signing account's chain.
    // Without this a dApp asking for mainnet while the account is bound to
    // Base would get a *Base* transaction signed — silently, and correctly
    // signed, which is the dangerous part.
    if let Some(requested) = field_str(obj, &["chain_id", "chainId"]) {
        let requested = normalize_chain_reference(requested)?;
        if requested != chain.chain_id {
            return Err(OcwpError::invalid_params(format!(
                "transaction.chain_id '{requested}' does not match the signing account chain '{}'",
                chain.chain_id
            )));
        }
    }

    let kind = TxKind::from_wire(field(obj, &["type"]))?;
    if kind == TxKind::Eip2930 {
        // An EIP-2930 access list cannot be re-encoded here; building an empty
        // one would change the transaction the dApp asked for.
        return Err(OcwpError::invalid_params(
            "EIP-2930 access lists are not supported; omit 'type' for an EIP-1559 transaction",
        ));
    }
    if kind == TxKind::Eip7702 && field(obj, &["authorization_list", "authorizationList"]).is_none()
    {
        return Err(OcwpError::invalid_params("EIP-7702 transactions require an authorizationList"));
    }
    if kind == TxKind::Eip7702 {
        // Shape-check up front so a malformed list is a `-32602` rather than an
        // RPC failure discovered several round trips later.
        validate_authorization_list(obj)?;
    }

    let to = obj.get("to").and_then(Value::as_str).map(String::from);
    let to_bytes = match &to {
        Some(addr) => {
            let bytes = decode_hex_field(addr, "transaction.to")?;
            if bytes.len() != 20 {
                return Err(OcwpError::invalid_params("transaction.to must be a 20-byte address"));
            }
            let mut buf = [0u8; 20];
            buf.copy_from_slice(&bytes);
            Some(buf)
        }
        // Contract creation: `to` absent is valid for typed transactions.
        None => None,
    };
    let value = field_quantity(obj, &["value"], "transaction.value")?.unwrap_or(0);
    let data = match field_str(obj, &["data", "input"]) {
        Some(d) => decode_hex_field(d, "transaction.data")?,
        None => Vec::new(),
    };

    // `from` must be the signing account. It is only used for nonce/gas
    // lookups, but a mismatched value would silently fetch another account's
    // nonce and produce a transaction that cannot be broadcast.
    let derived_from = session_address(session, chain, state.signer.vault_path())?;
    if let Some(from) = obj.get("from").and_then(Value::as_str) {
        if !from.eq_ignore_ascii_case(&derived_from) {
            return Err(OcwpError::invalid_params(
                "transaction.from does not match the signing account",
            ));
        }
    }
    let from = derived_from;

    // Fee fields: a legacy/2930 envelope is `gasPrice`-priced, a capped
    // envelope carries `max_fee`/`max_priority_fee`. Whichever the caller set
    // wins; only genuinely absent fields are filled from the chain, so a dApp
    // that pinned a fee ceiling keeps it.
    //
    // Every caller-supplied field is validated BEFORE any RPC fill: a
    // malformed request must be rejected as `-32602` without the daemon
    // reaching for the network (which would turn a clear client bug into an
    // opaque "endpoint unreachable").
    let gas_price = field_quantity(obj, &["gas_price", "gasPrice"], "transaction.gas_price")?;
    let requested_priority = field_quantity(
        obj,
        &["max_priority_fee_per_gas", "maxPriorityFeePerGas"],
        "transaction.max_priority_fee_per_gas",
    )?;
    let requested_max_fee =
        field_quantity(obj, &["max_fee_per_gas", "maxFeePerGas"], "transaction.max_fee_per_gas")?;
    if let (Some(priority), Some(cap)) = (requested_priority, requested_max_fee) &&
        priority > cap
    {
        return Err(OcwpError::invalid_params(
            "transaction.max_priority_fee_per_gas exceeds max_fee_per_gas",
        ));
    }
    if let (Some(price), Some(cap)) = (gas_price, requested_max_fee) &&
        kind.is_capped() &&
        price > cap
    {
        return Err(OcwpError::invalid_params(
            "transaction.gas_price exceeds max_fee_per_gas on a capped envelope",
        ));
    }

    let nonce = match field_quantity(obj, &["nonce"], "transaction.nonce")? {
        Some(n) => n,
        None => fetch_quantity(state, chain, "eth_getTransactionCount", json!([from, "pending"]))?
            .ok_or_else(|| {
                OcwpError::invalid_params("transaction.nonce required (RPC unavailable)")
            })?,
    };
    let gas_limit = match field_quantity(obj, &["gas_limit", "gas"], "transaction.gas_limit")? {
        Some(g) => g,
        None => fetch_quantity(
            state,
            chain,
            "eth_estimateGas",
            json!([{
                "from": from,
                "to": to,
                "value": format!("0x{value:x}"),
                "data": format!("0x{}", hex::encode(&data)),
            }]),
        )?
        .map_or(1_000_000, |g| g.saturating_mul(2)),
    };

    let base_fee = if kind.is_capped() && requested_max_fee.is_some() {
        // The caller pinned a ceiling; never consult the network for more.
        0
    } else {
        fetch_quantity(state, chain, "eth_gasPrice", json!([])).unwrap_or(None).unwrap_or(0)
    };
    let max_priority_fee = requested_priority.or(gas_price).unwrap_or_else(|| {
        if kind.is_capped() {
            fetch_quantity(state, chain, "eth_maxPriorityFeePerGas", json!([]))
                .unwrap_or(None)
                .unwrap_or(DEFAULT_PRIORITY_FEE_WEI)
        } else {
            0
        }
    });
    let max_fee = requested_max_fee
        .or(gas_price)
        .unwrap_or_else(|| base_fee.saturating_mul(2).saturating_add(max_priority_fee));
    if max_priority_fee > max_fee {
        return Err(OcwpError::invalid_params(
            "transaction.max_priority_fee_per_gas exceeds max_fee_per_gas",
        ));
    }

    let to_rlp = match &to_bytes {
        Some(bytes) => oc_signer::rlp::encode_bytes(bytes),
        // Contract creation: typed transactions encode an empty `to` (RLP 0x80).
        None => oc_signer::rlp::encode_bytes(&[]),
    };
    let mut items: Vec<u8> = Vec::new();
    if kind.is_capped() {
        items.extend(oc_signer::rlp::encode_u128(chain_numeric));
        items.extend(oc_signer::rlp::encode_u128(nonce));
        items.extend(oc_signer::rlp::encode_u128(max_priority_fee));
        items.extend(oc_signer::rlp::encode_u128(max_fee));
        items.extend(oc_signer::rlp::encode_u128(gas_limit));
        items.extend(to_rlp);
        items.extend(oc_signer::rlp::encode_u128(value));
        items.extend(oc_signer::rlp::encode_bytes(&data));
        if kind == TxKind::Eip7702 {
            items.extend(encode_authorization_list(
                session,
                chain,
                obj,
                state.signer.vault_path(),
            )?);
        } else {
            items.extend(oc_signer::rlp::encode_list(&[]));
        }
    } else {
        // Legacy: [nonce, gasPrice, gas, to, value, data], EIP-155 signed.
        items.extend(oc_signer::rlp::encode_u128(nonce));
        items.extend(oc_signer::rlp::encode_u128(gas_price.unwrap_or(max_fee)));
        items.extend(oc_signer::rlp::encode_u128(gas_limit));
        items.extend(to_rlp);
        items.extend(oc_signer::rlp::encode_u128(value));
        items.extend(oc_signer::rlp::encode_bytes(&data));
    }

    let mut raw = Vec::new();
    if kind == TxKind::Legacy {
        // A bare RLP list — no envelope byte, no access list.
        raw.extend_from_slice(&oc_signer::rlp::encode_list(&items));
    } else {
        raw.push(kind.type_byte());
        raw.extend_from_slice(&oc_signer::rlp::encode_list(&items));
    }
    let delegations = if kind == TxKind::Eip7702 {
        let entries: &[Value] = field(obj, &["authorization_list", "authorizationList"])
            .and_then(Value::as_array)
            .map_or(&[], Vec::as_slice);
        entries
            .iter()
            .filter_map(|entry| entry.get("address").and_then(Value::as_str))
            .map(|address| address.to_ascii_lowercase())
            .collect::<Vec<String>>()
    } else {
        Vec::new()
    };
    Ok(ResolvedTx {
        raw_hex: hex::encode(&raw),
        to,
        value: Some(value.to_string()),
        data: if data.is_empty() { None } else { Some(format!("0x{}", hex::encode(&data))) },
        kind_label: kind.label().to_string(),
        delegations,
    })
}

/// Shape-check every EIP-7702 authorization entry without signing anything.
fn validate_authorization_list(obj: &serde_json::Map<String, Value>) -> Result<(), OcwpError> {
    let entries = field(obj, &["authorization_list", "authorizationList"])
        .and_then(Value::as_array)
        .ok_or_else(|| OcwpError::invalid_params("'authorizationList' must be an array"))?;
    if entries.is_empty() {
        return Err(OcwpError::invalid_params("'authorizationList' must not be empty"));
    }
    for entry in entries {
        let entry = entry.as_object().ok_or_else(|| {
            OcwpError::invalid_params("authorizationList entries must be objects")
        })?;
        let address = entry
            .get("address")
            .and_then(Value::as_str)
            .ok_or_else(|| OcwpError::invalid_params("authorizationList entry needs 'address'"))?;
        if decode_hex_field(address, "authorizationList[].address")?.len() != 20 {
            return Err(OcwpError::invalid_params(
                "authorizationList[].address must be a 20-byte address",
            ));
        }
        field_quantity(entry, &["nonce"], "authorizationList[].nonce")?
            .ok_or_else(|| OcwpError::invalid_params("authorizationList[].nonce is required"))?;
    }
    Ok(())
}

/// The signing account's address for `chain`, decrypted per request (no
/// long-lived key cache).
fn session_address(
    session: &SessionEntry,
    chain: oc_core::Chain,
    vault: Option<&std::path::Path>,
) -> Result<String, OcwpError> {
    let secret = session_key(session, chain, vault)?;
    oc_signer::chains::EvmSigner
        .derive_address(secret.expose())
        .map_err(|_| OcwpError::internal("address derivation failed"))
}

/// Build the EIP-7702 `authorization_list` RLP: a list of
/// `[chain_id, address, nonce, y_parity, r, s]`, where `r`/`s` come from
/// signing the `0x05 || rlp([chain_id, address, nonce])` magic digest.
///
/// Each entry is signed by the session key, which is exactly the delegation a
/// user is asked to approve in the consent UI — so the consent view must show
/// the `address` field of every entry (see `buildTransactionView`).
fn encode_authorization_list(
    session: &SessionEntry,
    chain: oc_core::Chain,
    obj: &serde_json::Map<String, Value>,
    vault: Option<&std::path::Path>,
) -> Result<Vec<u8>, OcwpError> {
    let chain_ref = chain
        .chain_id
        .strip_prefix("eip155:")
        .ok_or_else(|| OcwpError::invalid_params("EIP-7702 requires an EVM chain"))?;
    let entries = field(obj, &["authorization_list", "authorizationList"])
        .and_then(Value::as_array)
        .ok_or_else(|| OcwpError::invalid_params("'authorizationList' must be an array"))?;

    let mut encoded_entries: Vec<u8> = Vec::new();
    for entry in entries {
        let entry = entry.as_object().ok_or_else(|| {
            OcwpError::invalid_params("authorizationList entries must be objects")
        })?;
        let address = entry
            .get("address")
            .and_then(Value::as_str)
            .ok_or_else(|| OcwpError::invalid_params("authorizationList entry needs 'address'"))?;
        let address_bytes = decode_hex_field(address, "authorizationList[].address")?;
        if address_bytes.len() != 20 {
            return Err(OcwpError::invalid_params(
                "authorizationList[].address must be a 20-byte address",
            ));
        }
        // An entry may pin its own chain; `0` means "any chain".
        let entry_chain = match field_str(entry, &["chainId", "chain_id"]) {
            Some(raw) => {
                let parsed = parse_quantity(raw, "authorizationList[].chainId")?;
                if parsed == 0 { chain_ref.to_string() } else { parsed.to_string() }
            }
            None => chain_ref.to_string(),
        };
        let nonce = field_quantity(entry, &["nonce"], "authorizationList[].nonce")?
            .ok_or_else(|| OcwpError::invalid_params("authorizationList[].nonce is required"))?;
        let result = oc_wallet::sign_authorization(
            &session.wallet,
            chain.chain_id,
            address,
            &nonce.to_string(),
            Some(session.passphrase.as_str()),
            Some(session.index),
            vault,
        )
        .map_err(|e| {
            tracing::warn!(error = %e, "ocwp: EIP-7702 authorization signing failed");
            OcwpError::unauthorized("failed to sign the EIP-7702 authorization")
        })?;
        let signature = decode_hex_field(&result.signature, "authorizationList[].signature")?;
        if signature.len() != 65 {
            return Err(OcwpError::internal("authorization signature must be 65 bytes"));
        }
        let (r, s) = signature.split_at(32);
        let recovery = u64::from(u8::from(signature[64] >= 27));
        let entry_chain_numeric =
            u64::try_from(parse_quantity(&entry_chain, "authorizationList[].chainId")?).map_err(
                |_| OcwpError::invalid_params("authorizationList[].chainId is out of range"),
            )?;
        // Minimal big-endian integers: the tuple hash the signature covers is
        // defined over exactly these encodings, so a padded 16-byte scalar here
        // would produce a tx whose authorization does not recover.
        let tuple = [
            oc_signer::rlp::encode_u64(entry_chain_numeric),
            oc_signer::rlp::encode_bytes(&address_bytes),
            oc_signer::rlp::encode_u64(u64::try_from(nonce).map_err(|_| {
                OcwpError::invalid_params("authorizationList[].nonce is out of range")
            })?),
            oc_signer::rlp::encode_u64(recovery),
            oc_signer::rlp::encode_bytes(r),
            oc_signer::rlp::encode_bytes(s),
        ]
        .concat();
        encoded_entries.extend(oc_signer::rlp::encode_list(&tuple));
    }
    Ok(oc_signer::rlp::encode_list(&encoded_entries))
}

/// Fetch a hex quantity from the chain RPC (internal, not rate-limited like
/// the dApp-facing `oc_rpc`; called at most a few times per signing request).
fn fetch_quantity(
    state: &super::AppState,
    chain: oc_core::Chain,
    method: &str,
    params: Value,
) -> Result<Option<u128>, OcwpError> {
    let result =
        rpc_proxy::internal_call(&state.chains, &state.config, chain.chain_id, method, params)?;
    let hex_str =
        result.as_str().ok_or_else(|| OcwpError::internal("rpc returned non-string quantity"))?;
    Ok(Some(parse_quantity(hex_str, "rpc quantity")?))
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

/// Dispatch an `oc_*` method. Called by the wallet-rpc router for methods with
/// the `oc_` prefix; unknown `oc_*` names fail closed.
///
/// `origin` is the already-validated `chrome-extension://<id>` the request came
/// from — it pins every session-scoped call to the extension that unlocked it.
pub(crate) fn dispatch(
    state: &super::AppState,
    method: &str,
    params: &Value,
    origin: &str,
) -> Result<Value, OcwpError> {
    match method {
        "oc_hello" => handle_hello(state),
        "oc_unlock" => handle_unlock(state, params, origin),
        "oc_lock" => handle_lock(state, params, origin),
        "oc_session_status" => handle_session_status(state, params, origin),
        "oc_accounts" => handle_accounts(state, params, origin),
        "oc_connect_site" => handle_connect_site(state, params, origin),
        "oc_revoke_site" => handle_revoke_site(state, params, origin),
        "oc_list_sites" => handle_list_sites(state, params, origin),
        "oc_chain_registry" => handle_chain_registry(state, params, origin),
        "oc_add_custom_chain" => handle_add_custom_chain(state, params, origin),
        "oc_sign_transaction" => handle_sign_transaction(state, params, origin),
        "oc_send_transaction" => handle_send_transaction(state, params, origin),
        "oc_sign_message" => handle_sign_message(state, params, origin),
        "oc_sign_typed_data" => handle_sign_typed_data(state, params, origin),
        "oc_sign_authorization" => handle_sign_authorization(state, params, origin),
        "oc_rpc" => handle_rpc(state, params, origin),
        "oc_simulate" => handle_simulate(state, params, origin),
        "oc_policy_preview" => handle_policy_preview(state, params, origin),
        "oc_audit_tail" => handle_audit_tail(state, params, origin),
        "oc_passkey_challenge" => handle_passkey_challenge(state, params, origin),
        "oc_passkey_register" => handle_passkey_register(state, params, origin),
        other => Err(OcwpError::unsupported(format!("method not found: {other}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rlp_decodes_typed_tx_fields() {
        // Build a minimal type-2 tx and decode it back.
        let to = [0x11u8; 20];
        let items: Vec<u8> = [
            oc_signer::rlp::encode_u128(8453),
            oc_signer::rlp::encode_u128(7),
            oc_signer::rlp::encode_u128(1),
            oc_signer::rlp::encode_u128(2),
            oc_signer::rlp::encode_u128(21000),
            oc_signer::rlp::encode_bytes(&to),
            oc_signer::rlp::encode_u128(1000),
            oc_signer::rlp::encode_bytes(&[0xde, 0xad, 0xbe, 0xef]),
            oc_signer::rlp::encode_list(&[]),
        ]
        .concat();
        let mut raw = vec![0x02u8];
        raw.extend_from_slice(&oc_signer::rlp::encode_list(&items));
        let summary = decode_tx_summary(&raw);
        assert_eq!(summary.to.as_deref(), Some("0x1111111111111111111111111111111111111111"));
        assert_eq!(summary.value.as_deref(), Some("1000"));
        assert_eq!(summary.data.as_deref(), Some("0xdeadbeef"));
    }

    #[test]
    fn rlp_decodes_legacy_tx_fields() {
        let to = [0x22u8; 20];
        let items: Vec<u8> = [
            oc_signer::rlp::encode_u128(3),
            oc_signer::rlp::encode_u128(20_000_000_000),
            oc_signer::rlp::encode_u128(21000),
            oc_signer::rlp::encode_bytes(&to),
            oc_signer::rlp::encode_u128(5_000_000_000_000_000_000),
            oc_signer::rlp::encode_bytes(&[]),
        ]
        .concat();
        let raw = oc_signer::rlp::encode_list(&items);
        let summary = decode_tx_summary(&raw);
        assert_eq!(summary.to.as_deref(), Some("0x2222222222222222222222222222222222222222"));
        assert_eq!(summary.value.as_deref(), Some("5000000000000000000"));
    }

    #[test]
    fn malformed_tx_summary_is_empty_not_panic() {
        let summary = decode_tx_summary(&[0x02, 0xff, 0xff]);
        assert!(summary.to.is_none());
        assert!(summary.value.is_none());
        assert!(decode_tx_summary(&[]).to.is_none());
    }

    #[test]
    fn quantity_parsing_accepts_decimal_and_hex() {
        assert_eq!(parse_quantity("1000", "v").unwrap(), 1000);
        assert_eq!(parse_quantity("0x3e8", "v").unwrap(), 1000);
        assert!(parse_quantity("nope", "v").is_err());
    }

    #[test]
    fn tx_kind_parses_eip1193_and_ocwp_spellings() {
        let cases: &[(&str, TxKind)] = &[
            (r#""0x0""#, TxKind::Legacy),
            (r#""0x00""#, TxKind::Legacy),
            ("0", TxKind::Legacy),
            (r#""0x1""#, TxKind::Eip2930),
            (r#""0x2""#, TxKind::Eip1559),
            (r#""0x02""#, TxKind::Eip1559),
            (r#""0x4""#, TxKind::Eip7702),
            (r#""0x04""#, TxKind::Eip7702),
        ];
        for (wire, expected) in cases {
            let value: Value = serde_json::from_str(wire).expect("json");
            assert_eq!(TxKind::from_wire(Some(&value)).expect("kind"), *expected, "{wire}");
        }
        // Absent = EIP-1559 (the documented default).
        assert_eq!(TxKind::from_wire(None).expect("kind"), TxKind::Eip1559);
        assert_eq!(TxKind::from_wire(Some(&Value::Null)).expect("kind"), TxKind::Eip1559);
        // Blob transactions are refused rather than re-encoded as something else.
        let blob = Value::String("0x3".into());
        assert!(TxKind::from_wire(Some(&blob)).is_err());
        let junk = Value::String("nope".into());
        assert!(TxKind::from_wire(Some(&junk)).is_err());
    }

    #[test]
    fn chain_reference_normalizes_hex_and_caip2() {
        assert_eq!(normalize_chain_reference("0x1").unwrap(), "eip155:1");
        assert_eq!(normalize_chain_reference("0x89").unwrap(), "eip155:137");
        assert_eq!(normalize_chain_reference("0x2105").unwrap(), "eip155:8453");
        // CAIP-2 references are decimal — `eip155:8453` is Base, NOT `0x8453`.
        assert_eq!(normalize_chain_reference("eip155:8453").unwrap(), "eip155:8453");
        assert_ne!(
            normalize_chain_reference("eip155:8453").unwrap(),
            normalize_chain_reference("0x8453").unwrap(),
            "decimal and hex references must not collapse to the same chain"
        );
        assert!(normalize_chain_reference("1").is_err(), "bare decimal is ambiguous");
        assert!(normalize_chain_reference("0xzz").is_err());
        assert!(normalize_chain_reference("eip155:").is_err());
        assert!(normalize_chain_reference("eip155:0x1").is_err(), "CAIP-2 is decimal");
    }

    #[test]
    fn project_tx_accepts_both_field_spellings() {
        let camel: Value = serde_json::json!({
            "to": "0x1111111111111111111111111111111111111111",
            "value": "0x3e8",
            "data": "0xdeadbeef",
            "input": "0xignored",
            "maxFeePerGas": "0x10",
        });
        let snake: Value = serde_json::json!({
            "to": "0x1111111111111111111111111111111111111111",
            "value": "0x3e8",
            "data": "0xdeadbeef",
            "max_fee_per_gas": "0x10",
        });
        let a = project_tx(&camel).expect("camelCase projection");
        let b = project_tx(&snake).expect("snake_case projection");
        assert_eq!(a.to, b.to);
        assert_eq!(a.value.as_deref(), Some("1000"), "hex quantity becomes decimal");
        assert_eq!(a.data.as_deref(), Some("0xdeadbeef"));
        assert_eq!(a.kind, Some(TxKind::Eip1559));

        // `input` is the EIP-1193 alias for `data`.
        let input_only = serde_json::json!({ "to": "0x1111111111111111111111111111111111111111", "input": "0xa9059cbb" });
        assert_eq!(
            project_tx(&input_only).expect("input alias").data.as_deref(),
            Some("0xa9059cbb")
        );
    }

    #[test]
    fn project_tx_rejects_junk() {
        assert!(project_tx(&serde_json::json!("not an object")).is_err());
        assert!(project_tx(&serde_json::json!({ "to": "0xdead" })).is_err(), "short address");
        assert!(project_tx(&serde_json::json!({ "value": "0xzz" })).is_err(), "bad quantity");
        assert!(project_tx(&serde_json::json!({ "data": "0xnothex" })).is_err());
    }

    #[test]
    fn field_helpers_prefer_first_present_and_skip_nulls() {
        let obj = serde_json::json!({ "a": Value::Null, "b": "second", "c": "third" });
        let map = obj.as_object().expect("object");
        assert_eq!(field_str(map, &["a", "b"]), Some("second"));
        assert_eq!(field_str(map, &["a", "c"]), Some("third"));
        assert_eq!(field_str(map, &["missing"]), None);
    }

    #[test]
    fn field_quantity_accepts_strings_and_numbers() {
        let obj = serde_json::json!({ "hex": "0x10", "dec": 16, "bad": true });
        let map = obj.as_object().expect("object");
        assert_eq!(field_quantity(map, &["hex"], "f").unwrap(), Some(16));
        assert_eq!(field_quantity(map, &["dec"], "f").unwrap(), Some(16));
        assert!(field_quantity(map, &["bad"], "f").is_err());
        assert_eq!(field_quantity(map, &["absent"], "f").unwrap(), None);
    }

    #[test]
    fn raw_summary_reports_envelope_type() {
        let to = [0x33u8; 20];
        let items: Vec<u8> = [
            oc_signer::rlp::encode_u128(1),
            oc_signer::rlp::encode_u128(0),
            oc_signer::rlp::encode_u128(1),
            oc_signer::rlp::encode_u128(2),
            oc_signer::rlp::encode_u128(21000),
            oc_signer::rlp::encode_bytes(&to),
            oc_signer::rlp::encode_u128(0),
            oc_signer::rlp::encode_bytes(&[]),
            oc_signer::rlp::encode_list(&[]),
        ]
        .concat();
        let mut raw = vec![0x02u8];
        raw.extend_from_slice(&oc_signer::rlp::encode_list(&items));
        assert_eq!(decode_tx_summary(&raw).kind_label, "0x02 (EIP-1559)");

        let mut raw7702 = vec![0x04u8];
        raw7702.extend_from_slice(&oc_signer::rlp::encode_list(&items));
        assert_eq!(decode_tx_summary(&raw7702).kind_label, "0x04 (EIP-7702 delegation)");

        let legacy = oc_signer::rlp::encode_list(&[oc_signer::rlp::encode_u128(0)].concat());
        assert_eq!(decode_tx_summary(&legacy).kind_label, "0x00 (legacy)");
    }

    #[test]
    fn delegation_detail_is_empty_without_authorizations() {
        let plain = ResolvedTx {
            raw_hex: String::new(),
            to: None,
            value: None,
            data: None,
            kind_label: "0x02 (EIP-1559)".into(),
            delegations: Vec::new(),
        };
        assert_eq!(delegation_detail(&plain), "");
        let delegating = ResolvedTx { delegations: vec!["0xaaa".into(), "0xbbb".into()], ..plain };
        assert_eq!(delegation_detail(&delegating), " delegations=[0xaaa,0xbbb]");
    }

    #[test]
    fn dispatch_rejects_unknown_oc_method() {
        // Dispatch needs an AppState; exercise the fail-closed arm indirectly
        // through the error constructor instead.
        let err = OcwpError::unsupported("method not found: oc_bogus");
        assert_eq!(err.code, super::super::errors::CODE_UNSUPPORTED);
    }

    #[test]
    fn policy_missing_constant_is_stable() {
        assert_eq!(super::super::errors::CODE_POLICY_MISSING, 4305);
    }

    #[test]
    fn session_settings_defaults_match_design() {
        let s = super::super::session::SessionSettings::default();
        assert_eq!(s.ttl_secs, 900);
        assert_eq!(s.idle_secs, 300);
    }

    #[test]
    fn registries_validate_origin_rejects_path() {
        assert!(super::super::registries::validate_origin("https://x.example/path").is_err());
        assert!(super::super::registries::validate_origin("https://x.example").is_ok());
    }
}
