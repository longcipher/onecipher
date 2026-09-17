//! Minimal RLP encoding/decoding for EVM signed transaction construction.
//!
//! Only implements the subset needed to append v, r, s to an unsigned
//! EIP-1559/EIP-2930 transaction list.
//!
//! A13: `no_std`-compatible (uses `alloc` only when `std` is off).

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::traits::SignerError;

/// Decode the length of an RLP item (string or list) at the start of `data`.
/// Returns `(payload_offset, payload_length)`.
fn decode_length(data: &[u8]) -> Result<(usize, usize), SignerError> {
    if data.is_empty() {
        return Err(SignerError::Transaction("empty input".into()));
    }
    let prefix = data[0];
    match prefix {
        // Single byte
        0x00..=0x7f => Ok((0, 1)),
        // Short string (0-55 bytes)
        0x80..=0xb7 => {
            let len = (prefix - 0x80) as usize;
            Ok((1, len))
        }
        // Long string (>55 bytes)
        0xb8..=0xbf => {
            let len_bytes = (prefix - 0xb7) as usize;
            if data.len() < 1 + len_bytes {
                return Err(SignerError::Transaction("truncated RLP length".into()));
            }
            let len = read_be_uint(&data[1..=len_bytes]);
            Ok((1 + len_bytes, len))
        }
        // Short list (0-55 bytes total payload)
        0xc0..=0xf7 => {
            let len = (prefix - 0xc0) as usize;
            Ok((1, len))
        }
        // Long list (>55 bytes total payload)
        0xf8..=0xff => {
            let len_bytes = (prefix - 0xf7) as usize;
            if data.len() < 1 + len_bytes {
                return Err(SignerError::Transaction("truncated RLP length".into()));
            }
            let len = read_be_uint(&data[1..=len_bytes]);
            Ok((1 + len_bytes, len))
        }
    }
}

fn read_be_uint(bytes: &[u8]) -> usize {
    let mut val = 0usize;
    for &b in bytes {
        val = (val << 8) | b as usize;
    }
    val
}

/// RLP-encode a byte string.
pub fn encode_bytes(data: &[u8]) -> Vec<u8> {
    if data.len() == 1 && data[0] < 0x80 {
        return data.to_vec();
    }
    let mut out = encode_length(data.len(), 0x80);
    out.extend_from_slice(data);
    out
}

/// RLP-encode a list from already-encoded concatenated items.
pub fn encode_list(items: &[u8]) -> Vec<u8> {
    let mut out = encode_length(items.len(), 0xc0);
    out.extend_from_slice(items);
    out
}

/// RLP-encode a non-negative integer as a minimal big-endian scalar.
///
/// Per RLP, the integer `0` is encoded as the empty string (`0x80`), and a
/// single byte `< 0x80` is encoded as that byte directly. This is the
/// canonical encoding for transaction fields (chain id, nonce, gas, value…).
pub fn encode_u64(val: u64) -> Vec<u8> {
    encode_minimal_int(&val.to_be_bytes())
}

/// RLP-encode a `u128` integer (e.g. wei value) as a minimal big-endian scalar.
pub fn encode_u128(val: u128) -> Vec<u8> {
    encode_minimal_int(&val.to_be_bytes())
}

/// Encode a big-endian integer byte array as RLP, stripping leading zeros.
fn encode_minimal_int(bytes: &[u8]) -> Vec<u8> {
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    encode_bytes(&bytes[start..])
}

fn encode_length(len: usize, offset: u8) -> Vec<u8> {
    if len < 56 {
        vec![offset + len as u8]
    } else {
        let len_bytes = be_bytes(len);
        let mut out = vec![offset + 55 + len_bytes.len() as u8];
        out.extend_from_slice(&len_bytes);
        out
    }
}

fn be_bytes(val: usize) -> Vec<u8> {
    if val == 0 {
        return vec![0];
    }
    let bytes = val.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len() - 1);
    bytes[start..].to_vec()
}

/// Strip leading zeros from a 32-byte scalar for minimal RLP encoding.
fn strip_leading_zeros(data: &[u8]) -> &[u8] {
    let start = data.iter().position(|&b| b != 0).unwrap_or(data.len());
    &data[start..]
}

/// Given unsigned typed transaction bytes (e.g. `0x02 || RLP([...fields])`)
/// and a signature, produce the signed transaction bytes:
/// `type_byte || RLP([...fields, v, r, s])`.
///
/// For EIP-1559 (type 0x02) and EIP-2930 (type 0x01), v is the raw
/// recovery ID (0 or 1). r and s are 32-byte big-endian scalars.
pub fn encode_signed_typed_tx(
    unsigned_tx: &[u8],
    v: u8,
    r: &[u8; 32],
    s: &[u8; 32],
) -> Result<Vec<u8>, SignerError> {
    if unsigned_tx.is_empty() {
        return Err(SignerError::Transaction("empty transaction".into()));
    }

    let type_byte = unsigned_tx[0];
    if type_byte != 0x01 && type_byte != 0x02 {
        return Err(SignerError::Transaction(
            "unsupported transaction type (expected 0x01 or 0x02)".into(),
        ));
    }

    let rlp_data = &unsigned_tx[1..];
    let (payload_offset, payload_length) = decode_length(rlp_data)?;

    if rlp_data.len() < payload_offset + payload_length {
        return Err(SignerError::Transaction("truncated RLP payload".into()));
    }

    // Extract the inner list items (raw concatenated RLP items)
    let items = &rlp_data[payload_offset..payload_offset + payload_length];

    // Append v, r, s as RLP-encoded items
    let v_encoded = encode_bytes(strip_leading_zeros(&[v]));
    let r_encoded = encode_bytes(strip_leading_zeros(r));
    let s_encoded = encode_bytes(strip_leading_zeros(s));

    let mut new_items = items.to_vec();
    new_items.extend_from_slice(&v_encoded);
    new_items.extend_from_slice(&r_encoded);
    new_items.extend_from_slice(&s_encoded);

    // Re-encode as list and prepend type byte
    let mut result = vec![type_byte];
    result.extend_from_slice(&encode_list(&new_items));
    Ok(result)
}

/// Split a concatenated RLP payload into its raw item slices (each slice
/// keeps its own RLP prefix).
fn split_items(payload: &[u8]) -> Result<Vec<&[u8]>, SignerError> {
    let mut items = Vec::new();
    let mut pos = 0;
    while pos < payload.len() {
        let (off, len) = decode_length(&payload[pos..])?;
        let total = off.saturating_add(len);
        if payload.len() - pos < total {
            return Err(SignerError::Transaction("truncated RLP item".into()));
        }
        items.push(&payload[pos..pos + total]);
        pos += total;
    }
    Ok(items)
}

/// Decode one RLP integer item to `u64` (minimal big-endian scalar).
fn decode_uint(item: &[u8]) -> Result<u64, SignerError> {
    let (off, len) = decode_length(item)?;
    if item.len() < off.saturating_add(len) {
        return Err(SignerError::Transaction("truncated RLP integer".into()));
    }
    let bytes = &item[off..off + len];
    if bytes.len() > 8 {
        return Err(SignerError::Transaction("integer exceeds u64".into()));
    }
    let mut val = 0u64;
    for &b in bytes {
        val = (val << 8) | u64::from(b);
    }
    Ok(val)
}

/// Given an unsigned legacy transaction and a signature, produce the signed
/// transaction bytes: `RLP([nonce, gasPrice, gasLimit, to, value, data, v, r, s])`.
///
/// Accepts both shapes:
/// - EIP-155 (9 items, `[..., chain_id, 0, 0]`): `v = chain_id * 2 + 35 + recovery_id`.
/// - Pre-EIP-155 (6 items): `v = 27 + recovery_id`.
///
/// `recovery_id` must be 0 or 1; r and s are 32-byte big-endian scalars.
pub fn encode_signed_legacy_tx(
    unsigned_tx: &[u8],
    recovery_id: u8,
    r: &[u8; 32],
    s: &[u8; 32],
) -> Result<Vec<u8>, SignerError> {
    if recovery_id > 1 {
        return Err(SignerError::Transaction("invalid recovery id (expected 0 or 1)".into()));
    }
    if unsigned_tx.is_empty() {
        return Err(SignerError::Transaction("empty transaction".into()));
    }
    if !matches!(unsigned_tx[0], 0xc0..=0xff) {
        return Err(SignerError::Transaction("expected RLP list (legacy transaction)".into()));
    }

    let (payload_offset, payload_length) = decode_length(unsigned_tx)?;
    if unsigned_tx.len() < payload_offset.saturating_add(payload_length) {
        return Err(SignerError::Transaction("truncated RLP payload".into()));
    }
    let payload = &unsigned_tx[payload_offset..payload_offset + payload_length];
    let items = split_items(payload)?;

    let (fields, v) = match items.len() {
        9 => {
            let chain_id = decode_uint(items[6])?;
            let v = chain_id
                .checked_mul(2)
                .and_then(|c| c.checked_add(35 + u64::from(recovery_id)))
                .ok_or_else(|| SignerError::Transaction("v overflows u64".into()))?;
            (&items[..6], v)
        }
        6 => (&items[..], 27 + u64::from(recovery_id)),
        _ => {
            return Err(SignerError::Transaction(
                "expected 6 (pre-EIP-155) or 9 (EIP-155) unsigned items".into(),
            ));
        }
    };

    let mut new_items = fields.concat();
    new_items.extend_from_slice(&encode_u64(v));
    new_items.extend_from_slice(&encode_bytes(strip_leading_zeros(r)));
    new_items.extend_from_slice(&encode_bytes(strip_leading_zeros(s)));

    Ok(encode_list(&new_items))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_bytes_single() {
        assert_eq!(encode_bytes(&[0x42]), vec![0x42]);
    }

    #[test]
    fn test_encode_bytes_short() {
        let data = vec![0x01, 0x02, 0x03];
        let encoded = encode_bytes(&data);
        assert_eq!(encoded[0], 0x83); // 0x80 + 3
        assert_eq!(&encoded[1..], &data[..]);
    }

    #[test]
    fn test_encode_bytes_empty() {
        assert_eq!(encode_bytes(&[]), vec![0x80]);
    }

    #[test]
    fn test_encode_list_empty() {
        assert_eq!(encode_list(&[]), vec![0xc0]);
    }

    #[test]
    fn test_roundtrip_signed_tx() {
        // Construct a minimal unsigned EIP-1559 tx:
        // 0x02 || RLP([chain_id=1, nonce=0, maxPriorityFee=0, maxFee=0, gas=0, to="", value=0,
        // data="", accessList=[]])
        let items: Vec<u8> = [
            encode_bytes(&[1]), // chain_id = 1
            encode_bytes(&[]),  // nonce = 0
            encode_bytes(&[]),  // maxPriorityFeePerGas = 0
            encode_bytes(&[]),  // maxFeePerGas = 0
            encode_bytes(&[]),  // gasLimit = 0
            encode_bytes(&[]),  // to = empty (contract creation)
            encode_bytes(&[]),  // value = 0
            encode_bytes(&[]),  // data = empty
            encode_list(&[]),   // accessList = empty
        ]
        .concat();

        let mut unsigned_tx = vec![0x02];
        unsigned_tx.extend_from_slice(&encode_list(&items));

        let r = [0u8; 32];
        let s = [0u8; 32];
        let v = 1u8;

        let signed = encode_signed_typed_tx(&unsigned_tx, v, &r, &s).unwrap();

        // Signed tx should start with type byte
        assert_eq!(signed[0], 0x02);

        // Decode the signed list
        let (offset, length) = decode_length(&signed[1..]).unwrap();
        let signed_items = &signed[1 + offset..1 + offset + length];

        // It should be longer than the unsigned items (v + r + s appended)
        assert!(signed_items.len() > items.len());
    }

    #[test]
    fn test_strip_leading_zeros() {
        assert_eq!(strip_leading_zeros(&[0, 0, 1, 2]), &[1, 2]);
        assert_eq!(strip_leading_zeros(&[0, 0, 0, 0]), &[] as &[u8]);
        assert_eq!(strip_leading_zeros(&[1, 2, 3]), &[1, 2, 3]);
    }

    #[test]
    fn test_rejects_legacy_tx() {
        // Legacy tx starts with RLP list prefix (0xc0+), not a type byte
        let legacy = vec![0xc0];
        let r = [0u8; 32];
        let s = [0u8; 32];
        assert!(encode_signed_typed_tx(&legacy, 0, &r, &s).is_err());
    }

    /// Build an unsigned EIP-155 legacy tx:
    /// `RLP([nonce=0, gasPrice=1gwei, gas=21000, to, value=1wei, data="", chain=1, 0, 0])`.
    fn unsigned_legacy_eip155() -> Vec<u8> {
        let to = [0x11u8; 20];
        let items: Vec<u8> = [
            encode_u64(0),             // nonce
            encode_u64(1_000_000_000), // gasPrice
            encode_u64(21_000),        // gasLimit
            encode_bytes(&to),         // to
            encode_u64(1),             // value
            encode_bytes(&[]),         // data
            encode_u64(1),             // chain_id
            encode_bytes(&[]),         // 0
            encode_bytes(&[]),         // 0
        ]
        .concat();
        encode_list(&items)
    }

    #[test]
    fn test_encode_signed_legacy_tx_eip155() {
        let unsigned = unsigned_legacy_eip155();
        let r = [0x22u8; 32];
        let s = [0x33u8; 32];

        let signed = encode_signed_legacy_tx(&unsigned, 1, &r, &s).unwrap();

        let (off, len) = decode_length(&signed).unwrap();
        let fields = split_items(&signed[off..off + len]).unwrap();
        assert_eq!(fields.len(), 9, "signed legacy tx must carry 9 items");

        // v = chain_id * 2 + 35 + recovery_id = 1*2+35+1 = 38
        assert_eq!(decode_uint(fields[6]).unwrap(), 38);

        // First six fields are preserved byte-for-byte.
        let (uoff, ulen) = decode_length(&unsigned).unwrap();
        let unsigned_payload = &unsigned[uoff..uoff + ulen];
        let unsigned_fields = split_items(unsigned_payload).unwrap();
        assert_eq!(fields[..6], unsigned_fields[..6]);

        // r and s round-trip.
        assert_eq!(rlp_payload(fields[7]), &r[..]);
        assert_eq!(rlp_payload(fields[8]), &s[..]);
    }

    #[test]
    fn test_encode_signed_legacy_tx_pre_eip155() {
        // Pre-EIP-155: only 6 items, v = 27 + recovery_id.
        let to = [0x11u8; 20];
        let items: Vec<u8> = [
            encode_u64(0),
            encode_u64(1_000_000_000),
            encode_u64(21_000),
            encode_bytes(&to),
            encode_u64(1),
            encode_bytes(&[]),
        ]
        .concat();
        let unsigned = encode_list(&items);

        let signed = encode_signed_legacy_tx(&unsigned, 0, &[0x22u8; 32], &[0x33u8; 32]).unwrap();
        let (off, len) = decode_length(&signed).unwrap();
        let fields = split_items(&signed[off..off + len]).unwrap();
        assert_eq!(fields.len(), 9);
        assert_eq!(decode_uint(fields[6]).unwrap(), 27);
    }

    #[test]
    fn test_encode_signed_legacy_tx_rejects_bad_input() {
        let r = [0u8; 32];
        let s = [0u8; 32];
        // Empty input.
        assert!(encode_signed_legacy_tx(&[], 0, &r, &s).is_err());
        // Typed tx (not a bare RLP list).
        assert!(encode_signed_legacy_tx(&[0x02, 0xc0], 0, &r, &s).is_err());
        // Bad recovery id.
        assert!(encode_signed_legacy_tx(&unsigned_legacy_eip155(), 2, &r, &s).is_err());
        // Wrong item count (7 items is neither pre-EIP-155 nor EIP-155).
        let seven: Vec<u8> = [
            encode_u64(0),
            encode_u64(1),
            encode_u64(2),
            encode_u64(3),
            encode_u64(4),
            encode_u64(5),
            encode_u64(6),
        ]
        .concat();
        assert!(encode_signed_legacy_tx(&encode_list(&seven), 0, &r, &s).is_err());
        // chain_id wider than u64.
        let to = [0x11u8; 20];
        let big_chain: Vec<u8> = [
            encode_u64(0),
            encode_u64(1),
            encode_u64(2),
            encode_bytes(&to),
            encode_u64(0),
            encode_bytes(&[]),
            encode_bytes(&[0xff; 9]),
            encode_bytes(&[]),
            encode_bytes(&[]),
        ]
        .concat();
        assert!(encode_signed_legacy_tx(&encode_list(&big_chain), 0, &r, &s).is_err());
    }

    /// Decode one RLP item to its raw payload bytes (test helper).
    fn rlp_payload(item: &[u8]) -> &[u8] {
        let (off, len) = decode_length(item).unwrap();
        &item[off..off + len]
    }

    #[test]
    fn test_v_zero_encoded_as_rlp_integer_zero() {
        // BUG TEST: In RLP, integer 0 is encoded as the empty byte string → [0x80].
        // encode_bytes(&[0]) returns [0x00] (the byte value 0), which is the RLP
        // encoding of a single-byte string containing 0x00 — NOT integer zero.
        // For EIP-1559/EIP-2930 transactions, yParity=0 must be encoded as integer 0.
        //
        // The correct encoding uses strip_leading_zeros:
        //   strip_leading_zeros(&[0]) → &[]
        //   encode_bytes(&[])         → [0x80]

        // First, verify the underlying primitives:
        assert_eq!(
            strip_leading_zeros(&[0]),
            &[] as &[u8],
            "strip_leading_zeros(&[0]) should yield empty slice"
        );
        assert_eq!(
            encode_bytes(&[]),
            vec![0x80],
            "encode_bytes of empty slice should be [0x80] (RLP integer 0)"
        );
        assert_eq!(
            encode_bytes(&[0]),
            vec![0x00],
            "encode_bytes(&[0]) is [0x00] — correct for a byte string, wrong for integer 0"
        );

        // Now verify the signed transaction encoding with v=0:
        let items: Vec<u8> = [
            encode_bytes(&[1]), // chain_id = 1
            encode_bytes(&[]),  // nonce = 0
            encode_bytes(&[]),  // maxPriorityFeePerGas = 0
            encode_bytes(&[]),  // maxFeePerGas = 0
            encode_bytes(&[]),  // gasLimit = 0
            encode_bytes(&[]),  // to = empty
            encode_bytes(&[]),  // value = 0
            encode_bytes(&[]),  // data = empty
            encode_list(&[]),   // accessList = empty
        ]
        .concat();

        let mut unsigned_tx = vec![0x02];
        unsigned_tx.extend_from_slice(&encode_list(&items));

        let r = [0u8; 32];
        let s = [0u8; 32];
        let v = 0u8; // recovery id 0

        let signed = encode_signed_typed_tx(&unsigned_tx, v, &r, &s).unwrap();

        // Decode the signed list to inspect the appended v field
        let (offset, length) = decode_length(&signed[1..]).unwrap();
        let signed_payload = &signed[1 + offset..1 + offset + length];

        // The original unsigned items occupy `items.len()` bytes.
        // After them come v, r, s as RLP-encoded items.
        let v_and_rs = &signed_payload[items.len()..];

        // The first byte of the appended data is the RLP-encoded v.
        // For v=0 (integer zero), it MUST be 0x80 (empty byte string).
        assert_eq!(
            v_and_rs[0], 0x80,
            "v=0 must be RLP-encoded as 0x80 (integer zero), not 0x00 (byte value zero)"
        );
    }

    #[test]
    fn test_v_one_encoded_correctly() {
        // v=1 should be encoded as [0x01] — a single byte < 0x80 is its own RLP encoding.
        let items: Vec<u8> = [
            encode_bytes(&[1]),
            encode_bytes(&[]),
            encode_bytes(&[]),
            encode_bytes(&[]),
            encode_bytes(&[]),
            encode_bytes(&[]),
            encode_bytes(&[]),
            encode_bytes(&[]),
            encode_list(&[]),
        ]
        .concat();

        let mut unsigned_tx = vec![0x02];
        unsigned_tx.extend_from_slice(&encode_list(&items));

        let r = [0u8; 32];
        let s = [0u8; 32];
        let v = 1u8;

        let signed = encode_signed_typed_tx(&unsigned_tx, v, &r, &s).unwrap();

        let (offset, length) = decode_length(&signed[1..]).unwrap();
        let signed_payload = &signed[1 + offset..1 + offset + length];
        let v_and_rs = &signed_payload[items.len()..];

        assert_eq!(v_and_rs[0], 0x01, "v=1 must be RLP-encoded as 0x01");
    }
}
