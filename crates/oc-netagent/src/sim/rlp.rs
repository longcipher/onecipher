//! Minimal RLP decoder for EVM signed transactions.
//!
//! Only the subset needed by the offline simulator: decode the top-level
//! transaction list and extract `to`, `value`, and `data`. Supports legacy
//! (untyped) and typed transactions (EIP-2930 `0x01`, EIP-1559 `0x02`,
//! EIP-4844 `0x03` — the last only for field positions; blob tx simulation
//! is out of scope and rejected elsewhere).
//!
//! This is intentionally tiny and self-contained: the workspace's `oc-signer`
//! RLP module only *encodes* signed transactions, and pulling a full RLP
//! library (alloy-rlp, rlp) into `oc-netagent` would add a dependency for
//! ~150 lines of pure parsing.

/// A parsed transaction, with only the fields the simulator needs.
#[derive(Debug, Clone)]
pub(crate) struct TxFields {
    /// `to` field, or `None` for contract creation transactions.
    pub(crate) to: Option<[u8; 20]>,
    /// `value` in wei.
    pub(crate) value: u128,
    /// `data` (empty for native transfers).
    pub(crate) data: Vec<u8>,
}

/// Parse a signed transaction into its simulator-relevant fields.
///
/// Accepts legacy transactions (RLP list of 9 items) and typed transactions
/// (`0x01`/`0x02`/`0x03` followed by an RLP list). For EIP-2930 and EIP-1559
/// the `to`/`value`/`data` are at the same list offsets (indices 4, 5, 6);
/// for legacy they are at indices 3, 4, 5.
pub(crate) fn decode_tx_fields(tx: &[u8]) -> Result<TxFields, String> {
    if tx.is_empty() {
        return Err("empty transaction".into());
    }

    let (list_offset, list_len, item_count) = match tx[0] {
        // Legacy: the whole payload is a list of 9 items.
        0xc0..=0xf7 => {
            let (off, len) = list_header(tx, 0)?;
            (off, len, 9)
        }
        0xf8..=0xff => {
            let (off, len) = list_header(tx, 0)?;
            (off, len, 9)
        }
        // Typed transactions: envelope byte then a list.
        // EIP-2930 has 11 items; EIP-1559 and EIP-4844 have 12 and 14.
        0x01 => {
            let (off, len) = list_header(tx, 1)?;
            (off, len, 11)
        }
        0x02 => {
            let (off, len) = list_header(tx, 1)?;
            (off, len, 12)
        }
        0x03 => {
            let (off, len) = list_header(tx, 1)?;
            (off, len, 14)
        }
        other => {
            return Err(format!("unsupported transaction envelope byte 0x{other:02x}"));
        }
    };

    let payload = tx
        .get(list_offset..list_offset + list_len)
        .ok_or_else(|| "truncated RLP list payload".to_string())?;

    let items = split_items(payload)?;
    if items.len() < item_count {
        return Err(format!(
            "transaction list has {} items, expected at least {item_count}",
            items.len()
        ));
    }

    // Field offsets by envelope:
    //   legacy [nonce, gasPrice, gas, to, value, data, v, r, s]         → to=3
    //   0x01   [chainId, nonce, gasPrice, gas, to, value, data, …]       → to=4
    //   0x02   [chainId, nonce, maxPriFee, maxFee, gas, to, value, …]    → to=5
    //   0x03   [chainId, nonce, maxPriFee, maxFee, gas, to, value, …]    → to=5
    let (to_idx, value_idx, data_idx) = match tx[0] {
        0x01 => (4, 5, 6),
        0x02 | 0x03 => (5, 6, 7),
        _ => (3, 4, 5),
    };

    let to = if items[to_idx].is_empty() {
        None // contract creation
    } else {
        Some(
            items[to_idx]
                .as_slice()
                .try_into()
                .map_err(|_| "to field is not a 20-byte address".to_string())?,
        )
    };

    let value = be_u128(&items[value_idx]);
    let data = items[data_idx].clone();

    Ok(TxFields { to, value, data })
}

/// Decode an RLP list header starting at `start`. Returns `(payload_offset,
/// payload_length)` relative to the whole input.
fn list_header(tx: &[u8], start: usize) -> Result<(usize, usize), String> {
    let prefix = *tx.get(start).ok_or_else(|| "truncated list header".to_string())?;
    match prefix {
        0xc0..=0xf7 => Ok((start + 1, (prefix - 0xc0) as usize)),
        0xf8..=0xff => {
            let len_bytes = (prefix - 0xf7) as usize;
            let bytes = tx
                .get(start + 1..start + 1 + len_bytes)
                .ok_or_else(|| "truncated long-list length".to_string())?;
            let len = be_usize(bytes);
            Ok((start + 1 + len_bytes, len))
        }
        other => Err(format!("expected list header, got 0x{other:02x}")),
    }
}

/// Split a concatenated RLP payload into its items.
fn split_items(payload: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    let mut items = Vec::new();
    let mut pos = 0usize;
    while pos < payload.len() {
        let prefix = payload[pos];
        let (item_start, item_len) = if prefix <= 0x7f {
            // Single byte: the byte itself.
            (pos, 1)
        } else if (0x80..=0xb7).contains(&prefix) {
            // Short string.
            (pos + 1, (prefix - 0x80) as usize)
        } else if (0xb8..=0xbf).contains(&prefix) {
            // Long string.
            let len_bytes = (prefix - 0xb7) as usize;
            let lb = payload
                .get(pos + 1..pos + 1 + len_bytes)
                .ok_or_else(|| "truncated long-string length".to_string())?;
            let len = be_usize(lb);
            (pos + 1 + len_bytes, len)
        } else if (0xc0..=0xf7).contains(&prefix) {
            // Short list: item is the whole (prefix, payload) — the nested
            // list content is opaque to us; treat as one item.
            let len = (prefix - 0xc0) as usize;
            (pos + 1, len)
        } else {
            // Long list.
            let len_bytes = (prefix - 0xf7) as usize;
            let lb = payload
                .get(pos + 1..pos + 1 + len_bytes)
                .ok_or_else(|| "truncated long-list length".to_string())?;
            let len = be_usize(lb);
            (pos + 1 + len_bytes, len)
        };

        let end =
            item_start.checked_add(item_len).ok_or_else(|| "item length overflow".to_string())?;
        if end > payload.len() {
            return Err(format!("truncated RLP item at offset {pos}"));
        }
        items.push(payload[item_start..end].to_vec());
        pos = end;
    }
    Ok(items)
}

/// Interpret a big-endian byte slice as `u128` (values beyond u128 saturate).
fn be_u128(bytes: &[u8]) -> u128 {
    if bytes.len() > 16 {
        return u128::MAX;
    }
    let mut out = 0u128;
    for &b in bytes {
        out = (out << 8) | u128::from(b);
    }
    out
}

fn be_usize(bytes: &[u8]) -> usize {
    let mut out = 0usize;
    for &b in bytes {
        out = (out << 8) | usize::from(b);
    }
    out
}

// ── Encoding helpers (test-only) ─────────────────────────────────────────

/// Encode a byte string as an RLP item (test helper; matches the decode above).
#[cfg(test)]
pub(crate) fn encode_item(data: &[u8]) -> Vec<u8> {
    if data.len() == 1 && data[0] < 0x80 {
        return data.to_vec();
    }
    let mut out = Vec::new();
    if data.len() < 56 {
        out.push(0x80 + data.len() as u8);
    } else {
        let len_bytes = be_bytes(data.len());
        out.push(0xb7 + len_bytes.len() as u8);
        out.extend_from_slice(&len_bytes);
    }
    out.extend_from_slice(data);
    out
}

/// Encode a list from already-encoded items (test helper).
#[cfg(test)]
pub(crate) fn encode_list(items: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    if items.len() < 56 {
        out.push(0xc0 + items.len() as u8);
    } else {
        let len_bytes = be_bytes(items.len());
        out.push(0xf7 + len_bytes.len() as u8);
        out.extend_from_slice(&len_bytes);
    }
    out.extend_from_slice(items);
    out
}

/// Big-endian minimal bytes of a `u128` (test helper).
#[cfg(test)]
pub(crate) fn u256_be(value: u128) -> Vec<u8> {
    if value == 0 {
        return vec![];
    }
    let bytes = value.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    bytes[start..].to_vec()
}

#[cfg(test)]
fn be_bytes(val: usize) -> Vec<u8> {
    if val == 0 {
        return vec![0];
    }
    let bytes = val.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len() - 1);
    bytes[start..].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_tx_field_positions() {
        let to = [0xab_u8; 20];
        let mut items = Vec::new();
        items.extend_from_slice(&encode_item(&[0x01])); // nonce
        items.extend_from_slice(&encode_item(&[0x04])); // gasPrice
        items.extend_from_slice(&encode_item(&[0x52, 0x08])); // gas
        items.extend_from_slice(&encode_item(&to));
        items.extend_from_slice(&encode_item(&u256_be(1_000_000))); // value
        items.extend_from_slice(&encode_item(&[0xde, 0xad])); // data
        items.extend_from_slice(&encode_item(&[0x1b]));
        items.extend_from_slice(&encode_item(&[0xaa; 32]));
        items.extend_from_slice(&encode_item(&[0xbb; 32]));
        let tx = encode_list(&items);

        let fields = decode_tx_fields(&tx).expect("decode");
        assert_eq!(fields.to, Some(to));
        assert_eq!(fields.value, 1_000_000);
        assert_eq!(fields.data, vec![0xde, 0xad]);
    }

    #[test]
    fn legacy_contract_creation_to_is_none() {
        let mut items = Vec::new();
        items.extend_from_slice(&encode_item(&[0x01]));
        items.extend_from_slice(&encode_item(&[0x04]));
        items.extend_from_slice(&encode_item(&[0x52, 0x08]));
        items.extend_from_slice(&encode_item(&[])); // to = empty → creation
        items.extend_from_slice(&encode_item(&u256_be(0)));
        items.extend_from_slice(&encode_item(&[0x60, 0x00])); // initcode
        items.extend_from_slice(&encode_item(&[0x1b]));
        items.extend_from_slice(&encode_item(&[0xaa; 32]));
        items.extend_from_slice(&encode_item(&[0xbb; 32]));
        let tx = encode_list(&items);

        let fields = decode_tx_fields(&tx).expect("decode");
        assert!(fields.to.is_none());
        assert_eq!(fields.value, 0);
        assert_eq!(fields.data, vec![0x60, 0x00]);
    }

    #[test]
    fn typed_eip1559_tx_field_positions() {
        let to = [0xcd_u8; 20];
        let mut items = Vec::new();
        items.extend_from_slice(&encode_item(&[0x01])); // chainId
        items.extend_from_slice(&encode_item(&[0x01])); // nonce
        items.extend_from_slice(&encode_item(&[0x04])); // maxPriorityFee
        items.extend_from_slice(&encode_item(&[0x04])); // maxFee
        items.extend_from_slice(&encode_item(&[0x52, 0x08])); // gas
        items.extend_from_slice(&encode_item(&to));
        items.extend_from_slice(&encode_item(&u256_be(42)));
        items.extend_from_slice(&encode_item(&[0xde, 0xad, 0xbe, 0xef]));
        items.extend_from_slice(&encode_item(&[0xc0])); // access list (empty)
        items.extend_from_slice(&encode_item(&[0x01])); // yParity
        items.extend_from_slice(&encode_item(&[0xaa; 32]));
        items.extend_from_slice(&encode_item(&[0xbb; 32]));
        let mut tx = vec![0x02];
        tx.extend_from_slice(&encode_list(&items));

        let fields = decode_tx_fields(&tx).expect("decode");
        assert_eq!(fields.to, Some(to));
        assert_eq!(fields.value, 42);
        assert_eq!(fields.data, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn rejects_unknown_envelope() {
        let err = decode_tx_fields(&[0x7f, 0x00]).unwrap_err();
        assert!(err.contains("unsupported transaction envelope"));
    }

    #[test]
    fn rejects_truncated_payload() {
        // 0xc0 claims an empty payload — no items follow.
        let err = decode_tx_fields(&[0xc0, 0x01]).unwrap_err();
        assert!(err.contains("expected at least 9"));
    }

    #[test]
    fn value_beyond_u128_saturates() {
        let bytes = vec![0xff; 17];
        assert_eq!(be_u128(&bytes), u128::MAX);
    }
}
