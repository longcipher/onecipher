//! Path- and generation-bound plaintext envelope (`ocenv/1`, B1).
//!
//! Before age encryption, the JSON payload is wrapped as:
//!
//! ```text
//! ocenv/1\n
//! tag:secret\n
//! path:<name>\n
//! generation:<u64>\n
//! \n
//! <payload JSON bytes>
//! ```
//!
//! `tag:secret` domain-separates secret envelopes from any future `ocenv/1`
//! use. `path` binds the ciphertext to its lookup name so swapped files fail
//! closed; `generation` binds it to the monotonic index generation (B4) so a
//! replayed old ciphertext after delete + re-insert is detected. Assembly
//! uses [`Zeroizing`] buffers so the header does not linger in freed memory.
//!
//! Unwrap never panics on attacker-controlled bytes: every malformed input
//! maps to [`EnvelopeError::Tampered`] with a fine-grained `reason`.

use zeroize::Zeroizing;

/// Envelope magic (`onecipher envelope v1`).
pub const ENVELOPE_MAGIC: &str = "ocenv/1";
/// Fixed domain-separation tag for secret payloads.
pub const ENVELOPE_TAG: &str = "secret";
/// Separator between the header block and the payload.
const HEADER_END: &[u8] = b"\n\n";

/// Errors returned by envelope wrap / unwrap.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EnvelopeError {
    /// The envelope is malformed or bound to a different path.
    #[error("tampered envelope for '{path}': {reason}")]
    Tampered { path: String, reason: String },
    /// The caller-supplied path cannot be embedded (newline/NUL).
    #[error("invalid path: {0}")]
    InvalidPath(String),
}

/// Wrap `payload_json` with the `ocenv/1` header for `path` at `generation`.
///
/// The returned buffer is [`Zeroizing`] (wiped on drop).
pub fn wrap_envelope(
    path: &str,
    generation: u64,
    payload_json: &[u8],
) -> Result<Zeroizing<Vec<u8>>, EnvelopeError> {
    if path.is_empty() || path.contains(['\n', '\r', '\0']) {
        return Err(EnvelopeError::InvalidPath("path must not contain newline or NUL".into()));
    }
    // Header is built inside a Zeroizing guard so the assembled bytes are
    // wiped when the guard is dropped after the copy below.
    let header = Zeroizing::new(format!(
        "{ENVELOPE_MAGIC}\ntag:{ENVELOPE_TAG}\npath:{path}\ngeneration:{generation}\n\n"
    ));
    let mut out = Zeroizing::new(Vec::with_capacity(header.len() + payload_json.len()));
    out.extend_from_slice(header.as_bytes());
    out.extend_from_slice(payload_json);
    Ok(out)
}

/// Unwrap an envelope, verifying the magic, tag and path binding.
///
/// Returns `(generation, payload_json)`. `expected_path` is echoed in
/// [`EnvelopeError::Tampered::path`] so callers can attribute the failure.
/// Never panics: all indexing is bounds-checked and header parsing tolerates
/// non-UTF8 and truncated inputs.
pub fn unwrap_envelope(
    expected_path: &str,
    data: &[u8],
) -> Result<(u64, Zeroizing<Vec<u8>>), EnvelopeError> {
    let tampered = |reason: &str| EnvelopeError::Tampered {
        path: expected_path.to_string(),
        reason: reason.to_string(),
    };
    // Locate the blank-line separator without ever slicing out of bounds.
    let mut sep_at: Option<usize> = None;
    let mut i = 0usize;
    while i.saturating_add(1) < data.len() {
        if data[i] == b'\n' && data[i + 1] == b'\n' {
            sep_at = Some(i);
            break;
        }
        i = i.saturating_add(1);
    }
    let Some(sep) = sep_at else {
        return Err(tampered("missing header/payload separator"));
    };
    let (header_bytes, rest) = data.split_at(sep);
    // `rest` starts with the two separator newlines; skip them safely.
    let payload = rest.get(HEADER_END.len()..).ok_or_else(|| tampered("missing payload"))?;
    let header = std::str::from_utf8(header_bytes).map_err(|_| tampered("header is not UTF-8"))?;
    let mut lines = header.split('\n');
    let magic = lines.next().ok_or_else(|| tampered("missing magic"))?;
    if magic != ENVELOPE_MAGIC {
        return Err(tampered("bad magic"));
    }
    let tag_line = lines.next().ok_or_else(|| tampered("missing tag"))?;
    if tag_line != format!("tag:{ENVELOPE_TAG}") {
        return Err(tampered("bad tag"));
    }
    let path_line = lines.next().ok_or_else(|| tampered("missing path"))?;
    let bound_path = path_line.strip_prefix("path:").ok_or_else(|| tampered("bad path line"))?;
    if bound_path != expected_path {
        return Err(tampered("path mismatch"));
    }
    let gen_line = lines.next().ok_or_else(|| tampered("missing generation"))?;
    let gen_text =
        gen_line.strip_prefix("generation:").ok_or_else(|| tampered("bad generation line"))?;
    if gen_text.is_empty() || !gen_text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(tampered("bad generation"));
    }
    if lines.next().is_some() {
        return Err(tampered("extra header line"));
    }
    // Reject absurd generations early (still parsed as u64 below).
    let generation: u64 = gen_text.parse().map_err(|_| tampered("bad generation"))?;
    let mut payload_buf = Zeroizing::new(Vec::with_capacity(payload.len()));
    payload_buf.extend_from_slice(payload);
    Ok((generation, payload_buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_preserves_payload_and_gen() {
        let payload = br#"{"secret":"hunter2"}"#;
        let wrapped = wrap_envelope("github/personal", 7, payload).unwrap();
        assert!(wrapped.starts_with(b"ocenv/1\n"));
        let (generation, out) = unwrap_envelope("github/personal", &wrapped).unwrap();
        assert_eq!(generation, 7);
        assert_eq!(&out[..], &payload[..]);
    }

    #[test]
    fn path_mismatch_reports_tampered_with_path() {
        let wrapped = wrap_envelope("alpha", 1, b"{}").unwrap();
        let err = unwrap_envelope("beta", &wrapped).unwrap_err();
        assert_eq!(
            err,
            EnvelopeError::Tampered { path: "beta".into(), reason: "path mismatch".into() }
        );
    }

    #[test]
    fn malformed_inputs_are_tampered_not_panic() {
        for data in [
            vec![],
            b"".to_vec(),
            b"garbage".to_vec(),
            b"ocenv/1\n".to_vec(),
            b"ocenv/1\ntag:secret\npath:a\ngen:1\n".to_vec(),
            b"badmagic\ntag:secret\npath:a\ngen:1\n\n{}".to_vec(),
            b"ocenv/1\ntag:wrong\npath:a\ngen:1\n\n{}".to_vec(),
            b"ocenv/1\ntag:secret\npath:a\ngen:abc\n\n{}".to_vec(),
            b"ocenv/1\ntag:secret\npath:a\ngen:\n\n{}".to_vec(),
            b"ocenv/1\ntag:secret\npath:a\ngen:1\nextra:x\n\n{}".to_vec(),
            vec![0xff, 0xfe, 0x0a, 0x0a],
        ] {
            let _ = unwrap_envelope("a", &data).unwrap_err();
        }
    }

    #[test]
    fn wrap_rejects_newline_path() {
        assert!(wrap_envelope("a\nb", 1, b"{}").is_err());
        assert!(wrap_envelope("", 1, b"{}").is_err());
    }

    /// Soak (E2): 2000 random envelopes round-trip; 200 near-miss mutations
    /// never panic (each returns Ok with matching path or a Tampered error).
    #[test]
    fn soak_random_and_near_miss_never_panics() {
        // Deterministic xorshift64 (no extra dev-deps, reproducible soak).
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..2000 {
            let name_len = 1 + (next() % 24) as usize;
            let mut name = String::with_capacity(name_len);
            for _ in 0..name_len {
                let c = (b'a' + (next() % 26) as u8) as char;
                name.push(c);
            }
            let generation = next();
            let payload_len = (next() % 64) as usize;
            let mut payload = Vec::with_capacity(payload_len);
            for _ in 0..payload_len {
                payload.push((next() % 256) as u8);
            }
            let wrapped = wrap_envelope(&name, generation, &payload).unwrap();
            let (out_gen, out_payload) = unwrap_envelope(&name, &wrapped).unwrap();
            assert_eq!(out_gen, generation);
            assert_eq!(&out_payload[..], &payload[..]);
        }
        // Near-miss: valid envelope with 1-2 bytes flipped; must not panic.
        let base = wrap_envelope("soak/path", 42, b"{\"secret\":\"x\"}").unwrap();
        for n in 0..200 {
            let mut mutated = base.to_vec();
            let flips = 1 + (n % 2);
            for f in 0..flips {
                let idx = (n * 31 + f * 17) % mutated.len();
                mutated[idx] ^= 0x01 << ((n + f) % 8);
            }
            let _ = unwrap_envelope("soak/path", &mutated);
            let _ = unwrap_envelope("other", &mutated);
        }
    }
}
