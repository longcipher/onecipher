//! Fuzz target for `PayX402Request::decode` — simulates untrusted input at the
//! UDS (Unix Domain Socket) boundary between the UI process and the
//! Network-Agent.
//!
//! ## cargo-fuzz vs proptest
//!
//! The T8 spec requires `cargo fuzz run payx402_decode -- -max_total_time=60`.
//! `cargo-fuzz` requires nightly Rust + the `cargo-fuzz` binary. A proper
//! `fuzz/` directory is provided alongside this file for `cargo +nightly fuzz`.
//!
//! This proptest-based target is the **stable-Rust fallback** that achieves the
//! same intent: `PayX402Request::decode` must never panic on arbitrary bytes.
//! It runs as part of `cargo test -p oc-proto` on stable toolchains.

#![deny(unsafe_code)]

use oc_proto::{PayX402Request, PayX402Response};
use proptest::prelude::*;
use prost::Message;

proptest! {
    /// `PayX402Request::decode` must never panic on arbitrary bytes.
    /// It may return `Err`, but must not crash (UDS boundary — untrusted input).
    #[test]
    fn fuzz_payx402_request_decode_no_crash(
        bytes in proptest::collection::vec(any::<u8>(), 0..4096)
    ) {
        let _ = PayX402Request::decode(&bytes[..]);
    }

    /// `PayX402Response::decode` must never panic on arbitrary bytes either
    /// (response parsing on the UI-process side is also an untrusted boundary
    /// once a malicious or buggy Network-Agent is in play).
    #[test]
    fn fuzz_payx402_response_decode_no_crash(
        bytes in proptest::collection::vec(any::<u8>(), 0..4096)
    ) {
        let _ = PayX402Response::decode(&bytes[..]);
    }

    /// Round-trip property: any `PayX402Request` that we encode must decode
    /// back to an equal value. This catches encode/decode asymmetry.
    #[test]
    fn payx402_request_encode_decode_roundtrip(
        session_key_id in "[a-z0-9-]{0,32}",
        url in "https?://[a-z0-9./-]{0,64}",
        method in prop_oneof![Just("GET"), Just("POST"), Just("PUT"), Just("DELETE")],
        body in proptest::collection::vec(any::<u8>(), 0..256),
        header_keys in proptest::collection::vec("[A-Za-z-]{0,16}", 0..8),
        header_vals in proptest::collection::vec("[A-Za-z0-9._-]{0,32}", 0..8),
    ) {
        let mut headers = std::collections::HashMap::new();
        for (k, v) in header_keys.into_iter().zip(header_vals.into_iter()) {
            headers.insert(k, v);
        }
        let original = PayX402Request {
            session_key_id,
            url,
            method: method.to_string(),
            body,
            headers,
            // Stage 0 additions: default values for new payment requirement fields
            amount_usd: 0.0,
            asset: String::new(),
            chain_id: String::new(),
            recipient: String::new(),
        };
        let buf = original.encode_to_vec();
        let decoded = PayX402Request::decode(buf.as_slice())
            .expect("decode of encode_to_vec output must succeed");
        prop_assert_eq!(original, decoded);
    }
}
