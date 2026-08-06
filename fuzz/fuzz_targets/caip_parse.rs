#![no_main]

//! Fuzz CAIP-2 chain ID parsing (`oc_core::ChainId::from_str`). Chain IDs are
//! received from WalletConnect v2 session proposals and x402 payment
//! requirements — both untrusted inputs.

use std::str::FromStr;

use libfuzzer_sys::fuzz_target;
use oc_core::ChainId;

fuzz_target!(|data: &[u8]| {
    // Raw bytes as lossy UTF-8: CAIP-2 ids are ASCII but a malformed peer
    // sends arbitrary bytes.
    let s = String::from_utf8_lossy(data);
    let _ = ChainId::from_str(&s);
});
