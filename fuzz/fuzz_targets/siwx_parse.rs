#![no_main]

//! Fuzz CAIP-122 signing-string parsing (`oc_siwx::SiwxMessage::from_str`).
//! Sign-In messages arrive from dApps over WalletConnect — untrusted input.
//! The parser must never panic; any byte string is either a valid message or
//! a typed `SiwxError`.

use libfuzzer_sys::fuzz_target;
use oc_siwx::SiwxMessage;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let _ = s.parse::<SiwxMessage>();
});
