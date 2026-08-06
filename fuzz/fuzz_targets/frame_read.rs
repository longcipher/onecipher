#![no_main]

//! Fuzz the Key-Agent UDS frame decoder: `oc_keyagent::frame::read_frame`
//! followed by prost decoding of the resulting `KeyAgentRequest`. A malformed
//! peer (WC relay, HTTP-RPC client) can send arbitrary bytes over the socket;
//! this target ensures neither the frame codec nor the decoder panics.

use libfuzzer_sys::fuzz_target;
use oc_keyagent::frame::read_frame;
use oc_keyagent::KeyAgentRequest;
use prost::Message;

fuzz_target!(|data: &[u8]| {
    let mut cursor = std::io::Cursor::new(data);
    // read_frame enforces its own 4 MiB cap internally; if it yields a
    // payload, feed it to the prost decoder (the true panic surface).
    if let Ok(payload) = read_frame(&mut cursor) {
        if !payload.is_empty() {
            let _ = KeyAgentRequest::decode(payload.as_slice());
        }
    }
});
