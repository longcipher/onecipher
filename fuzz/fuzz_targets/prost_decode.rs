#![no_main]

//! Fuzz the prost wire types directly: `KeyAgentRequest` and
//! `KeyAgentResponse` decode. These bytes come from the UDS IPC boundary
//! (mirrored over the WC relay and the local HTTP-RPC surface), so malformed
//! frames must never panic the Key-Agent or Network-Agent.

use libfuzzer_sys::fuzz_target;
use oc_keyagent::{KeyAgentRequest, KeyAgentResponse};
use prost::Message;

fuzz_target!(|data: &[u8]| {
    let _ = KeyAgentRequest::decode(data);
    let _ = KeyAgentResponse::decode(data);
});
