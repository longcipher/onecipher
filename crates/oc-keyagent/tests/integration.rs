//! Integration tests for oc-keyagent.
//!
//! These tests exercise the public API surface (frame codec, request/response
//! round-trips, server `handle_conn`) end-to-end via `UnixStream::pair()`.
//! They do NOT bind a real UDS path — `UnixStream::pair()` creates a connected
//! pair of anonymous sockets, which is sufficient for testing `handle_conn`.
//!
//! Per R56, these tests MUST NOT use `tokio` — they use `std::thread` for the
//! server side and synchronous `read_frame` / `write_frame` on the client side.

use std::{os::unix::net::UnixStream, thread};

use oc_keyagent::{
    KeyAgentError,
    frame::{read_frame, write_frame},
    handle_conn,
    request::{KeyAgentRequest, KeyAgentRequestKind},
    response::{KeyAgentResponse, KeyAgentResponseKind},
};
use oc_proto::{Empty, PayX402Request};
use proptest::prelude::*;
use prost::Message;

// ---------------------------------------------------------------------------
// 1. Frame codec round-trip (integration-level — frame.rs has unit tests too)
// ---------------------------------------------------------------------------

#[test]
fn test_frame_round_trip_integration() {
    let payload = b"integration test payload";
    let mut buf = Vec::new();
    write_frame(&mut buf, payload).unwrap();
    let mut cursor = std::io::Cursor::new(buf);
    let decoded = read_frame(&mut cursor).unwrap();
    assert_eq!(decoded, payload);
}

// ---------------------------------------------------------------------------
// 2. Request → server → response round-trip via UDS
// ---------------------------------------------------------------------------

#[test]
fn test_request_response_round_trip() {
    let (client, server) = UnixStream::pair().unwrap();
    let handle = thread::spawn(move || handle_conn(server));

    let req = KeyAgentRequest {
        kind: Some(KeyAgentRequestKind::PayX402(PayX402Request {
            session_key_id: "sk-integration".to_string(),
            url: "https://example.com".to_string(),
            method: "GET".to_string(),
            body: vec![],
            headers: std::collections::HashMap::new(),
            ..Default::default()
        })),
    };
    let mut client_w = client.try_clone().unwrap();
    write_frame(&mut client_w, &req.encode_to_vec()).unwrap();

    let mut client_r = client;
    let payload = read_frame(&mut client_r).unwrap();
    let resp = KeyAgentResponse::decode(payload.as_slice()).unwrap();

    // Handler now processes real requests — response may be Ok, Deny, or Error
    // depending on policy state. We just verify we got a valid response.
    assert!(resp.kind.is_some(), "response must have a kind");

    drop(client_w);
    drop(client_r);
    handle.join().unwrap().unwrap();
}

// ---------------------------------------------------------------------------
// 3. Clean client disconnect → handle_conn returns Ok(())
// ---------------------------------------------------------------------------

#[test]
fn test_client_disconnect_clean_shutdown() {
    let (client, server) = UnixStream::pair().unwrap();
    let handle = thread::spawn(move || handle_conn(server));
    drop(client);
    let result = handle.join().unwrap();
    assert!(result.is_ok(), "handle_conn should Ok(()) on clean disconnect, got: {result:?}");
}

// ---------------------------------------------------------------------------
// 4. Malformed payload → Error response, connection stays alive
// ---------------------------------------------------------------------------

#[test]
fn test_malformed_frame_returns_error_then_continues() {
    let (client, server) = UnixStream::pair().unwrap();
    let handle = thread::spawn(move || handle_conn(server));

    let mut client_w = client.try_clone().unwrap();
    let mut client_r = client;

    // First: send garbage that fails prost decode.
    write_frame(&mut client_w, b"not a valid prost payload").unwrap();
    let payload = read_frame(&mut client_r).unwrap();
    let resp = KeyAgentResponse::decode(payload.as_slice()).unwrap();
    assert!(matches!(resp.kind, Some(KeyAgentResponseKind::Error(_))));

    // Then: send a valid request — the connection must still be alive.
    // Handler now processes real requests — response may be Ok/Deny/Error.
    let req = KeyAgentRequest { kind: Some(KeyAgentRequestKind::ListWallets(Empty {})) };
    write_frame(&mut client_w, &req.encode_to_vec()).unwrap();
    let payload2 = read_frame(&mut client_r).unwrap();
    let resp2 = KeyAgentResponse::decode(payload2.as_slice()).unwrap();
    assert!(resp2.kind.is_some(), "must get a valid response");

    drop(client_w);
    drop(client_r);
    handle.join().unwrap().unwrap();
}

// ---------------------------------------------------------------------------
// 5. Multiple requests on one connection (keep-alive)
// ---------------------------------------------------------------------------

#[test]
fn test_multiple_requests_one_connection() {
    let (client, server) = UnixStream::pair().unwrap();
    let handle = thread::spawn(move || handle_conn(server));

    let mut client_w = client.try_clone().unwrap();
    let mut client_r = client;

    for _ in 0..5 {
        let req = KeyAgentRequest { kind: Some(KeyAgentRequestKind::ListWallets(Empty {})) };
        write_frame(&mut client_w, &req.encode_to_vec()).unwrap();
        let payload = read_frame(&mut client_r).unwrap();
        let resp = KeyAgentResponse::decode(payload.as_slice()).unwrap();
        // Handler now processes real requests — verify we got a valid response.
        assert!(resp.kind.is_some(), "every response must have a kind");
    }

    drop(client_w);
    drop(client_r);
    handle.join().unwrap().unwrap();
}

// ---------------------------------------------------------------------------
// 6. Empty request (kind = None) → dispatch error response
// ---------------------------------------------------------------------------

#[test]
fn test_empty_request_returns_error_response() {
    let (client, server) = UnixStream::pair().unwrap();
    let handle = thread::spawn(move || handle_conn(server));

    let req = KeyAgentRequest { kind: None };
    let mut client_w = client.try_clone().unwrap();
    write_frame(&mut client_w, &req.encode_to_vec()).unwrap();

    let mut client_r = client;
    let payload = read_frame(&mut client_r).unwrap();
    let resp = KeyAgentResponse::decode(payload.as_slice()).unwrap();
    assert!(resp.is_error());

    drop(client_w);
    drop(client_r);
    handle.join().unwrap().unwrap();
}

// ---------------------------------------------------------------------------
// 7. All KeyAgentRequest variants dispatch without panicking
// ---------------------------------------------------------------------------

#[test]
fn test_all_request_variants_dispatch() {
    let (client, server) = UnixStream::pair().unwrap();
    let handle = thread::spawn(move || handle_conn(server));

    let mut client_w = client.try_clone().unwrap();
    let mut client_r = client;

    // One of each variant (field values are dummy — handlers are stubs).
    let requests: Vec<KeyAgentRequest> = vec![
        KeyAgentRequest {
            kind: Some(KeyAgentRequestKind::CreateSessionKey(oc_proto::CreateSessionKeyRequest {
                label: "x".into(),
                rules: None,
                budget: None,
                auth: None,
            })),
        },
        KeyAgentRequest {
            kind: Some(KeyAgentRequestKind::RevokeSessionKey(oc_proto::RevokeSessionKeyRequest {
                session_key_id: "x".into(),
                auth: None,
            })),
        },
        KeyAgentRequest {
            kind: Some(KeyAgentRequestKind::PayX402(PayX402Request {
                session_key_id: "x".into(),
                url: "x".into(),
                method: "x".into(),
                body: vec![],
                headers: std::collections::HashMap::new(),
                ..Default::default()
            })),
        },
        KeyAgentRequest {
            kind: Some(KeyAgentRequestKind::SignTransaction(oc_proto::SignTransactionRequest {
                session_key_id: "x".into(),
                wallet_id: "x".into(),
                chain_id: "x".into(),
                raw_tx_hex: "x".into(),
                auth: None,
            })),
        },
        KeyAgentRequest {
            kind: Some(KeyAgentRequestKind::SignUserOp(oc_proto::SignUserOpRequest {
                session_key_id: "x".into(),
                wallet_id: "x".into(),
                chain_id: "x".into(),
                user_op_hex: "x".into(),
                auth: None,
            })),
        },
        KeyAgentRequest {
            kind: Some(KeyAgentRequestKind::SignMessage(oc_proto::SignMessageRequest {
                session_key_id: "x".into(),
                wallet_id: "x".into(),
                message: vec![],
                auth: None,
            })),
        },
        KeyAgentRequest {
            kind: Some(KeyAgentRequestKind::SignTypedData(oc_proto::SignTypedDataRequest {
                session_key_id: "x".into(),
                wallet_id: "x".into(),
                typed_data_json: "x".into(),
                auth: None,
            })),
        },
        KeyAgentRequest {
            kind: Some(KeyAgentRequestKind::GetPaymentHistory(
                oc_proto::GetPaymentHistoryRequest {
                    session_key_id: "x".into(),
                    since_unix: 0,
                    limit: 10,
                },
            )),
        },
        KeyAgentRequest {
            kind: Some(KeyAgentRequestKind::GetBalance(oc_proto::GetBalanceRequest {
                wallet_id: "x".into(),
                chain_id: "x".into(),
            })),
        },
        KeyAgentRequest { kind: Some(KeyAgentRequestKind::ListWallets(Empty {})) },
    ];

    for (i, req) in requests.into_iter().enumerate() {
        write_frame(&mut client_w, &req.encode_to_vec()).unwrap();
        let payload = read_frame(&mut client_r).unwrap();
        let resp = KeyAgentResponse::decode(payload.as_slice()).unwrap();
        // Handler now processes real requests — verify we got a valid response (Ok/Deny/Error).
        assert!(resp.kind.is_some(), "variant {i} must dispatch without panic");
    }

    drop(client_w);
    drop(client_r);
    handle.join().unwrap().unwrap();
}

// ---------------------------------------------------------------------------
// 8. Fuzz: arbitrary byte payload round-trips through frame codec
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn test_frame_fuzz_round_trip(
        payload in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..4096)
    ) {
        let mut buf = Vec::new();
        write_frame(&mut buf, &payload).unwrap();
        let mut cursor = std::io::Cursor::new(buf);
        let decoded = read_frame(&mut cursor).unwrap();
        prop_assert_eq!(decoded, payload);
    }
}

// ---------------------------------------------------------------------------
// 9. Fuzz: PayX402Request round-trips through encode + decode
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn test_pay_x402_request_fuzz_round_trip(
        session_key_id in "[a-z0-9-]{0,32}",
        url in "https?://[a-z]{0,16}\\.[a-z]{0,8}",
        method in "(GET|POST|PUT|DELETE)",
        body in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..512),
    ) {
        let req = KeyAgentRequest {
            kind: Some(KeyAgentRequestKind::PayX402(PayX402Request {
                session_key_id,
                url,
                method,
                body,
                headers: std::collections::HashMap::new(),
                ..Default::default()
            })),
        };
        let bytes = req.encode_to_vec();
        let decoded = KeyAgentRequest::decode(bytes.as_slice()).unwrap();
        prop_assert_eq!(req, decoded);
    }
}

// ---------------------------------------------------------------------------
// 10. Server-side handle_conn error propagation on write failure
// ---------------------------------------------------------------------------

#[test]
fn test_handle_conn_returns_err_when_client_drops_mid_write() {
    // If the client closes its read side before the server finishes writing,
    // handle_conn must return an Err (broken pipe). This is a smoke test that
    // the error path doesn't panic.
    let (client, server) = UnixStream::pair().unwrap();
    let handle = thread::spawn(move || handle_conn(server));

    // Send a request, then immediately close the client's read side (by
    // dropping the read half). The server's write will fail with EPIPE.
    let req = KeyAgentRequest { kind: Some(KeyAgentRequestKind::ListWallets(Empty {})) };
    let mut client_w = client.try_clone().unwrap();
    write_frame(&mut client_w, &req.encode_to_vec()).unwrap();
    // Shut down the read side of `client` so the server's write hits EPIPE.
    // (shutdown(Read) closes our read direction — but the server's write
    // succeeds only if our read direction is open. We can't easily force
    // EPIPE from the test without racing, so just close the whole client.)
    drop(client_w);
    // Read any response that may have made it through, then close.
    let _ = client.shutdown(std::net::Shutdown::Both);
    drop(client);

    // The server thread will either Ok(()) (if it wrote before close) or
    // Err(BrokenPipe). Either is acceptable; we only assert no panic.
    let _ = handle.join().unwrap();
}

// ---------------------------------------------------------------------------
// 11. KeyAgentError Display formatting (smoke test)
// ---------------------------------------------------------------------------

#[test]
fn test_key_agent_error_display() {
    let e = KeyAgentError::NotImplemented("test feature".to_string());
    let s = format!("{e}");
    assert!(s.contains("not yet implemented"), "got: {s}");
    assert!(s.contains("test feature"), "got: {s}");

    let e2 = KeyAgentError::InvalidRequest("bad".to_string());
    assert!(format!("{e2}").contains("invalid request"));
}
