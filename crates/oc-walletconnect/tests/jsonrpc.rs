use oc_walletconnect::jsonrpc::{JsonRpcError, JsonRpcErrorCode, JsonRpcRequest, JsonRpcResponse};
use serde_json::json;

#[test]
fn request_serializes_per_spec() {
    let req = JsonRpcRequest::new("eth_sendTransaction", json!({"to":"0xabc"}), 42);
    let s = serde_json::to_string(&req).unwrap();
    assert_eq!(
        s,
        r#"{"jsonrpc":"2.0","method":"eth_sendTransaction","params":{"to":"0xabc"},"id":42}"#
    );
}

#[test]
fn response_roundtrips_success() {
    let resp = JsonRpcResponse::success(42, json!({"signature":"0xdead"}));
    let s = serde_json::to_string(&resp).unwrap();
    let parsed: JsonRpcResponse = serde_json::from_str(&s).unwrap();
    assert_eq!(parsed.id, 42);
    assert_eq!(parsed.result, Some(json!({"signature":"0xdead"})));
    assert!(parsed.error.is_none());
}

#[test]
fn response_roundtrips_error() {
    let err = JsonRpcError::new(JsonRpcErrorCode::UserRejected, "user said no".into());
    let resp = JsonRpcResponse::error(7, err);
    let s = serde_json::to_string(&resp).unwrap();
    assert!(s.contains(r#""code":4001"#));
    assert!(s.contains(r#""message":"user said no""#));
}

#[test]
fn request_with_null_id_parses_notification() {
    // WC v2 requires id; notifications (id=null) are not used. Reject them.
    let bad = r#"{"jsonrpc":"2.0","method":"foo","params":null,"id":null}"#;
    let res: Result<JsonRpcRequest, _> = serde_json::from_str(bad);
    assert!(res.is_err());
}
