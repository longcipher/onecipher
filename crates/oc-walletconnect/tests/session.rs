use std::time::{SystemTime, UNIX_EPOCH};

use oc_walletconnect::session::{WcSession, WcSessionState, WcSessionTable};

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

#[test]
fn session_lifecycle_transitions() {
    let mut s = WcSession::new_pairing("topic-1".into(), "0xsym".into(), now() + 86400);
    assert_eq!(s.state, WcSessionState::Propose);

    s.settle(
        "topic-settled".into(),
        vec!["eip155:8453".into()],
        vec!["eth_sendTransaction".into(), "personal_sign".into()],
    );
    assert_eq!(s.state, WcSessionState::Active);

    s.expire();
    assert_eq!(s.state, WcSessionState::Expired);
}

#[test]
fn table_insert_and_lookup() {
    let mut t = WcSessionTable::new();
    let s = WcSession::new_pairing("t1".into(), "0xsym".into(), now() + 3600);
    t.insert(s);
    assert!(t.get("t1").is_some());
    assert!(t.get("missing").is_none());
}

#[test]
fn table_remove_drops_session() {
    let mut t = WcSessionTable::new();
    let s = WcSession::new_pairing("t1".into(), "0xsym".into(), now() + 3600);
    t.insert(s);
    assert!(t.remove("t1").is_some());
    assert!(t.get("t1").is_none());
}

#[test]
fn session_method_authorization() {
    let mut s = WcSession::new_pairing("t1".into(), "0xsym".into(), now() + 3600);
    s.settle(
        "t1".into(),
        vec!["eip155:8453".into()],
        vec!["eth_sendTransaction".into(), "personal_sign".into()],
    );
    assert!(s.is_method_allowed("eth_sendTransaction"));
    assert!(!s.is_method_allowed("eth_signTypedData_v4"));
}
