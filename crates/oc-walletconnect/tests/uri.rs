use oc_walletconnect::uri::PairingUri;

#[test]
fn parses_valid_uri() {
    let s = "wc:abc123def@2?relay-protocol=waku&symKey=0xdeadbeef";
    let uri = PairingUri::parse(s).unwrap();
    assert_eq!(uri.topic, "abc123def");
    assert_eq!(uri.version, 2);
    assert_eq!(uri.relay_protocol, Some("waku".into()));
    assert_eq!(uri.sym_key, Some("0xdeadbeef".into()));
}

#[test]
fn serializes_roundtrip() {
    let s = "wc:abc123def@2?relay-protocol=waku&symKey=0xdeadbeef";
    let uri = PairingUri::parse(s).unwrap();
    let out = uri.to_string();
    assert_eq!(out, s);
}

#[test]
fn rejects_missing_wc_scheme() {
    assert!(PairingUri::parse("http://abc@2").is_err());
}

#[test]
fn rejects_missing_version() {
    assert!(PairingUri::parse("wc:abc").is_err());
}
