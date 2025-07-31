use oc_walletconnect::relay::{RelayClient, RelayConfig};

#[tokio::test]
async fn relay_config_defaults() {
    let cfg = RelayConfig::default();
    assert_eq!(cfg.url, "wss://relay.walletconnect.com");
    assert_eq!(cfg.reconnect_max_ms, 60_000);
}

#[tokio::test]
async fn connect_rejects_invalid_url() {
    let cfg = RelayConfig { url: "not-a-url".into(), reconnect_max_ms: 1000 };
    let result = RelayClient::connect(cfg).await;
    assert!(result.is_err());
}
