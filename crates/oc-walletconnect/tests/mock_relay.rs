use oc_walletconnect::mock_relay::MockRelay;

#[tokio::test]
async fn publish_reaches_subscribers() {
    let relay = MockRelay::new();
    let mut sub_a = relay.subscribe("topic-a").await;
    let mut sub_b = relay.subscribe("topic-a").await;

    relay.publish("topic-a", b"hello").await;

    let msg_a = sub_a.recv().await.unwrap();
    let msg_b = sub_b.recv().await.unwrap();
    assert_eq!(msg_a, b"hello");
    assert_eq!(msg_b, b"hello");
}

#[tokio::test]
async fn subscribers_on_different_topics_isolated() {
    let relay = MockRelay::new();
    let mut sub_a = relay.subscribe("topic-a").await;
    let mut sub_b = relay.subscribe("topic-b").await;

    relay.publish("topic-a", b"foo").await;

    assert_eq!(sub_a.recv().await.unwrap(), b"foo");
    assert!(sub_b.try_recv().is_err());
}
