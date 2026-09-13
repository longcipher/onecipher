//! Property test: `format ∘ parse` is the identity on valid messages.

#![allow(
    unused_crate_dependencies,
    reason = "integration test crate links lib deps it does not use"
)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use oc_siwx::SiwxMessage;
use proptest::prelude::*;

fn domain_strategy() -> impl Strategy<Value = String> {
    prop::string::string_regex(
        "[a-z0-9]([a-z0-9-]{0,8}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,8}[a-z0-9])?){0,2}",
    )
    .expect("domain regex")
}

fn label_strategy() -> impl Strategy<Value = String> {
    prop::string::string_regex("[A-Za-z0-9][A-Za-z0-9_.~-]{0,12}").expect("label regex")
}

fn uri_strategy() -> impl Strategy<Value = String> {
    (label_strategy(), prop::option::of(label_strategy())).prop_map(|(host, path)| {
        let mut uri = format!("https://{host}.example.com");
        if let Some(p) = path {
            uri.push('/');
            uri.push_str(&p);
        }
        uri
    })
}

fn statement_strategy() -> impl Strategy<Value = String> {
    // Statement charset: reserved / unreserved / SP (no CTL, no non-ASCII).
    prop::string::string_regex("[A-Za-z0-9 .,;:'()!-]+").expect("statement regex")
}

fn timestamp_strategy() -> impl Strategy<Value = String> {
    prop::sample::select(vec![
        "2021-09-30T16:25:24Z",
        "2024-01-01T00:00:00Z",
        "2022-01-27T17:09:38.578Z",
        "2023-06-15T12:30:45+02:00",
        "2099-12-31T23:59:59Z",
    ])
    .prop_map(str::to_owned)
}

fn nonce_strategy() -> impl Strategy<Value = String> {
    prop::string::string_regex("[A-Za-z0-9]{8,24}").expect("nonce regex")
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]
    #[test]
    fn format_parse_roundtrip(
        domain in domain_strategy(),
        address in nonce_strategy(),
        uri in uri_strategy(),
        statement in prop::option::of(statement_strategy()),
        nonce in nonce_strategy(),
        issued_at in timestamp_strategy(),
        expiration in prop::option::of(timestamp_strategy()),
        resources in proptest::collection::vec(uri_strategy(), 0..4),
        chain_name in prop::sample::select(vec!["Ethereum", "Solana"]),
    ) {
        let mut msg = SiwxMessage::new(&domain, &address, &uri, "1", &nonce)
            .expect("generated fields are valid");
        if let Some(s) = statement {
            msg = msg.with_statement(&s).expect("statement");
        }
        msg = msg.with_issued_at_raw(&issued_at).expect("issued_at");
        if let Some(e) = expiration {
            // Expiration must parse; temporal validity is irrelevant here.
            if let Ok(m) = msg.clone().with_expiration_time_raw(&e) {
                msg = m;
            }
        }
        if !resources.is_empty() {
            msg = msg.with_resources(resources.iter()).expect("resources");
        }
        let raw = msg.to_sign_string(chain_name);
        let parsed: SiwxMessage = raw.parse().expect("generated text must parse");
        prop_assert_eq!(parsed.to_sign_string(chain_name), raw);
        prop_assert_eq!(parsed.domain(), msg.domain());
        prop_assert_eq!(parsed.address(), msg.address());
        prop_assert_eq!(parsed.uri(), msg.uri());
        prop_assert_eq!(parsed.nonce(), msg.nonce());
        prop_assert_eq!(parsed.issued_at_raw(), msg.issued_at_raw());
        prop_assert_eq!(parsed.chain_name(), Some(chain_name));
    }
}
