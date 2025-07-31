//! WalletConnect v2 pairing URI parser/serializer.
//!
//! Format: `wc:<topic>@<version>?relay-protocol=<p>&symKey=<hex>`

use std::fmt;

use crate::error::{WcError, WcResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingUri {
    pub topic: String,
    pub version: u32,
    pub relay_protocol: Option<String>,
    pub relay_data: Option<String>,
    pub sym_key: Option<String>,
    pub methods: Vec<String>,
}

impl PairingUri {
    pub fn parse(s: &str) -> WcResult<Self> {
        let rest = s
            .strip_prefix("wc:")
            .ok_or_else(|| WcError::InvalidUri("missing 'wc:' scheme".into()))?;

        let (topic_version, query) = match rest.split_once('?') {
            Some((a, b)) => (a, Some(b)),
            None => (rest, None),
        };

        let (topic, version) = topic_version
            .split_once('@')
            .ok_or_else(|| WcError::InvalidUri("missing '@version'".into()))?;
        let version: u32 =
            version.parse().map_err(|_| WcError::InvalidUri("version not a number".into()))?;

        let mut relay_protocol = None;
        let mut relay_data = None;
        let mut sym_key = None;
        let mut methods = Vec::new();
        if let Some(q) = query {
            for pair in q.split('&') {
                let (k, v) = pair
                    .split_once('=')
                    .ok_or_else(|| WcError::InvalidUri(format!("bad query pair: {pair}")))?;
                match k {
                    "relay-protocol" => relay_protocol = Some(v.to_string()),
                    "relay-data" => relay_data = Some(v.to_string()),
                    "symKey" => sym_key = Some(v.to_string()),
                    "methods" => methods = v.split(',').map(String::from).collect(),
                    _ => {} // forward-compat: ignore unknown keys
                }
            }
        }

        Ok(Self { topic: topic.to_string(), version, relay_protocol, relay_data, sym_key, methods })
    }

    pub fn new(topic: impl Into<String>, sym_key: impl Into<String>) -> Self {
        Self {
            topic: topic.into(),
            version: 2,
            relay_protocol: Some("waku".into()),
            relay_data: None,
            sym_key: Some(sym_key.into()),
            methods: Vec::new(),
        }
    }
}

impl fmt::Display for PairingUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "wc:{}@{}", self.topic, self.version)?;
        let mut first = true;
        let mut emit = |k: &str, v: &str, first: &mut bool| -> fmt::Result {
            if *first {
                write!(f, "?")?;
                *first = false;
            } else {
                write!(f, "&")?;
            }
            write!(f, "{k}={v}")
        };
        if let Some(p) = &self.relay_protocol {
            emit("relay-protocol", p, &mut first)?;
        }
        if let Some(d) = &self.relay_data {
            emit("relay-data", d, &mut first)?;
        }
        if let Some(k) = &self.sym_key {
            emit("symKey", k, &mut first)?;
        }
        if !self.methods.is_empty() {
            emit("methods", &self.methods.join(","), &mut first)?;
        }
        Ok(())
    }
}
