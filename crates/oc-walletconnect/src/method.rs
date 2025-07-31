//! WalletConnect v2 standard JSON-RPC method names and session protocol structs.

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const SESSION_PROPOSE: &str = "wc_sessionPropose";
pub const SESSION_SETTLE: &str = "wc_sessionSettle";
pub const SESSION_REQUEST: &str = "wc_sessionRequest";
pub const SESSION_DELETE: &str = "wc_sessionDelete";
pub const SESSION_PING: &str = "wc_sessionPing";
pub const SESSION_UPDATE: &str = "wc_sessionUpdate";
pub const SESSION_EVENT: &str = "wc_sessionEvent";

pub const PERSONAL_SIGN: &str = "personal_sign";
pub const ETH_SIGN: &str = "eth_sign";
pub const ETH_SIGN_TYPED_DATA: &str = "eth_signTypedData";
pub const ETH_SIGN_TYPED_DATA_V4: &str = "eth_signTypedData_v4";
pub const ETH_SEND_TRANSACTION: &str = "eth_sendTransaction";
pub const ETH_SIGN_TRANSACTION: &str = "eth_signTransaction";
pub const ETH_REQUEST_ACCOUNTS: &str = "eth_requestAccounts";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposerMetadata {
    pub name: String,
    pub description: String,
    pub url: String,
    #[serde(default)]
    pub icons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct SessionProposeParams {
    pub relays: Vec<RelayProtocolOptions>,
    #[serde(rename = "requiredNamespaces")]
    pub required_namespaces: Value,
    #[serde(rename = "optionalNamespaces", skip_serializing_if = "Option::is_none")]
    pub optional_namespaces: Option<Value>,
    pub proposer: Proposer,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct Proposer {
    pub publicKey: String,
    pub metadata: ProposerMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayProtocolOptions {
    pub protocol: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct SessionSettleParams {
    pub relay: RelayProtocolOptions,
    pub controller: SessionParticipant,
    pub namespaces: Value,
    pub expiry: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct SessionParticipant {
    pub publicKey: String,
    pub metadata: ProposerMetadata,
}
