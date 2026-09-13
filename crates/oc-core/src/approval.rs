//! Approval types shared between the Network-Agent and the Web UI.
//!
//! These types are intentionally in `oc-core` (zero network deps) so that
//! `oc-webui` can reference them without pulling in `hpx`/`boring`/`tokio`.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Risk classification
// ---------------------------------------------------------------------------

/// Risk level assigned to a pending approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    /// Policy allows; no warnings.
    Safe,
    /// Policy warns; user must acknowledge before signing.
    Warning,
    /// Simulation revert or multiple warnings; 5s countdown before sign.
    Danger,
    /// Policy denies outright; sign button hidden.
    Forbidden,
}

/// Source of a risk reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskSource {
    Policy,
    Simulation,
    Heuristic,
}

/// A single risk reason attached to a pending approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskReason {
    /// Machine-readable code (e.g. "policy_warn_large_approval", "sim_revert").
    pub code: String,
    /// The risk level this reason contributes.
    pub level: RiskLevel,
    /// Human-readable description.
    pub message: String,
    /// Where this risk was identified.
    pub source: RiskSource,
    /// Optional structured detail.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Transaction simulation
// ---------------------------------------------------------------------------

/// Direction of a token balance change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenDirection {
    Send,
    Receive,
}

/// A single token balance change from simulation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenDelta {
    pub token: String,
    pub direction: TokenDirection,
    /// Human-readable amount string.
    pub amount: String,
}

/// Decoded action from ABI decoding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecodedAction {
    pub contract_name: String,
    pub function_name: String,
    /// JSON-encoded decoded arguments.
    pub args: serde_json::Value,
    /// One-line human-readable description.
    pub human_readable: String,
}

/// Result of EVM transaction simulation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxSimulation {
    pub success: bool,
    pub gas_used: u64,
    pub balance_change: Vec<TokenDelta>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decoded_action: Option<DecodedAction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// ---------------------------------------------------------------------------
// PendingApproval
// ---------------------------------------------------------------------------

/// A signing request awaiting user decision in the Web UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingApproval {
    /// Unique identifier for this approval.
    pub id: Uuid,
    /// JSON-RPC method (e.g. "eth_sendTransaction", "personal_sign").
    pub method: String,
    /// The original request params.
    pub params: serde_json::Value,
    /// dApp name (from WC session metadata).
    pub dapp_name: String,
    /// dApp origin URL.
    pub dapp_origin: String,
    /// Chain identifier (CAIP-2).
    pub chain_id: String,
    /// Overall risk level (max of all risk_reasons).
    pub risk: RiskLevel,
    /// Individual risk reasons.
    pub risk_reasons: Vec<RiskReason>,
    /// Optional simulation result (None if sim failed or non-EVM).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub simulation: Option<TxSimulation>,
    /// Structured CAIP-122 Sign-In summary, when the request carries a
    /// parseable Sign-In message. Lets approval UIs highlight the phishing-
    /// relevant fields (domain, address, URI) instead of raw params.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub siwx_summary: Option<SiwxSummary>,
    /// Unix timestamp when this approval was created.
    pub created_at_unix: u64,
    /// Unix timestamp when this approval expires.
    pub expires_at_unix: u64,
}

/// Structured summary of a CAIP-122 Sign-In message for approval UIs.
///
/// Plain data (no `oc-siwx` dependency — `oc-core` stays the dependency-free
/// base); populated by the Net-Agent when the request `message` param parses
/// as CAIP-122.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiwxSummary {
    /// Authority requesting the signing (phishing-critical — highlight it).
    pub domain: String,
    /// Blockchain address performing the signing.
    pub address: String,
    /// URI that is the subject of the signing.
    pub uri: String,
    /// Preamble chain label (`"Ethereum"`, `"Solana"`), if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_name: Option<String>,
    /// Anti-replay nonce.
    pub nonce: String,
    /// Original lexical form of `issued-at`.
    pub issued_at: String,
    /// Original lexical form of `expiration-time`, if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiration_time: Option<String>,
    /// Resource URIs referenced by the message.
    #[serde(default)]
    pub resources: Vec<String>,
}

// ---------------------------------------------------------------------------
// ApprovalDecision
// ---------------------------------------------------------------------------

/// Decision made by the user in the Web UI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ApprovalDecision {
    Approve,
    Reject { reason: String },
    Timeout,
}
