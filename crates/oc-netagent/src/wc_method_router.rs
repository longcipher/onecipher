//! JSON-RPC method → KeyAgentRequest translation.
//!
//! Implements `WalletMethodHandler` so the `WcWalletServer` can dispatch
//! inbound WC requests. Each JSON-RPC method is mapped to a `KeyAgentRequest`
//! variant, forwarded to the Key-Agent via UDS, and the response is translated
//! back to a JSON value (or a JSON-RPC error code).

use oc_keyagent::{
    KeyAgentRequest, KeyAgentRequestKind, KeyAgentResponse, KeyAgentResponseKind,
    proto::{
        GenerateChallengeRequest, GetBalanceRequest, ListWalletsResponse, PasskeyAuthorization,
        PayX402Request, SignMessageRequest, SignTransactionRequest, SignTypedDataRequest,
        SignUserOpRequest,
    },
};
use oc_walletconnect::{
    WalletMethodHandler, jsonrpc::JsonRpcErrorCode, wallet_server::HandlerResult,
};
use prost::Message;
use serde_json::{Value, json};

use crate::key_agent_client::KeyAgentClient;

pub struct WcMethodRouter {
    key_agent: KeyAgentClient,
}

impl WcMethodRouter {
    pub fn new(key_agent: KeyAgentClient) -> Self {
        Self { key_agent }
    }

    /// P0-2: Extract a [`PasskeyAuthorization`] from the WC JSON params `auth`
    /// sub-object.
    ///
    /// The `auth` object must contain:
    /// - `challenge_hex`: hex-encoded 32-byte challenge (from `GenerateChallenge`)
    /// - `signature_hex`: hex-encoded Passkey signature over `challenge || credential_id`
    /// - `credential_id`: Passkey credential ID string
    ///
    /// Returns `Ok(None)` when no `auth` field is present (callers decide
    /// whether to treat that as an error — signing RPCs require it, while
    /// read-only RPCs do not).
    fn extract_passkey_auth(
        params: &Value,
    ) -> Result<Option<PasskeyAuthorization>, (JsonRpcErrorCode, String)> {
        let auth_obj = match params.get("auth") {
            Some(v) if !v.is_null() => v,
            _ => return Ok(None),
        };
        let challenge_hex = auth_obj
            .get("challenge_hex")
            .and_then(Value::as_str)
            .ok_or_else(|| (JsonRpcErrorCode::Unauthorized, "missing auth.challenge_hex".into()))?;
        let signature_hex = auth_obj
            .get("signature_hex")
            .and_then(Value::as_str)
            .ok_or_else(|| (JsonRpcErrorCode::Unauthorized, "missing auth.signature_hex".into()))?;
        let credential_id = auth_obj
            .get("credential_id")
            .and_then(Value::as_str)
            .ok_or_else(|| (JsonRpcErrorCode::Unauthorized, "missing auth.credential_id".into()))?;
        let challenge = hex::decode(challenge_hex).map_err(|e| {
            (JsonRpcErrorCode::Unauthorized, format!("invalid auth.challenge_hex: {e}"))
        })?;
        let signature = hex::decode(signature_hex).map_err(|e| {
            (JsonRpcErrorCode::Unauthorized, format!("invalid auth.signature_hex: {e}"))
        })?;
        Ok(Some(PasskeyAuthorization {
            challenge,
            signature,
            credential_id: credential_id.to_string(),
        }))
    }

    async fn forward(
        &self,
        kind: KeyAgentRequestKind,
    ) -> Result<Vec<u8>, (JsonRpcErrorCode, String)> {
        let req = KeyAgentRequest { kind: Some(kind) };
        let resp: KeyAgentResponse = self
            .key_agent
            .send(&req)
            .await
            .map_err(|e| (JsonRpcErrorCode::Internal, format!("key-agent wire: {e}")))?;
        match resp.kind {
            Some(KeyAgentResponseKind::Ok(b)) => Ok(b),
            Some(KeyAgentResponseKind::Deny(d)) => {
                let code = match oc_keyagent::proto::DenyReason::try_from(d.reason)
                    .unwrap_or(oc_keyagent::proto::DenyReason::Unknown)
                {
                    oc_keyagent::proto::DenyReason::RateLimitMinute => {
                        JsonRpcErrorCode::PolicyRateLimit
                    }
                    oc_keyagent::proto::DenyReason::RateLimitHour => {
                        JsonRpcErrorCode::PolicyRateLimit
                    }
                    oc_keyagent::proto::DenyReason::BudgetExceeded => {
                        JsonRpcErrorCode::PolicyBudgetExceeded
                    }
                    oc_keyagent::proto::DenyReason::Whitelist => JsonRpcErrorCode::PolicyWhitelist,
                    oc_keyagent::proto::DenyReason::Expired => JsonRpcErrorCode::PolicyExpired,
                    oc_keyagent::proto::DenyReason::PasskeyForged => JsonRpcErrorCode::Unauthorized,
                    oc_keyagent::proto::DenyReason::PolicyMissing => {
                        JsonRpcErrorCode::PolicyMissing
                    }
                    oc_keyagent::proto::DenyReason::Cooldown => JsonRpcErrorCode::PolicyCooldown,
                    oc_keyagent::proto::DenyReason::Unknown => JsonRpcErrorCode::Internal,
                };
                Err((code, "policy denied".into()))
            }
            Some(KeyAgentResponseKind::Error(msg)) => Err((JsonRpcErrorCode::Signer, msg)),
            None => Err((JsonRpcErrorCode::Internal, "empty key-agent response".into())),
        }
    }
}

impl WalletMethodHandler for WcMethodRouter {
    fn handle<'a>(
        &'a self,
        method: &str,
        params: Value,
        _session_topic: &str,
    ) -> HandlerResult<'a> {
        let method = method.to_string();
        Box::pin(async move {
            match method.as_str() {
                "onecipher_listWallets" => {
                    let bytes = self
                        .forward(KeyAgentRequestKind::ListWallets(oc_keyagent::proto::Empty {}))
                        .await?;
                    let resp: ListWalletsResponse = Message::decode(bytes.as_slice())
                        .map_err(|e| (JsonRpcErrorCode::Internal, format!("decode: {e}")))?;
                    let wallets: Vec<Value> = resp.wallets.iter().map(|w| {
                    let accounts: Vec<Value> = w.accounts.iter().map(|a| {
                        json!({"account_id": a.account_id, "address": a.address, "chain_id": a.chain_id, "derivation_path": a.derivation_path})
                    }).collect();
                    json!({"id": w.id, "name": w.name, "key_type": w.key_type, "created_at": w.created_at, "accounts": accounts})
                }).collect();
                    Ok(json!({"wallets": wallets}))
                }

                "eth_sendTransaction" |
                "eth_signTransaction" |
                "solana_signTransaction" |
                "cosmos_signDirect" |
                "cosmos_signAmino" |
                "onecipher_signTransaction" => {
                    // P0-2: Passkey gate — signing RPCs require auth.
                    let auth = Self::extract_passkey_auth(&params)?.ok_or_else(|| {
                        (JsonRpcErrorCode::Unauthorized, "missing passkey authorization".into())
                    })?;
                    let wallet_id = params
                        .get("wallet_id")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            (JsonRpcErrorCode::UnsupportedMethod, "missing wallet_id".into())
                        })?
                        .to_string();
                    let chain_id = params
                        .get("chain_id")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            (JsonRpcErrorCode::UnsupportedMethod, "missing chain_id".into())
                        })?
                        .to_string();
                    let raw_tx_hex = params
                        .get("raw_tx_hex")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            (JsonRpcErrorCode::UnsupportedMethod, "missing raw_tx_hex".into())
                        })?
                        .to_string();
                    let session_key_id = params
                        .get("session_key_id")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    let req = SignTransactionRequest {
                        session_key_id,
                        wallet_id,
                        chain_id,
                        raw_tx_hex,
                        auth: Some(auth),
                    };
                    let bytes = self.forward(KeyAgentRequestKind::SignTransaction(req)).await?;
                    let resp: oc_keyagent::proto::SignTransactionResponse =
                        Message::decode(bytes.as_slice())
                            .map_err(|e| (JsonRpcErrorCode::Internal, format!("decode: {e}")))?;
                    Ok(json!({"signature": resp.signature, "signed_tx_hex": resp.signed_tx_hex}))
                }

                "personal_sign" | "eth_sign" | "solana_signMessage" | "onecipher_signMessage" => {
                    // P0-2: Passkey gate — signing RPCs require auth.
                    let auth = Self::extract_passkey_auth(&params)?.ok_or_else(|| {
                        (JsonRpcErrorCode::Unauthorized, "missing passkey authorization".into())
                    })?;
                    let wallet_id = params
                        .get("wallet_id")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            (JsonRpcErrorCode::UnsupportedMethod, "missing wallet_id".into())
                        })?
                        .to_string();
                    let message = params
                        .get("message")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            (JsonRpcErrorCode::UnsupportedMethod, "missing message".into())
                        })?
                        .as_bytes()
                        .to_vec();
                    let session_key_id = params
                        .get("session_key_id")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    let req =
                        SignMessageRequest { session_key_id, wallet_id, message, auth: Some(auth) };
                    let bytes = self.forward(KeyAgentRequestKind::SignMessage(req)).await?;
                    let resp: oc_keyagent::proto::SignMessageResponse =
                        Message::decode(bytes.as_slice())
                            .map_err(|e| (JsonRpcErrorCode::Internal, format!("decode: {e}")))?;
                    Ok(json!({"signature": resp.signature}))
                }

                "eth_signTypedData_v4" | "onecipher_signTypedData" => {
                    // P0-2: Passkey gate — signing RPCs require auth.
                    let auth = Self::extract_passkey_auth(&params)?.ok_or_else(|| {
                        (JsonRpcErrorCode::Unauthorized, "missing passkey authorization".into())
                    })?;
                    let wallet_id = params
                        .get("wallet_id")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            (JsonRpcErrorCode::UnsupportedMethod, "missing wallet_id".into())
                        })?
                        .to_string();
                    let typed_data_json = params
                        .get("typed_data_json")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            (JsonRpcErrorCode::UnsupportedMethod, "missing typed_data_json".into())
                        })?
                        .to_string();
                    let session_key_id = params
                        .get("session_key_id")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    let req = SignTypedDataRequest {
                        session_key_id,
                        wallet_id,
                        typed_data_json,
                        auth: Some(auth),
                    };
                    let bytes = self.forward(KeyAgentRequestKind::SignTypedData(req)).await?;
                    let resp: oc_keyagent::proto::SignTypedDataResponse =
                        Message::decode(bytes.as_slice())
                            .map_err(|e| (JsonRpcErrorCode::Internal, format!("decode: {e}")))?;
                    Ok(json!({"signature": resp.signature}))
                }

                "onecipher_signUserOp" => {
                    // P0-2: Passkey gate — signing RPCs require auth.
                    let auth = Self::extract_passkey_auth(&params)?.ok_or_else(|| {
                        (JsonRpcErrorCode::Unauthorized, "missing passkey authorization".into())
                    })?;
                    let wallet_id = params
                        .get("wallet_id")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            (JsonRpcErrorCode::UnsupportedMethod, "missing wallet_id".into())
                        })?
                        .to_string();
                    let chain_id = params
                        .get("chain_id")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            (JsonRpcErrorCode::UnsupportedMethod, "missing chain_id".into())
                        })?
                        .to_string();
                    let user_op_hex = params
                        .get("user_op_hex")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            (JsonRpcErrorCode::UnsupportedMethod, "missing user_op_hex".into())
                        })?
                        .to_string();
                    let session_key_id = params
                        .get("session_key_id")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    let req = SignUserOpRequest {
                        session_key_id,
                        wallet_id,
                        chain_id,
                        user_op_hex,
                        auth: Some(auth),
                    };
                    let bytes = self.forward(KeyAgentRequestKind::SignUserOp(req)).await?;
                    let resp: oc_keyagent::proto::SignUserOpResponse =
                        Message::decode(bytes.as_slice())
                            .map_err(|e| (JsonRpcErrorCode::Internal, format!("decode: {e}")))?;
                    Ok(
                        json!({"signature": resp.signature, "signed_user_op_hex": resp.signed_user_op_hex}),
                    )
                }

                // P0-2: Challenge issuance RPC. Clients MUST call this before any
                // Passkey-gated signing RPC to obtain a fresh 32-byte nonce that the
                // Key-Agent stores in its pending_challenges set.
                "onecipher_generateChallenge" => {
                    let credential_id = params
                        .get("credential_id")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            (JsonRpcErrorCode::UnsupportedMethod, "missing credential_id".into())
                        })?
                        .to_string();
                    let req = GenerateChallengeRequest { credential_id };
                    let bytes = self.forward(KeyAgentRequestKind::GenerateChallenge(req)).await?;
                    let resp: oc_keyagent::proto::GenerateChallengeResponse =
                        Message::decode(bytes.as_slice())
                            .map_err(|e| (JsonRpcErrorCode::Internal, format!("decode: {e}")))?;
                    Ok(json!({"challenge_hex": hex::encode(&resp.challenge)}))
                }

                "onecipher_getBalance" => {
                    let wallet_id = params
                        .get("wallet_id")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            (JsonRpcErrorCode::UnsupportedMethod, "missing wallet_id".into())
                        })?
                        .to_string();
                    let chain_id = params
                        .get("chain_id")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            (JsonRpcErrorCode::UnsupportedMethod, "missing chain_id".into())
                        })?
                        .to_string();
                    let req = GetBalanceRequest { wallet_id, chain_id };
                    let bytes = self.forward(KeyAgentRequestKind::GetBalance(req)).await?;
                    let resp: oc_keyagent::proto::BalanceResponse =
                        Message::decode(bytes.as_slice())
                            .map_err(|e| (JsonRpcErrorCode::Internal, format!("decode: {e}")))?;
                    Ok(
                        json!({"wallet_id": resp.wallet_id, "chain_id": resp.chain_id, "balance": resp.balance, "decimals": resp.decimals, "symbol": resp.symbol}),
                    )
                }

                "onecipher_payX402" => {
                    let session_key_id = params
                        .get("session_key_id")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            (JsonRpcErrorCode::UnsupportedMethod, "missing session_key_id".into())
                        })?
                        .to_string();
                    let url = params
                        .get("url")
                        .and_then(Value::as_str)
                        .ok_or_else(|| (JsonRpcErrorCode::UnsupportedMethod, "missing url".into()))?
                        .to_string();
                    let method =
                        params.get("method").and_then(Value::as_str).unwrap_or("GET").to_string();
                    let body = params
                        .get("body")
                        .and_then(Value::as_str)
                        .map(|b| b.as_bytes().to_vec())
                        .unwrap_or_default();
                    let headers = params
                        .get("headers")
                        .and_then(|v| serde_json::from_value(v.clone()).ok())
                        .unwrap_or_default();
                    let req = PayX402Request {
                        session_key_id,
                        url,
                        method,
                        body,
                        headers,
                        ..Default::default()
                    };
                    let bytes = self.forward(KeyAgentRequestKind::PayX402(req)).await?;
                    let resp: oc_keyagent::proto::PayX402Response =
                        Message::decode(bytes.as_slice())
                            .map_err(|e| (JsonRpcErrorCode::Internal, format!("decode: {e}")))?;
                    Ok(
                        json!({"status": resp.status, "receipt": resp.receipt, "retry_authorization": resp.retry_authorization, "deny_reason": resp.deny_reason, "error": resp.error}),
                    )
                }

                _ => {
                    Err((JsonRpcErrorCode::UnsupportedMethod, format!("unknown method: {method}")))
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn extract_passkey_auth_returns_none_when_no_auth() {
        let params = json!({"wallet_id": "w1"});
        let result = WcMethodRouter::extract_passkey_auth(&params).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn extract_passkey_auth_returns_none_when_auth_is_null() {
        let params = json!({"wallet_id": "w1", "auth": null});
        let result = WcMethodRouter::extract_passkey_auth(&params).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn extract_passkey_auth_parses_valid_auth() {
        let params = json!({
            "auth": {
                "challenge_hex": "aabb",
                "signature_hex": "ccdd",
                "credential_id": "cred-1"
            }
        });
        let result = WcMethodRouter::extract_passkey_auth(&params).unwrap().unwrap();
        assert_eq!(result.challenge, vec![0xaa, 0xbb]);
        assert_eq!(result.signature, vec![0xcc, 0xdd]);
        assert_eq!(result.credential_id, "cred-1");
    }

    #[test]
    fn extract_passkey_auth_rejects_missing_challenge_hex() {
        let params = json!({
            "auth": {
                "signature_hex": "ccdd",
                "credential_id": "cred-1"
            }
        });
        let err = WcMethodRouter::extract_passkey_auth(&params).unwrap_err();
        assert_eq!(err.0, JsonRpcErrorCode::Unauthorized);
        assert!(err.1.contains("challenge_hex"));
    }

    #[test]
    fn extract_passkey_auth_rejects_missing_signature_hex() {
        let params = json!({
            "auth": {
                "challenge_hex": "aabb",
                "credential_id": "cred-1"
            }
        });
        let err = WcMethodRouter::extract_passkey_auth(&params).unwrap_err();
        assert_eq!(err.0, JsonRpcErrorCode::Unauthorized);
        assert!(err.1.contains("signature_hex"));
    }

    #[test]
    fn extract_passkey_auth_rejects_missing_credential_id() {
        let params = json!({
            "auth": {
                "challenge_hex": "aabb",
                "signature_hex": "ccdd"
            }
        });
        let err = WcMethodRouter::extract_passkey_auth(&params).unwrap_err();
        assert_eq!(err.0, JsonRpcErrorCode::Unauthorized);
        assert!(err.1.contains("credential_id"));
    }

    #[test]
    fn extract_passkey_auth_rejects_invalid_hex_challenge() {
        let params = json!({
            "auth": {
                "challenge_hex": "zzzz",
                "signature_hex": "ccdd",
                "credential_id": "cred-1"
            }
        });
        let err = WcMethodRouter::extract_passkey_auth(&params).unwrap_err();
        assert_eq!(err.0, JsonRpcErrorCode::Unauthorized);
        assert!(err.1.contains("challenge_hex"));
    }

    #[test]
    fn extract_passkey_auth_rejects_invalid_hex_signature() {
        let params = json!({
            "auth": {
                "challenge_hex": "aabb",
                "signature_hex": "not-hex",
                "credential_id": "cred-1"
            }
        });
        let err = WcMethodRouter::extract_passkey_auth(&params).unwrap_err();
        assert_eq!(err.0, JsonRpcErrorCode::Unauthorized);
        assert!(err.1.contains("signature_hex"));
    }

    #[test]
    fn extract_passkey_auth_rejects_non_string_challenge() {
        let params = json!({
            "auth": {
                "challenge_hex": 123,
                "signature_hex": "ccdd",
                "credential_id": "cred-1"
            }
        });
        let err = WcMethodRouter::extract_passkey_auth(&params).unwrap_err();
        assert_eq!(err.0, JsonRpcErrorCode::Unauthorized);
    }

    #[test]
    fn extract_passkey_auth_empty_challenge_hex_is_valid() {
        let params = json!({
            "auth": {
                "challenge_hex": "",
                "signature_hex": "ccdd",
                "credential_id": "cred-1"
            }
        });
        let result = WcMethodRouter::extract_passkey_auth(&params).unwrap().unwrap();
        assert!(result.challenge.is_empty());
    }
}
