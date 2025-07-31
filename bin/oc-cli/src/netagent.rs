//! ConnectRPC client abstraction for the Network-Agent.
//!
//! In Phase 1, the actual ConnectRPC transport (tonic/connect-rs) is deferred
//! to Phase D (T17-T21). The trait abstraction lets tests inject a mock client
//! to verify RPC construction without a real Net-Agent.
//!
//! Per ponytail YAGNI, tonic/connect-rs are NOT added as dev-deps yet — the
//! mock is hand-written and doesn't need them.

use std::os::unix::net::UnixStream;

use oc_keyagent::{
    frame::FrameClient,
    request::{KeyAgentRequest, KeyAgentRequestKind},
    response::{KeyAgentResponse, KeyAgentResponseKind},
};
use oc_proto::{
    CreateSessionKeyRequest, CreateSessionKeyResponse, ListSessionKeysResponse, PayX402Request,
    PayX402Response, RevokeSessionKeyRequest, RevokeSessionKeyResponse,
};
use prost::Message;

use crate::CliError;

/// Abstracts the Network-Agent ConnectRPC client.
///
/// Each method maps 1:1 to an `AgentService` RPC from `proto/agent.proto`.
/// Phase D (T17-T21) will provide a real ConnectRPC-backed implementation;
/// until then, `UnimplementedClient` is wired in by `main()` so the CLI's
/// arg-parsing and RPC-construction paths can be exercised end-to-end via
/// the mock in tests.
pub(crate) trait NetAgentClient: Send + Sync {
    /// RPC: `CreateSessionKey(CreateSessionKeyRequest) → CreateSessionKeyResponse`
    fn create_session_key(
        &self,
        req: CreateSessionKeyRequest,
    ) -> Result<CreateSessionKeyResponse, CliError>;

    /// RPC: `RevokeSessionKey(RevokeSessionKeyRequest) → RevokeSessionKeyResponse`
    fn revoke_session_key(
        &self,
        req: RevokeSessionKeyRequest,
    ) -> Result<RevokeSessionKeyResponse, CliError>;

    /// RPC: `ListSessionKeys(Empty) → ListSessionKeysResponse`
    fn list_session_keys(&self) -> Result<ListSessionKeysResponse, CliError>;

    /// RPC: `PayX402(PayX402Request) → PayX402Response`
    fn pay_x402(&self, req: PayX402Request) -> Result<PayX402Response, CliError>;
}

/// Production stub — returns `CliError::NetAgentUnavailable` for all RPCs.
///
/// Phase D (T17-T21) will replace this with a real ConnectRPC client over the
/// UDS between the UI process and the Network-Agent (R15).
pub(crate) struct UnimplementedClient;

impl NetAgentClient for UnimplementedClient {
    fn create_session_key(
        &self,
        _req: CreateSessionKeyRequest,
    ) -> Result<CreateSessionKeyResponse, CliError> {
        Err(CliError::NetAgentUnavailable)
    }

    fn revoke_session_key(
        &self,
        _req: RevokeSessionKeyRequest,
    ) -> Result<RevokeSessionKeyResponse, CliError> {
        Err(CliError::NetAgentUnavailable)
    }

    fn list_session_keys(&self) -> Result<ListSessionKeysResponse, CliError> {
        Err(CliError::NetAgentUnavailable)
    }

    fn pay_x402(&self, _req: PayX402Request) -> Result<PayX402Response, CliError> {
        Err(CliError::NetAgentUnavailable)
    }
}

/// UDS-backed client that talks to the Key-Agent daemon via [`FrameClient`].
///
/// Each RPC opens a fresh UDS connection (one request per connection, matching
/// the Key-Agent server's `handle_conn` loop), sends a [`KeyAgentRequest`]
/// frame, and decodes the [`KeyAgentResponse`].
///
/// Falls back to [`UnimplementedClient`] in `main()` when the daemon is not
/// reachable.
pub(crate) struct UdsKeyAgentClient {
    client: FrameClient,
}

impl UdsKeyAgentClient {
    /// Connect to the Key-Agent at the default socket path.
    ///
    /// Probe-connects to verify the daemon is listening; returns `Err` if the
    /// socket is unreachable so `main()` can fall back to a stub client.
    pub(crate) fn connect_default() -> Result<Self, String> {
        let client = FrameClient::connect_default().map_err(|e| e.to_string())?;
        // Probe-connect to verify the daemon is listening. The connection is
        // immediately dropped — actual RPCs open fresh connections per call.
        UnixStream::connect(client.socket_path()).map_err(|e| {
            format!("cannot reach Key-Agent at {}: {e}", client.socket_path().display())
        })?;
        Ok(Self { client })
    }

    /// Send a request frame and return the raw response.
    fn send(&self, req: &KeyAgentRequest) -> Result<KeyAgentResponse, CliError> {
        self.client
            .send_request(req)
            .map_err(|e| CliError::InvalidArgs(format!("key-agent IPC failed: {e}")))
    }
}

impl NetAgentClient for UdsKeyAgentClient {
    fn create_session_key(
        &self,
        req: CreateSessionKeyRequest,
    ) -> Result<CreateSessionKeyResponse, CliError> {
        let req = KeyAgentRequest { kind: Some(KeyAgentRequestKind::CreateSessionKey(req)) };
        let resp = self.send(&req)?;
        decode_ok(resp)
    }

    fn revoke_session_key(
        &self,
        req: RevokeSessionKeyRequest,
    ) -> Result<RevokeSessionKeyResponse, CliError> {
        let req = KeyAgentRequest { kind: Some(KeyAgentRequestKind::RevokeSessionKey(req)) };
        let resp = self.send(&req)?;
        decode_ok(resp)
    }

    fn list_session_keys(&self) -> Result<ListSessionKeysResponse, CliError> {
        // The Key-Agent has no ListSessionKeys request variant (folded into
        // the ListWallets slot per request.rs deviation note; T18 will wire
        // it). Return an error rather than sending an unmatched request.
        Err(CliError::InvalidArgs(
            "ListSessionKeys not supported by Key-Agent (T18 pending)".to_string(),
        ))
    }

    fn pay_x402(&self, req: PayX402Request) -> Result<PayX402Response, CliError> {
        let req = KeyAgentRequest { kind: Some(KeyAgentRequestKind::PayX402(req)) };
        let resp = self.send(&req)?;
        decode_ok(resp)
    }
}

/// Decode a [`KeyAgentResponse`] expecting the `Ok` variant carrying a
/// prost-encoded payload of type `T`.
fn decode_ok<T: Message + Default>(resp: KeyAgentResponse) -> Result<T, CliError> {
    match resp.kind {
        Some(KeyAgentResponseKind::Ok(bytes)) => T::decode(bytes.as_slice())
            .map_err(|e| CliError::InvalidArgs(format!("response decode failed: {e}"))),
        Some(KeyAgentResponseKind::Deny(payload)) => Err(CliError::InvalidArgs(format!(
            "request denied by policy (reason code: {})",
            payload.reason
        ))),
        Some(KeyAgentResponseKind::Error(msg)) => {
            Err(CliError::InvalidArgs(format!("key-agent error: {msg}")))
        }
        None => Err(CliError::InvalidArgs("empty response from key-agent".to_string())),
    }
}
