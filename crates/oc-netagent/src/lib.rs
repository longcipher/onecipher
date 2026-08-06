//! Network-Agent library crate.
//!
//! v0.4: The ConnectRPC-over-UDS server has been abolished. The sole external
//! interface is now WalletConnect v2 (WSS relay). This crate hosts:
//! - The WC v2 Wallet Role server (via `oc-walletconnect`)
//! - The JSON-RPC method router that translates inbound WC requests into `KeyAgentRequest` UDS
//!   frames forwarded to the Key-Agent.
//! - Pairing URI generation + Passkey confirmation gate.
//! - WC session state persistence.

#![forbid(unsafe_code)]

pub mod approval;
pub mod error;
pub mod http_rpc;
pub mod intent;
pub mod key_agent_client;
pub mod otlp;
pub mod rpc_client;
pub mod sim;
pub mod telemetry_drain;
pub mod wc_method_router;
pub mod wc_pairing;
pub mod wc_session_store;

pub use approval::{
    ApprovalChannel, ApprovalDecision, DecodedAction, PendingApproval, RiskLevel, RiskReason,
    RiskSource, TokenDelta, TokenDirection, TxSimulation,
};
pub use error::NetAgentError;
pub use http_rpc::{LocalRpcServer, LocalRpcServerConfig};
pub use intent::{
    CallData, Intent, IntentError, IntentKind, IntentResult, IntentStatus, IntentSummary,
    MessageEncoding, MockRpcClient, RpcClient, RpcError, execute_intent, simulate_intent,
};
pub use key_agent_client::KeyAgentClient;
// The approval log (JSONL WAL for crash recovery) lives in `oc-core` so the
// Web UI can persist approvals without depending on this network crate.
pub use oc_core::approval_log::ApprovalLog;
pub use otlp::{OtlpSink, OtlpSinkConfig};
pub use rpc_client::HpxRpcClient;
pub use sim::{SimError, simulate_evm_tx};
pub use telemetry_drain::{
    DEFAULT_BATCH_SIZE as TELEMETRY_BATCH_SIZE, DEFAULT_DRAIN_INTERVAL, DrainStats, MemorySink,
    StdoutSink, TelemetrySink, drain_once, drain_until_empty, run_drain_loop,
};
pub use wc_method_router::WcMethodRouter;
pub use wc_pairing::{PairingError, generate_pairing_uri};
pub use wc_session_store::{SessionStore, SessionStoreError};

/// Default pairing TTL: 24 hours (in seconds).
pub const DEFAULT_PAIRING_TTL: u64 = 86_400;

/// Run the WC v2 wallet-role server. Blocks until shutdown.
///
/// `key_agent_sock` is the UDS path to the Key-Agent.
/// `relay_url` is the WC v2 relay WSS URL (default `wss://relay.walletconnect.com`).
pub async fn run_server(
    key_agent_sock: &str,
    relay_url: &str,
    state_dir: &str,
) -> Result<(), NetAgentError> {
    let key_agent = KeyAgentClient::new(key_agent_sock);
    let router = WcMethodRouter::new(key_agent);
    let store = SessionStore::open(state_dir)?;

    let cfg = oc_walletconnect::WcWalletConfig {
        relay_url: relay_url.to_string(),
        relay_protocol: "waku".into(),
        trusted_origins: vec![],
    };

    let mut server = oc_walletconnect::WcWalletServer::new(cfg, router);

    // Restore persisted sessions
    for session in store.load()? {
        server.insert_session(session).await;
    }

    tracing::info!(relay_url, "starting WC v2 wallet server");
    server.run().await.map_err(NetAgentError::Wc)?;
    Ok(())
}

/// Run the WC v2 wallet server with a control channel for dynamic pairing
/// injection.
///
/// Unlike [`run_server`], this function:
/// 1. Constructs the server and obtains a [`WcServerHandle`].
/// 2. Spawns `server.run()` in a background tokio task.
/// 3. Processes incoming pairing URIs from `pairing_rx` — each URI is converted to a
///    `Propose`-state session, inserted into the server's session table, and persisted to the
///    session store.
///
/// Returns when `pairing_rx` is closed or the server task exits.
///
/// # Arguments
///
/// - `key_agent_sock` — UDS path to the Key-Agent.
/// - `relay_url` — WC v2 relay WSS URL.
/// - `state_dir` — Directory for `wc_sessions.json` persistence.
/// - `pairing_rx` — Channel receiver for pairing URIs to inject at runtime.
pub async fn run_server_controlled(
    key_agent_sock: &str,
    relay_url: &str,
    state_dir: &str,
    pairing_rx: tokio::sync::mpsc::Receiver<oc_walletconnect::PairingUri>,
) -> Result<(), NetAgentError> {
    run_server_controlled_with_approvals(
        key_agent_sock,
        relay_url,
        state_dir,
        pairing_rx,
        None,
        None,
    )
    .await
}

/// Run the WC v2 wallet server with a control channel for dynamic pairing
/// injection, plus an optional Web UI approval channel and persistent log.
///
/// This is the full-featured entry point used by the daemon. When `approvals`
/// is `Some`, signing requests are gated by the Web UI approval flow; the
/// `approval_log` (if provided) persists pending/resolved approvals for
/// daemon-restart recovery. The plain [`run_server_controlled`] is a thin
/// wrapper passing `None` for both.
pub async fn run_server_controlled_with_approvals(
    key_agent_sock: &str,
    relay_url: &str,
    state_dir: &str,
    mut pairing_rx: tokio::sync::mpsc::Receiver<oc_walletconnect::PairingUri>,
    approvals: Option<
        tokio::sync::mpsc::Sender<(
            oc_core::approval::PendingApproval,
            tokio::sync::oneshot::Sender<oc_core::approval::ApprovalDecision>,
        )>,
    >,
    approval_log: Option<std::sync::Arc<oc_core::approval_log::ApprovalLog>>,
) -> Result<(), NetAgentError> {
    let key_agent = KeyAgentClient::new(key_agent_sock);
    let router = match approvals {
        Some(tx) => {
            let (channel, mut rx) = ApprovalChannel::new(64);
            // Bridge the router's approval channel into the daemon's mpsc
            // sender that feeds the Web UI queue.
            tokio::spawn(async move {
                while let Some((approval, resp_tx)) = rx.recv().await {
                    if tx.send((approval, resp_tx)).await.is_err() {
                        break;
                    }
                }
            });
            WcMethodRouter::with_approval(
                key_agent,
                channel,
                std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
                std::time::Duration::from_secs(300),
                approval_log,
            )
        }
        None => WcMethodRouter::new(key_agent),
    };
    let store = SessionStore::open(state_dir)?;

    let cfg = oc_walletconnect::WcWalletConfig {
        relay_url: relay_url.to_string(),
        relay_protocol: "waku".into(),
        trusted_origins: vec![],
    };

    let mut server = oc_walletconnect::WcWalletServer::new(cfg, router);
    let handle = server.session_handle();

    // Restore persisted sessions before starting the run loop.
    for session in store.load()? {
        server.insert_session(session).await;
    }

    tracing::info!(relay_url, "starting WC v2 wallet server (controlled)");

    // Spawn the server run loop in a background task.
    let server_task = tokio::spawn(async move { server.run().await });

    // Process pairing injection requests from the control channel.
    while let Some(uri) = pairing_rx.recv().await {
        tracing::info!(topic = %uri.topic, "injecting pairing URI");

        let session = match handle.add_pairing(&uri, DEFAULT_PAIRING_TTL).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "failed to add pairing");
                continue;
            }
        };

        // Persist: load, replace-or-append, save (full-replace semantics).
        let mut all = match store.load() {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "failed to load sessions for persist");
                continue;
            }
        };
        if let Some(existing) = all.iter_mut().find(|s| s.topic == session.topic) {
            *existing = session.clone();
        } else {
            all.push(session);
        }
        if let Err(e) = store.save(&all) {
            tracing::warn!(error = %e, "failed to persist sessions");
        }
    }

    // pairing_rx closed — abort the server task.
    server_task.abort();
    tracing::info!("WC v2 server controlled loop ended");
    Ok(())
}
