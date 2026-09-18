//! Daemon lifecycle for the unified OneCipher daemon.
//!
//! Extracted verbatim from `main.rs` (structural split, M-14): the daemon
//! owns the Key-Agent UDS server thread, the WC v2 relay task, the optional
//! Web UI / HTTP-RPC / WalletSigner servers, telemetry draining, and the
//! signal-driven graceful shutdown state machine (C-01).
//!
//! Architecture:
//! - **Key-Agent** (sync thread, R55): `oc_keyagent::server::run()` on UDS. Handles signing,
//!   policy, vault access via globals pointing at `~/.onecipher`.
//! - **WC v2 server** (tokio task): `oc_netagent::run_server_controlled()` connects outbound WSS to
//!   the WC relay, subscribes to pairing topics, and dispatches inbound JSON-RPC to the Key-Agent
//!   via UDS.
//! - **Control socket** (tokio task): accepts `CONNECT <uri>` and `PAIR` commands from `onecipher
//!   wc connect/pair` CLI calls. Injects pairing URIs into the WC server via a tokio mpsc channel.

mod control_socket;

use crate::CliError;

/// Maximum time the daemon waits for background servers to stop after a
/// termination signal before exiting anyway (C-01).
const DAEMON_SHUTDOWN_GRACE_SECS: u64 = 15;

/// Install the Key-Agent telemetry subscriber (P1 3.1).
///
/// The verbosity comes from `OC_TELEMETRY_LEVEL` (`trace`/`debug`/`info`/
/// `warn`/`error`, default `info`). Setting it to `off` skips installation
/// entirely, which leaves the ring buffer disabled and makes every
/// `tracing` macro a no-op.
///
/// Failure is non-fatal: a daemon that cannot record spans must still sign.
fn init_telemetry() {
    use oc_keyagent::telemetry::{self, TelemetryLevel};

    let raw = std::env::var("OC_TELEMETRY_LEVEL").unwrap_or_else(|_| "info".to_string());
    let level = match raw.trim().to_ascii_lowercase().as_str() {
        "off" | "none" | "0" => {
            eprintln!("telemetry: disabled (OC_TELEMETRY_LEVEL={raw})");
            return;
        }
        "trace" => TelemetryLevel::Trace,
        "debug" => TelemetryLevel::Debug,
        "warn" | "warning" => TelemetryLevel::Warn,
        "error" => TelemetryLevel::Error,
        // Anything unrecognized falls back to the default rather than
        // aborting startup over a typo'd env var.
        _ => TelemetryLevel::Info,
    };

    if telemetry::init(level) {
        eprintln!("telemetry: buffering at {level} (drain via DrainTelemetry RPC)");
    } else {
        eprintln!("telemetry: a global subscriber is already installed; skipping");
    }
}

/// Run the unified daemon: Key-Agent UDS server + WC v2 wallet server +
/// control socket for CLI pairing injection.
pub(crate) fn run_daemon() -> Result<(), CliError> {
    use std::os::unix::fs::PermissionsExt;

    eprintln!("onecipher daemon starting...");

    // --- Cross-boundary observability (P1 3.1) ---
    // Installed before anything else so startup spans are captured. The
    // Key-Agent cannot export telemetry itself (R56: no tokio/HTTP client;
    // R12: no non-UDS sockets), so it buffers redacted records in a bounded
    // ring that the Network-Agent drains over the control UDS.
    init_telemetry();

    // C-01: daemons must NOT use install_signal_handlers() — it terminates
    // the process directly, bypassing graceful shutdown and racing the async
    // select! loop. Instead: install the panic cleanup hook (covers SIGABRT)
    // and spawn the notifier thread; its signals are integrated into the
    // shutdown select! below so SIGTERM/SIGINT/SIGHUP/SIGQUIT all take the
    // same graceful path.
    oc_signer::process_hardening::install_panic_cleanup_hook();
    let signal_rx = oc_signer::process_hardening::spawn_signal_notifier();

    let engine = oc_keyagent::SigningEngine::open_default()
        .map_err(|e| CliError::DaemonInit(format!("key engine: {e}")))?;
    let state_dir = engine.state_dir().to_path_buf();
    eprintln!("signing engine opened at {}", state_dir.display());

    // --- Key-Agent UDS server (sync, dedicated thread per R55) ---
    let key_agent_sock = oc_keyagent::server::default_socket_path();
    eprintln!("key-agent socket: {}", key_agent_sock);
    let ka_sock_clone = key_agent_sock.clone();
    let sign_auth_internal_token = rand::random::<[u8; 32]>().to_vec();
    if let Err(e) =
        oc_keyagent::handler::set_sign_auth_internal_token(Some(sign_auth_internal_token.clone()))
    {
        // Fail-closed: without the internal capability token SignAuth
        // requests cannot be authorized; refuse to start the daemon.
        return Err(CliError::KeyAgent(format!("install sign-auth internal token: {e}")));
    }

    // Channel: Key-Agent thread → tokio select! loop (lifecycle monitoring).
    // The thread sends a message only on error; if it exits without sending,
    // the receiver's `recv()` returns `Err` → `.ok()` yields `None`.
    let ka_stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let ka_stop_thread = ka_stop.clone();
    let (ka_err_tx, ka_err_rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        // R12d/R53: confine the signing core BEFORE accepting any request.
        // The Linux seccomp filter is per-thread, so this does not restrict
        // the tokio WSS/WebUI layers; on macOS Seatbelt is deliberately
        // skipped by `apply_signing_thread_sandbox` because it is
        // process-wide and would sever the daemon's own relay connection.
        match oc_keyagent::apply_signing_thread_sandbox() {
            Ok(report) => {
                eprintln!(
                    "key-agent sandbox active: network_blocked={} coredump_disabled={} \
                     ptrace_denied={}",
                    report.network_blocked(),
                    report.coredump_disabled,
                    report.ptrace_denied
                );
                #[cfg(target_os = "macos")]
                if !report.network_blocked() {
                    eprintln!(
                        "WARNING: macOS network isolation degraded — signing thread has no Seatbelt filter; ensure R12a source scan and lsof checks in CI"
                    );
                }
            }
            Err(e) => {
                // Fail-closed: an unconfined signing core must not serve.
                let _ = ka_err_tx.send(format!("sandbox: {e}"));
                return;
            }
        }
        if let Err(e) = oc_keyagent::server::run(Some(&ka_sock_clone), Some(ka_stop_thread)) {
            let _ = ka_err_tx.send(format!("{e}"));
        }
    });

    // --- Control socket path ---
    let ctrl_sock_path = crate::commands::wc::control_socket_path();

    // --- Shared tokio runtime for async WC server + control loop ---
    let rt = crate::shared_runtime();

    let relay_url = std::env::var("OC_WC_RELAY_URL")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| {
            let cfg = oc_core::Config::load_or_default();
            if cfg.wc.relay_url.is_empty() { None } else { Some(cfg.wc.relay_url) }
        })
        .unwrap_or_else(|| "wss://relay.walletconnect.com".into());
    let state_dir_str = state_dir.to_string_lossy().to_string();
    let ka_sock_for_telemetry = key_agent_sock.clone();
    let ka_sock_for_webui = key_agent_sock.clone();
    let ka_sock_for_rpc = key_agent_sock.clone();
    let ka_sock_for_wc = key_agent_sock;

    // Channel: control socket → WC server (pairing URI injection)
    let (pairing_tx, pairing_rx) = tokio::sync::mpsc::channel::<oc_walletconnect::PairingUri>(32);

    // Approval channel shared between the WC method router (sender) and the
    // Web UI queue (receiver). Created unconditionally so the daemon can wire
    // it into the router even when the Web UI feature is compiled out.
    let (approval_tx, approval_rx): (
        tokio::sync::mpsc::Sender<(
            oc_core::approval::PendingApproval,
            tokio::sync::oneshot::Sender<oc_core::approval::ApprovalDecision>,
        )>,
        tokio::sync::mpsc::Receiver<(
            oc_core::approval::PendingApproval,
            tokio::sync::oneshot::Sender<oc_core::approval::ApprovalDecision>,
        )>,
    ) = tokio::sync::mpsc::channel(64);

    rt.block_on(async {
        // Shared cancellation flag for the WC server run loop (H3 fix): set on
        // Ctrl-C so the WC server stops gracefully instead of being dropped.
        let wc_cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

        // Bind control socket (tokio UDS, mode 0600)
        let _ = std::fs::remove_file(&ctrl_sock_path);
        if let Some(parent) = std::path::Path::new(&ctrl_sock_path).parent() {
            let _ = std::fs::create_dir_all(parent);
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
        let ctrl_listener = tokio::net::UnixListener::bind(&ctrl_sock_path).map_err(|e| {
            CliError::DaemonInit(format!("bind control socket {ctrl_sock_path}: {e}"))
        })?;
        let _ = std::fs::set_permissions(&ctrl_sock_path, std::fs::Permissions::from_mode(0o600));
        eprintln!("control socket: {}", ctrl_sock_path);

        // Spawn control socket accept loop
        let ctrl_tx = pairing_tx.clone();
        let ctrl_task = tokio::spawn(control_socket::control_socket_loop(ctrl_listener, ctrl_tx));

        // Spawn WC v2 server (consumes pairing_rx). When the Web UI is
        // enabled, the approval channel is wired into the router so signing
        // requests are gated by the browser approval flow.
        let wc_cancel_task = wc_cancel.clone();
        let approval_tx_for_wc = approval_tx.clone();

        // H3: load an optional pre-signing policy for the WC router. The
        // file is a serialized `oc_policy::PolicyV2`; absence means NO
        // policy evaluation on WC signing, which we surface loudly at
        // startup instead of silently skipping.
        let wc_policy = {
            let path = state_dir.join("wc-policy.json");
            match std::fs::read_to_string(&path).map_err(|e| (path.clone(), e)) {
                Ok(contents) => match serde_json::from_str::<oc_policy::PolicyV2>(&contents) {
                    Ok(p) => {
                        eprintln!("WC policy loaded from {}", path.display());
                        Some(p)
                    }
                    Err(e) => {
                        eprintln!(
                            "WARNING: malformed {} ({e}) — WC signing runs WITHOUT policy \
                             evaluation",
                            path.display()
                        );
                        None
                    }
                },
                Err((_, read_err)) => {
                    eprintln!(
                        "WARNING: no WC policy at {} ({read_err}) — chain whitelists, expiry \
                         and risk checks are NOT enforced on WalletConnect signing; create \
                         ~/.onecipher/wc-policy.json or set OC_WC_POLICY=off to explicitly opt out",
                        path.display()
                    );
                    None
                }
            }
        };

        let wc_task = tokio::spawn(async move {
            // dApp origin allowlist for wc_sessionPropose (deny-all by default).
            let trusted_origins = oc_core::Config::load_or_default().wc.trusted_origins;
            #[cfg(feature = "webui")]
            let result = oc_netagent::run_server_controlled_full(
                &ka_sock_for_wc,
                &relay_url,
                &state_dir_str,
                trusted_origins,
                pairing_rx,
                Some(sign_auth_internal_token.clone()),
                Some(approval_tx_for_wc),
                None,
                Some(wc_cancel_task),
                wc_policy,
            )
            .await;
            #[cfg(not(feature = "webui"))]
            let result = oc_netagent::run_server_controlled_full(
                &ka_sock_for_wc,
                &relay_url,
                &state_dir_str,
                trusted_origins,
                pairing_rx,
                Some(sign_auth_internal_token.clone()),
                None,
                None,
                Some(wc_cancel_task),
                wc_policy,
            )
            .await;
            if let Err(e) = result {
                eprintln!("WC v2 server error: {e}");
            }
        });

        // --- Telemetry drain loop (P1 3.1) ---
        // Pulls the Key-Agent's redacted span buffer over the UDS this side
        // already owns, and hands each batch to the configured sink. Skipped
        // when telemetry is off so an idle daemon does not poll a permanently
        // empty buffer.
        let telemetry_task = spawn_telemetry_drain(ka_sock_for_telemetry);

        // --- Web UI server (conditionally spawned) ---
        // Compiled out entirely without the `webui` feature: `webauthn-rs` is
        // the only thing that links OpenSSL at all (hpx uses pure-Rust rustls),
        // so a signing-only build has zero C-crypto and should not pay for it.
        #[cfg(not(feature = "webui"))]
        let webui_handle: Option<tokio::task::JoinHandle<()>> = None;
        #[cfg(feature = "webui")]
        let webui_handle: Option<tokio::task::JoinHandle<()>> = {
            let config = oc_core::Config::load_or_default();
            if config.webui.enabled {
                // Dual registration: a browser passkey registered in the Web
                // UI is mirrored into the Key-Agent's PasskeyPubkeyStore so the
                // same credential can authorize dApp signing. The closure is
                // built here (in oc-cli, which links oc-keyagent) rather than
                // inside oc-webui — pulling oc-keyagent into oc-webui would
                // drag hpx into that crate's graph and break the feature
                // isolation in this binary.
                let dual_register: Option<oc_webui::routes::auth::DualRegistrationFn> =
                    Some(std::sync::Arc::new(move |cred_id, algorithm, pubkey| {
                        use oc_keyagent::{
                            KeyAgentRequest, KeyAgentRequestKind,
                            frame::FrameClient,
                            proto::{ListWalletsResponse, RegisterPasskeyRequest},
                        };
                        let sock = ka_sock_for_webui.clone();
                        // M16: bind the browser passkey to a concrete wallet.
                        // Unbound ("") credentials are rejected by the
                        // Key-Agent because they act as signing wildcards.
                        // We bind to the first wallet that has an account on
                        // any chain — the daemon is single-user/local-first,
                        // so "the user's default wallet" is the correct
                        // binding target at registration time.
                        let wallet_id = {
                            use prost::Message as _;
                            let list_req = KeyAgentRequest {
                                kind: Some(KeyAgentRequestKind::ListWallets(
                                    oc_keyagent::proto::Empty {},
                                )),
                            };
                            match FrameClient::new(sock.clone()).send_request(&list_req) {
                                Ok(resp) if !resp.is_error() => {
                                    ListWalletsResponse::decode(match &resp.kind {
                                        Some(oc_keyagent::KeyAgentResponseKind::Ok(b)) => {
                                            b.as_slice()
                                        }
                                        _ => &[],
                                    })
                                    .ok()
                                    .and_then(|w| w.wallets.first().map(|w| w.id.clone()))
                                    .unwrap_or_default()
                                }
                                _ => String::new(),
                            }
                        };
                        if wallet_id.is_empty() {
                            eprintln!(
                                "webui passkey registration refused: no wallet exists to bind \
                                 the credential to"
                            );
                            return false;
                        }
                        let req = KeyAgentRequest {
                            kind: Some(KeyAgentRequestKind::RegisterPasskey(
                                RegisterPasskeyRequest {
                                    wallet_id,
                                    credential_id: cred_id.to_string(),
                                    algorithm: algorithm.to_string(),
                                    public_key: pubkey.to_vec(),
                                },
                            )),
                        };
                        match FrameClient::new(sock).send_request(&req) {
                            Ok(resp) if !resp.is_error() => true,
                            other => {
                                eprintln!("webui dual registration warning: {other:?}");
                                false
                            }
                        }
                    }));
                match oc_webui::run_webui_server(
                    &config.webui,
                    state_dir.clone(),
                    approval_rx,
                    pairing_tx,
                    dual_register,
                )
                .await
                {
                    Ok((handle, port)) => {
                        // Persist bound port for CLI `onecipher webui open`.
                        // H-02: atomic private write — the file is created
                        // 0600 from the start and can never be observed torn.
                        let port_file = state_dir.join("webui.port");
                        let _ = oc_core::paths::write_atomic_private(
                            &port_file,
                            port.to_string().as_bytes(),
                        );
                        eprintln!("Web UI listening on http://127.0.0.1:{port}");
                        Some(handle)
                    }
                    Err(e) => {
                        eprintln!("Web UI server failed to start: {e}");
                        None
                    }
                }
            } else {
                None
            }
        };

        // --- Local HTTP-RPC server (P1: AI-agent direct signing surface) ---
        // Loopback-only JSON-RPC 2.0, disabled by default. Enable with
        // OC_RPC_LISTEN=127.0.0.1:7667 — the address MUST be loopback; any
        // other value is rejected at bind time (R12e), surfaced as a startup
        // error in the spawned task.
        let rpc_handle: Option<tokio::task::JoinHandle<()>> = {
            match std::env::var("OC_RPC_LISTEN") {
                Ok(listen) => match listen.parse::<std::net::SocketAddr>() {
                    Ok(addr) => {
                        let mut rpc_approval = None;
                        let mut rpc_approval_mode = false;
                        #[cfg(feature = "webui")]
                        {
                            let config = oc_core::Config::load_or_default();
                            if config.webui.enabled {
                                let (channel, mut rx) = oc_netagent::ApprovalChannel::new(64);
                                let tx = approval_tx.clone();
                                tokio::spawn(async move {
                                    while let Some((approval, resp_tx)) = rx.recv().await {
                                        if tx.send((approval, resp_tx)).await.is_err() {
                                            break;
                                        }
                                    }
                                });
                                rpc_approval = Some(channel);
                                rpc_approval_mode = true;
                            }
                        }
                        let server =
                            oc_netagent::LocalRpcServer::new(oc_netagent::LocalRpcServerConfig {
                                listen: addr,
                                key_agent_sock: ka_sock_for_rpc,
                                approval: rpc_approval,
                                approval_mode: std::sync::Arc::new(
                                    std::sync::atomic::AtomicBool::new(rpc_approval_mode),
                                ),
                                approval_timeout: std::time::Duration::from_secs(300),
                                approval_log: None,
                            });
                        Some(tokio::spawn(async move {
                            match server.serve().await {
                                Ok(port) => {
                                    eprintln!("HTTP-RPC listening on 127.0.0.1:{port}");
                                }
                                Err(e) => {
                                    eprintln!("HTTP-RPC server failed to start: {e}");
                                }
                            }
                        }))
                    }
                    Err(e) => {
                        eprintln!("invalid OC_RPC_LISTEN '{listen}': {e}");
                        None
                    }
                },
                Err(_) => None,
            }
        };

        // --- WalletSigner JSON-RPC server (LedgerFlow WalletSigner, daemon-resident) ---
        // Disabled by default. When enabled via OC_WALLET_RPC_LISTEN, bind a
        // loopback-only WalletSigner endpoint for a local LedgerFlow signer.
        let (wallet_rpc_listen, wallet_rpc_wallet, wallet_rpc_index) =
            crate::commands::wallet_rpc::daemon_config();
        let wallet_rpc_handle: Option<tokio::task::JoinHandle<()>> = {
            const DISABLED: &str = "off";
            if wallet_rpc_listen.is_empty() || wallet_rpc_listen == DISABLED {
                None
            } else {
                match crate::commands::wallet_rpc::parse_loopback(&wallet_rpc_listen) {
                    Ok(parsed) => {
                        let state = crate::commands::wallet_rpc::SignerState::new(
                            &wallet_rpc_wallet,
                            wallet_rpc_index,
                        );
                        Some(tokio::spawn(async move {
                            if let Err(e) =
                                crate::commands::wallet_rpc::serve_async(state, parsed).await
                            {
                                eprintln!("WalletSigner server error: {e}");
                            }
                        }))
                    }
                    Err(e) => {
                        eprintln!(
                            "invalid OC_WALLET_RPC_LISTEN '{}': {e}; WalletSigner server disabled",
                            wallet_rpc_listen
                        );
                        None
                    }
                }
            }
        };

        eprintln!("daemon running (Ctrl+C to stop)");

        // Monitor the Key-Agent thread: bridge the sync mpsc receiver into the
        // tokio select! loop via `spawn_blocking`. `.recv().ok()` yields
        // `Some(msg)` if the thread reported an error, or `None` if the thread
        // exited without sending (sender dropped).
        let ka_monitor = tokio::task::spawn_blocking(move || ka_err_rx.recv().ok());

        // C-01: bridge the sync signal-notifier receiver into the select!
        // loop the same way. `.recv().ok()` yields `Some(sig)` when
        // SIGTERM/SIGINT/SIGHUP/SIGQUIT arrives, or `None` if the notifier
        // thread exited without delivering a signal.
        let signal_monitor = tokio::task::spawn_blocking(move || signal_rx.recv().ok());

        // Fan-in: every background server reports its exit through one
        // channel, so the select! needs a single branch and no JoinHandle is
        // moved away from the shutdown path — the C-01 grace period below
        // waits on these events after a signal.
        let (exit_tx, mut exit_rx) = tokio::sync::mpsc::unbounded_channel::<&'static str>();
        notify_on_exit(Some(ctrl_task), "control socket task", exit_tx.clone());
        notify_on_exit(Some(wc_task), "WC server", exit_tx.clone());
        notify_on_exit(webui_handle, "Web UI server", exit_tx.clone());
        notify_on_exit(rpc_handle, "HTTP-RPC server", exit_tx.clone());
        notify_on_exit(wallet_rpc_handle, "WalletSigner server", exit_tx.clone());
        drop(exit_tx);

        // `signal_exit` carries the signal number when the shutdown was
        // initiated by SIGTERM/SIGINT/SIGHUP/SIGQUIT so the conventional
        // `128 + sig` exit status can be applied after cleanup completes.
        let (result, signal_exit): (Result<(), CliError>, Option<u32>) = tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                eprintln!("daemon shutting down");
                graceful_stop(&ka_stop, &wc_cancel);
                (Ok(()), None)
            }
            sig = signal_monitor => {
                match sig {
                    Ok(Some(sig)) => {
                        eprintln!("daemon received signal {sig}; shutting down gracefully");
                        graceful_stop(&ka_stop, &wc_cancel);
                        (Ok(()), Some(sig))
                    }
                    Ok(None) => {
                        eprintln!("signal notifier exited without delivering a signal");
                        (Ok(()), None)
                    }
                    Err(_) => (Ok(()), None),
                }
            }
            Some(name) = exit_rx.recv() => {
                eprintln!("{name} exited");
                (Ok(()), None)
            }
            ka_err = ka_monitor => {
                match ka_err {
                    Ok(Some(msg)) => {
                        eprintln!("key-agent thread exited: {msg}");
                        (Err(CliError::KeyAgent(format!("key-agent died: {msg}"))), None)
                    }
                    Ok(None) => {
                        eprintln!("key-agent thread exited without error");
                        (Err(CliError::KeyAgent("key-agent thread exited".into())), None)
                    }
                    Err(_) => (
                        Err(CliError::KeyAgent("key-agent monitor task failed".into())),
                        None,
                    ),
                }
            }
        };

        // Stop draining before the Key-Agent socket goes away, so shutdown
        // does not log a burst of spurious connect failures.
        if let Some(task) = telemetry_task {
            task.abort();
        }

        // Cleanup control socket and stale port file (H3 fix: a leftover
        // `webui.port` would point at a dead process on the next start).
        let _ = std::fs::remove_file(&ctrl_sock_path);
        let _ = std::fs::remove_file(state_dir.join("webui.port"));

        // C-01: bounded grace period for signal-initiated shutdowns. Give the
        // background servers time to observe their cancellation flags and
        // exit; if they have not all stopped within the grace period, log and
        // exit anyway rather than hanging forever.
        if let Some(sig) = signal_exit {
            let grace = std::time::Duration::from_secs(DAEMON_SHUTDOWN_GRACE_SECS);
            match tokio::time::timeout(grace, async { while exit_rx.recv().await.is_some() {} })
                .await
            {
                Ok(()) => eprintln!("background tasks stopped cleanly"),
                Err(_) => eprintln!(
                    "shutdown grace period ({DAEMON_SHUTDOWN_GRACE_SECS}s) elapsed; \
                     exiting anyway"
                ),
            }
            eprintln!("daemon stopped by signal {sig}");
            // The notifier already ran the registered cleanup hooks (key-cache
            // zeroization); exit with the conventional death-by-signal status.
            std::process::exit(signal_exit_status(sig));
        }

        result
    })
}

/// Shared graceful-stop sequence for Ctrl-C and termination signals (C-01):
/// ask the Key-Agent thread and the WC server run loop to stop cooperatively
/// so every signal takes the same shutdown path.
fn graceful_stop(
    ka_stop: &std::sync::atomic::AtomicBool,
    wc_cancel: &std::sync::atomic::AtomicBool,
) {
    // Signal the Key-Agent thread to stop accepting and clean up its UDS
    // socket (cooperative graceful shutdown, R55).
    ka_stop.store(true, std::sync::atomic::Ordering::Relaxed);
    // Request a graceful stop of the WC server run loop (H3 fix) instead of
    // letting it be dropped mid-connection.
    wc_cancel.store(true, std::sync::atomic::Ordering::Relaxed);
}

/// Report `name` on `tx` once `handle` (when present) has completed.
///
/// Wrapping the optional JoinHandles keeps them out of the shutdown select!
/// while still surfacing their exit through a single fan-in channel.
fn notify_on_exit(
    handle: Option<tokio::task::JoinHandle<()>>,
    name: &'static str,
    tx: tokio::sync::mpsc::UnboundedSender<&'static str>,
) {
    // A `None` handle means the server was never started (feature or config
    // disabled) — not an exit event. Reporting it would shut the daemon down
    // immediately on startup.
    if handle.is_none() {
        return;
    }
    tokio::spawn(async move {
        if let Some(h) = handle {
            let _ = h.await;
        }
        let _ = tx.send(name);
    });
}

/// Conventional shell exit status for a process terminated by a signal:
/// `128 + signal_number`.
fn signal_exit_status(sig: u32) -> i32 {
    // Delivered signal numbers are small positive integers (Linux caps at
    // 64); clamping keeps the conversion total without panicking.
    128 + i32::try_from(sig.min(64)).unwrap_or(0)
}

/// Spawn the Key-Agent telemetry drain loop (P1 3.1).
///
/// Returns `None` when telemetry is disabled — there is no point polling a
/// buffer that is never written to.
///
/// Tunables:
/// - `OC_TELEMETRY_LEVEL=off` disables the whole subsystem (see [`init_telemetry`]).
/// - `OC_TELEMETRY_INTERVAL_SECS` overrides the poll interval (default 5s, clamped to >= 1s so a
///   typo cannot turn this into a busy loop).
fn spawn_telemetry_drain(key_agent_sock: String) -> Option<tokio::task::JoinHandle<()>> {
    if !oc_keyagent::telemetry::global_buffer().is_enabled() {
        return None;
    }

    let interval = std::env::var("OC_TELEMETRY_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .map_or(oc_netagent::DEFAULT_DRAIN_INTERVAL, |s| std::time::Duration::from_secs(s.max(1)));

    let client = oc_netagent::KeyAgentClient::new(key_agent_sock);
    let sink = std::sync::Arc::new(oc_netagent::StdoutSink);

    eprintln!("telemetry: draining every {}s", interval.as_secs());
    Some(tokio::spawn(async move {
        oc_netagent::run_drain_loop(client, sink, interval, oc_netagent::TELEMETRY_BATCH_SIZE)
            .await;
    }))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use super::*;

    #[test]
    fn signal_exit_status_uses_128_plus_signal() {
        assert_eq!(signal_exit_status(1), 129); // SIGHUP
        assert_eq!(signal_exit_status(2), 130); // SIGINT
        assert_eq!(signal_exit_status(3), 131); // SIGQUIT
        assert_eq!(signal_exit_status(15), 143); // SIGTERM
    }

    #[test]
    fn signal_exit_status_is_total_for_out_of_range_input() {
        assert_eq!(signal_exit_status(65), 128 + 64);
        assert_eq!(signal_exit_status(u32::MAX), 128 + 64);
    }

    #[test]
    fn graceful_stop_sets_both_cancellation_flags() {
        let ka = std::sync::atomic::AtomicBool::new(false);
        let wc = std::sync::atomic::AtomicBool::new(false);
        graceful_stop(&ka, &wc);
        assert!(ka.load(Ordering::Relaxed), "ka_stop must be set");
        assert!(wc.load(Ordering::Relaxed), "wc_cancel must be set");
    }
}
