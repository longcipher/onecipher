mod audit;
mod cli;
mod commands;
mod netagent;
#[cfg(test)]
mod tests;
mod tui;

// Re-export CLI types so `crate::` imports in command modules still work.
use clap::Parser;
use cli::{Cli, Commands};
pub(crate) use cli::{CliError, SignVia, parse_chain};

/// Shared tokio runtime — avoids per-command `Runtime::new()` overhead.
///
/// Lazily initialized on first use via `OnceLock`. All CLI commands and the
/// daemon share this single multi-threaded runtime. Commands should call
/// `crate::shared_runtime().block_on(...)` instead of constructing a fresh
/// `Runtime::new()`.
pub(crate) fn shared_runtime() -> &'static tokio::runtime::Runtime {
    use std::sync::OnceLock;
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to create tokio runtime")
    })
}

fn main() {
    oc_signer::process_hardening::harden_process();

    // L3 fix: resolve HOME exactly once, up front. Previously 17 call sites
    // each fell back to `/tmp` or `.` when HOME was unset, which would have
    // written the vault, key store and audit log into a world-writable
    // directory. Fail closed instead.
    if let Err(e) = oc_core::paths::home_dir() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }

    // Eagerly initialize the global key cache and register it for zeroization
    // on termination signals (SIGTERM, SIGINT, SIGHUP).
    let cache = oc_signer::global_key_cache();
    oc_signer::process_hardening::register_cleanup(move || cache.clear());
    oc_signer::process_hardening::install_signal_handlers();

    // Migrate legacy directories (~/.lws, ~/.ows) → ~/.onecipher if needed (one-time upgrade
    // paths).
    oc_wallet::migrate::migrate_vault_if_needed();
    update_shell_rc_paths(".lws/bin", ".onecipher/bin");
    update_shell_rc_paths(".ows/bin", ".onecipher/bin");

    let cli = Cli::parse();

    // Daemon mode: start the WC v2 server + signing engine (Stage 1 stub).
    if cli.daemon {
        let code = match run_daemon() {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("error: {e}");
                1
            }
        };
        oc_signer::global_key_cache().clear();
        std::process::exit(code);
    }

    // Try the Key-Agent daemon first; auto-spawn if not running.
    // Falls back to the stub client only if spawn + connect fails.
    let client: Box<dyn netagent::NetAgentClient> =
        match netagent::UdsKeyAgentClient::connect_or_spawn() {
            Ok(c) => Box::new(c),
            Err(e) => {
                eprintln!(
                    "warning: could not connect to Key-Agent daemon ({e}), using stub client"
                );
                Box::new(netagent::UnimplementedClient)
            }
        };
    let code = match run(cli, &*client) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    };

    // Explicitly zeroize all cached key material before exiting.
    oc_signer::global_key_cache().clear();
    std::process::exit(code);
}

fn run(cli: Cli, client: &dyn netagent::NetAgentClient) -> Result<(), CliError> {
    let command = match cli.command {
        Some(c) => c,
        None => return Ok(()),
    };
    match command {
        Commands::Wallet { subcommand } => match subcommand {
            cli::WalletCommands::Create { name, words, show_mnemonic } => {
                commands::wallet::create(&name, words, show_mnemonic)
            }
            cli::WalletCommands::Import {
                name,
                mnemonic,
                private_key,
                chain,
                index,
                interactive,
            } => {
                if interactive {
                    commands::wallet::import_interactive(&name, chain.as_deref())
                } else {
                    commands::wallet::import(&name, mnemonic, private_key, chain.as_deref(), index)
                }
            }
            cli::WalletCommands::Export { wallet, public_key, chain, compressed } => {
                if public_key {
                    commands::wallet::export_public_key(&wallet, chain.as_deref(), compressed)
                } else {
                    commands::wallet::export(&wallet)
                }
            }
            cli::WalletCommands::Delete { wallet, confirm } => {
                commands::wallet::delete(&wallet, confirm)
            }
            cli::WalletCommands::Rename { wallet, new_name } => {
                commands::wallet::rename(&wallet, &new_name)
            }
            cli::WalletCommands::List => commands::wallet::list(),
            cli::WalletCommands::Info => commands::info::run(),
            cli::WalletCommands::ChangePassword { wallet } => {
                commands::wallet::change_password(&wallet)
            }
        },
        Commands::Sign { subcommand } => match subcommand {
            cli::SignCommands::Message {
                chain,
                wallet,
                message,
                encoding,
                typed_data,
                index,
                json,
            } => commands::sign_message::run(
                &chain,
                &wallet,
                &message,
                &encoding,
                typed_data.as_deref(),
                index,
                json,
            ),
            cli::SignCommands::Tx { chain, wallet, tx, index, json, via } => {
                commands::sign_transaction::run(&chain, &wallet, &tx, index, json, via)
            }
            cli::SignCommands::SendTx { chain, wallet, tx, index, json, rpc_url } => {
                commands::send_transaction::run(
                    &chain,
                    &wallet,
                    &tx,
                    index,
                    json,
                    rpc_url.as_deref(),
                )
            }
            cli::SignCommands::Auth { chain, wallet, address, nonce, index, json } => {
                commands::sign_auth::run(&chain, &wallet, &address, &nonce, index, json)
            }
        },
        Commands::Vanity { starts_with, ends_with, count, jobs, save_path, save_to_vault } => {
            commands::vanity::run(
                starts_with.as_deref(),
                ends_with.as_deref(),
                count,
                jobs,
                save_path.as_deref(),
                save_to_vault,
            )
        }
        Commands::Verify {
            address,
            message,
            typed_data: _,
            typed_data_file: _,
            hash,
            no_hash,
            signature,
            chain,
        } => {
            // Verify command implementation
            let chain_parsed = oc_core::parse_chain(&chain)
                .map_err(|e| CliError::InvalidArgs(format!("invalid chain: {e}")))?;
            if chain_parsed.chain_type != oc_core::ChainType::Evm {
                return Err(CliError::InvalidArgs(
                    "verify is currently only supported for EVM chains".into(),
                ));
            }
            let sig_bytes = hex::decode(signature.strip_prefix("0x").unwrap_or(&signature))
                .map_err(|e| CliError::InvalidArgs(format!("invalid signature hex: {e}")))?;
            let signer = oc_signer::signer_for_chain(chain_parsed.chain_type);
            let valid = if let Some(hash_hex) = hash {
                let hash_bytes = hex::decode(hash_hex.strip_prefix("0x").unwrap_or(&hash_hex))
                    .map_err(|e| CliError::InvalidArgs(format!("invalid hash hex: {e}")))?;
                if no_hash {
                    signer.verify_hash(&address, &hash_bytes, &sig_bytes)?
                } else {
                    signer.verify_message(&address, &hash_bytes, &sig_bytes)?
                }
            } else if let Some(msg) = message {
                signer.verify_message(&address, msg.as_bytes(), &sig_bytes)?
            } else {
                return Err(CliError::InvalidArgs(
                    "one of --message, --typed-data, --typed-data-file, or --hash is required"
                        .into(),
                ));
            };
            if valid {
                println!("Signature is valid.");
                Ok(())
            } else {
                println!("Signature is INVALID.");
                Err(CliError::InvalidArgs("signature verification failed".into()))
            }
        }
        Commands::Fund { subcommand } => match subcommand {
            cli::FundCommands::Deposit { wallet, chain, token } => {
                commands::fund::run(&wallet, Some(&chain), Some(&token))
            }
            cli::FundCommands::Balance { wallet, chain } => {
                commands::fund::balance(&wallet, Some(&chain))
            }
        },
        Commands::Pay { subcommand } => match subcommand {
            cli::PayCommands::Request { url, wallet, method, body, no_passphrase } => {
                commands::pay::run(&url, &wallet, &method, body.as_deref(), no_passphrase)
            }
            cli::PayCommands::Discover { query, limit, offset } => {
                commands::pay::discover(query.as_deref(), limit, offset)
            }
        },
        Commands::Mnemonic { subcommand } => match subcommand {
            cli::MnemonicCommands::Generate { words } => commands::generate::run(words),
            cli::MnemonicCommands::Derive { chain, index, path, count, show_private_key } => {
                commands::derive::run(
                    chain.as_deref(),
                    index,
                    path.as_deref(),
                    count,
                    show_private_key,
                )
            }
        },
        Commands::Policy { subcommand } => match subcommand {
            cli::PolicyCommands::Create { file } => commands::policy::create(&file),
            cli::PolicyCommands::List => commands::policy::list(),
            cli::PolicyCommands::Show { id } => commands::policy::show(&id),
            cli::PolicyCommands::Delete { id, confirm } => commands::policy::delete(&id, confirm),
        },
        Commands::Key { subcommand } => match subcommand {
            cli::KeyCommands::Create { name, wallets, policies, expires_at } => {
                commands::key::create(&name, &wallets, &policies, expires_at.as_deref())
            }
            cli::KeyCommands::List => commands::key::list(),
            cli::KeyCommands::Revoke { id, confirm } => commands::key::revoke(&id, confirm),
        },
        Commands::Config { subcommand } => match subcommand {
            cli::ConfigCommands::Show => commands::config::show(),
            cli::ConfigCommands::Set { key, value } => commands::config::set(&key, &value),
        },
        Commands::Update { force } => commands::update::run(force),
        Commands::Uninstall { purge } => commands::uninstall::run(purge),
        // === OneCipher Phase 1 commands ===
        Commands::Audit { subcommand } => match subcommand {
            cli::AuditCommands::List { since, agent, status } => {
                commands::audit::list(since.as_deref(), agent.as_deref(), status.as_deref())
            }
            cli::AuditCommands::Secrets { format, max_age, skip_hibp } => {
                commands::audit_secrets::run(&format, max_age, skip_hibp)
            }
        },
        Commands::SessionKey { subcommand } => match subcommand {
            cli::SessionKeyCommands::Create { label, challenge, signature, credential_id } => {
                commands::session_key::create(
                    &label,
                    &challenge,
                    &signature,
                    &credential_id,
                    client,
                )
            }
            cli::SessionKeyCommands::Revoke {
                session_key_id,
                challenge,
                signature,
                credential_id,
            } => commands::session_key::revoke(
                &session_key_id,
                &challenge,
                &signature,
                &credential_id,
                client,
            ),
            cli::SessionKeyCommands::List => commands::session_key::list(client),
        },
        Commands::OcPay { subcommand } => match subcommand {
            cli::OcPayCommands::X402 { url, session_key, method, body } => {
                commands::pay_x402::run(&url, &session_key, &method, body.as_deref(), client)
            }
        },
        Commands::Status => commands::status::run(),
        Commands::Vault { subcommand } => match subcommand {
            cli::VaultCommands::Unlock => commands::vault::unlock(),
        },
        Commands::Backup { subcommand } => match subcommand {
            cli::BackupCommands::Export { out } => commands::backup::export(&out),
            cli::BackupCommands::Import { r#in } => commands::backup::import(&r#in),
        },
        Commands::Sbom { subcommand } => match subcommand {
            cli::SbomCommands::Verify { file } => commands::sbom::verify(&file),
            cli::SbomCommands::Generate { output } => commands::sbom::generate(&output),
        },
        Commands::Wc { subcommand } => match subcommand {
            cli::WcCommands::Pair { ttl } => commands::wc::pair(ttl),
            cli::WcCommands::Connect { uri } => commands::wc::connect(&uri),
            cli::WcCommands::Sessions => commands::wc::sessions(),
            cli::WcCommands::Disconnect { topic } => commands::wc::disconnect(&topic),
        },
        Commands::Webui { subcommand } => match subcommand {
            cli::WebUiCommands::Open => commands::webui::open(),
        },
        Commands::Intent { subcommand } => match subcommand {
            cli::IntentCommands::Submit { json, chain, session_key, sponsor, yes, rpc_url } => {
                commands::intent::run_submit(
                    &json,
                    &chain,
                    &session_key,
                    &sponsor,
                    yes,
                    rpc_url.as_deref(),
                )
            }
            cli::IntentCommands::Simulate { json, chain, session_key, rpc_url } => {
                commands::intent::run_simulate(&json, &chain, &session_key, rpc_url.as_deref())
            }
            cli::IntentCommands::Execute { json, chain, session_key, sponsor, rpc_url } => {
                commands::intent::run_execute(
                    &json,
                    &chain,
                    &session_key,
                    &sponsor,
                    rpc_url.as_deref(),
                )
            }
        },
        Commands::Secret { subcommand } => match subcommand {
            cli::SecretCommands::List { r#type, json } => {
                let item_type = r#type.as_deref().map(commands::parse_item_type).transpose()?;
                commands::secret::list(item_type, json)
            }
            cli::SecretCommands::Get { name, field, json, qr } => {
                commands::secret::get(&name, field.as_deref(), json, qr)
            }
            cli::SecretCommands::Add { name, r#type, meta, stdin } => {
                let item_type = commands::parse_item_type(&r#type)?;
                commands::secret::add(&name, item_type, &meta, stdin)
            }
            cli::SecretCommands::Update { name, field, stdin } => {
                commands::secret::update(&name, field.as_deref(), stdin)
            }
            cli::SecretCommands::Delete { name } => commands::secret::delete(&name),
            cli::SecretCommands::Rename { old, new } => commands::secret::rename(&old, &new),
            cli::SecretCommands::Edit { name, editor } => {
                commands::secret::edit(&name, editor.as_deref())
            }
            cli::SecretCommands::Copy { src, dst, force } => {
                commands::secret::copy(&src, &dst, force)
            }
            cli::SecretCommands::Move { src, dst, force } => {
                commands::secret::mv(&src, &dst, force)
            }
        },
        Commands::Password { subcommand } => match subcommand {
            cli::PasswordCommands::Add { name, url, username, generate, length, symbols } => {
                commands::password::add(&name, &url, &username, generate, length, symbols)
            }
            cli::PasswordCommands::Get { name, copy, timeout } => {
                commands::password::get(&name, copy, timeout)
            }
            cli::PasswordCommands::Generate {
                length,
                symbols,
                generator,
                xkcd_sep,
                xkcd_words,
                qr,
            } => {
                commands::password::generate(length, symbols, &generator, &xkcd_sep, xkcd_words, qr)
            }
        },
        Commands::Totp { subcommand } => match subcommand {
            cli::TotpCommands::Add { name, otpauth, secret, issuer, account } => {
                commands::totp::add(
                    &name,
                    otpauth.as_deref(),
                    secret.as_deref(),
                    issuer.as_deref(),
                    account.as_deref(),
                )
            }
            cli::TotpCommands::Generate { name, qr } => commands::totp::generate(&name, qr),
            cli::TotpCommands::Uris { name } => commands::totp::uris(&name),
            cli::TotpCommands::Hotp { name, counter, increment } => {
                commands::totp::hotp(&name, counter, increment)
            }
        },
        Commands::Age { subcommand } => match subcommand {
            cli::AgeCommands::Init => commands::age_cmd::init(),
            cli::AgeCommands::Recipient { subcommand } => match subcommand {
                cli::AgeRecipientCommands::Add { bech32 } => {
                    commands::age_cmd::recipient_add(&bech32)
                }
                cli::AgeRecipientCommands::List => commands::age_cmd::recipient_list(),
                cli::AgeRecipientCommands::Remove { bech32 } => {
                    commands::age_cmd::recipient_remove(&bech32)
                }
            },
            cli::AgeCommands::IdentityShow => commands::age_cmd::identity_show(),
            cli::AgeCommands::Reencrypt => commands::age_cmd::reencrypt(),
        },
        Commands::Migrate { dry_run, rollback } => commands::migrate::run(dry_run, rollback),
        Commands::Grep { pattern, regex, json } => commands::grep::run(&pattern, regex, json),
        Commands::Find { query, regex, json, r#type } => {
            commands::find::run(query.as_deref(), regex, json, r#type.as_deref())
        }
        Commands::Tui => {
            let store = commands::open_secret_store()?;
            tui::run(store).map_err(|e| CliError::InvalidArgs(e.to_string()))
        }
        Commands::Doctor { verbose } => commands::doctor::run(verbose),
        Commands::Fsck { fix, decrypt } => commands::fsck::run(fix, decrypt),
        Commands::Completion { shell } => commands::completion::run(&shell),
        #[cfg(feature = "git")]
        Commands::History { name, password, limit, json } => {
            commands::history::run(&name, password, limit, json)
        }
        Commands::AgentSecret { subcommand } => match subcommand {
            cli::AgentSecretCommands::Get { name, json } => {
                commands::agent_secret::agent_secret_get(&name, json)
            }
            cli::AgentSecretCommands::List { json } => {
                commands::agent_secret::agent_secret_list(json)
            }
            cli::AgentSecretCommands::Totp { name } => {
                commands::agent_secret::agent_totp_generate(&name)
            }
        },
        Commands::Env { names, keep_case, exec, command } => {
            commands::env_cmd::run(&names, keep_case, exec, &command)
        }
        #[cfg(feature = "git")]
        Commands::Git { subcommand } => match subcommand {
            cli::GitCommands::Init { remote } => commands::git_cmd::init(remote.as_deref()),
            cli::GitCommands::Pull => commands::git_cmd::pull(),
            cli::GitCommands::Push => commands::git_cmd::push(),
            cli::GitCommands::Log { name } => commands::git_cmd::log(name.as_deref()),
            cli::GitCommands::Status => commands::git_cmd::status(),
        },
    }
}

/// Run the unified daemon: Key-Agent UDS server + WC v2 wallet server +
/// control socket for CLI pairing injection.
///
/// Architecture:
/// - **Key-Agent** (sync thread, R55): `oc_keyagent::server::run()` on UDS. Handles signing,
///   policy, vault access via globals pointing at `~/.onecipher`.
/// - **WC v2 server** (tokio task): `oc_netagent::run_server_controlled()` connects outbound WSS to
///   the WC relay, subscribes to pairing topics, and dispatches inbound JSON-RPC to the Key-Agent
///   via UDS.
/// - **Control socket** (tokio task): accepts `CONNECT <uri>` and `PAIR` commands from `onecipher
///   wc connect/pair` CLI calls. Injects pairing URIs into the WC server via a tokio mpsc channel.
fn run_daemon() -> Result<(), CliError> {
    use std::os::unix::fs::PermissionsExt;

    eprintln!("onecipher daemon starting...");
    let engine = oc_keyagent::SigningEngine::open_default()
        .map_err(|e| CliError::DaemonInit(format!("key engine: {e}")))?;
    let state_dir = engine.state_dir().to_path_buf();
    eprintln!("signing engine opened at {}", state_dir.display());

    // --- Key-Agent UDS server (sync, dedicated thread per R55) ---
    let key_agent_sock = oc_keyagent::server::default_socket_path();
    eprintln!("key-agent socket: {}", key_agent_sock);
    let ka_sock_clone = key_agent_sock.clone();

    // Channel: Key-Agent thread → tokio select! loop (lifecycle monitoring).
    // The thread sends a message only on error; if it exits without sending,
    // the receiver's `recv()` returns `Err` → `.ok()` yields `None`.
    let (ka_err_tx, ka_err_rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        if let Err(e) = oc_keyagent::server::run(Some(&ka_sock_clone)) {
            let _ = ka_err_tx.send(format!("{e}"));
        }
    });

    // --- Control socket path ---
    let ctrl_sock_path = commands::wc::control_socket_path();

    // --- Shared tokio runtime for async WC server + control loop ---
    let rt = shared_runtime();

    let relay_url =
        std::env::var("OC_WC_RELAY_URL").unwrap_or_else(|_| "wss://relay.walletconnect.com".into());
    let state_dir_str = state_dir.to_string_lossy().to_string();
    let ka_sock_for_wc = key_agent_sock;

    // Channel: control socket → WC server (pairing URI injection)
    let (pairing_tx, pairing_rx) = tokio::sync::mpsc::channel::<oc_walletconnect::PairingUri>(32);

    rt.block_on(async {
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
        let ctrl_task = tokio::spawn(control_socket_loop(ctrl_listener, ctrl_tx));

        // Spawn WC v2 server (consumes pairing_rx)
        let wc_task = tokio::spawn(async move {
            if let Err(e) = oc_netagent::run_server_controlled(
                &ka_sock_for_wc,
                &relay_url,
                &state_dir_str,
                pairing_rx,
            )
            .await
            {
                eprintln!("WC v2 server error: {e}");
            }
        });

        // --- Web UI server (conditionally spawned) ---
        // Compiled out entirely without the `webui` feature: `webauthn-rs` is
        // the only thing that links OpenSSL into a binary that already links
        // BoringSSL (via `hpx`), so a signing-only build should not pay for it.
        #[cfg(not(feature = "webui"))]
        let webui_handle: Option<tokio::task::JoinHandle<()>> = None;
        #[cfg(feature = "webui")]
        let webui_handle: Option<tokio::task::JoinHandle<()>> = {
            let config = oc_core::Config::load_or_default();
            if config.webui.enabled {
                let (approval_tx, approval_rx) = tokio::sync::mpsc::channel(64);
                // Store approval_tx for later injection into WcMethodRouter (W1.9 plumbing).
                // For now, the channel exists but isn't connected to the router yet.
                let _ = approval_tx;

                match oc_webui::run_webui_server(&config.webui, state_dir.clone(), approval_rx)
                    .await
                {
                    Ok((handle, port)) => {
                        // Persist bound port for CLI `onecipher webui open`
                        let port_file = state_dir.join("webui.port");
                        let _ = std::fs::write(&port_file, port.to_string());
                        #[cfg(unix)]
                        {
                            let _ = std::fs::set_permissions(
                                &port_file,
                                std::fs::Permissions::from_mode(0o600),
                            );
                        }
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

        eprintln!("daemon running (Ctrl+C to stop)");

        // Monitor the Key-Agent thread: bridge the sync mpsc receiver into the
        // tokio select! loop via `spawn_blocking`. `.recv().ok()` yields
        // `Some(msg)` if the thread reported an error, or `None` if the thread
        // exited without sending (sender dropped).
        let ka_monitor = tokio::task::spawn_blocking(move || ka_err_rx.recv().ok());

        let result: Result<(), CliError> = tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                eprintln!("daemon shutting down");
                Ok(())
            }
            _ = ctrl_task => {
                eprintln!("control socket task exited");
                Ok(())
            }
            _ = wc_task => {
                eprintln!("WC server exited");
                Ok(())
            }
            () = async {
                match webui_handle {
                    Some(h) => { let _ = h.await; }
                    None => std::future::pending::<()>().await,
                }
            } => {
                eprintln!("Web UI server exited");
                Ok(())
            }
            ka_err = ka_monitor => {
                match ka_err {
                    Ok(Some(msg)) => {
                        eprintln!("key-agent thread exited: {msg}");
                        Err(CliError::KeyAgent(format!("key-agent died: {msg}")))
                    }
                    Ok(None) => {
                        eprintln!("key-agent thread exited without error");
                        Err(CliError::KeyAgent("key-agent thread exited".into()))
                    }
                    Err(_) => {
                        Err(CliError::KeyAgent("key-agent monitor task failed".into()))
                    }
                }
            }
        };

        // Cleanup control socket
        let _ = std::fs::remove_file(&ctrl_sock_path);
        result
    })
}

/// Control socket accept loop — handles `CONNECT <uri>` and `PAIR [ttl]`
/// commands from `onecipher wc connect/pair`.
///
/// Protocol (line-based, newline-terminated):
/// - Request:  `CONNECT <wc_uri>\n` or `PAIR [<ttl_secs>]\n`
/// - Response: `OK [details]\n` or `ERR <message>\n`
async fn control_socket_loop(
    listener: tokio::net::UnixListener,
    tx: tokio::sync::mpsc::Sender<oc_walletconnect::PairingUri>,
) {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let tx = tx.clone();
                tokio::spawn(async move {
                    let (reader, mut writer) = stream.into_split();
                    let mut reader = BufReader::new(reader);
                    let mut line = String::new();

                    if reader.read_line(&mut line).await.is_err() {
                        let _ = writer.write_all(b"ERR read failed\n").await;
                        return;
                    }

                    let line = line.trim();
                    if let Some(uri_str) = line.strip_prefix("CONNECT ") {
                        // dApp-generated URI → inject into WC server
                        match oc_walletconnect::PairingUri::parse(uri_str) {
                            Ok(uri) => {
                                if tx.send(uri).await.is_ok() {
                                    let _ = writer.write_all(b"OK pairing loaded\n").await;
                                } else {
                                    let _ = writer.write_all(b"ERR daemon shutting down\n").await;
                                }
                            }
                            Err(e) => {
                                let _ = writer
                                    .write_all(format!("ERR invalid URI: {e}\n").as_bytes())
                                    .await;
                            }
                        }
                    } else if line == "PAIR" || line.starts_with("PAIR ") {
                        // Daemon-generated pairing URI → return to user for QR display
                        let ttl: u64 = line
                            .strip_prefix("PAIR ")
                            .and_then(|s| s.trim().parse().ok())
                            .unwrap_or(oc_netagent::DEFAULT_PAIRING_TTL);
                        let (uri, _session) = oc_netagent::generate_pairing_uri(ttl);
                        let uri_for_send = uri.clone();
                        if tx.send(uri_for_send).await.is_ok() {
                            let _ = writer.write_all(format!("OK {uri}\n").as_bytes()).await;
                        } else {
                            let _ = writer.write_all(b"ERR daemon shutting down\n").await;
                        }
                    } else {
                        let _ = writer.write_all(b"ERR unknown command\n").await;
                    }
                });
            }
            Err(e) => {
                eprintln!("control socket accept error: {e}");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
}

/// Replace `src_bin` with `dst_bin` in common shell RC files.
pub(crate) fn update_shell_rc_paths(src_bin: &str, dst_bin: &str) {
    let Ok(home) = oc_core::paths::home_dir() else {
        return;
    };
    let rc_files = [
        std::path::PathBuf::from(&home).join(".zshrc"),
        std::path::PathBuf::from(&home).join(".bashrc"),
        std::path::PathBuf::from(&home).join(".bash_profile"),
        std::path::PathBuf::from(&home).join(".config/fish/config.fish"),
    ];
    for rc in &rc_files {
        if rc.exists() {
            if let Ok(contents) = std::fs::read_to_string(rc) {
                if contents.contains(src_bin) {
                    let updated = contents.replace(src_bin, dst_bin);
                    let _ = std::fs::write(rc, updated);
                }
            }
        }
    }
}
