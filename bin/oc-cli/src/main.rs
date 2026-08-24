// Test code may unwrap/expect/panic (workspace lint phase-1 carve-out).
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
mod audit;
mod cli;
mod commands;
mod daemon;
mod netagent;
#[cfg(test)]
mod test_util;
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
        tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap_or_else(|e| {
            eprintln!("error: failed to create tokio runtime: {e}");
            std::process::exit(1);
        })
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

    // Migrate legacy directories (~/.lws, ~/.ows) → ~/.onecipher if needed (one-time upgrade
    // paths).
    oc_wallet::migrate::migrate_vault_if_needed();
    update_shell_rc_paths(".lws/bin", ".onecipher/bin");
    update_shell_rc_paths(".ows/bin", ".onecipher/bin");

    let cli = Cli::parse();

    // Daemon mode: start the WC v2 server + signing engine (Stage 1 stub).
    if cli.daemon {
        // C-01: the daemon installs its own signal handling inside
        // daemon::run_daemon() (panic cleanup hook + notifier integrated into
        // the graceful shutdown select! loop). install_signal_handlers() must
        // NOT run here: it exits the process directly on the first signal,
        // bypassing graceful shutdown entirely.
        let code = match daemon::run_daemon() {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("error: {e}");
                1
            }
        };
        oc_signer::global_key_cache().clear();
        std::process::exit(code);
    }

    // C-01: one-shot commands keep the process-terminating signal handlers —
    // for short-lived CLI commands, running the cleanup hooks and exiting
    // immediately is correct. Daemons never reach this line.
    oc_signer::process_hardening::install_signal_handlers();

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
            cli::WalletCommands::ChangePassword { wallet, passphrase, new_passphrase } => {
                commands::wallet::change_password(
                    &wallet,
                    passphrase.as_deref(),
                    new_passphrase.as_deref(),
                )
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
                message.as_deref(),
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
            typed_data,
            typed_data_file,
            hash,
            no_hash,
            signature,
            chain,
        } => commands::verify::run(commands::verify::VerifyInput {
            address: &address,
            message: message.as_deref(),
            typed_data: typed_data.as_deref(),
            typed_data_file: typed_data_file.as_deref(),
            hash: hash.as_deref(),
            no_hash,
            signature: &signature,
            chain: &chain,
        }),
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
        Commands::Status => commands::status::run(),
        Commands::Service { subcommand } => match subcommand {
            cli::ServiceCommands::Install => commands::service::install(),
            cli::ServiceCommands::Uninstall => commands::service::uninstall(),
            cli::ServiceCommands::Status => commands::service::status(),
        },
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
            cli::WcCommands::Relay { url, project_id } => {
                commands::wc::relay_config(&url, project_id.as_deref())
            }
            cli::WcCommands::Probe { url, project_id, timeout } => {
                commands::wc::probe(url.as_deref(), project_id.as_deref(), timeout)
            }
            cli::WcCommands::DappSend { topic, method, params, sym_key, url } => {
                commands::wc::dapp_send(
                    &topic,
                    &method,
                    &params,
                    sym_key.as_deref(),
                    url.as_deref(),
                )
            }
        },
        Commands::Webui { subcommand } => match subcommand {
            cli::WebUiCommands::Open => commands::webui::open(),
            cli::WebUiCommands::Approval { subcommand } => match subcommand {
                cli::ApprovalCommands::List => commands::webui::approval_list(),
                cli::ApprovalCommands::Show { id } => commands::webui::approval_show(&id),
                cli::ApprovalCommands::Approve { id, yes } => {
                    commands::webui::approval_decision(&id, "approve", None, yes)
                }
                cli::ApprovalCommands::Reject { id, reason, yes } => {
                    commands::webui::approval_decision(&id, "reject", reason.as_deref(), yes)
                }
            },
            cli::WebUiCommands::Auth { subcommand } => match subcommand {
                cli::AuthCommands::Status => commands::webui::auth_status(),
                cli::AuthCommands::Lock => commands::webui::auth_lock(),
                cli::AuthCommands::Bootstrap => commands::webui::auth_bootstrap(),
            },
        },
        Commands::Intent { subcommand } => match subcommand {
            cli::IntentCommands::Submit { json, chain, session_key, yes, rpc_url, from } => {
                commands::intent::run_submit(
                    &json,
                    &chain,
                    &session_key,
                    yes,
                    rpc_url.as_deref(),
                    from.as_deref(),
                )
            }
            cli::IntentCommands::Simulate { json, chain, session_key, rpc_url } => {
                commands::intent::run_simulate(&json, &chain, &session_key, rpc_url.as_deref())
            }
            cli::IntentCommands::Execute { json, chain, session_key, rpc_url, from } => {
                commands::intent::run_execute(
                    &json,
                    &chain,
                    &session_key,
                    rpc_url.as_deref(),
                    from.as_deref(),
                )
            }
        },
        Commands::Secret { subcommand } => match subcommand {
            cli::SecretCommands::List { r#type, json } => {
                let item_type = r#type.as_deref().map(commands::parse_item_type).transpose()?;
                commands::secret::list(item_type, json)
            }
            cli::SecretCommands::Get { name, field, json, qr, copy, timeout } => {
                commands::secret::get(&name, field.as_deref(), json, qr, copy, timeout)
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
        Commands::WalletRpc { subcommand } => match subcommand {
            cli::WalletRpcCommands::Serve { listen, wallet, index } => {
                commands::wallet_rpc::serve(&listen, &wallet, index)
            }
        },
        Commands::Send { chain, to, token, amount, wallet, rpc_url, index, gas_limit, json } => {
            commands::send::run(
                &chain, &wallet, &to, &token, &amount, &rpc_url, index, gas_limit, json,
            )
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
