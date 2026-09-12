// Test code may unwrap/expect/panic (workspace lint phase-1 carve-out).
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
mod audit;
mod cli;
mod commands;
mod daemon;
mod enclave_spawn;
mod exit;
mod netagent;
pub(crate) mod output;
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

    // Per-request enclave child: decrypt→sign→wipe for exactly one piped
    // request, then exit. This branch runs before any daemon/client setup so
    // the child stays minimal (no tokio runtime, no UDS listeners). Stdout
    // carries only the single JSON response line.
    if cli.enclave_child {
        let code = match oc_keyagent::enclave::run_enclave_child() {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("enclave child failed: {e}");
                1
            }
        };
        std::process::exit(code);
    }

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
            // Agent JSON single stream: success and failure both speak
            // stdout. With ONECIPHER_JSON_ERRORS=1 the failure is one JSON
            // object carrying the stable SCREAMING_SNAKE code (C10 keeps
            // the numeric sysexits mapping unchanged).
            if output::is_json_mode() {
                output::emit_error(&e.to_envelope());
            } else {
                eprintln!("error: {e}");
            }
            e.exit_code()
        }
    };

    // Explicitly zeroize all cached key material before exiting.
    oc_signer::global_key_cache().clear();
    std::process::exit(code);
}

fn dispatch_wallet(subcommand: cli::WalletCommands) -> Result<(), CliError> {
    match subcommand {
        cli::WalletCommands::Create { name, words, show_mnemonic } => {
            commands::wallet::create(&name, words, show_mnemonic)
        }
        cli::WalletCommands::Import { name, mnemonic, private_key, chain, index, interactive } => {
            if interactive {
                // Interactive import blocks on TTY prompts; refuse
                // explicitly under agent JSON mode.
                output::reject_interactive_if_json("wallet import --interactive")?;
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
        cli::WalletCommands::Delete { wallet, confirm, force } => {
            // Unified destructive-action contract: `--force` aliases `--confirm`.
            let confirmed = confirm || force;
            output::require_confirm(confirmed, &format!("delete wallet '{wallet}'"))?;
            commands::wallet::delete(&wallet, confirmed)
        }
        cli::WalletCommands::Rename { wallet, new_name } => {
            commands::wallet::rename(&wallet, &new_name)
        }
        cli::WalletCommands::List { json } => commands::wallet::list(json),
        cli::WalletCommands::Info => commands::info::run(),
        cli::WalletCommands::ChangePassword { wallet, passphrase, new_passphrase } => {
            commands::wallet::change_password(
                &wallet,
                passphrase.as_deref(),
                new_passphrase.as_deref(),
            )
        }
    }
}

fn dispatch_sign(subcommand: cli::SignCommands) -> Result<(), CliError> {
    match subcommand {
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
            commands::send_transaction::run(&chain, &wallet, &tx, index, json, rpc_url.as_deref())
        }
        cli::SignCommands::Auth { chain, wallet, address, nonce, index, json } => {
            commands::sign_auth::run(&chain, &wallet, &address, &nonce, index, json)
        }
    }
}

fn dispatch_mnemonic(subcommand: cli::MnemonicCommands) -> Result<(), CliError> {
    match subcommand {
        cli::MnemonicCommands::Generate { words } => commands::generate::run(words),
        cli::MnemonicCommands::Derive { chain, index, path, count, show_private_key } => {
            commands::derive::run(chain.as_deref(), index, path.as_deref(), count, show_private_key)
        }
    }
}

fn dispatch_policy(subcommand: cli::PolicyCommands) -> Result<(), CliError> {
    match subcommand {
        cli::PolicyCommands::Create { file } => commands::policy::create(&file),
        cli::PolicyCommands::List => commands::policy::list(),
        cli::PolicyCommands::Show { id } => commands::policy::show(&id),
        cli::PolicyCommands::Delete { id, confirm, force } => {
            let confirmed = confirm || force;
            output::require_confirm(confirmed, &format!("delete policy '{id}'"))?;
            commands::policy::delete(&id, confirmed)
        }
    }
}

fn dispatch_key(subcommand: cli::KeyCommands) -> Result<(), CliError> {
    match subcommand {
        cli::KeyCommands::Create { name, wallets, policies, expires_at } => {
            commands::key::create(&name, &wallets, &policies, expires_at.as_deref())
        }
        cli::KeyCommands::List => commands::key::list(),
        cli::KeyCommands::Revoke { id, confirm, force } => {
            let confirmed = confirm || force;
            output::require_confirm(confirmed, &format!("revoke API key '{id}'"))?;
            commands::key::revoke(&id, confirmed)
        }
    }
}

fn dispatch_config(subcommand: cli::ConfigCommands) -> Result<(), CliError> {
    match subcommand {
        cli::ConfigCommands::Show => commands::config::show(),
        cli::ConfigCommands::Set { key, value } => commands::config::set(&key, &value),
    }
}

fn dispatch_audit(subcommand: cli::AuditCommands) -> Result<(), CliError> {
    match subcommand {
        cli::AuditCommands::List { since, agent, status } => {
            commands::audit::list(since.as_deref(), agent.as_deref(), status.as_deref())
        }
        cli::AuditCommands::Secrets { format, max_age, skip_hibp } => {
            commands::audit_secrets::run(&format, max_age, skip_hibp)
        }
    }
}

fn dispatch_session_key(
    subcommand: cli::SessionKeyCommands,
    client: &dyn netagent::NetAgentClient,
) -> Result<(), CliError> {
    match subcommand {
        cli::SessionKeyCommands::Create { label, challenge, signature, credential_id } => {
            commands::session_key::create(&label, &challenge, &signature, &credential_id, client)
        }
        cli::SessionKeyCommands::Revoke { session_key_id, challenge, signature, credential_id } => {
            commands::session_key::revoke(
                &session_key_id,
                &challenge,
                &signature,
                &credential_id,
                client,
            )
        }
        cli::SessionKeyCommands::List => commands::session_key::list(client),
    }
}

fn dispatch_service(subcommand: cli::ServiceCommands) -> Result<(), CliError> {
    match subcommand {
        cli::ServiceCommands::Install => commands::service::install(),
        cli::ServiceCommands::Uninstall => commands::service::uninstall(),
        cli::ServiceCommands::Status => commands::service::status(),
    }
}

fn dispatch_vault(subcommand: cli::VaultCommands) -> Result<(), CliError> {
    match subcommand {
        cli::VaultCommands::Unlock => commands::vault::unlock(),
    }
}

fn dispatch_backup(subcommand: cli::BackupCommands) -> Result<(), CliError> {
    match subcommand {
        cli::BackupCommands::Export { out, recipients } => {
            commands::backup::export(&out, &recipients)
        }
        cli::BackupCommands::Import { r#in, identity } => {
            commands::backup::import(&r#in, identity.as_deref())
        }
    }
}

fn dispatch_sbom(subcommand: cli::SbomCommands) -> Result<(), CliError> {
    match subcommand {
        cli::SbomCommands::Verify { file } => commands::sbom::verify(&file),
        cli::SbomCommands::Generate { output } => commands::sbom::generate(&output),
    }
}

fn dispatch_wc(subcommand: cli::WcCommands) -> Result<(), CliError> {
    match subcommand {
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
            commands::wc::dapp_send(&topic, &method, &params, sym_key.as_deref(), url.as_deref())
        }
    }
}

fn dispatch_webui(subcommand: cli::WebUiCommands) -> Result<(), CliError> {
    match subcommand {
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
    }
}

fn dispatch_intent(subcommand: cli::IntentCommands) -> Result<(), CliError> {
    match subcommand {
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
    }
}

fn dispatch_secret(subcommand: cli::SecretCommands) -> Result<(), CliError> {
    match subcommand {
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
        cli::SecretCommands::Delete { name, force } => commands::secret::delete(&name, force),
        cli::SecretCommands::Rename { old, new } => commands::secret::rename(&old, &new),
        cli::SecretCommands::Edit { name, editor } => {
            // $EDITOR cannot run under agent JSON mode; refuse explicitly.
            output::reject_interactive_if_json("secret edit")?;
            commands::secret::edit(&name, editor.as_deref())
        }
        cli::SecretCommands::Copy { src, dst, force } => commands::secret::copy(&src, &dst, force),
        cli::SecretCommands::Move { src, dst, force } => commands::secret::mv(&src, &dst, force),
    }
}

fn dispatch_password(subcommand: cli::PasswordCommands) -> Result<(), CliError> {
    match subcommand {
        cli::PasswordCommands::Add { name, url, username, generate, length, symbols } => {
            commands::password::add(&name, &url, &username, generate, length, symbols)
        }
        cli::PasswordCommands::Get { name, copy, timeout, json } => {
            commands::password::get(&name, copy, timeout, json)
        }
        cli::PasswordCommands::Generate {
            length,
            symbols,
            generator,
            xkcd_sep,
            xkcd_words,
            qr,
        } => commands::password::generate(length, symbols, &generator, &xkcd_sep, xkcd_words, qr),
    }
}

fn dispatch_totp(subcommand: cli::TotpCommands) -> Result<(), CliError> {
    match subcommand {
        cli::TotpCommands::Add { name, otpauth, secret, issuer, account } => commands::totp::add(
            &name,
            otpauth.as_deref(),
            secret.as_deref(),
            issuer.as_deref(),
            account.as_deref(),
        ),
        cli::TotpCommands::Generate { name, qr, json } => commands::totp::generate(&name, qr, json),
        cli::TotpCommands::Uris { name, json } => commands::totp::uris(&name, json),
        cli::TotpCommands::Hotp { name, counter, increment, json } => {
            commands::totp::hotp(&name, counter, increment, json)
        }
    }
}

fn dispatch_age(subcommand: cli::AgeCommands) -> Result<(), CliError> {
    match subcommand {
        cli::AgeCommands::Init => commands::age_cmd::init(),
        cli::AgeCommands::Recipient { subcommand } => match subcommand {
            cli::AgeRecipientCommands::Add { bech32 } => commands::age_cmd::recipient_add(&bech32),
            cli::AgeRecipientCommands::List => commands::age_cmd::recipient_list(),
            cli::AgeRecipientCommands::Remove { bech32 } => {
                commands::age_cmd::recipient_remove(&bech32)
            }
        },
        cli::AgeCommands::IdentityShow => commands::age_cmd::identity_show(),
        cli::AgeCommands::Reencrypt => commands::age_cmd::reencrypt(),
    }
}

fn dispatch_agent_secret(subcommand: cli::AgentSecretCommands) -> Result<(), CliError> {
    match subcommand {
        cli::AgentSecretCommands::Get { name, json } => {
            commands::agent_secret::agent_secret_get(&name, json)
        }
        cli::AgentSecretCommands::List { json } => commands::agent_secret::agent_secret_list(json),
        cli::AgentSecretCommands::Totp { name } => {
            commands::agent_secret::agent_totp_generate(&name)
        }
    }
}

fn dispatch_wallet_rpc(subcommand: cli::WalletRpcCommands) -> Result<(), CliError> {
    match subcommand {
        cli::WalletRpcCommands::Serve { listen, wallet, index } => {
            commands::wallet_rpc::serve(&listen, &wallet, index)
        }
    }
}

#[cfg(feature = "git")]
fn dispatch_git(subcommand: cli::GitCommands) -> Result<(), CliError> {
    match subcommand {
        cli::GitCommands::Init { remote } => commands::git_cmd::init(remote.as_deref()),
        cli::GitCommands::Pull => commands::git_cmd::pull(),
        cli::GitCommands::Push => commands::git_cmd::push(),
        cli::GitCommands::Log { name } => commands::git_cmd::log(name.as_deref()),
        cli::GitCommands::Status => commands::git_cmd::status(),
    }
}

#[allow(clippy::too_many_arguments)]
fn dispatch_send(
    chain: String,
    to: String,
    token: String,
    amount: String,
    wallet: String,
    rpc_url: String,
    index: u32,
    gas_limit: Option<u64>,
    json: bool,
) -> Result<(), CliError> {
    commands::send::run(&chain, &wallet, &to, &token, &amount, &rpc_url, index, gas_limit, json)
}

fn dispatch_env(
    names: Vec<String>,
    set: Vec<String>,
    prompt: Vec<String>,
    keep_case: bool,
    exec: bool,
    command: Vec<String>,
) -> Result<(), CliError> {
    commands::env_cmd::run(&names, &set, &prompt, keep_case, exec, &command)
}

fn dispatch_tui() -> Result<(), CliError> {
    let store = commands::open_secret_store()?;
    tui::run(store).map_err(|e| CliError::InvalidArgs(e.to_string()))
}

fn dispatch_vanity(
    starts_with: Option<String>,
    ends_with: Option<String>,
    count: usize,
    jobs: Option<usize>,
    save_path: Option<std::path::PathBuf>,
    save_to_vault: bool,
) -> Result<(), CliError> {
    commands::vanity::run(
        starts_with.as_deref(),
        ends_with.as_deref(),
        count,
        jobs,
        save_path.as_deref(),
        save_to_vault,
    )
}

#[allow(clippy::too_many_arguments)]
fn dispatch_verify(
    address: String,
    message: Option<String>,
    typed_data: Option<String>,
    typed_data_file: Option<String>,
    hash: Option<String>,
    no_hash: bool,
    signature: String,
    chain: String,
) -> Result<(), CliError> {
    commands::verify::run(commands::verify::VerifyInput {
        address: &address,
        message: message.as_deref(),
        typed_data: typed_data.as_deref(),
        typed_data_file: typed_data_file.as_deref(),
        hash: hash.as_deref(),
        no_hash,
        signature: &signature,
        chain: &chain,
    })
}

fn run(cli: Cli, client: &dyn netagent::NetAgentClient) -> Result<(), CliError> {
    let Some(command) = cli.command else {
        return Ok(());
    };
    match command {
        Commands::Wallet { subcommand } => dispatch_wallet(subcommand),
        Commands::Sign { subcommand } => dispatch_sign(subcommand),
        Commands::Mnemonic { subcommand } => dispatch_mnemonic(subcommand),
        Commands::Policy { subcommand } => dispatch_policy(subcommand),
        Commands::Key { subcommand } => dispatch_key(subcommand),
        Commands::Config { subcommand } => dispatch_config(subcommand),
        Commands::Audit { subcommand } => dispatch_audit(subcommand),
        Commands::SessionKey { subcommand } => dispatch_session_key(subcommand, client),
        Commands::Service { subcommand } => dispatch_service(subcommand),
        Commands::Vault { subcommand } => dispatch_vault(subcommand),
        Commands::Backup { subcommand } => dispatch_backup(subcommand),
        Commands::Sbom { subcommand } => dispatch_sbom(subcommand),
        Commands::Wc { subcommand } => dispatch_wc(subcommand),
        Commands::Webui { subcommand } => dispatch_webui(subcommand),
        Commands::Intent { subcommand } => dispatch_intent(subcommand),
        Commands::Secret { subcommand } => dispatch_secret(subcommand),
        Commands::Password { subcommand } => dispatch_password(subcommand),
        Commands::Totp { subcommand } => dispatch_totp(subcommand),
        Commands::Age { subcommand } => dispatch_age(subcommand),
        Commands::AgentSecret { subcommand } => dispatch_agent_secret(subcommand),
        Commands::WalletRpc { subcommand } => dispatch_wallet_rpc(subcommand),
        Commands::Vanity { starts_with, ends_with, count, jobs, save_path, save_to_vault } => {
            dispatch_vanity(starts_with, ends_with, count, jobs, save_path, save_to_vault)
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
        } => dispatch_verify(
            address,
            message,
            typed_data,
            typed_data_file,
            hash,
            no_hash,
            signature,
            chain,
        ),
        Commands::Update { force } => commands::update::run(force),
        Commands::Uninstall { purge, force } => commands::uninstall::run(purge, force),
        Commands::Status => commands::status::run(),
        Commands::Migrate { dry_run, rollback } => commands::migrate::run(dry_run, rollback),
        Commands::Grep { pattern, regex, json } => commands::grep::run(&pattern, regex, json),
        Commands::Find { query, regex, json, r#type } => {
            commands::find::run(query.as_deref(), regex, json, r#type.as_deref())
        }
        Commands::Tui => {
            // The fullscreen TUI cannot speak the single-object JSON
            // stream; refuse explicitly instead of hanging the agent.
            output::reject_interactive_if_json("tui")?;
            dispatch_tui()
        }
        Commands::Doctor { verbose, json, repair_generations } => {
            commands::doctor::run_ext(verbose, json, repair_generations)
        }
        Commands::Fsck { fix, decrypt } => commands::fsck::run(fix, decrypt),
        Commands::Completion { shell } => commands::completion::run(&shell),
        Commands::Env { names, set, prompt, keep_case, exec, command } => {
            dispatch_env(names, set, prompt, keep_case, exec, command)
        }
        Commands::Send { chain, to, token, amount, wallet, rpc_url, index, gas_limit, json } => {
            dispatch_send(chain, to, token, amount, wallet, rpc_url, index, gas_limit, json)
        }
        #[cfg(feature = "git")]
        Commands::History { name, password, limit, json } => {
            commands::history::run(&name, password, limit, json)
        }
        #[cfg(feature = "git")]
        Commands::Git { subcommand } => dispatch_git(subcommand),
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
