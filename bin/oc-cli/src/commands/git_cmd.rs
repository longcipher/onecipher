//! Git sync commands for the secrets vault.
//!
//! Provides `onecipher git init|push|pull|log|status` subcommands that
//! operate on the vault root (`~/.onecipher` by default). All git
//! operations go through `oc_secret::git` — no direct `git2` dependency
//! is needed in the CLI crate.

use oc_core::Config;
use oc_secret::git;

use crate::CliError;

/// Resolve the vault root path (where the `.git` directory lives).
fn vault_root() -> std::path::PathBuf {
    Config::default().vault_path
}

/// `onecipher git init [--remote <url>]`
///
/// Initialize a git repository in the vault root. If `--remote` is given,
/// the URL is set as the `origin` remote.
pub(crate) fn init(remote: Option<&str>) -> Result<(), CliError> {
    let root = vault_root();
    if git::is_git_repo(&root) {
        eprintln!("git: repository already exists at {}", root.display());
    } else {
        git::init_at(&root)?;
        eprintln!("git: initialized repository at {}", root.display());
    }
    if let Some(url) = remote {
        git::set_remote(&root, "origin", url)?;
        eprintln!("git: set remote 'origin' -> {url}");
    }
    Ok(())
}

/// `onecipher git pull`
///
/// Fetch from `origin` and merge into the current branch.
pub(crate) fn pull() -> Result<(), CliError> {
    let root = vault_root();
    git::pull_at(&root)?;
    eprintln!("git: pull complete");
    Ok(())
}

/// `onecipher git push`
///
/// Push the current branch to `origin`.
pub(crate) fn push() -> Result<(), CliError> {
    let root = vault_root();
    git::push_at(&root)?;
    eprintln!("git: push complete");
    Ok(())
}

/// `onecipher git log [--name <secret>]`
///
/// Show commit history. If `--name` is given, only show commits that
/// touched the corresponding `secrets/<name>.age` file.
pub(crate) fn log(name: Option<&str>) -> Result<(), CliError> {
    let root = vault_root();
    let entries = if let Some(n) = name {
        let path = format!("secrets/{n}.age");
        git::file_history_at(&root, &path)?
    } else {
        git::history_at(&root)?
    };

    if entries.is_empty() {
        if let Some(n) = name {
            eprintln!("git: no history for '{n}'");
        } else {
            eprintln!("git: no commits yet");
        }
        return Ok(());
    }

    for e in &entries {
        let short: &str = e.oid.get(..7).unwrap_or(&e.oid);
        eprintln!("{short}  {author}  {msg}", author = e.author, msg = e.message.trim());
    }
    Ok(())
}

/// `onecipher git status`
///
/// Show the working-tree status (new, modified, deleted files).
pub(crate) fn status() -> Result<(), CliError> {
    let root = vault_root();
    let entries = git::status_at(&root)?;

    if entries.is_empty() {
        eprintln!("git: working tree clean");
        return Ok(());
    }

    for e in &entries {
        eprintln!("{:<10} {}", e.status, e.path);
    }
    Ok(())
}
