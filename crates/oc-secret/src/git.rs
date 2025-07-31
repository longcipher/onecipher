//! Git integration for the secrets vault.
//!
//! The secrets directory can optionally be a git repository for version
//! control and multi-device sync. This module provides thin wrappers
//! around libgit2 for commit, push, pull, and history operations.
//!
//! Design borrows from ripasso but is simplified:
//! - No commit signing (the audit chain already provides tamper evidence).
//! - Merge strategy instead of rebase (avoids history rewriting).
//! - Conflicts are surfaced as errors for manual resolution.
//!
//! # Hard-gate compliance
//!
//! `git2` is a synchronous C binding (libgit2 + libssh2 + zlib/openssl).
//! It does NOT pull in `tokio`, `reqwest`, `tungstenite`, `hyper`,
//! `async-std`, or `smol` — R56 is satisfied.

use std::path::{Path, PathBuf};

use thiserror::Error;

/// Errors returned by git operations.
#[derive(Debug, Error)]
pub enum GitError {
    /// Underlying libgit2 error.
    #[error("git error: {0}")]
    Git(#[from] git2::Error),
    /// The directory is not inside a git repository.
    #[error("not a git repository: {0}")]
    NotARepo(PathBuf),
    /// No remote named "origin" is configured.
    #[error("no remote 'origin' configured")]
    NoOrigin,
    /// A merge conflict was detected during pull.
    #[error("merge conflict: {0}")]
    MergeConflict(String),
    /// I/O error.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, GitError>;

/// A single entry in the commit history of a file (or the whole repo).
#[derive(Debug, Clone)]
pub struct FileHistoryEntry {
    /// Full commit OID (hex string).
    pub oid: String,
    /// Author name (from the commit signature).
    pub author: String,
    /// Unix timestamp (seconds since epoch).
    pub time: i64,
    /// Commit message.
    pub message: String,
}

/// A single working-tree status entry.
#[derive(Debug, Clone)]
pub struct StatusEntry {
    /// Path relative to the repository root.
    pub path: String,
    /// Human-readable status: "new", "modified", "deleted", "renamed", "unknown".
    pub status: String,
}

// ── Repository discovery & initialization ─────────────────────────────

/// Check if the given directory is inside a git repository.
///
/// The path is canonicalized first to resolve symlinks (macOS `/var` →
/// `/private/var`), which `Repository::discover` may not follow.
pub fn is_git_repo(dir: &Path) -> bool {
    let canonical = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
    git2::Repository::discover(&canonical).is_ok()
}

/// Initialize a git repository in the given directory.
pub fn init_repo(dir: &Path) -> Result<git2::Repository> {
    let repo = git2::Repository::init(dir)?;
    Ok(repo)
}

/// Open (discover) the git repository containing `dir`.
///
/// The path is canonicalized first to resolve symlinks (macOS `/var` →
/// `/private/var`), which `Repository::discover` may not follow.
pub fn repo_for_secrets(dir: &Path) -> Result<git2::Repository> {
    let canonical = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
    git2::Repository::discover(&canonical).map_err(|_| GitError::NotARepo(dir.to_path_buf()))
}

// ── Commit ────────────────────────────────────────────────────────────

/// Add paths to the index and create a commit.
///
/// `paths` are relative to the repository working directory. Files that
/// no longer exist on disk are staged as deletions (via `remove_path`),
/// which supports delete + rename operations.
///
/// If the resulting tree is identical to the parent's tree, no commit is
/// created and the parent's OID is returned (avoids empty commits).
pub fn add_and_commit(repo: &git2::Repository, paths: &[&str], message: &str) -> Result<git2::Oid> {
    // 1. Stage each path — add existing files, remove deleted ones.
    let mut index = repo.index()?;
    let workdir = repo.workdir();
    for path in paths {
        let p = Path::new(path);
        let exists = workdir.is_some_and(|wd| wd.join(p).exists());
        if exists {
            index.add_path(p)?;
        } else {
            // File was deleted — stage the removal. Ignore errors for
            // paths that were never tracked.
            let _ = index.remove_path(p);
        }
    }
    index.write()?;

    // 2. Write tree from the staged index.
    let tree_id = index.write_tree()?;
    let tree = repo.find_tree(tree_id)?;

    // 3. Get parent commit (if any).
    let head_commit = repo.head().ok().and_then(|h| h.peel_to_commit().ok());

    // 4. Skip empty commits — if the tree hasn't changed, return parent.
    if let Some(ref parent) = head_commit {
        let parent_tree = parent.tree()?;
        if parent_tree.id() == tree_id {
            return Ok(parent.id());
        }
    }

    // 5. Create the commit.
    let parents: Vec<&git2::Commit<'_>> = head_commit.iter().collect();
    let sig = repo.signature()?;

    let oid = repo.commit(Some("HEAD"), &sig, &sig, message, &tree, &parents)?;

    Ok(oid)
}

/// Auto-commit changes in the secrets vault.
///
/// Called after `put`/`delete`/`rename` operations. If the vault root is
/// not a git repository, this is a silent no-op. `abs_paths` are absolute
/// paths to the files that changed; they are converted to repo-relative
/// paths internally so the function works regardless of where the `.git`
/// directory lives.
pub fn auto_commit(vault_root: &Path, abs_paths: &[&Path], message: &str) -> Result<()> {
    if !is_git_repo(vault_root) {
        return Ok(());
    }
    let repo = repo_for_secrets(vault_root)?;
    let workdir = repo.workdir().ok_or_else(|| {
        GitError::Git(git2::Error::from_str("bare repository has no working directory"))
    })?;

    let mut rel_paths: Vec<String> = Vec::with_capacity(abs_paths.len());
    for abs in abs_paths {
        let rel = relative_to_workdir(abs, workdir)?;
        rel_paths.push(rel);
    }
    let rel_refs: Vec<&str> = rel_paths.iter().map(String::as_str).collect();
    add_and_commit(&repo, &rel_refs, message)?;
    Ok(())
}

/// Compute the path of `abs` relative to the repository `workdir`.
///
/// Paths are canonicalized to resolve symlinks (macOS `/var` →
/// `/private/var`). For files that no longer exist on disk (deletions,
/// renames), the parent directory is canonicalized instead and the file
/// name is re-joined.
fn relative_to_workdir(abs: &Path, workdir: &Path) -> Result<String> {
    let canonical = if let Ok(c) = std::fs::canonicalize(abs) {
        c
    } else {
        // File may not exist (deleted/renamed). Canonicalize the parent
        // directory (which should still exist) and re-join the file name.
        let parent = abs.parent().ok_or_else(|| GitError::NotARepo(workdir.to_path_buf()))?;
        let canon_parent =
            std::fs::canonicalize(parent).map_err(|_| GitError::NotARepo(workdir.to_path_buf()))?;
        let file_name = abs.file_name().ok_or_else(|| GitError::NotARepo(workdir.to_path_buf()))?;
        canon_parent.join(file_name)
    };
    let rel =
        canonical.strip_prefix(workdir).map_err(|_| GitError::NotARepo(workdir.to_path_buf()))?;
    Ok(rel.to_string_lossy().into_owned())
}

// ── Push & Pull ───────────────────────────────────────────────────────

/// Credential callback for SSH/HTTPS remotes.
///
/// Tries the SSH agent first, then falls back to a plain username. This
/// mirrors ripasso's approach but uses `USER` env var instead of pulling
/// in the `whoami` crate.
fn cred_helper(
    tried_sshkey: &mut bool,
    _url: &str,
    username: Option<&str>,
    allowed: git2::CredentialType,
) -> std::result::Result<git2::Cred, git2::Error> {
    let user = username.unwrap_or("git");

    if allowed.contains(git2::CredentialType::USERNAME) {
        return git2::Cred::username(user);
    }

    if *tried_sshkey {
        return Err(git2::Error::from_str("no authentication available"));
    }
    *tried_sshkey = true;
    git2::Cred::ssh_key_from_agent(user)
}

/// Push the current branch to `origin`.
pub fn push(repo: &git2::Repository) -> Result<()> {
    let mut origin = repo.find_remote("origin").map_err(|_| GitError::NoOrigin)?;

    let head = repo.head()?;
    let branch_name = head.shorthand().unwrap_or("master");

    let refspec = format!("refs/heads/{branch_name}:refs/heads/{branch_name}");

    let mut callbacks = git2::RemoteCallbacks::new();
    let mut tried_sshkey = false;
    callbacks.credentials(|url, user, allowed| cred_helper(&mut tried_sshkey, url, user, allowed));
    callbacks.push_update_reference(|_refname, status| {
        if let Some(s) = status {
            return Err(git2::Error::from_str(&format!("push rejected: {s}")));
        }
        Ok(())
    });

    let mut opts = git2::PushOptions::new();
    opts.remote_callbacks(callbacks);
    origin.push(&[&refspec], Some(&mut opts))?;

    Ok(())
}

/// Pull from `origin` using a merge strategy (not rebase).
///
/// - If local and remote are at the same commit → no-op.
/// - If local is behind only → fast-forward.
/// - If diverged → attempt a merge commit.
/// - If conflicts → return [`GitError::MergeConflict`].
pub fn pull(repo: &git2::Repository) -> Result<()> {
    let mut origin = repo.find_remote("origin").map_err(|_| GitError::NoOrigin)?;

    // 1. Fetch with credential callbacks.
    let mut callbacks = git2::RemoteCallbacks::new();
    let mut tried_sshkey = false;
    callbacks.credentials(|url, user, allowed| cred_helper(&mut tried_sshkey, url, user, allowed));

    let mut fetch_opts = git2::FetchOptions::new();
    fetch_opts.remote_callbacks(callbacks);
    origin.fetch(&["refs/heads/*:refs/remotes/origin/*"], Some(&mut fetch_opts), None)?;

    // 2. Resolve local and remote commits.
    let head = repo.head()?;
    let local_commit = head.peel_to_commit()?;
    let branch_name = head.shorthand().unwrap_or("master");

    let remote_ref = format!("refs/remotes/origin/{branch_name}");
    let remote_commit = repo.revparse_single(&remote_ref)?.peel_to_commit()?;

    // 3. Already up to date.
    if local_commit.id() == remote_commit.id() {
        return Ok(());
    }

    // 4. Compute ahead/behind.
    let (ahead, behind) = repo.graph_ahead_behind(local_commit.id(), remote_commit.id())?;

    // 5. Behind only — fast-forward.
    if behind > 0 && ahead == 0 {
        repo.checkout_tree(remote_commit.as_object(), None)?;
        let mut head_ref = repo.head()?;
        head_ref.set_target(remote_commit.id(), "fast-forward")?;
        return Ok(());
    }

    // 6. Diverged — attempt merge.
    if ahead > 0 && behind > 0 {
        let mut index = repo.merge_commits(&local_commit, &remote_commit, None)?;
        if index.has_conflicts() {
            return Err(GitError::MergeConflict(
                "merge conflicts detected, resolve manually".into(),
            ));
        }
        let tree_id = index.write_tree_to(repo)?;
        let tree = repo.find_tree(tree_id)?;
        let sig = repo.signature()?;
        repo.commit(
            Some("HEAD"),
            &sig,
            &sig,
            "Merge remote-tracking branch",
            &tree,
            &[&local_commit, &remote_commit],
        )?;
        return Ok(());
    }

    // 7. Local is ahead only — nothing to do.
    Ok(())
}

// ── History ───────────────────────────────────────────────────────────

/// Get the full commit history (newest first).
pub fn history(repo: &git2::Repository) -> Result<Vec<FileHistoryEntry>> {
    let mut revwalk = repo.revwalk()?;
    revwalk.push_head()?;
    revwalk.set_sorting(git2::Sort::TOPOLOGICAL)?;

    let mut entries = Vec::new();
    for oid_result in revwalk {
        let oid = oid_result?;
        let commit = repo.find_commit(oid)?;
        entries.push(FileHistoryEntry {
            oid: oid.to_string(),
            author: commit.author().name().unwrap_or("").to_string(),
            time: commit.time().seconds(),
            message: commit.message().unwrap_or("").to_string(),
        });
    }
    Ok(entries)
}

/// Get commit history for a specific file (newest first).
///
/// Walks the commit graph and diffs each commit against its parent to
/// determine whether the file was touched. For the initial commit (no
/// parent), the file is considered touched if it exists in the tree.
pub fn file_history(repo: &git2::Repository, file_path: &str) -> Result<Vec<FileHistoryEntry>> {
    let mut revwalk = repo.revwalk()?;
    revwalk.push_head()?;
    revwalk.set_sorting(git2::Sort::TOPOLOGICAL)?;

    let mut entries = Vec::new();
    for oid_result in revwalk {
        let oid = oid_result?;
        let commit = repo.find_commit(oid)?;

        let tree = commit.tree()?;
        let parent_tree = commit.parent(0).ok().map(|p| p.tree()).transpose()?;

        let diff = repo.diff_tree_to_tree(parent_tree.as_ref(), Some(&tree), None)?;

        let mut touched = false;
        for delta in diff.deltas() {
            if delta.old_file().path() == Some(Path::new(file_path)) ||
                delta.new_file().path() == Some(Path::new(file_path))
            {
                touched = true;
                break;
            }
        }

        if touched {
            entries.push(FileHistoryEntry {
                oid: oid.to_string(),
                author: commit.author().name().unwrap_or("").to_string(),
                time: commit.time().seconds(),
                message: commit.message().unwrap_or("").to_string(),
            });
        }
    }

    Ok(entries)
}

// ── Status ────────────────────────────────────────────────────────────

/// Get the working-tree status entries.
pub fn status_entries(repo: &git2::Repository) -> Result<Vec<StatusEntry>> {
    let statuses = repo.statuses(None)?;

    let mut entries = Vec::new();
    for entry in statuses.iter() {
        let path = entry.path().unwrap_or("").to_string();
        let s = entry.status();
        let status = if s.contains(git2::Status::INDEX_NEW) || s.contains(git2::Status::WT_NEW) {
            "new"
        } else if s.contains(git2::Status::INDEX_MODIFIED) || s.contains(git2::Status::WT_MODIFIED)
        {
            "modified"
        } else if s.contains(git2::Status::INDEX_DELETED) || s.contains(git2::Status::WT_DELETED) {
            "deleted"
        } else if s.contains(git2::Status::INDEX_RENAMED) || s.contains(git2::Status::WT_RENAMED) {
            "renamed"
        } else {
            "unknown"
        };
        entries.push(StatusEntry { path, status: status.to_string() });
    }
    Ok(entries)
}

// ── Remote management ─────────────────────────────────────────────────

/// Set (or replace) a remote URL.
pub fn set_remote(dir: &Path, name: &str, url: &str) -> Result<()> {
    let repo = repo_for_secrets(dir)?;
    // Delete existing remote if present (ignore error if not found).
    let _ = repo.remote_delete(name);
    repo.remote(name, url)?;
    Ok(())
}

// ── Convenience wrappers (directory-based, no git2 types leaked) ──────

/// Initialize a git repository at `dir` if one doesn't already exist.
pub fn init_at(dir: &Path) -> Result<()> {
    if is_git_repo(dir) {
        return Ok(());
    }
    init_repo(dir).map(|_| ())
}

/// Push from the repository containing `dir`.
pub fn push_at(dir: &Path) -> Result<()> {
    let repo = repo_for_secrets(dir)?;
    push(&repo)
}

/// Pull into the repository containing `dir`.
pub fn pull_at(dir: &Path) -> Result<()> {
    let repo = repo_for_secrets(dir)?;
    pull(&repo)
}

/// Full commit history for the repository containing `dir`.
pub fn history_at(dir: &Path) -> Result<Vec<FileHistoryEntry>> {
    let repo = repo_for_secrets(dir)?;
    history(&repo)
}

/// File history for the repository containing `dir`.
pub fn file_history_at(dir: &Path, file_path: &str) -> Result<Vec<FileHistoryEntry>> {
    let repo = repo_for_secrets(dir)?;
    file_history(&repo, file_path)
}

/// Working-tree status for the repository containing `dir`.
pub fn status_at(dir: &Path) -> Result<Vec<StatusEntry>> {
    let repo = repo_for_secrets(dir)?;
    status_entries(&repo)
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    /// Configure a local git identity so commits succeed without a global config.
    fn set_test_identity(repo: &git2::Repository) {
        let mut config = repo.config().unwrap();
        config.set_str("user.name", "Test User").unwrap();
        config.set_str("user.email", "test@example.com").unwrap();
    }

    #[test]
    fn is_git_repo_false_for_plain_dir() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!is_git_repo(dir.path()));
    }

    #[test]
    fn init_repo_creates_repository() {
        let dir = tempfile::tempdir().unwrap();
        let repo = init_repo(dir.path()).unwrap();
        assert!(repo.workdir().is_some());
        assert!(is_git_repo(dir.path()));
    }

    #[test]
    fn repo_for_secrets_finds_repo() {
        let dir = tempfile::tempdir().unwrap();
        init_repo(dir.path()).unwrap();
        let repo = repo_for_secrets(dir.path()).unwrap();
        assert!(repo.workdir().is_some());
    }

    #[test]
    fn repo_for_secrets_finds_parent_repo() {
        let dir = tempfile::tempdir().unwrap();
        init_repo(dir.path()).unwrap();
        let subdir = dir.path().join("secrets");
        fs::create_dir_all(&subdir).unwrap();
        // discover() should walk up from subdir to the repo root.
        let repo = repo_for_secrets(&subdir).unwrap();
        assert!(repo.workdir().is_some());
    }

    #[test]
    fn add_and_commit_creates_initial_commit() {
        let dir = tempfile::tempdir().unwrap();
        let repo = init_repo(dir.path()).unwrap();
        set_test_identity(&repo);

        let file = dir.path().join("test.txt");
        fs::write(&file, "hello").unwrap();

        let oid = add_and_commit(&repo, &["test.txt"], "initial commit").unwrap();
        assert!(!oid.is_zero());
    }

    #[test]
    fn add_and_commit_creates_second_commit() {
        let dir = tempfile::tempdir().unwrap();
        let repo = init_repo(dir.path()).unwrap();
        set_test_identity(&repo);

        let file = dir.path().join("test.txt");
        fs::write(&file, "v1").unwrap();
        let first = add_and_commit(&repo, &["test.txt"], "first").unwrap();

        fs::write(&file, "v2").unwrap();
        let second = add_and_commit(&repo, &["test.txt"], "second").unwrap();

        assert_ne!(first, second);
    }

    #[test]
    fn add_and_commit_skips_empty_commit() {
        let dir = tempfile::tempdir().unwrap();
        let repo = init_repo(dir.path()).unwrap();
        set_test_identity(&repo);

        fs::write(dir.path().join("a.txt"), "content").unwrap();
        let first = add_and_commit(&repo, &["a.txt"], "first").unwrap();

        // Commit again without changes — should return the same OID.
        let second = add_and_commit(&repo, &["a.txt"], "no-op").unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn add_and_commit_handles_deletion() {
        let dir = tempfile::tempdir().unwrap();
        let repo = init_repo(dir.path()).unwrap();
        set_test_identity(&repo);

        fs::write(dir.path().join("gone.txt"), "content").unwrap();
        add_and_commit(&repo, &["gone.txt"], "add").unwrap();

        fs::remove_file(dir.path().join("gone.txt")).unwrap();
        let oid = add_and_commit(&repo, &["gone.txt"], "delete").unwrap();
        assert!(!oid.is_zero());

        // Verify the file is gone in the tree.
        let head = repo.head().unwrap();
        let commit = head.peel_to_commit().unwrap();
        let tree = commit.tree().unwrap();
        assert!(tree.get_name("gone.txt").is_none());
    }

    #[test]
    fn auto_commit_noop_without_repo() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("test.txt");
        fs::write(&file, "content").unwrap();
        // Should succeed silently (no repo).
        auto_commit(dir.path(), &[&file], "test").unwrap();
    }

    #[test]
    fn auto_commit_commits_changes() {
        let dir = tempfile::tempdir().unwrap();
        let repo = init_repo(dir.path()).unwrap();
        set_test_identity(&repo);

        let file = dir.path().join("secrets").join("github.age");
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(&file, "encrypted").unwrap();

        auto_commit(dir.path(), &[&file], "Add secret: github").unwrap();

        let entries = history(&repo).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].message, "Add secret: github");
    }

    #[test]
    fn history_returns_newest_first() {
        let dir = tempfile::tempdir().unwrap();
        let repo = init_repo(dir.path()).unwrap();
        set_test_identity(&repo);

        for i in 0..3 {
            fs::write(dir.path().join("f.txt"), format!("v{i}")).unwrap();
            add_and_commit(&repo, &["f.txt"], &format!("commit {i}")).unwrap();
        }

        let entries = history(&repo).unwrap();
        assert_eq!(entries.len(), 3);
        // Newest first.
        assert_eq!(entries[0].message, "commit 2");
        assert_eq!(entries[1].message, "commit 1");
        assert_eq!(entries[2].message, "commit 0");
    }

    #[test]
    fn file_history_filters_by_file() {
        let dir = tempfile::tempdir().unwrap();
        let repo = init_repo(dir.path()).unwrap();
        set_test_identity(&repo);

        fs::write(dir.path().join("a.txt"), "a").unwrap();
        add_and_commit(&repo, &["a.txt"], "add a").unwrap();

        fs::write(dir.path().join("b.txt"), "b").unwrap();
        add_and_commit(&repo, &["b.txt"], "add b").unwrap();

        fs::write(dir.path().join("a.txt"), "a2").unwrap();
        add_and_commit(&repo, &["a.txt"], "update a").unwrap();

        let a_history = file_history(&repo, "a.txt").unwrap();
        assert_eq!(a_history.len(), 2);
        assert_eq!(a_history[0].message, "update a");
        assert_eq!(a_history[1].message, "add a");

        let b_history = file_history(&repo, "b.txt").unwrap();
        assert_eq!(b_history.len(), 1);
        assert_eq!(b_history[0].message, "add b");
    }

    #[test]
    fn status_entries_shows_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let repo = init_repo(dir.path()).unwrap();
        set_test_identity(&repo);

        fs::write(dir.path().join("tracked.txt"), "content").unwrap();
        add_and_commit(&repo, &["tracked.txt"], "add").unwrap();

        fs::write(dir.path().join("untracked.txt"), "new").unwrap();
        fs::write(dir.path().join("tracked.txt"), "modified").unwrap();

        let entries = status_entries(&repo).unwrap();
        assert!(entries.iter().any(|e| e.path == "untracked.txt" && e.status == "new"));
        assert!(entries.iter().any(|e| e.path == "tracked.txt" && e.status == "modified"));
    }

    #[test]
    fn set_remote_creates_origin() {
        let dir = tempfile::tempdir().unwrap();
        init_repo(dir.path()).unwrap();

        set_remote(dir.path(), "origin", "https://example.com/repo.git").unwrap();

        let repo = repo_for_secrets(dir.path()).unwrap();
        let origin = repo.find_remote("origin").unwrap();
        assert_eq!(origin.url().unwrap(), "https://example.com/repo.git");
    }

    #[test]
    fn set_remote_replaces_existing() {
        let dir = tempfile::tempdir().unwrap();
        init_repo(dir.path()).unwrap();

        set_remote(dir.path(), "origin", "https://old.example.com").unwrap();
        set_remote(dir.path(), "origin", "https://new.example.com").unwrap();

        let repo = repo_for_secrets(dir.path()).unwrap();
        let origin = repo.find_remote("origin").unwrap();
        assert_eq!(origin.url().unwrap(), "https://new.example.com");
    }

    #[test]
    fn push_and_pull_with_bare_remote() {
        // Set up a bare repo to act as the "remote".
        let remote_dir = tempfile::tempdir().unwrap();
        let bare_repo = git2::Repository::init_bare(remote_dir.path()).unwrap();

        // Create a working repo and add the bare repo as origin.
        let local_dir = tempfile::tempdir().unwrap();
        let repo = init_repo(local_dir.path()).unwrap();
        set_test_identity(&repo);
        let bare_path = remote_dir.path().to_string_lossy().to_string();
        repo.remote("origin", &bare_path).unwrap();

        // Make a commit and push.
        fs::write(local_dir.path().join("secret.age"), "encrypted").unwrap();
        add_and_commit(&repo, &["secret.age"], "initial").unwrap();

        let head_oid = repo.head().unwrap().target().unwrap();
        push(&repo).unwrap();

        // Verify the bare repo received the commit.
        let bare_head = bare_repo.head().unwrap();
        let bare_oid = bare_head.target().unwrap();
        assert_eq!(bare_oid, head_oid);

        // Create a second clone and make a commit, push it.
        let second_dir = tempfile::tempdir().unwrap();
        let second_repo = git2::Repository::clone(&bare_path, second_dir.path()).unwrap();
        set_test_identity(&second_repo);

        // The clone's default branch might be "master" or "main".
        let second_branch = second_repo.head().unwrap().shorthand().unwrap().to_string();
        fs::write(second_dir.path().join("second.age"), "data").unwrap();
        add_and_commit(&second_repo, &["second.age"], "second commit").unwrap();
        push(&second_repo).unwrap();

        // Pull in the first repo — should get the second commit via fast-forward.
        pull(&repo).unwrap();

        let entries = history(&repo).unwrap();
        assert!(entries.iter().any(|e| e.message == "second commit"));
        assert!(entries.iter().any(|e| e.message == "initial"));

        // The second file should now exist locally.
        assert!(local_dir.path().join("second.age").exists());

        // Avoid unused variable warning for second_branch.
        let _ = second_branch;
    }

    #[test]
    fn pull_noop_when_up_to_date() {
        let remote_dir = tempfile::tempdir().unwrap();
        let _bare_repo = git2::Repository::init_bare(remote_dir.path()).unwrap();

        let local_dir = tempfile::tempdir().unwrap();
        let repo = init_repo(local_dir.path()).unwrap();
        set_test_identity(&repo);
        let bare_path = remote_dir.path().to_string_lossy().to_string();
        repo.remote("origin", &bare_path).unwrap();

        fs::write(local_dir.path().join("f.txt"), "content").unwrap();
        add_and_commit(&repo, &["f.txt"], "initial").unwrap();
        push(&repo).unwrap();

        // Pull immediately — should be a no-op.
        pull(&repo).unwrap();
    }

    #[test]
    fn convenience_wrappers_work() {
        let dir = tempfile::tempdir().unwrap();
        init_at(dir.path()).unwrap();
        assert!(is_git_repo(dir.path()));

        // init_at is idempotent.
        init_at(dir.path()).unwrap();

        let repo = repo_for_secrets(dir.path()).unwrap();
        set_test_identity(&repo);

        fs::write(dir.path().join("f.txt"), "v1").unwrap();
        add_and_commit(&repo, &["f.txt"], "first").unwrap();

        let hist = history_at(dir.path()).unwrap();
        assert_eq!(hist.len(), 1);

        let fh = file_history_at(dir.path(), "f.txt").unwrap();
        assert_eq!(fh.len(), 1);

        let st = status_at(dir.path()).unwrap();
        assert!(st.is_empty()); // clean working tree
    }
}
