//! Ownership / type / permission verification for the Key-Agent UDS socket.
//!
//! [`crate::server::run`] creates the socket directory and the socket node
//! with owner-only modes, but creation alone is not verification:
//! `create_dir_all` succeeds silently on a *pre-existing* directory, and
//! `chmod` cannot repair ownership. On a shared system a co-resident user
//! could therefore pre-create a permissive directory — or a symlink, or a
//! regular file — at the predictable socket path, then read signing
//! requests or plant a fake agent.
//!
//! This module closes that gap with the same defence pago
//! (`agent.go: checkDirSecurity` / `checkSocketSecurity`) uses: before
//! *using* a socket path, verify via `Lstat` (which does not follow
//! symlinks) that
//!
//! 1. the parent directory is a real directory — not a symlink,
//! 2. it is owned by the current user,
//! 3. it grants no access to group or other,
//! 4. the socket node itself is a Unix domain socket with the same ownership and no group/other
//!    access.
//!
//! Threat-model scope: OneCipher does not defend against an attacker
//! running code as the same UID; these checks defend against *co-resident*
//! users on a shared system. Anything stronger (MAC, socket activation)
//! belongs to the deployment, not the binary.

#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::Path;

use crate::error::KeyAgentError;

/// The real user id of this process.
///
/// `getuid(2)` cannot fail and dereferences nothing. On non-Unix platforms
/// the concept does not exist and `0` is returned so callers compile; the
/// verification functions below are no-ops there.
#[cfg(unix)]
pub(crate) fn current_uid() -> u64 {
    #[allow(unsafe_code)]
    // SAFETY: `libc::getuid()` takes no arguments, cannot fail, and only
    // reads the process's real user id.
    unsafe {
        u64::from(libc::getuid())
    }
}

/// Non-Unix stub: no user ids, no socket ownership semantics.
#[cfg(not(unix))]
pub(crate) fn current_uid() -> u64 {
    0
}

/// Verify that `dir` is a real directory owned by the current user with no
/// group/other access.
///
/// Uses `symlink_metadata` (the `Lstat` equivalent) so a symlink at the
/// path is rejected rather than followed. Call this after creating the
/// directory (creation fixes the mode of directories we own) and before
/// binding a socket inside it.
///
/// # Errors
///
/// Returns [`KeyAgentError::SocketSecurity`] when the path is missing, is
/// not a directory, is owned by another user, or is accessible to
/// group/other.
#[cfg(unix)]
pub fn verify_socket_dir(dir: &Path) -> Result<(), KeyAgentError> {
    let meta = std::fs::symlink_metadata(dir).map_err(|e| {
        KeyAgentError::SocketSecurity(format!(
            "cannot stat socket directory {}: {e}",
            dir.display()
        ))
    })?;

    // `is_dir()` on `symlink_metadata` output is false for a symlink, even
    // one pointing at a directory — exactly the check we want.
    if !meta.is_dir() {
        return Err(KeyAgentError::SocketSecurity(format!(
            "socket directory {} is not a directory (symlink or special file)",
            dir.display()
        )));
    }

    let uid = u64::from(meta.uid());
    if uid != current_uid() {
        return Err(KeyAgentError::SocketSecurity(format!(
            "socket directory {} is owned by uid {uid}, expected uid {}",
            dir.display(),
            current_uid()
        )));
    }

    let mode = meta.mode();
    if mode & 0o077 != 0 {
        return Err(KeyAgentError::SocketSecurity(format!(
            "socket directory {} is accessible to other users (mode {:o})",
            dir.display(),
            mode & 0o777
        )));
    }

    Ok(())
}

/// Verify the socket node: a Unix domain socket owned by the current user
/// with no group/other access. The parent directory is verified first.
///
/// Call this on the client side before connecting (a swapped or planted
/// socket file must never receive a signing request) and on the server
/// side after binding.
///
/// # Errors
///
/// Returns [`KeyAgentError::SocketSecurity`] when the node is missing, is
/// not a socket, is owned by another user, or is accessible to
/// group/other. The parent-directory checks of [`verify_socket_dir`] are
/// included.
#[cfg(unix)]
pub fn verify_socket_file(socket: &Path) -> Result<(), KeyAgentError> {
    if let Some(parent) = socket.parent() {
        if !parent.as_os_str().is_empty() {
            verify_socket_dir(parent)?;
        }
    }

    let meta = std::fs::symlink_metadata(socket).map_err(|e| {
        KeyAgentError::SocketSecurity(format!("cannot stat socket {}: {e}", socket.display()))
    })?;

    if !meta.file_type().is_socket() {
        return Err(KeyAgentError::SocketSecurity(format!(
            "socket path {} is not a Unix domain socket",
            socket.display()
        )));
    }

    let uid = u64::from(meta.uid());
    if uid != current_uid() {
        return Err(KeyAgentError::SocketSecurity(format!(
            "socket {} is owned by uid {uid}, expected uid {}",
            socket.display(),
            current_uid()
        )));
    }

    let mode = meta.mode();
    if mode & 0o077 != 0 {
        return Err(KeyAgentError::SocketSecurity(format!(
            "socket {} is accessible to other users (mode {:o})",
            socket.display(),
            mode & 0o777
        )));
    }

    Ok(())
}

/// Non-Unix stub: there are no Unix domain sockets to verify.
#[cfg(not(unix))]
pub fn verify_socket_dir(_dir: &Path) -> Result<(), KeyAgentError> {
    Ok(())
}

/// Non-Unix stub: see [`verify_socket_dir`].
#[cfg(not(unix))]
pub fn verify_socket_file(_socket: &Path) -> Result<(), KeyAgentError> {
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::{fs::PermissionsExt, net::UnixListener};

    use super::*;

    /// A fresh 0700 directory under the system temp dir, removed on drop.
    ///
    /// The name is kept short on purpose: macOS caps Unix socket paths at
    /// `SUN_LEN` (104) bytes and `std::env::temp_dir()` is already deep.
    struct TempDirGuard {
        path: std::path::PathBuf,
    }

    impl TempDirGuard {
        fn new(tag: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos());
            let path =
                std::env::temp_dir().join(format!("oc-ka-{tag}-{}-{nanos}", std::process::id()));
            std::fs::create_dir_all(&path).expect("create temp dir");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                .expect("chmod 0700");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDirGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn fresh_private_dir_passes() {
        let dir = TempDirGuard::new("d");
        assert!(verify_socket_dir(dir.path()).is_ok());
    }

    #[test]
    fn missing_dir_fails_closed() {
        let missing = std::env::temp_dir().join("oc-ka-absent-12345");
        let _ = std::fs::remove_dir_all(&missing);
        let err = verify_socket_dir(&missing).expect_err("missing dir must fail");
        assert!(matches!(err, KeyAgentError::SocketSecurity(_)));
    }

    #[test]
    fn permissive_dir_fails_closed() {
        let dir = TempDirGuard::new("p");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777))
            .expect("chmod 0777");
        let err = verify_socket_dir(dir.path()).expect_err("0777 dir must fail");
        assert!(matches!(err, KeyAgentError::SocketSecurity(_)));
        // Restore so Drop can clean up.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("restore 0700");
    }

    #[test]
    fn symlinked_dir_fails_closed() {
        let real = TempDirGuard::new("r");
        let link = std::env::temp_dir().join(format!(
            "oc-ka-lnk-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        std::os::unix::fs::symlink(real.path(), &link).expect("create symlink");
        let err = verify_socket_dir(&link).expect_err("symlink must fail");
        assert!(matches!(err, KeyAgentError::SocketSecurity(_)));
        let _ = std::fs::remove_file(&link);
    }

    #[test]
    fn regular_file_at_dir_path_fails_closed() {
        let dir = TempDirGuard::new("f");
        let file = dir.path().join("not-a-dir");
        std::fs::write(&file, b"x").expect("write file");
        let err = verify_socket_dir(&file).expect_err("regular file must fail");
        assert!(matches!(err, KeyAgentError::SocketSecurity(_)));
    }

    #[test]
    fn bound_socket_with_0600_passes() {
        let dir = TempDirGuard::new("s");
        let sock = dir.path().join("s.sock");
        let listener = UnixListener::bind(&sock).expect("bind");
        std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600))
            .expect("chmod 0600");
        assert!(verify_socket_file(&sock).is_ok());
        drop(listener);
    }

    #[test]
    fn permissive_socket_fails_closed() {
        let dir = TempDirGuard::new("sp");
        let sock = dir.path().join("s.sock");
        let listener = UnixListener::bind(&sock).expect("bind");
        std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o644))
            .expect("chmod 0644");
        let err = verify_socket_file(&sock).expect_err("0644 socket must fail");
        assert!(matches!(err, KeyAgentError::SocketSecurity(_)));
        drop(listener);
    }

    #[test]
    fn non_socket_file_at_socket_path_fails_closed() {
        let dir = TempDirGuard::new("sf");
        let sock = dir.path().join("s.sock");
        std::fs::write(&sock, b"not a socket").expect("write file");
        let err = verify_socket_file(&sock).expect_err("regular file must fail");
        assert!(matches!(err, KeyAgentError::SocketSecurity(_)));
    }

    #[test]
    fn missing_socket_fails_closed() {
        let dir = TempDirGuard::new("sm");
        let sock = dir.path().join("a.sock");
        let err = verify_socket_file(&sock).expect_err("missing socket must fail");
        assert!(matches!(err, KeyAgentError::SocketSecurity(_)));
    }
}
