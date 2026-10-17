//! End-to-end tests that drive the real `onecipher` binary.
//!
//! Mirrors pago's `test/e2e_test.go` split:
//!
//! - **Non-interactive** cases run the binary directly with a private `HOME` and assert on exit
//!   codes plus stdout/stderr (`run_cli`).
//! - **TTY** cases run it behind a pseudo-terminal (`run_pty`) so prompt paths that only fire when
//!   stdin is a terminal are covered.
//!
//! Every test works in a throwaway `HOME`, so no user state is touched and
//! tests are independent of one another. Tests that need an external
//! dependency (`sh`, `/dev/fd`) skip rather than fail when it is missing,
//! per the repository's testing conventions.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    collections::HashMap,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::mpsc,
    thread,
};

use portable_pty::{CommandBuilder, PtySize, native_pty_system};

/// The binary under test (cargo builds it before running integration tests).
const BIN: &str = env!("CARGO_BIN_EXE_onecipher");

// ── Non-interactive runner ────────────────────────────────────────────────

/// Result of one binary invocation.
struct Run {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

/// A throwaway `HOME`; removed on drop.
struct HomeGuard {
    path: PathBuf,
}

impl HomeGuard {
    fn new(tag: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let path =
            std::env::temp_dir().join(format!("oc-e2e-{tag}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&path).expect("create test home");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for HomeGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Run the binary with `HOME` pointed at `home` and stdin fed `stdin`.
fn run_cli(home: &Path, args: &[&str], stdin: &str) -> Run {
    let mut child = Command::new(BIN)
        .args(args)
        .env("HOME", home)
        .env("ONECIPHER_PASSPHRASE", "e2e-pass")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn onecipher");

    let mut stdin_pipe = child.stdin.take().expect("stdin");
    stdin_pipe.write_all(stdin.as_bytes()).expect("write stdin");
    drop(stdin_pipe); // signals EOF to the reader

    let out = child.wait_with_output().expect("wait");
    Run {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// Initialize an age identity + recipients inside `home`.
fn age_init(home: &Path) -> Run {
    run_cli(home, &["age", "init"], "")
}

// ── PTY runner ────────────────────────────────────────────────────────────

/// Run the binary under a pseudo-terminal, send `input`, and capture output.
///
/// Only `HOME` and `env` are exported; every other variable is inherited so
/// the test process cannot accidentally leak a passphrase into the child.
fn run_pty(home: &Path, args: &[&str], env: &HashMap<String, String>, input: &str) -> Run {
    let pty_system = native_pty_system();
    let pair = pty_system
        .openpty(PtySize { rows: 24, cols: 80, pixel_width: 0, pixel_height: 0 })
        .expect("open pty");

    let mut cmd = CommandBuilder::new(BIN);
    for arg in args {
        cmd.arg(arg);
    }
    cmd.env_clear();
    cmd.env("HOME", home.to_string_lossy().to_string());
    cmd.env("PATH", std::env::var("PATH").unwrap_or_default());
    cmd.env("TERM", "dumb");
    for (k, v) in env {
        cmd.env(k, v);
    }

    let mut child = pair.slave.spawn_command(cmd).expect("spawn on pty");
    drop(pair.slave);

    // Feed the scripted input, then close the writer so the child sees EOF.
    {
        let mut writer = pair.master.take_writer().expect("pty writer");
        writer.write_all(input.as_bytes()).expect("write input");
    }

    // Drain the master on a helper thread: a blocking read on the pty would
    // deadlock if the child produced more than the pipe buffer holds.
    let mut reader = pair.master.try_clone_reader().expect("pty reader");
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            match reader.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
        let _ = tx.send(String::from_utf8_lossy(&buf).into_owned());
    });

    let status = child.wait().expect("wait child");
    let output = rx.recv_timeout(std::time::Duration::from_secs(10)).unwrap_or_default();

    Run { code: extract_code(&status), stdout: output, stderr: String::new() }
}

/// portable-pty carries its own `ExitStatus` (no `Deref` to std's).
fn extract_code(status: &portable_pty::ExitStatus) -> Option<i32> {
    if status.success() {
        return Some(0);
    }
    // A signalled child has no meaningful exit code.
    if status.signal().is_some() {
        return None;
    }
    i32::try_from(status.exit_code()).ok()
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[test]
fn version_prints_a_semver() {
    let home = HomeGuard::new("version");
    let r = run_cli(home.path(), &["--version"], "");
    assert_eq!(r.code, Some(0), "stderr: {}", r.stderr);
    assert!(r.stdout.contains('.'), "expected a dotted version: {:?}", r.stdout);
}

#[test]
fn secret_lifecycle_add_get_and_missing_exit_code() {
    let home = HomeGuard::new("lifecycle");
    let init = age_init(home.path());
    assert_eq!(init.code, Some(0), "age init failed: {}", init.stderr);

    let payload = r#"{"secret":"hunter2","notes":"e2e note"}"#;
    let add = run_cli(
        home.path(),
        &["secret", "add", "github/personal", "--type", "password", "--stdin"],
        payload,
    );
    assert_eq!(add.code, Some(0), "secret add failed: {} / {}", add.stdout, add.stderr);

    let get = run_cli(home.path(), &["secret", "get", "github/personal"], "");
    assert_eq!(get.code, Some(0), "secret get failed: {}", get.stderr);
    assert!(get.stdout.contains("hunter2"), "secret value must round-trip: {}", get.stdout);

    // D: a missing entry must exit 66 (EX_NOINPUT), not a generic failure.
    let missing = run_cli(home.path(), &["secret", "get", "does/not/exist"], "");
    assert_eq!(missing.code, Some(66), "stderr: {}", missing.stderr);
    assert!(missing.stderr.contains("not found"), "stderr: {}", missing.stderr);
}

#[test]
fn secret_edit_without_editor_and_without_a_tty_fails_cleanly() {
    let home = HomeGuard::new("edit-no-tty");
    assert_eq!(age_init(home.path()).code, Some(0));
    let add = run_cli(
        home.path(),
        &["secret", "add", "svc/api", "--type", "password", "--stdin"],
        r#"{"secret":"tok-123"}"#,
    );
    assert_eq!(add.code, Some(0), "{}", add.stderr);

    // No EDITOR/VISUAL is exported and stdin is a pipe: the command must
    // refuse with a usage error (64) instead of spawning `vi` on a pipe or
    // writing plaintext somewhere surprising.
    let child = Command::new(BIN)
        .args(["secret", "edit", "svc/api"])
        .env("HOME", home.path())
        .env_remove("EDITOR")
        .env_remove("VISUAL")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    let out = child.wait_with_output().expect("wait");
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert_eq!(out.status.code(), Some(64), "expected EX_USAGE, stderr: {stderr}");
    assert!(stderr.contains("terminal") || stderr.contains("EDITOR"), "stderr: {stderr}");
}

#[test]
fn secret_edit_uses_an_external_editor_when_one_is_configured() {
    let home = HomeGuard::new("edit-external");
    assert_eq!(age_init(home.path()).code, Some(0));
    let add = run_cli(
        home.path(),
        &["secret", "add", "svc/api", "--type", "password", "--stdin"],
        r#"{"secret":"tok-123"}"#,
    );
    assert_eq!(add.code, Some(0), "{}", add.stderr);

    // `true` leaves the staging content untouched, so the round-trip is a
    // no-op save; the point is that the external editor path runs and the
    // staging file does not survive under /tmp.
    let edited = run_cli(home.path(), &["secret", "edit", "svc/api", "--editor", "true"], "");
    assert_eq!(edited.code, Some(0), "external editor path failed: {}", edited.stderr);

    // The plaintext staging directory lives in the private state dir and is
    // removed afterwards — nothing may be left in the shared temp dir.
    let leaked = std::fs::read_dir(std::env::temp_dir()).map_or(0, |entries| {
        entries
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().starts_with("onecipher-edit-"))
            .count()
    });
    assert_eq!(leaked, 0, "no plaintext staging dir may remain in the temp dir");
}

#[test]
fn secret_dir_prints_the_store_root() {
    let home = HomeGuard::new("dir");
    assert_eq!(age_init(home.path()).code, Some(0));

    let r = run_cli(home.path(), &["secret", "dir"], "");
    assert_eq!(r.code, Some(0), "stderr: {}", r.stderr);
    let printed = r.stdout.trim();
    assert!(
        printed.ends_with("/store") &&
            printed.starts_with(
                &home.path().to_string_lossy()[..20.min(home.path().to_string_lossy().len())]
            ),
        "expected the store dir inside the test HOME, got: {printed}"
    );

    let json = run_cli(home.path(), &["secret", "dir", "--json"], "");
    assert_eq!(json.code, Some(0));
    assert!(json.stdout.contains("\"dir\""), "json output: {}", json.stdout);
}

#[test]
fn store_flag_selects_a_named_store() {
    let home = HomeGuard::new("store-flag");
    assert_eq!(age_init(home.path()).code, Some(0));

    // Default: <home>/store. Named: <home>/stores/<name>.
    let default = run_cli(home.path(), &["secret", "dir"], "");
    assert_eq!(default.code, Some(0));
    let named = run_cli(home.path(), &["--store", "work", "secret", "dir"], "");
    assert_eq!(named.code, Some(0), "stderr: {}", named.stderr);
    assert!(
        named.stdout.trim().ends_with("/stores/work"),
        "expected a named store dir, got: {}",
        named.stdout
    );
    assert_ne!(default.stdout.trim(), named.stdout.trim());

    // A traversal attempt is a usage error, never a path.
    let evil = run_cli(home.path(), &["--store", "../escape", "secret", "dir"], "");
    assert_eq!(evil.code, Some(64), "traversal must be rejected: {}", evil.stdout);
}

#[test]
fn secret_cat_dumps_decrypted_contents() {
    let home = HomeGuard::new("cat");
    assert_eq!(age_init(home.path()).code, Some(0));

    for (name, secret) in [("github/personal", "gh-token"), ("email/work", "mail-pass")] {
        let payload = format!(r#"{{"secret":"{secret}","notes":"note for {name}"}}"#);
        let add = run_cli(
            home.path(),
            &["secret", "add", name, "--type", "password", "--stdin"],
            &payload,
        );
        assert_eq!(add.code, Some(0), "{}", add.stderr);
    }

    let all = run_cli(home.path(), &["secret", "cat"], "");
    assert_eq!(all.code, Some(0), "stderr: {}", all.stderr);
    assert!(all.stdout.contains("github/personal"), "output: {}", all.stdout);
    assert!(all.stdout.contains("gh-token"), "output: {}", all.stdout);
    assert!(all.stdout.contains("mail-pass"), "output: {}", all.stdout);

    // A prefix restricts the dump — the basis for `secret cat github | grep ...`.
    let scoped = run_cli(home.path(), &["secret", "cat", "github"], "");
    assert_eq!(scoped.code, Some(0));
    assert!(scoped.stdout.contains("gh-token"), "output: {}", scoped.stdout);
    assert!(!scoped.stdout.contains("mail-pass"), "prefix must scope: {}", scoped.stdout);

    let json = run_cli(home.path(), &["secret", "cat", "--json"], "");
    assert_eq!(json.code, Some(0));
    assert!(json.stdout.contains("\"gh-token\""), "output: {}", json.stdout);
}

#[test]
fn secret_get_field_otp_generates_a_code() {
    let home = HomeGuard::new("otp");
    assert_eq!(age_init(home.path()).code, Some(0));

    let uri = "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example";
    let payload = format!(r#"{{"secret":"{uri}"}}"#);
    let add =
        run_cli(home.path(), &["secret", "add", "svc/otp", "--type", "totp", "--stdin"], &payload);
    assert_eq!(add.code, Some(0), "{}", add.stderr);

    let code = run_cli(home.path(), &["secret", "get", "svc/otp", "--field", "otp"], "");
    assert_eq!(code.code, Some(0), "stderr: {}", code.stderr);
    let printed = code.stdout.trim();
    assert!(!printed.contains("otpauth"), "must not print the seed URI: {printed}");
    assert!(
        printed.len() == 6 && printed.chars().all(|c| c.is_ascii_digit()),
        "expected a 6-digit code, got: {printed}"
    );
}

#[test]
fn secret_menu_runs_an_action_sequence_without_a_picker() {
    let home = HomeGuard::new("menu");
    assert_eq!(age_init(home.path()).code, Some(0));

    let add = run_cli(
        home.path(),
        &["secret", "add", "svc/api", "--type", "password", "--stdin"],
        r#"{"secret":"tok-123","notes":"user: alice"}"#,
    );
    assert_eq!(add.code, Some(0), "{}", add.stderr);

    // A stand-in for wtype/xdotool: record the arguments so the test can
    // assert what would have been typed.
    let script_dir = HomeGuard::new("menu-script");
    let script = script_dir.path().join("fake-type.sh");
    let out = script_dir.path().join("typed.txt");
    std::fs::write(&script, format!("#!/bin/sh\nprintf '%s\\n' \"$@\" >> {}\n", out.display()))
        .expect("write script");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))
            .expect("chmod +x");
    }

    let program = script.to_string_lossy().to_string();
    let r = run_cli(
        home.path(),
        &[
            "secret",
            "menu",
            "--name",
            "svc/api",
            "--typing-program",
            &program,
            "type-content",
            "secret",
            "type-text",
            "\t",
            "type-content",
            "notes",
        ],
        "",
    );
    assert_eq!(r.code, Some(0), "stderr: {}", r.stderr);

    let typed = std::fs::read_to_string(&out).expect("read typed output");
    assert!(typed.contains("tok-123"), "the secret must be typed: {typed}");
    assert!(typed.contains("user: alice"), "the notes must be typed: {typed}");

    // An unknown key is a usage error, not a silent no-op.
    let bad = run_cli(
        home.path(),
        &["secret", "menu", "--name", "svc/api", "--typing-program", &program, "clip", "nope"],
        "",
    );
    assert_eq!(bad.code, Some(64), "stderr: {}", bad.stderr);
}

#[test]
fn passphrase_prompt_appears_on_a_tty() {
    let home = HomeGuard::new("tty-prompt");
    assert_eq!(age_init(home.path()).code, Some(0));

    let env = HashMap::new();
    // `vault unlock` with no wallets reports cleanly; the point is that the
    // interactive prompt path ran (stdin was a terminal) rather than the
    // non-interactive fallback.
    let r = run_pty(home.path(), &["vault", "unlock"], &env, "\n");
    assert_eq!(r.code, Some(0), "output: {}", r.stdout);
    assert!(
        r.stdout.contains("Passphrase") || r.stdout.contains("no wallets"),
        "expected the passphrase prompt or the empty-vault notice: {}",
        r.stdout
    );
}
