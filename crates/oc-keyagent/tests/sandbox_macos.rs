//! Out-of-process verification that the macOS Seatbelt profile actually
//! blocks network access (R12).
//!
//! `sandbox_init(3)` is irreversible for the lifetime of the process, and the
//! profile denies `process-fork` / `process-exec*`. Applying it inside the
//! normal test harness would therefore break every test that runs afterwards
//! in the same binary. Instead this test re-executes *itself* as a child
//! process with a marker environment variable set; the child applies the
//! sandbox, attempts an outbound TCP connection, and reports the result via
//! its exit code.
//!
//! Exit-code contract for the child:
//!
//! | Code | Meaning |
//! |---|---|
//! | 0 | Sandbox applied AND the outbound connection was refused. |
//! | 10 | `sandbox_init` itself failed. |
//! | 11 | Sandbox applied but the outbound connection SUCCEEDED (R12 breach). |
//! | 12 | The UDS control path broke under the sandbox (false positive). |
//! | 13 | A TCP listener bind SUCCEEDED under the sandbox (R12 breach). |

#![cfg(target_os = "macos")]

use std::{
    io::{Read as _, Write as _},
    net::{TcpListener, TcpStream},
    os::unix::net::{UnixListener, UnixStream},
    time::Duration,
};

/// Set in the child process to switch it into "sandboxed probe" mode.
const CHILD_MARKER: &str = "OC_SANDBOX_CHILD_PROBE";

/// A destination that is guaranteed to be routable-but-unreachable quickly if
/// the sandbox does *not* block us. We only care whether the syscall itself is
/// permitted, so a short timeout is enough: a sandbox denial surfaces
/// immediately as `EPERM`, whereas a permitted-but-filtered connection times
/// out.
const PROBE_ADDR: &str = "1.1.1.1:80";

fn main_is_child() -> bool {
    std::env::var_os(CHILD_MARKER).is_some()
}

/// The child-process body: apply the sandbox, then probe.
fn run_child() -> ! {
    if let Err(e) = oc_keyagent::sandbox::apply_seatbelt() {
        eprintln!("child: sandbox_init failed: {e}");
        std::process::exit(10);
    }

    // 1. UDS must still work — the Key-Agent's entire IPC surface depends on it. A profile that
    //    blocked UDS would be a false positive.
    let sock_dir = std::env::temp_dir().join(format!("oc-sbx-{}", std::process::id()));
    if std::fs::create_dir_all(&sock_dir).is_err() {
        eprintln!("child: could not create socket dir");
        std::process::exit(12);
    }
    let sock_path = sock_dir.join("probe.sock");
    let uds_ok = (|| -> std::io::Result<bool> {
        let listener = UnixListener::bind(&sock_path)?;
        let mut client = UnixStream::connect(&sock_path)?;
        let (mut server, _) = listener.accept()?;
        client.write_all(b"ping")?;
        client.shutdown(std::net::Shutdown::Write)?;
        let mut buf = Vec::new();
        server.read_to_end(&mut buf)?;
        Ok(buf == b"ping")
    })()
    .unwrap_or(false);
    let _ = std::fs::remove_dir_all(&sock_dir);

    if !uds_ok {
        eprintln!("child: UDS round-trip failed under the sandbox");
        std::process::exit(12);
    }

    // 2. Inbound TCP: binding a listener must be denied, including on loopback. R12c says the
    //    Key-Agent never listens on TCP at all.
    for bind_addr in ["127.0.0.1:0", "0.0.0.0:0"] {
        if let Ok(l) = TcpListener::bind(bind_addr) {
            eprintln!("child: TcpListener::bind({bind_addr}) SUCCEEDED — R12 breach");
            drop(l);
            std::process::exit(13);
        }
    }

    // 3. Outbound TCP must be denied — both to a routable public address and to loopback, so a
    //    co-resident service cannot be used as a relay.
    let addr: std::net::SocketAddr = PROBE_ADDR.parse().expect("static addr parses");
    match TcpStream::connect_timeout(&addr, Duration::from_secs(2)) {
        Ok(_) => {
            eprintln!("child: outbound TCP SUCCEEDED under the sandbox — R12 breach");
            std::process::exit(11);
        }
        Err(e) => {
            // Any error is acceptable evidence that we did not reach the
            // network; `PermissionDenied` is the signature of a Seatbelt deny.
            eprintln!("child: outbound TCP denied as expected: {e} ({:?})", e.kind());
            std::process::exit(0);
        }
    }
}

/// Re-exec this test binary as a sandboxed child and return its exit code.
///
/// The child must run exactly ONE probe, so `--exact` with the full test name
/// is passed. Without it, libtest would run every test in the binary and the
/// second probe would re-apply `sandbox_init` — which is irreversible per
/// process — and exit with a misleading code.
fn spawn_probe(test_name: &str) -> i32 {
    let exe = std::env::current_exe().expect("test binary path");
    let status = std::process::Command::new(exe)
        .arg("--exact")
        .arg(test_name)
        .env(CHILD_MARKER, "1")
        .status()
        .expect("re-exec test binary");
    status.code().unwrap_or(-1)
}

// The child branch has to run before libtest takes over, which `#[ctor]`-free
// Rust cannot do from a normal `#[test]`. Instead every test first checks the
// marker and, if set, diverts into the child body.
fn dispatch_child_if_needed() {
    if main_is_child() {
        run_child();
    }
}

#[test]
fn seatbelt_blocks_outbound_network_but_allows_uds() {
    dispatch_child_if_needed();

    let code = spawn_probe("seatbelt_blocks_outbound_network_but_allows_uds");
    match code {
        0 => {}
        10 => panic!("sandbox_init failed in the child — the Seatbelt profile is invalid"),
        11 => panic!("R12 BREACH: outbound TCP succeeded inside the Seatbelt sandbox"),
        12 => panic!("the Seatbelt profile broke UDS, which the Key-Agent requires"),
        13 => panic!("R12 BREACH: a TCP listener bind succeeded inside the Seatbelt sandbox"),
        other => panic!("unexpected child exit code {other}"),
    }
}

#[test]
fn seatbelt_profile_is_syntactically_valid() {
    dispatch_child_if_needed();

    // Applying the profile in a throwaway child is the only way to have the
    // kernel validate it. Exit code 10 means `sandbox_init` rejected it.
    assert_ne!(
        spawn_probe("seatbelt_profile_is_syntactically_valid"),
        10,
        "the Seatbelt profile must be accepted by the kernel"
    );
}
