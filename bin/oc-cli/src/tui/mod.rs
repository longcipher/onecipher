//! Interactive TUI for the OneCipher unified vault.
//!
//! Uses ratatui + crossterm. Provides a vim-like interface for browsing,
//! creating, editing, and copying secrets.
//!
//! # Hard-gate compliance
//!
//! The TUI lives in `oc-cli` (the binary crate) — it does NOT touch the
//! isolated crates (`oc-crypto`, `oc-policy`, `oc-keyagent`, …). The
//! `ratatui` / `crossterm` / `arboard` dependencies are therefore never
//! propagated into the R56 isolation boundary.

pub(crate) mod app;
pub(crate) mod clipboard;
pub(crate) mod input;
pub(crate) mod ui;

use std::{
    io::stdout,
    time::{Duration, Instant},
};

use app::App;
use crossterm::{
    event::{self, Event},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use oc_secret::SecretStore;
use ratatui::{Terminal, backend::CrosstermBackend};

/// Polling interval for periodic events (TOTP refresh, clipboard auto-clear).
const TICK_INTERVAL: Duration = Duration::from_millis(250);

/// RAII guard that disables raw mode when dropped.
///
/// This ensures the terminal is restored even if the TUI loop panics or
/// returns an error, so the user's shell is never left in raw mode.
struct RawModeGuard;

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
    }
}

/// Best-effort background launch of the Key-Agent daemon.
///
/// The TUI itself drives the local secret store and never sends Key-Agent
/// RPCs, so instead of blocking startup on the daemon socket, this probes
/// the socket and — only when nothing is listening — fire-and-forgets
/// `onecipher --daemon` on a helper thread and returns immediately. No
/// warning is printed: daemon absence is not an error for the TUI.
pub(crate) fn ensure_daemon_background() {
    use std::os::unix::net::UnixStream;

    let socket_path = oc_keyagent::server::default_socket_path();
    if UnixStream::connect(&socket_path).is_ok() {
        return;
    }
    // Clean up a stale socket file so the daemon can bind on launch.
    if std::path::Path::new(&socket_path).exists() {
        let _ = std::fs::remove_file(&socket_path);
    }
    std::thread::Builder::new()
        .name("onecipher-daemon-spawn".into())
        .spawn(|| {
            use std::process::Stdio;
            let Ok(exe) = std::env::current_exe() else { return };
            let _ = std::process::Command::new(exe)
                .arg("--daemon")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn();
        })
        .ok();
}

/// Run the TUI loop. Returns when the user quits (q) or an unrecoverable
/// error occurs.
pub(crate) fn run(store: SecretStore) -> eyre::Result<()> {
    let mut app = App::new(store);
    app.reload();

    // Enable raw mode and enter the alternate screen.
    enable_raw_mode()?;
    let _raw_guard = RawModeGuard; // disables raw mode on drop (error or success).

    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Main event loop.
    let result = run_loop(&mut terminal, &mut app);

    // Restore terminal (alternate screen + cursor + raw mode).
    let _ = execute!(terminal.backend_mut(), LeaveAlternateScreen);
    let _ = terminal.show_cursor();
    // RawModeGuard::drop disables raw mode.

    result
}

/// Inner event loop: render → poll input → handle periodic events.
fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    app: &mut App,
) -> eyre::Result<()> {
    let mut last_tick = Instant::now();
    while !app.should_quit {
        terminal.draw(|frame| ui::render(app, frame))?;

        // Poll for input with a timeout so periodic events also run.
        let timeout = TICK_INTERVAL.checked_sub(last_tick.elapsed()).unwrap_or(Duration::ZERO);
        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if input::handle_key(app, key) {
                    break;
                }
            }
        }

        // Tick: refresh TOTP cache and check clipboard expiry.
        if last_tick.elapsed() >= TICK_INTERVAL {
            app.refresh_totp();
            app.check_clipboard();
            last_tick = Instant::now();
        }
    }
    Ok(())
}
