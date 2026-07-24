//! Keyboard input handling, dispatched by [`Mode`].
//!
//! Vim-inspired key bindings:
//! - `j`/`k` (or arrow keys) for navigation
//! - `/` to search
//! - `Enter` to view detail
//! - `c` to copy, `t` for TOTP
//! - `d` to delete (with confirmation)
//! - `?` for help, `q` to quit

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::tui::app::{App, Mode};

/// Number of rows to scroll on PageUp / PageDown.
const PAGE_SCROLL: usize = 10;

/// Handle a key event. Returns `true` if the app should quit.
pub(crate) fn handle_key(app: &mut App, key: KeyEvent) -> bool {
    // Ctrl+C always quits immediately.
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        app.should_quit = true;
        return true;
    }

    match app.mode {
        Mode::Normal => handle_normal_key(app, key),
        Mode::Search => handle_search_key(app, key),
        Mode::Insert => handle_insert_key(app, key),
        Mode::Confirm => handle_confirm_key(app, key),
        Mode::Detail => handle_detail_key(app, key),
        Mode::Help => handle_help_key(app, key),
    }
}

fn handle_normal_key(app: &mut App, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Char('q') => {
            app.should_quit = true;
            true
        }
        KeyCode::Char('j') | KeyCode::Down => {
            app.move_down();
            false
        }
        KeyCode::Char('k') | KeyCode::Up => {
            app.move_up();
            false
        }
        KeyCode::Char('g') | KeyCode::Home => {
            app.selected = 0;
            false
        }
        KeyCode::Char('G') | KeyCode::End => {
            if !app.filtered_indices.is_empty() {
                app.selected = app.filtered_indices.len() - 1;
            }
            false
        }
        KeyCode::PageDown => {
            for _ in 0..PAGE_SCROLL {
                app.move_down();
            }
            false
        }
        KeyCode::PageUp => {
            for _ in 0..PAGE_SCROLL {
                app.move_up();
            }
            false
        }
        KeyCode::Char('/') => {
            app.enter_search();
            false
        }
        KeyCode::Enter => {
            app.enter_detail();
            false
        }
        KeyCode::Char('c') => {
            app.copy_secret();
            false
        }
        KeyCode::Char('t') => {
            app.copy_totp();
            false
        }
        KeyCode::Char('?') => {
            app.mode = Mode::Help;
            false
        }
        KeyCode::Char('d') => {
            app.mode = Mode::Confirm;
            false
        }
        KeyCode::Char('n') => {
            if app.experimental {
                app.set_message("New secret creation not yet implemented");
            } else {
                app.set_message(
                    "New secret creation is experimental. Restart with --experimental to enable.",
                );
            }
            false
        }
        _ => false,
    }
}

fn handle_search_key(app: &mut App, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Esc => {
            app.mode = Mode::Normal;
            app.input_buffer.clear();
            false
        }
        KeyCode::Enter => {
            app.search_query = app.input_buffer.clone();
            app.mode = Mode::Normal;
            app.filter();
            app.selected = 0;
            false
        }
        KeyCode::Backspace => {
            app.input_buffer.pop();
            false
        }
        KeyCode::Char(c) => {
            app.input_buffer.push(c);
            false
        }
        _ => false,
    }
}

fn handle_insert_key(app: &mut App, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Esc => {
            app.mode = Mode::Normal;
            app.input_buffer.clear();
            false
        }
        KeyCode::Enter => {
            // Insert mode is reserved for future new-secret / edit flows.
            app.mode = Mode::Normal;
            false
        }
        KeyCode::Backspace => {
            app.input_buffer.pop();
            false
        }
        KeyCode::Char(c) => {
            app.input_buffer.push(c);
            false
        }
        _ => false,
    }
}

fn handle_confirm_key(app: &mut App, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Char('y' | 'Y') => {
            app.delete_current();
            app.mode = Mode::Normal;
            false
        }
        KeyCode::Char('n' | 'N') | KeyCode::Esc => {
            app.mode = Mode::Normal;
            false
        }
        _ => false,
    }
}

fn handle_detail_key(app: &mut App, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Esc | KeyCode::Char('q') => {
            app.mode = Mode::Normal;
            app.detail_entry = None;
            false
        }
        KeyCode::Char('c') => {
            app.copy_secret();
            false
        }
        KeyCode::Char('t') => {
            app.copy_totp();
            false
        }
        _ => false,
    }
}

fn handle_help_key(app: &mut App, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Esc | KeyCode::Char('q' | '?') => {
            app.mode = Mode::Normal;
            false
        }
        _ => false,
    }
}
