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
use oc_core::ItemType;

use crate::tui::app::{App, FormField, Mode};

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
        #[cfg(feature = "git")]
        Mode::Git => handle_git_key(app, key),
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
        KeyCode::Home => {
            app.selected = 0;
            false
        }
        KeyCode::Char('G') | KeyCode::End => {
            if let Some(idx) =
                app.tree_rows.iter().rposition(|r| matches!(r, crate::tui::app::TreeRow::Entry(_)))
            {
                app.selected = idx;
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
            app.enter_insert();
            false
        }
        KeyCode::Char('e') => {
            app.enter_edit();
            false
        }
        #[cfg(feature = "git")]
        KeyCode::Char('g') => {
            app.enter_git();
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
    // If form is somehow missing, bail to Normal.
    let has_form = app.form.is_some();
    if !has_form {
        app.mode = Mode::Normal;
        return false;
    }

    match key.code {
        KeyCode::Esc => {
            app.form = None;
            app.mode = Mode::Normal;
            false
        }
        KeyCode::Up => {
            if let Some(form) = &mut app.form {
                form.move_up();
            }
            false
        }
        KeyCode::Down => {
            if let Some(form) = &mut app.form {
                form.move_down();
            }
            false
        }
        KeyCode::Left => {
            if let Some(form) = &mut app.form {
                if form.focus == FormField::Type && form.type_index > 0 {
                    form.type_index -= 1;
                }
            }
            false
        }
        KeyCode::Right => {
            if let Some(form) = &mut app.form {
                if form.focus == FormField::Type {
                    let max = ItemType::all().len().saturating_sub(1);
                    if form.type_index < max {
                        form.type_index += 1;
                    }
                }
            }
            false
        }
        KeyCode::Enter => {
            let focus = app.form.as_ref().map(|f| f.focus);
            match focus {
                Some(FormField::Submit) => {
                    app.submit_form();
                }
                Some(FormField::Cancel) => {
                    app.form = None;
                    app.mode = Mode::Normal;
                }
                _ => {
                    // Advance to next field.
                    if let Some(form) = &mut app.form {
                        form.move_down();
                    }
                }
            }
            false
        }
        KeyCode::Backspace => {
            if let Some(form) = &mut app.form {
                if let Some(field) = form.focused_field_mut() {
                    field.pop();
                }
            }
            false
        }
        KeyCode::Char(c) => {
            if let Some(form) = &mut app.form {
                if let Some(field) = form.focused_field_mut() {
                    field.push(c);
                }
            }
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

/// Handle keys in the git status / history view.
#[cfg(feature = "git")]
fn handle_git_key(app: &mut App, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Esc | KeyCode::Char('q') => {
            app.mode = Mode::Normal;
            false
        }
        KeyCode::Char('p') => {
            app.git_pull();
            false
        }
        KeyCode::Char('P') => {
            app.git_push();
            false
        }
        KeyCode::Char('r') => {
            app.reload_git();
            false
        }
        KeyCode::Char('?') => {
            app.mode = Mode::Help;
            false
        }
        _ => false,
    }
}
