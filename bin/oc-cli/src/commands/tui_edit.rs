//! In-memory multiline editor for `secret edit` (plaintext never touches disk).
//!
//! pago edits encrypted entries through a tview text area without ever
//! writing the plaintext to disk; this is the OneCipher equivalent, built
//! on the ratatui + crossterm dependencies the TUI already uses (both live
//! in `oc-cli`, outside the R56 isolation boundary). When no external
//! editor is configured and stdin is a TTY, `secret edit` uses this editor
//! so the decrypted payload exists only in process memory — no temp file
//! is created at any point, unlike the hardened external-editor path in
//! [`super::editor`].
//!
//! Scope: this is a deliberately small editor (insert / delete / newline /
//! tab / arrows / Home / End / PageUp / PageDown). Undo, selection and
//! clipboard are intentionally out of scope for the first iteration; the
//! external editor path remains available for heavy editing.

use std::{io::stdout, time::Duration};

use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Layout},
    widgets::Paragraph,
};
use zeroize::Zeroizing;

use crate::CliError;

/// Poll interval; also caps redraw latency.
const TICK_INTERVAL: Duration = Duration::from_millis(250);

/// Lines moved by PageUp / PageDown.
const PAGE_STEP: usize = 10;

/// Bottom status line documenting the key bindings.
const STATUS_LINE: &str =
    " Ctrl+D save · Ctrl+C/Esc discard · Enter newline · Tab tab · arrows/Home/End/PgUp/PgDn move ";

/// RAII guard restoring the terminal on every exit path (including panics).
struct RawModeGuard;

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
    }
}

/// Edit `initial` in a full-screen in-memory editor.
///
/// Returns `Ok(Some(text))` when the user saves (Ctrl+D) and `Ok(None)`
/// when the edit is discarded (Ctrl+C / Esc).
///
/// # Errors
///
/// Returns [`CliError::Io`] when the terminal cannot be put into raw mode
/// or the alternate screen, or when event reading fails.
pub(crate) fn edit_in_memory(initial: &str) -> Result<Option<Zeroizing<String>>, CliError> {
    enable_raw_mode().map_err(CliError::Io)?;
    let _raw_guard = RawModeGuard; // disables raw mode on drop (error or success).

    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen).map_err(CliError::Io)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).map_err(CliError::Io)?;

    let result = run_loop(&mut terminal, initial);

    // Restore the terminal before returning; the guard covers panics.
    let _ = execute!(terminal.backend_mut(), LeaveAlternateScreen);
    let _ = terminal.show_cursor();

    result
}

/// Editor buffer and cursor. `col` is a *char* index within `lines[row]`;
/// byte offsets are derived on demand so multi-byte input is safe.
struct EditorState {
    lines: Vec<String>,
    row: usize,
    col: usize,
    /// First visible row (vertical scroll offset).
    row_off: usize,
    /// First visible column (horizontal scroll offset).
    col_off: usize,
}

impl EditorState {
    fn new(text: &str) -> Self {
        let lines: Vec<String> = if text.is_empty() {
            vec![String::new()]
        } else {
            text.split('\n').map(str::to_owned).collect()
        };
        Self { lines, row: 0, col: 0, row_off: 0, col_off: 0 }
    }

    fn text(&self) -> String {
        self.lines.join("\n")
    }

    fn line_len(&self) -> usize {
        self.lines[self.row].chars().count()
    }

    /// Byte offset of char index `col` within the current line.
    fn char_to_byte(&self, col: usize) -> usize {
        self.lines[self.row].chars().take(col).map(char::len_utf8).sum()
    }

    fn clamp_cursor(&mut self) {
        self.row = self.row.min(self.lines.len().saturating_sub(1));
        self.col = self.col.min(self.line_len());
    }

    fn insert(&mut self, c: char) {
        let byte = self.char_to_byte(self.col);
        self.lines[self.row].insert(byte, c);
        self.col += 1;
    }

    fn backspace(&mut self) {
        if self.col > 0 {
            let start = self.char_to_byte(self.col - 1);
            let end = self.char_to_byte(self.col);
            self.lines[self.row].replace_range(start..end, "");
            self.col -= 1;
        } else if self.row > 0 {
            // At column 0: merge this line into the previous one.
            let merged_len = self.lines[self.row - 1].chars().count();
            let tail = self.lines.remove(self.row);
            self.row -= 1;
            self.lines[self.row].push_str(&tail);
            self.col = merged_len;
        }
    }

    fn delete(&mut self) {
        if self.col < self.line_len() {
            let start = self.char_to_byte(self.col);
            let end = self.char_to_byte(self.col + 1);
            self.lines[self.row].replace_range(start..end, "");
        } else if self.row + 1 < self.lines.len() {
            // At end of line: pull the next line up.
            let tail = self.lines.remove(self.row + 1);
            self.lines[self.row].push_str(&tail);
        }
    }

    fn newline(&mut self) {
        let byte = self.char_to_byte(self.col);
        let tail = self.lines[self.row].split_off(byte);
        self.row += 1;
        self.lines.insert(self.row, tail);
        self.col = 0;
    }

    /// Adjust the scroll offsets so the cursor stays inside `width` x `height`.
    fn scroll_into_view(&mut self, width: u16, height: u16) {
        let height = height as usize;
        let width = width as usize;
        if self.row < self.row_off {
            self.row_off = self.row;
        }
        if self.row >= self.row_off + height {
            self.row_off = self.row + 1 - height;
        }
        if self.col < self.col_off {
            self.col_off = self.col;
        }
        if self.col >= self.col_off + width {
            self.col_off = self.col + 1 - width;
        }
    }
}

/// Outcome of a single key press.
enum KeyOutcome {
    Save,
    Abort,
    Ignored,
}

/// Apply one key press to the editor state.
fn handle_key(state: &mut EditorState, key: KeyEvent) -> KeyOutcome {
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        return match key.code {
            KeyCode::Char('d') => KeyOutcome::Save,
            KeyCode::Char('c') => KeyOutcome::Abort,
            _ => KeyOutcome::Ignored,
        };
    }

    match key.code {
        KeyCode::Char(c) => {
            state.insert(c);
        }
        KeyCode::Enter => state.newline(),
        KeyCode::Tab => state.insert('\t'),
        KeyCode::Backspace => state.backspace(),
        KeyCode::Delete => state.delete(),
        KeyCode::Left => state.col = state.col.saturating_sub(1),
        KeyCode::Right => state.col = (state.col + 1).min(state.line_len()),
        KeyCode::Up => state.row = state.row.saturating_sub(1),
        KeyCode::Down => state.row = (state.row + 1).min(state.lines.len() - 1),
        KeyCode::Home => state.col = 0,
        KeyCode::End => state.col = state.line_len(),
        KeyCode::PageUp => state.row = state.row.saturating_sub(PAGE_STEP),
        KeyCode::PageDown => state.row = (state.row + PAGE_STEP).min(state.lines.len() - 1),
        KeyCode::Esc => return KeyOutcome::Abort,
        _ => return KeyOutcome::Ignored,
    }
    state.clamp_cursor();
    KeyOutcome::Ignored
}

/// Render the editor: text area plus a one-line status bar and the cursor.
fn render(state: &EditorState, frame: &mut Frame<'_>) {
    let area = frame.area();
    let chunks = Layout::vertical([Constraint::Min(1), Constraint::Length(1)]).split(area);

    let text = state.lines.join("\n");
    let body = Paragraph::new(text).scroll((state.row_off as u16, state.col_off as u16));
    frame.render_widget(body, chunks[0]);
    frame.render_widget(Paragraph::new(STATUS_LINE), chunks[1]);

    let y = chunks[0].y + (state.row - state.row_off) as u16;
    let x = chunks[0].x + (state.col - state.col_off) as u16;
    frame.set_cursor_position((x, y));
}

/// Draw → poll → handle loop until save or discard.
fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    initial: &str,
) -> Result<Option<Zeroizing<String>>, CliError> {
    let mut state = EditorState::new(initial);

    loop {
        let size = terminal.size().map_err(CliError::Io)?;
        // The status line occupies the last row; the cursor must stay inside
        // the text area for `set_cursor_position` to be valid.
        state.scroll_into_view(size.width, size.height.saturating_sub(1));
        terminal.draw(|frame| render(&state, frame)).map_err(CliError::Io)?;

        if event::poll(TICK_INTERVAL).map_err(CliError::Io)? {
            if let Event::Key(key) = event::read().map_err(CliError::Io)? {
                match handle_key(&mut state, key) {
                    KeyOutcome::Save => return Ok(Some(Zeroizing::new(state.text()))),
                    KeyOutcome::Abort => return Ok(None),
                    KeyOutcome::Ignored => {}
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_state_splits_lines() {
        let state = EditorState::new("a\nbb\nccc");
        assert_eq!(state.lines.len(), 3);
        assert_eq!(state.line_len(), 1);
    }

    #[test]
    fn empty_initial_has_one_editable_line() {
        let state = EditorState::new("");
        assert_eq!(state.lines, vec![String::new()]);
    }

    #[test]
    fn insert_and_newline_move_the_cursor() {
        let mut state = EditorState::new("");
        state.insert('h');
        state.insert('i');
        state.newline();
        state.insert('x');
        assert_eq!(state.text(), "hi\nx");
        assert_eq!(state.row, 1);
        assert_eq!(state.col, 1);
    }

    #[test]
    fn backspace_merges_lines_at_column_zero() {
        let mut state = EditorState::new("ab\ncd");
        state.row = 1;
        state.col = 0;
        state.backspace();
        assert_eq!(state.text(), "abcd");
        assert_eq!(state.col, 2);
    }

    #[test]
    fn backspace_removes_one_char_not_one_byte() {
        let mut state = EditorState::new("héllo");
        state.col = 2; // after "hé"
        state.backspace();
        assert_eq!(state.text(), "hllo");
    }

    #[test]
    fn delete_at_eol_merges_next_line() {
        let mut state = EditorState::new("ab\ncd");
        state.col = 2;
        state.delete();
        assert_eq!(state.text(), "abcd");
    }

    #[test]
    fn movement_clamps_to_line_length() {
        let mut state = EditorState::new("long line\nhi");
        state.row = 0;
        state.col = 9;
        state.row = 1;
        state.clamp_cursor();
        assert_eq!(state.col, 2, "col must clamp to the shorter line");
    }

    #[test]
    fn scroll_keeps_cursor_visible() {
        let mut state = EditorState::new("");
        for i in 0..30 {
            state.insert(char::from(b'a' + u8::try_from(i % 26).unwrap_or(0)));
            state.newline();
        }
        state.row = 25;
        state.col = 0;
        state.scroll_into_view(80, 10);
        assert!(state.row_off <= 25 && 25 < state.row_off + 10);
    }

    #[test]
    fn ctrl_d_saves_and_ctrl_c_aborts() {
        let mut state = EditorState::new("x");
        let save = KeyEvent::new(KeyCode::Char('d'), KeyModifiers::CONTROL);
        assert!(matches!(handle_key(&mut state, save), KeyOutcome::Save));
        let abort = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert!(matches!(handle_key(&mut state, abort), KeyOutcome::Abort));
    }

    #[test]
    fn esc_aborts() {
        let mut state = EditorState::new("x");
        let esc = KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE);
        assert!(matches!(handle_key(&mut state, esc), KeyOutcome::Abort));
    }
}
