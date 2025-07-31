//! Ratatui rendering functions for the TUI.
//!
//! Layout (top to bottom):
//! ```text
//! ┌─────────────────────────────┐
//! │ Search bar (3 lines)        │
//! ├─────────────────────────────┤
//! │ List / Detail / Help (fill) │
//! ├─────────────────────────────┤
//! │ Status + help bar (2 lines) │
//! └─────────────────────────────┘
//! ```

use std::time::Instant;

use oc_core::ItemType;
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
};

use crate::tui::app::{App, Mode};

/// Render the main UI.
pub(crate) fn render(app: &mut App, frame: &mut Frame<'_>) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // search bar
            Constraint::Min(1),    // main content
            Constraint::Length(2), // status bar
        ])
        .split(frame.area());

    render_search(app, frame, chunks[0]);

    match app.mode {
        Mode::Detail => render_detail(app, frame, chunks[1]),
        Mode::Help => render_help(frame, chunks[1]),
        _ => render_list(app, frame, chunks[1]),
    }

    render_status(app, frame, chunks[2]);
}

/// Render the search / filter bar.
fn render_search(app: &App, frame: &mut Frame<'_>, area: Rect) {
    let (text, style) = if app.mode == Mode::Search {
        (format!("/{}", app.input_buffer), Style::default().fg(Color::Yellow))
    } else {
        let q = if app.search_query.is_empty() {
            "Press / to search".to_string()
        } else {
            format!("/{}", app.search_query)
        };
        (q, Style::default().fg(Color::DarkGray))
    };
    let paragraph = Paragraph::new(text)
        .style(style)
        .block(Block::default().borders(Borders::ALL).title("Search"));
    frame.render_widget(paragraph, area);
}

/// Render the secret list.
fn render_list(app: &mut App, frame: &mut Frame<'_>, area: Rect) {
    if app.filtered_indices.is_empty() {
        let msg = if app.entries.is_empty() {
            "No secrets in vault. Press 'n' to create one."
        } else {
            "No matching entries."
        };
        let paragraph = Paragraph::new(msg)
            .style(Style::default().fg(Color::DarkGray))
            .block(Block::default().borders(Borders::ALL).title("Secrets"));
        frame.render_widget(paragraph, area);
        return;
    }

    let items: Vec<ListItem<'_>> = app
        .filtered_indices
        .iter()
        .map(|&i| {
            let entry = &app.entries[i];
            let icon = type_icon(entry.item_type);
            let totp_span = if entry.item_type == ItemType::Totp {
                app.totp_cache
                    .get(&entry.name)
                    .map(|(code, _)| {
                        vec![
                            Span::raw("  "),
                            Span::styled(
                                code.as_str(),
                                Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
                            ),
                        ]
                    })
                    .unwrap_or_default()
            } else {
                Vec::new()
            };

            let mut spans = vec![
                Span::styled(format!("{icon} "), Style::default().fg(Color::Cyan)),
                Span::raw(&entry.name),
                Span::raw("  "),
                Span::styled(
                    format!("[{}]", entry.item_type),
                    Style::default().fg(Color::DarkGray),
                ),
            ];
            spans.extend(totp_span);

            ListItem::new(Line::from(spans))
        })
        .collect();

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("Secrets"))
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_symbol("> ");

    let mut state = ListState::default();
    if app.selected < app.filtered_indices.len() {
        state.select(Some(app.selected));
    }
    frame.render_stateful_widget(list, area, &mut state);
}

/// Render the status / help bar at the bottom.
fn render_status(app: &App, frame: &mut Frame<'_>, area: Rect) {
    let mut lines = Vec::new();

    // Message line (if not expired).
    if let Some((msg, expires)) = &app.message {
        if Instant::now() < *expires {
            lines.push(Line::from(vec![
                Span::styled(" ", Style::default()),
                Span::styled(msg.as_str(), Style::default().fg(Color::Green)),
            ]));
        }
    }
    if lines.is_empty() {
        lines.push(Line::from(""));
    }

    // Contextual key-binding hint.
    let hint = match app.mode {
        Mode::Normal => {
            "j/k:move  /:search  Enter:detail  c:copy  t:totp  d:delete  ?:help  q:quit"
        }
        Mode::Search => "Type to search, Enter:confirm, Esc:cancel",
        Mode::Detail => "Esc:back  c:copy  t:totp  q:quit",
        Mode::Help => "Esc/q:back",
        Mode::Insert => "Esc:cancel  Enter:confirm",
        Mode::Confirm => "y:confirm  n/Esc:cancel",
    };
    lines.push(Line::from(vec![Span::styled(hint, Style::default().fg(Color::DarkGray))]));

    let paragraph = Paragraph::new(lines);
    frame.render_widget(paragraph, area);
}

/// Render the detail view for a single entry.
fn render_detail(app: &App, frame: &mut Frame<'_>, area: Rect) {
    let Some(entry) = &app.detail_entry else {
        return;
    };

    let mut lines: Vec<Line<'_>> = vec![
        labelled_line("Name", &entry.name),
        labelled_line("Type", entry.item_type.label()),
        labelled_line("Created", &entry.created_at),
        labelled_line("Updated", &entry.updated_at),
    ];

    if let Some(url) = &entry.metadata.url {
        lines.push(labelled_line("URL", url));
    }
    if let Some(username) = &entry.metadata.username {
        lines.push(labelled_line("Username", username));
    }
    if let Some(issuer) = &entry.metadata.issuer {
        lines.push(labelled_line("Issuer", issuer));
    }
    if let Some(account) = &entry.metadata.account {
        lines.push(labelled_line("Account", account));
    }
    if let Some(chain) = &entry.metadata.chain {
        lines.push(labelled_line("Chain", chain));
    }
    if !entry.metadata.tags.is_empty() {
        let tags = entry.metadata.tags.join(", ");
        lines.push(labelled_line("Tags", &tags));
    }

    // Secret value is never displayed in plaintext — only masked.
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("Secret: ", Style::default().fg(Color::Cyan)),
        Span::styled("********", Style::default().fg(Color::Yellow)),
    ]));
    lines.push(Line::from(vec![Span::styled(
        "(press 'c' to copy to clipboard)",
        Style::default().fg(Color::DarkGray),
    )]));

    // Show live TOTP code if cached.
    if entry.item_type == ItemType::Totp {
        if let Some((code, expires)) = app.totp_cache.get(&entry.name) {
            let remaining = expires.saturating_duration_since(Instant::now()).as_secs();
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("TOTP: ", Style::default().fg(Color::Green)),
                Span::styled(
                    code.clone(),
                    Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
                ),
                Span::raw(format!(" (expires in {remaining}s)")),
            ]));
        }
    }

    let paragraph = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title("Detail"))
        .wrap(Wrap { trim: false });
    frame.render_widget(paragraph, area);
}

/// Render the help screen.
fn render_help(frame: &mut Frame<'_>, area: Rect) {
    let cyan = Style::default().fg(Color::Cyan);
    let bold = Style::default().add_modifier(Modifier::BOLD);
    let dim = Style::default().fg(Color::DarkGray);

    let lines = vec![
        Line::from(vec![Span::styled("OneCipher TUI — Key Bindings", bold)]),
        Line::from(""),
        Line::from(vec![Span::styled("  j / Down   ", cyan), Span::raw("Move selection down")]),
        Line::from(vec![Span::styled("  k / Up     ", cyan), Span::raw("Move selection up")]),
        Line::from(vec![Span::styled("  g / Home   ", cyan), Span::raw("Jump to top")]),
        Line::from(vec![Span::styled("  G / End    ", cyan), Span::raw("Jump to bottom")]),
        Line::from(vec![Span::styled("  PgDn       ", cyan), Span::raw("Scroll down 10 rows")]),
        Line::from(vec![Span::styled("  PgUp       ", cyan), Span::raw("Scroll up 10 rows")]),
        Line::from(vec![Span::styled("  /          ", cyan), Span::raw("Enter search mode")]),
        Line::from(vec![Span::styled("  Enter      ", cyan), Span::raw("View entry detail")]),
        Line::from(vec![
            Span::styled("  c          ", cyan),
            Span::raw("Copy secret to clipboard (40s auto-clear)"),
        ]),
        Line::from(vec![
            Span::styled("  t          ", cyan),
            Span::raw("Generate and copy TOTP code"),
        ]),
        Line::from(vec![
            Span::styled("  d          ", cyan),
            Span::raw("Delete selected entry (confirms)"),
        ]),
        Line::from(vec![Span::styled("  ?          ", cyan), Span::raw("Show this help")]),
        Line::from(vec![Span::styled("  Esc        ", cyan), Span::raw("Cancel / go back")]),
        Line::from(vec![Span::styled("  Ctrl+C     ", cyan), Span::raw("Force quit")]),
        Line::from(vec![Span::styled("  q          ", cyan), Span::raw("Quit")]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Set ONECIPHER_AGE_IDENTITY to enable copy/TOTP features.",
            dim,
        )]),
        Line::from(""),
        Line::from(vec![Span::styled("Press Esc or q to return", dim)]),
    ];

    let paragraph =
        Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title("Help"));
    frame.render_widget(paragraph, area);
}

// ── Helpers ───────────────────────────────────────────────────────────

/// Build a labelled detail line: `Label: value`.
///
/// Returns a `Line<'static>` so callers don't have to keep the value alive
/// (avoids temporary-value-dropped-while-borrowed errors for expressions
/// like `tags.join(", ")`).
fn labelled_line(label: &str, value: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{label}: "), Style::default().fg(Color::Cyan)),
        Span::raw(value.to_string()),
    ])
}

/// Return an emoji icon for the given item type.
fn type_icon(item_type: ItemType) -> &'static str {
    match item_type {
        ItemType::Mnemonic => "\u{1F511}",           // key
        ItemType::PrivateKey => "\u{1F5DD}\u{FE0F}", // old key
        ItemType::Password => "\u{1F512}",           // lock
        ItemType::Totp => "\u{1F553}",               // clock
        ItemType::Note => "\u{1F4DD}",               // memo
        ItemType::File => "\u{1F4CE}",               // paperclip
    }
}
