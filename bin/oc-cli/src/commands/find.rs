//! Fuzzy search command (`onecipher find`).
//!
//! Searches secrets using substring matching (via `SecretStore::search`),
//! falling back to a simple fuzzy scorer when no exact/substring matches
//! are found. Presents results via an interactive crossterm selector when
//! the terminal is interactive and multiple matches exist.

use std::io::{self, IsTerminal, Write};

use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyEvent, KeyModifiers},
    execute,
    style::{self, Attribute, Color, Stylize},
    terminal,
};
use oc_core::SecretIndexEntry;

use crate::CliError;

/// Entry point for `onecipher find [QUERY] [--regex] [--json] [--type <type>]`.
#[allow(dead_code)]
pub(crate) fn run(
    query: Option<&str>,
    regex: bool,
    json: bool,
    type_filter: Option<&str>,
) -> Result<(), CliError> {
    let store = super::open_secret_store()?;
    let item_type = type_filter.map(super::parse_item_type).transpose()?;

    let entries = if let Some(q) = query {
        let mut results = if regex {
            regex_search(&store, q)?
        } else {
            store.search(q).map_err(|e| CliError::InvalidArgs(e.to_string()))?
        };

        // Apply type filter.
        if let Some(ref filter_type) = item_type {
            results.retain(|e| &e.item_type == filter_type);
        }

        // If substring search returned nothing, try fuzzy matching.
        if results.is_empty() && !regex {
            let all_entries = store.list().map_err(|e| CliError::InvalidArgs(e.to_string()))?;
            let mut filtered = all_entries;
            if let Some(ref filter_type) = item_type {
                filtered.retain(|e| &e.item_type == filter_type);
            }
            results = fuzzy_search(q, &filtered);
        }

        // Exact name match → display directly.
        if results.len() == 1 && results[0].name.eq_ignore_ascii_case(q) {
            return display_entry(&results[0], json);
        }

        results
    } else {
        // No query — list all entries.
        let mut entries = store.list().map_err(|e| CliError::InvalidArgs(e.to_string()))?;
        if let Some(ref filter_type) = item_type {
            entries.retain(|e| &e.item_type == filter_type);
        }
        entries
    };

    if entries.is_empty() {
        println!("No matching secrets found.");
        return Ok(());
    }

    // Single result — display it directly.
    if entries.len() == 1 {
        return display_entry(&entries[0], json);
    }

    // JSON mode — output all matches as a JSON array.
    if json {
        let json_str = serde_json::to_string_pretty(&entries)?;
        println!("{json_str}");
        return Ok(());
    }

    // Interactive selector when stdin is a terminal.
    if io::stdin().is_terminal() {
        interactive_select(&entries)?;
    } else {
        // Non-interactive: print all matches.
        for e in &entries {
            print_index_entry(e);
            println!();
        }
    }

    Ok(())
}

/// Regex-based search over secret index entries.
fn regex_search(
    store: &oc_secret::SecretStore,
    pattern: &str,
) -> Result<Vec<SecretIndexEntry>, CliError> {
    let re = regex_lite::RegexBuilder::new(pattern)
        .case_insensitive(true)
        .build()
        .map_err(|e| CliError::InvalidArgs(format!("invalid regex: {e}")))?;

    let entries = store.list().map_err(|e| CliError::InvalidArgs(e.to_string()))?;

    Ok(entries
        .into_iter()
        .filter(|e| {
            re.is_match(&e.name) ||
                e.metadata.url.as_ref().is_some_and(|s| re.is_match(s)) ||
                e.metadata.username.as_ref().is_some_and(|s| re.is_match(s)) ||
                e.metadata.issuer.as_ref().is_some_and(|s| re.is_match(s)) ||
                e.metadata.account.as_ref().is_some_and(|s| re.is_match(s)) ||
                e.metadata.tags.iter().any(|t| re.is_match(t))
        })
        .collect())
}

/// Simple fuzzy scorer: matches query characters sequentially against the
/// target name. Returns `Some(score)` if all query characters were found,
/// `None` otherwise.
///
/// Scoring rewards:
/// - Consecutive character matches (bonus multiplier).
/// - Matching at word boundaries (after `-`, `_`, `/`, `.`).
/// - Early matches (smaller index → higher score).
fn fuzzy_score(query: &str, target: &str) -> Option<u32> {
    let query_lower: Vec<char> = query.to_ascii_lowercase().chars().collect();
    let target_lower: Vec<char> = target.to_ascii_lowercase().chars().collect();

    if query_lower.is_empty() {
        return Some(0);
    }

    let mut score: u32 = 0;
    let mut consecutive = 0u32;
    let mut qi = 0;

    for (ti, &tc) in target_lower.iter().enumerate() {
        if qi >= query_lower.len() {
            break;
        }
        if tc == query_lower[qi] {
            consecutive += 1;
            // Base score: 10 per match.
            score += 10;
            // Consecutive bonus: (consecutive - 1) * 5.
            if consecutive > 1 {
                score += (consecutive - 1) * 5;
            }
            // Word boundary bonus: if the previous character is a separator.
            if ti == 0 || is_separator(target_lower[ti - 1]) {
                score += 15;
            }
            // Position bonus: earlier matches score higher.
            score += (target_lower.len() as u32).saturating_sub(ti as u32);
            qi += 1;
        } else {
            consecutive = 0;
        }
    }

    (qi == query_lower.len()).then_some(score)
}

fn is_separator(c: char) -> bool {
    c == '-' || c == '_' || c == '/' || c == '.' || c == ' '
}

/// Fuzzy search: score all entries, return top 10 sorted by score descending.
fn fuzzy_search(query: &str, entries: &[SecretIndexEntry]) -> Vec<SecretIndexEntry> {
    let mut scored: Vec<(u32, &SecretIndexEntry)> =
        entries.iter().filter_map(|e| fuzzy_score(query, &e.name).map(|s| (s, e))).collect();

    scored.sort_by_key(|a| std::cmp::Reverse(a.0));
    scored.into_iter().take(10).map(|(_, e)| e.clone()).collect()
}

/// Display a single `SecretIndexEntry` (without decrypting).
fn display_entry(entry: &SecretIndexEntry, json: bool) -> Result<(), CliError> {
    if json {
        let json_str = serde_json::to_string_pretty(entry)?;
        println!("{json_str}");
    } else {
        print_index_entry(entry);
    }
    Ok(())
}

/// Pretty-print a `SecretIndexEntry` to stdout.
fn print_index_entry(e: &SecretIndexEntry) {
    println!("Name:      {}", e.name);
    println!("Type:      {}", e.item_type);
    println!("ID:        {}", e.id);
    println!("Created:   {}", e.created_at);
    println!("Updated:   {}", e.updated_at);
    if let Some(url) = &e.metadata.url {
        println!("URL:       {url}");
    }
    if let Some(user) = &e.metadata.username {
        println!("Username:  {user}");
    }
    if let Some(issuer) = &e.metadata.issuer {
        println!("Issuer:    {issuer}");
    }
    if let Some(account) = &e.metadata.account {
        println!("Account:   {account}");
    }
    if !e.metadata.tags.is_empty() {
        println!("Tags:      {}", e.metadata.tags.join(", "));
    }
}

/// Interactive fuzzy selector using crossterm.
///
/// Renders a list of entries in the terminal. The user can navigate with
/// Up/Down arrows, press Enter to select, or q/Esc to quit.
fn interactive_select(entries: &[SecretIndexEntry]) -> Result<(), CliError> {
    let mut stdout = io::stdout();
    terminal::enable_raw_mode()?;
    execute!(stdout, cursor::Hide, terminal::EnterAlternateScreen)?;

    let result = run_selector(entries, &mut stdout);

    // Always restore terminal state.
    execute!(stdout, cursor::Show, terminal::LeaveAlternateScreen)?;
    terminal::disable_raw_mode()?;

    match result {
        Ok(Some(selected)) => {
            // Display the selected entry.
            display_entry(&selected, false)?;
        }
        Ok(None) => {
            // User cancelled — no output.
        }
        Err(e) => {
            return Err(e);
        }
    }

    Ok(())
}

/// The core selector loop. Runs in raw mode with alternate screen.
fn run_selector(
    entries: &[SecretIndexEntry],
    stdout: &mut io::Stdout,
) -> Result<Option<SecretIndexEntry>, CliError> {
    let mut selected: usize = 0;
    let mut query = String::new();
    let mut filtered: Vec<usize> = (0..entries.len()).collect();

    loop {
        render_selector(stdout, entries, &filtered, selected, &query)?;

        if let Event::Key(KeyEvent { code, modifiers, .. }) = event::read()? {
            match code {
                KeyCode::Up => {
                    if selected > 0 {
                        selected -= 1;
                    } else if !filtered.is_empty() {
                        selected = filtered.len() - 1;
                    }
                }
                KeyCode::Down => {
                    if !filtered.is_empty() && selected < filtered.len() - 1 {
                        selected += 1;
                    } else {
                        selected = 0;
                    }
                }
                KeyCode::Enter => {
                    if !filtered.is_empty() {
                        return Ok(Some(entries[filtered[selected]].clone()));
                    }
                }
                KeyCode::Esc => {
                    return Ok(None);
                }
                KeyCode::Char('c') if modifiers.contains(KeyModifiers::CONTROL) => {
                    return Ok(None);
                }
                KeyCode::Char('q') => {
                    return Ok(None);
                }
                KeyCode::Char(c) => {
                    query.push(c);
                    update_filtered(entries, &query, &mut filtered, &mut selected);
                }
                KeyCode::Backspace => {
                    query.pop();
                    update_filtered(entries, &query, &mut filtered, &mut selected);
                }
                _ => {}
            }
        }
    }
}

/// Update the filtered list based on the current query. Resets selection
/// if the current selection is out of bounds.
fn update_filtered(
    entries: &[SecretIndexEntry],
    query: &str,
    filtered: &mut Vec<usize>,
    selected: &mut usize,
) {
    if query.is_empty() {
        *filtered = (0..entries.len()).collect();
    } else {
        // Score all entries, keep those with a fuzzy match, sorted by score.
        let mut scored: Vec<(u32, usize)> = entries
            .iter()
            .enumerate()
            .filter_map(|(i, e)| fuzzy_score(query, &e.name).map(|s| (s, i)))
            .collect();
        scored.sort_by_key(|a| std::cmp::Reverse(a.0));
        *filtered = scored.into_iter().map(|(_, i)| i).collect();
    }
    if *selected >= filtered.len() {
        *selected = filtered.len().saturating_sub(1);
    }
}

/// Render the selector list.
fn render_selector(
    stdout: &mut io::Stdout,
    entries: &[SecretIndexEntry],
    filtered: &[usize],
    selected: usize,
    query: &str,
) -> Result<(), CliError> {
    execute!(stdout, cursor::MoveTo(0, 0), terminal::Clear(terminal::ClearType::All))?;

    // Title line.
    let title = "onecipher find — type to filter, ↑↓ to navigate, Enter to select, q to quit";
    writeln!(stdout, "{}", style::PrintStyledContent(title.bold().with(Color::Cyan)))?;

    // Query line.
    writeln!(
        stdout,
        "{}{}",
        style::PrintStyledContent("> ".with(Color::Green)),
        style::Print(query)
    )?;
    writeln!(stdout)?;

    // Entries list.
    if filtered.is_empty() {
        writeln!(stdout, "{}", style::PrintStyledContent("  (no matches)".with(Color::DarkGrey)))?;
    } else {
        for (display_idx, &entry_idx) in filtered.iter().enumerate() {
            let e = &entries[entry_idx];
            let name = &e.name;
            let type_str = format!("[{}]", e.item_type);

            if display_idx == selected {
                writeln!(
                    stdout,
                    "{} {} {}",
                    style::PrintStyledContent("▸".with(Color::Green).bold()),
                    style::PrintStyledContent(
                        name.clone().with(Color::White).attribute(Attribute::Bold)
                    ),
                    style::PrintStyledContent(type_str.with(Color::DarkGrey))
                )?;
            } else {
                writeln!(
                    stdout,
                    "  {} {}",
                    style::PrintStyledContent(name.clone().with(Color::White)),
                    style::PrintStyledContent(type_str.with(Color::DarkGrey))
                )?;
            }
        }
    }

    stdout.flush()?;
    Ok(())
}
