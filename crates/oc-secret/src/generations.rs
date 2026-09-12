//! Git-sync generation index (`generations` file).
//!
//! The `generations` file tracks per-secret monotonic generation counters so
//! git-sync peers can detect lag/stale replicas without decrypting anything.
//!
//! Format: one `"<path> <generation>"` record per line, sorted by path. `gen` is a
//! base-10 `u64`. Parsing is max-reduce with silent drops:
//! - blank lines are skipped,
//! - lines failing validation are silently dropped,
//! - duplicate paths collapse to the maximum generation.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

/// File name of the generation index inside the store root.
pub const GENERATIONS_FILE: &str = "generations";

/// Parse `generations` text with max-reduce semantics.
///
/// Empty lines are skipped, invalid lines are silently dropped, and duplicate
/// paths collapse to the maximum generation.
pub fn parse_generations(text: &str) -> BTreeMap<String, u64> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((path, generation)) = line.rsplit_once(char::is_whitespace) else {
            continue;
        };
        let path = path.trim();
        let generation = generation.trim();
        if !is_valid_path(path) {
            continue;
        }
        let Ok(generation) = generation.parse::<u64>() else {
            continue;
        };
        out.entry(path.to_string())
            .and_modify(|e: &mut u64| *e = (*e).max(generation))
            .or_insert(generation);
    }
    out
}

/// Render a generation map sorted by path (BTreeMap iteration order).
pub fn render_generations(map: &BTreeMap<String, u64>) -> String {
    let mut s = String::new();
    for (path, generation) in map {
        s.push_str(path);
        s.push(' ');
        s.push_str(&generation.to_string());
        s.push('\n');
    }
    s
}

/// Merge two generation maps (union, max-reduce on collision).
pub fn merge_generations(
    a: &BTreeMap<String, u64>,
    b: &BTreeMap<String, u64>,
) -> BTreeMap<String, u64> {
    let mut out = a.clone();
    for (k, v) in b {
        out.entry(k.clone()).and_modify(|e| *e = (*e).max(*v)).or_insert(*v);
    }
    out
}

/// Path of the `generations` file for a store root.
pub fn generations_path(root: &Path) -> PathBuf {
    root.join(GENERATIONS_FILE)
}

/// Load the `generations` file; missing file yields an empty map.
pub fn load_generations(root: &Path) -> BTreeMap<String, u64> {
    let path = generations_path(root);
    match std::fs::read_to_string(&path) {
        Ok(text) => parse_generations(&text),
        Err(_) => BTreeMap::new(),
    }
}

/// Save the `generations` file atomically at 0600.
pub fn save_generations(root: &Path, map: &BTreeMap<String, u64>) -> std::io::Result<()> {
    let text = render_generations(map);
    oc_core::paths::write_atomic_private(&generations_path(root), text.as_bytes())
}

/// Bump the generation for `path` (insert 1 if absent, else +1 saturating).
pub fn bump_generation(root: &Path, path: &str) -> std::io::Result<u64> {
    let mut map = load_generations(root);
    let next = map.get(path).copied().unwrap_or(0).saturating_add(1);
    map.insert(path.to_string(), next);
    save_generations(root, &map)?;
    Ok(next)
}

/// Validate a generation path: reuse secret-name rules (no empty, no
/// backslash, no leading dot, no `..` component).
fn is_valid_path(path: &str) -> bool {
    if path.is_empty() || path.len() > 512 {
        return false;
    }
    if path.contains('\\') || path.contains('\0') {
        return false;
    }
    if path == "." || path == ".." || path.starts_with('.') {
        return false;
    }
    if path.split('/').any(|c| c == ".." || c.is_empty()) {
        return false;
    }
    if path.trim() != path {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_skips_blank_and_drops_invalid_silently() {
        let text = "\n  \na 1\nbad-line-no-generation\nc notanumber\na 5\na 3\n../evil 9\n";
        let m = parse_generations(text);
        // Same path takes max (5), invalid lines dropped.
        assert_eq!(m.get("a"), Some(&5));
        assert!(!m.contains_key("bad-line-no-generation"));
        assert!(!m.contains_key("c"));
        assert!(!m.contains_key("../evil"));
    }

    #[test]
    fn render_is_sorted_and_merge_is_union_max() {
        let mut a = BTreeMap::new();
        a.insert("b".to_string(), 1);
        a.insert("a".to_string(), 5);
        let text = render_generations(&a);
        assert!(text.starts_with("a 5\nb 1\n"));
        let mut b = BTreeMap::new();
        b.insert("a".to_string(), 3);
        b.insert("c".to_string(), 7);
        let m = merge_generations(&a, &b);
        assert_eq!(m.get("a"), Some(&5));
        assert_eq!(m.get("c"), Some(&7));
    }

    #[test]
    fn bump_starts_at_one_and_increments() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(bump_generation(dir.path(), "x").unwrap(), 1);
        assert_eq!(bump_generation(dir.path(), "x").unwrap(), 2);
        assert_eq!(load_generations(dir.path()).get("x"), Some(&2));
    }
}
