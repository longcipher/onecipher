//! `.age-recipients` file parsing, writing, and directory-scoped discovery.
//!
//! A recipients file is a plain-text file where each non-comment, non-empty
//! line is an age recipient string (`age1...`). Lines starting with `#` are
//! comments. This mirrors the `age` CLI's `.age-recipients` convention.

use std::{
    path::{Path, PathBuf},
    str::FromStr,
};

use age::x25519::Recipient as AgeX25519Recipient;

/// Errors returned by recipients file operations.
#[derive(Debug, thiserror::Error)]
pub enum RecipientError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid recipient '{0}': {1}")]
    InvalidRecipient(String, String),
    #[error("no recipients file found in any parent directory of {0}")]
    NotFound(PathBuf),
}

/// An age X25519 recipient (public key).
#[derive(Clone, Debug)]
pub struct Recipient {
    inner: AgeX25519Recipient,
}

impl FromStr for Recipient {
    type Err = RecipientError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let inner: AgeX25519Recipient = s
            .parse()
            .map_err(|e: &str| RecipientError::InvalidRecipient(s.to_string(), e.to_string()))?;
        Ok(Self { inner })
    }
}

impl std::fmt::Display for Recipient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.inner, f)
    }
}

/// A parsed `.age-recipients` file: a list of [`Recipient`] values.
#[derive(Debug, Default)]
pub struct RecipientsFile;

impl RecipientsFile {
    /// Load and parse a recipients file from disk.
    pub fn load(path: &Path) -> Result<Vec<Recipient>, RecipientError> {
        let content = std::fs::read_to_string(path)?;
        Self::parse(&content)
    }

    /// Parse recipients from a string (one per line; `#` starts a comment).
    ///
    /// Inline `#` comments are supported: `age1... # laptop` parses as the
    /// recipient only. Duplicates are dropped first-seen-wins so a repeated
    /// line cannot change the set; use [`canonicalize_strings`] or [`merge_strings`]
    /// for the sorted canonical write form (B8).
    pub fn parse(content: &str) -> Result<Vec<Recipient>, RecipientError> {
        let strings = parse_recipient_strings(content)?;
        let mut recipients = Vec::with_capacity(strings.len());
        for s in strings {
            // Already validated by `parse_recipient_strings`; parsing again is
            // infallible in practice but the error path stays defensive.
            recipients.push(Recipient::from_str(&s).map_err(|e| match e {
                RecipientError::InvalidRecipient(_, msg) => {
                    RecipientError::InvalidRecipient(s.clone(), msg)
                }
                other => other,
            })?);
        }
        Ok(recipients)
    }

    /// Write a list of recipients to a file (one per line, sorted + deduped).
    ///
    /// Written atomically at 0600. The canonical sorted/deduped form (B8)
    /// keeps diffs minimal and makes `merge == union` convergent. This list
    /// is security-critical even though it holds only public keys: a torn
    /// write that drops trailing lines would silently re-encrypt subsequent
    /// secrets to a *subset* of the intended recipients, locking those
    /// recipients out without any error.
    pub fn save(path: &Path, recipients: &[Recipient]) -> Result<(), RecipientError> {
        let strings: Vec<String> = recipients.iter().map(|r| r.to_string()).collect();
        let canonical = canonicalize_strings(&strings);
        let mut content = String::new();
        for s in &canonical {
            content.push_str(s);
            content.push('\n');
        }
        oc_core::paths::write_atomic_private(path, content.as_bytes())?;
        Ok(())
    }

    /// Walk up the directory tree from `dir` looking for a `.age-recipients`
    /// file. Returns the path of the first match, or
    /// [`RecipientError::NotFound`] if none is found before reaching the
    /// filesystem root.
    pub fn find_for_dir(dir: &Path) -> Result<PathBuf, RecipientError> {
        let mut current = dir.canonicalize().unwrap_or_else(|_| dir.to_path_buf());
        loop {
            let candidate = current.join(".age-recipients");
            if candidate.is_file() {
                return Ok(candidate);
            }
            if !current.pop() {
                return Err(RecipientError::NotFound(dir.to_path_buf()));
            }
        }
    }
}

/// Parse recipient strings with `#` comments and first-seen dedup (B8).
///
/// Each non-empty, non-comment line yields one recipient string. A `#`
/// starts an inline comment (`age1... # laptop`). Surrounding whitespace is
/// trimmed. Duplicates are dropped keeping the first occurrence so reads are
/// idempotent; callers that need the canonical write form must pass the
/// result through [`canonicalize_strings`].
pub fn parse_recipient_strings(content: &str) -> Result<Vec<String>, RecipientError> {
    use std::collections::HashSet;
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for line in content.lines() {
        // Strip inline comments first, then trim.
        let before_comment = line.split('#').next().unwrap_or("");
        let trimmed = before_comment.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Validate eagerly so a typo fails closed instead of silently
        // dropping a recipient.
        Recipient::from_str(trimmed)?;
        if seen.insert(trimmed.to_string()) {
            out.push(trimmed.to_string());
        }
    }
    Ok(out)
}

/// Canonicalize recipient strings: sort + dedup (B8).
///
/// The sorted form keeps file diffs minimal and makes merges convergent:
/// `merge(a, b) == merge(b, a)` and repeated merges are idempotent.
pub fn canonicalize_strings(recipients: &[String]) -> Vec<String> {
    let mut out: Vec<String> =
        recipients.iter().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    out.sort();
    out.dedup();
    out
}

/// Merge two recipient sets as a union in canonical form (B8).
///
/// Convergent: order-independent and idempotent, so concurrent edits that
/// only add recipients resolve to the same set.
pub fn merge_strings(a: &[String], b: &[String]) -> Vec<String> {
    let mut combined = Vec::with_capacity(a.len() + b.len());
    combined.extend(a.iter().cloned());
    combined.extend(b.iter().cloned());
    canonicalize_strings(&combined)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn random_recipient_string() -> String {
        age::x25519::Identity::generate().to_public().to_string()
    }

    #[test]
    fn parse_valid_recipient_round_trips() {
        let r_str = random_recipient_string();
        let r = Recipient::from_str(&r_str).unwrap();
        assert_eq!(r.to_string(), r_str);
    }

    #[test]
    fn parse_with_comments_and_blanks() {
        let r_str = random_recipient_string();
        let content = format!("# comment\n\n{r_str}\n# another\n");
        let recipients = RecipientsFile::parse(&content).unwrap();
        assert_eq!(recipients.len(), 1);
        assert_eq!(recipients[0].to_string(), r_str);
    }

    #[test]
    fn parse_invalid_recipient_returns_error() {
        let result = RecipientsFile::parse("not-a-valid-recipient");
        assert!(matches!(result, Err(RecipientError::InvalidRecipient(_, _))));
    }

    #[test]
    fn save_and_load_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".age-recipients");

        let r1 = random_recipient_string();
        let r2 = random_recipient_string();
        let recipients = vec![Recipient::from_str(&r1).unwrap(), Recipient::from_str(&r2).unwrap()];

        RecipientsFile::save(&path, &recipients).unwrap();
        let loaded = RecipientsFile::load(&path).unwrap();
        assert_eq!(loaded.len(), 2);
        // Save canonicalizes (sorted), so compare as sets.
        let mut got: Vec<String> = loaded.iter().map(|r| r.to_string()).collect();
        got.sort();
        let mut expected = vec![r1, r2];
        expected.sort();
        assert_eq!(got, expected);
    }

    #[test]
    fn find_for_dir_finds_file_in_dir() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".age-recipients");
        let r_str = random_recipient_string();
        let recipients = vec![Recipient::from_str(&r_str).unwrap()];
        RecipientsFile::save(&path, &recipients).unwrap();

        let found = RecipientsFile::find_for_dir(dir.path()).unwrap();
        // Compare via canonicalize to avoid macOS /tmp -> /private/tmp symlink issues.
        let found_c = found.canonicalize().unwrap_or(found);
        let path_c = path.canonicalize().unwrap_or(path);
        assert_eq!(found_c, path_c);
    }

    #[test]
    fn display_matches_to_string() {
        let r_str = random_recipient_string();
        let r = Recipient::from_str(&r_str).unwrap();
        assert_eq!(format!("{r}"), r_str);
    }

    #[test]
    fn parse_supports_inline_comments_and_first_seen_dedup() {
        let r = random_recipient_string();
        let content = format!("# header\n{r} # laptop\n{r}\n  {r}  \n");
        let parsed = parse_recipient_strings(&content).unwrap();
        assert_eq!(parsed, vec![r]);
    }

    #[test]
    fn canonicalize_sorts_and_dedups() {
        let b = "b".to_string();
        let a = "a".to_string();
        assert_eq!(canonicalize_strings(&[b.clone(), a.clone(), b.clone()]), vec![a, b]);
    }

    #[test]
    fn merge_is_union_convergent_and_idempotent() {
        let a = vec!["b".to_string(), "a".to_string()];
        let b = vec!["c".to_string(), "a".to_string()];
        let ab = merge_strings(&a, &b);
        let ba = merge_strings(&b, &a);
        assert_eq!(ab, ba);
        assert_eq!(ab, vec!["a".to_string(), "b".to_string(), "c".to_string()]);
        assert_eq!(merge_strings(&ab, &ab), ab);
        assert_eq!(merge_strings(&ab, &[]), ab);
    }

    #[test]
    fn save_writes_canonical_sorted_form() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".age-recipients");
        let r1 = random_recipient_string();
        let r2 = random_recipient_string();
        let (hi, lo) = if r1 > r2 { (r1.clone(), r2.clone()) } else { (r2.clone(), r1.clone()) };
        let recipients = vec![Recipient::from_str(&hi).unwrap(), Recipient::from_str(&lo).unwrap()];
        RecipientsFile::save(&path, &recipients).unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<&str> = raw.lines().collect();
        lines.sort_unstable();
        let mut expected = vec![r1.as_str(), r2.as_str()];
        expected.sort_unstable();
        assert_eq!(lines, expected);
    }
}
