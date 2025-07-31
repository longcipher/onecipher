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
    pub fn parse(content: &str) -> Result<Vec<Recipient>, RecipientError> {
        let mut recipients = Vec::new();
        for (lineno, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let recipient = Recipient::from_str(trimmed).map_err(|e| match e {
                RecipientError::InvalidRecipient(_, msg) => {
                    RecipientError::InvalidRecipient(format!("line {lineno}"), msg)
                }
                other => other,
            })?;
            recipients.push(recipient);
        }
        Ok(recipients)
    }

    /// Write a list of recipients to a file (one per line).
    pub fn save(path: &Path, recipients: &[Recipient]) -> Result<(), RecipientError> {
        let mut content = String::new();
        for r in recipients {
            content.push_str(&r.to_string());
            content.push('\n');
        }
        std::fs::write(path, content)?;
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
        assert_eq!(loaded[0].to_string(), r1);
        assert_eq!(loaded[1].to_string(), r2);
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
}
