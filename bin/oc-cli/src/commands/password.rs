//! Password-specific CLI commands (`onecipher password ...`).
//!
//! Convenience wrappers around [`super::secret`] that pre-fill `ItemType::Password`
//! and handle password generation + clipboard copy.

use oc_core::{ItemType, SecretMetadata, SecretPayload};

use crate::CliError;

/// Default generated password length.
#[allow(dead_code)]
const DEFAULT_PASSWORD_LENGTH: usize = 32;

/// Entry point for `onecipher password add <name> --url <url> --username <user>
/// [--generate] [--length 32] [--symbols]`.
///
/// When `--generate` is set, a random password is generated and stored.
/// Otherwise, the password is read from `ONECIPHER_SECRET` env var or an
/// interactive prompt.
#[allow(dead_code)]
pub(crate) fn add(
    name: &str,
    url: &str,
    username: &str,
    generate: bool,
    length: usize,
    symbols: bool,
) -> Result<(), CliError> {
    let secret = if generate {
        generate_password(length, symbols)
    } else {
        super::read_secret_from_env_or_prompt()?
    };

    let metadata = SecretMetadata {
        url: Some(url.to_string()),
        username: Some(username.to_string()),
        ..Default::default()
    };

    let payload = SecretPayload { secret, notes: None, extra: None };
    let recipients = super::load_recipients()?;
    if recipients.is_empty() {
        return Err(CliError::InvalidArgs(
            "no recipients found — run `onecipher age init` first".into(),
        ));
    }

    let entry =
        oc_secret::SecretEntry::new(name, ItemType::Password, &payload, metadata, &recipients)
            .map_err(|e| CliError::InvalidArgs(format!("failed to create entry: {e}")))?;

    let store = super::open_secret_store()?;
    store.put(&entry).map_err(super::secret::map_store_error)?;
    println!("Password added: {name}");
    Ok(())
}

/// Entry point for `onecipher password get <name> [--copy] [--timeout 45]`.
///
/// Decrypts and prints the password. When `--copy` is set, the password is
/// copied to the system clipboard and auto-cleared after `timeout` seconds.
/// A `timeout` of 0 disables auto-clear.
#[allow(dead_code)]
pub(crate) fn get(name: &str, copy: bool, timeout: u64) -> Result<(), CliError> {
    let store = super::open_secret_store()?;
    let entry = store.get(name).map_err(super::secret::map_store_error)?;
    let identity = super::load_age_identity()?;
    let payload = entry
        .decrypt(&identity)
        .map_err(|e| CliError::InvalidArgs(format!("decryption failed: {e}")))?;

    if copy {
        super::clipboard::copy_and_clear(&payload.secret, timeout)?;
    } else {
        println!("{}", payload.secret);
    }

    Ok(())
}

/// Entry point for `onecipher password generate [--length 32] [--symbols] [--qr]`.
///
/// Generates a random password and prints it to stdout.
/// When `--qr` is set, the password is displayed as a QR code in the terminal.
///
/// Supports three generator strategies:
/// - `cryptic`: random characters (default)
/// - `memorable`: word+digit+word+symbol pattern
/// - `xkcd`: XKCD-style passphrase (correct-horse-battery-staple)
#[allow(dead_code)]
pub(crate) fn generate(
    length: usize,
    symbols: bool,
    generator: &str,
    xkcd_sep: &str,
    xkcd_words: usize,
    qr: bool,
) -> Result<(), CliError> {
    let password = match generator {
        "cryptic" => generate_password(length, symbols),
        "memorable" => generate_memorable(length, symbols),
        "xkcd" => generate_xkcd(xkcd_words, xkcd_sep),
        other => {
            return Err(CliError::InvalidArgs(format!(
                "unknown generator '{other}'; expected: cryptic, memorable, xkcd"
            )));
        }
    };
    if qr {
        return super::print_qr(&password);
    }
    println!("{password}");
    Ok(())
}

/// Generate a random password.
///
/// When `symbols` is true, uses ASCII printable characters 33-126 (includes
/// letters, digits, and symbols). When false, uses only alphanumeric
/// characters (a-z, A-Z, 0-9).
fn generate_password(length: usize, symbols: bool) -> String {
    let charset: Vec<u8> = if symbols {
        (33u8..=126).collect()
    } else {
        let mut chars: Vec<u8> = (b'a'..=b'z').collect();
        chars.extend(b'A'..=b'Z');
        chars.extend(b'0'..=b'9');
        chars
    };

    (0..length)
        .map(|_| {
            let idx = rand::random_range(0..charset.len());
            charset[idx] as char
        })
        .collect()
}

/// EFF-style short wordlist (150 common, easy-to-spell English words).
/// Derived from the EFF Diceware short wordlist for passphrase generation.
const WORDLIST: &[&str] = &[
    "acid", "acorn", "acre", "aged", "agent", "agile", "aging", "agony", "aide", "aids", "alarm",
    "alias", "alibi", "alien", "align", "alive", "alloy", "alpha", "altar", "alter", "amber",
    "angel", "anger", "angle", "angry", "ankle", "annex", "apple", "arena", "argue", "arise",
    "armor", "army", "aroma", "arrow", "aside", "asset", "atlas", "attic", "audio", "author",
    "awake", "bacon", "badge", "bagel", "baker", "basic", "basin", "batch", "beach", "beast",
    "being", "bench", "berry", "birth", "blade", "blame", "blank", "blast", "blaze", "bleed",
    "blend", "bless", "blind", "block", "bloom", "blown", "board", "bonus", "booth", "brain",
    "brand", "brave", "bread", "break", "breed", "brick", "bride", "brief", "bring", "broad",
    "brook", "brown", "brush", "buddy", "build", "bunch", "burst", "buyer", "cabin", "cable",
    "camel", "candy", "cargo", "carry", "catch", "cause", "cedar", "chain", "chair", "chalk",
    "chaos", "charm", "chase", "cheap", "check", "cheek", "chess", "chest", "chief", "child",
    "chunk", "civic", "civil", "claim", "clash", "class", "clean", "clear", "climb", "cling",
    "clock", "clone", "close", "cloud", "coach", "coast", "color", "comet", "coral", "couch",
    "could", "count", "court", "cover", "crack", "craft", "crane", "crash", "crawl", "crazy",
    "cream", "crime", "cross", "crowd", "crown", "crush", "curve", "cycle", "dairy",
];

/// Symbol characters used by the memorable generator.
const MEMORABLE_SYMBOLS: &[char] = &['!', '@', '#', '$', '%', '^', '&', '*', '-', '_', '+', '='];

/// Generate a memorable password: word + digit + word + symbol, repeated until
/// length is met.
fn generate_memorable(length: usize, symbols: bool) -> String {
    let mut result = String::new();
    while result.len() < length {
        let word1 = WORDLIST[rand::random_range(0..WORDLIST.len())];
        let digit = (b'0' + rand::random_range(0u8..10)) as char;
        let word2 = WORDLIST[rand::random_range(0..WORDLIST.len())];
        result.push_str(word1);
        result.push(digit);
        result.push_str(word2);
        if symbols {
            let sym = MEMORABLE_SYMBOLS[rand::random_range(0..MEMORABLE_SYMBOLS.len())];
            result.push(sym);
        }
    }
    result.truncate(length);
    result
}

/// Generate an XKCD-style passphrase: N random words joined by a separator.
fn generate_xkcd(num_words: usize, sep: &str) -> String {
    (0..num_words)
        .map(|_| WORDLIST[rand::random_range(0..WORDLIST.len())])
        .collect::<Vec<_>>()
        .join(sep)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_password_has_correct_length() {
        let pw = generate_password(20, false);
        assert_eq!(pw.len(), 20);
    }

    #[test]
    fn generated_password_alphanumeric_only() {
        let pw = generate_password(100, false);
        assert!(pw.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn generated_password_with_symbols_has_printable_chars() {
        let pw = generate_password(100, true);
        assert!(pw.chars().all(|c| c.is_ascii_graphic()));
    }

    #[test]
    fn default_password_length_is_32() {
        assert_eq!(DEFAULT_PASSWORD_LENGTH, 32);
    }

    #[test]
    fn memorable_password_respects_length() {
        let pw = generate_memorable(50, true);
        assert_eq!(pw.len(), 50);
    }

    #[test]
    fn memorable_password_without_symbols_has_no_symbols() {
        let pw = generate_memorable(200, false);
        assert!(pw.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn xkcd_passphrase_word_count() {
        let pw = generate_xkcd(4, "-");
        let words: Vec<&str> = pw.split('-').collect();
        assert_eq!(words.len(), 4);
        assert!(words.iter().all(|w| WORDLIST.contains(w)));
    }

    #[test]
    fn xkcd_passphrase_custom_separator() {
        let pw = generate_xkcd(3, ".");
        assert!(pw.contains('.'));
        assert_eq!(pw.matches('.').count(), 2);
    }

    #[test]
    fn wordlist_has_150_entries() {
        assert_eq!(WORDLIST.len(), 150);
    }
}
