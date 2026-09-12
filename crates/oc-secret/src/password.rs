//! Unified password generation (pwgen-style) and strength audit.
//!
//! This module is the single source of truth for password material: the
//! `password generate` / `password add --generate` CLI paths and any future
//! caller share these functions. Generation uses a CSPRNG (`rand`) and
//! returns [`Zeroizing`] buffers that are wiped on drop; only the CLI
//! `--json`/stdout boundary converts to a plain `String` (documented
//! forensic window on [`oc_core::SecretPayload`]).
//!
//! Per R56 this module is synchronous `std` only (no `tokio`).

use zeroize::Zeroizing;

/// Default generated password length (matches the CLI `--length` default).
pub const PASSWORD_DEFAULT_LENGTH: usize = 32;

/// Minimum password length accepted by the strength audit.
pub const PASSWORD_MIN_LENGTH: usize = 12;

/// Character set for `cryptic` generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PasswordCharset {
    /// Lowercase + uppercase + digits.
    Alphanum,
    /// Lowercase hex (`0-9a-f`).
    Hex,
    /// All ASCII printable characters (33-126, letters + digits + symbols).
    Printable,
    /// Lowercase alphanumeric plus `-` (URL/slug safe).
    Slug,
}

impl PasswordCharset {
    /// Byte alphabet for this charset (never empty).
    fn alphabet(self) -> &'static [u8] {
        match self {
            Self::Alphanum => b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
            Self::Hex => b"0123456789abcdef",
            Self::Printable => {
                // ASCII 33..=126 laid out literally so the table is `static`.
                b"!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"
            }
            Self::Slug => b"abcdefghijklmnopqrstuvwxyz0123456789-",
        }
    }
}

/// Generator strategy for [`generate`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum PasswordGenerator {
    /// Random characters from a charset.
    #[default]
    Cryptic,
    /// `word + digit + word + symbol` repeated to length.
    Memorable,
    /// XKCD-style passphrase: N random words joined by a separator.
    Xkcd,
}

impl PasswordGenerator {
    /// Parse a generator name (`cryptic` / `memorable` / `xkcd`).
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "cryptic" => Some(Self::Cryptic),
            "memorable" => Some(Self::Memorable),
            "xkcd" => Some(Self::Xkcd),
            _ => None,
        }
    }
}

/// Options for [`generate`].
#[derive(Clone, Debug)]
pub struct PasswordOptions {
    /// Desired length in characters (cryptic/memorable) or bytes of output.
    pub length: usize,
    /// When true (cryptic only), use the full printable set; otherwise alphanum.
    pub symbols: bool,
    /// Generation strategy.
    pub generator: PasswordGenerator,
    /// Word separator for the XKCD strategy.
    pub xkcd_sep: String,
    /// Word count for the XKCD strategy.
    pub xkcd_words: usize,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self {
            length: PASSWORD_DEFAULT_LENGTH,
            symbols: false,
            generator: PasswordGenerator::Cryptic,
            xkcd_sep: "-".to_string(),
            xkcd_words: 4,
        }
    }
}

/// Errors returned by [`generate`].
#[derive(Debug, thiserror::Error)]
pub enum PasswordError {
    /// Unknown generator name.
    #[error("unknown generator '{0}'; expected: cryptic, memorable, xkcd")]
    UnknownGenerator(String),
}

/// Generate a random password with the given options.
///
/// Dispatches to the strategy in `opts.generator`. The returned buffer is
/// [`Zeroizing`] (wiped on drop).
pub fn generate(opts: &PasswordOptions) -> Result<Zeroizing<String>, PasswordError> {
    match opts.generator {
        PasswordGenerator::Cryptic => Ok(generate_password(opts.length, opts.symbols)),
        PasswordGenerator::Memorable => Ok(generate_memorable(opts.length, opts.symbols)),
        PasswordGenerator::Xkcd => Ok(generate_xkcd(opts.xkcd_words, &opts.xkcd_sep)),
    }
}

/// Generate a random cryptic password.
///
/// When `symbols` is true, uses all ASCII printable characters (33-126);
/// otherwise only alphanumeric characters.
pub fn generate_password(length: usize, symbols: bool) -> Zeroizing<String> {
    let charset = if symbols { PasswordCharset::Printable } else { PasswordCharset::Alphanum };
    generate_with_charset(length, charset)
}

/// Generate a random password from an explicit charset.
pub fn generate_with_charset(length: usize, charset: PasswordCharset) -> Zeroizing<String> {
    let alphabet = charset.alphabet();
    let mut out = Zeroizing::new(String::with_capacity(length));
    for _ in 0..length {
        let idx = rand::random_range(0..alphabet.len());
        out.push(alphabet[idx] as char);
    }
    out
}

/// EFF-style short wordlist (150 common, easy-to-spell English words).
/// Derived from the EFF Diceware short wordlist for passphrase generation.
pub const WORDLIST: &[&str] = &[
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
pub const MEMORABLE_SYMBOLS: &[char] =
    &['!', '@', '#', '$', '%', '^', '&', '*', '-', '_', '+', '='];

/// Generate a memorable password: word + digit + word + symbol, repeated
/// until `length` is met, then truncated.
pub fn generate_memorable(length: usize, symbols: bool) -> Zeroizing<String> {
    let mut result = Zeroizing::new(String::new());
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

/// Generate an XKCD-style passphrase: `num_words` random words joined by `sep`.
pub fn generate_xkcd(num_words: usize, sep: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::new());
    for i in 0..num_words {
        if i > 0 {
            out.push_str(sep);
        }
        out.push_str(WORDLIST[rand::random_range(0..WORDLIST.len())]);
    }
    out
}

/// Audit a password for weakness.
///
/// Returns `Some(reason)` when the password is weak (`< 12` chars or missing
/// character classes), `None` when it passes. Shared by `audit secrets` so
/// the CLI never re-implements the policy.
pub fn password_strength(password: &str) -> Option<String> {
    let len = password.chars().count();
    let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
    let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_special = password.chars().any(|c| !c.is_ascii_alphanumeric());

    if len < PASSWORD_MIN_LENGTH {
        return Some(format!("too short ({len} chars, minimum {PASSWORD_MIN_LENGTH})"));
    }
    let mut missing = Vec::new();
    if !has_upper {
        missing.push("uppercase");
    }
    if !has_lower {
        missing.push("lowercase");
    }
    if !has_digit {
        missing.push("digit");
    }
    if !has_special {
        missing.push("special char");
    }
    if missing.is_empty() { None } else { Some(format!("missing: {}", missing.join(", "))) }
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
    fn charset_alphabets_have_expected_shapes() {
        let hex = generate_with_charset(64, PasswordCharset::Hex);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        let slug = generate_with_charset(64, PasswordCharset::Slug);
        assert!(slug.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'));
    }

    #[test]
    fn default_options_match_cli_contract() {
        let opts = PasswordOptions::default();
        assert_eq!(opts.length, PASSWORD_DEFAULT_LENGTH);
        assert_eq!(PASSWORD_DEFAULT_LENGTH, 32);
        let pw = generate(&opts).unwrap();
        assert_eq!(pw.len(), 32);
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

    #[test]
    fn generator_parses_known_names() {
        assert_eq!(PasswordGenerator::parse("cryptic"), Some(PasswordGenerator::Cryptic));
        assert_eq!(PasswordGenerator::parse("XKCD"), Some(PasswordGenerator::Xkcd));
        assert_eq!(PasswordGenerator::parse("bogus"), None);
    }

    #[test]
    fn strength_flags_short_and_weak() {
        assert!(password_strength("short").is_some());
        assert!(password_strength("alllowercasepassword").is_some());
        assert!(password_strength("Correct-Horse-9-battery!").is_none());
    }
}
