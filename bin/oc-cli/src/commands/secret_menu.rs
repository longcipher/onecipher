//! `onecipher secret menu` — pick an entry, then clip or type parts of it.
//!
//! Ported from seniorpw's `senior menu`, which is the fastest way to use a
//! password manager from a window-manager keybinding:
//!
//! ```text
//! onecipher secret menu type-content secret type-text "\n"
//! onecipher secret menu type-content user type-text "\t" type-content secret type-text "\n"
//! onecipher secret menu clip secret
//! ```
//!
//! Actions are `(action, argument)` pairs executed in order:
//!
//! | Action | Argument | Effect |
//! |---|---|---|
//! | `clip <KEY>` | key name | copy the value to the clipboard |
//! | `type-content <KEY>` | key name | type the value |
//! | `type-text <TEXT>` | literal text | type the text (`\t`, `\n`, …) |
//! | `sleep <MS>` | milliseconds | wait between actions |
//!
//! Keys: `secret` (also `password`, or empty) is the stored value, `notes`
//! the notes field, `otp` generates a code from an `otpauth://` value
//! (seniorpw's `-k otp`), and any other name is looked up in the entry's
//! `extra` JSON.
//!
//! Selection: `--name` skips the picker entirely (script-friendly), a TTY
//! uses the built-in picker shared with `onecipher find`, and
//! `--menu-program` delegates to a dmenu-like program that reads the names
//! on stdin and prints the choice on stdout.

use std::{
    io::Write,
    process::{Command, Stdio},
    thread,
    time::Duration,
};

use oc_core::SecretPayload;
use zeroize::Zeroizing;

use crate::CliError;

/// Typing programs tried in order when `--typing-program` is not given.
///
/// Wayland first, then X11, then the macOS fallback. `osascript` is last
/// because it is always present on macOS but needs Accessibility
/// permissions, whereas `wtype`/`xdotool` are the native tools where they
/// apply.
const DEFAULT_TYPING_PROGRAMS: &[&str] = &["wtype", "ydotool", "xdotool", "xvkbd", "osascript"];

/// Menu programs tried in order when `--menu-program` is not given.
const DEFAULT_MENU_PROGRAMS: &[&str] = &["bemenu", "tofi", "wofi", "rofi", "dmenu", "fzf"];

/// Entry point for `onecipher secret menu [ACTIONS...]`.
pub(crate) fn run(
    name: Option<&str>,
    menu_program: Option<&str>,
    typing_program: Option<&str>,
    key_delay: Option<u16>,
    clipboard_timeout: u64,
    action_args: &[String],
) -> Result<(), CliError> {
    let actions = parse_actions(action_args)?;

    let chosen = match name {
        Some(n) => n.to_string(),
        None => pick_entry(menu_program)?,
    };

    let store = super::open_secret_store()?;
    let entry = store.get(&chosen).map_err(super::secret::map_store_error)?;
    let identity = super::load_age_identity()?;
    let payload = entry
        .decrypt(&identity)
        .map_err(|e| CliError::InvalidArgs(format!("decryption failed: {e}")))?;

    for action in &actions {
        match action {
            Action::Sleep(ms) => thread::sleep(Duration::from_millis(u64::from(*ms))),
            Action::TypeText(text) => type_string(typing_program, key_delay, text)?,
            Action::Clip(key) => {
                let value = resolve_key(&payload, key)?;
                super::clipboard::copy_and_clear(&value, clipboard_timeout)?;
            }
            Action::TypeContent(key) => {
                let value = resolve_key(&payload, key)?;
                type_string(typing_program, key_delay, &value)?;
            }
        }
    }
    Ok(())
}

/// A parsed menu action.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Action {
    Clip(String),
    TypeContent(String),
    TypeText(String),
    Sleep(u16),
}

/// Parse the flat `action argument ...` list into [`Action`]s.
///
/// Every action takes exactly one argument; a dangling action is a usage
/// error (exit 64) rather than something silently ignored, because a
/// half-typed sequence would otherwise type the wrong thing into the
/// focused window.
pub(crate) fn parse_actions(args: &[String]) -> Result<Vec<Action>, CliError> {
    if args.is_empty() {
        return Err(CliError::InvalidArgs(
            "no actions given; expected pairs like: clip secret, type-text \"\\n\"".into(),
        ));
    }
    if args.len() % 2 != 0 {
        return Err(CliError::InvalidArgs(format!(
            "action '{}' is missing its argument (actions come in pairs)",
            args[args.len() - 1]
        )));
    }

    let mut actions = Vec::with_capacity(args.len() / 2);
    // `chunks(2)` is equivalent here: an odd length was rejected above.
    for pair in args.chunks(2) {
        let (kind, arg) = (&pair[0], &pair[1]);
        actions.push(match kind.as_str() {
            "clip" => Action::Clip(arg.clone()),
            "type-content" => Action::TypeContent(arg.clone()),
            "type-text" => Action::TypeText(arg.clone()),
            "sleep" => {
                let ms = arg.parse().map_err(|_| {
                    CliError::InvalidArgs(format!("sleep expects milliseconds, got '{arg}'"))
                })?;
                Action::Sleep(ms)
            }
            other => {
                return Err(CliError::InvalidArgs(format!(
                    "unknown action '{other}' (expected: clip, type-content, type-text, sleep)"
                )));
            }
        });
    }
    Ok(actions)
}

/// Resolve a key name against a payload.
///
/// `secret`/`password`/`""` → the secret value; `notes` → the notes field;
/// `otp` → a freshly generated code; anything else → a scalar in `extra`.
pub(crate) fn resolve_key(
    payload: &SecretPayload,
    key: &str,
) -> Result<Zeroizing<String>, CliError> {
    match key {
        "" | "secret" | "password" => Ok(Zeroizing::new(payload.secret.clone())),
        "notes" => Ok(Zeroizing::new(payload.notes.clone().unwrap_or_default())),
        "otp" => match super::totp_code_from_uri(&payload.secret) {
            Ok(code) => Ok(Zeroizing::new(code)),
            Err(_) if payload.notes.as_deref().is_some_and(|n| n.contains("otpauth://")) => {
                // seniorpw stores the URI on its own `otpauth:` line; accept
                // it in the notes field too.
                let uri = payload
                    .notes
                    .as_deref()
                    .unwrap_or_default()
                    .lines()
                    .find(|line| line.trim_start().starts_with("otpauth://"))
                    .map_or("", str::trim);
                Ok(Zeroizing::new(super::totp_code_from_uri(uri)?))
            }
            Err(e) => Err(e),
        },
        other => match payload.extra.as_ref().and_then(|v| v.get(other)) {
            Some(serde_json::Value::String(s)) => Ok(Zeroizing::new(s.clone())),
            Some(value) if !value.is_object() && !value.is_array() => {
                Ok(Zeroizing::new(value.to_string()))
            }
            Some(_) => Err(CliError::InvalidArgs(format!("extra field '{other}' is not a scalar"))),
            None => Err(CliError::InvalidArgs(format!(
                "no such key '{other}' (expected: secret, notes, otp, or a key of the extra JSON)"
            ))),
        },
    }
}

/// Pick an entry name: built-in TUI picker on a TTY, else an external
/// dmenu-like program.
fn pick_entry(menu_program: Option<&str>) -> Result<String, CliError> {
    let store = super::open_secret_store()?;
    let entries = store.list().map_err(super::secret::map_store_error)?;
    if entries.is_empty() {
        return Err(CliError::InvalidArgs("no secrets in this store".into()));
    }

    // A TTY with no explicit menu program: reuse the `onecipher find`
    // selector so both surfaces feel the same.
    if menu_program.is_none() && super::is_interactive_stdin() {
        let mut stdout = std::io::stdout();
        return match super::find::run_selector(&entries, &mut stdout)? {
            Some(entry) => Ok(entry.name),
            None => Err(CliError::InvalidArgs("no entry selected".into())),
        };
    }

    let programs: Vec<&str> = match menu_program {
        Some(p) => vec![p],
        None => DEFAULT_MENU_PROGRAMS.to_vec(),
    };

    let mut last_error = None;
    for program in programs {
        let mut child =
            match Command::new(program).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn() {
                Ok(child) => child,
                Err(e) => {
                    last_error = Some(format!("cannot start menu program '{program}': {e}"));
                    continue;
                }
            };

        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        if let Some(stdin) = child.stdin.as_mut() {
            if stdin.write_all(names.join("\n").as_bytes()).is_err() {
                last_error = Some(format!("cannot write to menu program '{program}'"));
                continue;
            }
        }
        match child.wait_with_output() {
            Ok(output) => {
                let chosen = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if chosen.is_empty() {
                    return Err(CliError::InvalidArgs("no entry selected".into()));
                }
                return Ok(chosen);
            }
            Err(e) => last_error = Some(format!("menu program '{program}' failed: {e}")),
        }
    }

    Err(CliError::InvalidArgs(
        last_error.unwrap_or_else(|| "no menu program available".to_string()),
    ))
}

/// Type `text` with the first available typing program.
///
/// Unknown programs follow seniorpw's convention: they are invoked as
/// `<program> type <text>`, which matches `ydotool`, `xdotool` and friends.
/// `osascript` (macOS) drives System Events instead.
fn type_string(
    typing_program: Option<&str>,
    key_delay: Option<u16>,
    text: &str,
) -> Result<(), CliError> {
    let programs: Vec<&str> = match typing_program {
        Some(p) => vec![p],
        None => DEFAULT_TYPING_PROGRAMS.to_vec(),
    };

    let delay = key_delay.map(|ms| ms.to_string());
    let mut last_error = None;

    for program in programs {
        let mut cmd = Command::new(program);
        let cmd = match program {
            "wtype" => {
                if let Some(d) = &delay {
                    cmd.args(["-d", d]);
                }
                cmd.arg(text)
            }
            "xdotool" => {
                cmd.arg("type");
                if let Some(d) = &delay {
                    cmd.args(["--delay", d]);
                }
                cmd.arg(text)
            }
            "ydotool" => {
                cmd.arg("type");
                if let Some(d) = &delay {
                    cmd.args(["--key-delay", d]);
                }
                cmd.arg(text)
            }
            "osascript" => cmd.args([
                "-e",
                &format!(
                    "tell application \"System Events\" to keystroke {}",
                    applescript_string(text)
                ),
            ]),
            _ => cmd.arg("type").arg(text),
        };

        match cmd.status() {
            Ok(status) if status.success() => return Ok(()),
            Ok(status) => {
                last_error = Some(format!("typing program '{program}' exited with {status}"));
            }
            Err(e) => {
                last_error = Some(format!("cannot start typing program '{program}': {e}"));
            }
        }
    }

    Err(CliError::InvalidArgs(
        last_error.unwrap_or_else(|| "no typing program available".to_string()),
    ))
}

/// Quote `text` as an AppleScript string literal.
fn applescript_string(text: &str) -> String {
    let escaped = text.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actions_parse_in_pairs() {
        let args = ["type-content", "user", "type-text", "\t", "sleep", "50"]
            .iter()
            .map(|s| (*s).to_string())
            .collect::<Vec<_>>();
        let actions = parse_actions(&args).expect("parse");
        assert_eq!(
            actions,
            vec![
                Action::TypeContent("user".into()),
                Action::TypeText("\t".into()),
                Action::Sleep(50),
            ]
        );
    }

    #[test]
    fn dangling_action_is_a_usage_error() {
        let args = vec!["clip".to_string()];
        let err = parse_actions(&args).expect_err("a dangling action must fail");
        assert!(err.to_string().contains("missing its argument"));
    }

    #[test]
    fn empty_action_list_is_rejected() {
        assert!(parse_actions(&[]).is_err());
    }

    #[test]
    fn unknown_action_is_rejected() {
        let args = vec!["shout".to_string(), "secret".to_string()];
        let err = parse_actions(&args).expect_err("unknown action must fail");
        assert!(err.to_string().contains("unknown action"));
    }

    #[test]
    fn sleep_rejects_non_numeric_argument() {
        let args = vec!["sleep".to_string(), "soon".to_string()];
        assert!(parse_actions(&args).is_err());
    }

    #[test]
    fn keys_resolve_to_the_expected_fields() {
        let payload = SecretPayload {
            secret: "hunter2".into(),
            notes: Some("user: alice".into()),
            extra: Some(serde_json::json!({"url": "https://example.com", "port": 443})),
        };
        assert_eq!(&*resolve_key(&payload, "secret").unwrap(), "hunter2");
        assert_eq!(&*resolve_key(&payload, "password").unwrap(), "hunter2");
        assert_eq!(&*resolve_key(&payload, "").unwrap(), "hunter2");
        assert_eq!(&*resolve_key(&payload, "notes").unwrap(), "user: alice");
        assert_eq!(&*resolve_key(&payload, "url").unwrap(), "https://example.com");
        assert_eq!(&*resolve_key(&payload, "port").unwrap(), "443");
    }

    #[test]
    fn missing_key_is_reported() {
        let payload = SecretPayload { secret: "x".into(), notes: None, extra: None };
        let err = resolve_key(&payload, "nope").expect_err("unknown key must fail");
        assert!(err.to_string().contains("no such key"));
    }

    #[test]
    fn applescript_literals_are_quoted() {
        assert_eq!(applescript_string("a\tb"), "\"a\tb\"");
        assert_eq!(applescript_string("say \"hi\""), "\"say \\\"hi\\\"\"");
    }
}
