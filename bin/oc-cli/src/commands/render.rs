//! Generic output templates with dual human/JSON rendering (D10).
//!
//! A single [`Report`] source renders two ways: human text (secrets hidden by
//! default) and JSON. `reveal.then()` opts into showing secret values:
//! `Report::render_human(false)` redacts, `render_human(true)` reveals.

use serde::Serialize;

/// One redatable field in a report.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct Field {
    /// Display key.
    pub(crate) key: String,
    /// Display value (secret when `secret == true`).
    pub(crate) value: String,
    /// Whether this field holds secret material.
    pub(crate) secret: bool,
}

impl Field {
    /// Public (non-secret) field.
    pub(crate) fn public(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self { key: key.into(), value: value.into(), secret: false }
    }

    /// Secret field (hidden unless revealed).
    pub(crate) fn secret(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self { key: key.into(), value: value.into(), secret: true }
    }

    fn display(&self, reveal: bool) -> &str {
        if self.secret && !reveal { "<hidden>" } else { &self.value }
    }
}

/// Single-source report: human and JSON views derive from the same fields.
#[derive(Clone, Debug, Default, Serialize)]
pub(crate) struct Report {
    /// Report title.
    pub(crate) title: String,
    /// Ordered fields.
    pub(crate) fields: Vec<Field>,
}

impl Report {
    /// New empty report.
    pub(crate) fn new(title: impl Into<String>) -> Self {
        Self { title: title.into(), fields: Vec::new() }
    }

    /// Builder: push a field, returning `Self` for chaining.
    pub(crate) fn then(mut self, field: Field) -> Self {
        self.fields.push(field);
        self
    }

    /// Opt-in secret reveal: mirrors `reveal.then()` chaining — call with
    /// `true` to show secrets, default (`false`) hides them.
    pub(crate) fn reveal(self, reveal: bool) -> Reveal {
        Reveal { report: self, reveal }
    }

    /// Human rendering with explicit reveal flag.
    pub(crate) fn render_human(&self, reveal: bool) -> String {
        let mut out = format!("=== {} ===\n", self.title);
        for f in &self.fields {
            out.push_str(&format!("{}: {}\n", f.key, f.display(reveal)));
        }
        out
    }
}

/// Chained reveal view: `report.reveal(true).then(...)` keeps appending while
/// remembering the reveal choice, then `render()` emits human text.
pub(crate) struct Reveal {
    report: Report,
    reveal: bool,
}

impl Reveal {
    /// Append another field after choosing reveal mode.
    pub(crate) fn then(mut self, field: Field) -> Self {
        self.report.fields.push(field);
        self
    }

    /// Render human text with the stored reveal choice.
    pub(crate) fn render(self) -> String {
        self.report.render_human(self.reveal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_hidden_by_default_and_shown_on_reveal() {
        let r = Report::new("demo")
            .then(Field::public("user", "alice"))
            .then(Field::secret("password", "hunter2"));
        assert!(r.render_human(false).contains("<hidden>"));
        assert!(!r.render_human(false).contains("hunter2"));
        assert!(r.render_human(true).contains("hunter2"));
    }

    #[test]
    fn reveal_then_chaining_renders() {
        let out = Report::new("t").reveal(false).then(Field::secret("k", "v")).render();
        assert!(out.contains("<hidden>"));
    }

    #[test]
    fn human_and_reveal_chain_share_single_source() {
        let r = Report::new("t").then(Field::public("a", "b"));
        assert!(r.render_human(false).contains("a: b"));
        let out = Report::new("t").reveal(false).then(Field::secret("k", "v")).render();
        assert!(out.contains("<hidden>"));
    }
}
