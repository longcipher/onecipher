//! Application state for the interactive TUI.
//!
//! Holds the [`SecretStore`], the filtered entry list, TOTP cache, and
//! clipboard auto-clear state. All business logic (navigation, search,
//! copy, delete) lives here so the rendering and input modules stay thin.

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use oc_core::{ItemType, SecretIndexEntry, SecretMetadata, SecretPayload};
use oc_secret::{AgeIdentity, SecretStore};

use crate::tui::clipboard;

/// Duration after which a copied secret is automatically cleared from the
/// clipboard.
const CLIPBOARD_CLEAR_SECS: u64 = 40;

/// TOTP codes are valid for 30 seconds (RFC 6238 default step).
const TOTP_VALIDITY: Duration = Duration::from_secs(30);

/// How long a transient status message stays on screen.
const MESSAGE_TTL: Duration = Duration::from_secs(5);

/// Interactive mode — controls which key bindings are active.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    /// Default browse mode (j/k navigation).
    Normal,
    /// Typing a search query.
    Search,
    /// Creating / editing a secret (reserved for future use).
    #[allow(dead_code)]
    Insert,
    /// Confirmation dialog (e.g. delete entry).
    Confirm,
    /// Viewing a single entry's metadata.
    Detail,
    /// Help screen.
    Help,
}

/// Form field identifiers for the new-secret creation form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FormField {
    Name,
    Type,
    Secret,
    Notes,
    Url,
    Username,
    Issuer,
    Account,
    Chain,
    Submit,
    Cancel,
}

/// State for the new-secret creation form.
pub(crate) struct FormState {
    /// Currently focused field.
    pub(crate) focus: FormField,
    /// Name input.
    pub(crate) name: String,
    /// Selected item type index (into `ItemType::all()`).
    pub(crate) type_index: usize,
    /// Secret value input.
    pub(crate) secret: String,
    /// Notes input.
    pub(crate) notes: String,
    /// URL input (for Password).
    pub(crate) url: String,
    /// Username input (for Password).
    pub(crate) username: String,
    /// Issuer input (for Totp).
    pub(crate) issuer: String,
    /// Account input (for Totp).
    pub(crate) account: String,
    /// Chain input (for Mnemonic/PrivateKey).
    pub(crate) chain: String,
    /// Error message to display inline.
    pub(crate) error: Option<String>,
}

impl FormState {
    pub(crate) fn new() -> Self {
        Self {
            focus: FormField::Name,
            name: String::new(),
            type_index: 0,
            secret: String::new(),
            notes: String::new(),
            url: String::new(),
            username: String::new(),
            issuer: String::new(),
            account: String::new(),
            chain: String::new(),
            error: None,
        }
    }

    /// Returns the selected `ItemType`.
    pub(crate) fn selected_type(&self) -> ItemType {
        ItemType::all().get(self.type_index).copied().unwrap_or(ItemType::Password)
    }

    /// Returns the ordered list of visible fields based on the selected type.
    pub(crate) fn visible_fields(&self) -> Vec<FormField> {
        let mut fields =
            vec![FormField::Name, FormField::Type, FormField::Secret, FormField::Notes];
        match self.selected_type() {
            ItemType::Password => {
                fields.push(FormField::Url);
                fields.push(FormField::Username);
            }
            ItemType::Totp => {
                fields.push(FormField::Issuer);
                fields.push(FormField::Account);
            }
            ItemType::Mnemonic | ItemType::PrivateKey => {
                fields.push(FormField::Chain);
            }
            _ => {}
        }
        fields.push(FormField::Submit);
        fields.push(FormField::Cancel);
        fields
    }

    /// Move focus to the previous field.
    pub(crate) fn move_up(&mut self) {
        let fields = self.visible_fields();
        if let Some(idx) = fields.iter().position(|f| *f == self.focus) {
            if idx > 0 {
                self.focus = fields[idx - 1];
            }
        }
    }

    /// Move focus to the next field.
    pub(crate) fn move_down(&mut self) {
        let fields = self.visible_fields();
        if let Some(idx) = fields.iter().position(|f| *f == self.focus) {
            if idx + 1 < fields.len() {
                self.focus = fields[idx + 1];
            }
        }
    }

    /// Get a mutable reference to the currently focused text field, if any.
    pub(crate) fn focused_field_mut(&mut self) -> Option<&mut String> {
        match self.focus {
            FormField::Name => Some(&mut self.name),
            FormField::Secret => Some(&mut self.secret),
            FormField::Notes => Some(&mut self.notes),
            FormField::Url => Some(&mut self.url),
            FormField::Username => Some(&mut self.username),
            FormField::Issuer => Some(&mut self.issuer),
            FormField::Account => Some(&mut self.account),
            FormField::Chain => Some(&mut self.chain),
            _ => None,
        }
    }
}

/// TUI application state.
pub(crate) struct App {
    /// The underlying secret store (age-encrypted filesystem vault).
    pub(crate) store: SecretStore,
    /// All entries from the plaintext index (reloaded on changes).
    pub(crate) entries: Vec<SecretIndexEntry>,
    /// Indices into `entries` that match the current search filter.
    pub(crate) filtered_indices: Vec<usize>,
    /// Currently selected row (index into `filtered_indices`).
    pub(crate) selected: usize,
    /// Active search query (empty = show all).
    pub(crate) search_query: String,
    /// Current interactive mode.
    pub(crate) mode: Mode,
    /// When the clipboard should be auto-cleared (40s after copy).
    pub(crate) clipboard_clear_at: Option<Instant>,
    /// Cached TOTP codes: entry name → (code, expiry).
    pub(crate) totp_cache: HashMap<String, (String, Instant)>,
    /// Entry being viewed in `Mode::Detail`.
    pub(crate) detail_entry: Option<SecretIndexEntry>,
    /// Transient status message and its expiry time.
    pub(crate) message: Option<(String, Instant)>,
    /// Input buffer for `Mode::Search` / `Mode::Insert`.
    pub(crate) input_buffer: String,
    /// Quit flag — the event loop exits when this is `true`.
    pub(crate) should_quit: bool,
    /// Optional age identity for decrypting secrets (copy / TOTP).
    ///
    /// Loaded from the `ONECIPHER_AGE_IDENTITY` env var at construction
    /// time. When `None`, copy and TOTP features display a guidance
    /// message instead of failing.
    identity: Option<AgeIdentity>,
    /// New-secret creation form state (active when in `Mode::Insert`).
    pub(crate) form: Option<FormState>,
}

impl App {
    /// Create a new `App` from a [`SecretStore`].
    ///
    /// Attempts to load an age identity from `ONECIPHER_AGE_IDENTITY` so
    /// that copy / TOTP features work out of the box.
    pub(crate) fn new(store: SecretStore) -> Self {
        let identity =
            std::env::var("ONECIPHER_AGE_IDENTITY").ok().and_then(|s| AgeIdentity::parse(&s).ok());

        Self {
            store,
            entries: Vec::new(),
            filtered_indices: Vec::new(),
            selected: 0,
            search_query: String::new(),
            mode: Mode::Normal,
            clipboard_clear_at: None,
            totp_cache: HashMap::new(),
            detail_entry: None,
            message: None,
            input_buffer: String::new(),
            should_quit: false,
            identity,
            form: None,
        }
    }

    /// Reload entries from the store and re-apply the search filter.
    pub(crate) fn reload(&mut self) {
        match self.store.list() {
            Ok(entries) => {
                self.entries = entries;
                self.filter();
            }
            Err(e) => {
                self.set_message(&format!("Failed to list entries: {e}"));
                self.entries.clear();
                self.filtered_indices.clear();
            }
        }
    }

    /// Apply the current `search_query` to build `filtered_indices`.
    pub(crate) fn filter(&mut self) {
        if self.search_query.is_empty() {
            self.filtered_indices = (0..self.entries.len()).collect();
        } else {
            let q = self.search_query.to_ascii_lowercase();
            self.filtered_indices = self
                .entries
                .iter()
                .enumerate()
                .filter(|(_, e)| entry_matches(e, &q))
                .map(|(i, _)| i)
                .collect();
        }
        // Clamp selection.
        if self.selected >= self.filtered_indices.len() {
            self.selected = self.filtered_indices.len().saturating_sub(1);
        }
    }

    /// Move the selection up by one row.
    pub(crate) fn move_up(&mut self) {
        if self.selected > 0 {
            self.selected -= 1;
        }
    }

    /// Move the selection down by one row.
    pub(crate) fn move_down(&mut self) {
        if self.selected + 1 < self.filtered_indices.len() {
            self.selected += 1;
        }
    }

    /// Get the currently selected entry (if any).
    pub(crate) fn current_entry(&self) -> Option<&SecretIndexEntry> {
        self.filtered_indices.get(self.selected).and_then(|&i| self.entries.get(i))
    }

    /// Enter search mode (pre-fills the input buffer with the current query).
    pub(crate) fn enter_search(&mut self) {
        self.mode = Mode::Search;
        self.input_buffer = self.search_query.clone();
    }

    /// Enter the detail view for the selected entry.
    pub(crate) fn enter_detail(&mut self) {
        if let Some(entry) = self.current_entry() {
            self.detail_entry = Some(entry.clone());
            self.mode = Mode::Detail;
        }
    }

    /// Copy the selected entry's secret to the clipboard (40s auto-clear).
    pub(crate) fn copy_secret(&mut self) {
        let Some(e) = self.current_entry() else {
            self.set_message("No entry selected");
            return;
        };
        let name = e.name.clone();

        match self.copy_entry_secret(&name) {
            Ok(clear_at) => {
                self.clipboard_clear_at = Some(clear_at);
                self.set_message(&format!(
                    "Copied '{name}' (auto-clears in {CLIPBOARD_CLEAR_SECS}s)"
                ));
            }
            Err(msg) => self.set_message(&msg),
        }
    }

    /// Generate and copy the TOTP code for the selected entry.
    pub(crate) fn copy_totp(&mut self) {
        let Some(e) = self.current_entry() else {
            self.set_message("No entry selected");
            return;
        };
        let name = e.name.clone();

        // Verify the entry is a TOTP.
        let is_totp = self.current_entry().is_some_and(|e| e.item_type == ItemType::Totp);
        if !is_totp {
            self.set_message("Selected entry is not a TOTP");
            return;
        }

        // Check cache first (avoid re-decrypting within the same 30s window).
        if let Some((code, expires)) = self.totp_cache.get(&name).cloned() {
            if Instant::now() < expires {
                match clipboard::copy_to_clipboard(&code) {
                    Ok(clear_at) => {
                        self.clipboard_clear_at = Some(clear_at);
                        self.set_message("TOTP copied (auto-clears in 40s)");
                        return;
                    }
                    Err(e) => {
                        self.set_message(&format!("Clipboard error: {e}"));
                        return;
                    }
                }
            }
        }

        // Generate a fresh code.
        match self.generate_and_copy_totp(&name) {
            Ok((code, clear_at)) => {
                let totp_expires = Instant::now() + TOTP_VALIDITY;
                self.totp_cache.insert(name, (code, totp_expires));
                self.clipboard_clear_at = Some(clear_at);
                self.set_message("TOTP copied (auto-clears in 40s)");
            }
            Err(msg) => self.set_message(&msg),
        }
    }

    /// Check whether the clipboard should be cleared and clear it if so.
    pub(crate) fn check_clipboard(&mut self) {
        let clear_at = self.clipboard_clear_at;
        match clipboard::check_and_clear(clear_at) {
            Ok(true) => {
                self.clipboard_clear_at = None;
                self.set_message("Clipboard cleared");
            }
            Ok(false) => {}
            Err(e) => {
                // Stop retrying — clear the timer so we don't spam errors.
                self.clipboard_clear_at = None;
                self.set_message(&format!("Failed to clear clipboard: {e}"));
            }
        }
    }

    /// Remove expired entries from the TOTP cache.
    pub(crate) fn refresh_totp(&mut self) {
        let now = Instant::now();
        self.totp_cache.retain(|_, (_, expires)| *expires > now);
    }

    /// Delete the currently selected entry (called after confirmation).
    pub(crate) fn delete_current(&mut self) {
        let Some(e) = self.current_entry() else {
            self.set_message("No entry selected");
            return;
        };
        let name = e.name.clone();
        match self.store.delete(&name) {
            Ok(()) => {
                self.set_message(&format!("Deleted '{name}'"));
                self.reload();
            }
            Err(e) => self.set_message(&format!("Delete failed: {e}")),
        }
    }

    /// Enter insert mode — initializes the new-secret creation form.
    pub(crate) fn enter_insert(&mut self) {
        self.form = Some(FormState::new());
        self.mode = Mode::Insert;
    }

    /// Submit the new-secret creation form.
    ///
    /// Validates inputs, encrypts the payload with age, and persists it to
    /// the `SecretStore`. On success, reloads entries and returns to Normal
    /// mode. On failure, sets an inline error message on the form.
    pub(crate) fn submit_form(&mut self) {
        let Some(form) = &self.form else { return };

        // Validate.
        if form.name.trim().is_empty() {
            self.form.as_mut().unwrap().error = Some("Name is required".into());
            return;
        }
        if form.secret.is_empty() {
            self.form.as_mut().unwrap().error = Some("Secret value is required".into());
            return;
        }

        let name = form.name.trim().to_string();
        let item_type = form.selected_type();
        let payload = SecretPayload {
            secret: form.secret.clone(),
            notes: if form.notes.is_empty() { None } else { Some(form.notes.clone()) },
            extra: None,
        };
        let mut metadata = SecretMetadata::default();
        match item_type {
            ItemType::Password => {
                if !form.url.is_empty() {
                    metadata.url = Some(form.url.clone());
                }
                if !form.username.is_empty() {
                    metadata.username = Some(form.username.clone());
                }
            }
            ItemType::Totp => {
                if !form.issuer.is_empty() {
                    metadata.issuer = Some(form.issuer.clone());
                }
                if !form.account.is_empty() {
                    metadata.account = Some(form.account.clone());
                }
            }
            ItemType::Mnemonic | ItemType::PrivateKey if !form.chain.is_empty() => {
                metadata.chain = Some(form.chain.clone());
            }
            _ => {}
        }

        // Load recipients.
        let recipients = match crate::commands::load_recipients() {
            Ok(r) => r,
            Err(e) => {
                self.form.as_mut().unwrap().error = Some(format!("Recipients error: {e}"));
                return;
            }
        };
        if recipients.is_empty() {
            self.form.as_mut().unwrap().error =
                Some("No recipients found — run `onecipher age init` first".into());
            return;
        }

        // Create and persist the entry.
        let entry =
            match oc_secret::SecretEntry::new(&name, item_type, &payload, metadata, &recipients) {
                Ok(e) => e,
                Err(e) => {
                    self.form.as_mut().unwrap().error = Some(format!("Create failed: {e}"));
                    return;
                }
            };
        if let Err(e) = self.store.put(&entry) {
            self.form.as_mut().unwrap().error = Some(format!("Save failed: {e}"));
            return;
        }

        // Success — clear form, reload, return to Normal.
        self.form = None;
        self.mode = Mode::Normal;
        self.reload();
        self.set_message(&format!("Secret added: {name}"));
    }

    /// Set a transient status message (auto-expires after [`MESSAGE_TTL`]).
    pub(crate) fn set_message(&mut self, msg: &str) {
        self.message = Some((msg.to_string(), Instant::now() + MESSAGE_TTL));
    }

    // ── Private helpers ───────────────────────────────────────────────

    /// Decrypt the named entry and copy its secret to the clipboard.
    ///
    /// Takes `&self` so it doesn't conflict with `&mut self` in the caller.
    fn copy_entry_secret(&self, name: &str) -> Result<Instant, String> {
        let identity =
            self.identity.as_ref().ok_or("No age identity loaded (set ONECIPHER_AGE_IDENTITY)")?;
        let entry = self.store.get(name).map_err(|e| format!("Store error: {e}"))?;
        let payload = entry.decrypt(identity).map_err(|e| format!("Decrypt error: {e}"))?;
        clipboard::copy_to_clipboard(&payload.secret).map_err(|e| format!("Clipboard error: {e}"))
    }

    /// Generate a fresh TOTP code for the named entry and copy it.
    fn generate_and_copy_totp(&self, name: &str) -> Result<(String, Instant), String> {
        let identity =
            self.identity.as_ref().ok_or("No age identity loaded (set ONECIPHER_AGE_IDENTITY)")?;
        let entry = self.store.get(name).map_err(|e| format!("Store error: {e}"))?;
        let payload = entry.decrypt(identity).map_err(|e| format!("Decrypt error: {e}"))?;
        let code = oc_secret::totp::generate_totp(&payload.secret)
            .map_err(|e| format!("TOTP error: {e}"))?;
        let clear_at =
            clipboard::copy_to_clipboard(&code).map_err(|e| format!("Clipboard error: {e}"))?;
        Ok((code, clear_at))
    }
}

/// Case-insensitive substring match against searchable metadata fields.
fn entry_matches(entry: &SecretIndexEntry, query: &str) -> bool {
    entry.name.to_ascii_lowercase().contains(query) ||
        entry.metadata.url.as_ref().is_some_and(|s| s.to_ascii_lowercase().contains(query)) ||
        entry.metadata.username.as_ref().is_some_and(|s| s.to_ascii_lowercase().contains(query)) ||
        entry.metadata.issuer.as_ref().is_some_and(|s| s.to_ascii_lowercase().contains(query)) ||
        entry.metadata.account.as_ref().is_some_and(|s| s.to_ascii_lowercase().contains(query)) ||
        entry.metadata.tags.iter().any(|t| t.to_ascii_lowercase().contains(query))
}
