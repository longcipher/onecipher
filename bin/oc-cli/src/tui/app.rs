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
    /// Creating (`n`) or editing (`e`) a secret via the shared form.
    Insert,
    /// Confirmation dialog (e.g. delete entry).
    Confirm,
    /// Viewing a single entry's metadata.
    Detail,
    /// Git status / history view (`g`).
    #[cfg(feature = "git")]
    Git,
    /// Help screen.
    Help,
}

/// One row of the tree-ordered secret list.
///
/// Entries whose names contain `/` are grouped under a namespace header:
/// `github/personal` renders as a `github/` header followed by an indented
/// entry row. Flat names (no `/`) render without a header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TreeRow {
    /// A namespace header (e.g. `github/`). Not selectable.
    Header(String),
    /// A selectable entry — index into `App::entries`.
    Entry(usize),
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

/// State for the new-secret / edit-secret form.
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
    /// When set, this form edits the entry with this name instead of creating
    /// a new one. An empty `secret` on submit then means "keep the current
    /// value" rather than "store an empty secret".
    pub(crate) editing_name: Option<String>,
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
            editing_name: None,
        }
    }

    /// Build a form pre-filled from an existing entry for editing.
    ///
    /// The secret field is left empty: it is never displayed in plaintext.
    /// The caller decides (via `secret.is_empty()`) whether to keep or replace
    /// the stored value on submit.
    pub(crate) fn from_entry(entry: &SecretIndexEntry) -> Self {
        let mut form = Self::new();
        form.editing_name = Some(entry.name.clone());
        form.name = entry.name.clone();
        if let Some(idx) = ItemType::all().iter().position(|t| *t == entry.item_type) {
            form.type_index = idx;
        }
        form.url = entry.metadata.url.clone().unwrap_or_default();
        form.username = entry.metadata.username.clone().unwrap_or_default();
        form.issuer = entry.metadata.issuer.clone().unwrap_or_default();
        form.account = entry.metadata.account.clone().unwrap_or_default();
        form.chain = entry.metadata.chain.clone().unwrap_or_default();
        form
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
    /// Tree-ordered display rows derived from `filtered_indices` (see
    /// [`TreeRow`]). Selection indexes into this, not `filtered_indices`.
    pub(crate) tree_rows: Vec<TreeRow>,
    /// Currently selected row (index into `tree_rows`).
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
    /// New-secret / edit-secret form state (active when in `Mode::Insert`).
    pub(crate) form: Option<FormState>,
    /// Working-tree status entries for the git view (`g`).
    #[cfg(feature = "git")]
    pub(crate) git_status: Vec<oc_secret::git::StatusEntry>,
    /// Recent commit history for the git view (`g`).
    #[cfg(feature = "git")]
    pub(crate) git_history: Vec<oc_secret::git::FileHistoryEntry>,
    /// Whether the vault root is inside a git repository.
    #[cfg(feature = "git")]
    pub(crate) git_is_repo: bool,
    /// Transient git-view message (sync result / error).
    #[cfg(feature = "git")]
    pub(crate) git_message: Option<(String, Instant)>,
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
            tree_rows: Vec::new(),
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
            #[cfg(feature = "git")]
            git_status: Vec::new(),
            #[cfg(feature = "git")]
            git_history: Vec::new(),
            #[cfg(feature = "git")]
            git_is_repo: false,
            #[cfg(feature = "git")]
            git_message: None,
        }
    }

    /// Enter the git status / history view and load the current repo state.
    #[cfg(feature = "git")]
    pub(crate) fn enter_git(&mut self) {
        let root = crate::commands::secret_store_root();
        self.git_is_repo = oc_secret::git::is_git_repo(&root);
        self.git_message = None;
        self.reload_git();
        self.mode = Mode::Git;
    }

    /// (Re)load git status + history. Errors become a transient message.
    #[cfg(feature = "git")]
    pub(crate) fn reload_git(&mut self) {
        let root = crate::commands::secret_store_root();
        self.git_status = match oc_secret::git::status_at(&root) {
            Ok(s) => s,
            Err(e) => {
                self.git_message =
                    Some((format!("git status failed: {e}"), Instant::now() + MESSAGE_TTL));
                Vec::new()
            }
        };
        self.git_history = match oc_secret::git::history_at(&root) {
            Ok(h) => h,
            Err(e) => {
                self.git_message =
                    Some((format!("git log failed: {e}"), Instant::now() + MESSAGE_TTL));
                Vec::new()
            }
        };
    }

    /// Run `git pull` against `origin` and refresh the git view.
    #[cfg(feature = "git")]
    pub(crate) fn git_pull(&mut self) {
        let root = crate::commands::secret_store_root();
        self.git_message = Some((format!("git pull: running..."), Instant::now() + MESSAGE_TTL));
        match oc_secret::git::pull_at(&root) {
            Ok(()) => {
                self.git_message = Some((format!("git pull: ok"), Instant::now() + MESSAGE_TTL))
            }
            Err(e) => {
                self.git_message =
                    Some((format!("git pull failed: {e}"), Instant::now() + MESSAGE_TTL))
            }
        }
        self.reload_git();
        self.reload();
    }

    /// Run `git push` to `origin` and refresh the git view.
    #[cfg(feature = "git")]
    pub(crate) fn git_push(&mut self) {
        let root = crate::commands::secret_store_root();
        self.git_message = Some((format!("git push: running..."), Instant::now() + MESSAGE_TTL));
        match oc_secret::git::push_at(&root) {
            Ok(()) => {
                self.git_message = Some((format!("git push: ok"), Instant::now() + MESSAGE_TTL))
            }
            Err(e) => {
                self.git_message =
                    Some((format!("git push failed: {e}"), Instant::now() + MESSAGE_TTL))
            }
        }
        self.reload_git();
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
                self.tree_rows.clear();
            }
        }
    }

    /// Apply the current `search_query` to build `filtered_indices` and the
    /// tree-ordered `tree_rows`.
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
        self.build_tree();
        // Clamp selection to the last selectable (Entry) row.
        if self.selected >= self.tree_rows.len() || !self.current_row_is_entry() {
            self.selected =
                self.tree_rows.iter().rposition(|r| matches!(r, TreeRow::Entry(_))).unwrap_or(0);
        }
    }

    /// Build `tree_rows` from `filtered_indices`, grouping `/`-namespaced
    /// entries under a header. Namespaces sort alphabetically; flat entries
    /// (no `/`) render at the top without a header.
    fn build_tree(&mut self) {
        use std::collections::BTreeMap;

        let mut groups: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        let mut flat: Vec<usize> = Vec::new();
        for &i in &self.filtered_indices {
            if let Some(e) = self.entries.get(i) {
                match e.name.split_once('/') {
                    Some((ns, _)) => groups.entry(ns.to_string()).or_default().push(i),
                    None => flat.push(i),
                }
            }
        }

        let mut rows = Vec::new();
        for i in flat {
            rows.push(TreeRow::Entry(i));
        }
        for (ns, indices) in groups {
            rows.push(TreeRow::Header(format!("{ns}/")));
            for i in indices {
                rows.push(TreeRow::Entry(i));
            }
        }
        self.tree_rows = rows;
    }

    /// Whether the current selection sits on an entry row.
    pub(crate) fn current_row_is_entry(&self) -> bool {
        matches!(self.tree_rows.get(self.selected), Some(TreeRow::Entry(_)))
    }

    /// Move the selection up by one selectable (Entry) row, skipping headers.
    pub(crate) fn move_up(&mut self) {
        let mut idx = self.selected;
        while idx > 0 {
            idx -= 1;
            if matches!(self.tree_rows.get(idx), Some(TreeRow::Entry(_))) {
                self.selected = idx;
                return;
            }
        }
    }

    /// Move the selection down by one selectable (Entry) row, skipping headers.
    pub(crate) fn move_down(&mut self) {
        let mut idx = self.selected;
        while idx + 1 < self.tree_rows.len() {
            idx += 1;
            if matches!(self.tree_rows.get(idx), Some(TreeRow::Entry(_))) {
                self.selected = idx;
                return;
            }
        }
    }

    /// Get the currently selected entry (if any).
    pub(crate) fn current_entry(&self) -> Option<&SecretIndexEntry> {
        match self.tree_rows.get(self.selected) {
            Some(TreeRow::Entry(i)) => self.entries.get(*i),
            _ => None,
        }
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

    /// Enter insert mode with a form pre-filled from the selected entry.
    ///
    /// The secret field is intentionally left empty (never shown in
    /// plaintext); leaving it empty on submit keeps the stored value.
    pub(crate) fn enter_edit(&mut self) {
        let Some(entry) = self.current_entry() else {
            self.set_message("No entry selected");
            return;
        };
        self.form = Some(FormState::from_entry(entry));
        self.mode = Mode::Insert;
    }

    /// Submit the new-secret / edit-secret form.
    ///
    /// Creates a new entry when `form.editing_name` is `None`; otherwise it
    /// edits the named entry. For an edit, an empty `secret` field keeps the
    /// stored value and an empty `notes` field keeps the stored notes — so the
    /// form doubles as a metadata-only editor without ever showing the secret
    /// in plaintext.
    ///
    /// On success, reloads entries and returns to Normal mode. On failure,
    /// sets an inline error message on the form.
    pub(crate) fn submit_form(&mut self) {
        let Some(form) = &self.form else { return };

        // Validate.
        if form.name.trim().is_empty() {
            self.form.as_mut().unwrap().error = Some("Name is required".into());
            return;
        }
        let is_edit = form.editing_name.is_some();
        if !is_edit && form.secret.is_empty() {
            self.form.as_mut().unwrap().error = Some("Secret value is required".into());
            return;
        }
        // Editing must be able to decrypt to preserve unchanged fields.
        if is_edit && self.identity.is_none() {
            self.form.as_mut().unwrap().error =
                Some("Editing requires an age identity (set ONECIPHER_AGE_IDENTITY)".into());
            return;
        }

        let name = form.name.trim().to_string();
        let item_type = form.selected_type();
        let metadata = form_metadata(form);
        let editing_name = form.editing_name.clone();

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

        match editing_name {
            None => {
                // ---- Create ----
                let payload = SecretPayload {
                    secret: form.secret.clone(),
                    notes: if form.notes.is_empty() { None } else { Some(form.notes.clone()) },
                    extra: None,
                };
                let entry = match oc_secret::SecretEntry::new(
                    &name,
                    item_type,
                    &payload,
                    metadata,
                    &recipients,
                ) {
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
                self.form = None;
                self.mode = Mode::Normal;
                self.reload();
                self.set_message(&format!("Secret added: {name}"));
            }
            Some(old_name) => {
                // ---- Edit ----
                // Borrow the identity (it is not `Clone` — it holds key
                // material that must never be duplicated) and the store; the
                // closure cannot outlive this arm.
                let identity = self.identity.as_ref();
                let store = &self.store;

                let result = (|| -> Result<(), String> {
                    let mut entry =
                        store.get(&old_name).map_err(|e| format!("Load failed: {e}"))?;
                    let old_payload = entry
                        .decrypt(identity.ok_or("no age identity")?)
                        .map_err(|e| format!("Decrypt failed: {e}"))?;

                    // Rename first if the name changed (moves file + index atomically).
                    if old_name != name {
                        store
                            .rename(&old_name, &name)
                            .map_err(|e| format!("Rename failed: {e}"))?;
                        entry = store.get(&name).map_err(|e| format!("Reload failed: {e}"))?;
                    }

                    // Preserve stored values when the corresponding field is empty.
                    let payload = SecretPayload {
                        secret: if form.secret.is_empty() {
                            old_payload.secret.clone()
                        } else {
                            form.secret.clone()
                        },
                        notes: if form.notes.is_empty() {
                            old_payload.notes.clone()
                        } else {
                            Some(form.notes.clone())
                        },
                        extra: old_payload.extra,
                    };

                    let mut new_entry = oc_secret::SecretEntry::new(
                        &name,
                        item_type,
                        &payload,
                        metadata,
                        &recipients,
                    )
                    .map_err(|e| format!("Encrypt failed: {e}"))?;
                    // Preserve the original identity fields across the edit.
                    new_entry.id = entry.id.clone();
                    new_entry.created_at = entry.created_at;

                    store.put(&new_entry).map_err(|e| format!("Save failed: {e}"))?;
                    Ok(())
                })();

                match result {
                    Ok(()) => {
                        self.form = None;
                        self.mode = Mode::Normal;
                        self.reload();
                        self.set_message(&format!("Secret updated: {name}"));
                    }
                    Err(e) => {
                        self.form.as_mut().unwrap().error = Some(e);
                    }
                }
            }
        }
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

/// Build [`SecretMetadata`] from the form's type-specific fields.
///
/// Empty fields become `None` — a field the user cleared must not be
/// resurrected from a stale value.
fn form_metadata(form: &FormState) -> SecretMetadata {
    let mut metadata = SecretMetadata::default();
    match form.selected_type() {
        ItemType::Password => {
            metadata.url = (!form.url.is_empty()).then(|| form.url.clone());
            metadata.username = (!form.username.is_empty()).then(|| form.username.clone());
        }
        ItemType::Totp => {
            metadata.issuer = (!form.issuer.is_empty()).then(|| form.issuer.clone());
            metadata.account = (!form.account.is_empty()).then(|| form.account.clone());
        }
        ItemType::Mnemonic | ItemType::PrivateKey => {
            metadata.chain = (!form.chain.is_empty()).then(|| form.chain.clone());
        }
        _ => {}
    }
    metadata
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

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str) -> SecretIndexEntry {
        SecretIndexEntry {
            id: format!("id-{name}"),
            name: name.to_string(),
            item_type: ItemType::Password,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
            metadata: SecretMetadata::default(),
        }
    }

    /// An `App` with `entries` pre-populated, no git feature state needed.
    fn app_with(entries: Vec<SecretIndexEntry>) -> App {
        // Construct via a minimal store path: build the App by hand rather
        // than opening a real store (filesystem side effects in tests).
        let store = {
            // SecretStore::open requires a real dir; use a temp dir.
            let dir = tempfile::tempdir().unwrap();
            let cfg = oc_secret::StoreConfig::new(dir.path().to_path_buf());
            oc_secret::SecretStore::open(cfg).unwrap()
        };
        let mut app = App::new(store);
        app.entries = entries;
        app.tree_rows = Vec::new();
        app.filtered_indices = (0..app.entries.len()).collect();
        app
    }

    #[test]
    fn tree_groups_namespaced_entries_under_headers() {
        let mut app = app_with(vec![entry("bank"), entry("github/personal"), entry("github/work")]);
        app.filter();
        assert_eq!(app.tree_rows.len(), 4); // bank, github/ header, personal, work
        assert_eq!(app.tree_rows[0], TreeRow::Entry(0));
        assert_eq!(app.tree_rows[1], TreeRow::Header("github/".to_string()));
        assert_eq!(app.tree_rows[2], TreeRow::Entry(1));
        assert_eq!(app.tree_rows[3], TreeRow::Entry(2));
    }

    #[test]
    fn tree_sort_namespaces_alphabetically() {
        let mut app = app_with(vec![entry("zeta/key"), entry("alpha/key"), entry("plain")]);
        app.filter();
        // flat entry first, then alpha/, then zeta/
        assert_eq!(app.tree_rows[0], TreeRow::Entry(2));
        assert_eq!(app.tree_rows[1], TreeRow::Header("alpha/".to_string()));
        assert!(
            app.tree_rows.iter().position(|r| *r == TreeRow::Header("zeta/".to_string())).is_some()
        );
    }

    #[test]
    fn move_down_skips_namespace_headers() {
        let mut app = app_with(vec![entry("github/a"), entry("github/b"), entry("other")]);
        app.filter();
        // tree_rows: github/ header, a, b, other(flat)
        app.selected = 0;
        // selected is a header after filter clamp should have moved to an entry;
        // force onto the first entry to test skipping deterministically.
        app.selected = app.tree_rows.iter().position(|r| matches!(r, TreeRow::Entry(_))).unwrap();
        let first = app.current_entry().unwrap().name.clone();
        app.move_down();
        let second = app.current_entry().unwrap().name.clone();
        assert_ne!(first, second);
        assert!(!matches!(app.tree_rows[app.selected], TreeRow::Header(_)));
    }

    #[test]
    fn move_up_skips_namespace_headers() {
        let mut app = app_with(vec![entry("github/a"), entry("github/b"), entry("other")]);
        app.filter();
        // tree_rows: [Entry(other), Header(github/), Entry(a), Entry(b)] —
        // flat names sort first, then the github/ group alphabetically.
        app.selected = app.tree_rows.len() - 1; // last row: github/b
        app.move_up();
        assert!(!matches!(app.tree_rows[app.selected], TreeRow::Header(_)));
        assert_eq!(app.current_entry().unwrap().name, "github/a");
    }

    #[test]
    fn current_entry_is_none_on_a_header_row() {
        let mut app = app_with(vec![entry("github/a")]);
        app.filter();
        app.selected = app.tree_rows.iter().position(|r| matches!(r, TreeRow::Header(_))).unwrap();
        assert!(app.current_entry().is_none());
    }

    #[test]
    fn filter_respects_search_query() {
        let mut app = app_with(vec![entry("github/personal"), entry("work/password")]);
        app.search_query = "personal".to_string();
        app.filter();
        assert_eq!(app.tree_rows.len(), 2); // github/ header + personal entry
        assert_eq!(app.current_entry().unwrap().name, "github/personal");
    }

    #[test]
    fn form_metadata_only_sets_fields_for_the_selected_type() {
        let mut form = FormState::new();
        form.type_index = ItemType::all().iter().position(|t| *t == ItemType::Totp).unwrap();
        form.issuer = "GitHub".into();
        form.account = "octocat".into();
        form.url = "https://example.com".into(); // ignored for TOTP
        let md = form_metadata(&form);
        assert_eq!(md.issuer.as_deref(), Some("GitHub"));
        assert_eq!(md.account.as_deref(), Some("octocat"));
        assert_eq!(md.url, None);
    }

    #[test]
    fn form_metadata_empty_fields_become_none() {
        let form = FormState::new();
        let md = form_metadata(&form);
        assert_eq!(md.url, None);
        assert_eq!(md.username, None);
    }

    #[test]
    fn from_entry_prefills_metadata_and_marks_editing() {
        let mut e = entry("github/personal");
        e.item_type = ItemType::Totp;
        e.metadata.issuer = Some("GitHub".into());
        e.metadata.account = Some("octocat".into());
        let form = FormState::from_entry(&e);
        assert_eq!(form.editing_name.as_deref(), Some("github/personal"));
        assert_eq!(form.name, "github/personal");
        assert_eq!(form.selected_type(), ItemType::Totp);
        assert_eq!(form.issuer, "GitHub");
        assert_eq!(form.account, "octocat");
        // The secret must never be pre-filled into the form.
        assert!(form.secret.is_empty());
    }

    #[test]
    fn entry_matches_is_case_insensitive_across_fields() {
        let mut e = entry("github/personal");
        e.metadata.username = Some("OctoCat".into());
        // `entry_matches` expects the query already lowercased (the caller —
        // `App::filter` — lowercases before calling).
        assert!(entry_matches(&e, "octocat"));
        assert!(entry_matches(&e, "github"));
        assert!(!entry_matches(&e, "nonexistent"));
    }
}
