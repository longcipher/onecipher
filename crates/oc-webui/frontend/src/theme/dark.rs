use gloo_storage::Storage;
use leptos::prelude::*;

/// Provide a reactive dark-mode signal at app root.
#[derive(Debug, Clone, Copy)]
pub struct DarkMode {
    pub is_dark: RwSignal<bool>,
}

/// Initialize dark mode from localStorage preference, defaulting to dark.
pub fn provide_dark_mode() -> DarkMode {
    let stored: Option<String> = gloo_storage::LocalStorage::get("oc_dark_mode").ok();
    let initial = stored.map(|s| s == "true").unwrap_or(true);
    let is_dark = RwSignal::new(initial);

    // Apply class on init
    apply_dark_class(initial);

    let mode = DarkMode { is_dark };
    provide_context(mode);
    mode
}

/// Toggle dark mode and persist preference.
pub fn toggle_dark_mode() {
    let mode = expect_context::<DarkMode>();
    let new_val = !mode.is_dark.get();
    mode.is_dark.set(new_val);
    let _ = gloo_storage::LocalStorage::set("oc_dark_mode", new_val.to_string());
    apply_dark_class(new_val);
}

fn apply_dark_class(dark: bool) {
    let window = web_sys::window().expect("no window");
    let document = window.document().expect("no document");
    let html = document.document_element().expect("no html element");
    if dark {
        html.class_list().add_1("dark").ok();
    } else {
        html.class_list().remove_1("dark").ok();
    }
}
