// ponytail: placeholder i18n module. Add fluent-leptos when i18n is actually needed.
// For now, all strings are English inline in the view macros.

use gloo_storage::Storage;
use leptos::prelude::*;

/// Current locale signal (default "en").
#[derive(Debug, Clone, Copy)]
pub struct Locale {
    pub current: RwSignal<String>,
}

pub fn provide_locale() -> Locale {
    let stored: Option<String> = gloo_storage::LocalStorage::get("oc_locale").ok();
    let current = RwSignal::new(stored.unwrap_or_else(|| "en".to_string()));
    let locale = Locale { current };
    provide_context(locale);
    locale
}

/// Switch locale and persist.
pub fn set_locale(lang: &str) {
    let locale = expect_context::<Locale>();
    locale.current.set(lang.to_string());
    let _ = gloo_storage::LocalStorage::set("oc_locale", lang);
}
