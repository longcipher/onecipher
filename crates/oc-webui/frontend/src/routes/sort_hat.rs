use gloo_storage::Storage;
use leptos::prelude::*;
use leptos_router::components::A;

use crate::state::auth::use_auth;

/// SortHat determines where to redirect on app load (Section 4.2 logic).
#[component]
pub fn SortHat() -> impl IntoView {
    let auth = use_auth();

    // Check localStorage for cached page state
    let cached_page: Option<String> = gloo_storage::LocalStorage::get("oc_page_state").ok();
    let is_authenticated = auth.get();

    let target = if is_authenticated {
        cached_page.unwrap_or_else(|| "/dashboard".to_string())
    } else {
        // ponytail: check wallets via health endpoint; if it responds, wallets exist.
        // For now, assume wallets exist → unlock. No wallets → welcome.
        "/unlock".to_string()
    };

    view! {
        <p>"Redirecting…"</p>
        <A href=target>"Continue"</A>
    }
}
