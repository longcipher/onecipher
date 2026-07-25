use leptos::prelude::*;
use leptos_router::hooks::use_location;

/// Wraps children in a div that stays mounted but toggles `class:hidden`
/// based on whether the current route matches `when_path`.
///
/// This prevents unmounting (and thus re-fetching / tearing down WS subscriptions)
/// on route switches. The children remain in the DOM but are display:none when hidden.
#[component]
pub fn KeepAlive(
    /// The path prefix to match (e.g. "/sessions"). If the current path starts
    /// with this, the children are visible.
    when_path: &'static str,
    children: Children,
) -> impl IntoView {
    let location = use_location();
    let path = move || location.pathname.get();
    let visible = move || path().starts_with(when_path);

    view! {
        <div
            class:hidden=move || !visible()
            style=move || {
                if visible() { "" } else { "display:none;" }
            }
        >
            {children()}
        </div>
    }
}
