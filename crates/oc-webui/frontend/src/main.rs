mod api;
mod app;
mod cache;
mod components;
mod i18n;
mod routes;
mod state;
mod theme;

use leptos::mount::mount_to_body;

pub fn main() {
    console_error_panic_hook::set_once();

    // Inject CSS design tokens
    theme::inject_tokens();

    // Provide dark mode + locale context
    theme::dark::provide_dark_mode();
    i18n::provide_locale();

    mount_to_body(app::App);
}
