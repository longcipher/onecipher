use gloo_storage::Storage;
use leptos::prelude::*;
use leptos_router::components::A;
use wasm_bindgen_futures::JsFuture;

use crate::state::auth::use_auth;

#[component]
pub fn Unlock() -> impl IntoView {
    let auth = use_auth();
    let (error_msg, set_error_msg) = signal(None::<String>);
    let (loading, set_loading) = signal(false);
    let (logged_in, set_logged_in) = signal(false);

    let on_login = move |_| {
        set_loading.set(true);
        set_error_msg.set(None);

        leptos::task::spawn_local(async move {
            match webauthn_authenticate().await {
                Ok(()) => {
                    auth.set(true);
                    let _ = gloo_storage::LocalStorage::set("oc_page_state", "/dashboard");
                    set_logged_in.set(true);
                }
                Err(e) => {
                    set_error_msg.set(Some(e));
                    set_loading.set(false);
                }
            }
        });
    };

    view! {
        <div class="unlock">
            <h1>"OneCipher"</h1>
            <p>"Unlock your wallet"</p>
            <button on:click=on_login disabled=loading>
                {move || if loading.get() { "Authenticating…" } else { "Login with Passkey" }}
            </button>
            {move || error_msg.get().map(|e| view! { <p class="error">{e}</p> })}
            {move || logged_in.get().then(|| view! { <A href="/dashboard">"Go to Dashboard"</A> })}
        </div>
    }
}

async fn webauthn_authenticate() -> Result<(), String> {
    let window = web_sys::window().ok_or("no window")?;
    let navigator = window.navigator();
    let credentials = navigator.credentials();

    let opts = web_sys::CredentialRequestOptions::new();
    // ponytail: real impl would set publicKey challenge from server
    let promise = credentials
        .get_with_options(&opts)
        .map_err(|e| format!("WebAuthn get failed: {e:?}"))?;

    JsFuture::from(promise)
        .await
        .map_err(|e| format!("WebAuthn assertion failed: {e:?}"))?;

    // ponytail: real impl would send assertion to server for verification
    Ok(())
}
