//! Unlock page: WebAuthn login against the real backend.
//!
//! Flow: `POST /api/auth/webauthn/login/begin` → browser `navigator.credentials.get`
//! → `POST /api/auth/webauthn/login/finish` with the raw credential → store the
//! returned session id for subsequent authenticated API calls.

use gloo_storage::Storage;
use leptos::prelude::*;
use leptos_router::components::A;
use serde::Deserialize;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;

use crate::{api, state::auth::use_auth};

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
                Ok(session_id) => {
                    // Persist the session for authenticated API calls.
                    let _ = gloo_storage::LocalStorage::set("oc_session_id", &session_id);
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

#[derive(Debug, Deserialize)]
struct LoginBeginResponse {
    /// webauthn-rs `RequestChallengeResponse` — already the browser-native
    /// shape for `navigator.credentials.get({ publicKey: … })`.
    challenge: serde_json::Value,
    challenge_id: String,
}

#[derive(Debug, Deserialize)]
struct LoginFinishResponse {
    session_id: String,
    #[allow(dead_code)] // kept for diagnostics / future multi-credential UI
    credential_id: String,
}

/// Run the WebAuthn login ceremony against the backend.
///
/// Returns the server-issued session id.
async fn webauthn_authenticate() -> Result<String, String> {
    // 1. Request a fresh authentication challenge.
    let begin: LoginBeginResponse = api::post_json("/auth/webauthn/login/begin", &{})
        .await
        .map_err(|e| format!("login begin failed: {e}"))?;

    let window = web_sys::window().ok_or("no window")?;
    let navigator = window.navigator();
    let credentials = navigator.credentials();

    // 2. Ask the browser for an assertion. The webauthn-rs challenge is
    // already the `publicKey` request object, so we build the credentials
    // options by property assignment and cast the plain object (the standard
    // web-sys workaround — the typed setters do not map 1:1 onto the
    // serialized challenge).
    let public_key = js_sys::JSON::parse(
        &serde_json::to_string(&begin.challenge).map_err(|e| format!("challenge encode: {e}"))?,
    )
    .map_err(|e| format!("challenge parse: {e:?}"))?;

    let opts_obj = js_sys::Object::new();
    js_sys::Reflect::set(&opts_obj, &JsValue::from_str("publicKey"), &public_key)
        .map_err(|e| format!("failed to build credential options: {e:?}"))?;
    let opts = opts_obj.unchecked_into::<web_sys::CredentialRequestOptions>();

    let promise = credentials
        .get_with_options(&opts)
        .map_err(|e| format!("WebAuthn get failed: {e:?}"))?;

    let assertion = JsFuture::from(promise)
        .await
        .map_err(|e| format!("WebAuthn assertion failed: {e:?}"))?;

    // 3. Send the raw assertion back; the server verifies it and issues a
    // session cookie + session id. The assertion is serialized to its JSON
    // form so it can ride through the serde-based API layer.
    let assertion_json: serde_json::Value = serde_json::from_str(
        &JsValue::from(assertion)
            .as_string()
            .unwrap_or_else(|| "{}".into()),
    )
    .unwrap_or(serde_json::Value::Null);

    let body = serde_json::json!({
        "challenge_id": begin.challenge_id,
        "credential": assertion_json,
    });
    let finish: LoginFinishResponse =
        api::post_json("/auth/webauthn/login/finish", &body)
            .await
            .map_err(|e| format!("login finish failed: {e}"))?;

    Ok(finish.session_id)
}
