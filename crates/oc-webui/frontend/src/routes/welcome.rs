use leptos::prelude::*;
use leptos_router::components::A;

#[component]
pub fn Welcome() -> impl IntoView {
    view! {
        <div class="welcome">
            <h1>"Welcome to OneCipher"</h1>
            <p>"No wallet found. Create or import a wallet to get started."</p>
            <A href="/no-address">"Continue"</A>
        </div>
    }
}
