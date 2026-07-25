use leptos::prelude::*;

#[component]
pub fn NoAddress() -> impl IntoView {
    view! {
        <div class="no-address">
            <h1>"No Wallet Address"</h1>
            <p>"Please create or import a wallet using the CLI:"</p>
            <code>"onecipher wallet create"</code>
            <p>"Then refresh this page."</p>
        </div>
    }
}
