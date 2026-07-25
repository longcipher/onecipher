use leptos::prelude::*;
use leptos_router::components::A;

use crate::cache::{Scene, read_or_fetch};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WalletInfo {
    pub address: String,
    pub chain: String,
    pub label: Option<String>,
}

#[component]
pub fn WalletsPage() -> impl IntoView {
    let wallets = read_or_fetch::<Vec<WalletInfo>, _>(Scene::Wallets, "list", async {
        crate::api::get_json::<Vec<WalletInfo>>("/wallets").await
    });

    view! {
        <div style="max-width:800px;margin:0 auto;padding:1.5rem;">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1.5rem;">
                <h1 style="margin:0;">"Wallets"</h1>
                <div style="display:flex;gap:0.5rem;">
                    <A href="/wallets/create">
                        <button style="padding:0.5rem 1rem;background:var(--oc-accent);color:white;border:none;border-radius:var(--oc-radius);cursor:pointer;">
                            "Create"
                        </button>
                    </A>
                    <A href="/wallets/import">
                        <button style="padding:0.5rem 1rem;background:var(--oc-bg-input);border:1px solid var(--oc-border);border-radius:var(--oc-radius);cursor:pointer;color:var(--oc-text);">
                            "Import"
                        </button>
                    </A>
                </div>
            </div>

            {move || match wallets.get() {
                None => view! { <p style="color:var(--oc-text-muted);">"Loading wallets…"</p> }.into_any(),
                Some(list) if list.is_empty() => view! {
                    <p style="color:var(--oc-text-muted);">"No wallets found. Create or import one to get started."</p>
                }.into_any(),
                Some(list) => list.into_iter().map(|w| {
                    let label = w.label.unwrap_or_else(|| "Unnamed".into());
                    let addr_short = if w.address.len() > 10 {
                        format!("{}…{}", &w.address[..6], &w.address[w.address.len()-4..])
                    } else {
                        w.address.clone()
                    };
                    let href = format!("/wallets/info?address={}", w.address);
                    view! {
                        <A href=href>
                            <div style="background:var(--oc-bg-card);border:1px solid var(--oc-border);border-radius:var(--oc-radius);padding:1rem;margin-bottom:0.75rem;cursor:pointer;">
                                <div style="display:flex;justify-content:space-between;">
                                    <strong>{label}</strong>
                                    <span style="color:var(--oc-text-muted);font-size:0.875rem;">{w.chain}</span>
                                </div>
                                <div style="color:var(--oc-text-muted);font-size:0.875rem;margin-top:0.25rem;font-family:monospace;">
                                    {addr_short}
                                </div>
                            </div>
                        </A>
                    }
                }).collect::<Vec<_>>().into_any(),
            }}
        </div>
    }
}

#[component]
pub fn WalletCreate() -> impl IntoView {
    let (label, set_label) = signal(String::new());
    let (chain, set_chain) = signal(String::from("eip155:1"));
    let (error, set_error) = signal(None::<String>);
    let (created, set_created) = signal(false);
    let (loading, set_loading) = signal(false);

    let on_submit = move |ev: web_sys::SubmitEvent| {
        ev.prevent_default();
        set_loading.set(true);
        set_error.set(None);

        let chain_val = chain.get();
        let label_val = label.get();

        leptos::task::spawn_local(async move {
            let body = serde_json::json!({
                "chain": chain_val,
                "label": if label_val.is_empty() { None } else { Some(label_val) },
            });
            match crate::api::post_json::<_, serde_json::Value>("/wallets", &body).await {
                Ok(_) => set_created.set(true),
                Err(e) => set_error.set(Some(e.to_string())),
            }
            set_loading.set(false);
        });
    };

    view! {
        <div style="max-width:600px;margin:0 auto;padding:1.5rem;">
            <A href="/wallets"><span style="color:var(--oc-accent);cursor:pointer;">"<- Back"</span></A>
            <h1 style="margin:1rem 0;">"Create Wallet"</h1>

            {move || created.get().then(|| view! {
                <div style="background:#166534;color:#bbf7d0;padding:0.75rem;border-radius:var(--oc-radius);margin-bottom:1rem;">
                    "Wallet created successfully. "
                    <A href="/wallets"><span style="color:white;">"View wallets"</span></A>
                </div>
            })}

            {move || error.get().map(|e| view! {
                <p style="color:var(--oc-danger);margin-bottom:1rem;">{e}</p>
            })}

            <form on:submit=on_submit>
                <div style="margin-bottom:1rem;">
                    <label style="display:block;margin-bottom:0.25rem;color:var(--oc-text-muted);">"Chain"</label>
                    <select
                        prop:value=chain
                        on:change=move |ev| set_chain.set(event_target_value(&ev))
                        style="width:100%;padding:0.5rem;background:var(--oc-bg-input);border:1px solid var(--oc-border);border-radius:var(--oc-radius);color:var(--oc-text);"
                    >
                        <option value="eip155:1">"Ethereum"</option>
                        <option value="eip155:137">"Polygon"</option>
                        <option value="solana:mainnet">"Solana"</option>
                    </select>
                </div>

                <div style="margin-bottom:1.5rem;">
                    <label style="display:block;margin-bottom:0.25rem;color:var(--oc-text-muted);">"Label (optional)"</label>
                    <input
                        type="text"
                        prop:value=label
                        on:input=move |ev| set_label.set(event_target_value(&ev))
                        placeholder="My Wallet"
                        style="width:100%;padding:0.5rem;background:var(--oc-bg-input);border:1px solid var(--oc-border);border-radius:var(--oc-radius);color:var(--oc-text);box-sizing:border-box;"
                    />
                </div>

                <button
                    type="submit"
                    disabled=loading
                    style="width:100%;padding:0.75rem;background:var(--oc-accent);color:white;border:none;border-radius:var(--oc-radius);font-weight:600;cursor:pointer;"
                >
                    {move || if loading.get() { "Creating…" } else { "Create Wallet" }}
                </button>
            </form>
        </div>
    }
}

#[component]
pub fn WalletImport() -> impl IntoView {
    let (mnemonic, set_mnemonic) = signal(String::new());
    let (chain, set_chain) = signal(String::from("eip155:1"));
    let (error, set_error) = signal(None::<String>);
    let (imported, set_imported) = signal(false);
    let (loading, set_loading) = signal(false);

    let on_submit = move |ev: web_sys::SubmitEvent| {
        ev.prevent_default();
        set_loading.set(true);
        set_error.set(None);

        let mnemonic_val = mnemonic.get();
        let chain_val = chain.get();

        if mnemonic_val.is_empty() {
            set_error.set(Some("Mnemonic is required.".into()));
            set_loading.set(false);
            return;
        }

        leptos::task::spawn_local(async move {
            let body = serde_json::json!({
                "chain": chain_val,
                "mnemonic": mnemonic_val,
            });
            match crate::api::post_json::<_, serde_json::Value>("/wallets/import", &body).await {
                Ok(_) => set_imported.set(true),
                Err(e) => set_error.set(Some(e.to_string())),
            }
            set_loading.set(false);
        });
    };

    view! {
        <div style="max-width:600px;margin:0 auto;padding:1.5rem;">
            <A href="/wallets"><span style="color:var(--oc-accent);cursor:pointer;">"<- Back"</span></A>
            <h1 style="margin:1rem 0;">"Import Wallet"</h1>

            {move || imported.get().then(|| view! {
                <div style="background:#166534;color:#bbf7d0;padding:0.75rem;border-radius:var(--oc-radius);margin-bottom:1rem;">
                    "Wallet imported successfully. "
                    <A href="/wallets"><span style="color:white;">"View wallets"</span></A>
                </div>
            })}

            {move || error.get().map(|e| view! {
                <p style="color:var(--oc-danger);margin-bottom:1rem;">{e}</p>
            })}

            <form on:submit=on_submit>
                <div style="margin-bottom:1rem;">
                    <label style="display:block;margin-bottom:0.25rem;color:var(--oc-text-muted);">"Chain"</label>
                    <select
                        prop:value=chain
                        on:change=move |ev| set_chain.set(event_target_value(&ev))
                        style="width:100%;padding:0.5rem;background:var(--oc-bg-input);border:1px solid var(--oc-border);border-radius:var(--oc-radius);color:var(--oc-text);"
                    >
                        <option value="eip155:1">"Ethereum"</option>
                        <option value="eip155:137">"Polygon"</option>
                        <option value="solana:mainnet">"Solana"</option>
                    </select>
                </div>

                <div style="margin-bottom:1.5rem;">
                    <label style="display:block;margin-bottom:0.25rem;color:var(--oc-text-muted);">"Mnemonic Phrase"</label>
                    <textarea
                        prop:value=mnemonic
                        on:input=move |ev| set_mnemonic.set(event_target_value(&ev))
                        placeholder="word1 word2 word3 …"
                        rows=3
                        style="width:100%;padding:0.5rem;background:var(--oc-bg-input);border:1px solid var(--oc-border);border-radius:var(--oc-radius);color:var(--oc-text);box-sizing:border-box;resize:vertical;"
                    />
                </div>

                <button
                    type="submit"
                    disabled=loading
                    style="width:100%;padding:0.75rem;background:var(--oc-accent);color:white;border:none;border-radius:var(--oc-radius);font-weight:600;cursor:pointer;"
                >
                    {move || if loading.get() { "Importing…" } else { "Import Wallet" }}
                </button>
            </form>
        </div>
    }
}

#[component]
pub fn WalletInfo() -> impl IntoView {
    // ponytail: read ?address= query param and fetch wallet details
    view! {
        <div style="max-width:600px;margin:0 auto;padding:1.5rem;">
            <A href="/wallets"><span style="color:var(--oc-accent);cursor:pointer;">"<- Back"</span></A>
            <h1 style="margin:1rem 0;">"Wallet Info"</h1>
            <p style="color:var(--oc-text-muted);">"Wallet detail view — connect to GET /api/wallets/{address} when available."</p>
        </div>
    }
}
