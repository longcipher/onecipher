use leptos::prelude::*;

use crate::cache::{Scene, read_or_fetch};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Session {
    pub topic: String,
    pub peer: Option<String>,
    pub chains: Vec<String>,
    pub expiry: Option<u64>,
}

#[component]
pub fn SessionsPage() -> impl IntoView {
    let sessions = read_or_fetch::<Vec<Session>, _>(Scene::Sessions, "list", async {
        crate::api::get_json::<Vec<Session>>("/sessions").await
    });

    view! {
        <div style="max-width:800px;margin:0 auto;padding:1.5rem;">
            <h1 style="margin-bottom:1.5rem;">"WalletConnect Sessions"</h1>

            {move || match sessions.get() {
                None => view! { <p style="color:var(--oc-text-muted);">"Loading sessions…"</p> }.into_any(),
                Some(list) if list.is_empty() => view! {
                    <p style="color:var(--oc-text-muted);">"No active sessions."</p>
                }.into_any(),
                Some(list) => list.into_iter().map(|s| {
                    let topic = s.topic.clone();
                    let peer = s.peer.unwrap_or_else(|| "Unknown dApp".into());
                    let chains = s.chains.join(", ");
                    let topic_clone = topic.clone();
                    view! {
                        <div style="background:var(--oc-bg-card);border:1px solid var(--oc-border);border-radius:var(--oc-radius);padding:1rem;margin-bottom:0.75rem;">
                            <div style="display:flex;justify-content:space-between;align-items:center;">
                                <strong>{peer}</strong>
                                <span style="color:var(--oc-text-muted);font-size:0.75rem;font-family:monospace;">{topic}</span>
                            </div>
                            <div style="color:var(--oc-text-muted);font-size:0.875rem;margin-top:0.25rem;">
                                "Chains: "{chains}
                            </div>
                            <button
                                on:click=move |_| {
                                    let t = topic_clone.clone();
                                    leptos::task::spawn_local(async move {
                                        let _ = crate::api::delete(&format!("/sessions/{}", t)).await;
                                    });
                                }
                                style="margin-top:0.5rem;padding:0.25rem 0.75rem;background:var(--oc-danger);color:white;border:none;border-radius:var(--oc-radius);cursor:pointer;font-size:0.8rem;"
                            >
                                "Disconnect"
                            </button>
                        </div>
                    }
                }).collect::<Vec<_>>().into_any(),
            }}
        </div>
    }
}
