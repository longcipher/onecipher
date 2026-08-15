use leptos::prelude::*;

use crate::cache::{Scene, invalidate_scene, read_or_fetch};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Session {
    pub topic: String,
    pub peer: Option<String>,
    pub chains: Vec<String>,
    pub expiry: Option<u64>,
}

#[component]
pub fn SessionsPage() -> impl IntoView {
    let sessions = read_or_fetch(Scene::Sessions, "list", || {
        crate::api::get_json::<Vec<Session>>("/sessions")
    });

    // "Connect dApp" input: paste a WC v2 pairing URI (wc:...) and inject it
    // into the daemon's wallet server via POST /api/pairings.
    let uri = RwSignal::new(String::new());
    let connect_result = RwSignal::new(None::<String>);
    let connect = move |_| {
        let uri = uri.get_untracked();
        if uri.trim().is_empty() {
            return;
        }
        leptos::task::spawn_local(async move {
            match crate::api::post_json::<_, serde_json::Value>(
                "/pairings",
                &serde_json::json!({ "uri": uri }),
            )
            .await
            {
                Ok(v) => connect_result.set(Some(format!("Connected: {}", v["topic"]))),
                Err(e) => connect_result.set(Some(format!("Failed: {e}"))),
            }
        });
    };

    view! {
        <div style="max-width:800px;margin:0 auto;padding:1.5rem;">
            <h1 style="margin-bottom:1.5rem;">"WalletConnect Sessions"</h1>

            <div style="background:var(--oc-bg-card);border:1px solid var(--oc-border);border-radius:var(--oc-radius);padding:1rem;margin-bottom:1.5rem;">
                <strong>"Connect dApp"</strong>
                <p style="color:var(--oc-text-muted);font-size:0.8rem;margin:0.25rem 0 0.5rem;">
                    "Paste the dApp's WalletConnect pairing URI (wc:...)."
                </p>
                <div style="display:flex;gap:0.5rem;">
                    <input
                        prop:value=uri
                        on:input=move |ev| uri.set(event_target_value(&ev))
                        placeholder="wc:1234...@2?relay-protocol=irn&symKey=..."
                        style="flex:1;padding:0.5rem;border:1px solid var(--oc-border);border-radius:var(--oc-radius);background:var(--oc-bg);color:var(--oc-text);font-family:monospace;font-size:0.8rem;"
                    />
                    <button
                        on:click=connect
                        style="padding:0.5rem 1rem;background:#2563eb;color:white;border:none;border-radius:var(--oc-radius);cursor:pointer;font-size:0.85rem;"
                    >
                        "Connect"
                    </button>
                </div>
                {move || connect_result.get().map(|r| {
                    let color = if r.starts_with("Connected") { "#22c55e" } else { "#ef4444" };
                    view! { <p style=format!("color:{color};margin-top:0.5rem;font-size:0.85rem;")>{r}</p> }
                })}
            </div>

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
                                        if crate::api::delete(&format!("/sessions/{}", t)).await.is_ok() {
                                            // Refetch the list; without this the
                                            // disconnected dApp stays on screen.
                                            invalidate_scene(Scene::Sessions);
                                        }
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
