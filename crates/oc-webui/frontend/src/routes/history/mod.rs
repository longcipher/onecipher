use leptos::prelude::*;

use crate::cache::{Scene, read_or_fetch};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuditEntry {
    pub id: String,
    pub action: String,
    pub actor: Option<String>,
    pub detail: Option<String>,
    pub timestamp: Option<String>,
}

#[component]
pub fn HistoryPage() -> impl IntoView {
    let entries = read_or_fetch(Scene::Audit, "list", || {
        crate::api::get_json::<Vec<AuditEntry>>("/audit")
    });

    view! {
        <div style="max-width:800px;margin:0 auto;padding:1.5rem;">
            <h1 style="margin-bottom:1.5rem;">"Audit History"</h1>

            {move || match entries.get() {
                None => view! { <p style="color:var(--oc-text-muted);">"Loading audit log…"</p> }.into_any(),
                Some(list) if list.is_empty() => view! {
                    <p style="color:var(--oc-text-muted);">"No audit entries yet."</p>
                }.into_any(),
                Some(list) => list.into_iter().map(|e| {
                    let detail = e.detail.unwrap_or_default();
                    let actor = e.actor.unwrap_or_else(|| "system".into());
                    let ts = e.timestamp.unwrap_or_default();
                    view! {
                        <div style="background:var(--oc-bg-card);border:1px solid var(--oc-border);border-radius:var(--oc-radius);padding:0.75rem 1rem;margin-bottom:0.5rem;">
                            <div style="display:flex;justify-content:space-between;">
                                <strong>{e.action}</strong>
                                <span style="color:var(--oc-text-muted);font-size:0.75rem;">{ts}</span>
                            </div>
                            <div style="color:var(--oc-text-muted);font-size:0.875rem;margin-top:0.25rem;">
                                "by "{actor}" — "{detail}
                            </div>
                        </div>
                    }
                }).collect::<Vec<_>>().into_any(),
            }}
        </div>
    }
}
