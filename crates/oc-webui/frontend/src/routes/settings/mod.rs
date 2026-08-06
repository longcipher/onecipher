use leptos::prelude::*;

use crate::cache::{Scene, invalidate_scene, read_or_fetch};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Settings {
    pub auto_lock_secs: Option<u64>,
    pub require_biometric: Option<bool>,
    pub allowed_origins: Option<Vec<String>>,
}

#[component]
pub fn SettingsPage() -> impl IntoView {
    let settings = read_or_fetch(Scene::Settings, "current", || {
        crate::api::get_json::<Settings>("/settings")
    });
    let (saved, set_saved) = signal(false);

    view! {
        <div style="max-width:600px;margin:0 auto;padding:1.5rem;">
            <h1 style="margin-bottom:1.5rem;">"Settings"</h1>

            {move || saved.get().then(|| view! {
                <div style="background:#166534;color:#bbf7d0;padding:0.75rem;border-radius:var(--oc-radius);margin-bottom:1rem;">
                    "Settings saved."
                </div>
            })}

            {move || match settings.get() {
                None => view! { <p style="color:var(--oc-text-muted);">"Loading settings…"</p> }.into_any(),
                Some(s) => {
                    let lock_secs = s.auto_lock_secs.unwrap_or(300);
                    view! {
                        <div style="background:var(--oc-bg-card);border:1px solid var(--oc-border);border-radius:var(--oc-radius);padding:1.5rem;">
                            <div style="margin-bottom:1rem;">
                                <label style="display:block;margin-bottom:0.25rem;color:var(--oc-text-muted);">
                                    "Auto-lock timeout (seconds)"
                                </label>
                                <input
                                    type="number"
                                    prop:value=lock_secs.to_string()
                                    style="width:100%;padding:0.5rem;background:var(--oc-bg-input);border:1px solid var(--oc-border);border-radius:var(--oc-radius);color:var(--oc-text);box-sizing:border-box;"
                                />
                            </div>

                            <div style="margin-bottom:1rem;">
                                <label style="display:flex;align-items:center;gap:0.5rem;cursor:pointer;">
                                    <input type="checkbox" prop:checked=s.require_biometric.unwrap_or(true) />
                                    <span>"Require biometric for signing"</span>
                                </label>
                            </div>

                            <button
                                on:click=move |_| {
                                    leptos::task::spawn_local(async move {
                                        let body = serde_json::json!({"auto_lock_secs": 300});
                                        if crate::api::patch_json::<_, serde_json::Value>("/settings", &body).await.is_ok() {
                                            // Re-read from the daemon rather than
                                            // trusting the local patch: the server
                                            // may clamp or reject fields.
                                            invalidate_scene(Scene::Settings);
                                            set_saved.set(true);
                                        }
                                    });
                                }
                                style="padding:0.75rem 1.5rem;background:var(--oc-accent);color:white;border:none;border-radius:var(--oc-radius);font-weight:600;cursor:pointer;"
                            >
                                "Save"
                            </button>
                        </div>
                    }.into_any()
                }
            }}
        </div>
    }
}
