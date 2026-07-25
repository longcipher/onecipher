pub mod detail;
pub mod risk_card;
pub mod sim_panel;
pub mod submit_actions;

use leptos::prelude::*;
use leptos_router::components::A;

use crate::api::ws::{PendingApproval, connect_ws};

fn risk_border_color(level: &str) -> &'static str {
    match level {
        "Safe" => "#22c55e",
        "Warning" => "#eab308",
        "Danger" => "#f97316",
        "Forbidden" => "#ef4444",
        _ => "#6b7280",
    }
}

#[component]
pub fn ApprovalsList() -> impl IntoView {
    let approvals = RwSignal::<Vec<PendingApproval>>::new(vec![]);
    let error = RwSignal::<Option<String>>::new(None);

    // Fetch initial approvals
    let fetch_approvals = move || {
        leptos::task::spawn_local(async move {
            match crate::api::get_json::<Vec<PendingApproval>>("/approvals").await {
                Ok(list) => approvals.set(list),
                Err(e) => error.set(Some(e.to_string())),
            }
        });
    };

    // Mount: fetch + subscribe to WS
    leptos::reactive::owner::Owner::new().with(move || {
        fetch_approvals();
        connect_ws(approvals);
    });

    view! {
        <div class="approvals-list" style="max-width:800px;margin:0 auto;padding:1rem;">
            <h1 style="margin-bottom:1rem;">"Pending Approvals"</h1>

            {move || {
                error
                    .get()
                    .map(|e| view! { <p style="color:#ef4444;">{e}</p> }.into_any())
            }}

            {move || {
                let list = approvals.get();
                if list.is_empty() {
                    view! { <p style="color:#9ca3af;">"No pending approvals."</p> }.into_any()
                } else {
                    list.into_iter()
                        .map(|a| {
                            let border = risk_border_color(&a.risk_level);
                            let href = format!("/approvals/{}", a.id);
                            let method = a.method.clone();
                            let origin = a
                                .dapp_origin
                                .clone()
                                .unwrap_or_else(|| "unknown".into());
                            let risk = a.risk_level.clone();
                            view! {
                                <A href=href>
                                    <div
                                        style=format!(
                                            "border:2px solid {border};border-radius:8px;padding:1rem;margin-bottom:0.75rem;cursor:pointer;background:#1f2937;",
                                        )
                                    >
                                        <div style="display:flex;justify-content:space-between;align-items:center;">
                                            <span style="font-weight:600;">{method}</span>
                                            <span style=format!("color:{border};font-weight:600;")>
                                                {risk}
                                            </span>
                                        </div>
                                        <div style="color:#9ca3af;font-size:0.875rem;margin-top:0.25rem;">
                                            {origin}
                                        </div>
                                    </div>
                                </A>
                            }
                                .into_any()
                        })
                        .collect::<Vec<_>>()
                        .into_any()
                }
            }}
        </div>
    }
}
