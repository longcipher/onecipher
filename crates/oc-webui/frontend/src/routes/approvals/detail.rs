use leptos::prelude::*;
use leptos_router::{components::A, hooks::use_params_map};

use crate::api::ws::PendingApproval;

use super::risk_card::RiskCard;
use super::sim_panel::SimPanel;
use super::submit_actions::SubmitActions;

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
pub fn ApprovalDetail() -> impl IntoView {
    let params = use_params_map();
    let approval = RwSignal::<Option<PendingApproval>>::new(None);
    let error = RwSignal::<Option<String>>::new(None);
    let decision_result = RwSignal::<Option<String>>::new(None);

    {
        let params = params.clone();
        leptos::reactive::owner::Owner::new().with(move || {
            let id = move || params.read().get("id").unwrap_or_default();
            leptos::task::spawn_local(async move {
                let id_val = id();
                let path = format!("/approvals/{id_val}");
                match crate::api::get_json::<PendingApproval>(&path).await {
                    Ok(a) => approval.set(Some(a)),
                    Err(e) => error.set(Some(e.to_string())),
                }
            });
        });
    }

    view! {
        <div style="max-width:800px;margin:0 auto;padding:1rem;">
            <A href="/approvals">
                <span style="color:#60a5fa;cursor:pointer;">"<- Back"</span>
            </A>

            {move || error.get().map(|e| view! { <p style="color:#ef4444;margin-top:0.5rem;">{e}</p> })}

            {move || {
                decision_result
                    .get()
                    .map(|d| {
                        view! {
                            <p style="color:#22c55e;margin-top:0.5rem;font-weight:600;">
                                {format!("Request {d}")}
                            </p>
                        }
                    })
            }}

            {move || {
                approval
                    .get()
                    .map(|a| {
                        let border = risk_border_color(&a.risk_level);
                        let origin = a
                            .dapp_origin
                            .clone()
                            .unwrap_or_else(|| "unknown".into());
                        let params_display = a
                            .params
                            .clone()
                            .unwrap_or_else(|| "none".into());
                        let chain = a
                            .chain_id
                            .clone()
                            .unwrap_or_else(|| "unknown".into());
                        let is_resolved = decision_result.get().is_some();
                        let risk_reasons = a.risk_reasons.clone();
                        let risk_level = a.risk_level.clone();
                        let approval_id = a.id.clone();
                        let sim = a.simulation.clone();
                        let params_hex = a.params.clone();
                        let on_decided = Callback::new(move |msg: String| {
                            decision_result.set(Some(msg));
                        });
                        view! {
                            <div
                                style=format!(
                                    "border:2px solid {border};border-radius:8px;padding:1.5rem;margin-top:1rem;background:#1f2937;",
                                )
                            >
                                <h2 style="margin-bottom:1rem;">{a.method.clone()}</h2>
                                <div style="margin-bottom:0.5rem;">
                                    <strong>"DApp: "</strong>
                                    <span>{origin}</span>
                                </div>
                                <div style="margin-bottom:0.5rem;">
                                    <strong>"Chain: "</strong>
                                    <span>{chain}</span>
                                </div>
                                <div style="margin-bottom:0.5rem;">
                                    <strong>"Risk Level: "</strong>
                                    <span style=format!("color:{border};font-weight:600;")>
                                        {a.risk_level.clone()}
                                    </span>
                                </div>
                                <div style="margin-bottom:0.5rem;">
                                    <strong>"Params: "</strong>
                                    <pre style="background:#111827;padding:0.75rem;border-radius:4px;overflow-x:auto;font-size:0.8rem;white-space:pre-wrap;">
                                        {params_display}
                                    </pre>
                                </div>

                                // Simulation panel
                                <SimPanel simulation=sim params_hex=params_hex />

                                // Risk cards
                                {if !risk_reasons.is_empty() {
                                    view! {
                                        <div style="margin-bottom:1rem;">
                                            <strong>"Risk Reasons:"</strong>
                                            <div style="margin-top:0.5rem;">
                                                {risk_reasons
                                                    .into_iter()
                                                    .map(|r| {
                                                        view! { <RiskCard reason=r on_acknowledge=Callback::new(|_| {}) /> }
                                                    })
                                                    .collect::<Vec<_>>()}
                                            </div>
                                        </div>
                                    }.into_any()
                                } else {
                                    ().into_any()
                                }}

                                // Submit actions (state machine)
                                {if !is_resolved {
                                    view! {
                                        <div style="margin-top:1.5rem;">
                                            <SubmitActions
                                                approval_id=approval_id
                                                risk_level=risk_level
                                                risk_reasons=a.risk_reasons.clone()
                                                on_decided=on_decided
                                            />
                                        </div>
                                    }.into_any()
                                } else {
                                    ().into_any()
                                }}
                            </div>
                        }.into_any()
                    })
            }}
        </div>
    }
}
