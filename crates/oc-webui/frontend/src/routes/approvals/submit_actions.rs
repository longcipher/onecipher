use std::time::Duration;

use leptos::prelude::*;
use serde::Serialize;

use crate::api::ws::RiskReason;

/// Sign button state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignState {
    Disabled,
    Armed,
    Submitting,
    Forbidden,
}

#[derive(Serialize)]
struct DecisionBody {
    decision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

/// POST a decision for `approval_id`, converge the cache, and report back.
///
/// Extracted because the four button variants below (Forbidden-reject,
/// Disabled-reject, Armed-confirm, Armed-reject) were four copies of the same
/// block — and the copies had already drifted into not invalidating anything,
/// leaving a decided approval in the queue until the WebSocket happened to
/// echo it back.
fn submit_decision(
    approval_id: String,
    decision: &'static str,
    reason: Option<&'static str>,
    label: &'static str,
    on_decided: Callback<String>,
    sign_state: RwSignal<SignState>,
    error: RwSignal<Option<String>>,
) {
    sign_state.set(SignState::Submitting);
    leptos::task::spawn_local(async move {
        let path = format!("/approvals/{approval_id}/decision");
        let body = DecisionBody { decision: decision.into(), reason: reason.map(Into::into) };
        match crate::api::post_json::<DecisionBody, serde_json::Value>(&path, &body).await {
            Ok(_) => {
                // A decision removes the item from the queue and — if it was
                // approved — moves funds and appends to the audit log. Refetch
                // rather than waiting for a WS echo that may never arrive if
                // the socket dropped.
                crate::cache::invalidate_scene(crate::cache::Scene::Approvals);
                crate::cache::invalidate_scene(crate::cache::Scene::Balances);
                crate::cache::invalidate_scene(crate::cache::Scene::Audit);
                on_decided.run(label.into());
            }
            Err(e) => {
                error.set(Some(e.to_string()));
                sign_state.set(SignState::Disabled);
            }
        }
    });
}

#[component]
pub fn SubmitActions(
    approval_id: String,
    risk_level: String,
    risk_reasons: Vec<RiskReason>,
    #[prop(into)] on_decided: Callback<String>,
) -> impl IntoView {
    let warning_count = risk_reasons
        .iter()
        .filter(|r| r.level.as_deref() == Some("Warning"))
        .count() as u32;

    let unprocessed: RwSignal<u32> = RwSignal::new(warning_count);
    let danger_countdown: RwSignal<bool> = RwSignal::new(false);
    let sign_state: RwSignal<SignState> = RwSignal::new(if risk_level == "Forbidden" {
        SignState::Forbidden
    } else {
        SignState::Disabled
    });
    let error: RwSignal<Option<String>> = RwSignal::new(None);

    // Danger → start 5s countdown
    if risk_level == "Danger" && risk_level != "Forbidden" {
        danger_countdown.set(true);
        let ds = danger_countdown;
        gloo_timers::callback::Timeout::new(Duration::from_secs(5).as_millis() as u32, move || {
            ds.set(false);
        })
        .forget();
    }

    // ponytail: sign disabled when unprocessed warnings or countdown active
    let sign_disabled = Memo::new(move |_| unprocessed.get() > 0 || danger_countdown.get());

    let on_sign_click = move |_| {
        sign_state.set(SignState::Armed);
    };

    let on_cancel = move |_| {
        sign_state.set(SignState::Disabled);
    };

    // Store approval_id in a signal so callbacks can Copy it
    let id_signal = RwSignal::new(approval_id.clone());

    let on_ack_all = move |_| {
        unprocessed.set(0);
    };

    view! {
        <div>
            {move || error.get().map(|e| view! { <p style="color:#ef4444;margin-bottom:0.5rem;">{e}</p> })}

            {move || {
                if unprocessed.get() > 0 {
                    view! {
                        <button
                            on:click=on_ack_all
                            style="background:#eab308;color:#000;border:none;padding:0.4rem 1rem;border-radius:6px;font-weight:600;cursor:pointer;font-size:0.875rem;margin-bottom:0.75rem;"
                        >
                            {format!("Acknowledge All ({})", unprocessed.get())}
                        </button>
                    }.into_any()
                } else {
                    ().into_any()
                }
            }}

            {move || {
                if danger_countdown.get() {
                    view! {
                        <div style="color:#f97316;font-size:0.875rem;margin-bottom:0.5rem;font-weight:600;">
                            "Danger: sign disabled for 5 seconds..."
                        </div>
                    }.into_any()
                } else {
                    ().into_any()
                }
            }}

            <div style="display:flex;gap:0.75rem;margin-top:0.5rem;">
                {move || {
                    match sign_state.get() {
                        SignState::Forbidden => {
                            let on_reject = move |_| {
                                submit_decision(
                                    id_signal.get(),
                                    "rejected",
                                    Some("user rejected"),
                                    "Rejected",
                                    on_decided,
                                    sign_state,
                                    error,
                                );
                            };
                            view! {
                                <button
                                    on:click=on_reject
                                    style="background:#ef4444;color:white;border:none;padding:0.6rem 1.5rem;border-radius:6px;font-weight:600;cursor:pointer;"
                                >
                                    "Reject"
                                </button>
                            }.into_any()
                        }
                        SignState::Disabled => {
                            let on_reject = move |_| {
                                submit_decision(
                                    id_signal.get(),
                                    "rejected",
                                    Some("user rejected"),
                                    "Rejected",
                                    on_decided,
                                    sign_state,
                                    error,
                                );
                            };
                            view! {
                                <button
                                    on:click=on_sign_click
                                    disabled=sign_disabled.get()
                                    style=format!(
                                        "background:{};color:white;border:none;padding:0.6rem 1.5rem;border-radius:6px;font-weight:600;cursor:{};",
                                        if sign_disabled.get() { "#4b5563" } else { "#22c55e" },
                                        if sign_disabled.get() { "not-allowed" } else { "pointer" },
                                    )
                                >
                                    "Sign"
                                </button>
                                <button
                                    on:click=on_reject
                                    style="background:#ef4444;color:white;border:none;padding:0.6rem 1.5rem;border-radius:6px;font-weight:600;cursor:pointer;"
                                >
                                    "Reject"
                                </button>
                            }.into_any()
                        }
                        SignState::Armed => {
                            let on_confirm = move |_| {
                                submit_decision(
                                    id_signal.get(),
                                    "approved",
                                    None,
                                    "Approved",
                                    on_decided,
                                    sign_state,
                                    error,
                                );
                            };
                            let on_reject = move |_| {
                                submit_decision(
                                    id_signal.get(),
                                    "rejected",
                                    Some("user rejected"),
                                    "Rejected",
                                    on_decided,
                                    sign_state,
                                    error,
                                );
                            };
                            view! {
                                <button
                                    on:click=on_confirm
                                    style="background:#22c55e;color:white;border:none;padding:0.6rem 1.5rem;border-radius:6px;font-weight:600;cursor:pointer;"
                                >
                                    "Confirm Sign"
                                </button>
                                <button
                                    on:click=on_cancel
                                    style="background:#374151;color:#d1d5db;border:1px solid #4b5563;padding:0.6rem 1.5rem;border-radius:6px;font-weight:600;cursor:pointer;"
                                >
                                    "Cancel"
                                </button>
                                <button
                                    on:click=on_reject
                                    style="background:#ef4444;color:white;border:none;padding:0.6rem 1.5rem;border-radius:6px;font-weight:600;cursor:pointer;"
                                >
                                    "Reject"
                                </button>
                            }.into_any()
                        }
                        SignState::Submitting => view! {
                            <button
                                disabled=true
                                style="background:#4b5563;color:#9ca3af;border:none;padding:0.6rem 1.5rem;border-radius:6px;font-weight:600;cursor:not-allowed;"
                            >
                                "Signing..."
                            </button>
                        }.into_any(),
                    }
                }}
            </div>
        </div>
    }
}
