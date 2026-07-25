use leptos::prelude::*;

use crate::api::ws::RiskReason;

fn risk_level_color(level: &str) -> &'static str {
    match level {
        "Safe" => "#22c55e",
        "Warning" => "#eab308",
        "Danger" => "#f97316",
        "Forbidden" => "#ef4444",
        _ => "#6b7280",
    }
}

fn risk_level_bg(level: &str) -> &'static str {
    match level {
        "Safe" => "#052e16",
        "Warning" => "#422006",
        "Danger" => "#431407",
        "Forbidden" => "#450a0a",
        _ => "#1f2937",
    }
}

#[component]
pub fn RiskCard(
    reason: RiskReason,
    #[prop(into)] on_acknowledge: Callback<()>,
) -> impl IntoView {
    let level = reason.level.clone().unwrap_or_else(|| "Warning".into());
    let message = reason.message.clone().unwrap_or_else(|| "Unknown risk".into());
    let code = reason.code.clone().unwrap_or_default();
    let source = reason.source.clone().unwrap_or_default();
    let detail = reason.detail.clone();

    let color = risk_level_color(&level);
    let bg = risk_level_bg(&level);

    view! {
        <div
            style=format!(
                "border:1px solid {color};border-radius:6px;padding:0.75rem;margin-bottom:0.5rem;background:{bg};",
            )
        >
            <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:0.5rem;">
                <div style="flex:1;">
                    <div style=format!("color:{color};font-weight:600;font-size:0.875rem;margin-bottom:0.25rem;")>
                        {if code.is_empty() { level.clone() } else { format!("{level}: {code}") }}
                    </div>
                    <div style="color:#d1d5db;font-size:0.875rem;">{message}</div>
                    {if !source.is_empty() {
                        view! {
                            <div style="color:#9ca3af;font-size:0.75rem;margin-top:0.25rem;">
                                {format!("Source: {source}")}
                            </div>
                        }
                            .into_any()
                    } else {
                        ().into_any()
                    }}
                    {if let Some(d) = detail {
                        view! {
                            <pre style="color:#9ca3af;font-size:0.75rem;margin-top:0.25rem;white-space:pre-wrap;">
                                {d}
                            </pre>
                        }
                            .into_any()
                    } else {
                        ().into_any()
                    }}
                </div>
                <button
                    on:click=move |_| on_acknowledge.run(())
                    style="background:#374151;color:#d1d5db;border:1px solid #4b5563;padding:0.25rem 0.6rem;border-radius:4px;font-size:0.75rem;cursor:pointer;white-space:nowrap;flex-shrink:0;"
                >
                    "Acknowledge"
                </button>
            </div>
        </div>
    }
}
