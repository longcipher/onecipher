use leptos::prelude::*;

use crate::api::ws::TxSimulation;

#[component]
pub fn SimPanel(
    simulation: Option<TxSimulation>,
    params_hex: Option<String>,
) -> impl IntoView {
    match simulation {
        Some(sim) => view! { <SimResult sim /> }.into_any(),
        None => view! {
            <div style="background:#1f2937;border:1px solid #374151;border-radius:6px;padding:1rem;margin-bottom:1rem;">
                <div style="color:#eab308;font-weight:600;margin-bottom:0.5rem;">
                    "⚠ Decoding failed (offline)"
                </div>
                <div style="color:#9ca3af;font-size:0.875rem;margin-bottom:0.5rem;">
                    "Simulation unavailable. Showing raw transaction parameters."
                </div>
                <pre style="background:#111827;padding:0.75rem;border-radius:4px;overflow-x:auto;font-size:0.8rem;white-space:pre-wrap;color:#d1d5db;">
                    {params_hex.unwrap_or_else(|| "none".into())}
                </pre>
            </div>
        }.into_any(),
    }
}

#[component]
fn SimResult(sim: TxSimulation) -> impl IntoView {
    let success = sim.success.unwrap_or(false);
    let gas = sim.gas_used.unwrap_or(0);
    let deltas = sim.balance_change.unwrap_or_default();
    let decoded = sim.decoded_action;
    let error_msg = sim.error;

    let status_color = if success { "#22c55e" } else { "#ef4444" };
    let status_text = if success { "Simulation succeeded" } else { "Simulation failed" };

    view! {
        <div style="background:#1f2937;border:1px solid #374151;border-radius:6px;padding:1rem;margin-bottom:1rem;">
            // Status + gas
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.75rem;">
                <span style=format!("color:{status_color};font-weight:600;")>{status_text}</span>
                <span style="color:#9ca3af;font-size:0.875rem;">{format!("{gas} gas")}</span>
            </div>

            // Decoded action
            {decoded.map(|d| {
                let label = d.human_readable.unwrap_or_else(|| {
                    let contract = d.contract_name.unwrap_or_else(|| "Unknown".into());
                    let func = d.function_name.unwrap_or_else(|| "unknown".into());
                    format!("{contract}.{func}")
                });
                view! {
                    <div style="background:#111827;border-radius:4px;padding:0.75rem;margin-bottom:0.75rem;">
                        <div style="color:#60a5fa;font-size:0.75rem;margin-bottom:0.25rem;">"Action"</div>
                        <div style="color:#f3f4f6;font-weight:600;">{label}</div>
                    </div>
                }.into_any()
            })}

            // Error
            {error_msg.map(|e| view! {
                <div style="color:#ef4444;font-size:0.875rem;margin-bottom:0.5rem;">
                    {format!("Error: {e}")}
                </div>
            })}

            // Balance changes
            {if !deltas.is_empty() {
                view! {
                    <div style="margin-top:0.5rem;">
                        <div style="color:#9ca3af;font-size:0.75rem;margin-bottom:0.375rem;">"Balance Changes"</div>
                        {deltas.into_iter().map(|d| {
                            let is_send = d.direction == "Send";
                            let arrow_color = if is_send { "#ef4444" } else { "#22c55e" };
                            let arrow = if is_send { "→" } else { "←" };
                            view! {
                                <div style="display:flex;align-items:center;gap:0.5rem;padding:0.25rem 0;font-size:0.875rem;">
                                    <span style=format!("color:{arrow_color};font-weight:600;")>{arrow}</span>
                                    <span style="color:#d1d5db;">{d.amount}</span>
                                    <span style="color:#9ca3af;">{d.token}</span>
                                    <span style=format!("color:{arrow_color};font-size:0.75rem;")>{d.direction}</span>
                                </div>
                            }
                        }).collect::<Vec<_>>()}
                    </div>
                }.into_any()
            } else {
                ().into_any()
            }}
        </div>
    }
}
