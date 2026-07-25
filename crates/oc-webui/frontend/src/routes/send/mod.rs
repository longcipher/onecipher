use leptos::prelude::*;

#[component]
pub fn SendPage() -> impl IntoView {
    let (to, set_to) = signal(String::new());
    let (amount, set_amount) = signal(String::new());
    let (chain, set_chain) = signal(String::from("eip155:1"));
    let (error, set_error) = signal(None::<String>);
    let (sending, set_sending) = signal(false);
    let (sent, set_sent) = signal(false);

    let on_submit = move |ev: web_sys::SubmitEvent| {
        ev.prevent_default();
        set_error.set(None);
        set_sending.set(true);

        let to_val = to.get();
        let amount_val = amount.get();
        let _chain_val = chain.get();

        if to_val.is_empty() || amount_val.is_empty() {
            set_error.set(Some("Recipient and amount are required.".into()));
            set_sending.set(false);
            return;
        }

        leptos::task::spawn_local(async move {
            // ponytail: POST /api/send when the endpoint is wired
            set_sending.set(false);
            set_sent.set(true);
        });
    };

    view! {
        <div style="max-width:600px;margin:0 auto;padding:1.5rem;">
            <h1 style="margin-bottom:1.5rem;">"Send"</h1>

            {move || sent.get().then(|| view! {
                <div style="background:#166534;color:#bbf7d0;padding:0.75rem;border-radius:var(--oc-radius);margin-bottom:1rem;">
                    "Transaction submitted (stub)."
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
                        on:change=move |ev| {
                            let val = event_target_value(&ev);
                            set_chain.set(val);
                        }
                        style="width:100%;padding:0.5rem;background:var(--oc-bg-input);border:1px solid var(--oc-border);border-radius:var(--oc-radius);color:var(--oc-text);"
                    >
                        <option value="eip155:1">"Ethereum"</option>
                        <option value="eip155:137">"Polygon"</option>
                        <option value="solana:mainnet">"Solana"</option>
                    </select>
                </div>

                <div style="margin-bottom:1rem;">
                    <label style="display:block;margin-bottom:0.25rem;color:var(--oc-text-muted);">"Recipient"</label>
                    <input
                        type="text"
                        prop:value=to
                        on:input=move |ev| set_to.set(event_target_value(&ev))
                        placeholder="0x..."
                        style="width:100%;padding:0.5rem;background:var(--oc-bg-input);border:1px solid var(--oc-border);border-radius:var(--oc-radius);color:var(--oc-text);box-sizing:border-box;"
                    />
                </div>

                <div style="margin-bottom:1.5rem;">
                    <label style="display:block;margin-bottom:0.25rem;color:var(--oc-text-muted);">"Amount"</label>
                    <input
                        type="text"
                        prop:value=amount
                        on:input=move |ev| set_amount.set(event_target_value(&ev))
                        placeholder="0.0"
                        style="width:100%;padding:0.5rem;background:var(--oc-bg-input);border:1px solid var(--oc-border);border-radius:var(--oc-radius);color:var(--oc-text);box-sizing:border-box;"
                    />
                </div>

                <button
                    type="submit"
                    disabled=sending
                    style="width:100%;padding:0.75rem;background:var(--oc-accent);color:white;border:none;border-radius:var(--oc-radius);font-weight:600;cursor:pointer;"
                >
                    {move || if sending.get() { "Sending…" } else { "Send" }}
                </button>
            </form>
        </div>
    }
}
