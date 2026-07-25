use leptos::prelude::*;
use leptos_router::components::A;

use crate::api::ws::PendingApproval;
use crate::state::auth::use_auth;

#[component]
pub fn Dashboard() -> impl IntoView {
    let _auth = use_auth();
    let approvals = RwSignal::<Vec<PendingApproval>>::new(vec![]);

    // Fetch approvals on mount
    {
        leptos::reactive::owner::Owner::new().with(move || {
            crate::api::ws::connect_ws(approvals);
        });
    }

    view! {
        <div class="dashboard" style="min-height:100vh;background:var(--oc-bg);color:var(--oc-text);font-family:var(--oc-font);">
            <DashboardHeader />
            <main style="max-width:960px;margin:0 auto;padding:1.5rem;">
                <GasBar />
                <CurrentConnection />
                <DashboardPanel />
            </main>
        </div>
    }
}

#[component]
fn DashboardHeader() -> impl IntoView {
    view! {
        <header style="background:var(--oc-bg-card);border-bottom:1px solid var(--oc-border);padding:0.75rem 1.5rem;display:flex;justify-content:space-between;align-items:center;">
            <div style="display:flex;align-items:center;gap:1rem;">
                <A href="/dashboard"><strong style="font-size:1.25rem;">"OneCipher"</strong></A>
                <nav style="display:flex;gap:0.75rem;">
                    <A href="/dashboard">"Dashboard"</A>
                    <A href="/send">"Send"</A>
                    <A href="/wallets">"Wallets"</A>
                    <A href="/sessions">"Sessions"</A>
                    <A href="/approvals">"Approvals"</A>
                    <A href="/settings">"Settings"</A>
                </nav>
            </div>
            <button
                on:click=move |_| { crate::theme::dark::toggle_dark_mode(); }
                style="background:var(--oc-bg-input);border:1px solid var(--oc-border);border-radius:var(--oc-radius);padding:0.25rem 0.75rem;cursor:pointer;color:var(--oc-text);"
            >
                "Toggle Theme"
            </button>
        </header>
    }
}

#[component]
fn GasBar() -> impl IntoView {
    // ponytail: fetch gas prices from API when available
    view! {
        <div style="background:var(--oc-bg-card);border:1px solid var(--oc-border);border-radius:var(--oc-radius);padding:0.5rem 1rem;margin-bottom:1rem;display:flex;gap:1.5rem;font-size:0.875rem;">
            <span>"Gas: "~"N/A"</span>
            <span>"ETH: "~"N/A"</span>
        </div>
    }
}

#[component]
fn CurrentConnection() -> impl IntoView {
    // ponytail: show WalletConnect session info when available
    view! {
        <div style="background:var(--oc-bg-card);border:1px solid var(--oc-border);border-radius:var(--oc-radius);padding:0.75rem 1rem;margin-bottom:1rem;">
            <span style="color:var(--oc-text-muted);">"No active WalletConnect session"</span>
        </div>
    }
}

#[component]
fn DashboardPanel() -> impl IntoView {
    view! {
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:1rem;">
            <PanelCard title="Pending Approvals" href="/approvals" description="Review signing requests" />
            <PanelCard title="Wallets" href="/wallets" description="Manage your wallets" />
            <PanelCard title="Sessions" href="/sessions" description="WalletConnect sessions" />
            <PanelCard title="Session Keys" href="/dashboard" description="Multi-chain session keys" />
        </div>
    }
}

#[component]
fn PanelCard(title: &'static str, href: &'static str, description: &'static str) -> impl IntoView {
    view! {
        <A href=href>
            <div style="background:var(--oc-bg-card);border:1px solid var(--oc-border);border-radius:var(--oc-radius);padding:1.25rem;cursor:pointer;transition:border-color 0.15s;">
                <h3 style="margin:0 0 0.25rem 0;font-size:1rem;">{title}</h3>
                <p style="margin:0;color:var(--oc-text-muted);font-size:0.875rem;">{description}</p>
            </div>
        </A>
    }
}
