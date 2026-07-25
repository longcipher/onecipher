use leptos::prelude::*;
use leptos_router::{
    components::{Route, Router, Routes},
    path,
};

use crate::components::keep_alive::KeepAlive;
use crate::routes::{
    approvals::ApprovalsList, approvals::detail::ApprovalDetail, dashboard::Dashboard,
    history::HistoryPage, no_address::NoAddress, send::SendPage, sessions::SessionsPage,
    settings::SettingsPage, sort_hat::SortHat, unlock::Unlock, wallets::WalletCreate,
    wallets::WalletImport, wallets::WalletInfo, wallets::WalletsPage, welcome::Welcome,
};
use crate::state::auth::provide_auth;

#[component]
pub fn App() -> impl IntoView {
    provide_auth();

    view! {
        <Router>
            <Routes fallback=|| view! { <p>"Not Found"</p> }>
                // Landing / auth routes
                <Route path=path!("/") view=SortHat />
                <Route path=path!("/welcome") view=Welcome />
                <Route path=path!("/unlock") view=Unlock />
                <Route path=path!("/no-address") view=NoAddress />

                // Main app routes
                <Route path=path!("/dashboard") view=Dashboard />
                <Route path=path!("/send") view=SendPage />

                // Wallet routes
                <Route path=path!("/wallets") view=WalletsPage />
                <Route path=path!("/wallets/create") view=WalletCreate />
                <Route path=path!("/wallets/import") view=WalletImport />
                <Route path=path!("/wallets/info") view=WalletInfo />

                // Approvals
                <Route path=path!("/approvals") view=ApprovalsList />
                <Route path=path!("/approvals/:id") view=ApprovalDetail />

                // Keep-alive routes: stay mounted, toggled by class:hidden
                <Route path=path!("/sessions") view=SessionsPage />
                <Route path=path!("/history") view=HistoryPage />
                <Route path=path!("/settings") view=SettingsPage />
            </Routes>

            // Persistent mounts — always in DOM, hidden when not on their route.
            // WebSocket subscriptions stay alive across route switches.
            <KeepAlive when_path="/sessions">
                <SessionsPage />
            </KeepAlive>
            <KeepAlive when_path="/history">
                <HistoryPage />
            </KeepAlive>
            <KeepAlive when_path="/settings">
                <SettingsPage />
            </KeepAlive>
        </Router>
    }
}
