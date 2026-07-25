use leptos::prelude::{RwSignal, expect_context, provide_context};

/// Global authentication state.
#[derive(Debug, Clone, Copy)]
pub struct AuthState {
    pub is_authenticated: RwSignal<bool>,
}

/// Provide auth context at app root.
pub fn provide_auth() -> AuthState {
    let state = AuthState {
        is_authenticated: RwSignal::new(false),
    };
    provide_context(state);
    state
}

/// Consume auth context from anywhere in the tree.
pub fn use_auth() -> RwSignal<bool> {
    expect_context::<AuthState>().is_authenticated
}
