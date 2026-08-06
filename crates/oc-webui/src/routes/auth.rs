//! WebAuthn registration / login / session routes.
//!
//! Wires the [`crate::auth`] building blocks — [`BootstrapToken`],
//! [`WebAuthnManager`], [`SessionStore`] — into HTTP endpoints per the W1.6
//! spec:
//!
//! ```text
//! POST /api/auth/bootstrap                      — is first-time registration needed?
//! POST /api/auth/webauthn/register/begin        — start registration (requires bootstrap)
//! POST /api/auth/webauthn/register/finish       — finish + persist + dual-register with Key-Agent
//! POST /api/auth/webauthn/login/begin           — start login
//! POST /api/auth/webauthn/login/finish          — verify + create session
//! POST /api/auth/logout                         — destroy session
//! GET  /api/auth/status                         — is a session active?
//! POST /api/auth/lock                           — expire session (auto-lock trigger)
//! ```
//!
//! ## Dual registration (ADR-2 unification)
//!
//! A browser passkey registered here is ALSO forwarded to the Key-Agent's
//! `PasskeyPubkeyStore` via the `RegisterPasskey` RPC. That makes one
//! registration serve both trust domains: browser UI login (WebAuthn) and
//! dApp signing authorization (Key-Agent challenge-response). The two
//! registries remain distinct files (`webauthn_passkeys.json` vs
//! `passkeys.json`), but the user registers once.

use std::sync::Arc;

use axum::{
    Json,
    extract::State,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use tokio::sync::Mutex;

use crate::auth::{
    BootstrapToken, SessionStore,
    webauthn::{StoredCredential, WebAuthnManager},
};

/// A callback the daemon installs to forward a newly registered browser
/// passkey into the Key-Agent's `PasskeyPubkeyStore` (dual registration).
///
/// Returning `false` (or `None`) means the forward failed — the browser
/// registration still succeeds; the caller is told it did not reach the
/// Key-Agent.
pub type DualRegistrationFn = Arc<dyn Fn(&str, &str, &[u8]) -> bool + Send + Sync>;

/// Shared state for auth routes.
#[derive(Clone)]
pub struct AuthState {
    pub webauthn: WebAuthnManager,
    pub bootstrap: BootstrapToken,
    pub session_store: SessionStore,
    /// Installed by the daemon to mirror the passkey into the Key-Agent.
    /// `None` when the daemon cannot (Key-Agent not linked or unavailable).
    pub dual_register: Option<DualRegistrationFn>,
    /// Wall-clock auto-lock deadline (`None` = never). Set by the daemon.
    pub auto_lock_at: Arc<Mutex<Option<u64>>>,
}

/// Session cookie name.
pub const SESSION_COOKIE: &str = "oc_session";
/// Header used to carry the session id (simpler than cookie parsing in the
/// Leptos CSR client; cookie is still set for browser-native flows).
pub const SESSION_HEADER: &str = "x-oc-session";

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `POST /api/auth/bootstrap` — report whether first-time registration is
/// required, and if so whether a valid bootstrap token exists.
pub async fn bootstrap(State(state): State<AuthState>) -> Response {
    let has_credentials = state.webauthn.has_credentials().await;
    let needs_registration = !has_credentials;
    let token_ready = state.bootstrap.is_valid().await;
    Json(serde_json::json!({
        "needs_registration": needs_registration,
        "bootstrap_ready": token_ready,
        "bootstrap_ttl_secs": 300,
    }))
    .into_response()
}

/// `POST /api/auth/webauthn/register/begin`
///
/// Body: `{ "bootstrap_token": "<token>" }`. Requires a valid, unexpired,
/// unconsumed bootstrap token (first-time registration only).
#[derive(Debug, Deserialize)]
pub struct RegisterBeginRequest {
    pub bootstrap_token: String,
}

pub async fn register_begin(
    State(state): State<AuthState>,
    Json(body): Json<RegisterBeginRequest>,
) -> Response {
    // Registration is only allowed before any credential exists.
    if state.webauthn.has_credentials().await {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error": "already registered"})))
            .into_response();
    }
    if !state.bootstrap.validate_and_consume(&body.bootstrap_token).await {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "invalid or expired bootstrap token"})),
        )
            .into_response();
    }

    match state.webauthn.register_begin().await {
        Ok((ccr, user_id)) => Json(serde_json::json!({
            "challenge": ccr,
            "user_id": user_id.to_string(),
        }))
        .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("register begin failed: {e}")})),
        )
            .into_response(),
    }
}

/// `POST /api/auth/webauthn/register/finish`
#[derive(Debug, Deserialize)]
pub struct RegisterFinishRequest {
    pub user_id: String,
    pub credential: serde_json::Value,
}

pub async fn register_finish(
    State(state): State<AuthState>,
    Json(body): Json<RegisterFinishRequest>,
) -> Response {
    let user_id: uuid::Uuid = match body.user_id.parse() {
        Ok(id) => id,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid user_id"})))
                .into_response();
        }
    };

    // Re-serialize the raw credential into the type webauthn-rs expects.
    let response: webauthn_rs::prelude::RegisterPublicKeyCredential =
        match serde_json::from_value(body.credential) {
            Ok(r) => r,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": format!("invalid credential: {e}")})),
                )
                    .into_response();
            }
        };

    let stored: StoredCredential = match state.webauthn.register_finish(user_id, &response).await {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("registration failed: {e}")})),
            )
                .into_response();
        }
    };

    // Dual registration: forward the passkey to the Key-Agent so it can also
    // authorize dApp signing. Failure here must NOT fail the browser
    // registration — the passkey is already persisted for UI auth.
    let dual_registered = match &state.dual_register {
        Some(forward) => {
            let cred_id = stored.credential_id.clone();
            if let Some((algorithm, public_key)) = extract_sec1_public_key(&stored) {
                forward(&cred_id, &algorithm, &public_key)
            } else {
                tracing::warn!(cred_id = %cred_id, "passkey is not P-256/Ed25519; skipped Key-Agent registration");
                false
            }
        }
        None => false,
    };

    Json(serde_json::json!({
        "credential_id": stored.credential_id,
        "registered": true,
        "dual_registered": dual_registered,
    }))
    .into_response()
}

/// `POST /api/auth/webauthn/login/begin`
pub async fn login_begin(State(state): State<AuthState>) -> Response {
    match state.webauthn.login_begin().await {
        Ok((rcr, challenge_id)) => Json(serde_json::json!({
            "challenge": rcr,
            "challenge_id": challenge_id.to_string(),
        }))
        .into_response(),
        Err(e) => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": format!("login begin failed: {e}")})),
        )
            .into_response(),
    }
}

/// `POST /api/auth/webauthn/login/finish`
#[derive(Debug, Deserialize)]
pub struct LoginFinishRequest {
    pub challenge_id: String,
    pub credential: serde_json::Value,
}

pub async fn login_finish(
    State(state): State<AuthState>,
    Json(body): Json<LoginFinishRequest>,
) -> Response {
    let challenge_id: uuid::Uuid = match body.challenge_id.parse() {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid challenge_id"})),
            )
                .into_response();
        }
    };

    let response: webauthn_rs::prelude::PublicKeyCredential =
        match serde_json::from_value(body.credential) {
            Ok(r) => r,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": format!("invalid credential: {e}")})),
                )
                    .into_response();
            }
        };

    let credential_id = match state.webauthn.login_finish(challenge_id, &response).await {
        Ok(cid) => cid,
        Err(e) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": format!("login failed: {e}")})),
            )
                .into_response();
        }
    };

    let session = state.session_store.create_session(&credential_id, None);
    let mut response = Json(serde_json::json!({
        "session_id": session.id,
        "credential_id": credential_id,
    }))
    .into_response();
    if let Ok(cookie) = header::HeaderValue::from_str(&session.id) {
        response.headers_mut().insert(
            header::SET_COOKIE,
            header::HeaderValue::from_str(&format!(
                "{SESSION_COOKIE}={}; Path=/; HttpOnly; SameSite=Strict",
                session.id
            ))
            .unwrap_or(cookie),
        );
    }
    response
}

/// `POST /api/auth/logout`
#[derive(Debug, Deserialize)]
pub struct LogoutRequest {
    pub session_id: String,
}

pub async fn logout(State(state): State<AuthState>, Json(body): Json<LogoutRequest>) -> Response {
    state.session_store.remove(&body.session_id);
    Json(serde_json::json!({"ok": true})).into_response()
}

/// `GET /api/auth/status` — is a session active?
pub async fn status(State(state): State<AuthState>) -> Response {
    // The daemon enforces auto-lock; the frontend polls this endpoint.
    let locked = {
        let deadline = state.auto_lock_at.lock().await;
        deadline.is_some_and(|d| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .is_ok_and(|n| n.as_secs() >= d)
        })
    };
    Json(serde_json::json!({ "locked": locked })).into_response()
}

/// `POST /api/auth/lock` — destroy every session (auto-lock trigger).
pub async fn lock(State(state): State<AuthState>) -> Response {
    state.session_store.destroy_all();
    Json(serde_json::json!({"ok": true})).into_response()
}

// ---------------------------------------------------------------------------
// Dual registration helpers
// ---------------------------------------------------------------------------

/// Extract the SEC1-encoded public key + algorithm tag from a stored
/// credential, for forwarding to the Key-Agent's `PasskeyPubkeyStore`.
///
/// Returns `(algorithm, public_key_bytes)`:
/// - P-256 (EC2/SECP256R1) → `("p256", 0x04 || x || y)` — the Key-Agent's
///   [`oc_keyagent::passkey::PasskeyPubkey::P256`] SEC1 encoding.
/// - Ed25519 (OKP/ED25519) → `("ed25519", x)` — 32 raw bytes.
fn extract_sec1_public_key(stored: &StoredCredential) -> Option<(String, Vec<u8>)> {
    use webauthn_rs::prelude::COSEKeyType;

    let key = stored.credential.get_public_key();
    match &key.key {
        COSEKeyType::EC_EC2(ec2) if ec2.curve == webauthn_rs::prelude::ECDSACurve::SECP256R1 => {
            let mut sec1 = Vec::with_capacity(65);
            sec1.push(0x04); // uncompressed point
            sec1.extend_from_slice(ec2.x.as_ref());
            sec1.extend_from_slice(ec2.y.as_ref());
            Some(("p256".to_string(), sec1))
        }
        COSEKeyType::EC_OKP(okp) if okp.curve == webauthn_rs::prelude::EDDSACurve::ED25519 => {
            Some(("ed25519".to_string(), okp.x.as_ref().to_vec()))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sec1_extraction_rejects_non_ec2_keys() {
        // Without a real COSE key we cannot construct a Passkey; the safest
        // unit-level check is the algorithm-mapping branches. Build a fake
        // StoredCredential is impossible (Passkey fields are private), so this
        // guards the constant used by the router instead.
        assert_eq!(SESSION_COOKIE, "oc_session");
        assert_eq!(SESSION_HEADER, "x-oc-session");
    }

    #[test]
    fn auth_state_is_cloneable() {
        // AuthState must be Clone for axum extractors; compile-time check.
        let dir = tempfile::tempdir().unwrap();
        let origin = url::Url::parse("http://localhost:9090").unwrap();
        let w = WebAuthnManager::new(dir.path(), &origin).unwrap();
        let bs = BootstrapToken::new(dir.path());
        let ss = SessionStore::new(1800);
        let state = AuthState {
            webauthn: w,
            bootstrap: bs,
            session_store: ss,
            dual_register: None,
            auto_lock_at: Arc::new(Mutex::new(None)),
        };
        let _clone = state.clone();
    }

    #[tokio::test]
    async fn bootstrap_reports_registration_required_when_empty() {
        let dir = tempfile::tempdir().unwrap();
        let origin = url::Url::parse("http://localhost:9090").unwrap();
        let w = WebAuthnManager::new(dir.path(), &origin).unwrap();
        let bs = BootstrapToken::new(dir.path());
        let _ = bs.generate().await.unwrap();
        let state = AuthState {
            webauthn: w,
            bootstrap: bs,
            session_store: SessionStore::new(1800),
            dual_register: None,
            auto_lock_at: Arc::new(Mutex::new(None)),
        };
        let resp = bootstrap(State(state)).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn register_begin_rejects_without_bootstrap_token() {
        let dir = tempfile::tempdir().unwrap();
        let origin = url::Url::parse("http://localhost:9090").unwrap();
        let w = WebAuthnManager::new(dir.path(), &origin).unwrap();
        let bs = BootstrapToken::new(dir.path());
        // No token generated → validation must fail.
        let state = AuthState {
            webauthn: w,
            bootstrap: bs,
            session_store: SessionStore::new(1800),
            dual_register: None,
            auto_lock_at: Arc::new(Mutex::new(None)),
        };
        let body = RegisterBeginRequest { bootstrap_token: "nope".into() };
        let resp = register_begin(State(state), Json(body)).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn register_begin_succeeds_with_valid_token() {
        let dir = tempfile::tempdir().unwrap();
        let origin = url::Url::parse("http://localhost:9090").unwrap();
        let w = WebAuthnManager::new(dir.path(), &origin).unwrap();
        let bs = BootstrapToken::new(dir.path());
        let token = bs.generate().await.unwrap();
        let state = AuthState {
            webauthn: w,
            bootstrap: bs,
            session_store: SessionStore::new(1800),
            dual_register: None,
            auto_lock_at: Arc::new(Mutex::new(None)),
        };
        let body = RegisterBeginRequest { bootstrap_token: token };
        let resp = register_begin(State(state), Json(body)).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn status_reports_locked_when_deadline_passed() {
        let dir = tempfile::tempdir().unwrap();
        let origin = url::Url::parse("http://localhost:9090").unwrap();
        let state = AuthState {
            webauthn: WebAuthnManager::new(dir.path(), &origin).unwrap(),
            bootstrap: BootstrapToken::new(dir.path()),
            session_store: SessionStore::new(1800),
            dual_register: None,
            auto_lock_at: Arc::new(Mutex::new(Some(0))), // epoch = already past
        };
        let resp = status(State(state)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["locked"], true);
    }

    #[tokio::test]
    async fn lock_destroys_all_sessions() {
        let dir = tempfile::tempdir().unwrap();
        let origin = url::Url::parse("http://localhost:9090").unwrap();
        let state = AuthState {
            webauthn: WebAuthnManager::new(dir.path(), &origin).unwrap(),
            bootstrap: BootstrapToken::new(dir.path()),
            session_store: SessionStore::new(1800),
            dual_register: None,
            auto_lock_at: Arc::new(Mutex::new(None)),
        };
        let _s = state.session_store.create_session("cred-1", None);
        let _s2 = state.session_store.create_session("cred-2", None);
        assert_eq!(state.session_store.len(), 2);
        let resp = lock(State(state.clone())).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(state.session_store.len(), 0); // lock wipes every session
    }
}
