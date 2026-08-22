//! Authentication module: bootstrap token, WebAuthn, session management,
//! and the loopback CLI capability token.

pub mod bootstrap;
pub mod cli_token;
pub mod session;
pub mod webauthn;

pub use bootstrap::BootstrapToken;
pub use cli_token::CLI_TOKEN_HEADER;
pub use session::{AuthSession, SessionStore};
pub use webauthn::{StoredCredential, WebAuthnManager};
