//! Per-request subprocess enclave (IMPLEMENTED — on the hot path).
//!
//! Every signing request runs its decrypt→sign→wipe sequence in a dedicated
//! child process (`onecipher --enclave-child`). The parent (UDS listener,
//! Passkey/session authorization, policy pre-check, audit) never holds
//! decrypted key material; the child receives one [`EnclaveRequest`] over
//! stdin, decrypts, signs, wipes, writes one [`EnclaveResponse`] to stdout,
//! and exits. The child is stateless — spawned per request, no daemon, no
//! unlock step, no cache.
//!
//! ## Parent / child responsibility split
//!
//! | Concern | Parent | Child |
//! |---|---|---|
//! | UDS listen / accept / rate limit | yes | no (no sockets at all) |
//! | Passkey verification + wallet binding | yes | no (challenge state is parent-local) |
//! | Session-key liveness | yes | no |
//! | Stateful policy (budgets, rate limits) | yes (pre-check) | no |
//! | Stateless re-check (shape, chain, size caps) | fail-fast | yes (re-validated, fail-closed) |
//! | Vault decrypt (device-key or passphrase mode) | no | yes |
//! | Signing + address/pubkey derivation | no | yes |
//! | Zeroize of key material | n/a | yes (drop-scope) |
//! | Audit `pending` / `resolved` append | yes | no |
//! | Timeout kill + fail-closed mapping | yes | n/a (is killed) |
//! | Sandbox | inherited daemon profile | fresh full-process profile (Seatbelt on macOS) |
//!
//! ## Credential modes
//!
//! - **Device-key mode** (`credential_hex == None`): the child loads the persistent device key
//!   itself and derives the unlock token (HKDF-SHA256, wallet-bound), which unlocks the wallet's
//!   age scrypt envelope. No secret crosses the pipe. Used by the Key-Agent signing handlers.
//! - **Passphrase mode** (`credential_hex == Some(hex)`): the parent sends the owner passphrase
//!   over the local pipe and the child zeroizes the decoded bytes on drop. Used by the CLI owner
//!   paths and the loopback wallet-rpc server. The pipe is same-uid local, `stderr` is nulled, and
//!   the child inherits only the [`CHILD_ENV_ALLOWLIST`].
//!
//! ## Platform notes
//!
//! - Linux: the child installs the full seccomp BPF domain gate (`apply_sandbox_reported`) —
//!   non-UDS `socket(2)` kills the process (R12d). The child opens no sockets at all.
//! - macOS: Seatbelt is process-wide, so the embedded signing thread must skip it (or it would
//!   sever the daemon's own WSS relay). The enclave child is a *separate process* with no network
//!   needs, so it applies the full Seatbelt deny-network profile — out-of-process isolation stays
//!   in force while the parent keeps its relay. `filter_installed` is therefore `true` for enclave
//!   children on macOS.
//! - Windows: the child applies the process mitigation policies (no dynamic code, no remote image
//!   loads) and suppresses WER crash dumps. Job-object confinement is intentionally NOT applied:
//!   nesting the child in a kill-on- close job would couple its lifetime to handle inheritance
//!   across the pipe, and the timeout-kill in the parent already bounds its lifetime.
//!
//! ## Fallback policy
//!
//! The in-process decrypt path is retained ONLY as an explicit escape hatch:
//! `OC_ENCLAVE=off` (also `0`/`false`/`no`), or the `cfg(test)` default so
//! unit tests stay hermetic without spawning the real binary. Production
//! deployments MUST leave the enclave enabled (the default); running with
//! `OC_ENCLAVE=off` outside tests is unsupported and documented as such.
//!
//! R55/R56-safe: sync `std::process` + `std::io` only. No tokio, no TCP, no
//! new network dependencies (`zeroize` is memory-only).

// This module manipulates the process environment (`remove_var` in
// `scrub_child_env`; `set_var`/`remove_var` in tests, serialized by a mutex).
// The crate root has `#![deny(unsafe_code)]` — relaxed for this module only
// via a module-level inner attribute, mirroring `sandbox.rs` / `hardening.rs`.
// Production env mutation runs single-threaded at child entry, before any
// `thread::spawn`.
#![allow(unsafe_code)]

use std::{
    io::{BufRead, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Enclave pipe-protocol version. Bumped only with an incompatible wire
/// change; both sides fail closed on mismatch (never coerced).
pub const ENCLAVE_PROTOCOL_VERSION: u32 = 1;

/// CLI flag (hidden) that turns `onecipher` into a one-shot enclave child.
pub const ENCLAVE_CHILD_ARG: &str = "--enclave-child";

/// Default per-request enclave timeout (age scrypt decrypt is ~1 s at the
/// production work factor; 30 s is generous headroom for loaded hosts).
/// Overridable with `OC_ENCLAVE_TIMEOUT_SECS` (unparseable values fall back
/// to this default — never to "no timeout").
pub const ENCLAVE_DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum decoded payload size (message / tx / user-op bytes). One JSON line
/// larger than this fails closed before any key material is touched.
pub const ENCLAVE_MAX_PAYLOAD_BYTES: usize = 1024 * 1024;

/// Maximum `extra_json` (EIP-712 typed-data document) size in bytes.
pub const ENCLAVE_MAX_EXTRA_JSON_BYTES: usize = 256 * 1024;

/// Maximum length of small string fields (`request_id`, `wallet_id`,
/// `chain_id`, `op`). Oversized values fail closed.
pub const ENCLAVE_MAX_FIELD_CHARS: usize = 256;

// Operation names carried in `EnclaveRequest.op`.
pub const OP_PING: &str = "ping";
pub const OP_SIGN_MESSAGE: &str = "sign_message";
pub const OP_SIGN_TRANSACTION: &str = "sign_transaction";
pub const OP_SIGN_TYPED_DATA: &str = "sign_typed_data";
pub const OP_SIGN_USER_OP: &str = "sign_user_op";
pub const OP_SIGN_AUTH: &str = "sign_auth";
pub const OP_PUBLIC_KEY: &str = "public_key";

/// Environment variables the enclave child is allowed to inherit.
///
/// Everything else is stripped via `Command::env_clear` so owner secrets
/// (`ONECIPHER_PASSPHRASE` et al., drained burn-after-reading by the CLI) can
/// never leak into the child implicitly — the only secret channel is the
/// explicit `credential_hex` pipe field. `HOME` (and platform equivalents) is
/// required so the child can locate the vault and device-key store.
const CHILD_ENV_ALLOWLIST: &[&str] = &[
    "HOME",
    "USER",
    "LOGNAME",
    "XDG_RUNTIME_DIR",
    "XDG_CONFIG_HOME",
    "XDG_CACHE_HOME",
    "TMPDIR",
    "TEMP",
    "TMP",
    // Strict-hardening opt-in must propagate or parent/child would disagree.
    "OC_STRICT_HARDEN",
    // Windows needs these for the loader and path resolution.
    #[cfg(target_os = "windows")]
    "SYSTEMROOT",
    #[cfg(target_os = "windows")]
    "USERPROFILE",
    #[cfg(target_os = "windows")]
    "HOMEDRIVE",
    #[cfg(target_os = "windows")]
    "HOMEPATH",
    #[cfg(target_os = "windows")]
    "PATH",
];

/// Names that must never be visible inside the child, removed defensively on
/// entry (the parent's `env_clear` already strips them; this is belt-and-
/// braces against embedders that call `run_enclave_child` directly).
const CHILD_ENV_SCRUB: &[&str] = &[
    "ONECIPHER_PASSPHRASE",
    "OC_PASSPHRASE",
    "OWS_PASSPHRASE",
    "OWX_PASSPHRASE",
    "LWS_PASSPHRASE",
    "ONECIPHER_MNEMONIC",
    "OWS_MNEMONIC",
    "LWS_MNEMONIC",
    "ONECIPHER_PRIVATE_KEY",
    "OWS_PRIVATE_KEY",
    "LWS_PRIVATE_KEY",
];

// ---------------------------------------------------------------------------
// Mode
// ---------------------------------------------------------------------------

/// Whether per-request enclave isolation is in force.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnclaveMode {
    /// Spawn a subprocess per signing request (production default).
    Enabled,
    /// Use the in-process decrypt path. Explicit escape hatch only
    /// (`OC_ENCLAVE=off`) or the `cfg(test)` hermetic default.
    Disabled,
}

/// Resolve the enclave mode from the environment.
///
/// `OC_ENCLAVE=0|off|false|no` disables (explicit escape hatch);
/// `OC_ENCLAVE=1|true|yes|on` enables explicitly; unset or any other value
/// enables in production and disables under `cfg(test)` (so unit tests never
/// spawn the real binary). Unknown values fail towards isolation enabled in
/// production builds.
pub fn enclave_mode() -> EnclaveMode {
    match std::env::var("OC_ENCLAVE").map(|v| v.trim().to_ascii_lowercase()) {
        Ok(v) if ["0", "off", "false", "no"].contains(&v.as_str()) => EnclaveMode::Disabled,
        Ok(v) if ["1", "true", "yes", "on"].contains(&v.as_str()) => EnclaveMode::Enabled,
        Ok(_) => {
            if cfg!(test) {
                EnclaveMode::Disabled
            } else {
                EnclaveMode::Enabled
            }
        }
        Err(_) => {
            if cfg!(test) {
                EnclaveMode::Disabled
            } else {
                EnclaveMode::Enabled
            }
        }
    }
}

/// Whether signing requests must go through a subprocess enclave.
pub fn enclave_enabled() -> bool {
    enclave_mode() == EnclaveMode::Enabled
}

/// Per-request enclave timeout: `OC_ENCLAVE_TIMEOUT_SECS` when it parses as a
/// positive integer, otherwise [`ENCLAVE_DEFAULT_TIMEOUT`].
pub fn enclave_timeout() -> Duration {
    std::env::var("OC_ENCLAVE_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|secs| *secs > 0)
        .map_or(ENCLAVE_DEFAULT_TIMEOUT, Duration::from_secs)
}

// ---------------------------------------------------------------------------
// Protocol types
// ---------------------------------------------------------------------------

/// JSON request delivered to the enclave child over stdin (one line).
///
/// Versioned with `oc_version`; `request_id` correlates the parent's audit
/// `pending`/`resolved` entries with the child pid.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnclaveRequest {
    /// Pipe-protocol version — must equal [`ENCLAVE_PROTOCOL_VERSION`].
    pub oc_version: u32,
    /// Parent-generated correlation id, echoed back verbatim.
    pub request_id: String,
    /// Operation: one of the `OP_*` constants.
    pub op: String,
    /// Wallet identifier (all signing ops; empty for `ping`).
    #[serde(default)]
    pub wallet_id: String,
    /// CAIP-2 chain id (signing ops).
    #[serde(default)]
    pub chain_id: String,
    /// Hex payload: message bytes (`sign_message`/`sign_auth`), raw tx hex
    /// (`sign_transaction`), user-op hex (`sign_user_op`).
    #[serde(default)]
    pub payload_hex: String,
    /// EIP-712 typed-data JSON document (`sign_typed_data` only).
    #[serde(default)]
    pub extra_json: String,
    /// HD key index (passphrase mode only).
    #[serde(default)]
    pub index: u32,
    /// Hex-encoded owner passphrase (passphrase mode). `None` selects
    /// device-key mode, in which the child loads the device key itself and no
    /// secret crosses the pipe.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_hex: Option<String>,
    /// Vault-root override. Test isolation only — production requests MUST
    /// leave this as `None` (default `~/.onecipher`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault_dir: Option<String>,
}

impl EnclaveRequest {
    /// Build a signing request. `credential_hex` selects passphrase mode;
    /// pass `None` for device-key mode.
    pub fn sign(
        op: &str,
        wallet_id: &str,
        chain_id: &str,
        payload_hex: &str,
        credential_hex: Option<String>,
    ) -> Self {
        Self {
            oc_version: ENCLAVE_PROTOCOL_VERSION,
            request_id: new_request_id(),
            op: op.to_string(),
            wallet_id: wallet_id.to_string(),
            chain_id: chain_id.to_string(),
            payload_hex: payload_hex.to_string(),
            extra_json: String::new(),
            index: 0,
            credential_hex,
            vault_dir: None,
        }
    }

    /// Build a liveness / framing check (no secrets, no vault access).
    pub fn ping() -> Self {
        Self {
            oc_version: ENCLAVE_PROTOCOL_VERSION,
            request_id: new_request_id(),
            op: OP_PING.to_string(),
            wallet_id: String::new(),
            chain_id: String::new(),
            payload_hex: String::new(),
            extra_json: String::new(),
            index: 0,
            credential_hex: None,
            vault_dir: None,
        }
    }

    /// Stateless validation shared by parent (fail-fast) and child
    /// (fail-closed re-check). Fails on version mismatch, unknown op,
    /// oversized fields, or op-specific shape violations — before any key
    /// material is touched.
    pub fn validate(&self) -> Result<(), String> {
        if self.oc_version != ENCLAVE_PROTOCOL_VERSION {
            return Err(format!(
                "enclave version mismatch: got {}, want {ENCLAVE_PROTOCOL_VERSION}",
                self.oc_version
            ));
        }
        if self.request_id.is_empty() || self.request_id.len() > ENCLAVE_MAX_FIELD_CHARS {
            return Err("enclave request_id missing or oversized".to_string());
        }
        if self.wallet_id.len() > ENCLAVE_MAX_FIELD_CHARS {
            return Err("enclave wallet_id oversized".to_string());
        }
        if self.chain_id.len() > ENCLAVE_MAX_FIELD_CHARS {
            return Err("enclave chain_id oversized".to_string());
        }
        let needs_wallet = self.op != OP_PING;
        if needs_wallet && self.wallet_id.is_empty() {
            return Err(format!("enclave op '{}' requires wallet_id", self.op));
        }
        let needs_chain = matches!(
            self.op.as_str(),
            OP_SIGN_MESSAGE |
                OP_SIGN_TRANSACTION |
                OP_SIGN_TYPED_DATA |
                OP_SIGN_USER_OP |
                OP_SIGN_AUTH |
                OP_PUBLIC_KEY
        );
        if needs_chain && self.chain_id.is_empty() {
            return Err(format!("enclave op '{}' requires chain_id", self.op));
        }
        // Hex payloads are size-checked on decoded bytes; the hex text itself
        // is at most ~2x that plus prefixes.
        if self.payload_hex.len() > ENCLAVE_MAX_PAYLOAD_BYTES * 2 + 8 {
            return Err("enclave payload_hex oversized".to_string());
        }
        if self.extra_json.len() > ENCLAVE_MAX_EXTRA_JSON_BYTES {
            return Err("enclave extra_json oversized".to_string());
        }
        match self.op.as_str() {
            OP_PING | OP_SIGN_MESSAGE | OP_SIGN_TRANSACTION | OP_SIGN_TYPED_DATA |
            OP_SIGN_USER_OP | OP_SIGN_AUTH | OP_PUBLIC_KEY => Ok(()),
            other => Err(format!("unknown enclave op: {other}")),
        }
    }
}

/// JSON response written by the enclave child to stdout (one line).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnclaveResponse {
    /// Pipe-protocol version — always [`ENCLAVE_PROTOCOL_VERSION`].
    pub oc_version: u32,
    /// Echo of the request correlation id.
    pub request_id: String,
    /// Whether the operation succeeded.
    pub ok: bool,
    /// Hex signature (signing success only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_hex: Option<String>,
    /// Hex signed-tx bytes (`sign_transaction` / `sign_user_op` success).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_tx_hex: Option<String>,
    /// Chain-standard account address (message/auth/pubkey ops).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// Hex public key (message/auth/pubkey ops).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key_hex: Option<String>,
    /// Recovery id for secp256k1 signatures (`None` for Ed25519).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_id: Option<u8>,
    /// Child pid, for audit attribution (`request_id → pid → audit`).
    pub pid: u32,
    /// Machine-readable error (failure only; never carries key material).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl EnclaveResponse {
    /// Success response echoing `request_id` from the child `pid`.
    pub fn ok(request_id: &str, pid: u32) -> Self {
        Self {
            oc_version: ENCLAVE_PROTOCOL_VERSION,
            request_id: request_id.to_string(),
            ok: true,
            signature_hex: None,
            signed_tx_hex: None,
            address: None,
            public_key_hex: None,
            recovery_id: None,
            pid,
            error: None,
        }
    }

    /// Failure response (fail-closed; the message must not embed secrets).
    pub fn fail(request_id: &str, pid: u32, error: impl Into<String>) -> Self {
        Self {
            oc_version: ENCLAVE_PROTOCOL_VERSION,
            request_id: request_id.to_string(),
            ok: false,
            signature_hex: None,
            signed_tx_hex: None,
            address: None,
            public_key_hex: None,
            recovery_id: None,
            pid,
            error: Some(error.into()),
        }
    }
}

/// Parent-side enclave call failure. Carries the child pid when the child was
/// successfully spawned (even when it was later killed), so the parent can
/// always attribute the audit entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnclaveError {
    /// Child pid when spawn succeeded; `None` when spawn itself failed.
    pub pid: Option<u32>,
    /// Human/machine-readable cause (coded `E_...` prefix when available).
    pub message: String,
}

impl EnclaveError {
    fn new(pid: Option<u32>, message: impl Into<String>) -> Self {
        Self { pid, message: message.into() }
    }

    /// Borrow the machine-readable cause.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for EnclaveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.pid {
            Some(pid) => write!(f, "enclave(pid {pid}): {}", self.message),
            None => write!(f, "enclave: {}", self.message),
        }
    }
}

impl std::error::Error for EnclaveError {}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Monotonic per-process counter folded into [`new_request_id`].
static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Generate a correlation id: `<pid>-<nanos>-<counter>` in hex. Unique per
/// process without coordination; unpredictable enough that a sibling request
/// cannot claim another's audit entries.
pub fn new_request_id() -> String {
    let counter = REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!("{:x}-{:x}-{:x}", std::process::id(), nanos, counter)
}

/// Resolve the current executable for self-spawn. The enclave child is always
/// the same binary re-executed with [`ENCLAVE_CHILD_ARG`].
pub fn enclave_exe() -> Result<PathBuf, String> {
    std::env::current_exe().map_err(|e| format!("enclave exe: {e}"))
}

/// Environment the child inherits (see [`CHILD_ENV_ALLOWLIST`]).
fn child_env() -> Vec<(String, String)> {
    CHILD_ENV_ALLOWLIST
        .iter()
        .filter_map(|name| {
            std::env::var_os(name)
                .map(|value| ((*name).to_string(), value.to_string_lossy().into_owned()))
        })
        .collect()
}

/// Remove secret-bearing variables from the child environment (defense in
/// depth behind the parent's `env_clear` allowlist).
fn scrub_child_env() {
    for name in CHILD_ENV_SCRUB {
        // SAFETY: the enclave child is single-threaded at entry (this runs
        // before any `thread::spawn`), so no other thread can race on the
        // environment.
        unsafe {
            std::env::remove_var(name);
        }
    }
}

// ---------------------------------------------------------------------------
// Child side
// ---------------------------------------------------------------------------

/// Handle one enclave request with the default vault root (child side).
pub fn handle_enclave_request(req: &EnclaveRequest) -> EnclaveResponse {
    handle_enclave_request_at(req, None)
}

/// Handle one enclave request against an explicit vault root (child side).
///
/// Production callers pass `None` (default `~/.onecipher`); tests pass
/// `Some(tempdir)` so they never touch the real vault.
pub fn handle_enclave_request_at(req: &EnclaveRequest, vault: Option<&Path>) -> EnclaveResponse {
    let pid = std::process::id();
    if let Err(e) = req.validate() {
        return EnclaveResponse::fail(&req.request_id, pid, e);
    }
    if req.op == OP_PING {
        return EnclaveResponse::ok(&req.request_id, pid);
    }
    // The wire `vault_dir` override exists for test isolation; an explicit
    // function parameter (tests) wins over it, production call sites pass
    // `None` for both and land on the default `~/.onecipher` vault.
    let wire_vault: Option<PathBuf> = req.vault_dir.as_deref().map(PathBuf::from);
    let effective_vault: Option<&Path> = vault.or(wire_vault.as_deref());
    match req.op.as_str() {
        OP_SIGN_MESSAGE | OP_SIGN_AUTH => sign_message_child(req, effective_vault, pid),
        OP_SIGN_TRANSACTION | OP_SIGN_USER_OP => sign_transaction_child(req, effective_vault, pid),
        OP_SIGN_TYPED_DATA => sign_typed_data_child(req, effective_vault, pid),
        OP_PUBLIC_KEY => public_key_child(req, effective_vault, pid),
        // `validate` already rejects unknown ops; this arm is unreachable but
        // stays fail-closed rather than panicking.
        _ => EnclaveResponse::fail(&req.request_id, pid, format!("unknown enclave op: {}", req.op)),
    }
}

/// Decrypted chain key plus its signer, both drop-scoped inside the child.
struct ChildKey {
    key: oc_signer::SecretBytes,
    signer: Box<dyn oc_signer::ChainSigner>,
}

/// Load the chain signing key inside the child (decrypt→borrow scope).
///
/// Device-key mode (`credential_hex == None`): load the persistent device key
/// and derive the unlock token (HKDF-SHA256, wallet-bound — the same
/// derivation the in-process path uses, so parent and child never drift).
/// Passphrase mode: decrypt directly with the piped passphrase, which is
/// zeroized on drop. Returns coded (`E_...`) errors matching the in-process
/// path so the parent maps them without re-interpretation.
fn load_child_key(req: &EnclaveRequest, vault: Option<&Path>) -> Result<ChildKey, String> {
    let chain = oc_core::parse_chain(&req.chain_id).map_err(|e| {
        crate::handler::coded(crate::handler::err_code::PARAM, format!("invalid chain: {e}"))
    })?;
    let chain_type = chain.chain_type;
    if let Some(cred_hex) = req.credential_hex.as_deref() {
        let raw = hex::decode(cred_hex.trim()).map_err(|e| {
            crate::handler::coded(
                crate::handler::err_code::PARAM,
                format!("invalid credential hex: {e}"),
            )
        })?;
        if raw.len() > 1024 {
            return Err(crate::handler::coded(
                crate::handler::err_code::PARAM,
                "credential oversized",
            ));
        }
        let passphrase: Zeroizing<Vec<u8>> = Zeroizing::new(raw);
        let key = oc_wallet::ops::decrypt_signing_key(
            &req.wallet_id,
            chain_type,
            &passphrase,
            Some(req.index),
            vault,
        )
        .map_err(|e| {
            crate::handler::coded(
                crate::handler::err_code::DECRYPT,
                format!("wallet decrypt failed: {e}"),
            )
        })?;
        // `passphrase` is zeroized here on drop.
        let signer = oc_signer::signer_for_chain(chain_type);
        return Ok(ChildKey { key, signer });
    }
    // Device-key mode: same derivation the in-process path uses.
    let (key, signer) = crate::handler::load_chain_key_at(&req.wallet_id, &req.chain_id, vault)?;
    Ok(ChildKey { key, signer })
}

/// Decode `payload_hex`, enforcing [`ENCLAVE_MAX_PAYLOAD_BYTES`].
fn decode_payload(req: &EnclaveRequest) -> Result<Vec<u8>, String> {
    let text = req.payload_hex.strip_prefix("0x").unwrap_or(&req.payload_hex);
    let bytes = hex::decode(text.trim()).map_err(|e| {
        crate::handler::coded(crate::handler::err_code::PARAM, format!("invalid payload hex: {e}"))
    })?;
    if bytes.len() > ENCLAVE_MAX_PAYLOAD_BYTES {
        return Err(crate::handler::coded(
            crate::handler::err_code::PARAM,
            "payload exceeds enclave limit",
        ));
    }
    if bytes.is_empty() {
        return Err(crate::handler::coded(crate::handler::err_code::PARAM, "empty payload"));
    }
    Ok(bytes)
}

/// `sign_message` / `sign_auth` child implementation: decrypt → sign →
/// address + pubkey derivation. Only signature/address/pubkey leave the
/// child; the key is zeroized on scope exit.
fn sign_message_child(req: &EnclaveRequest, vault: Option<&Path>, pid: u32) -> EnclaveResponse {
    let message = match decode_payload(req) {
        Ok(m) => m,
        Err(e) => return EnclaveResponse::fail(&req.request_id, pid, e),
    };
    let loaded = match load_child_key(req, vault) {
        Ok(l) => l,
        Err(e) => return EnclaveResponse::fail(&req.request_id, pid, e),
    };
    let output = match loaded.signer.sign_message(loaded.key.expose(), &message) {
        Ok(o) => o,
        Err(e) => {
            return EnclaveResponse::fail(
                &req.request_id,
                pid,
                crate::handler::coded(
                    crate::handler::err_code::INTERNAL,
                    format!("signing failed: {e}"),
                ),
            );
        }
    };
    let address = match loaded.signer.derive_address(loaded.key.expose()) {
        Ok(a) => a,
        Err(e) => {
            return EnclaveResponse::fail(
                &req.request_id,
                pid,
                crate::handler::coded(
                    crate::handler::err_code::INTERNAL,
                    format!("address derivation: {e}"),
                ),
            );
        }
    };
    let public_key_hex = output
        .public_key
        .clone()
        .or_else(|| crate::handler::derive_public_key(loaded.signer.curve(), loaded.key.expose()))
        .map(hex::encode);
    let mut resp = EnclaveResponse::ok(&req.request_id, pid);
    resp.signature_hex = Some(hex::encode(&output.signature));
    resp.recovery_id = output.recovery_id;
    resp.address = Some(address);
    resp.public_key_hex = public_key_hex;
    resp
}

/// `sign_transaction` / `sign_user_op` child implementation: decrypt →
/// extract signable → sign → encode. Returns signature + signed-tx hex.
fn sign_transaction_child(req: &EnclaveRequest, vault: Option<&Path>, pid: u32) -> EnclaveResponse {
    let tx_bytes = match decode_payload(req) {
        Ok(t) => t,
        Err(e) => return EnclaveResponse::fail(&req.request_id, pid, e),
    };
    let loaded = match load_child_key(req, vault) {
        Ok(l) => l,
        Err(e) => return EnclaveResponse::fail(&req.request_id, pid, e),
    };
    let signable = match loaded.signer.extract_signable_bytes(&tx_bytes) {
        Ok(b) => b.to_vec(),
        Err(e) => {
            return EnclaveResponse::fail(
                &req.request_id,
                pid,
                crate::handler::coded(
                    crate::handler::err_code::PARAM,
                    format!("extract signable failed: {e}"),
                ),
            );
        }
    };
    let output = match loaded.signer.sign_transaction(loaded.key.expose(), &signable) {
        Ok(o) => o,
        Err(e) => {
            return EnclaveResponse::fail(
                &req.request_id,
                pid,
                crate::handler::coded(
                    crate::handler::err_code::INTERNAL,
                    format!("signing failed: {e}"),
                ),
            );
        }
    };
    let signed_tx = match loaded.signer.encode_signed_transaction(&tx_bytes, &output) {
        Ok(s) => s,
        Err(e) => {
            return EnclaveResponse::fail(
                &req.request_id,
                pid,
                crate::handler::coded(
                    crate::handler::err_code::INTERNAL,
                    format!("encode signed tx failed: {e}"),
                ),
            );
        }
    };
    let mut resp = EnclaveResponse::ok(&req.request_id, pid);
    resp.signature_hex = Some(hex::encode(&output.signature));
    resp.recovery_id = output.recovery_id;
    resp.signed_tx_hex = Some(hex::encode(&signed_tx));
    resp
}

/// `sign_typed_data` child implementation (EVM-only, mirroring the
/// in-process path).
fn sign_typed_data_child(req: &EnclaveRequest, vault: Option<&Path>, pid: u32) -> EnclaveResponse {
    if req.extra_json.is_empty() {
        return EnclaveResponse::fail(
            &req.request_id,
            pid,
            crate::handler::coded(crate::handler::err_code::PARAM, "missing typed-data JSON"),
        );
    }
    if serde_json::from_str::<serde_json::Value>(&req.extra_json).is_err() {
        return EnclaveResponse::fail(
            &req.request_id,
            pid,
            crate::handler::coded(crate::handler::err_code::PARAM, "invalid typed-data JSON"),
        );
    }
    let chain = match oc_core::parse_chain(&req.chain_id) {
        Ok(c) => c,
        Err(e) => {
            return EnclaveResponse::fail(
                &req.request_id,
                pid,
                crate::handler::coded(
                    crate::handler::err_code::PARAM,
                    format!("invalid chain: {e}"),
                ),
            );
        }
    };
    if chain.chain_type != oc_core::ChainType::Evm {
        return EnclaveResponse::fail(
            &req.request_id,
            pid,
            crate::handler::coded(
                crate::handler::err_code::PARAM,
                "typed-data signing is EVM-only",
            ),
        );
    }
    let loaded = match load_child_key(req, vault) {
        Ok(l) => l,
        Err(e) => return EnclaveResponse::fail(&req.request_id, pid, e),
    };
    let signer = oc_signer::chains::EvmSigner;
    let output = match signer.sign_typed_data(loaded.key.expose(), &req.extra_json) {
        Ok(o) => o,
        Err(e) => {
            return EnclaveResponse::fail(
                &req.request_id,
                pid,
                crate::handler::coded(
                    crate::handler::err_code::INTERNAL,
                    format!("signing failed: {e}"),
                ),
            );
        }
    };
    let mut resp = EnclaveResponse::ok(&req.request_id, pid);
    resp.signature_hex = Some(hex::encode(&output.signature));
    resp.recovery_id = output.recovery_id;
    resp
}

/// `public_key` child implementation: decrypt → derive address + pubkey, with
/// no signing side effect. Used by read-only key-listing surfaces so they
/// never hold key material either.
fn public_key_child(req: &EnclaveRequest, vault: Option<&Path>, pid: u32) -> EnclaveResponse {
    let loaded = match load_child_key(req, vault) {
        Ok(l) => l,
        Err(e) => return EnclaveResponse::fail(&req.request_id, pid, e),
    };
    let address = match loaded.signer.derive_address(loaded.key.expose()) {
        Ok(a) => a,
        Err(e) => {
            return EnclaveResponse::fail(
                &req.request_id,
                pid,
                crate::handler::coded(
                    crate::handler::err_code::INTERNAL,
                    format!("address derivation: {e}"),
                ),
            );
        }
    };
    let public_key =
        match crate::handler::derive_public_key(loaded.signer.curve(), loaded.key.expose()) {
            Some(k) => k,
            None => {
                return EnclaveResponse::fail(
                    &req.request_id,
                    pid,
                    crate::handler::coded(
                        crate::handler::err_code::INTERNAL,
                        "public key derivation failed",
                    ),
                );
            }
        };
    let mut resp = EnclaveResponse::ok(&req.request_id, pid);
    resp.address = Some(address);
    resp.public_key_hex = Some(hex::encode(&public_key));
    resp
}

/// Run the enclave child: confine, read one JSON line from stdin, handle,
/// write one JSON line to stdout. Used by the `onecipher --enclave-child`
/// entry point. Exits non-zero (via `Err`) on sandbox failure, malformed
/// input, or output errors — the parent treats all of these as fail-closed.
pub fn run_enclave_child() -> Result<(), String> {
    scrub_child_env();
    // Memory hardening first (mlockall before secrets exist), fail-closed
    // under OC_STRICT_HARDEN.
    let status = crate::hardening::apply_hardening();
    status
        .check_strict(crate::hardening::strict_mode_enabled())
        .map_err(|e| format!("enclave hardening: {e}"))?;
    // Fresh process, no network needs: install the FULL profile. On macOS
    // this is the Seatbelt deny-network profile the embedded signing thread
    // must skip — the child has no WSS relay to preserve, so out-of-process
    // isolation stays in force there too.
    crate::sandbox::apply_sandbox_reported().map_err(|e| format!("enclave sandbox: {e}"))?;

    let stdin = std::io::stdin();
    let mut line = String::new();
    stdin.lock().read_line(&mut line).map_err(|e| format!("enclave stdin: {e}"))?;
    if line.trim().is_empty() {
        return Err("enclave request: empty input".to_string());
    }
    if line.len() > (ENCLAVE_MAX_PAYLOAD_BYTES * 2 + ENCLAVE_MAX_EXTRA_JSON_BYTES + 4096) {
        return Err("enclave request: input oversized".to_string());
    }
    let req: EnclaveRequest =
        serde_json::from_str(line.trim()).map_err(|e| format!("enclave request JSON: {e}"))?;
    let resp = handle_enclave_request(&req);
    let out = serde_json::to_string(&resp).map_err(|e| format!("enclave response JSON: {e}"))?;
    let mut stdout = std::io::stdout();
    stdout.write_all(format!("{out}\n").as_bytes()).map_err(|e| format!("enclave stdout: {e}"))?;
    stdout.flush().map_err(|e| format!("enclave flush: {e}"))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Parent side
// ---------------------------------------------------------------------------

/// Spawn a per-request enclave child and round-trip one request.
///
/// The child is re-executed from `exe` with [`ENCLAVE_CHILD_ARG`], inherits
/// only [`CHILD_ENV_ALLOWLIST`], gets `stdin`/`stdout` pipes (`stderr` is
/// nulled), and is killed on timeout. Fails closed on spawn failure, timeout,
/// non-zero exit, version mismatch, `request_id` mismatch, malformed stdout,
/// or `ok == false` (surfaced as [`EnclaveError`] carrying the child pid when
/// spawn succeeded, so the parent can attribute the audit entry). The parent
/// never sees key material — only the JSON request/response cross the pipe.
pub fn spawn_enclave_child(
    exe: &Path,
    req: &EnclaveRequest,
    timeout: Duration,
) -> Result<EnclaveResponse, EnclaveError> {
    if let Err(e) = req.validate() {
        return Err(EnclaveError::new(None, format!("enclave request invalid: {e}")));
    }
    let mut cmd = Command::new(exe);
    cmd.arg(ENCLAVE_CHILD_ARG)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .env_clear();
    for (key, value) in child_env() {
        cmd.env(key, value);
    }
    // NOTE: no `kill_on_drop` — this toolchain's `std` does not provide it.
    // Timeout-kill plus the bounded reap in `wait_with_timeout` (the sole
    // owner of the `Child`) already bounds every child lifetime.
    for (key, value) in child_env() {
        cmd.env(key, value);
    }
    let mut child =
        cmd.spawn().map_err(|e| EnclaveError::new(None, format!("enclave spawn: {e}")))?;
    let pid = Some(child.id());
    let input = serde_json::to_string(req)
        .map_err(|e| EnclaveError::new(pid, format!("enclave request JSON: {e}")))?;
    if let Some(mut stdin) = child.stdin.take() {
        // A write failure here means the child already exited (bad image,
        // immediate sandbox kill) — fall through to `wait` so the exit
        // status, not the EPIPE, is reported.
        let _ = stdin.write_all(format!("{input}\n").as_bytes());
    }
    let output = wait_with_timeout(child, timeout).map_err(|e| EnclaveError::new(pid, e))?;
    if !output.status.success() {
        return Err(EnclaveError::new(pid, format!("enclave child exited with {}", output.status)));
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|e| EnclaveError::new(pid, format!("enclave stdout UTF8: {e}")))?;
    let resp: EnclaveResponse = serde_json::from_str(stdout.trim())
        .map_err(|e| EnclaveError::new(pid, format!("enclave response JSON: {e}")))?;
    if resp.oc_version != ENCLAVE_PROTOCOL_VERSION {
        return Err(EnclaveError::new(
            pid,
            format!(
                "enclave version mismatch: got {}, want {ENCLAVE_PROTOCOL_VERSION}",
                resp.oc_version
            ),
        ));
    }
    if resp.request_id != req.request_id {
        return Err(EnclaveError::new(pid, "enclave request_id mismatch"));
    }
    if resp.ok {
        Ok(resp)
    } else {
        Err(EnclaveError::new(pid, resp.error.unwrap_or_else(|| "enclave failed".to_string())))
    }
}

/// Wait for a child with a timeout (poll loop — sync, no async runtime).
///
/// On timeout the child is killed and reaped on a bounded grace window, then
/// a timeout error is returned. The bounded reap avoids zombies without
/// blocking the parent indefinitely on an unkillable child.
fn wait_with_timeout(
    mut child: std::process::Child,
    timeout: Duration,
) -> Result<std::process::Output, String> {
    let start = std::time::Instant::now();
    loop {
        if child.try_wait().map_err(|e| format!("enclave wait: {e}"))?.is_some() {
            return child.wait_with_output().map_err(|e| format!("enclave output: {e}"));
        }
        if start.elapsed() > timeout {
            let _ = child.kill();
            // Bounded reap: a SIGKILLed child normally exits within
            // milliseconds; never block the parent longer than ~2 s here.
            let reap_start = std::time::Instant::now();
            loop {
                match child.try_wait() {
                    Ok(Some(_)) => break,
                    Ok(None) => {
                        if reap_start.elapsed() > Duration::from_secs(2) {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(e) => return Err(format!("enclave reap: {e}")),
                }
            }
            return Err(format!("enclave timeout after {}s", timeout.as_secs()));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serialize env-mutating tests: `OC_ENCLAVE*` is process-global.
    static ENV_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn test_req(op: &str) -> EnclaveRequest {
        EnclaveRequest {
            oc_version: ENCLAVE_PROTOCOL_VERSION,
            request_id: "test-req-1".to_string(),
            op: op.to_string(),
            wallet_id: "w1".to_string(),
            chain_id: "eip155:1".to_string(),
            payload_hex: "deadbeef".to_string(),
            extra_json: String::new(),
            index: 0,
            credential_hex: None,
            vault_dir: None,
        }
    }

    #[test]
    fn ping_round_trips_through_handler() {
        let mut req = test_req(OP_PING);
        req.wallet_id.clear();
        req.chain_id.clear();
        req.payload_hex.clear();
        let resp = handle_enclave_request(&req);
        assert!(resp.ok);
        assert!(resp.error.is_none());
        assert_eq!(resp.oc_version, ENCLAVE_PROTOCOL_VERSION);
        assert_eq!(resp.request_id, req.request_id);
    }

    #[test]
    fn version_mismatch_fails_closed() {
        let mut req = test_req(OP_PING);
        req.oc_version = ENCLAVE_PROTOCOL_VERSION + 1;
        req.wallet_id.clear();
        let resp = handle_enclave_request(&req);
        assert!(!resp.ok);
        assert!(resp.error.as_deref().unwrap_or("").contains("version mismatch"));
    }

    #[test]
    fn unknown_op_fails_closed() {
        let mut req = test_req("decrypt");
        req.payload_hex.clear();
        let resp = handle_enclave_request(&req);
        assert!(!resp.ok);
    }

    #[test]
    fn signing_without_wallet_fails_closed() {
        let mut req = test_req(OP_SIGN_MESSAGE);
        req.wallet_id.clear();
        let resp = handle_enclave_request(&req);
        assert!(!resp.ok);
        assert!(resp.error.as_deref().unwrap_or("").contains("wallet_id"));
    }

    #[test]
    fn oversized_payload_fails_closed_before_vault() {
        let mut req = test_req(OP_SIGN_MESSAGE);
        req.payload_hex = "ab".repeat(ENCLAVE_MAX_PAYLOAD_BYTES + 64);
        let resp = handle_enclave_request(&req);
        assert!(!resp.ok);
        assert!(resp.error.as_deref().unwrap_or("").contains("oversized"));
    }

    #[test]
    fn typed_data_requires_json_body() {
        let mut req = test_req(OP_SIGN_TYPED_DATA);
        req.payload_hex.clear();
        let resp = handle_enclave_request(&req);
        assert!(!resp.ok);
        assert!(resp.error.as_deref().unwrap_or("").contains("typed-data"));
    }

    #[test]
    fn typed_data_rejects_non_evm_chain() {
        let mut req = test_req(OP_SIGN_TYPED_DATA);
        req.chain_id = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp".to_string();
        req.payload_hex.clear();
        req.extra_json = "{}".to_string();
        let resp = handle_enclave_request(&req);
        assert!(!resp.ok);
        assert!(resp.error.as_deref().unwrap_or("").contains("EVM-only"));
    }

    #[test]
    fn request_response_json_shape_is_stable() {
        let req = EnclaveRequest::sign(OP_SIGN_MESSAGE, "w1", "eip155:1", "deadbeef", None);
        assert_eq!(req.oc_version, ENCLAVE_PROTOCOL_VERSION);
        assert_ne!(req.request_id, "");
        let json = serde_json::to_string(&req).expect("req json");
        let back: EnclaveRequest = serde_json::from_str(&json).expect("req round-trip");
        assert_eq!(back.op, OP_SIGN_MESSAGE);
        assert_eq!(back.oc_version, ENCLAVE_PROTOCOL_VERSION);
        // New optional fields omit cleanly so older log scrapers keep parsing.
        assert!(!json.contains("vault_dir"));
    }

    #[test]
    fn request_ids_are_unique() {
        let a = new_request_id();
        let b = new_request_id();
        assert_ne!(a, b);
    }

    #[test]
    fn spawn_fails_closed_on_missing_exe() {
        let req = EnclaveRequest::ping();
        let err = spawn_enclave_child(
            Path::new("/nonexistent/onecipher-test-binary"),
            &req,
            Duration::from_secs(5),
        )
        .expect_err("missing exe must fail");
        assert!(err.pid.is_none(), "spawn failure carries no pid");
        assert!(err.message().contains("spawn"));
    }

    #[test]
    fn spawn_rejects_invalid_request_without_spawning() {
        let mut req = EnclaveRequest::ping();
        req.oc_version += 1;
        let err = spawn_enclave_child(
            Path::new("/nonexistent/never-spawned"),
            &req,
            Duration::from_secs(5),
        )
        .expect_err("invalid request must fail pre-spawn");
        assert!(err.pid.is_none());
        assert!(err.message().contains("invalid"));
    }

    #[test]
    fn wait_with_timeout_kills_a_hanging_child() {
        // `sleep` ignores stdin and produces no output: the bounded wait must
        // kill it instead of blocking.
        let child = Command::new("sleep")
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("sleep must spawn");
        let err = wait_with_timeout(child, Duration::from_millis(200)).expect_err("must time out");
        assert!(err.contains("timeout"), "unexpected error: {err}");
    }

    #[test]
    fn wait_with_timeout_reaps_a_fast_child() {
        let child = Command::new("true")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("true must spawn");
        let out = wait_with_timeout(child, Duration::from_secs(5)).expect("true must exit fast");
        assert!(out.status.success());
    }

    #[test]
    fn enclave_mode_parses_documented_values() {
        let _guard = ENV_GUARD.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let original = std::env::var("OC_ENCLAVE").ok();
        for disabled in ["0", "off", "OFF", " false ", "no", "NO"] {
            // SAFETY: serialized by ENV_GUARD; restored before release.
            unsafe { std::env::set_var("OC_ENCLAVE", disabled) };
            assert_eq!(enclave_mode(), EnclaveMode::Disabled, "{disabled:?} must disable");
        }
        for enabled in ["1", "true", "TRUE", " yes ", "on", "ON"] {
            // SAFETY: see above.
            unsafe { std::env::set_var("OC_ENCLAVE", enabled) };
            assert_eq!(enclave_mode(), EnclaveMode::Enabled, "{enabled:?} must enable");
        }
        // SAFETY: see above.
        unsafe { std::env::remove_var("OC_ENCLAVE") };
        // Unset: production default ON, cfg(test) hermetic default OFF.
        assert_eq!(enclave_mode(), EnclaveMode::Disabled, "cfg(test) default must be hermetic");
        match original {
            // SAFETY: see above.
            Some(v) => unsafe { std::env::set_var("OC_ENCLAVE", v) },
            // SAFETY: see above.
            None => unsafe { std::env::remove_var("OC_ENCLAVE") },
        }
    }

    #[test]
    fn enclave_timeout_falls_back_on_garbage() {
        let _guard = ENV_GUARD.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let original = std::env::var("OC_ENCLAVE_TIMEOUT_SECS").ok();
        // SAFETY: serialized by ENV_GUARD; restored before release.
        unsafe { std::env::set_var("OC_ENCLAVE_TIMEOUT_SECS", "45") };
        assert_eq!(enclave_timeout(), Duration::from_secs(45));
        for bad in ["0", "-3", "soon", ""] {
            // SAFETY: see above.
            unsafe { std::env::set_var("OC_ENCLAVE_TIMEOUT_SECS", bad) };
            assert_eq!(enclave_timeout(), ENCLAVE_DEFAULT_TIMEOUT, "{bad:?} must fall back");
        }
        // SAFETY: see above.
        unsafe { std::env::remove_var("OC_ENCLAVE_TIMEOUT_SECS") };
        assert_eq!(enclave_timeout(), ENCLAVE_DEFAULT_TIMEOUT);
        match original {
            // SAFETY: see above.
            Some(v) => unsafe { std::env::set_var("OC_ENCLAVE_TIMEOUT_SECS", v) },
            // SAFETY: see above.
            None => unsafe { std::env::remove_var("OC_ENCLAVE_TIMEOUT_SECS") },
        }
    }

    /// Build a passphrase-mode wallet in a temp vault for child-side tests.
    fn temp_passphrase_wallet(vault: &Path, wallet_id: &str, passphrase: &[u8]) {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let envelope = oc_vault::crypto::encrypt_with_passphrase(phrase.as_bytes(), passphrase)
            .expect("envelope encrypt");
        let wallet = oc_core::EncryptedWallet::new(
            wallet_id.to_string(),
            "enclave-test-wallet".to_string(),
            Vec::new(),
            serde_json::to_value(&envelope).expect("envelope json"),
            oc_core::KeyType::Mnemonic,
        );
        oc_vault::save_encrypted_wallet(&wallet, Some(vault)).expect("save wallet");
    }

    #[test]
    fn child_sign_message_decrypts_signs_and_returns_address() {
        let dir = tempfile::tempdir().expect("tempdir");
        let wallet_id = "enclave-child-msg";
        let passphrase = b"child-test-passphrase";
        temp_passphrase_wallet(dir.path(), wallet_id, passphrase);
        let req = EnclaveRequest {
            oc_version: ENCLAVE_PROTOCOL_VERSION,
            request_id: "child-msg-1".to_string(),
            op: OP_SIGN_MESSAGE.to_string(),
            wallet_id: wallet_id.to_string(),
            chain_id: "eip155:1".to_string(),
            payload_hex: hex::encode(b"hello enclave"),
            extra_json: String::new(),
            index: 0,
            credential_hex: Some(hex::encode(passphrase)),
            vault_dir: None,
        };
        let resp = handle_enclave_request_at(&req, Some(dir.path()));
        assert!(resp.ok, "child sign failed: {:?}", resp.error);
        assert_eq!(resp.request_id, req.request_id);
        let sig = hex::decode(resp.signature_hex.expect("signature")).expect("sig hex");
        assert_eq!(sig.len(), 65, "EVM signature must be 65 bytes");
        let address = resp.address.expect("address");
        assert!(address.starts_with("0x"), "unexpected address: {address}");
        assert!(resp.public_key_hex.expect("pubkey").len() == 66, "compressed secp256k1");
    }

    #[test]
    fn child_sign_message_wrong_passphrase_fails_closed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let wallet_id = "enclave-child-bad-pp";
        temp_passphrase_wallet(dir.path(), wallet_id, b"correct-passphrase");
        let req = EnclaveRequest {
            oc_version: ENCLAVE_PROTOCOL_VERSION,
            request_id: "child-msg-bad".to_string(),
            op: OP_SIGN_MESSAGE.to_string(),
            wallet_id: wallet_id.to_string(),
            chain_id: "eip155:1".to_string(),
            payload_hex: hex::encode(b"hello"),
            extra_json: String::new(),
            index: 0,
            credential_hex: Some(hex::encode(b"wrong-passphrase")),
            vault_dir: None,
        };
        let resp = handle_enclave_request_at(&req, Some(dir.path()));
        assert!(!resp.ok);
        assert!(resp.error.as_deref().unwrap_or("").contains("E_DECRYPT"));
    }

    #[test]
    fn child_public_key_derives_without_signing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let wallet_id = "enclave-child-pubkey";
        let passphrase = b"pubkey-passphrase";
        temp_passphrase_wallet(dir.path(), wallet_id, passphrase);
        for chain_id in ["eip155:1", "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"] {
            let req = EnclaveRequest {
                oc_version: ENCLAVE_PROTOCOL_VERSION,
                request_id: format!("child-pubkey-{chain_id}"),
                op: OP_PUBLIC_KEY.to_string(),
                wallet_id: wallet_id.to_string(),
                chain_id: chain_id.to_string(),
                payload_hex: String::new(),
                extra_json: String::new(),
                index: 0,
                credential_hex: Some(hex::encode(passphrase)),
                vault_dir: None,
            };
            let resp = handle_enclave_request_at(&req, Some(dir.path()));
            assert!(resp.ok, "pubkey failed for {chain_id}: {:?}", resp.error);
            assert!(resp.signature_hex.is_none(), "pubkey op must not sign");
            assert!(resp.public_key_hex.is_some(), "pubkey missing for {chain_id}");
        }
    }
}
