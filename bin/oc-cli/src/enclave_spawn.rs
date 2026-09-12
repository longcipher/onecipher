//! Parent-side enclave spawning for CLI owner paths and the loopback
//! wallet-rpc server.
//!
//! The Key-Agent handlers route through the enclave internally; the surfaces
//! in this binary (one-shot `sign` commands, `wallet-rpc` handlers, the
//! wallet-rpc intent signer) hold owner passphrases instead of device keys, so
//! they build passphrase-mode [`oc_keyagent::enclave::EnclaveRequest`]s here
//! and spawn the same `--enclave-child` entry point. Unit tests (`cfg(test)`)
//! take the in-process fallback so they stay hermetic without spawning the
//! real binary.

use oc_keyagent::enclave::{EnclaveRequest, EnclaveResponse};

/// Whether CLI/wallet-rpc signing must go through a subprocess enclave.
///
/// Hermetic under `cfg(test)` (in-process fallback); otherwise follows
/// `OC_ENCLAVE` (default on, `=off` is the explicit escape hatch).
pub(crate) fn signing_enclave_enabled() -> bool {
    if cfg!(test) {
        return false;
    }
    oc_keyagent::enclave::enclave_enabled()
}

/// Hex-encode an owner passphrase for the `credential_hex` pipe field.
pub(crate) fn passphrase_credential_hex(passphrase: &str) -> String {
    hex::encode(passphrase.as_bytes())
}

/// Start a fresh versioned request for `op` (caller fills the payload).
pub(crate) fn fresh_request(op: &str, wallet_id: &str, chain_id: &str) -> EnclaveRequest {
    EnclaveRequest {
        oc_version: oc_keyagent::enclave::ENCLAVE_PROTOCOL_VERSION,
        request_id: oc_keyagent::enclave::new_request_id(),
        op: op.to_string(),
        wallet_id: wallet_id.to_string(),
        chain_id: chain_id.to_string(),
        payload_hex: String::new(),
        extra_json: String::new(),
        index: 0,
        credential_hex: None,
        vault_dir: None,
    }
}

/// Spawn the enclave child (self re-executed) for one request.
///
/// Fails closed: spawn/timeout/child failures surface as `Err` carrying the
/// child pid when spawn succeeded. Child-reported errors already carry
/// `E_...` codes and pass through verbatim; parent-side failures are coded
/// `E_INTERNAL`.
pub(crate) fn spawn_enclave(req: &EnclaveRequest) -> Result<EnclaveResponse, String> {
    let exe = std::env::current_exe().map_err(|e| format!("E_INTERNAL: enclave exe: {e}"))?;
    oc_keyagent::enclave::spawn_enclave_child(&exe, req, oc_keyagent::enclave::enclave_timeout())
        .map_err(|e| {
            let rendered = e.to_string();
            if e.message().starts_with("E_") { rendered } else { format!("E_INTERNAL: {rendered}") }
        })
}

/// Extract a required hex field from an enclave response (fail-closed).
pub(crate) fn response_hex(field: Option<&String>, name: &str) -> Result<Vec<u8>, String> {
    match field {
        Some(h) => hex::decode(h).map_err(|e| format!("E_INTERNAL: enclave bad {name} hex: {e}")),
        None => Err(format!("E_INTERNAL: enclave omitted {name}")),
    }
}

/// Map enclave failures to client-facing wallet-rpc errors.
///
/// L-07: filesystem paths and vault internals stay in the log, never on the
/// loopback wire. Caller input errors (`E_PARAM`) are safe to echo; everything
/// else becomes a generic `internal error`.
pub(crate) fn sanitize_enclave_error(e: &str) -> String {
    if e.starts_with("E_PARAM") {
        e.to_string()
    } else {
        tracing::warn!("wallet-rpc: enclave signing failed: {e}");
        "internal error".to_string()
    }
}
