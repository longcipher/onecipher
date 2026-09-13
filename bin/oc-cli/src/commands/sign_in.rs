//! CAIP-122 Sign-In with X (`onecipher sign-in`).
//!
//! Local message tooling: build (`message`), inspect (`parse`), verify
//! (`verify`) and mint nonces (`nonce`). Signing itself stays in the wallet
//! (Key-Agent `SignSiwx` via the daemon); verification of EOAs is pure
//! crypto, while contract / counterfactual accounts (EIP-1271 / ERC-6492)
//! need `--rpc-url`.

use oc_siwx::{AuthOpts, SiwxMessage};
use serde_json::json;

use crate::CliError;

/// Read `--message` or `--message-file` (exactly one required).
///
/// Files conventionally end with a newline but the CAIP-122 parser rejects
/// trailing LF (callers trim it): strip trailing CR/LF from file input.
/// `--message` is used verbatim.
fn load_message(message: Option<&str>, message_file: Option<&str>) -> Result<String, CliError> {
    match (message, message_file) {
        (Some(m), None) => Ok(m.to_string()),
        (None, Some(path)) => std::fs::read_to_string(path)
            .map(|c| c.trim_end_matches(['\r', '\n']).to_string())
            .map_err(|e| CliError::InvalidArgs(format!("cannot read message file '{path}': {e}"))),
        (Some(_), Some(_)) => {
            Err(CliError::InvalidArgs("--message and --message-file are mutually exclusive".into()))
        }
        (None, None) => {
            Err(CliError::InvalidArgs("one of --message or --message-file is required".into()))
        }
    }
}

/// Split a CAIP-2 chain id into `(namespace, reference)`.
fn split_chain(chain: &str) -> Result<(&str, &str), CliError> {
    chain.split_once(':').ok_or_else(|| {
        CliError::InvalidArgs(format!("chain '{chain}' is not a CAIP-2 chain id (ns:reference)"))
    })
}

/// Pick the chain label + verifier namespace for a CAIP-2 chain id.
fn chain_label(namespace: &str) -> Result<&'static str, CliError> {
    match namespace {
        "eip155" => Ok(oc_siwx::EVM_CHAIN_NAME),
        "solana" => Ok(oc_siwx::SOLANA_CHAIN_NAME),
        other => Err(CliError::InvalidArgs(format!("unsupported sign-in namespace: {other}"))),
    }
}

/// Decode a signature: `0x`-prefixed hex always; base58 fallback for Solana.
fn decode_signature(signature: &str, namespace: &str) -> Result<Vec<u8>, CliError> {
    let hex_part = signature.strip_prefix("0x").unwrap_or(signature);
    if let Ok(bytes) = hex::decode(hex_part) {
        return Ok(bytes);
    }
    if namespace == "solana" {
        return bs58::decode(signature)
            .into_vec()
            .map_err(|e| CliError::InvalidArgs(format!("invalid signature (hex or base58): {e}")));
    }
    Err(CliError::InvalidArgs("invalid signature hex (0x prefix optional)".into()))
}

/// Entry point for `onecipher sign-in message`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_message(
    chain: &str,
    domain: &str,
    address: &str,
    uri: &str,
    statement: Option<&str>,
    nonce: Option<&str>,
    issued_at: Option<&str>,
    expiration_time: Option<&str>,
    not_before: Option<&str>,
    request_id: Option<&str>,
    resources: &[String],
    json: bool,
) -> Result<(), CliError> {
    let (namespace, reference) = split_chain(chain)?;
    let label = chain_label(namespace)?;
    // Chain-id shape is enforced by the namespace verifier up front so a
    // malformed reference cannot produce a signed-looking message.
    match namespace {
        "eip155" => {
            oc_signer::parse_evm_chain_id(reference)
                .map_err(|e| CliError::InvalidArgs(format!("invalid EVM chain id: {e}")))?;
        }
        "solana" => {
            oc_signer::validate_solana_chain_id(reference)
                .map_err(|e| CliError::InvalidArgs(format!("invalid Solana chain id: {e}")))?;
        }
        _ => unreachable!("chain_label rejected other namespaces"),
    }

    let nonce_owned;
    let nonce = if let Some(n) = nonce {
        n
    } else {
        nonce_owned = oc_siwx::nonce::generate_default();
        &nonce_owned
    };
    let mut msg = SiwxMessage::new(domain, address, uri, reference, nonce)
        .map_err(|e| CliError::InvalidArgs(format!("invalid message: {e}")))?;
    if let Some(s) = statement {
        msg = msg
            .with_statement(s)
            .map_err(|e| CliError::InvalidArgs(format!("invalid statement: {e}")))?;
    }
    if let Some(t) = issued_at {
        msg = msg
            .with_issued_at_raw(t)
            .map_err(|e| CliError::InvalidArgs(format!("invalid issued-at: {e}")))?;
    }
    if let Some(t) = expiration_time {
        msg = msg
            .with_expiration_time_raw(t)
            .map_err(|e| CliError::InvalidArgs(format!("invalid expiration-time: {e}")))?;
    }
    if let Some(t) = not_before {
        msg = msg
            .with_not_before_raw(t)
            .map_err(|e| CliError::InvalidArgs(format!("invalid not-before: {e}")))?;
    }
    if let Some(rid) = request_id {
        msg = msg
            .with_request_id(rid)
            .map_err(|e| CliError::InvalidArgs(format!("invalid request-id: {e}")))?;
    }
    if !resources.is_empty() {
        msg = msg
            .with_resources(resources.iter())
            .map_err(|e| CliError::InvalidArgs(format!("invalid resources: {e}")))?;
    }
    let text = msg.to_sign_string(label);
    if json {
        let rendered = serde_json::to_string_pretty(&json!({
            "chain": chain,
            "message": text,
            "domain": msg.domain(),
            "address": msg.address(),
            "uri": msg.uri(),
            "version": msg.version(),
            "chain_id": msg.chain_id(),
            "nonce": msg.nonce(),
            "issued_at": msg.issued_at_raw(),
            "expiration_time": msg.expiration_time_raw(),
            "not_before": msg.not_before_raw(),
        }))?;
        println!("{rendered}");
    } else {
        println!("{text}");
    }
    Ok(())
}

/// Entry point for `onecipher sign-in parse`.
pub(crate) fn run_parse(
    message: Option<&str>,
    message_file: Option<&str>,
    json: bool,
) -> Result<(), CliError> {
    let text = load_message(message, message_file)?;
    let msg: SiwxMessage = text
        .parse()
        .map_err(|e| CliError::InvalidArgs(format!("invalid CAIP-122 message: {e}")))?;
    if json {
        let rendered = serde_json::to_string_pretty(&json!({
            "domain": msg.domain(),
            "address": msg.address(),
            "uri": msg.uri(),
            "version": msg.version(),
            "chain_id": msg.chain_id(),
            "chain_name": msg.chain_name(),
            "statement": msg.statement(),
            "nonce": msg.nonce(),
            "issued_at": msg.issued_at_raw(),
            "expiration_time": msg.expiration_time_raw(),
            "not_before": msg.not_before_raw(),
            "request_id": msg.request_id(),
            "resources": msg.resources(),
        }))?;
        println!("{rendered}");
    } else {
        println!("domain:          {}", msg.domain());
        println!("address:         {}", msg.address());
        println!("uri:             {}", msg.uri());
        println!("version:         {}", msg.version());
        println!("chain_id:        {}", msg.chain_id());
        println!("chain_name:      {}", msg.chain_name().unwrap_or("(none)"));
        println!("statement:       {}", msg.statement().unwrap_or("(none)"));
        println!("nonce:           {}", msg.nonce());
        println!("issued_at:       {}", msg.issued_at_raw());
        println!("expiration_time: {}", msg.expiration_time_raw().unwrap_or("(none)"));
        println!("not_before:      {}", msg.not_before_raw().unwrap_or("(none)"));
        println!("request_id:      {}", msg.request_id().unwrap_or("(none)"));
        if msg.resources().is_empty() {
            println!("resources:       (none)");
        } else {
            println!("resources:");
            for r in msg.resources() {
                println!("  - {r}");
            }
        }
    }
    Ok(())
}

/// Entry point for `onecipher sign-in nonce`.
pub(crate) fn run_nonce(len: usize) -> Result<(), CliError> {
    let nonce = oc_siwx::nonce::generate(len)
        .map_err(|e| CliError::InvalidArgs(format!("invalid nonce length: {e}")))?;
    println!("{nonce}");
    Ok(())
}

/// Entry point for `onecipher sign-in verify`.
///
/// Contract / counterfactual accounts need `--rpc-url` (EIP-1271 / ERC-6492);
/// without it only EOAs (EIP-191) and Ed25519 keys verify. Failures exit
/// non-zero with the typed error (never `valid:false` + exit 0).
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_verify(
    message: Option<&str>,
    message_file: Option<&str>,
    signature: &str,
    domain: &str,
    nonce: &str,
    uri: Option<&str>,
    scheme: Option<&str>,
    chain_id: Option<&str>,
    chain: &str,
    rpc_url: Option<&str>,
    json: bool,
) -> Result<(), CliError> {
    let text = load_message(message, message_file)?;
    let (namespace, _) = split_chain(chain)?;
    chain_label(namespace)?;
    let sig_bytes = decode_signature(signature, namespace)?;

    let mut opts = AuthOpts::new(domain, nonce);
    if let Some(u) = uri {
        opts = opts.with_uri(u);
    }
    if let Some(s) = scheme {
        opts = opts.with_scheme(s);
    }
    if let Some(c) = chain_id {
        opts = opts.with_chain_id(c);
    }

    // Parse first so malformed input fails before any network I/O.
    let parsed: SiwxMessage = text
        .parse()
        .map_err(|e| CliError::InvalidArgs(format!("invalid CAIP-122 message: {e}")))?;

    if namespace == "solana" {
        if rpc_url.is_some() {
            return Err(CliError::InvalidArgs("--rpc-url is EVM-only (Solana needs no RPC)".into()));
        }
        let verifier = oc_signer::SolanaVerifier::new();
        oc_siwx::authenticate(&verifier, &text, &sig_bytes, &opts)
            .map_err(|e| CliError::InvalidArgs(format!("verification failed: {e}")))?;
    } else if let Some(url) = rpc_url {
        // EIP-1271 / ERC-6492 via the caller's endpoint (never a default;
        // the URL stays local and out of error strings).
        let reference = parsed.chain_id();
        let id = oc_signer::parse_evm_chain_id(reference)
            .map_err(|e| CliError::InvalidArgs(format!("invalid EVM chain id: {e}")))?;
        let verifier = oc_netagent::siwx_verify::RpcVerifier::with_rpc_for_chain(id, url);
        // The CLI is synchronous; the RPC path gets a throwaway
        // current-thread runtime (offline EOA/Ed25519 paths never touch it).
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| CliError::InvalidArgs(format!("runtime: {e}")))?;
        rt.block_on(verifier.verify(&parsed, &text, &sig_bytes))
            .map_err(|e| CliError::InvalidArgs(format!("verification failed: {e}")))?;
    } else {
        let verifier = oc_signer::EvmVerifier::new();
        oc_siwx::authenticate(&verifier, &text, &sig_bytes, &opts)
            .map_err(|e| CliError::InvalidArgs(format!("verification failed: {e}")))?;
    }

    if json {
        let rendered = serde_json::to_string_pretty(&json!({
            "valid": true,
            "chain": chain,
            "domain": parsed.domain(),
            "address": parsed.address(),
        }))?;
        println!("{rendered}");
    } else {
        println!("Signature is valid.");
    }
    Ok(())
}
