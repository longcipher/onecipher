//! x402 payment CLI (R7, R33). Dispatches via `NetAgentClient`.
//!
//! `onecipher ocpay x402 <url> --session-key <id> [--method GET] [--body <json>]`
//!
//! RPC: `PayX402(PayX402Request) → PayX402Response`

use std::collections::HashMap;

use oc_keyagent::proto::{PayX402Request, PaymentStatus};

use crate::{CliError, netagent::NetAgentClient};

/// Entry point for `onecipher ocpay x402`.
pub(crate) fn run(
    url: &str,
    session_key_id: &str,
    method: &str,
    body: Option<&str>,
    client: &dyn NetAgentClient,
) -> Result<(), CliError> {
    let body_bytes = body.map(|b| b.as_bytes().to_vec()).unwrap_or_default();
    let req = PayX402Request {
        session_key_id: session_key_id.to_string(),
        url: url.to_string(),
        method: method.to_string(),
        body: body_bytes,
        headers: HashMap::new(),
        ..Default::default()
    };
    let resp = client.pay_x402(req)?;
    match resp.status {
        s if s == PaymentStatus::Ok as i32 => {
            println!("payment OK; receipt: {}", hex::encode(&resp.receipt));
        }
        s if s == PaymentStatus::Deny as i32 => {
            println!("payment DENIED: {}", resp.deny_reason);
        }
        s if s == PaymentStatus::Error as i32 => {
            println!("payment ERROR: {}", resp.error);
        }
        _ => {
            println!("payment unknown status: {}", resp.status);
        }
    }
    Ok(())
}
