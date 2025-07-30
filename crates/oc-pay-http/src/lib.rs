//! `oc-pay-http` — OneCipher HTTP payment client.
//!
//! Chain-agnostic: works with any chain the wallet supports. Payment
//! scheme dispatch (e.g. EVM "exact" / EIP-3009) is handled internally
//! based on the x402 `scheme` field.
//!
//! ```ignore
//! let result = oc_pay_http::pay(&wallet, "https://api.example.com/data", "GET", None).await?;
//! let services = oc_pay_http::discover(None, None, None).await?;
//! ```

pub(crate) mod chains;
pub(crate) mod discovery;
pub mod error;
pub mod fund;
pub mod types;
pub mod wallet;

pub mod x402;

pub use error::{OcPayHttpError, OcPayHttpErrorCode};
pub use types::{DiscoverResult, PayResult, PaymentInfo, Protocol, Service};
pub use wallet::{Account, WalletAccess};

/// Make an HTTP request with automatic payment handling.
///
/// Fires the request. If the server returns 402, detects the payment
/// protocol from the response and handles payment.
pub async fn pay(
    wallet: &dyn WalletAccess,
    url: &str,
    method: &str,
    body: Option<&str>,
) -> Result<PayResult, OcPayHttpError> {
    let client = hpx::Client::new();

    let initial = x402::build_request(&client, url, method, body, None)?.send().await?;

    if initial.status().as_u16() != 402 {
        let status = initial.status().as_u16();
        let text = initial.text().await.unwrap_or_default();
        return Ok(PayResult { protocol: Protocol::X402, status, body: text, payment: None });
    }

    let headers = initial.headers().clone();
    let body_402 = initial.text().await.unwrap_or_default();

    x402::handle_x402(wallet, url, method, body, &headers, &body_402).await
}

/// Discover payable services.
///
/// Supports pagination via `limit` and `offset`. Returns services and
/// pagination metadata so callers can page through the full directory.
pub async fn discover(
    query: Option<&str>,
    limit: Option<u64>,
    offset: Option<u64>,
) -> Result<DiscoverResult, OcPayHttpError> {
    discovery::discover_all(query, limit, offset).await
}
