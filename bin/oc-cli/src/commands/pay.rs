use oc_core::ChainType;

use crate::{CliError, commands::read_passphrase};

/// Concrete WalletAccess backed by oc-wallet.
struct CliWallet {
    wallet_name: String,
    passphrase: String,
}

impl oc_pay::http::WalletAccess for CliWallet {
    fn supported_chains(&self) -> Vec<ChainType> {
        if let Ok(info) = oc_wallet::get_wallet(&self.wallet_name, None) {
            let mut chains = Vec::new();
            for acct in &info.accounts {
                let ns = acct.chain_id.split(':').next().unwrap_or("");
                if let Some(ct) = ChainType::from_namespace(ns) {
                    if !chains.contains(&ct) {
                        chains.push(ct);
                    }
                }
            }
            if chains.is_empty() { vec![ChainType::Evm] } else { chains }
        } else {
            vec![ChainType::Evm]
        }
    }

    fn account(
        &self,
        network: &str,
    ) -> Result<oc_pay::http::Account, oc_pay::http::OcPayHttpError> {
        let info = oc_wallet::get_wallet(&self.wallet_name, None).map_err(|e| {
            oc_pay::http::OcPayHttpError::new(
                oc_pay::http::OcPayHttpErrorCode::WalletNotFound,
                e.to_string(),
            )
        })?;
        let ns = network.split(':').next().unwrap_or("eip155");
        let acct =
            info.accounts.iter().find(|a| a.chain_id.starts_with(&format!("{ns}:"))).ok_or_else(
                || {
                    oc_pay::http::OcPayHttpError::new(
                        oc_pay::http::OcPayHttpErrorCode::WalletNotFound,
                        format!("no {ns} account in wallet"),
                    )
                },
            )?;
        Ok(oc_pay::http::Account { address: acct.address.clone() })
    }

    fn sign_payload(
        &self,
        scheme: &str,
        network: &str,
        payload: &str,
    ) -> Result<String, oc_pay::http::OcPayHttpError> {
        match scheme {
            "exact" => {
                // EIP-712 typed data signing.
                // oc_wallet::sign_typed_data accepts both names ("base") and CAIP-2 IDs.
                let result = oc_wallet::sign_typed_data(
                    &self.wallet_name,
                    network,
                    payload,
                    Some(&self.passphrase),
                    None,
                    None,
                )
                .map_err(|e| {
                    oc_pay::http::OcPayHttpError::new(
                        oc_pay::http::OcPayHttpErrorCode::SigningFailed,
                        e.to_string(),
                    )
                })?;
                Ok(format!("0x{}", result.signature))
            }
            other => Err(oc_pay::http::OcPayHttpError::new(
                oc_pay::http::OcPayHttpErrorCode::ProtocolUnknown,
                format!("unsupported payment scheme: {other}"),
            )),
        }
    }
}

/// `onecipher pay request <url> --wallet <name> [--method GET] [--body '{}']`
pub(crate) fn run(
    url: &str,
    wallet_name: &str,
    method: &str,
    body: Option<&str>,
    skip_passphrase: bool,
) -> Result<(), CliError> {
    let passphrase = if skip_passphrase { String::new() } else { read_passphrase().to_string() };

    let wallet = CliWallet { wallet_name: wallet_name.to_string(), passphrase };

    let rt =
        tokio::runtime::Runtime::new().map_err(|e| CliError::InvalidArgs(format!("tokio: {e}")))?;

    let result = rt.block_on(oc_pay::http::pay(&wallet, url, method, body))?;

    if result.status < 400 {
        if let Some(ref payment) = result.payment {
            if payment.amount.is_empty() {
                eprintln!("Paid via {}", result.protocol);
            } else {
                eprintln!("Paid {} on {} via {}", payment.amount, payment.network, result.protocol);
            }
        }
    } else if result.payment.is_some() {
        eprintln!("HTTP {} — payment rejected by server", result.status);
    } else {
        eprintln!("HTTP {}", result.status);
    }

    println!("{}", result.body);
    Ok(())
}

/// `onecipher pay discover [--query <search>] [--limit N] [--offset N]`
pub(crate) fn discover(
    query: Option<&str>,
    limit: Option<u64>,
    offset: Option<u64>,
) -> Result<(), CliError> {
    let rt =
        tokio::runtime::Runtime::new().map_err(|e| CliError::InvalidArgs(format!("tokio: {e}")))?;

    let result = rt.block_on(oc_pay::http::discover(query, limit, offset))?;

    if result.services.is_empty() {
        eprintln!("No services found.");
        return Ok(());
    }

    eprintln!(
        "Showing {}-{} of {} services:\n",
        result.offset + 1,
        result.offset + result.services.len() as u64,
        result.total,
    );
    for svc in &result.services {
        println!("  {:>8}  {:<8}  {}", svc.price, svc.network, svc.description);
        println!("  {:>8}  {:8}  {}", "", "", svc.url);
        println!();
    }

    Ok(())
}
