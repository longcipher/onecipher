//! Control-socket wire protocol handling for the OneCipher daemon.
//!
//! The daemon listens on a Unix domain socket (`~/.onecipher/onecipher.ctrl`)
//! so sibling CLI invocations can inject WalletConnect pairing URIs into the
//! running WC v2 server.

/// Control socket accept loop — handles `CONNECT <uri>` and `PAIR [ttl]`
/// commands from `onecipher wc connect/pair`.
///
/// Protocol (line-based, newline-terminated):
/// - Request:  `CONNECT <wc_uri>\n` or `PAIR [<ttl_secs>]\n`
/// - Response: `OK [details]\n` or `ERR <message>\n`
pub(crate) async fn control_socket_loop(
    listener: tokio::net::UnixListener,
    tx: tokio::sync::mpsc::Sender<oc_walletconnect::PairingUri>,
) {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let tx = tx.clone();
                tokio::spawn(async move {
                    let (reader, mut writer) = stream.into_split();
                    let mut reader = BufReader::new(reader);
                    let mut line = String::new();

                    if reader.read_line(&mut line).await.is_err() {
                        let _ = writer.write_all(b"ERR read failed\n").await;
                        return;
                    }

                    let line = line.trim();
                    if let Some(uri_str) = line.strip_prefix("CONNECT ") {
                        // dApp-generated URI → inject into WC server
                        match oc_walletconnect::PairingUri::parse(uri_str) {
                            Ok(uri) => {
                                if tx.send(uri).await.is_ok() {
                                    let _ = writer.write_all(b"OK pairing loaded\n").await;
                                } else {
                                    let _ = writer.write_all(b"ERR daemon shutting down\n").await;
                                }
                            }
                            Err(e) => {
                                let _ = writer
                                    .write_all(format!("ERR invalid URI: {e}\n").as_bytes())
                                    .await;
                            }
                        }
                    } else if line == "PAIR" || line.starts_with("PAIR ") {
                        // Daemon-generated pairing URI → return to user for QR display
                        let ttl: u64 = line
                            .strip_prefix("PAIR ")
                            .and_then(|s| s.trim().parse().ok())
                            .unwrap_or(oc_netagent::DEFAULT_PAIRING_TTL);
                        let (uri, _session) = oc_netagent::generate_pairing_uri(ttl);
                        let uri_for_send = uri.clone();
                        if tx.send(uri_for_send).await.is_ok() {
                            let _ = writer.write_all(format!("OK {uri}\n").as_bytes()).await;
                        } else {
                            let _ = writer.write_all(b"ERR daemon shutting down\n").await;
                        }
                    } else {
                        let _ = writer.write_all(b"ERR unknown command\n").await;
                    }
                });
            }
            Err(e) => {
                eprintln!("control socket accept error: {e}");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
}
