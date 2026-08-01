use k256::elliptic_curve::Generate;
use sha2::Digest;

use crate::CliError;

pub(crate) fn run(
    starts_with: Option<&str>,
    ends_with: Option<&str>,
    count: usize,
    jobs: Option<usize>,
    save_path: Option<&std::path::Path>,
    save_to_vault: bool,
) -> Result<(), CliError> {
    if starts_with.is_none() && ends_with.is_none() {
        return Err(CliError::InvalidArgs(
            "at least one of --starts-with or --ends-with is required".into(),
        ));
    }

    // Parse and validate patterns
    let prefix = starts_with.map(|p| parse_pattern(p, "starts-with")).transpose()?;
    let suffix = ends_with.map(|s| parse_pattern(s, "ends-with")).transpose()?;

    // Configure thread count
    let num_threads =
        jobs.unwrap_or_else(|| std::thread::available_parallelism().map_or(4, |n| n.get()));
    eprintln!("Generating vanity address with {num_threads} threads...");

    if let Some(ref p) = prefix {
        eprintln!("  Prefix: {p}");
    }
    if let Some(ref s) = suffix {
        eprintln!("  Suffix: {s}");
    }
    eprintln!("  Count:  {count}");
    eprintln!();

    let mut results = Vec::new();
    let start = std::time::Instant::now();

    for i in 0..count {
        let (privkey, address) =
            find_vanity_address(prefix.as_deref(), suffix.as_deref(), num_threads)?;

        let elapsed = start.elapsed();
        eprintln!("[{}/{}] Found in {:.2}s", i + 1, count, elapsed.as_secs_f64());
        println!("Address:     {address}");
        println!("Private Key: {privkey}");
        println!();

        if save_to_vault {
            eprintln!(
                "WARNING: --save-to-vault is not yet implemented. Use `oc wallet import` manually."
            );
        }

        results.push(VanityResult { address, private_key: privkey });
    }

    // Save to file if requested
    if let Some(path) = save_path {
        let mut existing: Vec<VanityResult> = if path.exists() {
            let content = std::fs::read_to_string(path)?;
            serde_json::from_str(&content).unwrap_or_default()
        } else {
            Vec::new()
        };
        existing.extend(results);
        let json = serde_json::to_string_pretty(&existing)?;
        std::fs::write(path, json)?;
        eprintln!("Results saved to {}", path.display());
    }

    Ok(())
}

#[derive(serde::Serialize, serde::Deserialize)]
struct VanityResult {
    address: String,
    private_key: String,
}

fn parse_pattern(input: &str, field: &str) -> Result<String, CliError> {
    let trimmed = input.trim();
    // Strip optional 0x prefix
    let stripped =
        trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")).unwrap_or(trimmed);

    // Validate hex
    if stripped.is_empty() {
        return Err(CliError::InvalidArgs(format!("{field} pattern cannot be empty")));
    }
    if stripped.len() > 40 {
        return Err(CliError::InvalidArgs(format!(
            "{field} pattern too long (max 40 hex chars / 20 bytes)"
        )));
    }
    // Ensure valid hex characters
    if !stripped.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(CliError::InvalidArgs(format!(
            "{field} must be a valid hex pattern (0-9, a-f, A-F)"
        )));
    }
    Ok(stripped.to_ascii_lowercase())
}

fn find_vanity_address(
    prefix: Option<&str>,
    suffix: Option<&str>,
    num_threads: usize,
) -> Result<(String, String), CliError> {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    let found = Arc::new(AtomicBool::new(false));
    let result = Arc::new(std::sync::Mutex::new(None::<(String, String)>));

    std::thread::scope(|scope| -> Result<(), CliError> {
        let mut handles = Vec::with_capacity(num_threads);

        for _ in 0..num_threads {
            let found = Arc::clone(&found);
            let result = Arc::clone(&result);
            let prefix = prefix.map(|s| s.to_string());
            let suffix = suffix.map(|s| s.to_string());

            handles.push(scope.spawn(move || {
                while !found.load(Ordering::Relaxed) {
                    let signing_key = k256::ecdsa::SigningKey::generate();
                    let verifying_key = signing_key.verifying_key();
                    let pubkey_uncompressed = verifying_key.to_sec1_point(false);
                    let hash = sha3::Keccak256::digest(&pubkey_uncompressed.as_bytes()[1..]);
                    let address_bytes = &hash[12..];
                    let address_hex = hex::encode(address_bytes);

                    let matches_prefix =
                        prefix.as_deref().map_or(true, |p| address_hex.starts_with(p));
                    let matches_suffix =
                        suffix.as_deref().map_or(true, |s| address_hex.ends_with(s));

                    if matches_prefix && matches_suffix {
                        if found
                            .compare_exchange(false, true, Ordering::SeqCst, Ordering::Relaxed)
                            .is_ok()
                        {
                            let privkey_hex = hex::encode(signing_key.to_bytes());
                            let address = format!("0x{}", eip55_checksum(&address_hex));
                            *result.lock().unwrap() = Some((privkey_hex, address));
                        }
                        return;
                    }
                }
            }));
        }

        for handle in handles {
            handle.join().map_err(|_| CliError::InvalidArgs("thread panicked".into()))?;
        }
        Ok(())
    })?;

    result.lock().unwrap().take().ok_or_else(|| CliError::InvalidArgs("search interrupted".into()))
}

fn eip55_checksum(address_hex: &str) -> String {
    let lower = address_hex.to_lowercase();
    let hash = sha3::Keccak256::digest(lower.as_bytes());
    let hash_hex = hex::encode(hash);

    let mut checksummed = String::with_capacity(40);
    for (i, c) in lower.chars().enumerate() {
        if c.is_ascii_digit() {
            checksummed.push(c);
        } else {
            let nibble = u8::from_str_radix(&hash_hex[i..=i], 16).unwrap_or(0);
            if nibble >= 8 {
                checksummed.push(c.to_ascii_uppercase());
            } else {
                checksummed.push(c);
            }
        }
    }
    checksummed
}
