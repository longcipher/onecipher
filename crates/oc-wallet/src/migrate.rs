use std::path::PathBuf;

/// Migrate the vault directory from legacy locations to `~/.onecipher` if needed.
///
/// Migration chain:
/// 1. `~/.lws` (pre-0.7 "Local Wallet Server") → `~/.ows` (Open Wallet Standard)
/// 2. `~/.ows` → `~/.onecipher` (OneCipher)
///
/// Direct migration from either legacy directory is supported. Shell RC files are
/// updated to point PATH at `.onecipher/bin`.
pub fn migrate_vault_if_needed() {
    let Some(home) = std::env::var("HOME").ok() else {
        return;
    };

    let lws_dir = PathBuf::from(&home).join(".lws");
    let ows_dir = PathBuf::from(&home).join(".ows");
    let oc_dir = PathBuf::from(&home).join(".onecipher");

    // Step 1: Migrate .lws → .ows if .ows doesn't exist yet
    if lws_dir.exists() && !ows_dir.exists() {
        migrate_single_dir(&lws_dir, &ows_dir, ".lws", ".ows", ".lws/bin", ".ows/bin");
    } else if lws_dir.exists() && ows_dir.exists() {
        eprintln!(
            "warning: Both ~/.lws and ~/.ows exist. Using ~/.ows. Remove ~/.lws manually if no longer needed."
        );
    }

    // Step 2: Migrate .ows → .onecipher if .onecipher doesn't exist yet
    if ows_dir.exists() && !oc_dir.exists() {
        migrate_single_dir(&ows_dir, &oc_dir, ".ows", ".onecipher", ".ows/bin", ".onecipher/bin");
    } else if ows_dir.exists() && oc_dir.exists() {
        eprintln!(
            "warning: Both ~/.ows and ~/.onecipher exist. Using ~/.onecipher. Remove ~/.ows manually if no longer needed."
        );
    }
}

fn migrate_single_dir(
    src: &std::path::Path,
    dst: &std::path::Path,
    src_marker: &str,
    dst_marker: &str,
    src_bin: &str,
    dst_bin: &str,
) {
    if let Err(e) = std::fs::rename(src, dst) {
        eprintln!("warning: failed to migrate {} to {}: {e}", src.display(), dst.display());
        return;
    }

    let config_path = dst.join("config.json");
    if config_path.exists() {
        if let Ok(contents) = std::fs::read_to_string(&config_path) {
            let updated = contents.replace(src_marker, dst_marker);
            let _ = std::fs::write(&config_path, updated);
        }
    }

    let Some(home) = std::env::var("HOME").ok() else {
        return;
    };

    let rc_files = [
        PathBuf::from(&home).join(".zshrc"),
        PathBuf::from(&home).join(".bashrc"),
        PathBuf::from(&home).join(".bash_profile"),
        PathBuf::from(&home).join(".config/fish/config.fish"),
    ];

    for rc in &rc_files {
        if rc.exists() {
            if let Ok(contents) = std::fs::read_to_string(rc) {
                if contents.contains(src_bin) {
                    let updated = contents.replace(src_bin, dst_bin);
                    let _ = std::fs::write(rc, updated);
                }
            }
        }
    }

    eprintln!("Migrated wallet vault from ~/{} to ~/{}", src_marker, dst_marker);
}
