use std::path::PathBuf;

/// Migrate the vault directory from legacy locations to `~/.onecipher` if needed.
///
/// Migration chain:
/// 1. `~/.lws` (pre-0.7 "Local Wallet Server") → `~/.ows` (Open Wallet Standard)
/// 2. `~/.ows` → `~/.onecipher` (OneCipher)
pub fn migrate_vault_if_needed() {
    let Ok(home) = oc_core::paths::home_dir() else {
        return;
    };

    let lws_dir = PathBuf::from(&home).join(".lws");
    let ows_dir = PathBuf::from(&home).join(".ows");
    let oc_dir = PathBuf::from(&home).join(".onecipher");

    // Step 1: Migrate .lws → .ows if .ows doesn't exist yet
    if lws_dir.exists() && !ows_dir.exists() {
        migrate_single_dir(&lws_dir, &ows_dir, ".lws", ".ows");
    } else if lws_dir.exists() && ows_dir.exists() {
        tracing::warn!(
            "both ~/.lws and ~/.ows exist; using ~/.ows; remove ~/.lws manually if no longer needed"
        );
    }

    // Step 2: Migrate .ows → .onecipher if .onecipher doesn't exist yet
    if ows_dir.exists() && !oc_dir.exists() {
        migrate_single_dir(&ows_dir, &oc_dir, ".ows", ".onecipher");
    } else if ows_dir.exists() && oc_dir.exists() {
        tracing::warn!(
            "both ~/.ows and ~/.onecipher exist; using ~/.onecipher; remove ~/.ows manually if no longer needed"
        );
    }
}

/// Rename `src` → `dst` and patch `config.json` to replace `src_marker` with `dst_marker`.
///
/// Returns `true` on success. Shell RC file mutation is the caller's responsibility.
pub fn migrate_single_dir(
    src: &std::path::Path,
    dst: &std::path::Path,
    src_marker: &str,
    dst_marker: &str,
) -> bool {
    if let Err(e) = std::fs::rename(src, dst) {
        tracing::warn!(src = %src.display(), dst = %dst.display(), error = %e, "failed to migrate vault directory");
        return false;
    }

    let config_path = dst.join("config.json");
    if config_path.exists() {
        if let Ok(contents) = std::fs::read_to_string(&config_path) {
            let updated = contents.replace(src_marker, dst_marker);
            // Config is non-secret, but a torn write here leaves config.json
            // pointing at the wrong vault path post-migration.
            if oc_core::paths::write_atomic(
                &config_path,
                updated.as_bytes(),
                oc_core::paths::MODE_REGULAR_FILE,
            )
            .is_err()
            {
                tracing::warn!(path = %config_path.display(), "failed to update config paths during migration");
            }
        }
    }

    tracing::info!(from = src_marker, to = dst_marker, "migrated wallet vault");
    true
}
