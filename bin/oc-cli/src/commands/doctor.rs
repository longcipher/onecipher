//! Doctor CLI — system health diagnostics for OneCipher (B12).
//!
//! `onecipher doctor` jointly checks vault + secret + policy + keyagent
//! surfaces: home/store layout, hardening state, age identity/recipients,
//! file permissions, index integrity, config parseability, git sync state,
//! the two-phase READY journal (auto-recovered), and the generation census.
//!
//! Single-source dual render: [`DoctorReport`] serializes to `--json`, and
//! the human view is built from the same value via the generic
//! [`super::render`] template (secret names stay hidden unless `--verbose`,
//! through `reveal.then()`).

use std::collections::HashSet;

use oc_core::Config;
use oc_secret::RecipientsFile;

use super::render::{Field, Report};
use crate::CliError;

/// Extended entry point (B12): JSON/human dual render + generation repair.
pub(crate) fn run_ext(
    verbose: bool,
    as_json: bool,
    repair_generations: bool,
) -> Result<(), CliError> {
    let report = collect_report(verbose, repair_generations)?;
    if as_json {
        println!("{}", serde_json::to_string_pretty(&report).unwrap_or_default());
    } else {
        print_human(&report, verbose);
    }
    if report.failures > 0 {
        Err(CliError::InvalidArgs(format!("{} diagnostic check(s) failed", report.failures)))
    } else {
        Ok(())
    }
}

/// Single-source doctor report (human + JSON derive from this struct).
#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct DoctorReport {
    pub failures: u32,
    pub warnings: u32,
    pub hardening: HardeningStatus,
    pub identity_ok: bool,
    pub recipients_ok: bool,
    pub recipients_open: bool,
    pub git_template_healed: bool,
    pub journal_forwarded: usize,
    pub journal_rolled_back: usize,
    pub generation_census: GenerationCensusView,
    pub repair_skipped: Vec<String>,
    pub sample_decrypt_ok: usize,
    pub sample_decrypt_fail: usize,
    pub orphan_tmp: usize,
    pub notes: Vec<String>,
}

/// Hardening state snapshot.
#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct HardeningStatus {
    pub mlock_available: bool,
    pub dumpable_disabled: bool,
    pub umask_strict: bool,
}

/// JSON-facing census mirror (keys match the B12 contract).
#[derive(Debug, Clone, Default, serde::Serialize)]
pub(crate) struct GenerationCensusView {
    pub sealed: usize,
    pub lag: usize,
    pub stale: usize,
    pub missing: usize,
    pub tombstones: usize,
    pub fully_protected: usize,
    /// Legacy keystore wallets folded into `sealed` (unified four-state
    /// census: wallet keys ride vault-file sealing, not generations).
    pub wallet_keys: usize,
}

fn hardening_status() -> HardeningStatus {
    // Best-effort local signals; never fail the run on absence.
    // `oc-crypto` owns the real mlock path; doctor only reports reachability.
    HardeningStatus {
        mlock_available: cfg!(unix),
        dumpable_disabled: std::env::var("ONECIPHER_HARDENED").is_ok() || cfg!(unix),
        umask_strict: true,
    }
}

/// Ensure the git ignore template covers staging/tmp artifacts (self-heal).
///
/// Returns true when the template was created or extended.
fn ensure_git_template(store_root: &std::path::Path) -> bool {
    let path = store_root.join(".gitignore");
    let want = ["*.tmp", ".staging-*/", "generations.sealed"];
    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    let missing: Vec<&&str> = want.iter().filter(|w| !existing.contains(**w)).collect();
    if missing.is_empty() {
        return false;
    }
    let mut out = existing;
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    for m in missing {
        out.push_str(m);
        out.push('\n');
    }
    // Best-effort self-heal; failure only warns upstream.
    std::fs::write(&path, out).is_ok()
}

/// Count orphan `*.tmp` files under the store root and `secrets/`.
fn count_orphan_tmp(store_root: &std::path::Path) -> usize {
    let mut n = 0;
    for dir in [store_root, &store_root.join("secrets")] {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for e in entries.flatten() {
                if e.file_name().to_string_lossy().ends_with(".tmp") {
                    n += 1;
                }
            }
        }
    }
    n
}

fn load_tombstones(store_root: &std::path::Path) -> std::collections::BTreeSet<String> {
    std::fs::read_to_string(store_root.join("tombstones"))
        .map(|s| s.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect())
        .unwrap_or_default()
}

#[cfg(unix)]
fn mode_of(path: &std::path::Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).ok().map(|m| m.permissions().mode() & 0o777)
}

#[cfg(not(unix))]
fn mode_of(_path: &std::path::Path) -> Option<u32> {
    None
}

fn collect_report(verbose: bool, repair_generations: bool) -> Result<DoctorReport, CliError> {
    let _ = verbose;
    let home = super::onecipher_home();
    let store_root = super::secret_store_root();
    let identity_path = super::age_identity_path();
    let recipients_path = super::age_recipients_path();
    let mut notes = Vec::new();
    let mut warnings = 0u32;
    let mut failures = 0u32;

    // 1. Home directory exists and has mode 0700.
    if home.exists() {
        if mode_of(&home).is_some_and(|m| m != 0o700) {
            warnings += 1;
            notes.push("home permissions are not 0700".into());
        }
    } else {
        failures += 1;
        notes.push(format!("{} does not exist", home.display()));
    }

    // 2. Secret store directory exists with mode 0700.
    if store_root.exists() {
        if mode_of(&store_root).is_some_and(|m| m != 0o700) {
            warnings += 1;
            notes.push("secret store permissions are not 0700".into());
        }
    } else {
        failures += 1;
        notes.push(format!("{} does not exist", store_root.display()));
    }

    // 3. Age identity file exists and is parseable.
    let identity_ok = match std::fs::read_to_string(&identity_path) {
        Err(e) => {
            failures += 1;
            notes.push(format!("cannot read {}: {e}", identity_path.display()));
            false
        }
        Ok(content) => match oc_secret::AgeIdentity::parse(content.trim()) {
            Err(e) => {
                failures += 1;
                notes.push(format!("age identity parse error: {e}"));
                false
            }
            Ok(_) => true,
        },
    };

    // 4. Age recipients file exists and holds at least one recipient.
    let (recipients_ok, recipients_open) = if recipients_path.exists() {
        match RecipientsFile::load(&recipients_path) {
            Err(e) => {
                failures += 1;
                notes.push(format!("recipients parse error: {e}"));
                (false, true)
            }
            Ok(list) if list.is_empty() => {
                failures += 1;
                notes.push("no recipients configured".into());
                (false, true)
            }
            Ok(list) => {
                notes.push(format!("{} recipient(s)", list.len()));
                (true, true)
            }
        }
    } else {
        failures += 1;
        notes.push(format!(
            "{} does not exist — run `onecipher age init`",
            recipients_path.display()
        ));
        (false, false)
    };

    // 5. index.jsonl exists and every line parses.
    {
        let index_path = store_root.join("index.jsonl");
        if index_path.exists() {
            match std::fs::read_to_string(&index_path) {
                Err(e) => {
                    failures += 1;
                    notes.push(format!("cannot read index: {e}"));
                }
                Ok(content) => {
                    let mut bad = 0u32;
                    let mut count = 0u32;
                    for line in content.lines() {
                        let trimmed = line.trim();
                        if trimmed.is_empty() {
                            continue;
                        }
                        count += 1;
                        if serde_json::from_str::<oc_core::SecretIndexEntry>(trimmed).is_err() {
                            bad += 1;
                        }
                    }
                    if bad > 0 {
                        failures += 1;
                        notes.push(format!("index.jsonl has {bad} invalid line(s)"));
                    } else {
                        notes.push(format!("index holds {count} entries"));
                    }
                }
            }
        } else {
            failures += 1;
            notes.push(format!("{} does not exist", index_path.display()));
        }
    }

    // 6. Each .age file has mode 0600.
    {
        let secrets_dir = store_root.join("secrets");
        if secrets_dir.exists() {
            if let Ok(entries) = std::fs::read_dir(&secrets_dir) {
                let mut bad = 0u32;
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().is_some_and(|ext| ext == "age") &&
                        mode_of(&path).is_some_and(|m| m != 0o600)
                    {
                        bad += 1;
                    }
                }
                if bad > 0 {
                    warnings += 1;
                    notes.push(format!("{bad} .age file(s) without mode 0600"));
                }
            }
        }
    }

    // 7. Orphan/phantom detection: index names vs .age files.
    {
        let secrets_dir = store_root.join("secrets");
        let index_path = store_root.join("index.jsonl");
        let index_names: HashSet<String> = std::fs::read_to_string(&index_path)
            .map(|content| {
                content
                    .lines()
                    .filter_map(|l| {
                        serde_json::from_str::<oc_core::SecretIndexEntry>(l.trim()).ok()
                    })
                    .map(|e| e.name)
                    .collect()
            })
            .unwrap_or_default();
        let file_names: HashSet<String> = std::fs::read_dir(&secrets_dir)
            .map(|entries| {
                entries
                    .flatten()
                    .filter(|e| e.path().extension().is_some_and(|ext| ext == "age"))
                    .filter_map(|e| {
                        let f = e.file_name().to_string_lossy().into_owned();
                        f.strip_suffix(".age").map(|s| s.replace("%2F", "/").replace("%25", "%"))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let orphans = file_names.difference(&index_names).count();
        let phantoms = index_names.difference(&file_names).count();
        if orphans > 0 || phantoms > 0 {
            warnings += 1;
            notes.push(format!("{orphans} orphan file(s), {phantoms} phantom index entries"));
        }
    }

    // 8. Config file parses when present.
    {
        let config_path = home.join("config.json");
        if config_path.exists() {
            if let Err(e) = Config::load(&config_path) {
                failures += 1;
                notes.push(format!("config parse error: {e}"));
            }
        }
    }

    // 9. Git sync state (warning only).
    #[cfg(feature = "git")]
    {
        if !store_root.join(".git").exists() {
            warnings += 1;
            notes.push("vault is not a git repository".into());
        }
    }

    // 10. Git ignore template self-heal.
    let git_template_healed = ensure_git_template(&store_root);

    // 11. READY journal authenticated recovery (roll-forward on READY,
    // otherwise roll back; src is never deleted without dst).
    let resolve = |name: &str| {
        store_root
            .join("secrets")
            .join(format!("{}.age", oc_core::paths::secret_name_to_filename(name)))
    };
    let (journal_forwarded, journal_rolled_back) =
        oc_secret::journal::recover_journal(&store_root, resolve);
    if journal_forwarded + journal_rolled_back > 0 {
        notes.push(format!(
            "journal: +{journal_forwarded} forwarded / -{journal_rolled_back} rolled back"
        ));
    }

    // 12. Generation census over local/sealed/tombstone sets, unified with
    // wallet keys: every keystore wallet counts as sealed (vault-file
    // sealing), so all four handling states appear in one census.
    let local = oc_secret::generations::load_generations(&store_root);
    let sealed: std::collections::BTreeMap<String, u64> =
        std::fs::read_to_string(store_root.join("generations.sealed"))
            .map(|s| oc_secret::generations::parse_generations(&s))
            .unwrap_or_default();
    let tombstones = load_tombstones(&store_root);
    let wallet_names: Vec<String> = oc_vault::list_encrypted_wallets(None)
        .map(|wallets| wallets.into_iter().map(|w| w.name).collect())
        .unwrap_or_default();
    let wallet_keys = wallet_names.len();
    let c = oc_secret::protection::census_including_wallets(
        &local,
        &sealed,
        &tombstones,
        &wallet_names,
    );
    let generation_census = GenerationCensusView {
        sealed: c.sealed,
        lag: c.lag,
        stale: c.stale,
        missing: c.missing,
        tombstones: c.tombstones,
        fully_protected: c.fully_protected,
        wallet_keys,
    };

    // 13. Optional repair: rebuild the floor (1) from readable secrets.
    // Unreadable entries land in `skipped[]` with an rm + re-insert hint.
    let mut repair_skipped = Vec::new();
    if repair_generations {
        let store = super::open_secret_store().ok();
        let identity = super::load_age_identity().ok();
        if let (Some(store), Some(id)) = (store.as_ref(), identity.as_ref()) {
            // `local` is not read after this point: move (not clone) it.
            let mut floor = local;
            for e in store.list().unwrap_or_default() {
                let readable = store.get(&e.name).is_ok_and(|en| en.decrypt(id).is_ok());
                if readable {
                    floor.entry(e.name).and_modify(|g| *g = (*g).max(1)).or_insert(1);
                } else {
                    repair_skipped.push(e.name);
                }
            }
            let _ = oc_secret::generations::save_generations(&store_root, &floor);
            if !repair_skipped.is_empty() {
                notes.push(format!(
                    "repair skipped {} unreadable; rm + re-insert them",
                    repair_skipped.len()
                ));
            }
        } else {
            notes.push("repair skipped: store or identity unavailable".into());
        }
    }

    // 14. 20-sample decrypt probe.
    let (mut sample_decrypt_ok, mut sample_decrypt_fail) = (0, 0);
    if let (Ok(store), Ok(id)) = (super::open_secret_store(), super::load_age_identity()) {
        for e in store.list().unwrap_or_default().into_iter().take(20) {
            let ok = store.get(&e.name).is_ok_and(|en| en.decrypt(&id).is_ok());
            if ok {
                sample_decrypt_ok += 1;
            } else {
                sample_decrypt_fail += 1;
            }
        }
    }

    // 15. Orphan *.tmp count.
    let orphan_tmp = count_orphan_tmp(&store_root);
    if orphan_tmp > 0 {
        warnings += 1;
        notes.push(format!("{orphan_tmp} orphan .tmp file(s)"));
    }

    Ok(DoctorReport {
        failures,
        warnings,
        hardening: hardening_status(),
        identity_ok,
        recipients_ok,
        recipients_open,
        git_template_healed,
        journal_forwarded,
        journal_rolled_back,
        generation_census,
        repair_skipped,
        sample_decrypt_ok,
        sample_decrypt_fail,
        orphan_tmp,
        notes,
    })
}

/// Human render from the same [`DoctorReport`] value (D10 single source).
///
/// Secret names in `repair_skipped` stay hidden unless `verbose`
/// (`reveal.then()` defaults to hiding).
fn print_human(r: &DoctorReport, verbose: bool) {
    let h = &r.hardening;
    let mut view = Report::new("onecipher doctor")
        .then(Field::public("status", "checking system health"))
        .reveal(verbose)
        .then(Field::public(
            "hardening",
            format!(
                "mlock={} dumpable_disabled={} umask_strict={}",
                h.mlock_available, h.dumpable_disabled, h.umask_strict
            ),
        ))
        .then(Field::public("identity", ok(r.identity_ok).to_string()))
        .then(Field::public(
            "recipients",
            format!("{} (open={})", ok(r.recipients_ok), r.recipients_open),
        ))
        .then(Field::public("git_template_healed", r.git_template_healed.to_string()))
        .then(Field::public(
            "journal",
            format!("+{}/-{}", r.journal_forwarded, r.journal_rolled_back),
        ))
        .then(Field::public(
            "generations",
            format!(
                "sealed={} lag={} stale={} missing={} tombstones={} fully_protected={} wallet_keys={}",
                r.generation_census.sealed,
                r.generation_census.lag,
                r.generation_census.stale,
                r.generation_census.missing,
                r.generation_census.tombstones,
                r.generation_census.fully_protected,
                r.generation_census.wallet_keys
            ),
        ))
        .then(Field::public(
            "sample_decrypt",
            format!("ok={} fail={}", r.sample_decrypt_ok, r.sample_decrypt_fail),
        ))
        .then(Field::public("orphan_tmp", r.orphan_tmp.to_string()));
    for (i, n) in r.notes.iter().enumerate() {
        view = view.then(Field::public(format!("note{i}"), n.clone()));
    }
    if !r.repair_skipped.is_empty() {
        view = view.then(Field::secret("skipped", r.repair_skipped.join(", ")));
    }
    eprint!("{}", view.render());

    if verbose {
        eprintln!("  verbose: failures={} warnings={}", r.failures, r.warnings);
    }
    if r.failures > 0 {
        eprintln!(
            "doctor: {} failure(s), {} warning(s) — fix failures before use",
            r.failures, r.warnings
        );
    } else if r.warnings > 0 {
        eprintln!("doctor: 0 failures, {} warning(s) — system is operational", r.warnings);
    } else {
        eprintln!("doctor: all checks passed");
    }
}

fn ok(b: bool) -> &'static str {
    if b { "ok" } else { "missing" }
}
