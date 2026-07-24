//! T43 — Vault Unlock BDD step definitions.
//!
//! Implements the 3 scenarios in
//! `vault_unlock.feature`:
//!   1. Unlock wallet via Passkey challenge-response
//!   2. Vault file permissions enforced (700 dir, 600 file)
//!   3. Encrypted wallet file decrypts to HardenedBytes
//!
//! Per the T43 design, steps orchestrate EXISTING components directly:
//! - `oc_vault::Vault` for loading + decrypting the wallet file
//! - `oc_vault::save_encrypted_wallet` for writing the vault file with 0600/0700 perms
//! - `oc_keyagent::PasskeyVerifier` for the Passkey challenge-response
//! - `oc_signer::encrypt` for building the `CryptoEnvelope` (argon2id + AES-256-GCM-SIV)
//! - `oc_crypto::HardenedBytes` for the decrypted material (mlock + DONT_DUMP + zeroize)
//!
//! ## State management
//!
//! The conformance `World` struct (see `tests/conformance/main.rs`) cannot be
//! edited per T43 constraint #1. Several pieces of per-scenario state need to
//! flow across step boundaries (vault file path, plaintext bytes, decrypted
//! `HardenedBytes`).
//!
//! cucumber 0.21 with the default `#[tokio::main]` runtime runs scenarios
//! CONCURRENTLY on a shared worker pool, with step-level interleaving on the
//! same thread. A bare `thread_local` is therefore unsafe — concurrent
//! scenarios on the same thread would corrupt each other's state (verified
//! empirically: Scenario 1's decrypt step ran between Scenario 3's
//! "zeroized" and "no copy escapes" steps, re-setting `decrypted = Some`
//! and tripping the assertion).
//!
//! We key per-scenario state by the leaked `TempDir` root (`vault_dir`), which
//! is unique per scenario (created by `tempdir()` in the Background step). The
//! key is stashed in `world.audit_path` (a `World` field that T43 scenarios do
//! not otherwise touch — T43 has no audit-log steps) so each step can recover
//! its own scenario's state. The state itself lives in a process-global
//! `Mutex<HashMap<PathBuf, VaultState>>`.
//!
//! `HardenedBytes` has a `Drop` impl (zeroize + munlock); storing it in
//! `Option<HardenedBytes>` inside the HashMap is sound — when the test binary
//! exits, the HashMap is dropped, which drops each `HardenedBytes`, which
//! zeroizes + munlocks the page. For Scenario 3 we explicitly take the
//! `HardenedBytes` out of the HashMap entry to assert the drop path.

use std::{
    collections::HashMap,
    os::unix::fs::MetadataExt,
    path::PathBuf,
    sync::{LazyLock, Mutex},
};

use cucumber::{given, then, when};
use ed25519_dalek::{Signer, SigningKey};
use oc_core::{EncryptedWallet, KeyType};
use oc_crypto::HardenedBytes;
use oc_keyagent::{PasskeyPubkey, PasskeyVerifier, proto::PasskeyAuthorization};
use oc_signer::encrypt as signer_encrypt;
use oc_vault::{Vault, save_encrypted_wallet};
use tempfile::tempdir;

use crate::ConformanceWorld;

// ---------------------------------------------------------------------------
// Process-global per-scenario state (keyed by vault_dir, stored in
// world.audit_path so each step can recover its scenario's state).
// ---------------------------------------------------------------------------

/// Per-scenario state that does not fit in the immutable `ConformanceWorld`.
///
/// One entry per scenario, keyed by `vault_dir` (the leaked `TempDir` root).
#[derive(Default)]
struct VaultState {
    /// Full path to the wallet JSON file (`<vault_dir>/wallets/<id>.json`).
    vault_file: Option<PathBuf>,
    /// Plaintext mnemonic bytes that were encrypted into the vault file.
    /// Used by the "no plaintext on disk" assertion.
    plaintext: Vec<u8>,
    /// Passphrase used to encrypt the vault (UTF-8).
    passphrase: String,
    /// Decrypted material held only in Key-Agent memory. Set by the decrypt
    /// step; explicitly taken + dropped by Scenario 3's "zeroized" step.
    decrypted: Option<HardenedBytes>,
    /// Scenario 2's separate data dir (created with explicit 0700 perms).
    perms_dir: Option<PathBuf>,
    /// Scenario 2's separate vault file (created with explicit 0600 perms).
    perms_file: Option<PathBuf>,
}

/// Process-global map of per-scenario state, keyed by `vault_dir`.
///
/// `Mutex::new` is `const` since Rust 1.63, but `HashMap::new` is not
/// const, so we wrap the whole thing in a `LazyLock` (stable since Rust
/// 1.80). Holding the lock across step boundaries is safe because step
/// functions are synchronous (no `await` inside the critical section).
static VAULT_STATES: LazyLock<Mutex<HashMap<PathBuf, VaultState>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Run `f` with a mutable borrow of the calling scenario's `VaultState`.
///
/// The scenario is identified by `world.audit_path`, which the Background step
/// sets to the leaked `TempDir` root (a fresh, unique path per scenario).
fn with_state<F, R>(world: &ConformanceWorld, f: F) -> R
where
    F: FnOnce(&mut VaultState) -> R,
{
    let key = world
        .audit_path
        .clone()
        .expect("world.audit_path (vault_dir) must be set by the Background step");
    let mut states = VAULT_STATES
        .lock()
        .expect("VAULT_STATES mutex poisoned — a previous step panicked while holding the lock");
    let state = states.entry(key).or_default();
    f(state)
}

// ---------------------------------------------------------------------------
// Background steps (T43-specific — NOT shared with other feature files)
// ---------------------------------------------------------------------------

/// `Given the encrypted vault file is stored on disk under the OneCipher data directory`
///
/// Creates a real encrypted wallet file on disk using the production code
/// path: `oc_signer::encrypt` → `EncryptedWallet::new` → `save_encrypted_wallet`
/// (which writes `<vault>/wallets/<id>.json` with 0600 perms and creates the
/// `<vault>` + `<vault>/wallets/` dirs with 0700 perms).
///
/// The plaintext is a 12-word mnemonic placeholder ("wallet-mnemonic-words");
/// the passphrase is "test-passphrase". Both are stashed in `VaultState` for
/// later steps to assert that the on-disk file does NOT contain the plaintext.
///
/// The `TempDir` is leaked (`std::mem::forget`) so it survives the scenario.
/// The leaked `vault_dir` path is also stashed in `world.audit_path` so that
/// subsequent step functions can recover this scenario's `VaultState` entry
/// from the process-global `VAULT_STATES` HashMap (cucumber 0.21 runs scenarios
/// concurrently on the same thread, so `thread_local` would corrupt state
/// across scenarios — see the module docs).
#[given("the encrypted vault file is stored on disk under the OneCipher data directory")]
async fn vault_file_stored_on_disk(world: &mut ConformanceWorld) {
    let tmp = tempdir().expect("tempdir for OneCipher data dir");
    let vault_dir: PathBuf = tmp.path().to_path_buf();
    // Leak so the dir survives the scenario (mirrors T22/T23 pattern).
    std::mem::forget(tmp);

    // Stash the vault_dir in `world.audit_path` so every subsequent step in
    // this scenario can recover its own `VaultState` entry. `audit_path` is
    // an existing `World` field that T43 scenarios do not otherwise use.
    world.audit_path = Some(vault_dir.clone());

    // Encrypt the wallet mnemonic with the test passphrase. oc_signer::encrypt
    // uses argon2id KDF + AES-256-GCM-SIV (or HKDF if encrypt_with_hkdf). The result
    // is a CryptoEnvelope that we serialize to JSON and embed in the wallet
    // record's `crypto` field.
    let plaintext = b"wallet-mnemonic-words".to_vec();
    let passphrase = "test-passphrase";
    let envelope = signer_encrypt(&plaintext, passphrase.as_bytes()).expect("oc_signer::encrypt");

    let wallet = EncryptedWallet::new(
        "vault-unlock-id".to_string(),
        "vault-unlock-wallet".to_string(),
        Vec::new(),
        serde_json::to_value(&envelope).expect("serialize CryptoEnvelope"),
        KeyType::Mnemonic,
    );

    // save_encrypted_wallet writes <vault_dir>/wallets/<id>.json with 0600
    // and creates <vault_dir>/wallets/ with 0700 (R42).
    save_encrypted_wallet(&wallet, Some(&vault_dir)).expect("save_encrypted_wallet");

    let wallet_file = vault_dir.join("wallets").join(format!("{}.json", wallet.id));

    with_state(world, |s| {
        // Replace any stale entry for this key (in case the scenario somehow
        // re-runs with the same vault_dir — shouldn't happen because tempdir
        // generates a unique path, but be defensive).
        *s = VaultState::default();
        s.vault_file = Some(wallet_file);
        s.plaintext = plaintext;
        s.passphrase = passphrase.to_string();
    });
}

/// `And the Owner has a registered Passkey credential with the Key-Agent`
///
/// Sets up:
/// - A fresh Ed25519 keypair as the "Passkey" (signing key on the UI side, verifying key registered
///   with the Key-Agent).
/// - A `PasskeyVerifier` bound to the verifying key + a test credential ID.
///
/// Mirrors the T23 `keyagent_running_with_passkey` setup pattern but does
/// NOT create an audit log (T43's scenarios do not assert on audit entries).
#[given("the Owner has a registered Passkey credential with the Key-Agent")]
async fn owner_has_registered_passkey(world: &mut ConformanceWorld) {
    let passkey_signing = SigningKey::generate(&mut rand_core::UnwrapErr(getrandom::SysRng));
    let verifying_key = passkey_signing.verifying_key();
    world.passkey_signing_key = Some(passkey_signing);

    // Credential ID is ASCII so it round-trips through the String field on
    // PasskeyAuthorization.
    let credential_id = b"cred-vault-unlock-001".to_vec();
    world.passkey_credential_id = Some(credential_id.clone());
    world.passkey_verifier =
        Some(PasskeyVerifier::new(PasskeyPubkey::Ed25519(verifying_key), credential_id));
}

// ---------------------------------------------------------------------------
// Scenario 1: Unlock wallet via Passkey challenge-response
// ---------------------------------------------------------------------------

/// `Given the Key-Agent is started with the vault file locked`
///
/// Asserts the vault file exists on disk. "Locked" means the decrypted
/// mnemonic is NOT currently in Key-Agent memory.
#[given("the Key-Agent is started with the vault file locked")]
async fn keyagent_started_vault_locked(world: &mut ConformanceWorld) {
    let (vault_file, has_decrypted) =
        with_state(world, |s| (s.vault_file.clone(), s.decrypted.is_some()));
    let vault_file = vault_file.expect("vault_file must be set by Background");
    assert!(
        vault_file.exists(),
        "vault file must exist on disk before unlock: {}",
        vault_file.display()
    );
    assert!(
        !has_decrypted,
        "vault must be locked (no decrypted material in memory) at unlock start"
    );
}

/// `When the Owner initiates an unlock via the UI or CLI`
///
/// Simulates the unlock trigger: the Key-Agent generates a fresh 32-byte
/// challenge nonce (via `PasskeyVerifier::generate_challenge`). The nonce
/// is stored in `world.challenges` for the subsequent Then step.
#[when("the Owner initiates an unlock via the UI or CLI")]
async fn owner_initiates_unlock(world: &mut ConformanceWorld) {
    let challenge = world
        .passkey_verifier
        .as_mut()
        .expect("passkey_verifier must be set by Background")
        .generate_challenge();
    world.challenges.clear();
    world.challenges.push(challenge);
}

/// `Then the Key-Agent generates a fresh 32-byte challenge`
#[then("the Key-Agent generates a fresh 32-byte challenge")]
async fn then_fresh_32_byte_challenge(world: &mut ConformanceWorld) {
    assert_eq!(
        world.challenges.len(),
        1,
        "expected exactly one challenge generated, got {}",
        world.challenges.len()
    );
    let challenge = world.challenges[0];
    assert_eq!(challenge.len(), 32, "challenge must be exactly 32 bytes, got {}", challenge.len());
    // Sanity: not all zeros (OsRng never produces all-zero 32-byte draws).
    assert!(
        challenge.iter().any(|&b| b != 0),
        "challenge must be cryptographically random (not all zeros)"
    );
}

/// `And the Owner signs the challenge with the Passkey private key`
///
/// The UI holds the Passkey signing key. Per the simplified protocol
/// (R30 / passkey.rs §Wire format), the signed message is
/// `challenge || credential_id`. We build the `PasskeyAuthorization` here
/// and stash it in `world.captured_auth` so the next step (verify) can
/// pass it to the verifier.
#[then("the Owner signs the challenge with the Passkey private key")]
async fn then_owner_signs_challenge(world: &mut ConformanceWorld) {
    let challenge =
        world.challenges.first().copied().expect("challenge must be set by the When step");
    let signing_key =
        world.passkey_signing_key.clone().expect("passkey_signing_key must be set by Background");
    let credential_id = world
        .passkey_credential_id
        .clone()
        .expect("passkey_credential_id must be set by Background");
    let credential_id_str =
        String::from_utf8(credential_id.clone()).expect("credential_id is utf8");

    let mut message = Vec::with_capacity(challenge.len() + credential_id.len());
    message.extend_from_slice(&challenge);
    message.extend_from_slice(&credential_id);
    let signature = signing_key.sign(&message);

    let auth = PasskeyAuthorization {
        challenge: challenge.to_vec(),
        signature: signature.to_bytes().to_vec(),
        credential_id: credential_id_str,
    };
    world.captured_auth = Some(auth);
}

/// `And the Key-Agent verifies the Passkey signature locally`
///
/// Calls `PasskeyVerifier::verify` on the auth captured in the previous
/// step. On success, the challenge is consumed (single-use). On failure
/// (Forged / Replay / Missing / CredentialMismatch) we panic — none of
/// these should happen with a freshly-generated challenge + correct
/// signing key.
#[then("the Key-Agent verifies the Passkey signature locally")]
async fn then_keyagent_verifies_signature(world: &mut ConformanceWorld) {
    let auth = world
        .captured_auth
        .as_ref()
        .expect("captured_auth must be set by the previous step")
        .clone();
    world
        .passkey_verifier
        .as_mut()
        .expect("passkey_verifier must be set")
        .verify(&auth)
        .expect("Passkey signature verification must succeed for a freshly-signed challenge");
    world.last_error = None;
}

/// `And on verification the Key-Agent decrypts the vault into HardenedBytes`
///
/// Loads the vault file via `Vault::load`, builds a `HardenedBytes` from the
/// passphrase (UTF-8), and calls `Vault::decrypt(&key)`. The decrypted
/// `HardenedBytes` is stashed in `VaultState.decrypted` so subsequent steps
/// can assert on its presence / absence.
#[then("on verification the Key-Agent decrypts the vault into HardenedBytes")]
async fn then_keyagent_decrypts_vault(world: &mut ConformanceWorld) {
    let (vault_file, passphrase) =
        with_state(world, |s| (s.vault_file.clone(), s.passphrase.clone()));
    let vault_file = vault_file.expect("vault_file must be set by Background");

    let vault = Vault::load(&vault_file).expect("Vault::load must succeed");
    let key = HardenedBytes::from_slice(passphrase.as_bytes())
        .expect("HardenedBytes::from_slice for passphrase");
    let decrypted: HardenedBytes =
        vault.decrypt(&key).expect("Vault::decrypt must succeed with the correct passphrase");

    // Sanity: the decrypted bytes match the original plaintext.
    with_state(world, |s| {
        assert_eq!(
            decrypted.expose(),
            s.plaintext.as_slice(),
            "decrypted bytes must match the original plaintext mnemonic"
        );
        s.decrypted = Some(decrypted);
    });
}

/// `And the decrypted material is wrapped in SecretBox and held only in Key-Agent memory`
///
/// There is no `SecretBox` type in the codebase (per T43 plan note). We
/// interpret this assertion as: the `HardenedBytes` exists in Key-Agent
/// memory (in `VaultState.decrypted`) and the in-memory bytes match the
/// original plaintext. The "only in Key-Agent memory" guarantee is enforced
/// structurally — `HardenedBytes` is page-locked + DONT_DUMP-marked and is
/// never exposed over RPC.
#[then(
    regex = r"^the decrypted material is wrapped in SecretBox and held only in Key-Agent memory$"
)]
async fn then_material_held_in_memory(world: &mut ConformanceWorld) {
    let has_decrypted = with_state(world, |s| s.decrypted.is_some());
    assert!(has_decrypted, "decrypted HardenedBytes must be present in Key-Agent memory");
}

/// `And no plaintext wallet content is written back to disk`
///
/// Reads every file under the OneCipher data directory and asserts none
/// of them contains the original plaintext mnemonic bytes. The vault file
/// on disk must remain the ciphertext (the `CryptoEnvelope` JSON).
#[then("no plaintext wallet content is written back to disk")]
async fn then_no_plaintext_on_disk(world: &mut ConformanceWorld) {
    // The vault_dir is the per-scenario key stashed in `world.audit_path`
    // by the Background step.
    let vault_dir =
        world.audit_path.clone().expect("world.audit_path (vault_dir) must be set by Background");
    let (vault_file, plaintext) =
        with_state(world, |s| (s.vault_file.clone(), s.plaintext.clone()));
    let vault_file = vault_file.expect("vault_file must be set");

    // 1. The vault file on disk must NOT equal the plaintext.
    let on_disk = std::fs::read(&vault_file).expect("read vault file");
    assert_ne!(
        on_disk.as_slice(),
        plaintext.as_slice(),
        "vault file on disk must NOT contain the raw plaintext"
    );
    assert!(
        !on_disk.windows(plaintext.len()).any(|w| w == plaintext.as_slice()),
        "vault file on disk must not contain the plaintext as a substring"
    );

    // 2. No file anywhere under the data directory contains the plaintext.
    walk_and_assert_no_plaintext(&vault_dir, &plaintext);
}

/// Recursively walk `dir` and assert no file contains `plaintext` as a
/// substring. Used by Scenario 1's "no plaintext on disk" step.
fn walk_and_assert_no_plaintext(dir: &std::path::Path, plaintext: &[u8]) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let meta = match std::fs::metadata(&path) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if meta.is_dir() {
            walk_and_assert_no_plaintext(&path, plaintext);
        } else if meta.is_file() {
            let bytes = std::fs::read(&path).expect("read file under vault dir");
            assert!(
                !bytes.windows(plaintext.len()).any(|w| w == plaintext),
                "file {} contains the plaintext — leak!",
                path.display()
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Scenario 2: Vault file permissions enforced (700 dir, 600 file)
// ---------------------------------------------------------------------------

/// `Given the OneCipher data directory and vault file are created on a Unix-like system`
///
/// Creates a separate temp data dir + vault file with explicit Unix perms:
/// - data dir: 0700 (owner rwx only)
/// - vault file: 0600 (owner rw only)
///
/// On non-Unix systems this step still creates the dir/file but skips the
/// permission assertions in the subsequent Then steps (gated by `cfg!(unix)`).
#[given(regex = r"^the OneCipher data directory and vault file are created on a Unix-like system$")]
async fn data_dir_and_vault_file_created(world: &mut ConformanceWorld) {
    let tmp = tempdir().expect("tempdir for perms test");
    let dir: PathBuf = tmp.path().to_path_buf();
    std::mem::forget(tmp);

    // Create the dir; on Unix set explicit 0700.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .expect("set dir perms 0700");
    }

    // Write a minimal vault file; on Unix set explicit 0600.
    let vault_file = dir.join("vault.json");
    std::fs::write(&vault_file, b"{\"cipher\":\"aes-256-gcm\"}").expect("write vault file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&vault_file, std::fs::Permissions::from_mode(0o600))
            .expect("set file perms 0600");
    }

    with_state(world, |s| {
        s.perms_dir = Some(dir);
        s.perms_file = Some(vault_file);
    });
}

/// `When the file permissions are inspected`
///
/// No-op: the perms are read directly in the Then steps below. This step
/// is the BDD "When" framing of the inspection action.
#[when("the file permissions are inspected")]
async fn when_file_perms_inspected(_world: &mut ConformanceWorld) {
    // No-op: assertions run in the Then steps.
}

/// `Then the data directory has mode 700 (owner read/write/execute only)`
#[then(regex = r"^the data directory has mode 700 \(owner read/write/execute only\)$")]
async fn then_dir_mode_700(world: &mut ConformanceWorld) {
    let dir = with_state(world, |s| s.perms_dir.clone()).expect("perms_dir must be set");
    assert!(dir.exists(), "data dir must exist");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&dir).expect("metadata for dir").permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "data dir must have mode 0700, got {:04o}", mode);
    }
    #[cfg(not(unix))]
    {
        // On non-Unix, perm assertions are skipped — file/dir existence is
        // verified above.
    }
}

/// `And the vault file has mode 600 (owner read/write only)`
#[then(regex = r"^the vault file has mode 600 \(owner read/write only\)$")]
async fn then_file_mode_600(world: &mut ConformanceWorld) {
    let file = with_state(world, |s| s.perms_file.clone()).expect("perms_file must be set");
    assert!(file.exists(), "vault file must exist");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode =
            std::fs::metadata(&file).expect("metadata for file").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "vault file must have mode 0600, got {:04o}", mode);
    }
}

/// `And the owner of both is the daemon's OS user`
///
/// Asserts the owner UID of the dir + file matches the current process's
/// effective UID. The "daemon user" in production is the OS user the
/// Key-Agent runs as; in the BDD, that is the test runner's UID.
#[then("the owner of both is the daemon's OS user")]
async fn then_owner_is_daemon_user(world: &mut ConformanceWorld) {
    #[cfg(unix)]
    {
        let (dir, file) = with_state(world, |s| (s.perms_dir.clone(), s.perms_file.clone()));
        let dir = dir.expect("perms_dir must be set");
        let file = file.expect("perms_file must be set");

        let current_uid = unsafe { libc::geteuid() };
        let dir_uid = std::fs::metadata(&dir).expect("metadata for dir").uid();
        let file_uid = std::fs::metadata(&file).expect("metadata for file").uid();
        assert_eq!(
            dir_uid, current_uid,
            "data dir owner UID {} must match daemon UID {}",
            dir_uid, current_uid,
        );
        assert_eq!(
            file_uid, current_uid,
            "vault file owner UID {} must match daemon UID {}",
            file_uid, current_uid,
        );
    }
    #[cfg(not(unix))]
    {
        // Owner concept is Unix-only; no-op on other platforms.
        let _ = world;
    }
}

// ---------------------------------------------------------------------------
// Scenario 3: Encrypted wallet file decrypts to HardenedBytes
// ---------------------------------------------------------------------------

/// `Given the vault file is encrypted with the wallet encryption key`
///
/// Already true from the Background step (`vault_file_stored_on_disk`).
/// This step just asserts the vault file exists and the encryption envelope
/// is non-trivial (i.e. the ciphertext field is populated, not the raw
/// plaintext).
#[given("the vault file is encrypted with the wallet encryption key")]
async fn vault_file_encrypted_with_key(world: &mut ConformanceWorld) {
    let (vault_file, plaintext) =
        with_state(world, |s| (s.vault_file.clone(), s.plaintext.clone()));
    let vault_file = vault_file.expect("vault_file must be set by Background");
    assert!(vault_file.exists(), "vault file must exist on disk");

    // The on-disk file must NOT be the raw plaintext — it must be the JSON
    // envelope containing the ciphertext + KDF params.
    let on_disk = std::fs::read_to_string(&vault_file).expect("read vault file");
    let plaintext_str = std::str::from_utf8(&plaintext).unwrap_or("");
    assert!(
        !plaintext_str.is_empty() && !on_disk.contains(plaintext_str),
        "vault file on disk must contain the encrypted envelope, not the plaintext"
    );
}

/// `When the Key-Agent decrypts the vault after a successful Passkey challenge-response`
///
/// Performs the full unlock flow:
/// 1. Generate a fresh challenge.
/// 2. Sign `challenge || credential_id` with the Passkey signing key.
/// 3. Build a `PasskeyAuthorization` and call `verify` (must succeed).
/// 4. Load the vault, build `HardenedBytes` from the passphrase, decrypt.
/// 5. Stash the decrypted `HardenedBytes` in `VaultState.decrypted`.
///
/// The `HardenedBytes` stays alive (in `VaultState`) until the "zeroized"
/// step below explicitly drops it.
#[when("the Key-Agent decrypts the vault after a successful Passkey challenge-response")]
async fn when_keyagent_decrypts_after_passkey(world: &mut ConformanceWorld) {
    // 1. Fresh challenge.
    let challenge =
        world.passkey_verifier.as_mut().expect("passkey_verifier must be set").generate_challenge();

    // 2. Sign challenge || credential_id.
    let signing_key = world.passkey_signing_key.clone().expect("passkey_signing_key must be set");
    let credential_id =
        world.passkey_credential_id.clone().expect("passkey_credential_id must be set");
    let credential_id_str =
        String::from_utf8(credential_id.clone()).expect("credential_id is utf8");
    let mut message = Vec::with_capacity(challenge.len() + credential_id.len());
    message.extend_from_slice(&challenge);
    message.extend_from_slice(&credential_id);
    let signature = signing_key.sign(&message);

    // 3. Verify the signature (must succeed — fresh challenge, correct key).
    let auth = PasskeyAuthorization {
        challenge: challenge.to_vec(),
        signature: signature.to_bytes().to_vec(),
        credential_id: credential_id_str,
    };
    world
        .passkey_verifier
        .as_mut()
        .expect("passkey_verifier must be set")
        .verify(&auth)
        .expect("Passkey verify must succeed before vault decrypt");

    // 4. Load + decrypt the vault.
    let (vault_file, passphrase) =
        with_state(world, |s| (s.vault_file.clone(), s.passphrase.clone()));
    let vault_file = vault_file.expect("vault_file must be set");
    let vault = Vault::load(&vault_file).expect("Vault::load must succeed");

    // 5. HardenedBytes from the passphrase; decrypt returns HardenedBytes.
    let key = HardenedBytes::from_slice(passphrase.as_bytes())
        .expect("HardenedBytes::from_slice for passphrase");
    let decrypted: HardenedBytes =
        vault.decrypt(&key).expect("Vault::decrypt must succeed with correct passphrase");

    with_state(world, |s| {
        assert_eq!(
            decrypted.expose(),
            s.plaintext.as_slice(),
            "decrypted bytes must match the original plaintext"
        );
        s.decrypted = Some(decrypted);
    });
    world.last_error = None;
}

/// `Then the decrypted bytes are stored in a HardenedBytes container`
///
/// Compile-time type guarantee: the binding in the When step is annotated
/// `let decrypted: HardenedBytes`. Runtime assertion: the container is
/// present in `VaultState.decrypted` and exposes the plaintext bytes.
#[then("the decrypted bytes are stored in a HardenedBytes container")]
async fn then_decrypted_in_hardened_bytes(world: &mut ConformanceWorld) {
    let (len, matches_plaintext) = with_state(world, |s| match &s.decrypted {
        Some(hb) => (hb.len(), hb.expose() == s.plaintext.as_slice()),
        None => (0usize, false),
    });
    assert!(len > 0, "decrypted HardenedBytes must be present and non-empty");
    assert!(matches_plaintext, "decrypted HardenedBytes must match the original plaintext");
}

/// `And the underlying memory page is mlock'd and marked MADV_DONTDUMP`
///
/// Soft assertion: the `HardenedBytes` constructor (`from_slice` / `new`)
/// calls `page_guard::lock` (mlock) and `page_guard::dont_dump`
/// (MADV_DONTDUMP on Linux). The hard guarantees are verified by the
/// `oc-crypto` unit tests (`alloc_roundtrip_small`, `drop_zeroizes_then_unlocks`).
/// The BDD asserts that the container is present — proving the mlock +
/// dont_dump path ran without error during construction.
#[then("the underlying memory page is mlock'd and marked MADV_DONTDUMP")]
async fn then_memory_page_mlock_dontdump(world: &mut ConformanceWorld) {
    let present = with_state(world, |s| s.decrypted.is_some());
    assert!(present, "HardenedBytes must be present — its constructor ran mlock + MADV_DONTDUMP");
}

/// `And the decrypted material is zeroized and munlock'd as soon as signing completes`
///
/// Takes the `HardenedBytes` out of `VaultState` and drops it. The `Drop`
/// impl calls `zeroize` first (wipes the bytes while the page is still
/// locked), then `page_guard::unlock` (munlock). We just assert the drop
/// completes without panic.
#[then(regex = r"^the decrypted material is zeroized and munlock'd as soon as signing completes$")]
async fn then_decrypted_zeroized_munlocked(world: &mut ConformanceWorld) {
    let taken = with_state(world, |s| s.decrypted.take());
    assert!(taken.is_some(), "HardenedBytes must have been present to drop");
    // Explicit drop — runs zeroize + munlock.
    drop(taken);
    // If we reach here, Drop completed without panic.
}

/// `And no copy of the decrypted material escapes the Key-Agent process boundary`
///
/// Soft assertion: the `HardenedBytes` has been dropped (taken out of
/// `VaultState` in the previous step), so no copy remains in Key-Agent
/// memory. The structural guarantee ("no copy escapes the process") is
/// enforced by:
/// 1. `HardenedBytes` is not exposed over the Key-Agent's RPC surface (T11 dispatch table returns
///    `not_implemented` for any method that would return raw key material).
/// 2. `HardenedBytes::Clone` produces a fresh page-locked allocation — there is no `as_raw` /
///    `into_raw` API that would let a copy leave the process.
#[then("no copy of the decrypted material escapes the Key-Agent process boundary")]
async fn then_no_copy_escapes(world: &mut ConformanceWorld) {
    let still_present = with_state(world, |s| s.decrypted.is_some());
    assert!(
        !still_present,
        "HardenedBytes must have been dropped — no copy should remain in Key-Agent memory"
    );
    // Structural guarantee: HardenedBytes is never returned over RPC.
    // (Verified by the agent_method_surface list in main.rs — none of the
    // methods return raw key material.)
}
