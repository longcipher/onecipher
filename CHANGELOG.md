# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] - 2026-08-24

### Added

- Daemon graceful shutdown: SIGTERM/SIGINT/SIGHUP/SIGQUIT feed the shutdown select loop with a bounded grace period and conventional death-by-signal exit status
- Signed policy store: policies are Ed25519-signed on save with a `.sig` sidecar; load verifies fail-closed (legacy unsigned files load with a loud warning)
- EIP-712 typed-data verification in `onecipher verify` (`--typed-data` / `--typed-data-file`, hashed per EIP-712 and verified against the raw digest)
- Real pending nonce fetch via `eth_getTransactionCount` in intent execution
- Persistent backup lockout and backup version validation
- Keyfile version upper bound check
- **signer**: TON wallet v5r1 constants (`WALLET_V5R1_CODE_DEPTH`, `DEFAULT_WALLET_ID`) with extended signer tests
- **signer**: New `HdError` variants and broader HD derivation-path test coverage
- **signer**: Global key cache (`KeyCache<HardenedBytes>`) registered for zeroization on termination signals
- **secret**: `SecretStore`/`StoreConfig` extensions (new error variants, age-identity integration) backing `doctor --repair-generations`
- **secret**: `RecipientsFile` management additions with tests
- **wallet**: Cosmos/Tron/TON broadcast paths in `sign_and_send` plus JSON field extraction helpers
- **policy**: New `PolicyRule` variants (`oc-core`) and `evaluate_rule` coverage in `oc-policy` v1 with tests
- **session-key**: Policy Merkle-root computation (`compute_merkle_root`) for key binding
- **netagent**: `WalletMethodHandler` implementation for `WcMethodRouter`; `HpxRpcClient` extensions
- **CLI**: `doctor --repair-generations` (rebuild the generations floor; unreadable entries reported as `skipped[]`) and `--json` single-source report
- **CLI**: `wallet-rpc` `sign_payment` handler and broadcast audit logging (`log_broadcast`, extended `AuditEntry` fields)
- **CLI**: Reworked `update` flow (latest-tag resolution, binary download, Python bindings refresh) and new clipboard helper
- **CLI**: New subcommand surface (`cli.rs`): `send`, `wallet-rpc serve`, `history`/`git` (git feature), extended `secret`/`totp`/`age`/`policy`/`env`/`fsck` options
- **CI**: New `no-std` job (A13 `oc-signer` host check, thumbv7m experimental), `skill-consistency`, `makefile-mirror`, and `cargo-deny` jobs
- **docs**: New `docs/crypto-unification-roadmap.md` (age-migration stages), `docs/publish-order.md` (leaf-first publish gate), root `SKILL.md` + `skills/onecipher/SKILL.md` (agent contract with JSON schema, exit codes, env table), `deny.toml` (supply-chain gate), `Makefile` (Justfile mirror), `.github/workflows/security.yml` (weekly sweep)
- **docs**: Security-model additions (per-request subprocess-enclave pilot RFC, integrity non-goals) and architecture intent-layer updates
- **keyagent**: Per-request subprocess enclave default-on — every signing request runs decrypt→sign→wipe in a `onecipher --enclave-child` subprocess over a versioned JSON pipe (`oc_version = 1`, `EnclaveRequest`/`EnclaveResponse` with `request_id` correlation); parent keeps UDS/auth/policy-pre-check/audit/rate-limit and never holds decrypted keys; timeout kill (30 s, `OC_ENCLAVE_TIMEOUT_SECS`) with fail-closed mapping and `request_id → pid → sig hash → latency` audit (`EnclavePending`/`EnclaveResolved` events)
- **CLI**: Hidden `--enclave-child` one-shot entry point (internal, spawned by the parent via self re-exec)
- **CLI**: One-shot `sign message` / `sign transaction` owner paths route through the enclave (passphrase-mode pipe credential, prompt-and-retry preserved)
- **CLI**: `wallet-rpc` `keys` / `sign` / `sign_payment` / `intentExecute` signer route through the enclave (read-only key listing uses the side-effect-free `public_key` op)

### Changed

- **BREAKING (age flag day)**: single `age` ciphertext format for wallet files (scrypt passphrase), `.ocbk` backup bundles (multi-X25519-recipient + `ocenv/1` `tag:backup`), and API-token wallet copies (single X25519 recipient; token bytes ARE the static secret, key files store only `token_hash` + `recipient`). Legacy Argon2id+AES-GCM-SIV / Argon2id+XChaCha20 / HKDF+AES-GCM files fail closed and must be recreated — no migration path by design. Unified API: `oc-vault::crypto` (`encrypt_with_passphrase`, `decrypt_with_passphrase`, `encrypt_to_recipients`, `decrypt_with_identity`, `token_identity`, `token_recipient`, `AgeEnvelope`, `AgeIdentity`)
- **BREAKING**: `backup export` requires `--recipient <age1...>` (repeatable); `backup import` takes `--identity <AGE-SECRET-KEY-1...>` (or hidden prompt). The v1 `BackupContainer` format, passphrase lockout sidecar and backoff are gone
- **BREAKING**: `ApiKeyFile` gains required `recipient` (`age1...`); pre-age key files fail closed at parse time
- **BREAKING**: Key-Agent device-key derivation is single-shot HKDF-SHA256 (`UnlockToken::new`); the legacy SHA-256 fallback and `UnlockToken::new_legacy_sha256` are removed — pre-age wallets are unreadable, no compat layer
- Atomic private writes for backups, age identities, and port files
- MADV_WIPEONFORK applied to locked key memory
- Zeroizing hardening across oc-secret
- UDS and RPC timeouts
- wallet-rpc handlers moved to spawn_blocking with error sanitization
- **signer**: EIP-712 `encode_type`/`encode_data`/`encode_atomic` refactor with unchanged test vectors (the interim `validate_envelope_params` dispatch front was superseded by the age flag day below and removed)
- **signer**: Cosmos signer restructure; Bitcoin signer restructure (P2WPKH-only, P2TR inputs fail closed)
- **secret**: `SecretEntry` age-identity error mapping (`MemGuardError`, `AgeError`) and store API reshaping
- **core**: `paths` hardening — atomic/private writes (`write_atomic`, `write_atomic_private`, `unique_tmp_path`), stricter wallet-ID and secret-name validation
- **core**: Chain-type additions; workspace registers `oc-session-key` and documents the `bitcoin` 0.32 keep-rationale (A10: PSBT/sighash stay in audited `rust-bitcoin`)
- **keyagent**: Token-gated decrypt path (`attempt_decrypt_with_token`, `wallet_decrypts_with_token`, `load_chain_key`)
- **keyagent**: All five signing handlers (`SignTransaction`, `SignMessage`, `SignAuth`, `SignTypedData`, `SignUserOp`) route through the enclave by default; in-process decrypt kept behind `OC_ENCLAVE=off` (tests / escape hatch); WC/HTTP-RPC intent Execute inherits enclave isolation via the Key-Agent UDS path
- **keyagent**: Enclave child installs the full sandbox profile (Linux seccomp BPF, macOS Seatbelt, Windows mitigations) and inherits only an env allowlist (`HOME`, `XDG_*`, `TMPDIR`, `OC_STRICT_HARDEN`, Windows loader vars)
- **CLI**: `main` resolves `HOME` once up front and fails closed when unset (no more `/tmp` fallback); shared tokio runtime for commands and daemon
- **CLI**: `update`, `doctor`, `fsck`, `secret`, `totp`, `age_cmd`, `policy`, `env_cmd` rework and output alignment

### Removed

- **BREAKING**: `oc-signer::crypto` deleted entirely (Argon2id+AES-GCM-SIV wallet envelopes, HKDF+AES-GCM token envelopes, `validate_envelope_params`, all KDF param types); `oc-signer` owns signing only
- **BREAKING**: `oc-vault::backup::BackupContainer` deleted (custom Argon2id+XChaCha20 format, `Argon2idParams`, `Locked`/`LockedOut`/`WrongPassphrase` errors, attempts sidecar); replaced by `export_backup`/`import_backup`
- **BREAKING**: workspace deps `aes-gcm-siv` + `argon2` removed (`chacha20poly1305` stays for `oc-walletconnect`, `hkdf` stays for `UnlockToken` + WalletConnect v2); features `oc-signer/fast-kdf` and `oc-vault/test-utils` removed (`oc-vault/fast-kdf` now pins the age scrypt work factor for tests)
- **BREAKING**: `oc-pay` payment-protocol crate deleted (including the leftover `crates/oc-pay/` skeleton); `pay`/`fund`/`ocpay` commands are gone — payment belongs to the sister project `ledgerflow` (OneCipher exposes loopback `wallet-rpc` for it)
- **BREAKING**: Unset `HOME` now exits 1 instead of silently falling back to `/tmp`/`.` for vault, key store, and audit paths
- **BREAKING**: `wallet-rpc` server is opt-in (disabled unless `OC_WALLET_RPC_LISTEN` is set, loopback-only) with fail-closed per-request Passkey auth on signing methods
- **BREAKING**: Bitcoin Taproot (P2TR) inputs fail closed — the signer is P2WPKH-only (BIP-84)
- **BREAKING**: Per-request enclave isolation is default-on — signing spawns `onecipher --enclave-child` via self re-exec (same binary, hidden `--enclave-child` flag); environments that forbid process spawn must set `OC_ENCLAVE=off` explicitly (test-only escape hatch, unsupported in production); enclave children inherit only an env allowlist, so owner secrets must travel via pipe/env-take, not ambient environment
- **BREAKING**: Key-Agent audit log gains `enclave_pending` / `enclave_resolved` event variants (old readers must tolerate unknown `snake_case` variants)

### Fixed

- Policy engine rejects NaN/negative amounts (`InvalidAmount`), persist race fixed, v3 rule-tree depth/size caps
- Web UI path-traversal fix, approval expiry enforcement, bounded WebAuthn challenges
- WalletConnect per-message error containment, sessionUpdate subset enforcement, chain-allowlist dispatch, replay dedup
- `CrossChainTransfer` intents fail closed as unsupported until bridge integration lands
- **CLI**: `doctor` human/JSON reports are single-source (no more divergent views); `fsck --decrypt` validates rotation by re-encrypting all secrets
- **secret**: `doctor --repair-generations` recovers the generations floor from readable secrets instead of failing the whole run
- **keyagent**: `SignTransaction` / `SignUserOp` accept `0x`-prefixed hex payloads (previously rejected as invalid hex — this unblocks WC intent Execute, which sends `0x`-prefixed unsigned bytes)
- **keyagent**: `lock_memory` skips process-wide `mlockall(MCL_FUTURE)` when `RLIMIT_MEMLOCK` is under 64 MiB — a small-but-sufficient limit previously let `mlockall` succeed in fresh (small) processes and then aborted the first multi-megabyte allocation (e.g. enclave-child age buffers) with `ENOMEM`/SIGABRT; the snapshot now honestly reports `memory_locked = false` there

### Security

- Fail-closed `HOME` resolution, atomic private writes, and strict wallet-ID/secret-name validation (`oc-core::paths`)
- Token-gated Key-Agent decrypt path with per-wallet token verification
- `deny.toml` supply-chain gate (advisories/licenses/bans/sources, per-waiver dated rationale) enforced by CI and the weekly `security.yml` sweep (`cargo deny` + `cargo audit`)
- A13 `no_std` pilot gate for `oc-signer` (host must pass; thumbv7m experimental)

## [0.1.0] - 2026-07-24

### Added

- Unified sensitive data vault (private keys, passwords, TOTP, encrypted notes)
- Multi-chain signing: EVM, Solana, Bitcoin, Cosmos, Tron, TON, Sui, Spark, Filecoin, XRPL, Nano, Near
- Policy Engine v2 with 11-step pre-signing evaluation (rate limits, budgets, cooldowns, whitelists, expiry, passkey auth)
- age X25519 encryption at rest (pure Rust, no GPG dependency)
- Memory hardening: HardenedBytes with mlock + MADV_DONTDUMP + zeroize on drop
- Key-Agent daemon: sync std::thread + std::os::unix::net (NO tokio, NO TCP)
- Network-Agent: tokio + WalletConnect v2 relay (WSS)
- Sandbox: seccomp + prctl on Linux (R51/R52)
- Audit log: SHA-256 chained, Ed25519 signed, append-only JSONL
- Session key lifecycle (create, revoke, list) with passkey authorization
- x402 payment protocol support (HTTP client + Key-Agent integration)
- MPP (Micro-Payment Protocol) channel stubs (Phase 1)
- Intent framing, simulation, and execution layer
- Encrypted .ocbk backup with Argon2id key derivation
- Interactive TUI (ratatui + crossterm + arboard)
- Optional git sync for encrypted vault versioning
- BDD conformance test suite (cucumber-rs)
- R56 hard gate: dependency isolation for crypto/policy/keyagent crates
- R12 hard gate: no TCP symbols in release binary
- SBOM verification (CycloneDX)
- CLI with --json output and --stdin input for agent automation
- Legacy wallet migration from ~/.lws and ~/.ows
- Post-quantum cryptography experiments (ml-dsa, ml-kem feature-gated)
