# oc-secret

Unified secret vault with age encryption for OneCipher.

Provides a single interface for managing all sensitive data: wallet mnemonics,
private keys, passwords, TOTP seeds, and encrypted notes. All secrets are
encrypted with [age](https://age-encryption.org/) (X25519 or scrypt
passphrase) and stored as individual files in a directory tree.

## Hard-gate compliance

- **R56:** No `tokio`, `reqwest`, `tungstenite`, `hyper`, `async-std`, or
  `smol` dependencies — synchronous `std` only.
- **R51/R52:** The `age` dependency lives here, NOT in `oc-crypto` (which
  remains zero-I/O, zero network deps).
- All key material flows through `oc_crypto::HardenedBytes` (page-locked +
  zeroized on drop).

## Layout

- `age.rs` — age encryption / decryption wrapper.
- `entry.rs` — `SecretEntry` (encrypted payload + plaintext index metadata).
- `store.rs` — `SecretStore` (directory tree + JSONL index).
- `recipients.rs` — `.age-recipients` file parsing / discovery.
- `totp.rs` — TOTP code generation from otpauth URIs / raw base32 secrets.
- `migrate.rs` — Legacy wallet migration.
- `git.rs` — Git-backed vault sync (skeleton; filled in stage 5).
