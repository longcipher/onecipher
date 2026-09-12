# Crypto Unification Roadmap — COMPLETE (`age` flag day)

> All three legacy cipher stacks now converge on `age` envelopes. This
> migration shipped as a BREAKING flag day: no backward compatibility, no
> migration path, no dual readers. Legacy files fail closed at parse time.

## Unified stacks (current)

| # | Owner | Mechanism | Envelope | Status |
|---|---|---|---|---|
| 1 | Wallet files (`EncryptedWallet.crypto`) | age scrypt passphrase | `AgeEnvelope { cipher: "age", ciphertext: base64 }` | CURRENT |
| 2 | `.ocbk` backup bundles | age multi-X25519-recipient + `ocenv/1` (`tag:backup`) | pretty-printed `AgeEnvelope` JSON | CURRENT |
| 3 | API-token wallet copies (`ApiKeyFile.wallet_secrets`) | age single-X25519-recipient (token bytes ARE the static secret) | `AgeEnvelope` JSON per wallet | CURRENT |
| — | `oc-secret` entries | age (X25519 + scrypt) + `ocenv/1` (`tag:secret`) | `.age` files | UNCHANGED |

Unified API: `oc-vault::crypto` (`encrypt_with_passphrase`,
`decrypt_with_passphrase`, `encrypt_to_recipients`, `decrypt_with_identity`,
`token_identity`, `token_recipient`, `AgeEnvelope`, `AgeIdentity`,
`CryptoError`). Backup bundles: `oc-vault::{export_backup, import_backup}`.

Rules from here on:

- DO NOT add a second cipher/KDF combo. There is exactly one envelope.
- Every `decrypt` path validates the `cipher == "age"` tag FIRST, then
  base64-decodes and age-decrypts. Anything else fails closed as
  `InvalidParams` — never coerced.
- The token plaintext is shown once at creation; key files store only
  `token_hash` + `recipient` (the `age1...` public key).

## Token recipient model

Each API token (`oc_key_<64 hex>`, 32 random bytes) maps deterministically
to an X25519 identity: the bytes are bech32-encoded as an
`AGE-SECRET-KEY-...` string and parsed back (`token_identity`). At creation
the wallet secret is age-encrypted to the derived recipient
(`token_recipient`, stored in the key file). At use time the presented token
must re-derive the stored recipient (constant-time compare) before the copy
is decrypted — a token from a different key cannot decrypt the copy even
with disk access.

## What was deleted (Stage4 completion)

- Stack 1: `oc-signer::crypto` (`encrypt`/`decrypt` Argon2id+AES-256-GCM-SIV,
  `validate_envelope_params`, `KdfParams`/`HkdfKdfParams`/`KdfParamsVariant`/
  `CipherParams`) — the entire module is gone; `oc-signer` owns signing only.
- Stack 2: `oc-vault::backup::BackupContainer` (Argon2id+XChaCha20-Poly1305,
  `Argon2idParams`, magic/version header, persistent lockout sidecar,
  backoff overrides, `Locked`/`LockedOut`/`WrongPassphrase` errors).
- Stack 3: `oc-signer::crypto::encrypt_with_hkdf`/`decrypt_hkdf`
  (HKDF-SHA256+AES-256-GCM-SIV); `UnlockToken::new_legacy_sha256` and the
  Key-Agent legacy-SHA256 fallback.
- Deps: `aes-gcm-siv` + `argon2` removed from the workspace
  (`chacha20poly1305` stays for `oc-walletconnect`; `hkdf` stays for
  `oc-core::UnlockToken` and the WalletConnect v2 protocol).
- Features: `oc-signer/fast-kdf` removed; `oc-vault/fast-kdf` now pins the
  age scrypt work factor for tests; `oc-vault/test-utils` removed with the
  backup lockout helpers.
- In-memory-only HKDF is NOT a stack and stays: `oc-core::UnlockToken::new`
  (device-key derivation feeding the age scrypt input) and
  `oc-walletconnect` (WalletConnect v2 session keys, protocol-mandated).

## History (superseded stages)

- Stage4 (validator front: `validate_envelope_params` + dual dispatch +
  deprecation headers): RETIRED with the flag day — the validator and both
  dispatch arms are deleted, not extended.
- Stages A/B/C (detector, dual-reader, gradual migration): SUPERSEDED —
  the flag day replaced the gradual rollout; there is no `--to-age` flag,
  no `NeedsMigration` error, and no legacy reader.
