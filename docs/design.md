# Design

> OneCipher design document — staged evolution of the architecture, storage, and cryptographic primitives.

## Stage 0–3: Architecture Retrospective

### Stage 0 — Security Foundations
Fixed critical security vulnerabilities: empty-password signing paths,
Passkey verification stubs, x402 amount parsing, audit log keys, and
CLI client connections. Established the HardenedBytes memory-hardening
contract and the R56 dependency isolation hard gates.

### Stage 1 — Unified Binary
Merged the dual-process architecture (Key-Agent + Network-Agent) into a
single `onecipher` binary. Created the signing-core facade (the
`oc-signer` crate; formerly referenced as `oc-signing-core`) and used
`tokio::task::spawn_blocking` for async→sync bridging. The Key-Agent
runs as a sync `std::thread` with UDS; the WC v2 server runs on tokio.

### Stage 2 — AI Agent Native Features
- **Intent Layer (`oc-netagent::intent`):** Declarative intent framing,
  simulation, and execution for Pay/SignTransaction/SignMessage/CrossChainTransfer.
- **Paymaster (`oc-pay`):** ERC-4337 gas abstraction via sponsor strategies.
- **Real Session Keys:** ERC-7579 (EVM) and Session Tokens (Solana).
- **Policy v3:** Cedar-like DSL with permit/forbid rules.
- **CLI integration:** `onecipher intent`, `onecipher pay` commands.

### Stage 3 — TEE + Cross-Chain (Planned)
Documented but not yet implemented: TEE-based subprocess enclave,
cross-chain routing via ERC-7683, and Cedar-policy full integration.

## Stage 4 — Unified Secret Vault (age + TUI)

### 4.1 Motivation

- The current architecture is wallet-specific, with three parallel encryption stacks running side by side: Argon2id + AES-GCM-SIV for wallets, Argon2id + XChaCha20 for `.ocbk` backups, and HKDF + AES-GCM for API tokens.
- The goal is to unify these into a general-purpose secret vault that supports private keys, passwords, and TOTP secrets.
- Inspiration: ripasso (one file per secret + directory-tree namespaces + git integration) and sops (age with multiple recipients).
- age is chosen as the single encryption layer: pure Rust, no system gpg dependency, native multi-recipient support, and interoperable with rage.

### 4.2 Core Types

- `ItemType` enum: `Mnemonic` / `PrivateKey` / `Password` / `Totp` / `Note` / `File`.
- `SecretEntry` struct: `id` / `name` / `item_type` / `created_at` / `updated_at` / `metadata` / `encrypted_payload`.
- `SecretPayload` struct (post-decryption): `secret` / `notes` / `extra`.
- `KeyType` remains compatible (`Mnemonic` / `PrivateKey` are subsets of `ItemType`).

### 4.3 age Encryption Architecture

- Key model: an age X25519 master identity (`~/.onecipher/keys/age-identity.txt`) plus a `.age-recipients` file listing multiple recipients.
- Passphrase fallback: age scrypt mode (for devices without a local identity).
- Encryption flow: read `.age-recipients` → `age::Encryptor::for_recipients` → write the age envelope.
- Decryption flow: `age::Decryptor` → try the local identity → on failure, prompt for a passphrase.
- No sops-style data key wrapping; age's native multi-recipient stanza is sufficient.

### 4.4 On-Disk Format

- Directory layout: `~/.onecipher/secrets/` tree structure, with leaf nodes as `.age` files.
- `.age-recipients`: one bech32 age public key per line, with support for per-subdirectory overrides.
- Single-file format: standard age binary envelope (no custom header).
- Decrypted payload: JSON `{ "secret", "notes", "extra" }`.
- TOTP: the `otpauth://` URI is stored in the `secret` field.
- Index: `~/.onecipher/index.jsonl` (plaintext metadata + an Ed25519 signature) to enable fast search.

### 4.5 Crate Split

- New `oc-secret` crate: `age.rs` / `entry.rs` / `store.rs` / `recipients.rs` / `totp.rs` / `migrate.rs` / `git.rs`.
- Dependencies: `age` / `totp-rs` / `oc-core` / `oc-crypto` / `oc-keyagent` (audit) — all synchronous, R56-compliant.
- `oc-vault`: generalize the `Vault` wrapper; reuse `BackupContainer`.
- `oc-wallet`: remove the duplicated `vault.rs`; route `decrypt_signing_key` through `oc-secret`.
- `oc-policy`: extend with `read_secret` / `write_secret` operations.
- `oc-keyagent`: extend audit `EventType` with `SecretRead` / `SecretWritten` / `SecretDeleted` / `SecretMigrated` / `AgeRecipientAdded` / `AgeReencrypted`.

### 4.6 TUI Design

- Framework: `ratatui` + `crossterm`.
- Layout: search box + tree list + status bar.
- Key bindings: `j`/`k` move, `/` search, `Enter` open, `n` new, `e` edit, `d` delete, `c` copy (auto-clear after 40s), `t` TOTP, `g` git, `q` quit.
- State: an `App` struct holds `entries` / `filtered` / `selected` / `mode` / `clipboard_clear_at` / `totp_codes`.
- The TUI shares the `oc-secret` library with the CLI; feature parity is enforced.

### 4.7 CLI Design (AI-Agent Friendly)

- `secret list/get/add/update/delete/rename` (`--json` / `--stdin`).
- `password add/get/generate`.
- `totp add/generate/uris`.
- `age init/recipient add/list/identity show/reencrypt`.
- `migrate legacy-wallets`.
- `git pull/push/log`.
- `tui` launch.
- Global `--json` flag, `--stdin` input, exit-code semantics (`0` / `1` / `2` / `3` / `4`).
- API token mode is extended to cover secret operations.

### 4.8 Migration and Backward Compatibility

- Progressive migration: `.json` → `.age`, with legacy files retained read-only.
- `migrate --rollback` reverts the migration.
- The `EncryptedWallet` format remains supported for compatibility.

### 4.9 Implementation Roadmap

- Phase 1: type layer + `oc-secret` crate + age integration + BDD.
- Phase 2: CLI `secret` / `password` / `totp` commands + policy/audit extension.
- Phase 3: migration + `oc-wallet` refactor + `oc-vault` generalization.
- Phase 4: TUI (`ratatui`).
- Phase 5: git sync (`libgit2`).
- Phase 6: AI Agent extension (API token + policy + daemon).

### 4.10 Hard-Gate Constraints

- **R56**: `age` / `totp-rs` / `arboard` are synchronous libraries and MUST NOT transitively pull `tokio` / `reqwest`; `ratatui` / `crossterm` are confined to `oc-cli`. `git2` (libgit2 + libssh2 + OpenSSL) is synchronous and R56-compliant, but is gated behind the optional `git` feature of `oc-secret` so that environments without a working libssh2 toolchain can still build the release binary.
- **R51/R52**: `oc-crypto` stays zero-I/O; `age` MUST NOT be added to `oc-crypto`.
- **R55**: `oc-keyagent` remains tokio-free.
- **R12**: The release binary MUST NOT contain TCP-specific symbols (`TcpListener`, `TcpStream`, `AF_INET`). Phase 1-6 changes add only file I/O, terminal rendering, and (optionally) libgit2 sync — no direct TCP code paths. Verified via `nm` symbol inspection.
- **Memory hardening**: `SecretPayload.secret` MUST use `HardenedBytes`.

### 4.11 Feature Flags

| Crate | Feature | Default | Description |
|-------|---------|---------|-------------|
| `oc-secret` | `git` | off | Enables the `oc_secret::git` module (libgit2 sync). When disabled, `SecretStore` auto-commit is a no-op and the `onecipher git` subcommand is unavailable. |
| `oc-cli` | `git` | on | Forwards to `oc-secret/git`. Enables the `onecipher git` subcommand. Disable with `--no-default-features` for environments without libssh2. |
| `oc-wallet` | `rpc` | off | Enables hpx/tokio RPC client (R56: keeps `oc-keyagent` clean). |
| `oc-wallet` | `sui-grpc` | off | Enables Sui gRPC verification. |

## §6 Component Design References

### §6.1 Intent Layer (`oc-netagent::intent`)
The Intent Layer provides a declarative interface for AI agents to
express signing and payment intentions (e.g. "pay 10.5 USDC to 0xABC
on Base") without constructing raw transactions. Intents flow through
three stages: **Simulated** (pre-flight `eth_call` + `eth_estimateGas`
to produce a human-readable summary), **Confirmed** (user/Passkey
approves the summary), and **Executed** (signed and broadcast,
optionally via the Paymaster for gasless transactions).

Key types: `Intent`, `IntentKind` (`Pay` / `SignTransaction` /
`SignMessage` / `CrossChainTransfer`), `IntentStatus`, `IntentResult`,
`IntentSummary`, `MessageEncoding`.
Key functions: `simulate_intent`, `execute_intent`.

`simulate_intent` and `execute_intent` both take an `&dyn RpcClient`
trait object. `oc-netagent::intent` stays decoupled from the Key-Agent by
depending only on this `RpcClient` abstraction (gas estimation, tx
construction, `send_raw_transaction`, receipt polling); real RPC
implementations are supplied by `oc-netagent`. `execute_intent` builds
an unsigned EIP-1559 transaction and forwards it through the RPC
client — it does not sign directly. `MockRpcClient` backs unit tests.

### §6.2 Session Keys (`oc-session-key`)
Session keys enable delegated signing for AI agents without exposing
the master key. EVM uses ERC-7715 `grantPermission` on an ERC-7579
SCA; Solana uses the Session Tokens program. Per R21, the crate
defines the `SessionKeyProvider` trait unifying `grant` /
`verify_active` / `revoke` / `sign_with` across chains. Per R56, the
crate MUST NOT depend on tokio / reqwest / tungstenite / hyper /
async-std / smol — it uses native `async fn` (edition 2024) returning
runtime-agnostic `Pin<Box<dyn Future>>` futures; the caller
(Net-Agent) supplies the executor.

Phase 1 ships `EvmSessionKeyProvider` (`evm.rs`) and
`SolanaSessionKeyProvider` (`solana.rs`), both backed by the
`MockRpcClient` in `rpc.rs`. Phase 2 (`real.rs`) defines the
`EvmRpcClient`, `EvmBundlerClient`, and `SolanaRpcClient` traits for
injectable real providers; the real on-chain RPC implementations
(alloy / solana-client) are wired up in `oc-netagent`.

Key types: `SessionKeyProvider`, `GrantReceipt`, `KeyScheme`,
`OwnerKey`, `PublicKey`, `SessionPrivateKey`, `SignPayload`,
`Signature`, `SolanaInstruction`.
Key function: `derive_session_key_id` — format
`sk-{chain_namespace}-0x{8-byte hash}`, where the hash is the first
8 bytes of `SHA-256("onecipher-session-key" || session_pubkey || chain_id)`.

**Deviation note (R74 YAGNI):** Phase 1/2 use SHA-256 for the Merkle
root and session-key ID derivation instead of keccak256. keccak256
lives in `oc-netagent` where the alloy dependency is available; the
real Merkle tree + ABI encoding is a Phase 2+ concern.
