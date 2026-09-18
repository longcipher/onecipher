# OneCipher

[Project Home](https://onecipher.longcipher.com/) | [Documentation](https://book.longcipher.com/onecipher/)

## Target Architecture

OneCipher is the **wallet** in a two-project sibling architecture with
[LedgerFlow](https://github.com/longcipher/ledgerflow). The two projects are
decoupled by responsibility and communicate only through standard protocols:

```text
┌──────────────────────────────────────────────────────────────┐
│  LedgerFlow  (payment protocol + authz layer, sibling repo)  │
│                                                              │
│  x402 / MPP wire protocols  ·  Warrant authz + delegation    │
│  PoP  ·  approval gates  ·  revocation  ·  Facilitator rails  │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  WalletSigner (ledgerflow-wallet) — a WalletSigner     │  │
│  │  consumer via explicit loopback JSON-RPC 2.0 binding   │  │
│  └──────────────────────────┬─────────────────────────────┘  │
└─────────────────────────────┼────────────────────────────────┘
                              │ ledgerflow_sign / ledgerflow_keys
                              │ ledgerflow_sign_payment (base64, JSON-RPC 2.0)
┌─────────────────────────────┼────────────────────────────────┐
│  OneCipher  (this repo) — the WALLET, a WalletSigner         │
│                                                        provider │
│  Key custody · hardened memory · local signing · policy ·     │
│  audit · WebUI approvals                                      │
│  wallet-rpc server: loopback-only, opt-in via env             │
└──────────────────────────────────────────────────────────────┘
```

**Design split (keep this project simple & effective):**

- **OneCipher owns wallet concerns only**: key custody, hardened local
  signing, the policy engine, audit, and human approval flows. It does **not**
  implement payment-protocol logic.
- **LedgerFlow owns payments & authorization**: the x402/MPP wire protocols,
  warrant/delegation/PoP/approval/revocation authz, and settlement routing.
- **Decoupling contract**: OneCipher exposes the LedgerFlow `WalletSigner`
  interface over loopback JSON-RPC 2.0. Clients first call
  `ledgerflow_generate_challenge`, then submit the resulting
  `PasskeyAuthorization` alongside `ledgerflow_keys`, `ledgerflow_sign`, or
  `ledgerflow_sign_payment` via `onecipher wallet-rpc serve`. LedgerFlow calls
  it as a plain `WalletSigner` consumer. There is no compile-time dependency
  between the two repositories.
- **Fail-closed local signer**: the daemon no longer auto-exposes `wallet-rpc`.
  Enable it explicitly with `OC_WALLET_RPC_LISTEN=127.0.0.1:18080`, and each
  signing request must carry a fresh Passkey authorization payload.
- The former `oc-pay` payment-protocol crate was removed; payment protocol
  work now lives entirely in LedgerFlow.

[Project Home](https://onecipher.longcipher.com/) | [Documentation](https://book.longcipher.com/onecipher/)

Policy-gated, local-key-custody signing stack and **unified sensitive data
vault** for AI agents — fully designed and implemented in accordance with the
[WalletConnect v2 Specification](https://specs.walletconnect.com/) and [Open Wallet Standard](https://openwallet.sh) and hardened for production
agent workloads.

OneCipher is more than a wallet: it is a single encrypted vault for private
keys (12 chains), passwords, TOTP secrets, and encrypted notes — all protected
by `age` (pure Rust, no GPG dependency), memory hardening, and the Policy
Engine.

## Why OneCipher

- **Local key custody.** Private keys are encrypted at rest and only decrypted
  inside the Key-Agent process after policy checks pass. Sensitive material
  lives in `mlock`'d, `MADV_DONTDUMP`'d, zeroized memory (`HardenedBytes`).
- **Policy before signing.** An 11-step Policy Engine v2 gates every agent
  operation pre-signing — chain allowlists, amount/budget/rate-limit rules,
  expiry, passkey authorization, and optional custom executables.
- **Hardened Key-Agent.** Sync `std::thread` + `std::os::unix::net` (NO tokio,
  NO TCP — R55/R12). Linux builds add seccomp + prctl sandboxing (R51/R52).
- **Every chain, one interface.** EVM, Solana, Bitcoin, Cosmos, Tron, TON, Sui,
  Spark, Filecoin, XRPL, Nano, Near — first-class via CAIP-2/CAIP-10 addressing.
- **Unified sensitive data vault.** Private keys, passwords, TOTP secrets, and
  encrypted notes share one vault, one policy engine, and one audit log —
  replacing the need for separate `pass`/`ripasso`/OTP apps alongside a wallet.
- **age encryption (pure Rust).** Secrets at rest are encrypted with
  X25519-based `age`, no GPG/system dependency. Multi-recipient support enables
  multi-device access and key rotation via `age reencrypt`.
- **Interactive TUI.** A `ratatui`-based terminal UI (`onecipher tui`) browses
  wallets, secrets, TOTP codes, and audit entries without leaving the vault.
- **AI-agent-friendly CLI.** Every secret command supports `--json` output and
  `--stdin` input so agents can pipe material in/out without prompts.
- **Optional git sync.** Vaults can be versioned and synchronized across hosts
  with `onecipher git pull` / `git push` (encrypted payloads, never plaintext).

## Unified Sensitive Data Vault

OneCipher consolidates several sensitive-data tools into one hardened vault:

| Capability | What it stores | Replaces |
|------------|----------------|----------|
| Private key management | 12 chains: EVM, Solana, Bitcoin, Cosmos, Tron, TON, Spark, Filecoin, Sui, XRPL, Nano, Near | Per-chain key stores |
| Password management | Site credentials with URL + username | `pass` / `ripasso` |
| TOTP two-factor auth | RFC 6238 OTP secrets | Authy / Google Authenticator |
| Encrypted notes | Free-form secret text | Encrypted text files |
| age encryption | X25519 recipients, multi-device | GPG-based encryption |
| Interactive TUI | `ratatui` + `crossterm` + `arboard` | — |
| AI-agent CLI | `--json` / `--stdin` everywhere | — |
| git sync (optional) | Encrypted vault versioning | Manual sync / cloud drives |

All vault entries flow through the same Policy Engine and append-only audit log,
so a TOTP read and a signing operation are governed by one consistent ruleset.

## Workspace Layout

```text
.
├── bin/                    # Binary crates
│   └── oc-cli/             # `onecipher` CLI (sole binary)
├── crates/                 # Library crates
│   ├── oc-core/            # Core types, CAIP, error types
│   ├── oc-crypto/          # Memory hardening (mlock, zeroize, page guards)
│   ├── oc-keyagent/        # Key-Agent lib (sync std, NO tokio — R56)
│   ├── oc-netagent/        # Network-Agent lib (tokio + WC v2 + intent layer)
│   ├── oc-policy/          # Policy Engine v2/v3 (11-step evaluation)
│   ├── oc-secret/          # Secret vault (age-encrypted secrets + TOTP)
│   ├── oc-session-key/     # Multi-chain SessionKeyProvider (EVM/Solana)
│   ├── oc-signer/          # Multi-chain signing
│   ├── oc-vault/           # Wallet vault (filesystem 700/600, .ocbk backup)
│   ├── oc-wallet/          # Wallet operations (key store, policy, migration)
│   └── oc-walletconnect/   # WalletConnect v2 protocol wrapper (relay, crypto)
├── docs/                   # Specification documents
└── Cargo.toml              # Workspace root (pure [workspace] declaration)
```

## Architecture

```text
                    dApps / External Agents
                           │
              WalletConnect v2 relay (WSS)
                           │
┌──────────────────────────────────────────────────────┐
│  Network-Agent (oc-netagent)                         │
│  tokio + WalletConnect v2 relay (waku)               │
│  - WC pairing, session management                    │
│  - JSON-RPC method router → KeyAgentRequest          │
│  - Forwards signing requests to Key-Agent via UDS    │
│           │                                          │
│           │  Unix Domain Socket (prost frames)       │
│           ▼                                          │
│  ┌───────────────────────────────────────────────┐   │
│  │  Key-Agent (oc-keyagent)                      │   │
│  │  sync std::thread + std::os::unix::net (NO tokio)│
│  │  - Policy Engine v2 (pre-signing, 11-step)    │   │
│  │  - Audit log (append-only JSONL, 0600)        │   │
│  │  - Sandbox: seccomp + prctl (Linux)           │   │
│  │  - Passkey authorization                      │   │
│  │  ┌─────────────────────────────────────────┐  │   │
│  │  │  Signing Core (oc-signer + oc-crypto)   │  │   │
│  │  │  - In-process only                      │  │   │
│  │  │  - HardenedBytes (mlock + MADV_DONTDUMP)│  │   │
│  │  │  - Zeroize on drop                      │  │   │
│  │  └─────────────────────────────────────────┘  │   │
│  │  ┌─────────────────────────────────────────┐  │   │
│  │  │  Wallet Vault (oc-vault)                │  │   │
│  │  │  ~/.onecipher/wallets/ (700/600)        │  │   │
│  │  │  .ocbk encrypted backup                 │  │   │
│  │  └─────────────────────────────────────────┘  │   │
│  └───────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────┘

CLI / SDK (oc-cli)
       │
       │  local UDS (same prost frame protocol)
       ▼
   Key-Agent
```

The OneCipher API **never** returns raw private keys.

### Two-layer architecture

The Network-Agent and Key-Agent are **separate internal layers** within the
single `onecipher` binary:

- **Network-Agent** uses tokio + WalletConnect v2 (WSS relay) to receive
  signing requests from dApps and external agents. It translates each
  request into a `KeyAgentRequest` protobuf frame and forwards it to the
  Key-Agent layer via `tokio::task::spawn_blocking`.
- **Key-Agent** uses sync `std::thread` + `std::os::unix::net` (NO tokio,
  NO TCP — R55/R56). It holds the encrypted wallet vault, enforces the
  Policy Engine v2, and performs signing in hardened memory. On Linux,
  seccomp + prctl sandboxing blocks all network syscalls at runtime.

This separation is enforced by the **R56 hard gate**: the Key-Agent crate
tree (`oc-keyagent`, `oc-crypto`, `oc-policy`, `oc-session-key`) MUST NOT
depend on `tokio`, `reqwest`, `tungstenite`, `hyper`, `async-std`, or `smol`
— even as dev-deps. Pulling async/network libraries into the signing layer
would violate the security boundary.

### Unified vault architecture

The unified sensitive-data vault sits above the same hardened core, so
passwords, TOTP secrets, and notes enjoy the same memory and policy
guarantees as private keys:

```text
┌─────────────────────────────────────────────┐
│              onecipher CLI / TUI              │
│         (ratatui + crossterm + arboard)       │
├─────────────────────────────────────────────┤
│            oc-secret (unified vault)          │
│  age encryption │ TOTP │ file tree │          │
│  recipients │ git sync                        │
├──────────┬──────────┬──────────┬─────────────┤
│ oc-core  │ oc-crypto│ oc-policy│ oc-keyagent │
│ types    │ hardened │ policy   │ audit log   │
│          │ memory   │ engine   │             │
├──────────┴──────────┴──────────┴─────────────┤
│  oc-signer (12-chain signing) │ oc-wallet    │
└─────────────────────────────────────────────┘
```

## Hard Gates (Non-Negotiable)

These are non-negotiable invariants verified by `cargo tree` inspection
(R56) and binary symbol analysis (R12), verified by dev-dependency and source scans:

- **R56 (dependency isolation):** `oc-crypto`, `oc-policy`, `oc-keyagent`,
  `oc-session-key` MUST NOT depend on `tokio`, `reqwest`,
  `tungstenite`, `hyper`, `async-std`, or `smol` — even as dev-deps. Verified
  via `cargo tree -p <crate>` inspection.
- **R12 (no TCP in Key-Agent binary):** The `onecipher` release binary
  MUST NOT contain TCP-specific symbols (`TcpListener`, `TcpStream`,
  `AF_INET`). Verified via `nm` symbol inspection of the release binary.
  Generic libc symbols (`bind`, `socket`) are allowed — they're needed for
  UDS, and T12 seccomp filtering enforces the network syscall ban at runtime.
- **R51/R52 (zero I/O in crypto):** `oc-crypto` has zero I/O and zero network
  dependencies.
- **R55 (no tokio in Key-Agent):** Key-Agent uses sync `std::thread` +
  `std::os::unix::net`, NOT tokio.

## Security Design

The unified vault inherits every hardening primitive the signing stack
already enforces:

- **age X25519 encryption (pure Rust).** Secrets at rest are sealed with
  `age` scrypt-based X25519 recipients. There is no GPG dependency, no
  external daemon, and no system trust root beyond the Rust crypto crates.
- **Multi-recipient support.** A single vault entry can be encrypted to
  several `age` recipients, enabling multi-device access. Adding or removing
  a device is a one-shot `age reencrypt` over the whole tree.
- **Memory hardening.** Decrypted material lives in `HardenedBytes`
  (`mlock` + `MADV_DONTDUMP` + `zeroize` on drop), never in plain `String`
  or `Vec<u8>`.
- **Audit log.** Every read, write, sign, and TOTP generation appends a
  tamper-evident record to a SHA-256 chained, Ed25519-signed JSONL log
  (`0600`, append-only).
- **Policy engine.** The 11-step Policy Engine v2 performs both
  **pre-signing** and **pre-read** checks — chain allowlists, amount/budget
  limits, rate limits, expiry, and passkey authorization apply to vault
  reads as well as transactions.
- **R56 hard gate.** `oc-crypto`, `oc-policy`, `oc-keyagent`,
  and `oc-session-key` MUST NOT depend on `tokio`,
  `reqwest`, `tungstenite`, `hyper`, `async-std`, or `smol` — keeping the
  crypto/policy/audit core free of any async runtime or network stack.

## Quick Start

### From source

```bash
# Clone
git clone https://github.com/longcipher/onecipher.git
cd onecipher

# Setup toolchain (nightly for rustfmt/clippy, stable for builds)
just setup

# Build entire workspace
just build

# Build the release binary
cargo build --release --bin onecipher
```

### First-time setup

```bash
# 1. Initialize the age encryption key (one-time)
onecipher age init

# 2. Create a wallet (derives addresses for all 12 chains)
onecipher wallet create --name "agent-treasury"

# 3. Verify everything works
onecipher status
```

### Password management

```bash
# Add a password (hierarchical names with / are supported)
onecipher password add github/personal --url https://github.com --username alice
# → prompts for password interactively

# Add a password with auto-generated password
onecipher password add aws/prod --url https://aws.amazon.com --username admin --generate --length 32

# Retrieve a password
onecipher password get github/personal

# Retrieve and copy to clipboard (auto-clears after 40s)
onecipher password get github/personal --copy

# Generate a standalone random password
onecipher password generate --length 24 --symbols
```

### TOTP two-factor auth

```bash
# Add a TOTP secret via otpauth URI (from QR code or manual setup)
onecipher totp add discord --otpauth "otpauth://totp/Discord:alice?secret=AAAAAAAAAAAAAAAA&issuer=Discord"

# Add a TOTP secret via base32 secret + issuer/account
onecipher totp add github-2fa --secret AAAAAAAAAAAAAAAA --issuer GitHub --username alice

# Generate current TOTP code
onecipher totp generate discord

# Show otpauth URI for backup
onecipher totp uris discord
```

### Encrypted notes & generic secrets

```bash
# Add an encrypted note (hierarchical names supported)
echo '{"secret":"recovery phrase words here"}' | \
  onecipher secret add notes/recovery --type note --stdin

# Add an API key
echo '{"secret":"sk-abc123..."}' | \
  onecipher secret add api-keys/openai --type password --stdin --meta url=https://api.openai.com

# List all secrets
onecipher secret list
onecipher secret list --json       # machine-readable
onecipher secret list --type note  # filter by type

# Retrieve a secret
onecipher secret get notes/recovery
onecipher secret get notes/recovery --json

# Rename a secret
onecipher secret rename notes/recovery notes/recovery-v2

# Delete a secret
onecipher secret delete notes/recovery-v2
```

### Supported secret types

| Type | Use case | Example name |
|------|----------|-------------|
| `password` | Site credentials, API keys | `github/personal`, `aws/prod` |
| `note` | Encrypted free-form text | `notes/recovery`, `notes/ssh-config` |
| `totp` | TOTP seed (use `totp add` shortcut) | `discord`, `github-2fa` |
| `mnemonic` | BIP-39 seed phrases | `wallets/main-mnemonic` |
| `private-key` | Raw private keys | `wallets/evm-key` |

### Signing

```bash
# Sign a message (EVM)
onecipher sign message --wallet agent-treasury --chain ethereum --message "hello"

# Sign on Solana
onecipher sign message --wallet agent-treasury --chain solana --message "hello"

# Sign a Bitcoin transaction
onecipher sign tx --wallet agent-treasury --chain bitcoin --tx "0200000001..."

# Use a bare EVM chain ID (e.g. Base = 8453)
onecipher sign tx --wallet agent-treasury --chain 8453 --tx "02f8..."
```

### WalletConnect

```bash
# Generate a pairing URI (QR-ready)
onecipher wc pair

# Connect to a dApp via pairing URI
onecipher wc connect "wc:<topic>@2?relay-protocol=irn&symKey=..."

# List active sessions
onecipher wc sessions

# Disconnect a session
onecipher wc disconnect --topic <topic>
```

### Age encryption management

```bash
# Show your age public key (for sharing with other devices)
onecipher age identity-show

# Add a recipient (multi-device access)
onecipher age recipient add age1...

# List recipients
onecipher age recipient list

# Re-encrypt vault with current recipients (after key rotation)
onecipher age reencrypt
```

### Migration & maintenance

```bash
# Migrate legacy wallets into the unified vault
onecipher migrate

# Dry-run migration (preview only)
onecipher migrate --dry-run

# Create an encrypted backup
onecipher backup export backup.ocbk

# Restore from backup
onecipher backup import backup.ocbk

# Launch interactive TUI
onecipher tui
```

### Git sync (optional)

```bash
# Pull encrypted vault changes from remote
onecipher git pull

# Push encrypted vault changes to remote
onecipher git push
```

## Development

### Common commands (via `just`)

```bash
just           # list all recipes
just format    # cargo sort + cargo +nightly fmt
just lint      # fmt check + clippy + cargo sort + hard gates
just test      # unit + integration tests
just test-all  # alias for `test`
just build     # cargo build --workspace
just ci        # full CI check (lint + test + build)
just docs      # cargo doc --no-deps --open
just mutants   # full mutation testing (cargo-mutants)
just mutants-incremental  # incremental mutation testing
```

### Direct cargo commands

```bash
# Build
cargo build --workspace
cargo build --release --bin onecipher    # use --bin, not -p, for binaries

# Test
cargo test --workspace --all-features
cargo mutants --workspace --all-features       # mutation testing

# Lint
RUSTC_WRAPPER= cargo +nightly fmt --all -- --check
RUSTC_WRAPPER= cargo +nightly clippy --all --all-targets -- -D warnings
cargo tree -p oc-crypto -e features    # R56 hard gate (no tokio/reqwest/etc.)
cargo tree -p oc-policy -e features
cargo tree -p oc-keyagent -e features
nm target/release/onecipher | grep -i tcp    # R12 hard gate (requires release build)
```

> **Note:** If your local `~/.cargo/config.toml` sets a `rustc-wrapper`
> (e.g. `sccache` / `kache`) but the wrapper binary is missing, prefix cargo
> commands with `RUSTC_WRAPPER=` to disable the wrapper.

### Cargo workspace rules

- Root `Cargo.toml` is a **pure workspace declaration** (no `[package]`).
- Sub-crates inherit `version`/`edition`/`license`/`repository`/`publish`
  via `*.workspace = true`.
- Shared dependencies live in `[workspace.dependencies]` and are referenced
  via `dep = { workspace = true }`.
- Sub-crates MAY add features on top: `tokio = { workspace = true, features = ["full"] }`.
- Use `cargo add <crate> --workspace -p <sub-crate>` to add new workspace deps.
- The sole binary crate lives in `bin/oc-cli/` (package `oc-cli`, binary
  name `onecipher`). Build with `cargo build --bin onecipher`.

## Testing Matrix

- **Unit tests** (`#[cfg(test)]` modules): inner TDD loop, colocated with
  implementation. Run via `just test`.
- **Property tests** (`proptest`): invariant checking, colocated. Runs in the
  normal `cargo test` flow.
- **Integration tests** (`crates/<name>/tests/`): cross-module integration.
- **Mutation tests** (`cargo-mutants`): verify test quality by injecting
  faults. Surviving mutants indicate gaps in coverage or assertions.
  Run via `just mutants` (full) or `just mutants-incremental` (changed only).
- **Hard-gate verification**: R56 verified via `cargo tree -p <crate>`,
  R12 verified via source scans and runtime `lsof` checks.

## Supported Chains

| Chain | Curve | Address Format | Derivation Path |
|-------|-------|----------------|-----------------|
| EVM (Ethereum, Polygon, etc.) | secp256k1 | EIP-55 checksummed | `m/44'/60'/0'/0/0` |
| Solana | Ed25519 | base58 | `m/44'/501'/0'/0'` |
| Bitcoin | secp256k1 | BIP-84 bech32 | `m/84'/0'/0'/0/0` |
| Cosmos | secp256k1 | bech32 | `m/44'/118'/0'/0/0` |
| Tron | secp256k1 | base58check | `m/44'/195'/0'/0/0` |
| TON | Ed25519 | raw/bounceable | `m/44'/607'/0'` |
| Sui | Ed25519 | 0x + BLAKE2b-256 hex | `m/44'/784'/0'/0'/0'` |
| Spark (Bitcoin L2) | secp256k1 | spark: prefixed | `m/84'/0'/0'/0/0` |
| Filecoin | secp256k1 | f1 base32 | `m/44'/461'/0'/0/0` |
| XRPL | secp256k1 | base58check | `m/44'/144'/0'/0/0` |
| Nano | Ed25519 | nano_ + base32 | `m/44'/165'/0'` |
| Near | ED25519 | named account | `m/44'/397'/0'/0'/0'` |

## CLI Reference

| Command | Description |
|---------|-------------|
| `onecipher wallet create` | Create a new wallet with addresses for all chains |
| `onecipher wallet import` | Import a wallet from mnemonic or private key |
| `onecipher wallet export` | Export wallet secret (mnemonic or private key) |
| `onecipher wallet delete` | Delete a wallet from the vault |
| `onecipher wallet rename` | Rename a wallet |
| `onecipher wallet list` | List all wallets in the vault |
| `onecipher wallet info` | Show vault path and supported chains |
| `onecipher wallet change-password` | Change a wallet's encryption passphrase |
| `onecipher sign message` | Sign a message (EIP-191, EIP-712, chain-specific) |
| `onecipher sign tx` | Sign a raw transaction (`--via wc` for WalletConnect) |
| `onecipher sign send-tx` | Sign and broadcast a transaction |
| `onecipher sign auth` | Sign an EIP-7702 authorization |
| `onecipher verify` | Verify a signature (message / typed data / raw hash) |
| `onecipher send` | Build, sign, and broadcast an ERC-20 transfer |
| `onecipher vanity` | Brute-force generate vanity addresses |
| `onecipher mnemonic generate` | Generate a BIP-39 mnemonic phrase |
| `onecipher mnemonic derive` | Derive addresses from a mnemonic |
| `onecipher policy create` | Register a policy from a JSON file |
| `onecipher policy list` | List all registered policies |
| `onecipher policy show` | Show details of a policy |
| `onecipher policy delete` | Delete a policy |
| `onecipher key create` | Create an API key for agent access |
| `onecipher key list` | List all API keys |
| `onecipher key revoke` | Revoke an API key |
| `onecipher session-key create` | Create a session key (via Network-Agent) |
| `onecipher session-key revoke` | Revoke a session key (via Network-Agent) |
| `onecipher session-key list` | List all session keys (via Network-Agent) |
| `onecipher intent submit` | Submit an intent: simulate → confirm → execute |
| `onecipher intent simulate` | Simulate an intent (dry-run) |
| `onecipher intent execute` | Execute an intent programmatically |
| `onecipher audit list` | List audit log entries (`--since`, `--agent`, `--status`) |
| `onecipher audit secrets` | Audit stored passwords (weak/duplicate/old/HIBP) |
| `onecipher vault unlock` | Unlock the vault |
| `onecipher backup export` | Create an encrypted `.ocbk` backup |
| `onecipher backup import` | Restore from an `.ocbk` backup |
| `onecipher sbom verify` | Verify a CycloneDX SBOM file |
| `onecipher sbom generate` | Generate a CycloneDX SBOM for the workspace |
| `onecipher wc pair` | Generate a WalletConnect pairing URI |
| `onecipher wc connect` | Connect to a dApp via WalletConnect pairing URI |
| `onecipher wc sessions` | List saved WalletConnect sessions |
| `onecipher wc disconnect` | Disconnect a WalletConnect session |
| `onecipher wc relay` | Configure the WC v2 relay endpoint |
| `onecipher wc probe` | Probe relay connectivity (subscribe + ping echo) |
| `onecipher wc dapp-send` | Send a JSON-RPC request as a dApp (testing aid) |
| `onecipher webui open` | Open the local Web UI in the browser |
| `onecipher webui approval` | List/show/approve/reject pending approvals |
| `onecipher webui auth` | Query/lock Web UI passkey sessions |
| `onecipher service install` | Install the daemon as a systemd user service |
| `onecipher service uninstall` | Remove the systemd user service |
| `onecipher service status` | Show daemon service status |
| `onecipher status` | Show Key-Agent / Network-Agent status |
| `onecipher config show` | Show current configuration and RPC endpoints |
| `onecipher config set` | Set a configuration value |
| `onecipher update` | Update onecipher to the latest release |
| `onecipher uninstall` | Remove onecipher from the system |
| `onecipher age init` | Initialize the age encryption key |
| `onecipher age identity-show` | Show the age public key |
| `onecipher age recipient add/list/remove` | Manage age recipients for multi-device access |
| `onecipher age reencrypt` | Re-encrypt the entire vault to current recipients |
| `onecipher password add` | Add a password entry (url, username, `--generate`) |
| `onecipher password get` | Retrieve a password (optionally `--copy` to clipboard) |
| `onecipher password generate` | Generate a random password (cryptic/memorable/xkcd) |
| `onecipher totp add` | Add a TOTP secret from an `otpauth://` URI or base32 secret |
| `onecipher totp generate` | Generate the current TOTP code for an entry |
| `onecipher totp uris` | Output the otpauth URI for backup |
| `onecipher totp hotp` | Generate an HOTP code at a counter value |
| `onecipher secret list/get/add/update/delete/rename` | Generic secret CRUD (`--json` / `--stdin`) |
| `onecipher secret edit/copy/move` | Edit in `$EDITOR`, copy, or move secrets |
| `onecipher agent-secret get/list/totp` | Agent-mode reads via API token permissions |
| `onecipher env` | Run a command with secrets injected as env vars |
| `onecipher grep` | Search inside decrypted secret content |
| `onecipher find` | Fuzzy-search secrets by name/type |
| `onecipher fsck` | Check and repair secret store integrity |
| `onecipher history` | Show version history of a secret (`git` feature) |
| `onecipher migrate` | Migrate legacy keystore wallets to age-encrypted secrets |
| `onecipher tui` | Launch the interactive terminal UI |
| `onecipher git init/pull/push/log/status` | Git sync for the encrypted vault (`git` feature) |
| `onecipher doctor` | Run system health diagnostics |
| `onecipher completion` | Generate shell completions (bash/zsh/fish/…) |
| `onecipher wallet-rpc serve` | Expose the loopback JSON-RPC 2.0 WalletSigner |

Payment-protocol commands (`pay`, `fund`, `ocpay`) were removed — payment
protocol work now lives entirely in
[LedgerFlow](https://github.com/longcipher/ledgerflow), which consumes
OneCipher's signing through `wallet-rpc serve`.

## Language Bindings

The Node.js and Python bindings are **fully self-contained** — they embed the
Rust core via native FFI and are published as external packages (not part of
this repository's workspace).

```bash
# Node.js SDK + CLI
npm install @onecipher/core
npm install -g @onecipher/core  # provides `onecipher` CLI
npm install @onecipher/adapters # viem, Solana, WDK adapters

# Python
pip install onecipher
```

## Specification

The full spec lives in [`docs/`](docs/):

| Document | Scope |
|---|---|
| [Quick Start](docs/quickstart.md) | Install, create a wallet, sign, agent access |
| [CLI Reference](docs/cli-reference.md) | Full command reference |
| [Architecture](docs/architecture.md) | Two-layer design, crates, hard gates |
| [Storage Format](docs/storage-format.md) | Vault layout, wallet/API key file formats, encryption |
| [Signing Interface](docs/signing-interface.md) | Sign, signAndSend, signMessage, signTypedData, error codes |
| [Policy Engine](docs/policy-engine.md) | Declarative rules, executable policies, API key crypto |
| [Wallet Lifecycle](docs/wallet-lifecycle.md) | Creation, import, export, backup, deletion |
| [Supported Chains](docs/supported-chains.md) | Chain families, CAIP identifiers, derivation rules |
| [Security Model](docs/security-model.md) | Key isolation, memory hardening, threat model |
| [Sign-in with Wallet](docs/sign-in-with-wallet.md) | Generic IAM integration over WC v2 |
| [Web UI Approval Design](docs/webui-approval-design.md) | Local browser approval flow design |
| [x402/MPP Integration Gaps](docs/x402-mpp-integration-gaps.md) | Live-test findings and fixes |
| [Design](docs/design.md) | Staged architecture evolution notes |

OneCipher-specific design notes live in [`docs/design.md`](docs/design.md).

## Agent Instructions

See [AGENTS.md](AGENTS.md) for the full development guide (workspace layout,
hard gates, build/test/lint commands, engineering principles).

## License

Apache-2.0
