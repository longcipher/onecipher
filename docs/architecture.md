# Architecture

> OneCipher system design, Rust crate structure, and compile-time security guarantees.

## Overview

OneCipher is a **single-binary, cross-chain, AI Agent Native** cryptographic wallet implemented in Rust. The `onecipher` binary embeds both an async runtime (tokio) for network communication and a sync-only signing core for key operations.

```
┌──────────────────────────────────────────────────────────────────────┐
│                    onecipher (single binary)                          │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐    │
│  │  tokio runtime (async layer)                                  │    │
│  │  ┌─────────────┐  ┌──────────────────────────┐               │    │
│  │  │ WC v2 Server│  │ Control Socket            │               │    │
│  │  │ (WSS relay) │  │ (UDS, line protocol)      │               │    │
│  │  └──────┬──────┘  └───────────┬──────────────┘               │    │
│  │         └─────────────────────┘                                │    │
│  │                          ▼                                     │    │
│  │              ┌───────────────────────┐                         │    │
│  │              │   Intent Engine *     │                         │    │
│  │              │ (CLI-only, off hot    │                         │    │
│  │              │  path — see footnote) │                         │    │
│  │              └───────────┬───────────┘                         │    │
│  │              * dashed = CLI-only (`intent` cmd); WC/HTTP-RPC    │    │
│  │                hot path forwards directly to Key-Agent via      │    │
│  │                UDS frames, NOT through `execute_intent`.        │    │
│  └──────────────────────────┼─────────────────────────────────────┘    │
│                             │ UDS frames (KeyAgentRequest)            │
│  ┌──────────────────────────▼────────────────────────────────────┐    │
│  │  Key-Agent thread (sync std::thread, R55/R56-enforced crates) │    │
│  │  ┌─────────────┐  ┌──────────────┐  ┌────────────────────┐   │    │
│  │  │ Policy v3   │  │ Vault Decrypt │  │ Multi-chain Signer │   │    │
│  │  │ (oc-policy) │  │ (oc-vault)   │  │ (oc-signer)        │   │    │
│  │  │  rule tree) │  │  unlock)      │  │  Cosmos/...)       │   │    │
│  │  └─────────────┘  └──────────────┘  └────────────────────┘   │    │
│  │  ┌─────────────────────────────────────────────────────────┐ │    │
│  │  │ HardenedBytes (mlock + MADV_DONTDUMP + zeroize)         │ │    │
│  │  └─────────────────────────────────────────────────────────┘ │    │
│  │  ┌─────────────────────────────────────────────────────────┐ │    │
│  │  │ Audit Log (append-only JSONL, persistent device key)    │ │    │
│  │  └─────────────────────────────────────────────────────────┘ │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                                                      │
│  CLI subcommands (clap): wallet · sign · secret · password · totp ·  │
│  age · tui · wc · webui · intent · policy · key · audit · ...        │
└──────────────────────────────┬───────────────────────────────────────┘
                               │ WSS (outbound)
                               ▼
                  ┌─────────────────────────┐
                  │  WalletConnect Relay    │
                  └──────────┬──────────────┘
                             │ WSS
          ┌──────────────────┼──────────────────┐
          ▼                  ▼                  ▼
  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
  │  Web dApp    │  │ Mobile dApp  │  │  AI Agent    │
  └──────────────┘  └──────────────┘  └──────────────┘
```

> **Note:** The ConnectRPC-over-UDS server was abolished in v0.4. The sole external interface is now WalletConnect v2 (WSS relay). The control socket accepts CONNECT/PAIR commands for pairing URI injection.

### Key Design Decisions

- **Single binary**: `onecipher` embeds both the async runtime (tokio) and the sync Key-Agent thread. No dual daemons — the tokio layer reaches the Key-Agent via UDS frames (`KeyAgentRequest`).
- **Compile-time isolation**: The signing crates (`oc-policy`, `oc-crypto`, `oc-signer`, `oc-vault`) have zero async/network dependencies. CI enforces this via R56.
- **`spawn_blocking` bridge**: async layer calls signing-core via `tokio::task::spawn_blocking`, avoiding reactor blockage.
- **Local First**: All signing and policy evaluation happen locally. The server never touches plaintext private keys.
- **Intent Layer is CLI-only**: `oc-netagent::intent` (`simulate_intent`/`execute_intent`) is NOT on the production hot path. The WC v2, HTTP-RPC, and WalletSigner flows forward directly to the Key-Agent via UDS `KeyAgentRequest` frames; wiring Intent in is tracked behind an opt-in feature (see Integration status below).

> **Daemon module layout:** daemon lifecycle lives in `bin/oc-cli/src/daemon/`
> (`mod.rs` lifecycle + control socket), extracted from `main.rs`. Signal
> handling is split: one-shot commands use exiting signal handlers, while the
> daemon uses a signal notifier feeding its graceful-shutdown `select!` loop
> (`SIGTERM`/`SIGINT`/`SIGHUP`/`SIGQUIT`) with panic-hook cleanup.

## Workspace Layout

```
onecipher/
├── bin/
│   └── oc-cli/                 # `onecipher` single binary
├── crates/
│   ├── oc-core/                # Core types, CAIP, error types
│   ├── oc-crypto/              # Memory hardening (mlock, zeroize, page guards)
│   ├── oc-keyagent/            # Key-Agent handler logic (sync)
│   ├── oc-netagent/            # Network-Agent (WC v2 + intent layer)
│   ├── oc-policy/              # Policy Engine v2/v3 (11-step + Cedar-like rule tree)
│   ├── oc-secret/              # Secret vault (age-encrypted secrets + TOTP)
│   ├── oc-session-key/         # Multi-chain SessionKeyProvider (EVM/Solana)
│   ├── oc-signer/              # Multi-chain signing
│   ├── oc-vault/               # Wallet vault (filesystem 700/600, .ocbk backup)
│   ├── oc-wallet/              # Wallet operations (key store, policy, migration)
│   ├── oc-walletconnect/       # WalletConnect v2 protocol wrapper
│   └── oc-webui/               # Web UI HTTP server (approval queue, WebAuthn auth, static dashboard)
├── docs/                       # This documentation
└── Cargo.toml                  # Workspace root
```

## Hard Gates

These are non-negotiable invariants enforced by CI:

| Gate | Rule | Scope | Enforcement |
|------|------|-------|-------------|
| **R56** | No `tokio`, `reqwest`, `tungstenite`, `hyper`, `async-std`, `smol` | `oc-crypto`, `oc-policy`, `oc-session-key` (even as dev-deps) | `cargo tree -p <crate> -e features` |
| **R12** | No TCP in isolated crates; loopback-only binds in the daemon | `oc-keyagent`, `oc-crypto`, `oc-policy`, `oc-session-key` sources; `onecipher` daemon | Five sub-rules: **R12a** source isolation — isolated crate sources must not contain `TcpListener`/`TcpStream` (`rg 'TcpListener\|TcpStream'`); **R12b** the daemon binary MAY contain TCP symbols (axum/hyper for the Web UI HTTP server and WC relay); **R12c** any daemon `TcpListener` must bind `127.0.0.1` exclusively (`lsof -iTCP -sTCP:LISTEN`); **R12d** at runtime the Key-Agent's seccomp BPF filter denies `connect(2)`/`bind(2)` to non-UDS sockets; **R12e** a non-loopback `[webui] listen` address is rejected at startup and the Web UI server refuses to start. **Note (macOS):** `apply_signing_thread_sandbox` skips Seatbelt on macOS (process-wide would kill WSS); network isolation falls back to source scan + `lsof`, not kernel enforcement. Full isolation requires out-of-process enclave (future) |
| **R51/R52** | Zero I/O, zero network dependencies | `oc-crypto` | Architecture + review |
| **R55** | Signing core uses sync `std::thread` only | `oc-keyagent` crate | `cargo tree -p <crate> -e features` |
| **R53** | Drop all capabilities except `CAP_IPC_LOCK` | `onecipher` binary (Linux, when enclave enabled) | `sandbox.rs` |

## Crate Dependency Tree

```
oc-signing core crates (R56 leaf — zero async/network deps)
├── oc-policy      (declarative + executable policy evaluation)
├── oc-crypto      (HardenedBytes, KeyCache, page guards)
├── oc-signer      (multi-chain signing, HD derivation)
├── oc-vault       (encrypted wallet storage, filesystem perms)
└── oc-session-key (SessionKeyProvider — native async fn, runtime-agnostic)

oc-wallet (operation layer — MAY carry tokio via the `rpc`/`sui-grpc` features)
└── wallet CRUD, key store, policy store, migration, broadcast

oc-netagent (async — tokio runtime)
├── oc-walletconnect  (WC v2 protocol)
└── oc-signer         (called via spawn_blocking)

bin/oc-cli (single binary)
├── tokio runtime (WC v2 server, Control Socket UDS)
├── oc-keyagent (sync std::thread signing engine, R55)
└── clap (CLI: wallet · sign · secret · password · totp · age · tui · wc · webui · intent · policy · key · audit · ...)
```

> **R56 scope clarification (M6):** the R56 hard gate (no tokio/reqwest/
> tungstenite/hyper/async-std/smol) applies to the **signing core** crates
> `oc-crypto`, `oc-policy`, `oc-keyagent`, `oc-session-key` — and, per
> `ci/check_deps.sh`, `oc-signer`/`oc-vault` are also kept clean. `oc-wallet`
> is the **operation layer** and is explicitly allowed to carry tokio/hpx via
> its `rpc`/`sui-grpc` features (default on). It is NOT an R56 leaf.

## Design Principles

| Principle | Meaning |
|---|---|
| **Least privilege + compile-time isolation** | The signing core crate has zero async/network deps; CI enforces via `cargo tree` |
| **Local First** | All signing, policy evaluation completed locally; server only stores encrypted blobs |
| **AI Agent Native** | Intent-based execution, real session keys, Paymaster gas abstraction |
| **Zero-knowledge server** | Server never touches plaintext private keys or mnemonics |
| **Single binary deployment** | One `onecipher` binary — no daemon management for users |

## Signing Flow

```
1. Request arrives (CLI command or WC v2 JSON-RPC)
2. If daemon mode: forward to SigningEngine via spawn_blocking
3. SigningEngine verifies unlock token (not expired)
4. If agent token (ows_key_): evaluate all attached policies (AND semantics)
5. If owner passphrase: skip policy evaluation (sudo access)
6. If denied → return POLICY_DENIED (key material never touched)
7. Decrypt wallet secret into HardenedBytes (mlock'd, zeroized on drop)
8. Derive chain-specific signing key (HD derivation or direct)
9. Sign payload
10. Zeroize all key material
11. Return signature
```

> **Integration status (updated):**
>
> - **Sandbox IS enforced at runtime.** The daemon calls
>   `apply_signing_thread_sandbox()` on the dedicated Key-Agent thread before
>   accepting requests (fail-closed on error). Linux seccomp is per-thread,
>   so the tokio relay is unaffected; macOS skips Seatbelt deliberately
>   because `sandbox_init` is process-wide and would sever the WSS relay.
> - **Policy v2 is wired into the WC router** behind an opt-in file:
>   `~/.onecipher/wc-policy.json` (a serialized `PolicyV2`). When the file is
>   present, chain-whitelist and expiry rules deny non-conforming requests
>   and contract/chain-unspecified checks surface as warnings on the approval
>   card. When absent, the daemon logs a loud startup warning — absence is an
>   explicit operator choice, not a silent bypass. The Key-Agent itself still
>   does not depend on `oc-policy` (R56 layering); enforcement lives at the
>   network boundary.
> - **Session keys are real state**: `CreateSessionKey` persists a record;
>   `RevokeSessionKey` flips it; signing requests carrying a revoked id are
>   rejected (`E_SESSION_KEY`) before key material is touched.
> - **Passkey unlock is stable-secret based**: the vault passphrase derives
>   from the device key (v2 HKDF, legacy SHA-256 fallback for pre-v2
>   wallets); the verified Passkey challenge/signature is purely the
>   authorization gate. Every passkey-gated path enforces the
>   passkey↔wallet binding.
> - Policy v3 remains a hand-rolled Cedar-*like* rule tree gated behind the
>   `experimental-v3` feature (off by default).
> - **Intent Layer:** `oc-netagent::intent` is CLI-only (`onecipher intent simulate/execute`); the WC, HTTP-RPC, and WalletSigner hot paths forward directly to the Key-Agent via UDS frames, not through `execute_intent`. `simulate_intent`/`execute_intent` are exercised only by unit tests and `HpxRpcClient::native_price_usd` remains a stub. Wiring the Intent Layer into the signing path is tracked behind an explicit opt-in feature to avoid breaking existing dApp clients.

## Testing Strategy

| Level | Tool | Scope |
|-------|------|-------|
| **Unit** | `#[cfg(test)]` | Per-module, colocated |
| **Property** | `proptest` | Invariant checking (policy engine, CAIP parsing) |
| **Integration** | `tests/` dir | Cross-crate (signing-core → vault → signer) |
| **Mutation** | `cargo-mutants` | Verify test quality via fault injection |
| **Hard gate** | `cargo tree` + `rg` + `lsof` | R56/R12 enforcement |

```bash
just format    # nightly rustfmt
just lint      # clippy + R56 + cargo sort
just test      # unit + integration
just mutants   # mutation testing (cargo-mutants)
just test-all  # alias for `just test`
just ci        # full CI check
```

## References

- [WalletConnect v2 Specification](https://specs.walletconnect.com/)
- [Open Wallet Standard](https://openwallet.sh)
- [ERC-4337: Account Abstraction](https://eips.ethereum.org/EIPS/eip-4337)
- [ERC-7579: Modular Smart Contract Accounts](https://eips.ethereum.org/EIPS/eip-7579)
- [ERC-7715: Session Keys](https://eips.ethereum.org/EIPS/eip-7715)
- [ERC-7683: Cross-Chain Intent](https://eips.ethereum.org/EIPS/eip-7683)
- [Cedar Policy Language](https://www.cedarpolicy.com/)
- [x402 Payment Protocol](https://x402.org/)
