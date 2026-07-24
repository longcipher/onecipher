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
│  │  ┌─────────────┐  ┌──────────────┐  ┌────────────────────┐  │    │
│  │  │ WC v2 Server│  │ x402 Client  │  │ JSON-RPC Server    │  │    │
│  │  │ (WSS relay) │  │ (HTTP 402)   │  │ (loopback UDS)     │  │    │
│  │  └──────┬──────┘  └──────┬───────┘  └─────────┬──────────┘  │    │
│  │         └────────────────┼────────────────────┘              │    │
│  │                          ▼                                    │    │
│  │              ┌───────────────────────┐                        │    │
│  │              │   Intent Engine       │                        │    │
│  │              │   (simulate + review) │                        │    │
│  │              └───────────┬───────────┘                        │    │
│  └──────────────────────────┼────────────────────────────────────┘    │
│                             │ spawn_blocking                          │
│  ┌──────────────────────────▼────────────────────────────────────┐    │
│  │  Signing Core (sync-only, R56-enforced crates)                │    │
│  │  ┌─────────────┐  ┌──────────────┐  ┌────────────────────┐   │    │
│  │  │ Policy v3   │  │ Vault Decrypt │  │ Multi-chain Signer │   │    │
│  │  │ (oc-policy) │  │ (oc-vault)   │  │ (oc-signer)        │   │    │
│  │  │  Cedar DSL) │  │  unlock)      │  │  Cosmos/...)       │   │    │
│  │  └─────────────┘  └──────────────┘  └────────────────────┘   │    │
│  │  ┌─────────────────────────────────────────────────────────┐ │    │
│  │  │ HardenedBytes (mlock + MADV_DONTDUMP + zeroize)         │ │    │
│  │  └─────────────────────────────────────────────────────────┘ │    │
│  │  ┌─────────────────────────────────────────────────────────┐ │    │
│  │  │ Audit Log (append-only JSONL, persistent device key)    │ │    │
│  │  └─────────────────────────────────────────────────────────┘ │    │
│  └─────────────────────────────────────────────────────────────────┘    │
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

### Key Design Decisions

- **Single binary**: `onecipher` embeds both the async runtime (tokio) and the sync signing core. No dual daemons, no UDS IPC between them.
- **Compile-time isolation**: The signing crates (`oc-policy`, `oc-crypto`, `oc-signer`, `oc-vault`) have zero async/network dependencies. CI enforces this via R56.
- **`spawn_blocking` bridge**: async layer calls signing-core via `tokio::task::spawn_blocking`, avoiding reactor blockage.
- **Local First**: All signing and policy evaluation happen locally. The server never touches plaintext private keys.

## Workspace Layout

```
onecipher/
├── bin/
│   └── oc-cli/                 # `onecipher` single binary
├── crates/
│   ├── oc-conformance/         # BDD conformance test crate (cucumber)
│   ├── oc-core/                # Core types, CAIP, error types
│   ├── oc-crypto/              # Memory hardening (mlock, zeroize, page guards)
│   ├── oc-intent/              # Intent layer (simulate + review + execute)
│   ├── oc-keyagent/            # Key-Agent handler logic (sync)
│   ├── oc-netagent/            # Network-Agent (WC v2 server logic)
│   ├── oc-pay/                 # Payment primitives (x402 + MPP settlers)
│   ├── oc-policy/              # Policy Engine v2/v3 (11-step + Cedar DSL)
│   ├── oc-proto/               # Prost proto definitions
│   ├── oc-session-key/         # Multi-chain SessionKeyProvider (EVM/Solana)
│   ├── oc-signer/              # Multi-chain signing
│   ├── oc-vault/               # Wallet vault (filesystem 700/600, .ocbk backup)
│   ├── oc-wallet/              # Wallet operations (key store, policy, migration)
│   └── oc-walletconnect/       # WalletConnect v2 protocol wrapper
├── docs/                       # This documentation
└── Cargo.toml                  # Workspace root
```

## Hard Gates

These are non-negotiable invariants enforced by CI:

| Gate | Rule | Scope | Enforcement |
|------|------|-------|-------------|
| **R56** | No `tokio`, `reqwest`, `tungstenite`, `hyper`, `async-std`, `smol` | `oc-crypto`, `oc-policy`, `oc-session-key` (even as dev-deps) | `cargo tree -p <crate> -e features` |
| **R12** | No TCP symbols (`TcpListener`, `TcpStream`, `AF_INET`) | `onecipher` binary's signing-core code paths | `nm` symbol inspection |
| **R51/R52** | Zero I/O, zero network dependencies | `oc-crypto` | Architecture + review |
| **R55** | Signing core uses sync `std::thread` only | `oc-keyagent` crate | `cargo tree -p <crate> -e features` |
| **R53** | Drop all capabilities except `CAP_IPC_LOCK` | `onecipher` binary (Linux, when enclave enabled) | `sandbox.rs` |

## Crate Dependency Tree

```
oc-signing crates (R56 leaf — zero async/network deps)
├── oc-policy      (declarative + executable policy evaluation)
├── oc-crypto      (HardenedBytes, KeyCache, page guards)
├── oc-signer      (multi-chain signing, HD derivation)
├── oc-vault       (encrypted wallet storage, filesystem perms)
├── oc-wallet      (wallet CRUD, policy store, migration)
└── oc-proto       (prost IPC definitions)

oc-netagent (async — tokio runtime)
├── oc-walletconnect  (WC v2 protocol)
└── oc-signer         (called via spawn_blocking)

bin/oc-cli (single binary)
├── tokio runtime (WC server, x402, JSON-RPC)
├── oc-keyagent (sync signing engine)
└── clap (CLI parsing)
```

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

## Testing Strategy

| Level | Tool | Scope |
|-------|------|-------|
| **Unit** | `#[cfg(test)]` | Per-module, colocated |
| **Property** | `proptest` | Invariant checking (policy engine, CAIP parsing) |
| **Integration** | `tests/` dir | Cross-crate (signing-core → vault → signer) |
| **BDD** | `cucumber` | End-to-end scenarios (conformance crate) |
| **Hard gate** | `cargo tree` + `nm` | R56/R12 enforcement |

```bash
just format    # nightly rustfmt
just lint      # clippy + R56 + cargo sort
just test      # unit + integration
just bdd       # conformance scenarios
just test-all  # everything
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
