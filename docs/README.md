# OneCipher Documentation

> Cross-platform, cross-chain cryptographic wallet for AI Agent workloads.
> Fully implemented in Rust. Designed in accordance with the WalletConnect v2 protocol and the Open Wallet Standard.

## Quick Start

- [Quick Start](quickstart.md) — install, create a wallet, sign your first transaction
- [CLI Reference](cli-reference.md) — full command reference

## Architecture

- [Architecture](architecture.md) — system design, crate structure, hard gates

## Protocol Specifications

- [Storage Format](storage-format.md) — vault structure, wallet/API key file formats, encryption
- [Signing Interface](signing-interface.md) — sign, signMessage, signTypedData, error codes
- [Policy Engine](policy-engine.md) — declarative rules, executable policies, API key cryptography
- [Wallet Lifecycle](wallet-lifecycle.md) — create, import, export, backup, recovery, deletion
- [Supported Chains](supported-chains.md) — CAIP identifiers, derivation paths, chain families

## Security

- [Security Model](security-model.md) — key isolation, memory hardening, threat model, conformance requirements

## Specification

OneCipher is a local-first wallet specification for encrypted wallet storage, signing operations, policy enforcement, and multi-chain account derivation.

The key words `MUST`, `MUST NOT`, `SHOULD`, `SHOULD NOT`, and `MAY` in the specification documents are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

### Normative Core

| Document | Scope |
|---|---|
| [Storage Format](storage-format.md) | Vault directory, wallet/API key file formats, encryption |
| [Signing Interface](signing-interface.md) | Core signing operations, error handling |
| [Policy Engine](policy-engine.md) | Access model, policy rules, evaluation semantics |
| [Wallet Lifecycle](wallet-lifecycle.md) | Creation, import, export, backup, recovery |
| [Supported Chains](supported-chains.md) | Chain families, identifiers, derivation paths |

### Optional Profiles

| Document | Scope |
|---|---|
| [Security Model](security-model.md) | Key isolation, memory hardening, conformance |

### Reference Implementation

| Document | Scope |
|---|---|
| [Architecture](architecture.md) | Rust crate structure, design decisions |
| [CLI Reference](cli-reference.md) | Command-line interface |
| [Quick Start](quickstart.md) | Getting started guide |

## Specification Versioning

- Wallet file schema: `oc_version = 2`
- Policy schema: `version = 1`

## Extension Rules

- New chain families MAY be added with a stable CAIP-2 namespace, deterministic derivation path, and address encoding rule.
- Policy engines MAY add namespaced declarative rule types but MUST reject unknown unnamespaced rule types.
- Files MAY include additional metadata fields; unknown fields MUST be preserved during non-destructive updates.
