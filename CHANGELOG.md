# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
