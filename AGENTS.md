# OneCipher Agent Instructions

## Scope

This is the OneCipher workspace — a policy-gated, local-key-custody signing
stack fully designed and implemented in accordance with the WalletConnect v2 protocol and the Open Wallet Standard (OWS).

- `bin/` contains binary crates (`oc-cli` → `onecipher`).
- `crates/` contains reusable library crates (`oc-core`, `oc-crypto`, …).

## Workspace Layout

```
.
├── bin/                    # Binary crates
│   └── oc-cli/             # `onecipher` CLI
├── crates/                 # Library crates
│   ├── oc-conformance/     # BDD conformance test crate (cucumber)
│   ├── oc-core/            # Core types, CAIP, error types
│   ├── oc-crypto/          # Memory hardening (mlock, zeroize, page guards)
│   ├── oc-intent/          # Intent framing, execution, simulation
│   ├── oc-keyagent/        # Key-Agent lib (sync std, NO tokio — R56)
│   ├── oc-netagent/        # Network-Agent lib (tokio + WalletConnect v2)
│   ├── oc-pay/             # Payment primitives (x402 + MPP settlers)
│   ├── oc-pay-http/        # HTTP payment client (x402 discovery/fund/pay)
│   ├── oc-paymaster/       # ERC-4337 Paymaster client (gas sponsorship)
│   ├── oc-policy/          # Policy Engine v2/v3 (11-step evaluation)
│   ├── oc-proto/           # prost proto definitions (AgentService IPC)
│   ├── oc-session-key/     # Multi-chain SessionKeyProvider (EVM/Solana)
│   ├── oc-signer/          # Multi-chain signing
│   ├── oc-signing-core/    # Signing engine core (orchestrates oc-signer)
│   ├── oc-vault/           # Wallet vault (filesystem 700/600, .ocbk backup)
│   ├── oc-wallet/          # Wallet operations (key store, policy, migration)
│   └── oc-walletconnect/   # WalletConnect v2 protocol wrapper (relay, crypto)
├── docs/                   # Specification documents
└── Cargo.toml              # Workspace root (pure [workspace] declaration)
```

## Execution Strategy

- Maximize parallelism by dispatching subagents aggressively for independent
  tasks. Consume tokens freely to complete tasks faster.
- When fixing errors, edit files FIRST, wait for the edit to succeed, and
  only THEN run cargo commands to verify. Do not parallelize file edits
  with cargo builds.

## Tool Usage & Commands

- **NEVER execute `cargo` commands in parallel.** Rust's cargo uses strict
  file locks on the `target/` directory — concurrent invocations will fail
  with `Blocking waiting for file lock`.
- ALWAYS run `cargo check`, `cargo build`, or `cargo test` sequentially.
- If the local machine has a `rustc-wrapper` (sccache / kache) configured
  globally but the wrapper binary is missing, prefix cargo commands with
  `RUSTC_WRAPPER= ` to disable the wrapper for that invocation.
- Use `just <recipe>` for common tasks — see `Justfile`.

## Cargo Workspace Rules (Critical)

1. The root `Cargo.toml` is a **pure workspace declaration** — it has no
   `[package]` section. All package metadata lives in `[workspace.package]`
   and is inherited by sub-crates via `version.workspace = true`,
   `edition.workspace = true`, etc.
2. Sub-crates MUST use `workspace = true` for `version`, `edition`,
   `license`, `repository`, `publish`, and `[lints]`.
3. Shared dependencies are declared once in `[workspace.dependencies]` and
   referenced in sub-crates via `dep = { workspace = true }`.
4. Sub-crates MAY add features on top of the workspace dep:
   `tokio = { workspace = true, features = ["full"] }`.
5. When adding a new dependency used by 2+ crates, add it to
   `[workspace.dependencies]` in the root `Cargo.toml` first.
6. Single-crate dependencies may stay inline in the sub-crate's
   `Cargo.toml` (e.g. `uuid`, `criterion`, `bs58`).
7. Never manually type dependency versions for workspace deps; use
   `cargo add <crate> --workspace -p <sub-crate>`.

## OneCipher Hard Gates

These are non-negotiable invariants verified by `cargo tree` inspection
(R56) and binary symbol analysis (R12), supplemented by conformance tests:

- **R56 (dependency isolation):** `oc-crypto`, `oc-policy`, `oc-keyagent`,
  `oc-session-key`, `oc-signing-core` MUST NOT depend on `tokio`,
  `reqwest`, `tungstenite`, `hyper`, `async-std`, or `smol` — even as
  dev-deps. Verified via `cargo tree -p <crate>` inspection.
- **R12 (no TCP in Key-Agent binary):** The `oc-keyagent` release binary
  MUST NOT contain TCP-specific symbols (`TcpListener`, `TcpStream`,
  `AF_INET`). Verified via `nm` symbol inspection of the release binary.
  Generic libc symbols (`bind`, `socket`) are allowed — they're needed for
  UDS, and T12 seccomp filtering enforces the network syscall ban at runtime.
- **R51/R52 (zero I/O in crypto):** `oc-crypto` MUST have zero I/O and zero
  network dependencies.
- **R55 (no tokio in Key-Agent):** The Key-Agent main loop uses sync
  `std::os::unix::net` + `std::thread`, NOT tokio.

## Build Commands

```bash
# Build entire workspace
cargo build --workspace

# Build a specific binary (use --bin, not -p, for bin crates)
cargo build --release --bin onecipher

# Build a specific library crate
cargo build -p oc-crypto

# Check without producing artifacts (faster)
cargo check --workspace --all-targets
```

## Test Commands

```bash
# All unit + integration tests (exclude slow conformance BDD)
cargo test --workspace --exclude oc-conformance

# Conformance BDD scenarios (cucumber-driven, slow)
cargo test -p oc-conformance --test conformance

# All tests
cargo test --workspace --all-features

# Run a single conformance feature
cargo test -p oc-conformance --test conformance -- audit_cli
```

## Lint Commands

```bash
# Format check (requires nightly rustfmt)
cargo +nightly fmt --all -- --check

# Clippy (workspace lints are pedantic + nursery)
RUSTC_WRAPPER= cargo +nightly clippy --all -- -D warnings

# R56 hard gate — verify no forbidden async/network deps in isolated crates
cargo tree -p oc-crypto
cargo tree -p oc-policy
cargo tree -p oc-keyagent

# R12 hard gate — verify no TCP symbols in the release binary (requires build first)
cargo build --release --bin onecipher
nm target/release/onecipher | grep -i tcp   # should return nothing
```

## Justfile Recipes

```bash
just           # list recipes
just format    # cargo sort + cargo +nightly fmt
just fix       # auto-fix clippy warnings
just lint      # fmt check + clippy + cargo sort check
just test      # unit + integration tests (excludes BDD)
just bdd       # conformance BDD scenarios
just bdd-one <name>  # single conformance feature
just test-all  # all tests including BDD
just build     # cargo build --workspace
just check     # cargo check --all-targets --all-features
just ci        # full CI check (lint + test + build)
just docs      # cargo doc --no-deps --open
just setup     # install dev tools (cargo-sort, nightly toolchain)
```

## Engineering Principles

### Rust Implementation Guidelines

1. **Error handling:**
   - Library layer: `thiserror`.
   - Application/CLI layer: `eyre` (currently `oc-cli` uses `thiserror`).
2. **Concurrency:**
   - Key-Agent: sync `std::thread` + `std::os::unix::net` (R55 — NO tokio).
   - Network-Agent: `tokio` + `tonic` (ConnectRPC over UDS).
   - Prefer lock-free patterns where possible; `Mutex` is acceptable for
     low-contention state.
3. **Safety:**
   - `unsafe` is confined to `oc-crypto/src/page_guard.rs` (mlock/madvise)
     and `oc-keyagent/src/sandbox.rs` (seccomp/prctl on Linux).
   - Every `unsafe` block MUST document the safety invariant.
4. **Memory hardening:**
   - Sensitive material (mnemonics, private keys) MUST go through
     `oc_crypto::HardenedBytes` (mlock + MADV_DONTDUMP + zeroize on drop).
   - Never hold sensitive material in `String` or `Vec<u8>` — use
     `HardenedBytes` or `secrecy::SecretBox`.
5. **Logging:**
   - Libraries SHOULD use `tracing` (NOT `println!` / `eprintln!`).
   - The workspace lints allow `print_stdout` / `print_stderr` because some
     modules fully designed and implemented in accordance with the Open Wallet Standard (process_hardening, chain
     deprecation warnings) use `eprintln!` for user-facing diagnostics.
     New code should still prefer `tracing`.

### Key Design Principles

- **Modularity:** Each crate is a standalone library with clear boundaries.
  `oc-crypto` has zero I/O; `oc-keyagent` has zero async runtime.
- **Type Safety:** Strong static typing across interfaces. Newtypes for
  distinguished types (e.g. `PasskeyPubkey`, `SessionKeyId`).
- **Defense in Depth:** Policy engine (pre-signing) + sandbox (runtime) +
  memory hardening (in-process) + audit log (post-hoc).

### Testing Requirements

- **BDD scenarios:** Gherkin features drive the conformance test suite in
  `crates/oc-conformance/` (step definitions in
  `crates/oc-conformance/tests/conformance/steps/`).
- **Unit tests:** Colocate with implementation (`#[cfg(test)]`).
- **Property tests:** Use `proptest` for invariant checking (colocated).
- **Integration tests:** Place in crate-level `tests/`.
- **Hard-gate tests:** R56 (dependency isolation) is verified via
  `cargo tree` inspection; R12 (no TCP symbols) via `nm` symbol analysis
  of the release binary. Conformance tests exercise these in
  `keyagent_sandbox.feature`.

### Common Pitfalls

- Do NOT add `tokio` to `oc-keyagent`, `oc-crypto`, `oc-policy`, or
  `oc-session-key` — R56 hard gate.
- Do NOT hold sensitive material in `String` / `Vec<u8>` — use
  `HardenedBytes`.
- Do NOT use `cargo build -p oc-keyagent` expecting a binary — `oc-keyagent`
  is a library crate only. The sole binary is `onecipher` (from `oc-cli`):
  use `cargo build --bin onecipher`.
- Do NOT introduce `unwrap()` / `expect()` / `panic!` in production code
  paths — the workspace lints allow them (for test code), but code review
  enforces this for non-test code.

## Development Workflow

Use outside-in development for behavior changes:

1. Start with a failing Gherkin scenario driving the conformance suite in
   `crates/oc-conformance/`.
2. Drive implementation with failing crate-local unit tests.
3. Keep `proptest` in the normal `cargo test` loop.
4. Keep cucumber steps thin — route business rules through shared crates.

After each feature or bug fix, run:

```bash
just format
just lint
just test
just bdd
just test-all
```

If any command fails, report the failure and do not claim completion.

## Language Requirement

- Documentation, comments, and commit messages must be English only.
- Code identifiers must be English.
