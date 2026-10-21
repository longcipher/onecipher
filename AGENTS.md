# OneCipher Agent Instructions

## Non-negotiables

- Surgical edits only: every changed line must trace to the request. No drive-by refactors, no reformatting untouched code, no deleting pre-existing dead code (mention it instead).
- Fix root causes. Never silence a warning, weaken a check, or patch a symptom to make a gate pass.
- Never report completion while any `just` gate below fails. Report the failure verbatim and stop.
- Stop and ask when a request is ambiguous, conflicts with existing conventions, or requires credentials, publishing, or destructive operations.
- When a correction reveals a missing rule, add one specific rule here ("always X for Y", never "be careful with Y"); delete rules that never catch real errors.

## Scope

- OneCipher is a policy-gated, local-key-custody signing stack built to the WalletConnect v2 protocol and the Open Wallet Standard. It is pre-1.0: the workspace sets `publish = false`, so there is no backward-compatibility guarantee.
- `crates/` holds the library crates: `oc-core` (types, CAIP, paths), `oc-crypto` (memory hardening), `oc-policy` (policy engine v1/v2/v3), `oc-keyagent` (Key-Agent), `oc-netagent` (Network-Agent, WalletConnect v2, intent layer), `oc-walletconnect` (WC v2 protocol wrapper), `oc-secret` (age-encrypted user secrets + TOTP), `oc-vault` (on-disk keyfile format), `oc-wallet` (wallet operations), `oc-session-key` (multi-chain session keys), `oc-signer` (multi-chain signing), `oc-siwx` (Sign-In With X), `oc-webui` (approval queue HTTP server). `bin/oc-cli` is the `onecipher` binary.
- `extension/` is the WXT + React browser extension (OCWP client); `fuzz/` is a separate cargo-fuzz workspace; `reproducer/` builds the dual-target reproducer; `crates/oc-webui/frontend` is its own Leptos/WASM workspace and is NOT a member of the root workspace.
- Storage boundary is authoritative and the three crates must not be merged or cross-called: `oc-vault` owns *how* bytes are stored on disk (0700 dir / 0600 file, `.ocbk` age bundle), `oc-wallet` owns *what* wallet operations do, `oc-secret` owns *user* secrets and never holds keys. `oc-wallet::key_store` API tokens are not user secrets and stay in `oc-wallet`.
- The payment-protocol layer was removed from this workspace and is owned by the sibling project LedgerFlow. OneCipher is a pure wallet that exposes a loopback JSON-RPC 2.0 `WalletSigner` server (`onecipher wallet-rpc`, disabled unless `OC_WALLET_RPC_LISTEN` is set); signing methods on that surface require per-request Passkey authorization. The Intent types live in `crates/oc-netagent/src/intent`; the retired `oc-intent` crate is gone.
- English only in code, comments, docs, and commit messages.

## Execution

- Parallelize aggressively: dispatch subagents for independent research, exploration, and implementation.
- NEVER run two `cargo` commands concurrently, and never overlap file edits with a running `cargo` command (`target/` file lock): finish edits, wait, then run.
- NEVER use `git worktree`. Edit the current branch in place.
- TDD for behavior changes: failing crate-local test first, smallest change to pass, then run `just mutants` and fix surviving mutants.

## Verification loop

After each feature or bug fix, in order; any failure means the task is not done:

```bash
just format
just lint
just test
just mutants
```

`just mutants` is this repo's mutation-testing recipe. CI does not call `just`; it runs the same cargo commands job by job, so `just lint` must stay equivalent to those jobs.

## Workspace rules

- Hard gates, all non-negotiable:
  - **R56 (dependency isolation):** `oc-crypto`, `oc-policy`, `oc-keyagent` and `oc-session-key` must not depend on `tokio`, `reqwest`, `tungstenite`, `hyper`, `async-std` or `smol`, not even as dev-dependencies. Verified with `cargo tree`.
  - **R12 (no TCP in isolated crates):** R12a forbids `TcpListener`/`TcpStream` in the isolated crates' sources (`just r12-check`). R12b allows TCP in the `onecipher` daemon (Web UI + WC relay). R12c requires every daemon bind to be `127.0.0.1` only. R12d enforces this at runtime with a seccomp BPF filter that denies `connect(2)`/`bind(2)` to non-UDS sockets. R12e makes the daemon refuse to start the Web UI on a non-loopback address.
  - **R51/R52:** `oc-crypto` performs zero I/O and has zero network dependencies.
  - **R55:** the Key-Agent main loop is sync `std::os::unix::net` + `std::thread`, never tokio.
- The Justfile is a strict mirror of the `Makefile`: every recipe must have a `make` target with the same command body, and `scripts/check-makefile-mirror.sh` enforces it in CI. Change both files in the same PR; adding, renaming or editing a recipe without its Makefile twin breaks CI.
- Changing the CLI surface means updating `SKILL.md` and `docs/cli-reference.md` in the same change (`just skill-check`).
- Every `deny.toml` skip or ignore needs a dated rationale, an owner and an expiry; a bare waiver is a policy failure.
- The duplicate-dependency gate is a ratchet, not a zero-duplicates rule: the baseline only ever moves down. Lower it in the same change that removes a duplicate.
- `unsafe` is confined to the low-level modules: `oc-crypto/src/page_guard.rs` (mlock/madvise), `oc-keyagent/src/{sandbox,enclave,hardening,socket_guard,server}.rs` (seccomp, prctl, socket checks), `oc-core/src/{paths,config}.rs`, `oc-signer/src/{mnemonic,process_hardening}.rs` and `oc-netagent/src/{rpc_client,intent/hot_path}.rs`. Every `unsafe` block documents its safety invariant; the other crates keep `#![forbid(unsafe_code)]`.
- Sensitive material must live in `oc_crypto::HardenedBytes` (mlock + `MADV_DONTDUMP` + zeroize on drop) or `secrecy::SecretBox`, never in `String` or `Vec<u8>`.

## Dependency choices

- Errors: `thiserror` in the library crates, `eyre` in the binaries. Never `anyhow`.
- Observability: `tracing` for new code; the workspace allows `print_stdout`/`print_stderr` because some user-facing diagnostics still use `eprintln!`.
- `hpx` is the HTTP client and it must use the pure-Rust rustls backend. Linking BoringSSL (hpx's `boring-tls`) together with OpenSSL (webauthn-rs) makes the linker resolve `-lcrypto` to the wrong library and breaks the build; that collision is why the TLS stack is fixed on rustls.
- `dashmap` is used for the Web UI approval queue and session table and inside `oc-policy` v2; `std::sync::Mutex` is acceptable for low-contention state.
- `prost` is the protobuf wire codec for the Key-Agent frame, the Network-Agent, the WalletSigner RPC and the CLI. There is no `tonic` in this tree.
- `bitcoin` 0.32 is kept on purpose and its feature set is minimal (`base64` only): do not enable extra features without a security review.
- `unsafe`-free crates should keep `#![forbid(unsafe_code)]` where the crate allows it.

## Code conventions

- Atomic writes: anything that overwrites a secret-bearing file goes through `oc_core::paths::write_atomic_private`. Never `fs::write` a secret.
- Symlinks: `fs::metadata` and `Path::exists` follow symlinks. Use `symlink_metadata` when verifying ownership or mode of a path that must not be a symlink; `oc_keyagent::socket_guard` is the reference pattern.
- Socket paths are predictable: verify the socket directory and node (type, owner, no group/other access) before binding and before connecting. Never weaken `oc_keyagent::socket_guard::verify_socket_file`.
- Plaintext on disk: decrypted secrets must never be staged in the shared temp directory. `secret edit` uses the in-memory editor, or stages inside the 0700 state directory and zero-fills plus unlinks afterwards.
- Exit codes: leaf failures carry a stable SCREAMING_SNAKE code so `main` can pick a distinct BSD sysexits status through `CliError::code` and `exit::exit_code_for`. Keep distinguishable variants separate (`NotFound` is 66, `InvalidName`/`Tampered` are 65).
- Blocking accepts: a blocking `accept()` ignores a cooperative stop flag, so the Key-Agent accept loop keeps the listener non-blocking and polls. Do not make that loop blocking again.
- Signal handling: register the handler *before* announcing the wait, otherwise a signal arriving in between beats the cleanup.
- Anything that prompts must check `is_interactive_stdin()` and either fall back to a non-interactive path or abort with a clear message; `OC_NONINTERACTIVE` forces the non-interactive answer by design.
- Store names: `--store <NAME>` / `ONECIPHER_STORE` selects `<home>/stores/<NAME>`. The name is validated by `validate_store_name` (which reuses `oc_core::paths::validate_wallet_id`) before it reaches the environment, so an invalid name never becomes a path.
- Threat model: OneCipher does not protect against an attacker running code as the same UID. It does protect against co-resident users on a shared system (data dir, agent socket and socket dir are 0700/0600 and verified before use). Do not widen the latter without flagging it.
- Fuzz targets live in `fuzz/` and cover the frame reader, CAIP parsing, prost decoding and SIWx parsing. Property tests use `proptest` and are colocated in the crate they exercise.
