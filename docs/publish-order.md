# Publish Order Gate

> Workspace crates are `publish = false` today (see root `Cargo.toml`
> `[workspace.package]`). If publishing is ever enabled, this document is the
> gate: publish in dependency order, leaf-first, and re-verify the hard gates
> at each step.

## Order (leaf → root)

1. `oc-core`, `oc-crypto` (no workspace deps; R51/R52 + R56 leaves)
2. `oc-policy` (depends on core only; R56 leaf)
3. `oc-signer` (depends on core + crypto; A13 `no_std` pilot — verify
   `cargo check -p oc-signer --no-default-features` before publish)
4. `oc-vault` (depends on core + crypto + signer)
5. `oc-session-key` (depends on crypto + policy + signer; R56 leaf —
   `cargo tree -p oc-session-key` must show no tokio/reqwest/hyper)
6. `oc-keyagent` (depends on core + crypto + signer + vault + wallet; R55/R56 —
   sync only, no tokio)
7. `oc-walletconnect`, `oc-secret` (independent leaves beside the signing core)
8. `oc-netagent` (first tokio crate; `real-rpc` feature wires session-key bridges)
9. `oc-wallet` (operation layer; `rpc`/`sui-grpc` features pull tokio/hpx —
   explicitly NOT an R56 leaf)
10. `oc-webui` (axum; loopback-only per R12c/R12e)
11. `oc-cli` (`onecipher` binary; last)

## Gate checklist per crate

- `cargo tree -p <crate>` shows no forbidden runtime in R56 leaves.
- `rg -n 'TcpListener|TcpStream'` shows nothing in
  `oc-keyagent` / `oc-crypto` / `oc-policy` / `oc-session-key` sources (R12a).
- `deny.toml` waivers (if any) carry dated rationale + expiry.
- `docs/cli-reference.md` + `SKILL.md` updated if the CLI surface changed
  (`scripts/check-skill-consistency.sh` passes).
- `Justfile` + `Makefile` updated together
  (`scripts/check-makefile-mirror.sh` passes).
