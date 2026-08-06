# OneCipher Fuzzing

This directory contains [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz)
fuzz targets for the external-input panic surface of OneCipher. These inputs
can be reached from untrusted peers over WalletConnect v2 / HTTP-RPC / UDS.

## Targets

- **`frame_read`** — decodes length-prefixed UDS frames
  (`oc_keyagent::frame::read_frame`) and feeds the payload to the prost
  `KeyAgentRequest` decoder. The 4 MiB frame cap is enforced internally;
  the prost decode is the true panic surface.
- **`caip_parse`** — parses CAIP-2 chain IDs from arbitrary (lossy) UTF-8
  bytes via `oc_core::ChainId::from_str`.
- **`prost_decode`** — decodes raw bytes directly as `KeyAgentRequest` and
  `KeyAgentResponse` prost wire messages.

## Prerequisites

Install cargo-fuzz (requires a nightly toolchain, provided by
`rust-toolchain.toml` at the workspace root):

```sh
cargo install cargo-fuzz
```

## Running

```sh
# run a single target (e.g. frame_read)
cargo +nightly fuzz run frame_read

# or any of the others
cargo +nightly fuzz run caip_parse
cargo +nightly fuzz run prost_decode
```

For an unattended smoke run (a few seconds each) use `--sanitizer` none and a
low iteration count, or run them in CI as a nightly job:

```sh
cargo +nightly fuzz run frame_read -- -max_total_time=60 -print_final_stats=1
```

## Workspace note

`fuzz/` is **intentionally excluded** from the main OneCipher workspace. The
root `Cargo.toml` contains `exclude = ["examples", "fuzz"]`, and `fuzz/`
declares its own empty `[workspace]` table so that `cargo fuzz` (and
`cargo check` inside this directory) operate standalone rather than trying to
join the parent workspace.
