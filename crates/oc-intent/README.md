# oc-intent (retired / empty)

This directory is **intentionally empty**. It is NOT a workspace member.

## History

The OneCipher Intent layer (`Intent`, `IntentKind`, `execute_intent`,
`simulate_intent`, …) originally lived in a standalone crate `oc-intent`.
During a workspace "de-wheeling" pass it was merged into
[`crates/oc-netagent/src/intent`](../oc-netagent/src/intent), because
`oc-netagent` is the sole consumer of these types (via `HpxRpcClient`), and
`oc-policy` / `oc-keyagent` must remain independent of the Intent layer.

## Why this directory still exists

It is kept (empty, with `src/`) and listed in the root `Cargo.toml`
`exclude = [..., "crates/oc-intent"]` to avoid breaking historical checkouts
and tooling that may reference the path. It is **not** part of the build.

## What to do

- To change Intent types, edit `crates/oc-netagent/src/intent/*`.
- Do **not** add a `Cargo.toml` here — that would re-introduce a duplicate
  Intent definition and break the build.
