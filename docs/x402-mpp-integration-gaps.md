# x402 / MPP Integration Gaps Identified (2026-08-16)

This document records gaps found while running real x402 (Arc Testnet) and MPP
(Tempo Moderato) payment tests, and tracks the fixes applied to OneCipher.

## Test Summary

| Test | Network | Result | Evidence |
|---|---|---|---|
| x402 exact (EIP-3009) | Arc Testnet (5042002) | ✅ PASS | tx `0x38a531c9...` status=1, AuthorizationUsed + Transfer 10000 units |
| MPP charge | Tempo Moderato (42431) | ✅ PASS | tx `0xa678fb46...` status=1, 2× Transfer + fee log, pathUSD -10000 |

## Gaps Found

### G1. Wallet import/create fails when a chain feature is compiled out — FIXED

**Symptom**: `onecipher wallet import --private-key` (and `wallet create`) fails
with `Xrpl support is not compiled in; rebuild with --features xrpl` because
`derive_all_accounts*` iterates ALL chain types and calls `derive_address` on
the fail-closed `UnsupportedSigner`.

**Root cause**: `derive_all_accounts` (mnemonic) and `derive_all_accounts_from_keys`
(private key) in `crates/oc-wallet/src/ops.rs` do not check whether a chain's
signer is available before deriving.

**Fix** (applied):
- Added `ChainSigner::is_available() -> bool` (default `true`) in
  `crates/oc-signer/src/traits.rs`.
- `UnsupportedSigner` overrides it to return `false` (chains/mod.rs).
- Both derive functions in oc-wallet now `continue` (skip) unavailable chains
  instead of failing the whole import/create.

**Impact**: Wallet import now succeeds without `xrpl`; the xrpl account is
omitted until the binary is rebuilt with `--features xrpl`.

### G2. `sign message --typed-data` requires a dummy `--message` — FIXED

**Symptom**: `onecipher sign message --typed-data <json>` failed with
"the following required arguments were not provided: --message".

**Fix** (applied): `--message` is now `Option<String>` with
`required_unless_present = "typed_data"` (`bin/oc-cli/src/cli.rs`); the handler
(`bin/oc-cli/src/commands/sign_message.rs`) validates that at least one of
`--message` / `--typed-data` is present and uses `message.unwrap_or_default()`
for the non-typed-data path. Verified: `sign message --typed-data <json>`
now works without `--message`, producing the identical signature as before.

### G3. x402 `pay request` assumes a real x402 merchant — OPEN (by design)

The `pay request` command performs the real x402 HTTP flow (402 → EIP-3009
signature → resend). It requires a merchant endpoint that serves the standard
x402 `PaymentRequired` response. This is correct behavior; no fix needed, but
documented for merchant operators.

### G4. Arc native USDC EIP-712 domain is non-standard — DOCUMENTED

Arc's native USDC (ERC-20 interface `0x3600...`) exposes `DOMAIN_SEPARATOR()`
and `eip712Domain()` but the domain parameters do NOT match the common
combinations (name "USD Coin"/"USDC" × version "1"/"2" × chainId 5042002/1 ×
salt). The `transferWithAuthorization` (FiatTokenV2) call succeeded with a
domain derived from `name="USDC" version="2" chainId=5042002` + no-salt, which
was verified on-chain. Operators integrating Arc should verify the domain via
the on-chain `DOMAIN_SEPARATOR()` before production use.

### G5. `cast wallet verify` EIP-712 — TOOLING NOTE

The installed foundry `cast` lacks `wallet verify-typed-data` / `eip712-domain`
subcommands (older build). Verified the onecipher EIP-712 signature by byte
equality with `cast wallet sign --data` (identical output) instead.

## Fixes Applied

| Gap | File(s) | Change |
|---|---|---|
| G1 | `oc-signer/src/traits.rs`, `oc-signer/src/chains/mod.rs`, `oc-wallet/src/ops.rs` | `is_available()` + skip in derive loops + updated test assertion |
| G2 | `bin/oc-cli/src/cli.rs`, `bin/oc-cli/src/commands/sign_message.rs`, `bin/oc-cli/src/main.rs` | `--message` optional when `--typed-data` present |
