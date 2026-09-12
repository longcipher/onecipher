---
name: onecipher
description: Agent-facing contract for the `onecipher` CLI (wallets, signing, secrets, policy, WalletConnect, intents). Use when automating `onecipher` commands, parsing `--json` output, or handling exit codes and error envelopes.
---

# OneCipher Agent SKILL

> Agent-facing contract for the `onecipher` CLI. This file mirrors the
> command table in the root `SKILL.md` (the consistency source) and adds the
> machine-consumable details agents need: JSON output schema, exit codes,
> environment variables, and security warnings.
>
> Every top-level `onecipher <command>` below maps to a `Commands::` variant
> in `bin/oc-cli/src/cli.rs`. The CI job `skill-consistency`
> (`scripts/check-skill-consistency.sh`) fails if a CLI variant is missing
> from the root `SKILL.md` or `docs/cli-reference.md` — change the CLI and
> you MUST update the root `SKILL.md` and the CLI reference in the same PR,
> then mirror any new command into the table below.

## Top-level commands

| Command | Variant | Purpose |
|---|---|---|
| `wallet` | `Wallet` | Create/import/export/delete/rename/list wallets |
| `sign` | `Sign` | Sign message / tx / send-tx / auth |
| `mnemonic` | `Mnemonic` | Generate / derive BIP-39 mnemonics |
| `vanity` | `Vanity` | Brute-force vanity addresses |
| `verify` | `Verify` | Verify a cryptographic signature |
| `policy` | `Policy` | Create/list/show/delete policies |
| `key` | `Key` | Create/list/revoke API keys |
| `config` | `Config` | Show / set configuration |
| `update` | `Update` | Self-upgrade via curl/wget (zero in-process HTTP) |
| `uninstall` | `Uninstall` | Uninstall the binary (optional purge) |
| `audit` | `Audit` | List audit log entries / audit secrets |
| `session-key` | `SessionKey` | Create / revoke / list session keys |
| `status` | `Status` | Key-Agent / Network-Agent status (local) |
| `service` | `Service` | systemd user service install/uninstall/status |
| `vault` | `Vault` | Vault unlock |
| `backup` | `Backup` | Export / import `.ocbk` containers |
| `sbom` | `Sbom` | Verify / generate CycloneDX SBOM |
| `wc` | `Wc` | WalletConnect pair/connect/sessions/disconnect/relay/probe/dapp-send |
| `webui` | `Webui` | Open Web UI / approvals / auth |
| `intent` | `Intent` | Submit / simulate / execute AI intents |
| `secret` | `Secret` | List/get/add/update/delete/rename/edit/copy/move secrets |
| `password` | `Password` | Add / get / generate passwords |
| `totp` | `Totp` | Add / generate / uris / hotp TOTP codes |
| `age` | `Age` | Init / recipient / identity-show / reencrypt |
| `agent-secret` | `AgentSecret` | Agent-mode get / list / totp (token-gated) |
| `env` | `Env` | Run a command with secrets as env vars |
| `migrate` | `Migrate` | Migrate legacy keystore (dry-run / rollback) |
| `grep` | `Grep` | Search inside decrypted secret content |
| `find` | `Find` | Fuzzy-search secrets |
| `tui` | `Tui` | Interactive terminal browser |
| `doctor` | `Doctor` | System health diagnostics |
| `completion` | `Completion` | Shell completion scripts |
| `fsck` | `Fsck` | Secret store integrity check / repair |
| `history` | `History` | Secret version history (`git` feature only) |
| `git` | `Git` | Vault git sync (`git` feature only) |
| `wallet-rpc` | `WalletRpc` | Loopback WalletSigner JSON-RPC server |
| `send` | `Send` | ERC-20 transfer (build, sign, broadcast) |

Notes:

- `history` / `git` exist only in builds with the `git` feature
  (`#[cfg(feature = "git")]` on the `Commands::` variants).
- `onecipher --daemon` (global flag, no `Commands::` variant) starts the
  daemon (Key-Agent + WC v2 server + control socket) instead of running a
  one-shot command.
- Payment-protocol commands (`pay`, `fund`, `ocpay`) were removed: the
  `oc-pay` crate is deleted from this workspace and payment belongs to the
  sister project `ledgerflow`. OneCipher exposes `wallet-rpc` for it.

## Conventions for agents

- Passphrases / tokens via `ONECIPHER_PASSPHRASE` env or interactive prompt,
  never a `--passphrase` flag.
- `--qr` renders half-block QR and never fails the command (plaintext
  fallback on error).
- `intent submit --yes` skips the confirmation prompt; without `--yes` a
  non-terminal stdin cancels gracefully.
- `update` uses external `curl`/`wget` only — no in-process HTTP.
- Prefer `--json` for machine parsing where the subcommand offers it
  (`sign`, `verify`, `secret get/list`, `find`, `grep`, `doctor`, `send`,
  …); human-readable text is the default otherwise.

## JSON output schema

Successful `--json` commands print the result object to stdout. Failures
print a human line to stderr by default:

```text
error: <human-readable message>
```

Set `ONECIPHER_JSON_ERRORS=1` to get a stable machine envelope on stderr
instead (`bin/oc-cli/src/main.rs`):

```json
{ "code": "WALLET_NOT_FOUND", "message": "wallet not found: ..." }
```

`code` is a stable `SCREAMING_SNAKE` string from `CliError::code()`
(`bin/oc-cli/src/cli.rs`). Match on `code`, never on the message text:

| `code` | Meaning |
|---|---|
| `WALLET_NOT_FOUND` | No wallet with that name/ID |
| `AMBIGUOUS_WALLET` | Name matches more than one wallet |
| `WALLET_NAME_EXISTS` | Create with a taken name |
| `INVALID_INPUT` | Bad flag value / malformed argument |
| `BROADCAST_FAILED` | Transaction broadcast rejected |
| `WALLET_ERROR` | Other wallet-layer failure |
| `CHAIN_NOT_SUPPORTED` | Unknown / unsupported chain |
| `CAIP_PARSE_ERROR` | Malformed CAIP-2/CAIP-10 identifier |
| `INVALID_PASSPHRASE` | Wrong vault passphrase |
| `POLICY_DENIED` | Policy engine denied the operation |
| `API_KEY_NOT_FOUND` | Unknown API key ID |
| `API_KEY_EXPIRED` | Expired API key |
| `VAULT_ERROR` | Vault open / decrypt failure |
| `MNEMONIC_ERROR` | Bad mnemonic phrase |
| `HD_ERROR` | HD derivation failure |
| `SIGNER_ERROR` | Signing failure |
| `CRYPTO_ERROR` | Envelope / cipher failure |
| `IO_ERROR` | Filesystem failure |
| `JSON_ERROR` | Malformed JSON input |
| `GIT_ERROR` | Vault git-sync failure (`git` feature) |
| `SECRET_STORE_ERROR` | Secret store failure |
| `RECIPIENT_ERROR` | age recipient failure |
| `MIGRATION_ERROR` | Legacy migration failure |
| `INVALID_ARGS` | CLI usage error |
| `NET_AGENT_UNAVAILABLE` | Key-Agent daemon unreachable and unspawnable |
| `DAEMON_INIT_FAILED` | Daemon failed to start |
| `KEY_AGENT_ERROR` | Key-Agent RPC failure |

## Exit codes

| Code | Meaning | Source |
|---|---|---|
| `0` | Success | `main()` returns `Ok(())` |
| `1` | Every CLI error today | `CliError::exit_code()` — an explicit per-variant match (kept stable by policy; match on the JSON `code`, not the number) |
| `128 + sig` | Daemon killed by signal (129 SIGHUP, 130 SIGINT, 131 SIGQUIT, 143 SIGTERM) | `signal_exit_status()` after graceful-shutdown cleanup |

`HOME` unset is fail-closed (exit 1 before any vault/key/audit path is
resolved), never a silent fallback to `/tmp` or `.`.

## Environment variables

| Variable | Used by | Notes |
|---|---|---|
| `ONECIPHER_PASSPHRASE` | Vault unlock, API-token auth (`agent-secret`) | Cleared from memory immediately after reading; least-secure option (visible in `/proc/[pid]/environ`) — prefer prompt or fd where possible |
| `ONECIPHER_NEW_PASSPHRASE` | `wallet change-password` (new passphrase) | Non-interactive fallback |
| `ONECIPHER_WALLET` | `--wallet` default (`sign`, `send`, …) | Overridden by the explicit flag |
| `ONECIPHER_MNEMONIC` | `wallet import --mnemonic`, `mnemonic derive` | Read instead of stdin |
| `ONECIPHER_PRIVATE_KEY` | `wallet import --private-key` | Read instead of stdin |
| `ONECIPHER_SECP256K1_KEY` / `ONECIPHER_ED25519_KEY` | `wallet import` (explicit both-curves import) | |
| `ONECIPHER_JSON_ERRORS` | All commands | `=1` selects the `{code, message}` stderr envelope |
| `OC_WALLET_RPC_LISTEN` | `onecipher --daemon` | Enables the opt-in WalletSigner server; loopback only (non-loopback rejected) |
| `OC_RPC_LISTEN` | `onecipher --daemon` | Daemon HTTP-RPC listen address |
| `OC_WC_RELAY_URL` / `OC_WC_PROJECT_ID` / `OC_WC_ATTESTATION` | `wc` / daemon relay | Public relay URL, project id, Verify attestation JWT |
| `OC_RPC_URL` | `send`, intent execution | Chain RPC endpoint fallback |
| `OC_PRICE_FEED_URL` | Intent budget checks | No feed → fail-closed |
| `OC_TELEMETRY_LEVEL` / `OC_TELEMETRY_INTERVAL_SECS` | Daemon telemetry | Default `info` |
| `OC_ENCLAVE` / `OC_ENCLAVE_TIMEOUT_SECS` | Per-request enclave isolation | Default on: all signing runs decrypt→sign→wipe in a `onecipher --enclave-child` subprocess (Key-Agent handlers, CLI owner paths, wallet-rpc). `OC_ENCLAVE=off` is the test-only escape hatch (unsupported in production; never a silent downgrade). Timeout default 30 s, kill + fail-closed |

## Security warnings for agents

1. **No secret on the command line, ever.** There is no `--passphrase`
   flag by design; likewise never pass mnemonics, private keys, or API
   tokens as argv (visible via `/proc`, shell history, audit). Use env
   (least preferred), stdin, or interactive prompt.
2. **`wallet export` / `mnemonic` output is live key material.** It
   requires an interactive terminal; `--show-mnemonic` displays once and
   must never be logged, cached, or pasted into tickets.
3. **`agent-secret` is token-gated least-privilege.** The value in
   `ONECIPHER_PASSPHRASE` is an `oc_key_…` API token, not the vault
   passphrase; `SecretPermissions` still apply. A denied read is
   `POLICY_DENIED`, not an error to retry with a stronger credential.
4. **`wallet-rpc` is loopback-only and opt-in.** Disabled unless
   `OC_WALLET_RPC_LISTEN` is set; non-loopback binds are rejected at
   startup; signing methods need per-request Passkey authorization.
   Never proxy it to a public interface.
5. **`env` injects secrets into a child process.** Prefer `--exec` semantics
   awareness, minimal `--name` scope, and never `set -x` / debug-log the
   child environment.
6. **`update` shells out to `curl`/`wget`.** Review the downloaded artifact
   via `sbom verify` before installing in sensitive environments.
7. **Destructive commands need explicit confirmation**
   (`secret delete --force`, `wallet delete --confirm`, `policy delete
   --confirm`, `key revoke --confirm`); `--force` is accepted as an alias
   for `--confirm` on wallet/policy/key deletion (one contract, two
   spellings). There is no undo outside `.ocbk` backups.

## Unified secret handling plane

Wallet keys, passwords, OTP seeds and notes share one mental model
(`SecretKind`: `wallet_key` / `password` / `totp_seed` / `note`), one CRUD
surface (`oc_secret::crud`: create/get/update/delete/rename/copy), one
`--json` envelope and one audit taxonomy. Storage stays split
(`oc-vault` = key bytes, `oc-wallet::ops` = wallet operations,
`oc-secret` = age-encrypted user secrets) — only the handling plane is
unified; crates are not merged.

| Concern | Contract |
|---|---|
| Kind | `SecretKind` in `oc_core::secret`; `secret list --type` accepts the same names |
| Read envelope | `{"name","id","kind","item_type","metadata","generation","payload?"}` from `secret get --json`, `password get --json`, `totp uris --json` |
| Code emitters | `totp generate/hotp [--json]`, `password generate` print the bare code/password (scriptable `$(...)`); `--json` wraps as `{"name","kind","code"}` |
| Render | Listings hide secrets by default (`Report` + `reveal.then()`); `get`/`generate` are the explicit reveal |
| Destructive gate | `secret` family: `--force`; wallet/policy/key: `--confirm` (alias `--force`) |
| Audit ops | Dotted `AuditOp` names (`secret.create`, `password.generate`, `totp.generate`, `wallet.create`, `wallet.sign`, …); signing rides the strong track (`audit-strong.jsonl`), everything else the light track (`audit.jsonl`) |
| OTP | All TOTP/HOTP math lives in `oc_secret::totp` (short 80/96-bit seeds accepted, bare base32 = SHA-1/6-digit/30s); the CLI passes arguments through |
| Passwords | Generation (`cryptic`/`memorable`/`xkcd`) and strength policy live in `oc_secret::password`; in-memory secrets ride page-locked buffers, plain `String` exists only at the `--json` serialization boundary (zeroized on drop) |
