# OneCipher Agent SKILL

> Agent-facing contract for the `onecipher` CLI. This file is the source of
> truth for automation: every top-level `onecipher <command>` below maps to a
> `Commands::` variant in `bin/oc-cli/src/cli.rs`. The CI job
> `skill-consistency` (`scripts/check-skill-consistency.sh`) fails if a CLI
> variant is missing here or in `docs/cli-reference.md` — change the CLI and
> you MUST update this file and the CLI reference in the same PR.

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
| `history` | `History` | Secret version history (git feature) |
| `git` | `Git` | Vault git sync (git feature) |
| `wallet-rpc` | `WalletRpc` | Loopback WalletSigner JSON-RPC server |
| `send` | `Send` | ERC-20 transfer (build, sign, broadcast) |

## Conventions for agents

- Passphrases / tokens via `ONECIPHER_PASSPHRASE` env or interactive prompt,
  never a `--passphrase` flag.
- `--qr` renders half-block QR and never fails the command (plaintext
  fallback on error).
- `intent submit --yes` skips the confirmation prompt; without `--yes` a
  non-terminal stdin cancels gracefully.
- `update` uses external `curl`/`wget` only — no in-process HTTP.

## Unified secret handling plane

Wallet keys, passwords, OTP seeds and notes share one mental model
(`SecretKind`: `wallet_key` / `password` / `totp_seed` / `note`), one CRUD
surface, one `--json` envelope
(`{"name","id","kind","item_type","metadata","generation","payload?"}`),
and one dotted audit taxonomy (`secret.create`, `totp.generate`,
`wallet.sign`, …; signing rides `audit-strong.jsonl`, the rest
`audit.jsonl`). Storage stays split (`oc-vault` bytes /
`oc-wallet::ops` operations / `oc-secret` user secrets) — only the
handling plane is unified. Destructive commands take `--force`
(`secret` family) or `--confirm` with `--force` accepted as an alias
(wallet/policy/key). OTP math and password generation live in
`oc_secret` (library is truth, CLI passes through); `totp
generate`/`hotp` and `password generate` print bare values for
`$(...)` capture unless `--json` is given.
