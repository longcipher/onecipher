# CLI Reference

> Command-line interface for the `onecipher` Rust binary.

## Install

Build from source:

```bash
git clone https://github.com/longcipher/onecipher.git
cd onecipher
cargo build --release --bin onecipher
```

The binary is at `target/release/onecipher`. Prebuilt Node.js and Python
packages are also available (see the README's [Language
Bindings](../README.md#language-bindings)).

Global flags: `--daemon` starts the daemon (Key-Agent + WC v2 server +
control socket) instead of running a one-shot command.
`onecipher --version` reports the release version and git commit.

Passphrases and API tokens are supplied via `ONECIPHER_PASSPHRASE` or an
interactive prompt, never a dedicated `--passphrase` flag.

## Wallet Commands

### `onecipher wallet create`

Create a new wallet. Generates a BIP-39 mnemonic and derives addresses for all supported chains.

```bash
onecipher wallet create --name "my-wallet"
```

| Flag | Description |
|------|-------------|
| `--name <NAME>` | Wallet name (required) |
| `--words <12\|15\|18\|21\|24>` | Mnemonic word count (default: 12) |
| `--show-mnemonic` | Display the generated mnemonic once at creation time (DANGEROUS) |

Output:

```
Created wallet 3198bc9c-...
  eip155:1                              0xab16...   m/44'/60'/0'/0/0
  solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp  7Kz9...    m/44'/501'/0'/0'
  sui:mainnet                              0x...      m/44'/784'/0'/0'/0'
  bip122:000000000019d6689c085ae165831e93   bc1q...    m/84'/0'/0'/0/0
  cosmos:cosmoshub-4                     cosmos1... m/44'/118'/0'/0/0
  tron:mainnet                           TKLm...    m/44'/195'/0'/0/0
  xrpl:mainnet                           rHsM...    m/44'/144'/0'/0/0
```

### `onecipher wallet import`

Import an existing wallet from a mnemonic or private key.

```bash
# Import from mnemonic (reads from ONECIPHER_MNEMONIC env or stdin)
echo "goose puzzle decorate ..." | onecipher wallet import --name "imported" --mnemonic

# Import from private key (reads from ONECIPHER_PRIVATE_KEY env or stdin)
echo "4c0883a691..." | onecipher wallet import --name "from-evm" --private-key

# Import an Ed25519 key (e.g. from Solana)
echo "9d61b19d..." | onecipher wallet import --name "from-sol" --private-key --chain solana

# Import explicit keys for both curves via environment variables
ONECIPHER_SECP256K1_KEY="4c0883a691..." \
ONECIPHER_ED25519_KEY="9d61b19d..." \
  onecipher wallet import --name "both"

# Interactive prompt mode
onecipher wallet import --name "manual" --interactive
```

| Flag | Description |
|------|-------------|
| `--name <NAME>` | Wallet name (required) |
| `--mnemonic` | Import a mnemonic phrase |
| `--private-key` | Import a raw private key |
| `--chain <CHAIN>` | Source chain for private key import (determines curve: evm/bitcoin/cosmos/tron = secp256k1, solana/ton = ed25519) |
| `--index <N>` | Account index for HD derivation (mnemonic only, default: 0) |
| `--interactive` | Prompt for the mnemonic or private key |
| `ONECIPHER_SECP256K1_KEY` | Explicit secp256k1 private key via environment variable |
| `ONECIPHER_ED25519_KEY` | Explicit Ed25519 private key via environment variable |

Private key imports generate all chain accounts: the provided key is used for its curve's chains, and a random key is generated for the other curve. Use `ONECIPHER_SECP256K1_KEY` and `ONECIPHER_ED25519_KEY` together to supply both keys explicitly.

### `onecipher wallet export`

Export a wallet's secret to stdout. Requires an interactive terminal.

```bash
onecipher wallet export --wallet "my-wallet"
onecipher wallet export --wallet "my-wallet" --public-key --chain ethereum
```

- Mnemonic wallets output the phrase.
- Private key wallets output JSON: `{"secp256k1":"hex...","ed25519":"hex..."}`.
- `--public-key` exports the public key instead (`--chain` selects the chain,
  `--compressed` requests the compressed form where applicable).

### `onecipher wallet list` / `wallet info`

```bash
onecipher wallet list     # all wallets in the vault
onecipher wallet info     # vault path and supported chains
```

### `onecipher wallet rename` / `wallet delete`

```bash
onecipher wallet rename --wallet old-name --new-name new-name
onecipher wallet delete --wallet old-name --confirm   # --confirm required
```

### `onecipher wallet change-password`

Change a wallet's encryption passphrase.

```bash
onecipher wallet change-password --wallet my-wallet
# non-interactive:
onecipher wallet change-password --wallet my-wallet \
  --passphrase "$OLD" --new-passphrase "$NEW"
```

Environment fallbacks: `ONECIPHER_PASSPHRASE` (current) and
`ONECIPHER_NEW_PASSPHRASE` (new).

## Signing Commands

Chains are addressed three ways everywhere: by name (`ethereum`, `base`,
`solana`, ...), CAIP-2 ID (`eip155:8453`), or bare EVM chain ID (`8453`).

### `onecipher sign message`

Sign a message with chain-specific formatting (e.g., EIP-191 for EVM, `\x19TRON Signed Message` for Tron).

```bash
# EVM (Ethereum mainnet)
onecipher sign message --wallet "my-wallet" --chain ethereum --message "hello world"

# Solana
onecipher sign message --wallet "my-wallet" --chain solana --message "hello world"

# Base via bare chain ID
onecipher sign message --wallet "my-wallet" --chain 8453 --message "hello world"

# EIP-712 typed data (--message not required)
onecipher sign message --wallet "my-wallet" --chain ethereum \
  --typed-data '{"types":{...},"primaryType":"...","domain":{...},"message":{...}}'
```

| Flag | Description |
|------|-------------|
| `--wallet <NAME>` | Wallet name or ID (env: `ONECIPHER_WALLET`) |
| `--chain <CHAIN>` | Chain name, CAIP-2 ID, or bare EVM chain ID |
| `--message <MSG>` | Message to sign (optional when `--typed-data` is given) |
| `--encoding <ENC>` | Message encoding: `utf8` (default) or `hex` |
| `--typed-data <JSON>` | EIP-712 typed data JSON (EVM only) |
| `--index <N>` | Account index (default: 0) |
| `--json` | Output structured JSON |

### `onecipher sign tx`

Sign a raw transaction (hex-encoded bytes).

```bash
onecipher sign tx --wallet "my-wallet" --chain ethereum --tx "02f8..."
onecipher sign tx --wallet "my-wallet" --chain solana --tx "deadbeef..."

# Route signing through a paired WalletConnect session instead of local keys
onecipher sign tx --wallet "my-wallet" --chain ethereum --tx "02f8..." --via wc
```

| Flag | Description |
|------|-------------|
| `--wallet <NAME>` | Wallet name or ID |
| `--chain <CHAIN>` | Chain name, CAIP-2 ID, or bare EVM chain ID |
| `--tx <HEX>` | Hex-encoded transaction bytes |
| `--index <N>` | Account index (default: 0) |
| `--json` | Output structured JSON |
| `--via <local\|wc>` | Signing backend (default: `local`) |

### `onecipher sign send-tx`

Sign and broadcast through the configured RPC endpoint.

```bash
onecipher sign send-tx --wallet "my-wallet" --chain base --tx "02f8..."
onecipher sign send-tx --wallet "my-wallet" --chain base --tx "02f8..." \
  --rpc-url https://mainnet.base.org --json
```

### `onecipher sign auth`

Sign an EIP-7702 authorization (delegate address + chain ID + nonce).

```bash
onecipher sign auth --wallet "my-wallet" --chain ethereum \
  --address 0xe6Cae83F224f274b353412B8e8ED915A0E1A3E1c --nonce 5
```

### `onecipher verify`

Verify a signature against an address.

```bash
onecipher verify --address 0xab16... --message "hello" --signature 0x...
onecipher verify --address 0xab16... --typed-data '<json>' --signature 0x...
onecipher verify --address 0xab16... --typed-data-file order.json --signature 0x...
onecipher verify --address 0xab16... --hash <32-byte-hex> --no-hash --signature 0x...
```

`--typed-data` / `--typed-data-file` are fully functional: the EIP-712 typed
data is hashed per the EIP-712 specification and the signature is verified
against that raw digest (no EIP-191 `personal_sign` wrapping).

```bash
onecipher verify --address 0xab16... --signature 0x... --typed-data '{
  "types": {
    "EIP712Domain": [{"name":"name","type":"string"}],
    "Mail": [{"name":"contents","type":"string"}]
  },
  "primaryType": "Mail",
  "domain": {"name": "Ether Mail"},
  "message": {"contents": "Hello from OneCipher"}
}'
```

| Flag | Description |
|------|-------------|
| `--address <ADDR>` | Signer address (required) |
| `--message` / `--typed-data` / `--typed-data-file` / `--hash` | Input (mutually exclusive) |
| `--no-hash` | Treat `--hash` as pre-hashed (no EIP-191 prefix) |
| `--signature <HEX>` | Signature to verify (required) |
| `--chain <CHAIN>` | Chain type (default: `evm`) |

### `onecipher send`

Build, sign, and broadcast an ERC-20 token transfer (cast-style).

```bash
onecipher send --chain base --to 0xRecipient... --token 0xUSDC... \
  --amount 1000000 --wallet my-wallet --rpc-url https://mainnet.base.org
```

Amounts are integer base units (`1000000` = 1.0 USDC with 6 decimals).
`--gas-limit` overrides on-chain estimation; `--index` selects the account;
`--json` prints structured output including the transaction hash.

### `onecipher vanity`

Brute-force generate vanity addresses.

```bash
onecipher vanity --starts-with cafe --count 2 --jobs 8
onecipher vanity --ends-with dead --save-path vanities.json
onecipher vanity --starts-with cafe --save-to-vault
```

| Flag | Description |
|------|-------------|
| `--starts-with <HEX>` | Address must start with this hex pattern |
| `--ends-with <HEX>` | Address must end with this hex pattern |
| `--count <N>` | Number of matching wallets to generate (default: 1) |
| `--jobs <N>` | Parallel threads |
| `--save-path <FILE>` | Save results to JSON file (append mode) |
| `--save-to-vault` | Encrypt and save results into the vault |

## Mnemonic Commands

### `onecipher mnemonic generate`

Generate a new BIP-39 mnemonic phrase.

```bash
onecipher mnemonic generate --words 24
```

### `onecipher mnemonic derive`

Derive addresses from a mnemonic (reads from `ONECIPHER_MNEMONIC` env or stdin).

```bash
echo "word1 word2 ..." | onecipher mnemonic derive --chain ethereum

# Derive every supported chain
echo "word1 word2 ..." | onecipher mnemonic derive

# Custom path, multiple addresses, show private keys
echo "word1 word2 ..." | onecipher mnemonic derive --chain ethereum \
  --path "m/44'/60'/0'/0/5" --count 10 --show-private-key
```

## Policy Commands

### `onecipher policy create`

Register a policy from a JSON file.

```bash
onecipher policy create --file base-policy.json
```

Policy JSON format:

```json
{
  "id": "base-only",
  "name": "Base and Sepolia until year end",
  "version": 1,
  "created_at": "2026-03-22T00:00:00Z",
  "rules": [
    { "type": "allowed_chains", "chain_ids": ["eip155:8453", "eip155:84532"] },
    { "type": "expires_at", "timestamp": "2026-12-31T00:00:00Z" }
  ],
  "action": "deny"
}
```

Rules are AND-combined — all must pass. Supported declarative rule types:

| Rule | Description |
|------|-------------|
| `allowed_chains` | Deny if chain is not in the list |
| `expires_at` | Deny if current time is past the timestamp |
| `allowed_typed_data_contracts` | Restrict EIP-712 typed data to specific contracts |

Policies can also specify an `executable` field for custom validation — receives PolicyContext on stdin, writes `{"allow": true}` or `{"allow": false, "reason": "..."}` to stdout. See the [Policy Engine](policy-engine.md) doc for the full protocol.

### `onecipher policy list` / `show` / `delete`

```bash
onecipher policy list
onecipher policy show --id base-only
onecipher policy delete --id base-only --confirm   # --confirm required
```

## Key Commands (API Keys)

### `onecipher key create`

Create an API key for agent access to one or more wallets.

```bash
onecipher key create --name "claude-agent" \
  --wallet my-wallet \
  --policy base-only \
  --policy agent-expiry \
  --expires-at 2026-12-31T23:59:59Z
```

| Flag | Description |
|------|-------------|
| `--name <NAME>` | Key name (required) |
| `--wallet <NAME>` | Wallet name or ID (repeatable) |
| `--policy <ID>` | Policy ID to attach (repeatable) |
| `--expires-at <TS>` | Optional expiry (ISO-8601) |

Output includes the raw token (`ows_key_...`) — shown once. The agent uses this token in place of the passphrase.

### `onecipher key list` / `key revoke`

```bash
onecipher key list                                  # tokens are never shown
onecipher key revoke --id <key-id> --confirm        # --confirm required
```

## Session Key Commands

Session keys delegate signing to agents without exposing master keys
(ERC-7715/7579 on EVM, Session Tokens on Solana). These commands talk to the
Network-Agent over UDS; start the daemon first.

```bash
onecipher session-key create --label research-agent \
  --challenge <hex-nonce> --signature <hex-sig> --credential-id <id>
onecipher session-key list
onecipher session-key revoke <session-key-id> \
  --challenge <hex-nonce> --signature <hex-sig> --credential-id <id>
```

## Intent Commands (Stage 2)

Declarative intents ("pay 10.5 USDC to 0xABC on Base") with
simulate → confirm → execute lifecycle. `intent execute` fetches the real
pending nonce via `eth_getTransactionCount` before building the transaction.
`CrossChainTransfer` intents are rejected as unsupported (fail-closed) until
bridge integration lands; see [design notes](design.md) for status.

```bash
onecipher intent submit --json '{"type":"Pay","amount":"10.5 USDC","recipient":"0xABC"}' \
  --chain eip155:8453 --session-key sk-eip155-0xabc12345
onecipher intent simulate --json '...' --chain eip155:8453 --session-key ...
onecipher intent execute --json '...' --chain eip155:8453 --session-key ... --yes
```

## Audit Commands

```bash
# List audit log entries (LOCAL — reads the audit file directly)
onecipher audit list --since 24h --agent agent-01 --status DENIED

# Audit stored passwords for weakness (LOCAL)
onecipher audit secrets --format text --max-age 365
onecipher audit secrets --skip-hibp      # skip HaveIBeenPwned k-anonymity check
```

## Vault & Backup Commands

```bash
onecipher vault unlock          # prompts for passphrase

# .ocbk encrypted backup container (XChaCha20-Poly1305)
onecipher backup export --out backup.ocbk
onecipher backup import --in backup.ocbk
```

## SBOM Commands

```bash
onecipher sbom verify --file sbom.cdx.json    # verify a CycloneDX SBOM
onecipher sbom generate                       # generate sbom.cdx.json
onecipher sbom generate --output custom.json
```

## WalletConnect Commands

```bash
# Generate a pairing URI (QR-ready), optional TTL seconds (default 24h)
onecipher wc pair [--ttl 3600]

# Connect to a dApp via pairing URI
onecipher wc connect "wc:<topic>@2?relay-protocol=irn&symKey=..."

# List active sessions / disconnect by topic
onecipher wc sessions
onecipher wc disconnect <topic>

# Configure the relay (persisted to ~/.onecipher/config.json)
onecipher wc relay wss://relay.walletconnect.com --project-id YOUR_PROJECT_ID

# Diagnostics: subscribe to a fresh topic, publish a ping, wait for echo
onecipher wc probe [--url wss://...] [--project-id ID] [--timeout 10]

# Send a JSON-RPC request on a bound session as a dApp (testing aid)
onecipher wc dapp-send <topic> personal_sign '{"data":"0xdead"}' \
  [--sym-key <hex>] [--url wss://...]
```

## Web UI Commands

```bash
onecipher webui open            # open the local Web UI in the browser

# Inspect and resolve pending signing approvals (non-interactive)
onecipher webui approval list
onecipher webui approval show <uuid>
onecipher webui approval approve <uuid> [--yes]
onecipher webui approval reject <uuid> --reason "not expected" [--yes]

# Query / lock Web UI passkey sessions
onecipher webui auth status
onecipher webui auth bootstrap  # is first-time passkey registration needed?
onecipher webui auth lock       # expire all Web UI sessions
```

## Daemon Service Commands

Manage the daemon as a systemd user service (Linux).

```bash
onecipher service install     # writes ~/.config/systemd/user/onecipher.service
onecipher service uninstall
onecipher service status
```

## Secret Vault Commands (Phase 4)

OneCipher doubles as a unified sensitive-data vault: private keys, passwords,
TOTP seeds, and encrypted notes share one age-encrypted store, one policy
engine, and one audit log.

### Generic secrets

```bash
onecipher secret list [--type note] [--json]
onecipher secret get notes/recovery [--field secret] [--json] [--qr] [--copy] [--timeout 45]
echo '{"secret":"recovery phrase words here"}' | \
  onecipher secret add notes/recovery --type note --stdin
echo '{"secret":"sk-abc123..."}' | \
  onecipher secret add api-keys/openai --type password --stdin --meta url=https://api.openai.com
onecipher secret update notes/recovery --stdin
onecipher secret rename notes/recovery notes/recovery-v2
onecipher secret copy notes/recovery-v2 notes/backup [--force]
onecipher secret move notes/backup notes/archive [--force]
onecipher secret delete notes/recovery-v2
onecipher secret edit notes/recovery [--editor vim]   # edit in $EDITOR
```

Supported secret types: `password`, `note`, `totp`, `mnemonic`, `private-key`.

### Passwords

```bash
onecipher password add github/personal --url https://github.com --username alice
onecipher password add aws/prod --url https://aws.amazon.com --username admin \
  --generate --length 32 --symbols
onecipher password get github/personal [--copy] [--timeout 45]

# Standalone generator: cryptic (default), memorable, or xkcd word phrases
onecipher password generate --length 24 --symbols
onecipher password generate --generator xkcd --xkcd-words 5 --xkcd-sep "."
onecipher password generate --qr
```

### TOTP / HOTP

```bash
onecipher totp add discord --otpauth "otpauth://totp/Discord:alice?secret=AAAAAAAAAAAAAAAA&issuer=Discord"
onecipher totp add github-2fa --secret AAAAAAAAAAAAAAAA --issuer GitHub --account alice
onecipher totp generate discord [--qr]
onecipher totp uris discord                 # otpauth URI for backup
onecipher totp hotp legacy-account --counter 42 --increment
```

### age encryption management

```bash
onecipher age init                # initialize the age identity (one-time)
onecipher age identity-show       # show your age public key
onecipher age recipient add age1...
onecipher age recipient list
onecipher age recipient remove age1...
onecipher age reencrypt           # re-encrypt the whole vault to current recipients
```

### Agent-mode secret access (API token)

`agent-secret` reads the API token from `ONECIPHER_PASSPHRASE`, validates it
against the key file, enforces per-key `SecretPermissions`
(`read_patterns` globs, `allow_totp`), and operates directly on the local
SecretStore:

```bash
ONECIPHER_PASSPHRASE="ows_key_..." onecipher agent-secret get --name api-keys/openai
ONECIPHER_PASSPHRASE="ows_key_..." onecipher agent-secret list --json
ONECIPHER_PASSPHRASE="ows_key_..." onecipher agent-secret totp --name github-2fa
```

### Environment injection & search

```bash
# Run a command with secrets injected as environment variables
onecipher env --name api-keys/openai --name db/prod -- ./deploy.sh
onecipher env --name secrets/dir --keep-case --exec -- printenv   # exec(3) mode

# Search inside decrypted content (case-insensitive substring, or regex)
onecipher grep "sk-" [--regex] [--json]

# Fuzzy-search names/types
onecipher find openai [--type password] [--regex] [--json]

# Integrity check / repair
onecipher fsck [--fix] [--decrypt]

# Version history (requires the `git` feature)
onecipher history api-keys/openai [--password] [--limit 20] [--json]
```

### Git sync (optional, `git` feature)

Vaults can be versioned and synchronized across hosts. Only encrypted
payloads ever leave the machine.

```bash
onecipher git init [--remote git@github.com:you/vault.git]
onecipher git pull
onecipher git push
onecipher git log [--name api-keys/openai]
onecipher git status
```

## Migration & Maintenance

```bash
# Migrate legacy keystore v3 wallets to age-encrypted secrets
onecipher migrate
onecipher migrate --dry-run      # preview only
onecipher migrate --rollback     # remove migrated .age entries (legacy files kept)

# System health diagnostics
onecipher doctor [--verbose]

# Shell completions (bash, zsh, fish, powershell, elvish)
onecipher completion zsh > ~/.zfunc/_onecipher

# Interactive TUI: browse/copy/delete secrets, TOTP codes, audit entries
onecipher tui
```

## WalletSigner JSON-RPC Server (LedgerFlow integration)

Expose the loopback JSON-RPC 2.0 server implementing LedgerFlow's
`WalletSigner` interface (`ledgerflow_sign`, `ledgerflow_keys`,
`ledgerflow_sign_payment`). Off by default — enable explicitly:

```bash
OC_WALLET_RPC_LISTEN=127.0.0.1:18080 onecipher --daemon
# or standalone:
onecipher wallet-rpc serve [--listen 127.0.0.1:18080] \
  [--wallet default] [--index 0]
```

Every signing request must carry a fresh Passkey authorization payload.
See [signing-interface.md](signing-interface.md) for the surface rules and
[the LedgerFlow repo](https://github.com/longcipher/ledgerflow) for the
consumer side.

## System Commands

### `onecipher status` / `config`

```bash
onecipher status                        # Key-Agent / Network-Agent status (LOCAL)
onecipher config show                   # configuration + RPC endpoints
onecipher config set webui.enabled true # set a config value
```

### `onecipher update` / `uninstall`

```bash
onecipher update [--force]
onecipher uninstall           # keep wallet data
onecipher uninstall --purge   # also remove ~/.onecipher
```

## File Layout

```
~/.onecipher/
  wallets/
    <uuid>.json             # Encrypted wallet (AES-256-GCM-SIV + Argon2id)
  secrets/
    <tree>/<name>.age       # age-encrypted unified vault entries
  age-identity.txt          # age master identity (created by `age init`)
  .age-recipients           # age recipients (multi-device)
  policies/
    <id>.json               # Policy definitions (not secret)
  keys/
    <uuid>.json             # API key files (0600 permissions)
  logs/
    audit.jsonl             # Append-only, SHA-256 chained, Ed25519-signed audit log
  index.jsonl               # Plaintext metadata index (signed) for fast search
  config.json               # Global configuration
```

See [storage-format.md](storage-format.md) for the full on-disk specification.
