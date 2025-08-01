# CLI Reference

> Command-line interface for the `onecipher` Rust binary.

## Install

Build from source:

```bash
git clone https://github.com/longcipher/onecipher.git
cd onecipher
cargo build --workspace --release
```

The binary is at `target/release/onecipher`.

## Wallet Commands

### `onecipher wallet create`

Create a new wallet. Generates a BIP-39 mnemonic and derives addresses for all supported chains.

```bash
onecipher wallet create --name "my-wallet"
```

| Flag | Description |
|------|-------------|
| `--name <NAME>` | Wallet name (required) |
| `--show-mnemonic` | Display the generated mnemonic once at creation time |
| `--words <12\|24>` | Mnemonic word count (default: 12) |

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
```

| Flag | Description |
|------|-------------|
| `--name <NAME>` | Wallet name (required) |
| `--mnemonic` | Import a mnemonic phrase |
| `--private-key` | Import a raw private key |
| `--chain <CHAIN>` | Source chain for private key import (determines curve, default: evm) |
| `--index <N>` | Account index for HD derivation (mnemonic only, default: 0) |
| `ONECIPHER_SECP256K1_KEY` | Explicit secp256k1 private key via environment variable |
| `ONECIPHER_ED25519_KEY` | Explicit Ed25519 private key via environment variable |

Private key imports generate all 9 chain accounts: the provided key is used for its curve's chains, and a random key is generated for the other curve. Use `ONECIPHER_SECP256K1_KEY` and `ONECIPHER_ED25519_KEY` together to supply both keys explicitly.

### `onecipher wallet export`

Export a wallet's secret to stdout. Requires an interactive terminal.

```bash
onecipher wallet export --wallet "my-wallet"
```

- Mnemonic wallets output the phrase.
- Private key wallets output JSON: `{"secp256k1":"hex...","ed25519":"hex..."}`.

### `onecipher wallet list`

List all wallets in the vault.

```bash
onecipher wallet list
```

### `onecipher wallet info`

Show vault path and supported chains.

```bash
onecipher wallet info
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

Policies can also specify an `executable` field for custom validation — receives PolicyContext on stdin, writes `{"allow": true}` or `{"allow": false, "reason": "..."}` to stdout.

### `onecipher policy list`

```bash
onecipher policy list
```

### `onecipher policy show`

```bash
onecipher policy show --id base-only
```

### `onecipher policy delete`

```bash
onecipher policy delete --id base-only --confirm
```

## Key Commands

### `onecipher key create`

Create an API key for agent access to one or more wallets.

```bash
onecipher key create --name "claude-agent" \
  --wallet my-wallet \
  --policy base-only \
  --policy agent-expiry
```

| Flag | Description |
|------|-------------|
| `--name <NAME>` | Key name (required) |
| `--wallet <NAME>` | Wallet name or ID (repeatable) |
| `--policy <ID>` | Policy ID to attach (repeatable) |
| `--expires-at <TS>` | Optional expiry (ISO-8601) |

Output includes the raw token (`ows_key_...`) — shown once. The agent uses this token in place of the passphrase.

### `onecipher key list`

```bash
onecipher key list
```

### `onecipher key revoke`

```bash
onecipher key revoke --id <key-id> --confirm
```

## Signing Commands

### `onecipher sign message`

Sign a message with chain-specific formatting (e.g., EIP-191 for EVM, `\x19TRON Signed Message` for Tron).

```bash
# EVM (Ethereum mainnet)
onecipher sign message --wallet "my-wallet" --chain ethereum --message "hello world"

# Solana
onecipher sign message --wallet "my-wallet" --chain solana --message "hello world"

# Bitcoin
onecipher sign message --wallet "my-wallet" --chain bitcoin --message "hello world"

# Base via bare chain ID
onecipher sign message --wallet "my-wallet" --chain 8453 --message "hello world"
```

| Flag | Description |
|------|-------------|
| `--wallet <NAME>` | Wallet name or ID |
| `--chain <CHAIN>` | Chain name (`ethereum`, `base`, `arbitrum`, ...), CAIP-2 ID (`eip155:8453`), or bare EVM chain ID (`8453`) |
| `--message <MSG>` | Message to sign |
| `--encoding <ENC>` | Message encoding: `utf8` (default) or `hex` |
| `--typed-data <JSON>` | EIP-712 typed data JSON (EVM only) |
| `--json` | Output structured JSON |

### `onecipher sign tx`

Sign a raw transaction (hex-encoded bytes).

```bash
onecipher sign tx --wallet "my-wallet" --chain ethereum --tx "02f8..."
onecipher sign tx --wallet "my-wallet" --chain solana --tx "deadbeef..."
```

| Flag | Description |
|------|-------------|
| `--wallet <NAME>` | Wallet name or ID |
| `--chain <CHAIN>` | Chain name, CAIP-2 ID, or bare EVM chain ID |
| `--tx <HEX>` | Hex-encoded transaction bytes |
| `--json` | Output structured JSON |

Passphrases and API tokens are supplied via `ONECIPHER_PASSPHRASE` or an interactive prompt, not a dedicated `--passphrase` flag.

## Mnemonic Commands

### `onecipher mnemonic generate`

Generate a new BIP-39 mnemonic phrase.

```bash
onecipher mnemonic generate --words 24
```

### `onecipher mnemonic derive`

Derive an address from a mnemonic for a given chain.

```bash
echo "word1 word2 ..." | onecipher mnemonic derive --chain ethereum
```

## Payment Commands

### `onecipher pay request`

Make an HTTP request with automatic x402 payment handling.

```bash
onecipher pay request "https://api.example.com/data" --wallet "my-wallet"
onecipher pay request "https://api.example.com/submit" --wallet "my-wallet" --method POST --body '{"query":"test"}'
```

| Flag | Description |
|------|-------------|
| `--wallet <NAME>` | Wallet name (required) |
| `--method <METHOD>` | HTTP method: GET, POST, PUT, DELETE, PATCH (default: GET) |
| `--body <JSON>` | Request body (JSON string) |
| `--no-passphrase` | Skip passphrase prompt |

### `onecipher pay discover`

Discover x402-enabled services from the Bazaar directory.

```bash
onecipher pay discover
onecipher pay discover --query "weather"
onecipher pay discover --limit 20 --offset 100
```

| Flag | Description |
|------|-------------|
| `--query <SEARCH>` | Filter services by URL or description |
| `--limit <N>` | Max results per page (default: 100) |
| `--offset <N>` | Offset into results for pagination |

## Funding Commands

### `onecipher fund deposit`

Create a MoonPay deposit that generates multi-chain deposit addresses.

```bash
onecipher fund deposit --wallet "my-wallet"
onecipher fund deposit --wallet "my-wallet" --chain base
```

### `onecipher fund balance`

Check token balances for a wallet on a given chain.

```bash
onecipher fund balance --wallet "my-wallet" --chain base
```

## System Commands

### `onecipher update`

Update the `onecipher` binary to the latest release.

```bash
onecipher update
onecipher update --force
```

### `onecipher uninstall`

Remove `onecipher` from the system.

```bash
onecipher uninstall          # keep wallet data
onecipher uninstall --purge  # also remove ~/.onecipher
```

## File Layout

```
~/.onecipher/
  wallets/
    <uuid>.json             # Encrypted wallet (AES-256-GCM-SIV + Argon2id)
  policies/
    <id>.json               # Policy definitions (not secret)
  keys/
    <uuid>.json             # API key files (0600 permissions)
  logs/
    audit.jsonl             # Audit log
```
