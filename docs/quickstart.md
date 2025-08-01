# Quick Start

> Get started with OneCipher — install, create a wallet, and sign your first transaction.

## Install

Build from source:

```bash
git clone https://github.com/longcipher/onecipher.git
cd onecipher
cargo build --workspace --release
```

The binary is at `target/release/onecipher`. Add it to your `$PATH`.

## Create a Wallet

A single command derives addresses for every supported chain — EVM, Solana, Sui, Bitcoin, Cosmos, Tron, TON, XRPL, Filecoin, NEAR.

```bash
onecipher wallet create --name "agent-treasury"
```

```
Created wallet 3198bc9c-...
  eip155:1        0xab16...   m/44'/60'/0'/0/0
  solana:5eykt4   7Kz9...    m/44'/501'/0'/0'
  bip122:0000     bc1q...    m/84'/0'/0'/0/0
  cosmos:cosmo    cosmos1... m/44'/118'/0'/0/0
  tron:mainnet    TKLm...    m/44'/195'/0'/0/0
  ton:mainnet     UQ...      m/44'/607'/0'
  sui:mainnet     0x...      m/44'/784'/0'/0'/0'
```

## Fund the Wallet

Deposit crypto from any chain — it auto-converts to USDC on your target chain.

```bash
onecipher fund deposit --wallet agent-treasury --chain base
```

Check your balance:

```bash
onecipher fund balance --wallet agent-treasury --chain base
```

## Sign Messages and Transactions

```bash
# Sign a message
onecipher sign message --wallet agent-treasury --chain ethereum --message "hello"

# Sign a transaction
onecipher sign tx --wallet agent-treasury --chain solana --tx "deadbeef..."
```

## Pay for Services (x402)

OneCipher handles the full [x402](https://www.x402.org/) payment flow automatically. When a server returns `402 Payment Required`, the CLI signs the payment credential and retries.

```bash
# GET request — payment handled automatically
onecipher pay request "https://api.example.com/data" --wallet agent-treasury

# POST with a body
onecipher pay request "https://api.example.com/query" \
  --wallet agent-treasury \
  --method POST \
  --body '{"prompt": "summarize this document"}'
```

Discover available services:

```bash
onecipher pay discover
onecipher pay discover --query "weather"
```

## Set Up Agent Access

Create a scoped API key so your agent can sign autonomously — without ever seeing the private key.

### 1. Define a policy

```bash
cat > policy.json << 'EOF'
{
  "id": "agent-limits",
  "name": "Base chain only, expires end of year",
  "version": 1,
  "created_at": "2026-01-01T00:00:00Z",
  "rules": [
    { "type": "allowed_chains", "chain_ids": ["eip155:8453"] },
    { "type": "expires_at", "timestamp": "2026-12-31T23:59:59Z" }
  ],
  "action": "deny"
}
EOF
onecipher policy create --file policy.json
```

### 2. Create an API key

```bash
onecipher key create --name "my-agent" --wallet agent-treasury --policy agent-limits
# => ows_key_a1b2c3d4...  (save this — shown once)
```

### 3. Use the token to sign

The agent passes the API token where the passphrase would go. OneCipher detects the `ows_key_` prefix, evaluates all attached policies, and only signs if every policy allows it.

```bash
# Agent signs on Base — policy allows it
ONECIPHER_PASSPHRASE="ows_key_a1b2c3d4..." \
  onecipher sign tx --wallet agent-treasury --chain base --tx 0x02f8...

# Agent tries Ethereum mainnet — policy denies it
ONECIPHER_PASSPHRASE="ows_key_a1b2c3d4..." \
  onecipher sign tx --wallet agent-treasury --chain ethereum --tx 0x02f8...
# error: policy denied: chain eip155:1 not in allowlist
```

### 4. Revoke access

```bash
onecipher key revoke --id <key-id> --confirm
```

The token becomes useless immediately — no key rotation needed.

## How It Works

```
Agent / CLI / App
       │
       │  OneCipher CLI
       ▼
┌─────────────────────┐
│    Signing Engine    │     1. Agent calls onecipher.sign()
│  ┌────────────────┐  │     2. Policy engine evaluates
│  │ Policy Engine   │  │     3. Vault decrypts key
│  │ (pre-signing)   │  │     4. Transaction signed
│  └───────┬────────┘  │     5. Key wiped from memory
│  ┌───────▼────────┐  │     6. Signature returned
│  │ Multi-chain    │  │
│  │ Signer         │  │     The agent NEVER sees
│  └───────┬────────┘  │     the private key.
│  ┌───────▼────────┐  │
│  │  Wallet Vault   │  │
│  │ ~/.onecipher/   │  │
│  └────────────────┘  │
└─────────────────────┘
```

## Next Steps

- [CLI Reference](cli-reference.md) — full command list
- [Policy Engine](policy-engine.md) — custom policies, executable hooks, access control
- [Architecture](architecture.md) — system design and crate structure
- [Security Model](security-model.md) — key isolation and threat model
