# Quick Start

> Get started with OneCipher — install, create a wallet, sign your first transaction, and set up agent access.

## Install

Build from source:

```bash
git clone https://github.com/longcipher/onecipher.git
cd onecipher
cargo build --release --bin onecipher
```

The binary is at `target/release/onecipher`. Add it to your `$PATH`.

## Create a Wallet

A single command derives addresses for every supported chain — EVM, Solana,
Sui, Bitcoin, Cosmos, Tron, TON, XRPL, Filecoin, Nano, NEAR.

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

Fund the addresses directly from any exchange or faucet — check them with:

```bash
onecipher wallet list
```

## Sign Messages and Transactions

```bash
# Sign a message
onecipher sign message --wallet agent-treasury --chain ethereum --message "hello"

# Sign EIP-712 typed data (x402 EIP-3009 and similar)
onecipher sign message --wallet agent-treasury --chain ethereum \
  --typed-data '{"types":{...},"primaryType":"TransferWithAuthorization",...}'

# Sign a transaction
onecipher sign tx --wallet agent-treasury --chain solana --tx "deadbeef..."

# Sign and broadcast
onecipher sign send-tx --wallet agent-treasury --chain base --tx "02f8..."

# Verify a signature
onecipher verify --address 0xab16... --message "hello" --signature 0x...
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

Agents can also read secrets (with per-key read patterns) via
`agent-secret`, or run commands with secrets injected as environment
variables:

```bash
ONECIPHER_PASSPHRASE="ows_key_..." onecipher env --name api-keys/openai -- ./agent.sh
```

### 4. Revoke access

```bash
onecipher key revoke --id <key-id> --confirm
```

The token becomes useless immediately — no key rotation needed.

## Use It as a Password Manager / TOTP App

OneCipher is a unified sensitive-data vault. The same age encryption,
policy engine, and audit log protect passwords, TOTP seeds, and notes:

```bash
# Store a password (auto-generate supported)
onecipher password add github/personal --url https://github.com --username alice
onecipher password get github/personal --copy   # clipboard auto-clears after 45s

# Store a TOTP seed and generate codes
onecipher totp add discord --otpauth "otpauth://totp/Discord:alice?secret=AAAA&issuer=Discord"
onecipher totp generate discord

# Encrypted notes and generic secrets
echo '{"secret":"recovery phrase words here"}' | \
  onecipher secret add notes/recovery --type note --stdin

# Browse everything interactively
onecipher tui
```

## Connect dApps (WalletConnect)

```bash
onecipher wc pair                       # QR-ready pairing URI
onecipher wc connect "wc:<topic>@2?..."
onecipher wc sessions
```

Run the daemon (`onecipher --daemon`) to stay connected; signing requests
from paired dApps are policy-checked, audited, and (optionally) gated behind
Web UI approvals (`onecipher webui open`).

## Pay for APIs (via LedgerFlow)

Payment-protocol logic lives in the sibling project
[LedgerFlow](https://github.com/longcipher/ledgerflow). OneCipher acts as its
wallet: expose the loopback WalletSigner JSON-RPC server and LedgerFlow (or
any x402/MPP client) signs payment credentials through it:

```bash
OC_WALLET_RPC_LISTEN=127.0.0.1:18080 onecipher --daemon
```

Every signing request must carry a fresh Passkey authorization payload.
See [signing-interface.md](signing-interface.md) for surface rules.

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
- [Sign-in with Wallet](sign-in-with-wallet.md) — IAM integration over WC v2
