# onecipher CLI (oc-cli)

The `onecipher` command-line interface for OneCipher — policy-gated, local-key-custody wallet management and signing.

Part of the [OneCipher](https://github.com/longcipher/onecipher) project — a policy-gated, local-key-custody signing stack fully designed and implemented in accordance with the WalletConnect v2 protocol and the Open Wallet Standard.

## Quick Install

```bash
# From source (requires Rust 1.70+)
git clone https://github.com/longcipher/onecipher.git
cd core
cargo build --release --bin onecipher
```

Or use the Node.js package which includes the CLI:

```bash
npm install -g @onecipher/core  # provides `onecipher` command
```

## CLI Reference

| Command | Description |
|---------|-------------|
| `onecipher wallet create` | Create a new wallet with addresses for all chains |
| `onecipher wallet list` | List all wallets in the vault |
| `onecipher wallet info` | Show vault path and supported chains |
| `onecipher sign message` | Sign a message with chain-specific formatting |
| `onecipher sign tx` | Sign a raw transaction |
| `onecipher pay request` | Make a paid request to an x402-enabled API endpoint |
| `onecipher pay discover` | Discover x402-enabled services |
| `onecipher fund deposit` | Create a MoonPay deposit to fund a wallet with USDC |
| `onecipher fund balance` | Check token balances for a wallet |
| `onecipher mnemonic generate` | Generate a BIP-39 mnemonic phrase |
| `onecipher mnemonic derive` | Derive an address from a mnemonic |
| `onecipher policy create` | Register a policy from a JSON file |
| `onecipher policy list` | List all registered policies |
| `onecipher key create` | Create an API key for agent access |
| `onecipher key list` | List all API keys |
| `onecipher key revoke` | Revoke an API key |
| `onecipher update` | Update onecipher and bindings |
| `onecipher uninstall` | Remove onecipher from the system |

## File Layout

```
~/.onecipher/
  wallets/
    <uuid>.json             # Encrypted wallet (AES-256-GCM + scrypt)
  policies/
    <id>.json               # Policy definitions (not secret)
  keys/
    <uuid>.json             # API key files (0600 permissions)
  logs/
    audit.jsonl             # Audit log (append-only)
```

## License

Apache-2.0
