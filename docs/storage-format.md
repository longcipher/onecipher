# Storage Format

> The storage format is the core of the OneCipher standard. It defines how wallets, API keys, and policies are encrypted and stored on the local filesystem. Everything else — signing, policy enforcement, language bindings — operates on these files.

OneCipher extends the Ethereum Keystore v3 format with per-chain type adaptations, stored in a well-known directory with strict filesystem permissions. Any implementation that reads and writes these files correctly is a conforming OneCipher implementation.

## Vault Directory Structure

```
~/.onecipher/
├── config.json                    # Global configuration
├── wallets/
│   ├── <wallet-id>.json           # Encrypted wallet file (one per wallet)
│   └── ...
├── keys/
│   ├── <key-id>.json              # API key + encrypted wallet secrets (one per key)
│   └── ...
├── policies/
│   ├── <policy-id>.json           # Policy definition (declarative rules and/or executable)
│   └── ...
└── logs/
    └── audit.jsonl                # Append-only audit log
```

### Filesystem Permissions

```
~/.onecipher/                       drwx------  (700)
~/.onecipher/wallets/               drwx------  (700)
~/.onecipher/wallets/*.json         -rw-------  (600)
~/.onecipher/keys/                  drwx------  (700)
~/.onecipher/keys/*.json            -rw-------  (600)
~/.onecipher/policies/              drwxr-xr-x  (755)
~/.onecipher/policies/*.json        -rw-r--r--  (644)
~/.onecipher/config.json            -rw-------  (600)
~/.onecipher/logs/audit.jsonl       -rw-------  (600)
```

The `wallets/` and `keys/` directories contain encrypted secrets and MUST be readable only by the owner. Implementations MUST verify permissions on startup and refuse to operate if these directories are world-readable or group-readable.

The `policies/` directory uses relaxed permissions (755/644) because policy files are not secret — they contain rule definitions and paths to executables, not key material.

## Wallet File Format

Each wallet is stored as a single JSON file extending the Ethereum Keystore v3 structure:

```json
{
  "oc_version": 2,
  "id": "3198bc9c-6672-5ab3-d995-4942343ae5b6",
  "name": "agent-treasury",
  "created_at": "2026-02-27T10:30:00Z",
  "accounts": [
    {
      "account_id": "eip155:8453:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb",
      "address": "0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb",
      "chain_id": "eip155:8453",
      "derivation_path": "m/44'/60'/0'/0/0"
    }
  ],
  "crypto": {
    "cipher": "age",
    "ciphertext": "YWdlLWVuY3J5cHRpb24ub3JnL3YxLT4..."
  },
  "key_type": "mnemonic",
  "metadata": {}
}
```

The `crypto` object is an age envelope (`oc-vault::crypto::AgeEnvelope`):
`cipher` is always `"age"` and `ciphertext` is the base64-encoded age binary
(age scrypt passphrase for owner/device secrets). Any other `cipher` value
fails closed at decrypt time.

### Field Definitions

| Field | Type | Required | Description |
|---|---|---|---|
| `oc_version` | integer | yes | Schema version (currently `2`) |
| `id` | string | yes | UUID v4 wallet identifier |
| `name` | string | yes | Human-readable wallet name |
| `created_at` | string | yes | ISO 8601 creation timestamp |
| `accounts` | array | yes | Derived accounts (see Account object) |
| `crypto` | object | yes | Encryption parameters (see Crypto object) |
| `key_type` | string | yes | `mnemonic` (BIP-39) or `private_key` (raw) |
| `metadata` | object | no | Extensible metadata |

## API Key File Format

Each API key is stored as a JSON file in `~/.onecipher/keys/`. The key file contains metadata, policy attachments, and **encrypted copies of wallet secrets** re-encrypted under the API token (see [Policy Engine](policy-engine.md) for the full cryptographic design).

```json
{
  "id": "7a2f1b3c-4d5e-6f7a-8b9c-0d1e2f3a4b5c",
  "name": "claude-agent",
  "token_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "recipient": "age1ql3z7hj432v2jl2z8alunwwun8hm4s4h6h6h6h6h6h6h6h6h6",
  "created_at": "2026-03-22T10:30:00Z",
  "wallet_ids": ["3198bc9c-6672-5ab3-d995-4942343ae5b6"],
  "policy_ids": ["spending-limit", "base-only"],
  "expires_at": null,
  "wallet_secrets": {
    "3198bc9c-6672-5ab3-d995-4942343ae5b6": {
      "cipher": "age",
      "ciphertext": "YWdlLWVuY3J5cHRpb24ub3JnL3YxLT4..."
    }
  }
}
```

### Field Definitions

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | yes | UUID v4 key identifier |
| `name` | string | yes | Human-readable label for the key |
| `token_hash` | string | yes | SHA-256 hex digest of the raw token. The raw token (`oc_key_<64 hex chars>`) is shown once at creation and never stored. |
| `recipient` | string | yes | Age X25519 recipient (`age1...`) derived from the token bytes at creation. Wallet copies in `wallet_secrets` are age-encrypted to this recipient. |
| `created_at` | string | yes | ISO 8601 creation timestamp |
| `wallet_ids` | array | yes | Wallet IDs this key is authorized to access |
| `policy_ids` | array | yes | Policy IDs evaluated on every request made with this key |
| `expires_at` | string | no | ISO 8601 expiry timestamp. `null` means no expiry. |
| `wallet_secrets` | object | yes | Map of wallet ID → age envelope. Each entry is the wallet's decrypted secret re-encrypted to the key's age `recipient` (one X25519 stanza), whether that secret is a mnemonic phrase or private-key JSON. |

The `keys/` directory and its contents use the same strict permissions as `wallets/` (`700` for the directory, `600` for files) because `wallet_secrets` contains encrypted key material and `token_hash` must be protected against local reads.

Revoking an API key means deleting the key file. The encrypted secret copies are destroyed. The original wallet file and other API keys are unaffected.

### Crypto Object

The `crypto` object is an age envelope (one format for wallet files and API
key copies):

1. **age scrypt** is the passphrase path for wallet files: the raw
   passphrase bytes (owner UTF-8 passphrase or device-derived 32-byte
   secret) are hex-mapped into the scrypt passphrase input. Provides memory-
   hard offline-guessing resistance (auto-calibrated ~1 s work factor).
2. **age X25519** is the recipient path for API key copies and `.ocbk`
   backup bundles: each API token's 32 random bytes ARE the X25519 static
   secret, and the key file stores only the public recipient.

| Field | Type | Description |
|---|---|---|
| `cipher` | string | Always `"age"` — any other value fails closed |
| `ciphertext` | string | Base64-encoded age binary (self-describing recipient stanzas) |

There is no `kdfparams`/`auth_tag`/`cipherparams` anymore: the age binary
carries its own recipient stanzas (scrypt work factor or X25519 ephemeral
share) and authentication tag internally.

### What Gets Encrypted

The `ciphertext` contains the encrypted form of either:

- **BIP-39 mnemonic entropy** (128 or 256 bits) — when `key_type` is `mnemonic`. The mnemonic can derive keys for any supported chain via BIP-44 derivation paths.
- **Raw private key** (32 bytes for secp256k1/ed25519) — when `key_type` is `private_key`. Used for imported single-chain keys.

Storing the mnemonic (rather than individual private keys) enables a single encrypted blob to derive accounts across multiple chains and indices.

## Passphrase Management

The vault passphrase feeds the age scrypt recipient (after an injective hex mapping). OneCipher does NOT define how the passphrase is obtained — this is deliberately left to the implementation:

- **Interactive CLI**: Prompt at first use, optionally cache in OS keychain for a session
- **Agent/daemon mode**: Read from a file descriptor (RECOMMENDED), an environment variable (`ONECIPHER_PASSPHRASE`), or a hardware token. Environment variables are the least secure option — they are readable via `/proc/[pid]/environ` by same-user processes and leak into crash dumps and child process environments. Implementations using `ONECIPHER_PASSPHRASE` MUST clear it from the process environment immediately after reading.
- **Unlocked mode** (development only): A config flag that uses a well-known passphrase — MUST produce a visible warning

The passphrase MUST be at least 12 characters. Implementations SHOULD enforce this at wallet creation time.

## Audit Log

All signing operations are appended to `~/.onecipher/logs/audit.jsonl`:

```json
{
  "timestamp": "2026-02-27T10:35:22Z",
  "wallet_id": "3198bc9c-6672-5ab3-d995-4942343ae5b6",
  "operation": "broadcast_transaction",
  "chain_id": "eip155:8453",
  "details": "tx_hash=0xabc123..."
}
```

Current CLI audit operations use the unified dotted taxonomy (`AuditOp` in
`oc_core::secret`, shared by wallet, secret, password and TOTP commands):
`wallet.create`, `wallet.import`, `wallet.export`, `wallet.broadcast`,
`wallet.delete`, `wallet.rename`, `secret.create`, `secret.read`,
`secret.update`, `secret.delete`, `secret.rename`, `secret.copy`,
`password.add`, `password.generate`, `totp.add`, `totp.generate`, `totp.hotp`,
and the other `wallet.*` / `secret.*` operations. Signing operations
(`wallet.sign`, `wallet.broadcast`) ride the strong track
(`audit-strong.jsonl`); everything else rides the light track (`audit.jsonl`).

All fields except `timestamp`, `wallet_id`, and `operation` are optional.

The audit log is append-only. Implementations MUST NOT allow deletion or modification of existing entries. Log rotation is permitted (e.g., monthly archives).

## Backward Compatibility

BREAKING: the age flag day removed all legacy cipher support. Wallet files,
`.ocbk` bundles and API key files minted before the migration are NOT
readable by this build — they fail closed at parse/decrypt time and must be
recreated (re-import the mnemonic or private key, re-export backups,
re-issue API tokens). There is no migration path by design.

Ethereum Keystore v3 interchange still works at the edges: a v3 file can be
imported by reading its payload and wrapping it in a fresh age envelope
(adds `oc_version`, `name`, `accounts`).

## References

- [Ethereum Web3 Secret Storage Definition](https://ethereum.org/developers/docs/data-structures-and-encoding/web3-secret-storage)
- [ERC-2335: BLS12-381 Keystore](https://eips.ethereum.org/EIPS/eip-2335)
- [BIP-39: Mnemonic Seed Phrases](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
