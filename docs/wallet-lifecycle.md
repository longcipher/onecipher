# Wallet Lifecycle

> How wallets are created, imported, exported, backed up, recovered, and migrated.

## Creation

### Create from New Mnemonic

Generates a new BIP-39 mnemonic and derives accounts for all supported chains.

```bash
onecipher wallet create --name "agent-treasury"
onecipher wallet create --name "cold-storage" --words 24
onecipher wallet create --name "verify-once" --show-mnemonic   # DANGEROUS: prints the phrase once
```

**Flow:**
1. Generate 128–256 bits of cryptographically secure randomness
2. Encode as BIP-39 mnemonic (12/15/18/21/24 words)
3. Derive master seed via PBKDF2
4. Derive one account per supported chain using each chain's BIP-44 path
5. Encrypt mnemonic with vault passphrase (age scrypt)
6. Write encrypted wallet file to `~/.onecipher/wallets/<uuid>.json`
7. Wipe mnemonic, seed, and private keys from memory
8. Print only public information (addresses, IDs, derivation paths)

The mnemonic is never returned to the caller unless `--show-mnemonic` is passed explicitly.

### Import from Existing Key Material

Import a mnemonic or a raw private key. Secrets are read from environment
variables or stdin — never as CLI arguments — to avoid shell-history exposure.

```bash
# Mnemonic via stdin
echo "goose puzzle decorate ..." | onecipher wallet import --name "from-metamask" --mnemonic

# Private key via env var
ONECIPHER_PRIVATE_KEY="4c0883a691..." onecipher wallet import --name "from-evm" --private-key

# Ed25519 key (curve inferred from --chain)
ONECIPHER_PRIVATE_KEY="9d61b19d..." onecipher wallet import --name "from-sol" --private-key --chain solana

# Explicit keys for both curves
ONECIPHER_SECP256K1_KEY="4c0883a691..." \
ONECIPHER_ED25519_KEY="9d61b19d..." \
  onecipher wallet import --name "both"

# Interactive prompt
onecipher wallet import --name "manual" --interactive
```

Private key imports generate all chain accounts: the provided key covers its
curve's chains and a random key is generated for the other curve. The key
material is encrypted immediately and input buffers are zeroed.

## Inspection

```bash
onecipher wallet list          # all wallets in the vault
onecipher wallet info          # vault path + supported chains
```

## Export

Export operations extract key material for use with other wallet software.

### Export Secret

```bash
onecipher wallet export --wallet agent-treasury
```

- Mnemonic wallets output the phrase.
- Private-key wallets output JSON: `{"secp256k1":"hex...","ed25519":"hex..."}`.

### Export Public Key

```bash
onecipher wallet export --wallet agent-treasury --public-key --chain ethereum
onecipher wallet export --wallet agent-treasury --public-key --compressed   # secp256k1 only
```

Public keys are safe to share — no `--confirm`-style warnings needed.

## Passphrase Rotation

Change a wallet's encryption passphrase without touching key material:

```bash
onecipher wallet change-password --wallet agent-treasury

# Non-interactive (falls back to ONECIPHER_PASSPHRASE / ONECIPHER_NEW_PASSPHRASE)
onecipher wallet change-password --wallet agent-treasury \
  --passphrase "$OLD" --new-passphrase "$NEW"
```

API keys are unaffected: their encrypted secret copies are derived from the
API token, not the wallet passphrase.

## Rename & Delete

```bash
onecipher wallet rename --wallet old-name --new-name new-name

onecipher wallet delete --wallet old-name --confirm    # --confirm required
```

Deletion removes the encrypted wallet file and logs the operation to the
audit log. Ensure you have exported the mnemonic or private key first —
deletion is not reversible.

## Backup

OneCipher ships an age-encrypted `.ocbk` backup bundle format
(multi-X25519-recipient, `ocenv/1` `tag:backup` envelope):

```bash
# Export an age-encrypted backup of the wallet to two recipients
onecipher backup export --out ~/backups/treasury.ocbk --recipient <age1...> [--recipient ...]

# Restore from a backup bundle (identity of one of the export recipients)
onecipher backup import --in ~/backups/treasury.ocbk --identity <AGE-SECRET-KEY-1...>
```

The `.ocbk` bundle is self-contained and safe to store on any media —
it is encrypted at rest.

## Recovery

If the vault is lost but the mnemonic is available, re-import it:

```bash
echo "<mnemonic>" | onecipher wallet import --name "recovered" --mnemonic
```

All chain addresses derive deterministically from the same mnemonic at the
same account index, so the recovered wallet controls the same accounts.
For deeper recovery flows (scanning historical indices), derive candidate
addresses offline:

```bash
echo "<mnemonic>" | onecipher mnemonic derive --chain ethereum --count 20
```

## Migration (legacy keystore → age vault)

Wallets created before the unified secret vault used keystore v3-style JSON
files. Migrate them into age-encrypted vault entries:

```bash
onecipher migrate              # migrate legacy wallets into the unified vault
onecipher migrate --dry-run    # preview what would be migrated
onecipher migrate --rollback   # remove migrated .age entries (legacy files are kept)
```

Legacy `.json` files are never deleted by migration, so rollback is always
possible.

## Vault-Wide Key Rotation

Rotate the age encryption layer itself (e.g., after adding/removing devices):

```bash
onecipher age recipient add age1newdevice...
onecipher age reencrypt        # re-encrypt every entry to current recipients
```

This changes *who can decrypt* the vault — it does not rotate blockchain
keys. To rotate blockchain keys, create a new wallet and transfer assets.

## Lifecycle State Diagram

```
                    ┌─────────┐
                    │ Create  │
                    │ Import  │
                    └────┬────┘
                         │
                         ▼
                    ┌─────────┐
              ┌────▶│  Active │◀───────┐
              │     └────┬────┘        │
              │          │             │
         Unlock     Sign/Send    Attach Policy
              │          │             │
              │     ┌────▼────┐        │
              └─────│  Locked │        │
                    └────┬────┘        │
                         │             │
                    ┌────▼────┐   ┌────┴──────────┐
                    │ Export  │   │ change-password│
                    │ Backup  │   │ age reencrypt  │
                    └────┬────┘   └───────────────┘
                         │
                    ┌────▼────┐
                    │ Delete  │
                    └─────────┘
```

## References

- [BIP-39: Mnemonic Generation](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
- [BIP-32: Hierarchical Deterministic Wallets](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
- [Ethereum Keystore v3](https://ethereum.org/developers/docs/data-structures-and-encoding/web3-secret-storage)
- [age encryption](https://age-encryption.org/)
