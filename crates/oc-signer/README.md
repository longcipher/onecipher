# oc-signer

Multi-chain signing implementation for OneCipher. Provides chain-specific signers, HD derivation, and address encoding.

Part of the [OneCipher](https://github.com/longcipher/onecipher) project — a policy-gated, local-key-custody signing stack fully designed and implemented in accordance with the WalletConnect v2 protocol and the Open Wallet Standard.

## Overview

`oc-signer` supports:

- **EVM** (Ethereum, Polygon, Base, Arbitrum, Optimism, BSC, etc.) — secp256k1, EIP-55 addresses, EIP-191/EIP-712 message signing, EIP-7702 authorization
- **Solana** — Ed25519, base58 addresses
- **Sui** — Ed25519, BLAKE2b-256 hex addresses
- **Bitcoin** — secp256k1, BIP-84 native segwit (bech32)
- **Cosmos** — secp256k1, bech32 addresses
- **Tron** — secp256k1, base58check addresses
- **TON** — Ed25519, raw/bounceable addresses
- **Spark** (Bitcoin L2) — secp256k1, spark: prefixed addresses
- **XRPL** — secp256k1, Base58Check addresses
- **Filecoin** — secp256k1, f1 base32 addresses
- **NEAR** — Ed25519, implicit hex addresses, Borsh-serialized transactions

## License

Apache-2.0
