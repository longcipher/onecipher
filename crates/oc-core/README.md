# oc-core

Core types, CAIP-2/10 parsing, error types, and configuration for OneCipher. Zero crypto dependencies.

Part of the [OneCipher](https://github.com/longcipher/onecipher) project — a policy-gated, local-key-custody signing stack fully designed and implemented in accordance with the WalletConnect v2 protocol and the Open Wallet Standard.

## Overview

`oc-core` provides:

- CAIP-2 and CAIP-10 chain/account identifier parsing
- Core error types used across all OneCipher crates
- Wallet and API key configuration structures
- Vault path resolution (defaults to `~/.onecipher/`)

## License

Apache-2.0
