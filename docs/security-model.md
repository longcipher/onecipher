# Security Model

> Key isolation, memory hardening, threat model, and conformance requirements for OneCipher implementations.

## Key Lifecycle

```
1. OneCipher receives a sign request
2. If the credential is an API token, evaluate attached policies before decryption
3. Read the encrypted wallet or API-key-backed secret from disk
4. Derive the decryption key (Argon2id for passphrases, HKDF for API tokens)
5. Decrypt key material (mnemonic or private key) into hardened memory
6. Derive the chain-specific signing key if needed
7. Sign the payload
8. Immediately zero out decrypted mnemonic/private key bytes, derived signing key bytes, and KDF-derived key bytes
9. Return only the signature or signed payload
```

Immediate zeroization is critical. In the Rust implementation this is handled with `HardenedBytes` — page-locked (`mlock`), DONT_DUMP-marked (`MADV_DONTDUMP`), and zeroized on drop.

## Memory Hardening

All sensitive material (mnemonics, private keys, passphrases) flows through `HardenedBytes`:

| Property | Mechanism |
|---|---|
| Page locking | `mlock()` prevents swapping to disk |
| Dump protection | `MADV_DONTDUMP` excludes from core dumps |
| Zeroize on drop | Cryptographic zeroing when value goes out of scope |
| Scope | Used in `oc-crypto`, `oc-signer`, `oc-signing-core` |

The `oc-crypto` crate has zero I/O and zero network dependencies (R51/R52). It is the security foundation of the entire stack.

## Passphrase Handling

### 1. Interactive prompt (CLI mode)
The CLI prompts for the passphrase when needed.

### 2. Environment variable (CLI mode)
The CLI reads `ONECIPHER_PASSPHRASE` and clears it immediately after reading.

### 3. Function parameter (library API)
Library consumers pass the credential as a function parameter. That credential may be either the owner's passphrase or an `ows_key_...` API token.

> **Warning:** Environment variables remain the weakest supported delivery mechanism. They can leak via process inspection, crash dumps, or child-process inheritance if not cleared promptly.

## Threat Model

| Threat | Mitigation |
|---|---|
| Agent/LLM misuses a wallet via automation | API tokens scope access and trigger policy checks before decryption |
| Key leaked to logs | OneCipher does not log key material; audit logging records operations only |
| Core dump contains keys | Process hardening disables core dumps / attach where supported |
| Swap file contains keys | Hardened secret buffers use `mlock()` where available |
| Cold boot / memory forensics | Keys are zeroized immediately after signing; exposure window is short |
| Compromised process memory | Not fully mitigated in the current in-process model; a future subprocess enclave would address this |
| Passphrase brute force | Argon2id slows offline guessing; wallet envelopes use a minimum work factor of `2^16` |
| Token stolen, no disk access | Useless — encrypted key file not accessible |
| Disk access, no token | Can't decrypt — HKDF + AES-256-GCM |
| Token + disk access | Can decrypt, but requires bypassing OneCipher process entirely |
| Owner passphrase changed | API keys unaffected (independently encrypted) |
| API key revoked | Encrypted copy deleted — token decrypts nothing |

## Key Caching

Decrypting key material via Argon2id adds latency. The implementation maintains a short-lived, in-memory cache of derived key material:

| Property | Requirement |
|---|---|
| TTL | No more than 30 seconds; 5 seconds recommended |
| Max entries | Bounded (32 entries) with LRU eviction |
| Memory protection | Cached key material MUST be `mlock()`'d and zeroized on eviction |
| Signal handling | Cache MUST be cleared on SIGTERM, SIGINT, and SIGHUP before process exit |
| Cache key | Derived from `SHA-256(mnemonic || passphrase || derivation_path || curve)` — never the raw mnemonic |

## Current Model vs Future Enclave

### Current: in-process hardening + code-path policy enforcement

```
Agent → sign_transaction(wallet, chain, tx, "ows_key_...")
          │
          └─► onecipher-lib (same process)
                ├── token lookup + policy evaluation
                ├── HKDF decrypt wallet secret (mlock'd, zeroized on drop)
                ├── sign
                └── return signature
```

Policy enforcement is handled by the code path — the `ows_key_` credential triggers policy evaluation before decryption. The agent and signer share an address space. In-process hardening (mlock, zeroize, anti-ptrace, anti-coredump) reduces the window for key extraction.

### Future: per-request subprocess enclave

```
Agent → sign_transaction(wallet, chain, tx, "ows_key_...")
          │
          └─► onecipher-lib (parent process)
                ├── token lookup + policy evaluation
                └── fork/exec onecipher-enclave
                      ├── receive (token, wallet_id, tx) over stdin
                      ├── HKDF decrypt wallet secret
                      ├── sign
                      ├── zeroize
                      ├── write signature to stdout
                      └── exit
```

The decrypt→sign→wipe path moves to a child process. The parent never has the decrypted secret in its address space. The child is stateless — spawned per request, no daemon, no unlock step.

## Conformance Requirements

### Conformance Claims

An implementation claiming OneCipher conformance MUST declare the profiles it supports:

```text
OneCipher <supported profiles>
```

Examples:
- `OneCipher Storage + Signing + Policy + EVM Chain Profile`
- `OneCipher Storage + Signing + Lifecycle + Solana Chain Profile`

### Required Interoperability

Conforming implementations SHOULD ship or consume machine-readable test vectors for:
- Wallet file decryption and encryption
- API key file resolution and token verification
- Policy rule evaluation
- Chain-specific address derivation
- Transaction and message signing

When two conforming implementations exchange OneCipher artifacts, the following MUST remain interoperable:
- Wallet files can be parsed and validated consistently
- API key files can be resolved consistently by token hash
- Policy files produce the same allow or deny result for the same `PolicyContext`
- Canonical chain and account identifiers are preserved without lossy conversion

### Error Consistency

Implementations MUST preserve the error meanings defined by the [Signing Interface](signing-interface.md). They MUST NOT:
- Turn a policy denial into a generic authentication failure
- Collapse unsupported-chain errors into malformed-input errors
- Treat expired API keys as missing keys

### Security Requirements

**Secret Material** — implementations MUST:
- Decrypt wallet or API-key-backed secret material only for the duration of the operation
- Zeroize decrypted mnemonic, private key, derived key, and KDF output buffers after use
- Avoid writing decrypted secret material to logs, telemetry, or audit records

**Credential Handling** — implementations MUST:
- Treat owner credentials and API tokens as secrets
- Avoid echoing credentials in logs or human-readable errors
- Verify API token scope and policy attachments before any token-backed secret is decrypted

**Policy Enforcement** — implementations MUST:
- Evaluate built-in policy rules deterministically
- Short-circuit on denial when the policy model requires it
- Deny the request if an executable policy exits unsuccessfully or returns malformed output

Implementations MUST NOT provide a fallback path that bypasses token-attached policy evaluation.

**Audit Logging** — audit logs MUST be append-only. Records SHOULD include operation type, wallet identifier, chain identifier, API key identifier, allow/deny outcome, and timestamp. Records MUST NOT contain raw passphrases, API tokens, mnemonics, or private keys.

## References

- [Linux prctl(2) PR_SET_DUMPABLE](https://man7.org/linux/man-pages/man2/prctl.2.html)
- [mlock(2) Memory Locking](https://man7.org/linux/man-pages/man2/mlock.2.html)
