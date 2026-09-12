# Security Model

> Key isolation, memory hardening, threat model, and conformance requirements for OneCipher implementations.

## Key Lifecycle

```
1. OneCipher receives a sign request
2. Authenticate the caller with explicit request-scoped authorization
3. Evaluate attached policies before decryption when the surface requires them
4. Read the encrypted wallet or API-key-backed secret from disk
5. Derive the decryption key (Passkey/device-bound token/passphrase path, depending on the surface)
6. Decrypt key material (mnemonic or private key) into hardened memory
7. Derive the chain-specific signing key if needed
8. Sign the payload
9. Immediately zero out decrypted mnemonic/private key bytes, derived signing key bytes, and KDF-derived key bytes
10. Return only the signature or signed payload
```

Immediate zeroization is critical. In the Rust implementation this is handled with `HardenedBytes` — page-locked (`mlock`), DONT_DUMP-marked (`MADV_DONTDUMP`), and zeroized on drop.

## Memory Hardening

All sensitive material (mnemonics, private keys, passphrases) flows through `HardenedBytes`:

| Property | Mechanism |
|---|---|
| Page locking | `mlock()` prevents swapping to disk |
| Dump protection | `MADV_DONTDUMP` excludes from core dumps |
| Zeroize on drop | Cryptographic zeroing when value goes out of scope |
| Scope | Used in `oc-crypto`, `oc-signer` |

The `oc-crypto` crate has zero I/O and zero network dependencies (R51/R52). It is the security foundation of the entire stack.

## Authorization Handling

### 1. Interactive prompt (CLI mode)
The CLI prompts for the passphrase when an owner-driven flow needs it.

### 2. Passkey per request (local HTTP surfaces)
Local signing-sensitive JSON-RPC and WalletSigner requests carry a fresh
`PasskeyAuthorization` proof. Read-only helper methods such as health checks,
wallet listing, challenge minting, and balance reads remain unauthenticated,
but any auth-class signing or wallet-rpc operation verifies the
challenge/signature pair before it proceeds.

### 3. Daemon-internal capability token
WalletConnect-owned auth flows (`wc_authRequest`, daemon-controlled
`onecipher_signAuth`) do not forward a passkey proof over the relay. Instead,
the daemon injects a startup-minted internal token that the Key-Agent validates
before deriving the device-bound unlock token.

### 4. Environment variable (CLI mode)
The CLI reads `ONECIPHER_PASSPHRASE` and clears it immediately after reading.

> **Warning:** Environment variables remain the weakest supported owner credential delivery mechanism. They can leak via process inspection, crash dumps, or child-process inheritance if not cleared promptly.

## Threat Model

| Threat | Mitigation |
|---|---|
| Agent/LLM misuses a wallet via automation | Local automation must present a fresh Passkey proof; daemon-internal flows require a startup-minted token and can still be approval-gated |
| Key leaked to logs | OneCipher does not log key material; audit logging records operations only |
| Core dump contains keys | Process hardening disables core dumps / attach where supported |
| Swap file contains keys | Hardened secret buffers use `mlock()` where available |
| Cold boot / memory forensics | Keys are zeroized immediately after signing; exposure window is short |
| Compromised parent process memory | Enclaved: decrypted secrets live only in short-lived children; a parent-memory compromise sees authorization material and audit records, not keys |
| Compromised enclave-child memory | Narrow window (one request), sandboxed (seccomp/Seatbelt/job-object mitigations), zeroized on scope exit; a same-uid root attacker can still ptrace — anti-ptrace/non-dumpable raise the bar but are not a root boundary |
| Passphrase brute force | age scrypt slows offline guessing (auto-calibrated ~1 s work factor) |
| Token stolen, no disk access | Useless — encrypted key file not accessible |
| Disk access, no token | Can't decrypt — age X25519 (token bytes are the static secret) |
| Token + disk access | Can decrypt, but requires bypassing OneCipher process entirely |
| Owner passphrase changed | API keys unaffected (independently encrypted) |
| API key revoked | Encrypted copy deleted — token decrypts nothing |

## Key Caching

Decrypting key material via age scrypt adds latency. The implementation maintains a short-lived, in-memory cache of derived key material:

| Property | Requirement |
|---|---|
| TTL | No more than 30 seconds; 5 seconds recommended |
| Max entries | Bounded (32 entries) with LRU eviction |
| Memory protection | Cached key material MUST be `mlock()`'d and zeroized on eviction |
| Signal handling | Cache MUST be cleared on SIGTERM, SIGINT, and SIGHUP before process exit |
| Cache key | Derived from `SHA-256(mnemonic || passphrase || derivation_path || curve)` — never the raw mnemonic |

## Current Model: per-request subprocess enclave

### Enclaved signing (default on all surfaces)

```
Caller → sign_transaction / sign_message / signAuth / sign_typed_data /
         sign_user_op / wallet-rpc sign / intent Execute
           │
           └─► onecipher-lib (parent process)
                 ├── passkey or daemon-token authorization + wallet binding
                 ├── session-key liveness + stateful policy pre-check
                 ├── audit `pending` append (request_id, op, wallet, chain)
                 └── fork/exec onecipher --enclave-child (per request)
                       ├── scrub env, harden memory, install full sandbox
                       ├── re-validate request shape (stateless re-check)
                       ├── decrypt wallet secret (device-key or piped passphrase)
                       ├── sign (+ address/pubkey derivation)
                       ├── zeroize (drop-scope)
                       ├── write EnclaveResponse to stdout
                       └── exit
                 ├── timeout-kill on overrun (fail-closed, audit `resolved ok:false`)
                 ├── audit `resolved` append (request_id → pid → sig hash → latency)
                 └── return signature
```

Decrypted key material never exists in the parent address space. The child is
stateless — spawned per request, no daemon, no unlock step, no cache, no
sockets. Authorization stays parent-side (Passkey challenge state and session
records are parent-local by design); the child re-enforces everything
stateless: protocol version, op allowlist, field sizes, chain parsing, and
payload caps.

### In-process fallback (tests / `OC_ENCLAVE=off` only)

The pre-enclave in-process decrypt path is retained ONLY as an explicit escape
hatch: `OC_ENCLAVE=off` (`0`/`false`/`no`), or the `cfg(test)` hermetic
default so unit tests never spawn the real binary. Production deployments MUST
leave the enclave enabled (the default); running with `OC_ENCLAVE=off`
outside tests is unsupported. There is deliberately NO silent downgrade: a
spawn/timeout/child failure is a coded signing error, never a quiet return to
in-process signing.

### Pipe protocol (`crates/oc-keyagent/src/enclave.rs`)

Versioned (`oc_version = 1`; both sides fail closed on mismatch) JSON single-
line frames over stdin/stdout:

- `EnclaveRequest`: `oc_version`, `request_id` (parent correlation id),
  `op` (`ping` | `sign_message` | `sign_transaction` | `sign_typed_data` |
  `sign_user_op` | `sign_auth` | `public_key`), `wallet_id`, `chain_id`,
  `payload_hex`, `extra_json` (typed-data document), `index` (HD index,
  passphrase mode), `credential_hex` (owner passphrase, passphrase mode only;
  `None` selects device-key mode where no secret crosses the pipe),
  `vault_dir` (test isolation only — production is always `None`).
- `EnclaveResponse`: `oc_version`, echoed `request_id`, `ok`,
  `signature_hex`, `signed_tx_hex`, `address`, `public_key_hex`,
  `recovery_id`, child `pid` (audit attribution), `error` (coded, never key
  material).

The child inherits only an env allowlist (`HOME`, `USER`, `XDG_*`, `TMPDIR`,
`OC_STRICT_HARDEN`, plus Windows loader vars); `stderr` is nulled. The
per-request timeout defaults to 30 s (`OC_ENCLAVE_TIMEOUT_SECS` override;
unparseable values fall back to the default, never to "no timeout").

### Compromise model

- **Parent compromise** (UDS listener, auth, audit): the attacker sees
  Passkey proofs, session ids, and audit records — NOT decrypted keys. They
  can request signatures only through the same authorized front door (valid
  Passkey proof or daemon token per request), which is approval-gated and
  audit-logged.
- **Child compromise** (one request window): the attacker sees at most one
  wallet's key for milliseconds, inside a sandbox that denies non-UDS sockets
  (Linux seccomp BPF), all network (macOS Seatbelt), and dynamic code / remote
  images / crash dumps (Windows mitigations), with pages locked and zeroized
  on drop.
- **Pipe MITM (same uid)**: stdin/stdout pipes are same-uid local; cross-uid
  access is blocked by UDS/socket file modes (0700/0600) and the vault dir
  modes. A same-uid attacker who can already ptrace the parent gains nothing
  new from the pipe — and anti-ptrace/non-dumpable deny that ptrace.
- **Residual (honest)**: a same-uid **root** attacker defeats ptrace denial
  and can read either address space. The enclave raises the bar from "any
  renderer/RCE bug reads keys" to "persistent root read during a signing
  window" — it is not a hardware boundary (no SGX/SEV claim).

### Rollout (all stages landed)

- Stage 0: framing prototype + RFC; `sign` returned `EnclaveUnavailable`
  (fail-closed). ✅ landed (prior release)
- Stage 1: `--enclave-child` flag + opt-in `OC_ENCLAVE=1` daemon path for a
  single chain (EVM), fallback behind explicit `OC_ENCLAVE_FALLBACK=1`. ✅
  superseded by Stage 2 (the separate fallback flag was dropped: the only
  fallback knob is `OC_ENCLAVE=off`, and spawn failures never downgrade).
- Stage 2: default-on for all chains and all signing surfaces (Key-Agent
  handlers, CLI owner paths, wallet-rpc handlers, wallet-rpc intent signer;
  WC/HTTP-RPC intent Execute inherits it via the Key-Agent UDS path).
  In-process path kept behind `OC_ENCLAVE=off` (escape hatch). ✅ landed
  (this release)
- Stage 3: remove the in-process decrypt path. ⏳ scheduled for the next
  release — the parent still links the vault-decrypt code for the escape
  hatch; removal deletes `*_in_process` fallbacks and the `OC_ENCLAVE` knob.

### Open questions (closed)

- ~~Passkey challenge replay across the pipe (bind challenge to child PID +
  nonce?)~~ — resolved by construction: Passkey verification never crosses
  the pipe. The parent verifies against its local challenge table (single-use
  nonces) BEFORE spawning; the child receives no challenge, only the
  already-authorized `(wallet_id, chain, payload)`. `request_id` binds the
  audit trail, not the authorization.
- ~~Timeout + kill semantics under load (per-request spawn cost vs pool of
  pre-spawned children — pool reintroduces statefulness)~~ — per-request
   spawn kept (age scrypt dominates the cost, not `fork/exec`); timeout kill
  uses SIGKILL plus a bounded ~2 s reap (no zombies, no unbounded parent
  block). Pooling was rejected: reused children reintroduce cross-request
  state and break the wipe-per-request guarantee.
- ~~macOS Seatbelt profile for the child (stricter than the parent: no file
  writes except the audit pipe)~~ — the child applies the FULL Seatbelt
  deny-network profile (`apply_sandbox_reported`), which the embedded signing
  thread must skip. Out-of-process isolation therefore holds on macOS while
  the parent keeps its WSS relay; `filter_installed=true` for enclave
  children on macOS (see platform notes below).
- ~~Audit attribution when the child is killed mid-request (pending without
  resolved must alert, not silently drop)~~ — the parent appends `pending`
  before spawn and ALWAYS appends `resolved` after (success, child error, or
  timeout kill — with pid, latency, and an `alert` marker on failure). A
  `pending` entry with no matching `resolved` entry means the parent itself
  died mid-request.

### Platform notes (macOS / Windows degradation, written)

- **macOS**: `sandbox_init` (Seatbelt) is process-wide, so the embedded
  signing-thread sandbox deliberately skips it (it would sever the daemon's
  own WSS relay) and macOS in-process network isolation stays degraded
  (source-level R12a + runtime `lsof` checks). The ENCLAVE path has no such
  limitation: each child is a separate process with zero network needs, so it
  installs the full deny-network Seatbelt profile. Net effect: on macOS,
  subprocess isolation is strictly stronger than the old in-process model,
  and the "Seatbelt skipped" warning now applies only to the
  `OC_ENCLAVE=off` fallback.
- **Windows**: the child applies process mitigation policies (no dynamic
  code, no remote/low-label image loads) and suppresses WER crash dumps.
  Windows **job objects are intentionally NOT used**: nesting the child in a
  kill-on-close job would couple its lifetime to handle inheritance across
  the stdio pipes, and the parent-side timeout kill already bounds every
  child lifetime deterministically.

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

### N1 — Integrity non-goals (honest limitation)

Secret entries bind their lookup path and monotonic generation inside an
`ocenv/1` envelope (`oc-secret`), and `delete` retains a tombstone row so a
later insert uses `next = floor + 1` (saturating). This fails closed on
single-sided replays: a stale ciphertext file under a newer index, a
resurrected tombstone, or swapped entry paths.

A **joint rollback** of a ciphertext file *together with* its index row — or a
whole-commit restore (e.g. `git revert`, `git reset --hard`, filesystem
snapshot restore, full `index.jsonl` + `secrets/` copy from backup) — is NOT
detected and is indistinguishable from an intentional restore: the envelope
generation and the index floor agree again after the rollback. Implementations
MUST NOT claim rollback detection for this case. Operators who need rollback
evidence MUST rely on external append-only history outside the vault directory
(audit log, signed transparency record, remote backup journal).

## References

- [Linux prctl(2) PR_SET_DUMPABLE](https://man7.org/linux/man-pages/man2/prctl.2.html)
- [mlock(2) Memory Locking](https://man7.org/linux/man-pages/man2/mlock.2.html)
