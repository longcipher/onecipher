# OneCipher Web UI Approval Design — Complete Specification

> Status: **Design (approved, not yet implemented)**
> Date: 2026-07-25
> Owner: OneCipher Core
> Related: `specs/webui-approval/` (BDD spec, drives `/pb-build`)
> References: JoyID (`https://joy.id/`, `https://docs.joyid.dev/guide`), Rabby Wallet (`/Volumes/akext/tmp/Rabby`)

## 0. Goals & Non-Goals

### Goals

1. Provide a locally-served Web UI for the `onecipher` daemon so that
   browser-based dApps using WalletConnect v2 can route signing requests to
   a local page where the user approves/rejects.
2. Stay offline-first: no cloud dependency for risk analysis, transaction
   decoding, or simulation. Local `evm2` simulation replaces Rabby's
   server-side `preExecTx`.
3. Preserve all existing OneCipher hard gates: R56 (dependency isolation),
   R12 (revised — Key-Agent source path isolation + loopback-only listener),
   memory hardening (`HardenedBytes`), and the policy engine.
4. Reuse mature wallet UX patterns from Rabby (approval queue, risk levels,
   Sign-button gating, freshness-ledger cache invalidation) without copying
   browser-extension-specific or cloud-specific patterns.

### Non-Goals

- Mobile/native app (browser-only Web UI).
- dApp injection / content-script provider (WalletConnect v2 is the only
  bridge).
- Replacing the existing TUI (`bin/oc-cli/src/tui/`). The Web UI is an
  additional surface for browser-driven flows.
- Replacing the existing CLI `wc` commands. They remain for headless flows.
- TLS termination (HTTP on `127.0.0.1` is a secure context for WebAuthn).
- Multi-user / remote-access scenarios (loopback only).

## 1. Technology Selection

### Decision: Leptos CSR + axum + rust-embed + new crate `oc-webui`

| Dimension | Leptos CSR (chosen) | Topcoat (rejected) |
|---|---|---|
| Rendering | Client-side, WASM bundle, served as static assets by daemon | SSR-first, `$(...)` compiles to JS, owns the server |
| Maturity | 1.0 stable, production-ready | README: "Early-stage and experimental. Expect breaking changes." |
| Daemon fit | daemon keeps server ownership; axum mounts static + JSON API + WS on loopback | Topcoat wants to own the server → conflicts with existing WC server + control UDS |
| R56 impact | New deps only in `oc-webui` + `oc-cli`; isolated crates untouched | Same |
| R12 impact | Both need loopback `TcpListener`; R12 must be revised either way | Same |
| Offline | One-time WASM load, then pure `127.0.0.1` API + WS | No advantage over Leptos CSR for local scenario |
| Risk | Low | High (frequent breaking changes) |

**Rejected alternatives:** htmx + askama (insufficient for WebAuthn
client-side crypto); pure TypeScript + Vite (introduces Node toolchain,
violates "single Rust binary" philosophy).

### Build artifact layout

```
crates/oc-webui/                # new crate (axum router + approval queue + WebAuthn)
  src/
    router.rs                   # axum Router, mounts /api/* and /ws
    routes/{auth,approval,wallets,sessions,audit,settings,ws}.rs
    auth/{session,webauthn}.rs
    approval_queue.rs           # mpsc Receiver + DashMap<uuid, oneshot>
    embed.rs                    # rust-embed wraps frontend dist
    bootstrap.rs                # one-time bootstrap token
  frontend/                     # Leptos CSR project (separate trunk build)
    src/{app,api,state,cache,routes,components,theme,i18n}/
    Trunk.toml                  # trunk build -> dist/
bin/oc-cli/src/main.rs          # run_daemon() spawns axum::serve on loopback
```

## 2. Approval Flow Insertion & Data Flow

### Insertion point

`WcMethodRouter::handle` in
[crates/oc-netagent/src/wc_method_router.rs:118-401](file:///Volumes/akext/src/github.com/longcipher/onecipher/crates/oc-netagent/src/wc_method_router.rs#L118-L401),
**before** `forward(KeyAgentRequestKind::...)` for signing methods only.

Signing methods covered (from `wc_method_router.rs:143-264`):
- `eth_sendTransaction`, `eth_signTransaction`, `solana_signTransaction`,
  `onecipher_signTransaction` → `SignTransaction`
- `personal_sign`, `eth_sign`, `solana_signMessage`, `onecipher_signMessage`
  → `SignMessage`
- `eth_signTypedData_v4`, `onecipher_signTypedData` → `SignTypedData`
- `onecipher_signUserOp` → `SignUserOp`

Non-signing methods (`onecipher_listWallets`,
`onecipher_generateChallenge`, `onecipher_getBalance`) bypass the approval
gate.

### Approval mode switch

Stored in `~/.onecipher/config.toml`:

```toml
[webui]
enabled = true                  # daemon starts HTTP server when true
approval_mode = false           # OFF = implicit signing (current behavior)
approval_timeout_secs = 300     # 5 min, aligned with dApp wc_sessionRequest default
listen = "127.0.0.1:0"          # loopback, random port (no fixed-port probing)
session_timeout_secs = 1800     # 30 min WebAuthn session
auto_lock_at = ""               # ISO8601 deadline, empty = unlocked/not started
```

Runtime: `Arc<AtomicBool>` for `approval_mode`, shared by `WcMethodRouter`
and `oc-webui` settings route. Toggling via `POST /api/settings` or
`onecipher config set webui.approval_mode true`.

### Data flow (approval_mode = ON)

```
dApp ─WSS─▶ WC relay ─▶ WcWalletServer::run()
                              │ decrypt wc-2.0 envelope
                              ▼
                      WcMethodRouter::handle(method, params, topic)
                              │
                              ├─ Identify as signing method
                              ├─ Policy v3 11-step evaluation → Decision
                              │     ├─ Deny → reject immediately (Forbidden)
                              │     ├─ Warn → risk_level = Warning, reason recorded
                              │     └─ Allow → risk_level = Safe
                              ├─ evm2 simulation (EVM chains only)
                              │     ├─ success=false → risk_level = max(Danger)
                              │     └─ success=true → record balance_change + decoded_action
                              ├─ approval_mode.load(Relaxed)?
                              │     ├─ OFF and Safe → forward() [current behavior]
                              │     ├─ OFF and not Safe → still gate (risk-driven)
                              │     └─ ON → ApprovalChannel.request(pending)
                              │              │ mpsc::send((pending, oneshot_tx))
                              │              ▼
                              │        ApprovalQueue (oc-webui)
                              │        DashMap<uuid, oneshot_tx>
                              │              │ broadcast over WebSocket
                              │              ▼
                              │        Browser tab(s) render PendingApproval
                              │              │ user clicks Approve/Reject (two-step)
                              │              ▼
                              │        POST /api/approvals/{id}/decision
                              │              │
                              │              ▼
                              │        oneshot_tx.send(ApprovalDecision)
                              │              │
                              ◀──────────────┘
                              ├─ Approve  → forward() → Key-Agent UDS → sign
                              ├─ Reject   → JSON-RPC error -32001 Unauthorized
                              └─ Timeout  → JSON-RPC error -32001 RequestTimeout
                              ▼
                      WcWalletServer encrypts response, publishes to relay
```

### Core types (in `oc-netagent`, R56-clean — no axum/evm2)

```rust
// crates/oc-netagent/src/approval.rs
pub struct PendingApproval {
    pub request_id: Uuid,
    pub method: String,
    pub params: serde_json::Value,
    pub session_topic: String,
    pub dapp_origin: Option<String>,
    pub dapp_name: Option<String>,
    pub wallet_id: String,
    pub chain_id: Option<String>,         // CAIP-2
    pub created_at_unix: i64,
    pub expires_at_unix: i64,
    pub risk: RiskLevel,
    pub risk_reasons: Vec<RiskReason>,
    pub simulation: Option<TxSimulation>,
}

pub enum RiskLevel { Safe, Warning, Danger, Forbidden }

pub struct RiskReason {
    pub code: String,                     // "policy_warn_large_approval" | "sim_revert" | ...
    pub level: RiskLevel,
    pub message: String,
    pub source: RiskSource,               // Policy | Simulation | Static
    pub detail: serde_json::Value,
}

pub struct TxSimulation {
    pub success: bool,
    pub gas_used: Option<u64>,
    pub balance_change: Vec<TokenDelta>,
    pub decoded_action: Option<DecodedAction>,
    pub error: Option<String>,
}

pub enum ApprovalDecision {
    Approve,
    Reject { reason: String },
    Timeout,
}

pub struct ApprovalChannel {
    tx: mpsc::Sender<(PendingApproval, oneshot::Sender<ApprovalDecision>)>,
}
```

### Constraints

1. `oc-netagent` MUST NOT depend on `oc-webui`. Direction: `oc-webui` →
   `oc-netagent` (uses `ApprovalChannel`/`PendingApproval`/`ApprovalDecision`).
2. Multi-tab consistency: `DashMap<Uuid, oneshot::Sender>`. First `send` wins;
   subsequent attempts return HTTP 409. WebSocket broadcasts
   `ApprovalResolved { id, decision }` to sync other tabs.
3. Timeout: `tokio::time::timeout(approval_timeout, orx)`. On timeout, return
   JSON-RPC error code `-32001 RequestTimeout`. ApprovalQueue GCs expired
   entries.
4. dApp-agnostic: dApp sees standard WC methods; only the response may be
   delayed up to `approval_timeout_secs`.
5. Non-approval path: `approval_mode = false` AND `risk = Safe` ⇒ identical
   to current behavior, zero regression.

## 3. HTTP Server Architecture, R12 Revision, WebAuthn

### 3.1 HTTP server (loopback only)

- `axum::serve` on `127.0.0.1:0` (random port, written to
  `~/.onecipher/webui.port` mode 0600).
- WebSocket `/ws` for server→client push (pending approvals, sign-completed,
  auto-lock warnings).
- `rust-embed` serves Leptos CSR `dist/` (`index.html` + `pkg/*.wasm`).
- No CORS (loopback only, no cross-origin).

### 3.2 R12 revision (current R12 is broken — `nm` returns nothing because
binary is stripped; `strings | grep TcpStream` already matches 1 line from
`hpx-yawc` WSS client)

```
R12 (revised): Key-Agent code-path isolation
- R12a: oc-keyagent/oc-crypto/oc-policy/oc-session-key source MUST NOT
        reference TcpListener or TcpStream (verified via source grep, not nm)
- R12b: daemon binary MAY contain TcpStream (outbound WSS) and
        loopback-only TcpListener (approval UI)
- R12c: TcpListener MUST bind 127.0.0.1, MUST NOT bind 0.0.0.0 or non-loopback
- R12d: T12 seccomp filter MUST allow loopback bind, MUST deny non-loopback
        bind (runtime enforcement even if source is tampered)
- R12e: Key-Agent sync thread seccomp maintains network ban (UDS exception)
```

Verification commands (replace the broken `nm | grep -i tcp` in
`AGENTS.md`):

```bash
# R12a: source-level (replaces failed nm check)
! rg -n 'TcpListener|TcpStream' crates/oc-keyagent/src/ crates/oc-crypto/src/ \
                              crates/oc-policy/src/ crates/oc-session-key/src/
# R12c: runtime
lsof -iTCP -sTCP:LISTEN -P -n | grep onecipher  # only 127.0.0.1:* expected
```

### 3.3 WebAuthn Passkey authentication

**Path A chosen**: browser-native WebAuthn via `webauthn-rs`, separate
registry `~/.onecipher/webauthn_passkeys.json` (mode 0600). Existing
dApp-side Ed25519 `PasskeyPubkeyStore` (`~/.onecipher/passkeys.json`) is
untouched — Key-Agent still trusts only that one.

Rationale: WebCrypto cannot persist non-extractable Ed25519 keys across
sessions; browser-native WebAuthn (Face ID / Touch ID / security key) is the
only robust option. `webauthn-rs` is mature and matches OneCipher's
Passkey-first identity model.

### 3.4 Bootstrap flow (first-time registration)

```
1. daemon start → generate one-time bootstrap_token (32 bytes random, base64url)
   write to ~/.onecipher/bootstrap_token (mode 0600), TTL 5 min
2. user runs `onecipher webui open` → CLI reads port + token, opens
   https://127.0.0.1:port/register?bootstrap=<token>
3. daemon verifies bootstrap token (single-use, 5 min expiry)
4. browser calls navigator.credentials.create() → Passkey
5. POST /api/auth/webauthn/register/finish { credential, attestation }
6. daemon verifies via webauthn-rs, stores credential id + pubkey in
   webauthn_passkeys.json
7. Set session cookie (HttpOnly, SameSite=Strict; no Secure flag — HTTP)
```

### 3.5 Subsequent login

```
1. browser opens https://127.0.0.1:port/
2. daemon returns 401 + WWW-Authenticate: WebAuthn
3. front-end calls navigator.credentials.get() → user Face ID/Touch ID
4. POST /api/auth/webauthn/login/finish { assertion }
5. daemon verifies → set session cookie
6. subsequent /api/* carry cookie; daemon validates session
```

### 3.6 Session & auto-lock (improvement H)

```rust
struct Session {
    session_id: Uuid,
    webauthn_credential_id: Vec<u8>,
    created_at: i64,
    last_seen: i64,
    auto_lock_at: i64,    // persisted for crash recovery
}
```

- In-memory `DashMap<session_id, Session>` (cleared on daemon restart).
- `auto_lock_at` persisted to `config.toml` (atomic rename on each update).
- Daemon startup: if `now >= auto_lock_at` → immediate lock; else
  `tokio::time::sleep_until(auto_lock_at)`.
- Any `/api/*` call (authenticated) updates `last_seen` and
  `auto_lock_at = now + session_timeout_secs`, writes back to config.
- Lock event: clear DashMap, invalidate all cookies, WebSocket pushes
  `{ type: "auto_locked" }` 60s before and at deadline.

### 3.7 HTTPS vs HTTP

WebAuthn requires a secure context. `127.0.0.1` is a secure context per the
spec, so HTTP suffices. Cookie `Secure` flag cannot be set over HTTP; use
`HttpOnly; SameSite=Strict` only. No TLS certificate management burden.

### 3.8 oc-webui crate dependencies

```
oc-webui/Cargo.toml:
  axum (ws, macros), tower, tower-http (cors for dev only), rust-embed,
  webauthn-rs (danger-allow-state-serialisation), webauthn-rs-proto,
  tokio (sync, net, time), serde, serde_json, uuid (v4), dashmap, jiff,
  thiserror, tracing,
  oc-netagent (workspace), oc-core (workspace), oc-keyagent (workspace)
  # NOT: oc-crypto, oc-policy, oc-session-key (R56)
```

## 4. Risk Grading (Improvement A)

`oc-policy::v2::Decision` (or new v3) gains a `Warn` variant:

```rust
pub enum Decision {
    Allow,
    Warn(WarnReason),
    Deny(DenyReason),
}

pub enum WarnReason {
    LargeApproval { token: String, amount: u128 },
    NewContract { address: String },
    CrossChainBridge { dest_chain: String },
    HighGasUsage { gas_limit: u64 },
    UnverifiedDapp { origin: String },
    // extensible
}
```

The 11-step evaluation currently wired only to `PayX402` is extended to
`SignTransaction` / `SignMessage` / `SignTypedData` / `SignUserOp`. Internal
to `oc-policy`, no R56 impact.

Risk-level precedence (from Rabby `SignTx.tsx:817-828`):

```
FORBIDDEN > DANGER > WARNING > SAFE
```

- `Forbidden` (`Decision::Deny`) — WcMethodRouter rejects immediately, never
  enters queue.
- `Danger` — queue + Sign button disabled 5s + red border.
- `Warning` — queue + orange border + each `RiskReason` must be ack'd.
- `Safe` — implicit path if `approval_mode = false`, else queue (fast
  approve).

## 5. evm2 Transaction Simulation (Improvement B)

### 5.1 Crate `oc-sim`

```
crates/oc-sim/Cargo.toml:
  evm2 = { git = "https://github.com/alloy-rs/evm2", rev = "<pin>",
           default-features = false, features = ["std", "parse", "asm-keccak"] }
  alloy-primitives, alloy-eips, tokio (sync, spawn_blocking wrapper),
  serde, serde_json, thiserror, tracing, oc-core
  [features]
  default = []
  abi-fetch = ["dep:hpx"]   # optional Etherscan ABI fetch, off by default
```

### 5.2 Risk mitigation for evm2

- `evm2` is **not on crates.io** (as of 2026-07-25) — git pin to a specific
  commit, lockfile-pinned.
- `default-features = false`, only `["std", "parse", "asm-keccak"]` enabled.
  All precompile-heavy deps (`gmp-mpfr-sys`, `mcl_rust`, `blst`, `c-kzg`,
  `ark-bn254`, `ark-bls12-381`, `p256`) disabled.
- Abstracted behind `oc-sim::simulate_evm_tx(raw_tx, chain_id) -> Result<TxSimulation>`.
  Front-end and daemon never import `evm2` types directly — swapping back to
  `revm` later only touches `oc-sim` internals.
- CI adds `cargo audit` + `cargo deny` to monitor upstream RUSTSEC.

### 5.3 Simulation results

- `success: bool` — `evm2::Evm::transact` revert flag.
- `gas_used: u64` — from `ResultAndState`.
- `balance_change: Vec<TokenDelta>` — pre/post state diff.
- `decoded_action: Option<DecodedAction>` — ABI-decoded function call.
- `error: Option<String>` — revert message.

### 5.4 ABI decoding

- Local cache: `~/.onecipher/abi_cache/<address>.json` (mode 0600).
- Curated defaults ship with `oc-sim`: ERC-20, ERC-721, ERC-1155, Permit2,
  Uniswap V2/V3 router, Aave, Compound.
- Optional `abi-fetch` feature: `hpx` GET Etherscan `/api?module=contract&action=getabi`.
  Off by default (offline-first).
- Unknown calldata: UI displays raw hex + "Decoding failed (offline)".

### 5.5 Failure mode

Simulation failure does NOT block signing. `PendingApproval.simulation = None`
and UI shows raw params. `tracing::warn!` records the error for diagnosis.

## 6. Approval Queue Persistence (Improvement D)

- File: `~/.onecipher/logs/approval_queue.jsonl` (append-only, mode 0600,
  same directory and pattern as `audit.jsonl`).
- On enqueue: append `{"event":"pending","id":...,"approval":{...}}`.
- On resolve: append
  `{"event":"resolved","id":...,"decision":"approved|rejected|timeout","reason":"...","at":...}`.
- Daemon startup: replay file; re-queue any `pending` without a matching
  `resolved`; WebSocket pushes them to connected tabs.
- GC: daily cron (or on daemon start) archives records older than 7 days to
  `approval_queue.YYYY-MM-DD.jsonl.gz`.

## 7. Sign-Button Gating (Improvement C)

State machine (from Rabby `SubmitActions.tsx:32-90` + `SignTx.tsx:2966-2976`):

```
Disabled ───────────────► Armed ──────────────► Submitting
   │  (first click)         │  (Confirm click)    │  (await sign receipt)
   │                        │
   │                        ▼ (Cancel click)
   │                       Disabled
   ▼ (5s countdown elapses, all warnings ack'd, sim done)
  Disabled (auto-unlocked for first click)
```

- `Disabled` while: simulation pending, unprocessed `Warning` reasons, or
  `Danger` 5s countdown active.
- `Forbidden` hides Sign entirely; only Reject (red) shown.
- `Danger`: Sign disabled 5s, countdown displayed.
- `Warning`: each `RiskReason` rendered as a dismissible card; user MUST click
  "我已知晓" / "Acknowledge" to clear it before Sign unlocks.
- Two-step confirm: first click on Sign → reveal `Confirm Sign` + `Cancel`;
  second click on `Confirm Sign` → POST decision.

## 8. Frontend Leptos CSR Structure

### 8.1 Project layout

See Section 1 build artifact layout. The `frontend/` sub-project builds
independently via `trunk` to `dist/`, embedded into `oc-webui` via
`rust-embed`.

### 8.2 Routing & SortHat dispatcher (Improvement F)

```
/                    → SortHat (dispatcher, Redirects based on state)
/welcome             → first-time onboarding
/unlock              → WebAuthn login
/no-address          → no wallets yet
/dashboard           → portfolio + gas + current connection
/approvals           → pending approval list
/approvals/:id       → approval detail + Sign gating
/wallets             → wallet list
/wallets/create      → create (mnemonic)
/wallets/import      → import (mnemonic/keystore/private key)
/wallets/:id         → wallet detail + balances
/send                → initiate tx (StrayPage)
/sessions            → WC sessions (persistent mount)
/history             → audit/tx history (persistent mount)
/settings            → settings (persistent mount)
/settings/*          → settings sub-pages
```

SortHat decision order (single Redirect, no top-level switch):

```
1. no auth + no wallets        → /welcome
2. no auth + has wallets       → /unlock
3. authed + no wallets         → /no-address
4. authed + pending approval   → /approvals/{id}
5. authed + page_state_cache   → cached path
6. otherwise                   → /dashboard
```

`localStorage["oc_page_state"] = { path, search }` updated on route change,
restored by SortHat on refresh.

### 8.3 Persistent mounting for heavy views (Improvement G)

Sessions, History, Settings: mounted once, toggled via `class:hidden`
(`display:none`) rather than conditional render. Avoids re-subscribing to
WebSocket events / re-querying IndexedDB on each tab switch.

### 8.4 API contract

```
GET    /api/health
POST   /api/auth/bootstrap                           { token }
POST   /api/auth/webauthn/register/begin             → challenge
POST   /api/auth/webauthn/register/finish            { credential } → Set-Cookie
POST   /api/auth/webauthn/login/begin                → challenge
POST   /api/auth/webauthn/login/finish               { assertion } → Set-Cookie
POST   /api/auth/logout
GET    /api/auth/status                              → { unlocked, auto_lock_at? }
POST   /api/auth/lock

GET    /api/approvals                                → Vec<PendingApproval>
GET    /api/approvals/:id                            → PendingApproval
POST   /api/approvals/:id/decision                   { Approve | Reject{reason} }
GET    /api/approvals/history                        → Vec<ResolvedApproval>
POST   /api/approvals/:id/simulate                   → re-run evm2 sim (optional)

GET    /api/wallets                                  → Vec<WalletSummary>
POST   /api/wallets                                  { type, ... } → WalletId
GET    /api/wallets/:id                              → WalletInfo
GET    /api/wallets/:id/balances                     → Vec<TokenBalance>
DELETE /api/wallets/:id
POST   /api/wallets/:id/send                         { to, value, data, chain_id } → TxHash

GET    /api/wc/sessions                              → Vec<WcSession>
DELETE /api/wc/sessions/:topic
POST   /api/wc/pair                                  { uri }
POST   /api/wc/pair/generate                         { ttl_secs? } → { uri }

GET    /api/audit                                    → Vec<AuditEntry>
GET    /api/settings                                 → Settings
PATCH  /api/settings                                 { approval_mode?, ... }
GET    /api/policy/rules                             → Vec<Rule>
PATCH  /api/policy/rules/:id                         { enabled }
GET    /api/session-keys                             → Vec<SessionKey>
POST   /api/session-keys                             { wallet_id, chain_id, scope, ttl }
DELETE /api/session-keys/:id
GET    /api/secrets                                  → Vec<SecretMeta>
GET    /api/secrets/:id                              → SecretValue (requires 2nd WebAuthn)
POST   /api/secrets                                  { key, value }

GET    /ws  → WebSocket upgrade
  server→client:
    { type: "pending_approval", data: PendingApproval }
    { type: "approval_resolved", data: { id, decision } }
    { type: "sign_completed", data: { wallet_id, chain_id } }
    { type: "wc_session_changed", data: { topic, action } }
    { type: "policy_changed", data: { rule_id, enabled } }
    { type: "auto_lock_warning", data: { in_secs } }
    { type: "auto_locked" }
```

### 8.5 IndexedDB cache layer (Improvement E — Rabby's standout pattern)

Schema (Dexie via `rexie`):

```
wallets          id, updated_at
balances         wallet_id, chain_id, [wallet_id+chain_id], updated_at
wc_sessions      topic, state, created_at, updated_at
audit_log        id, session_id, [session_id+timestamp], chain_id, [chain_id+timestamp], timestamp
approval_history id, [wallet_id+timestamp], timestamp
sync             scene, wallet_id?, updated_at, is_syncing   ← freshness ledger
abi_cache        address, fetched_at
```

**Freshness ledger** (Rabby `db/schema/sync.ts` + `db/constants.ts`):

```
const CACHE_TTL_SECS = 600; // 10 min

read_or_fetch(scene, wallet_id?, fetch_fn):
  1. cached = db.get_cached(scene, wallet_id)
  2. if cached:
       fresh = db.get_sync(scene, wallet_id).updated_at > now - TTL
       if fresh: return cached
       else: spawn_local(refetch); return cached (stale-while-revalidate)
  3. else: blocking fetch; cache; set_sync(now); return
```

**Force-expire-on-event** (Rabby `background/index.ts:206-236`):

```
WebSocket event → invalidate(scene, wallet_id?) → set sync.updated_at = 0
  SignCompleted      → invalidate(balances, approval_history, audit_log, wc_sessions)
  WCSessionChanged   → invalidate(wc_sessions)
  PolicyChanged      → invalidate(policy_snapshot)
  ApprovalResolved   → invalidate(approval_history)
```

### 8.6 Theming (single naming, not Rabby's dual)

Three-layer CSS custom properties (from Rabby `cssvars.css:200-259`, but
**without** the dual-naming legacy compat):

```css
:root {
  /* 1. raw RGB triplet (for rgba()) */
  --oc-blue-rgb: 76, 101, 255;
  --oc-red-rgb: 235, 60, 60;
  --oc-neutral-1-rgb: 26, 26, 26;
  --oc-neutral-bg-1-rgb: 255, 255, 255;
  /* ... */

  /* 2. resolved color */
  --oc-blue: rgb(var(--oc-blue-rgb));
  --oc-neutral-title: rgb(var(--oc-neutral-1-rgb));
  --oc-neutral-bg-1: rgb(var(--oc-neutral-bg-1-rgb));

  /* 3. semantic alias (single naming, no --rabby-* / --r-* dual) */
  --oc-color-primary: var(--oc-blue);
  --oc-color-danger: var(--oc-red);
  --oc-bg-primary: var(--oc-neutral-bg-1);
}

html.dark {
  --oc-neutral-1-rgb: 240, 240, 240;
  --oc-neutral-bg-1-rgb: 22, 22, 22;
  /* only RGB layer overridden; resolved + alias auto-follow */
}
```

Single source: `oc-core::theme::Tokens` serializes to CSS vars string at
daemon startup, injected into `<style id="oc-tokens">`. Front-end reads CSS
vars, never duplicates.

### 8.7 i18n (Fluent, not Chrome messages.json)

`fluent-rs` + `fluent-leptos`. Locale files:
`frontend/src/i18n/locales/{en,zh-CN}.ftl`. Fluent handles plurals and ICU
natively. Lazy-loaded: first switch fetches `/locales/{lang}.ftl` (via
`rust-embed`), cached in `localStorage`.

### 8.8 WalletClient Proxy (from Rabby `app.tsx:48-114`)

Single `WalletClient` whose `call(method, params)` routes to
`POST /api/{method}`. No per-method wrappers. 401 response triggers
navigate to `/unlock`.

## 9. Phased Delivery Plan

### Phase W1 — Approval MVP

- `oc-webui` crate skeleton: axum router + rust-embed + bootstrap token +
  one-time WebAuthn registration
- `ApprovalChannel` type in `oc-netagent` + `WcMethodRouter` injection +
  `approval_mode` switch
- `approval_queue.jsonl` persistence + startup replay
- Front-end: SortHat + Unlock + ApprovalsList + ApprovalDetail (basic, no
  evm2 sim)
- WebSocket `/ws` for `pending_approval` + `approval_resolved`
- `onecipher webui open` CLI command
- R12 revision in `AGENTS.md` + source-level verification script
- `config.toml [webui]` section

### Phase W2 — Risk Grading + Sign Gating

- `oc-policy::Decision::Warn` variant + 11-step wired to signing methods
- `PendingApproval.risk` / `risk_reasons` populated by `WcMethodRouter`
- Front-end `RiskCard` + Sign-button state machine
  (Disabled → Armed → Submitting)
- Two-step confirm + Danger 5s countdown
- `/api/approvals/:id/simulate` endpoint (placeholder, returns None)

### Phase W3 — evm2 Transaction Simulation

- `oc-sim` crate (evm2 git pin + feature pruning)
- evm2 `transact` + state diff → `TxSimulation`
- ABI decoding (local cache + optional `abi-fetch`)
- Front-end `SimPanel` rendering `DecodedAction` + `balance_change` + `gas_used`
- Failure-mode degradation to raw hex

### Phase W4 — Full Web Wallet

- Wallets list / create / import / detail
- Send initiate-tx
- WC Sessions management (persistent mount)
- History audit log (persistent mount)
- Settings (approval mode / chains / policy / session keys / secrets)
- IndexedDB cache layer + freshness ledger + event invalidation
- Theming (light/dark) + Fluent i18n (en + zh-CN)
- Auto-lock with persisted deadline

## 10. Hard-Gate Verification

### R56 (dependency isolation — unchanged)

```bash
cargo tree -p oc-crypto      | grep -E 'evm2|axum|hyper|tower|rust-embed|webauthn'
cargo tree -p oc-policy      | grep -E 'evm2|axum|hyper|tower|rust-embed|webauthn'
cargo tree -p oc-keyagent    | grep -E 'evm2|axum|hyper|tower|rust-embed|webauthn'
cargo tree -p oc-session-key | grep -E 'evm2|axum|hyper|tower|rust-embed|webauthn'
# all four must produce no output
```

### R12 (revised)

```bash
# R12a: source-level (replaces failed nm check)
! rg -n 'TcpListener|TcpStream' crates/oc-keyagent/src/ crates/oc-crypto/src/ \
                              crates/oc-policy/src/ crates/oc-session-key/src/
# R12c: runtime — listener must be 127.0.0.1 only
lsof -iTCP -sTCP:LISTEN -P -n | grep onecipher
# R12d: T12 seccomp denies non-loopback bind at runtime (existing test)
```

### New workspace dependencies

| Dep | Version | Used by | R56 risk |
|---|---|---|---|
| `axum` | 0.8.9 (in lock) | oc-webui | none |
| `tower`, `tower-http` | latest | oc-webui | none |
| `rust-embed` | latest | oc-webui | none |
| `webauthn-rs`, `webauthn-rs-proto` | latest | oc-webui | none |
| `dashmap` | latest | oc-webui | none |
| `evm2` | git pin | oc-sim | none |
| `alloy-primitives`, `alloy-eips` | latest | oc-sim | none |
| `rexie`, `gloo-net`, `gloo-storage`, `fluent-leptos` | latest | oc-webui/frontend | none |

## 11. Rabby Pattern Adoption Summary

### Adopted

| Pattern | Rabby source | OneCipher adaptation |
|---|---|---|
| Approval-type → component routing | `Approval/index.tsx` | Leptos `match` on `ApprovalType` |
| Risk-level precedence (FORBIDDEN>DANGER>WARNING>safe) | `SignTx.tsx:817-828` | `oc-policy::Decision::{Deny,Warn,Allow}` → `RiskLevel` |
| "Processed rules" gate on Sign | `SignTx.tsx:2966-2976` | `Warning` reasons must be ack'd before Sign unlocks |
| Two-step Sign confirm | `SubmitActions.tsx:32-90` | Disabled → Armed → Submitting state machine |
| Balance-change surfacing | `useBalanceChange.ts` | Local `evm2` state diff (replaces cloud `preExecTx`) |
| Auto-lock with persisted deadline | `autoLock.ts:5-44` | `auto_lock_at` in `config.toml` |
| WC-as-keyring agnosticism | `keyring/index.ts:19` | Approval UI unaware of WC vs. UDS origin |
| Risk-level color tokens | `FooterBar.tsx:135-147` | `--oc-color-danger`/`warning` semantic aliases |
| SortHat dispatcher | `SortHat.tsx:9-92` | Leptos `<SortHat>` Redirect component |
| Page-state cache | `pageStateCache.ts` | `localStorage["oc_page_state"]` |
| Persistent mounting for heavy views | `DesktopRoute.tsx:72-86` | `class:hidden` toggle in Leptos |
| Compound-indexed IndexedDB | `db/schema/history.ts:29-33` | `[wallet_id+timestamp]` on `audit_log`/`approval_history` |
| Freshness ledger + force-expire-on-event | `db/schema/sync.ts` + `background/index.ts:206-236` | `sync` table + WS-event-driven invalidation |
| Reactive DB queries | `db/hooks/history.ts` via `useLiveQuery` | `use_live_query()` Leptos hook on Dexie `liveQuery` |
| Lazy locale loading | `i18n.ts:36-49` | Fetch `.ftl` on first switch, cache via `hasResourceBundle`-equivalent |
| Three-layer CSS custom properties | `cssvars.css:200-259` | `--oc-*-rgb` → `--oc-*` → `--oc-color-*` (single naming) |
| StrayPage full-page-form UX | `StrayPage`/`Welcome.tsx` | Send / Create / Import flows |
| Dashboard delegates to sub-components | `Dashboard/index.tsx:172-181` | `Dashboard` composes, sub-views implement |
| Proxy-based wallet RPC client | `app.tsx:48-114` | `WalletClient::call(method, params)` |
| Event-bus decoupling for unlock | `Unlock/index.tsx:235-237` | Leptos `Signal<AuthState>` updates |
| Session-key unlock caching | `password.ts:80-98` | In-memory unlocked keyring + `auto_lock_at` |
| Biometric-preferred unlock | `Unlock/index.tsx` | WebAuthn Face ID/Touch ID first |

### Rejected

| Pattern | Reason |
|---|---|
| Server-side `parseTx` / `preExecTx` | Offline-first; use local `evm2` |
| Closure-captured promise approval queue | MV3-specific; use `mpsc` + `oneshot` |
| `chrome.storage.local/session` | Use `oc-vault` + IndexedDB + `localStorage` |
| Four HTML entries (popup/notification/tab/desktop) | Single Web UI |
| Content-script / page-provider injection | WalletConnect v2 only |
| Offscreen document for HW wallet USB | daemon uses `hidapi`/`rusb` natively |
| `@debank/common` external chain registry | OneCipher has `oc-core::ChainType` (12 chains) |
| AntD + styled-components + Tailwind + Less mixed | Leptos picks **one** (Tailwind) |
| Dual-naming CSS tokens | Single `--oc-*` convention |
| `make-theme.js` Less→TS bridge | `oc-core::theme` single source |
| Rematch/Redux global store | Leptos `Signal`/`Resource` |
| String-held mnemonic | `HardenedBytes` enforced |
| Chrome `_locales/messages.json` | Fluent (`.ftl`) |
| MV3 SW liveness check | daemon is long-lived |
| `chrome.alarms` hourly tasks | `tokio::time::interval` |
| SecSDK / WardenPlugin anti-tamper | Compiled Rust already tamper-resistant |
| `wallet.json` V3 keystore (scrypt+AES-128-CTR) | OneCipher age-encrypted `.ocbk` |
| Hardcoded WC `projectId` | Configurable in `config.toml` |
| Per-page request serialization (content-script) | Daemon handles concurrent WC requests; UI renders multiple pending approvals |
| Four parallel state-management systems | One reactive primitive (`Signal`/`Resource`) + one cache (`use_live_query`) |
| `pending_tx_list` pre-exec forwarding | Local `evm2` handles nonce-conflict natively (single-version) |
| Pre-exec versioning (`v0`/`v1`/`v2`) | Local `evm2` is single-version |

## 12. Open Questions

None — all design decisions confirmed across Sections 1-7 above. The
`specs/webui-approval/` BDD spec is the executable source of truth; this
document is the human-readable companion.
