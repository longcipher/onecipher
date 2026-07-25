# Tasks — OneCipher Web UI Approval

> Spec dir: `specs/webui-approval/`
> Source of truth: `specs/webui-approval/features/*.feature`
> DAG ordering: tasks below are listed in dependency order. No forward references.
> Each task's Verification is machine-checkable.

## Conventions

- **Context:** What the task does and why.
- **Verification:** Exact commands + expected output.
- **Status:** `pending` | `in_progress` | `completed` (set by builder).
- **Scenario Coverage:** `@<tag>` from `features/*.feature`, or `N/A` for non-BDD tasks.

---

# Phase W1 — Approval MVP

## Task W1.0 — Add `[webui]` config section to `oc-core::config`

- **Context:** Introduce the `[webui]` table in `~/.onecipher/config.toml` with
  fields: `enabled` (bool, default false), `approval_mode` (bool, default false),
  `approval_timeout_secs` (u64, default 300), `listen` (string, default
  `"127.0.0.1:0"`), `session_timeout_secs` (u64, default 1800), `auto_lock_at`
  (string, default `""`). Add serde defaults; existing config files without
  the section MUST still parse (backward compat).
- **Verification:**
  ```bash
  cargo test -p oc-core --lib config
  # Expected: all config tests pass, including a new test asserting
  # that a config without [webui] parses to defaults.
  cargo build -p oc-core
  # Expected: compiles cleanly.
  ```
- **Status:** 🟢 DONE
- **Scenario Coverage:** `@w1-settings-get`
- **Loop Type:** TDD-only
- **Behavioral Contract:** A config file without `[webui]` section MUST parse to defaults; a config with `[webui]` MUST parse all fields.
- **Simplification Focus:** Uses serde defaults; no migration logic needed (backward compat via `#[serde(default)]`).
- **BDD Verification:** N/A (type-level foundation, no user-facing scenario)
- **Advanced Test Verification:** `cargo test -p oc-core --lib config` — new test asserting backward-compat parse.
- **Runtime Verification:** N/A (library crate, no runtime)

## Task W1.1 — Define `ApprovalChannel` types in `oc-netagent`

- **Context:** Create `crates/oc-netagent/src/approval.rs` defining
  `PendingApproval`, `RiskLevel`, `RiskReason`, `RiskSource`, `TxSimulation`,
  `TokenDelta`, `DecodedAction`, `ApprovalDecision`, `ApprovalChannel`. All
  types `Serialize`/`Deserialize` via `serde` and `Debug`. `ApprovalChannel`
  wraps `mpsc::Sender<(PendingApproval, oneshot::Sender<ApprovalDecision>)>`
  and exposes `async fn request(&self, p: PendingApproval, timeout: Duration)
  -> ApprovalDecision`. Re-export from `crates/oc-netagent/src/lib.rs`.
  No new dependencies on isolated crates (R56 unaffected).
- **Verification:**
  ```bash
  cargo build -p oc-netagent
  cargo test -p oc-netagent --lib approval
  cargo tree -p oc-keyagent | grep -E 'evm2|axum|webauthn'
  # Expected: build + tests pass; cargo tree outputs nothing.
  ```
- **Status:** 🟢 DONE
- **Scenario Coverage:** `@w1-approval-mode-on` `@w1-approve` `@w1-reject` `@w1-timeout` (type-level foundation)
- **Loop Type:** TDD-only
- **Behavioral Contract:** `ApprovalChannel::request()` MUST send the PendingApproval over mpsc and await the oneshot response with a timeout, returning `ApprovalDecision::Timeout` on expiry.
- **Simplification Focus:** Wraps existing tokio primitives; no custom queue abstraction.
- **BDD Verification:** N/A (type-level foundation)
- **Advanced Test Verification:** `cargo test -p oc-netagent --lib approval` — unit test for channel send/receive and timeout.
- **Runtime Verification:** N/A (library crate)

## Task W1.2 — Add `Decision::Warn` variant to `oc-policy`

- **Context:** Add `Warn(WarnReason)` to `oc-policy::v2::Decision` (or new v3
  if cleaner). Define `WarnReason` enum with variants: `LargeApproval`,
  `NewContract`, `CrossChainBridge`, `HighGasUsage`, `UnverifiedDapp`. Each
  variant carries relevant fields. Update all `match` arms on `Decision` to
  handle `Warn`. Wire the existing 11-step evaluation to also accept
  `SignTransaction`/`SignMessage`/`SignTypedData`/`SignUserOp` request types
  (currently only `PayX402`). No new external deps.
- **Verification:**
  ```bash
  cargo build -p oc-policy
  cargo test -p oc-policy
  cargo tree -p oc-policy | grep -E 'evm2|axum|webauthn|tokio|reqwest'
  # Expected: all pass; cargo tree outputs nothing.
  ```
- **Status:** 🟢 DONE
- **Scenario Coverage:** `@w2-policy-warn` `@w2-policy-deny-forbidden` (type-level foundation)
- **Loop Type:** TDD-only
- **Behavioral Contract:** `Decision::Warn(WarnReason)` MUST be handled in all existing `match` arms on `Decision`. The 11-step evaluation MUST accept signing request types (not just `PayX402`).
- **Simplification Focus:** Extends existing enum; no new crate or policy engine rewrite.
- **BDD Verification:** N/A (type-level foundation)
- **Advanced Test Verification:** `cargo test -p oc-policy` — all existing + new tests pass.
- **Runtime Verification:** N/A (library crate, R56 verified via `cargo tree`)

## Task W1.3 — Inject `ApprovalChannel` into `WcMethodRouter`

- **Context:** Extend `WcMethodRouter` (in
  `crates/oc-netagent/src/wc_method_router.rs`) with fields: `approval:
  Option<ApprovalChannel>`, `approval_mode: Arc<AtomicBool>`,
  `approval_timeout: Duration`, `approval_log:
  Arc<ApprovalLog>`. Update `WcMethodRouter::new()` (or builder) to accept
  these. In `handle()`, for signing methods (`eth_sendTransaction`,
  `eth_signTransaction`, `solana_signTransaction`, `onecipher_signTransaction`,
  `personal_sign`, `eth_sign`, `solana_signMessage`, `onecipher_signMessage`,
  `eth_signTypedData_v4`, `onecipher_signTypedData`, `onecipher_signUserOp`),
  before `forward()`:
  1. Call `oc-policy` 11-step evaluation → map `Deny`→immediate reject,
     `Warn`→Warning level, `Allow`→Safe.
  2. If `approval_mode=false` AND `risk=Safe` → `forward()` (zero regression).
  3. Otherwise construct `PendingApproval`, append to `approval_log`, call
     `approval.request(pending, timeout).await`.
  4. On `Approve` → `forward()` + log resolved "approved".
     On `Reject{reason}` → JSON-RPC error -32001 "user rejected" + log resolved "rejected".
     On `Timeout` → JSON-RPC error -32001 "approval timeout" + log resolved "timeout".
  Non-signing methods bypass entirely. Simulation field set to `None` for
  now (W3 populates it).
- **Verification:**
  ```bash
  cargo build -p oc-netagent
  cargo test -p oc-netagent
  # Expected: all tests pass; new unit test asserts that with
  # approval_mode=false and risk=Safe, forward() is called directly
  # (no channel send).
  ```
- **Status:** 🟢 DONE
- **Scenario Coverage:** `@w1-approval-mode-off` `@w1-approval-mode-on` `@w1-approve` `@w1-reject` `@w1-timeout` `@w1-non-signing-bypass`
- **Loop Type:** TDD-only
- **Behavioral Contract:** When `approval_mode=false` AND `risk=Safe`, `forward()` MUST be called directly (zero regression). Otherwise, construct `PendingApproval`, append to log, call `approval.request()`. Non-signing methods MUST bypass entirely.
- **Simplification Focus:** Simulation field set to `None` (W3 populates it). No separate approval service — inline in `WcMethodRouter::handle`.
- **BDD Verification:** `cargo test -p oc-conformance --test conformance -- webui_approval` after integration
- **Advanced Test Verification:** `cargo test -p oc-netagent --lib wc_method_router` — new unit test for approval_mode=false + Safe path.
- **Runtime Verification:** N/A (library crate)

## Task W1.4 — Implement `ApprovalLog` persistence

- **Context:** Create `crates/oc-netagent/src/approval_log.rs` with
  `ApprovalLog` struct wrapping a file handle to
  `~/.onecipher/logs/approval_queue.jsonl` (mode 0600). Methods: `async fn
  append_pending(&self, p: &PendingApproval)`, `async fn append_resolved(&self,
  id: Uuid, decision: &str, reason: &str)`, `async fn replay_unresolved(&self)
  -> Vec<PendingApproval>`, `async fn gc_older_than(&self, days: u64)`. Use
  `tokio::fs` with append mode; each line is one JSON object. Replay reads
  the file line-by-line and returns `pending` events whose `id` has no
  later `resolved` event.
- **Verification:**
  ```bash
  cargo test -p oc-netagent --lib approval_log
  # Expected: tests cover append + replay + gc, including a test where a
  # pending event has no matching resolved event and is replayed.
  ```
- **Status:** 🟢 DONE
- **Scenario Coverage:** `@w1-persist-pending` `@w1-persist-resolved-gc`
- **Loop Type:** TDD-only
- **Behavioral Contract:** `append_pending` writes a JSON line with `"event":"pending"`. `append_resolved` writes `"event":"resolved"`. `replay_unresolved` returns pending events whose `id` has no later resolved event. `gc_older_than` removes entries older than N days.
- **Simplification Focus:** Append-only JSONL; no database. Each line is one JSON object. Replay is a linear scan.
- **BDD Verification:** N/A (covered by W1.9 integration)
- **Advanced Test Verification:** `cargo test -p oc-netagent --lib approval_log` — tests cover append + replay + gc.
- **Runtime Verification:** N/A (library crate)

## Task W1.5 — Create `oc-webui` crate skeleton

- **Context:** Add `crates/oc-webui/` to the workspace. `Cargo.toml`
  dependencies: `axum` (features `ws`, `macros`), `tower`, `tower-http`,
  `rust-embed`, `webauthn-rs`, `webauthn-rs-proto`, `tokio` (features `sync`,
  `net`, `time`), `serde`, `serde_json`, `uuid` (feature `v4`), `dashmap`,
  `jiff`, `thiserror`, `tracing`, `oc-netagent` (workspace), `oc-core`
  (workspace), `oc-keyagent` (workspace). NOT `oc-crypto`, `oc-policy`,
  `oc-session-key`. Expose `pub async fn run_webui_server(listen: &str,
  approval_rx: mpsc::Receiver<...>, wc_server_handle: WcServerHandle,
  ka_sock_path: PathBuf, state_dir: PathBuf, config: WebuiConfig) ->
  io::Result<(JoinHandle, u16)>` returning the bound port. Stub all routes
  to return 501 Not Implemented for now.
- **Verification:**
  ```bash
  cargo build -p oc-webui
  cargo tree -p oc-webui | grep -E 'evm2|oc-crypto|oc-policy|oc-session-key'
  # Expected: build succeeds; cargo tree outputs nothing for forbidden deps.
  # oc-netagent/oc-core/oc-keyagent may appear (allowed).
  ```
- **Status:** 🟢 DONE
- **Scenario Coverage:** N/A
- **Loop Type:** TDD-only
- **Behavioral Contract:** `cargo build -p oc-webui` MUST succeed. `cargo tree -p oc-webui` MUST NOT show `oc-crypto`, `oc-policy`, `oc-session-key`, or `evm2`. All routes stub to 501.
- **Simplification Focus:** Skeleton only — stub routes. No actual auth or approval logic yet.
- **BDD Verification:** N/A (skeleton)
- **Advanced Test Verification:** `cargo build -p oc-webui` — compiles cleanly.
- **Runtime Verification:** N/A (skeleton)

## Task W1.6 — Implement WebAuthn bootstrap + registration + login

- **Context:** In `oc-webui`, implement `auth/bootstrap.rs` (one-time token
  generation, 5-min TTL, single-use), `auth/webauthn.rs` (registration
  begin/finish, login begin/finish via `webauthn-rs`), `auth/session.rs`
  (in-memory `DashMap<session_id, Session>`, cookie middleware). Routes:
  `POST /api/auth/bootstrap`, `POST /api/auth/webauthn/register/begin`,
  `POST /api/auth/webauthn/register/finish`, `POST
  /api/auth/webauthn/login/begin`, `POST /api/auth/webauthn/login/finish`,
  `POST /api/auth/logout`, `GET /api/auth/status`, `POST /api/auth/lock`.
  Store credentials in `~/.onecipher/webauthn_passkeys.json` (mode 0600).
  Cookie: `HttpOnly; SameSite=Strict` (no `Secure` — HTTP). Sessions
  auto-expire at `auto_lock_at`; activity extends.
- **Verification:**
  ```bash
  cargo test -p oc-webui --lib auth
  # Expected: unit tests for bootstrap TTL, single-use, registration
  # verification (mock webauthn-rs), session creation/extension.
  ```
- **Status:** 🟢 DONE
- **Scenario Coverage:** `@w1-bootstrap-token` `@w1-bootstrap-expired` `@w1-webauthn-register` `@w1-webauthn-login` `@w1-webauthn-session-missing` `@w1-auto-lock-deadline` `@w1-auto-lock-fire` `@w1-auto-lock-warning` `@w1-activity-extends`
- **Loop Type:** TDD-only
- **Behavioral Contract:** Bootstrap token: 32 bytes random, 5-min TTL, single-use, mode 0600. WebAuthn: registration stores credential in `webauthn_passkeys.json` (NOT `passkeys.json`). Cookie: `HttpOnly; SameSite=Strict`. Sessions auto-expire at `auto_lock_at`; activity extends.
- **Simplification Focus:** In-memory `DashMap` for sessions (no persistent session store). `webauthn-rs` handles all crypto — no manual COSE parsing.
- **BDD Verification:** `cargo test -p oc-conformance --test conformance -- webui_approval` after integration
- **Advanced Test Verification:** `cargo test -p oc-webui --lib auth` — bootstrap TTL, single-use, registration verification, session creation/extension.
- **Runtime Verification:** N/A (library crate)

## Task W1.7 — Implement `ApprovalQueue` + REST + WebSocket routes

- **Context:** In `oc-webui`, implement `approval_queue.rs`:
  `ApprovalQueue` holds `mpsc::Receiver` + `DashMap<Uuid,
  oneshot::Sender<ApprovalDecision>>` + `broadcast::Sender<WsEvent>`. On
  receive, insert into DashMap and broadcast `pending_approval`. On decision
  POST, find sender, send decision, remove from DashMap, broadcast
  `approval_resolved`. Second POST returns 409. Routes: `GET /api/approvals`,
  `GET /api/approvals/:id`, `POST /api/approvals/:id/decision`, `GET
  /api/approvals/history`, `GET /ws` (WebSocket upgrade; reject
  unauthenticated with close code 4401).
- **Verification:**
  ```bash
  cargo test -p oc-webui --lib approval_queue
  # Expected: tests cover enqueue, first-decision-wins, 409 on second,
  # WebSocket broadcast.
  ```
- **Status:** 🟢 DONE
- **Scenario Coverage:** `@w1-approval-mode-on` `@w1-approve` `@w1-reject` `@w1-multi-tab` `@w1-ws-pending-approval` `@w1-ws-approval-resolved` `@w1-ws-unauthenticated`
- **Loop Type:** TDD-only
- **Behavioral Contract:** `ApprovalQueue` holds mpsc Receiver + DashMap of oneshot Senders + broadcast Sender. On receive: insert + broadcast `pending_approval`. On POST decision: find sender, send, remove, broadcast `approval_resolved`. Second POST returns 409. WebSocket rejects unauthenticated with close code 4401.
- **Simplification Focus:** DashMap for first-wins concurrency (no distributed lock). Broadcast channel for WS fan-out.
- **BDD Verification:** `cargo test -p oc-conformance --test conformance -- webui_approval` after integration
- **Advanced Test Verification:** `cargo test -p oc-webui --lib approval_queue` — enqueue, first-decision-wins, 409 on second, WS broadcast.
- **Runtime Verification:** N/A (library crate)

## Task W1.8 — Implement settings + health routes

- **Context:** Routes: `GET /api/health` (no auth, returns `{ ok: true,
  version }`), `GET /api/settings` (auth, returns webui config), `PATCH
  /api/settings` (auth, updates `approval_mode` and other fields atomically;
  updates `Arc<AtomicBool>` in `WcMethodRouter` via shared handle; rewrites
  `config.toml` atomically).
- **Verification:**
  ```bash
  cargo test -p oc-webui --lib routes::settings
  # Expected: tests cover health (no auth), settings get/patch, atomicity.
  ```
- **Status:** 🟢 DONE
- **Scenario Coverage:** `@w1-health` `@w1-settings-get` `@w1-settings-patch-approval-mode`
- **Loop Type:** TDD-only
- **Behavioral Contract:** `GET /api/health` returns `{ ok: true, version }` without auth. `GET /api/settings` requires auth, returns webui config. `PATCH /api/settings` updates fields atomically, updates `Arc<AtomicBool>` in `WcMethodRouter`, rewrites `config.toml` atomically.
- **Simplification Focus:** Atomic config rewrite via temp file + rename (no WAL). Settings endpoint updates shared state via existing Arc<AtomicBool>.
- **BDD Verification:** `cargo test -p oc-conformance --test conformance -- api_surface` after integration
- **Advanced Test Verification:** `cargo test -p oc-webui --lib routes::settings` — health (no auth), settings get/patch, atomicity.
- **Runtime Verification:** N/A (library crate)

## Task W1.9 — Wire `run_webui_server` into daemon `run_daemon`

- **Context:** In `bin/oc-cli/src/main.rs::run_daemon()`, after
  `oc_netagent::run_server_controlled()` sets up the WC server, construct the
  `mpsc::channel` for approvals, build `ApprovalChannel`, inject into
  `WcMethodRouter` (via the netagent builder), spawn
  `oc_webui::run_webui_server()` in a `tokio::select!` arm alongside the
  existing three arms. Write the bound port to `~/.onecipher/webui.port`
  (mode 0600). On daemon start, call `ApprovalLog::replay_unresolved()` and
  re-queue via the ApprovalQueue. Conditionally spawn only when
  `config.webui.enabled`.
- **Verification:**
  ```bash
  cargo build --bin onecipher
  ./target/debug/onecipher daemon &
  sleep 2
  curl -s http://127.0.0.1:$(cat ~/.onecipher/webui.port)/api/health
  # Expected: {"ok":true,"version":"..."}
  kill %1
  ```
- **Status:** 🟢 DONE
- **Scenario Coverage:** `@w1-persist-pending`
- **Loop Type:** TDD-only
- **Behavioral Contract:** After `run_server_controlled()` sets up WC server, construct mpsc channel, build `ApprovalChannel`, inject into `WcMethodRouter`, spawn `run_webui_server()` in `tokio::select!`. Write bound port to `~/.onecipher/webui.port` (mode 0600). On start, call `ApprovalLog::replay_unresolved()` and re-queue. Conditionally spawn only when `config.webui.enabled`.
- **Simplification Focus:** Single `tokio::spawn` for webui server. No separate process or supervisor.
- **BDD Verification:** `cargo test -p oc-conformance --test conformance -- webui_approval` after integration
- **Advanced Test Verification:** `cargo build --bin onecipher` — compiles cleanly.
- **Runtime Verification:** `./target/debug/onecipher daemon &` → `curl -s http://127.0.0.1:$(cat ~/.onecipher/webui.port)/api/health` → `{"ok":true,"version":"..."}`

## Task W1.10 — Add `onecipher webui open` CLI command

- **Context:** In `bin/oc-cli/src/commands/`, add `webui.rs` with an `open`
  subcommand. Reads `~/.onecipher/webui.port` and
  `~/.onecipher/bootstrap_token`, constructs
  `https://127.0.0.1:<port>/register?bootstrap=<token>`, opens it via
  `webbrowser` crate (workspace dep). If bootstrap_token is expired or
  missing, instruct user to restart the daemon.
- **Verification:**
  ```bash
  cargo build --bin onecipher
  ./target/debug/onecipher webui open
  # Expected: opens browser at the register URL (or prints URL if headless).
  ```
- **Status:** 🟢 DONE
- **Scenario Coverage:** `@w1-bootstrap-token` (CLI side)
- **Loop Type:** TDD-only
- **Behavioral Contract:** Reads `~/.onecipher/webui.port` and `~/.onecipher/bootstrap_token`, constructs `https://127.0.0.1:<port>/register?bootstrap=<token>`, opens via `webbrowser` crate. If token expired/missing, instruct user to restart daemon.
- **Simplification Focus:** `webbrowser::open()` — one line. No custom browser detection.
- **BDD Verification:** N/A (CLI command, manual verification)
- **Advanced Test Verification:** `cargo build --bin onecipher` — compiles cleanly.
- **Runtime Verification:** `./target/debug/onecipher webui open` — prints or opens URL.

## Task W1.11 — Front-end Leptos CSR skeleton + SortHat + Unlock

- **Context:** Create `crates/oc-webui/frontend/` with `Cargo.toml`
  (`leptos` features `csr`, `gloo-net`, `gloo-storage`, `rexie`,
  `fluent-leptos`, `web-sys`). `Trunk.toml` builds to `dist/`. `index.html`
  mounts `<App/>`. Implement `app.rs` (Router + SortHat + GlobalPortals),
  `routes/sort_hat.rs` (Redirect logic per Section 4.2 of design doc),
  `routes/unlock.rs` (WebAuthn login flow via `navigator.credentials`),
  `routes/welcome.rs`, `routes/no_address.rs`, `routes/dashboard/` (minimal
  placeholder). `api/mod.rs` WalletClient Proxy. `state/auth.rs` Signal.
  `localStorage["oc_page_state"]` update on route change.
- **Verification:**
  ```bash
  cd crates/oc-webui/frontend && trunk build --release
  # Expected: dist/index.html + dist/pkg/*.wasm generated without errors.
  ```
- **Status:** 🟢 DONE
- **Scenario Coverage:** `@w4-sort-hat-no-auth-no-wallets` `@w4-sort-hat-no-auth-has-wallets` `@w4-sort-hat-pending-approval` `@w4-sort-hat-page-state-cache` `@w1-webauthn-login`
- **Loop Type:** TDD-only
- **Behavioral Contract:** `App` component renders Router + SortHat + GlobalPortals. SortHat redirects based on auth state and wallet presence. Unlock page implements WebAuthn login via `navigator.credentials`. `localStorage["oc_page_state"]` updated on route change.
- **Simplification Focus:** Minimal placeholder for Dashboard. No IndexedDB cache yet (W4). Uses gloo-net for fetch.
- **BDD Verification:** N/A (frontend build verification only)
- **Advanced Test Verification:** `cd crates/oc-webui/frontend && trunk build --release` — WASM generated without errors.
- **Runtime Verification:** N/A (build-time verification only)

## Task W1.12 — Front-end ApprovalsList + ApprovalDetail (basic)

- **Context:** Implement `routes/approvals/mod.rs` (list view, subscribes to
  WebSocket `pending_approval` events, renders cards with risk-level color
  borders), `routes/approvals/detail.rs` (single approval, renders method,
  params, dapp origin, risk reasons, basic Sign/Reject buttons — no
  two-step gating yet, that's W2). Wire to `/api/approvals` and
  `/api/approvals/:id/decision`. WebSocket client in `api/ws.rs` broadcasts
  to `Signal<Vec<PendingApproval>>`.
- **Verification:**
  ```bash
  cd crates/oc-webui/frontend && trunk build --release
  # Expected: build succeeds.
  # Manual smoke test: start daemon, send mock WC signing request,
  # verify approval appears in browser.
  ```
- **Status:** 🟢 DONE
- **Scenario Coverage:** `@w1-approval-mode-on` `@w1-approve` `@w1-reject` `@w1-ws-pending-approval`
- **Loop Type:** TDD-only
- **Behavioral Contract:** ApprovalsList subscribes to WebSocket `pending_approval` events, renders cards with risk-level color borders. ApprovalDetail renders method, params, dapp origin, risk reasons, basic Sign/Reject buttons (no two-step gating — that's W2). Wire to `/api/approvals` and `/api/approvals/:id/decision`.
- **Simplification Focus:** No two-step Sign gating (W2 adds it). No simulation panel (W3 adds it). Basic Sign/Reject buttons only.
- **BDD Verification:** N/A (frontend build verification only)
- **Advanced Test Verification:** `cd crates/oc-webui/frontend && trunk build --release` — build succeeds.
- **Runtime Verification:** N/A (build-time verification only)

## Task W1.13 — R12 revision in `AGENTS.md`

- **Context:** Update the R12 section of `AGENTS.md` to the revised R12a-R12e
  form (source-level grep + runtime lsof + T12 seccomp; remove the broken
  `nm | grep -i tcp` command). Update the "Lint Commands" section's R12 hard
  gate verification block. Add the new verification commands to `Justfile`
  under a `r12-check` recipe.
- **Verification:**
  ```bash
  rg -n 'nm target/release/onecipher' AGENTS.md Justfile
  # Expected: no matches (the broken command is removed).
  rg -n 'R12a|TcpListener' AGENTS.md
  # Expected: matches the new R12a definition.
  just r12-check
  # Expected: source grep returns no matches; exits 0.
  ```
- **Status:** 🟢 DONE
- **Scenario Coverage:** `@w1-r12-source-isolation` `@w1-r12-loopback-only`
- **Loop Type:** TDD-only
- **Behavioral Contract:** R12 section updated to R12a-R12e form. Broken `nm | grep -i tcp` command removed. New verification commands added to Justfile under `r12-check` recipe.
- **Simplification Focus:** Documentation update only — no code changes.
- **BDD Verification:** `cargo test -p oc-conformance --test conformance -- webui_approval` (R12 scenarios)
- **Advanced Test Verification:** `just r12-check` — exits 0.
- **Runtime Verification:** N/A (documentation task)

## Task W1.14 — Conformance BDD step definitions for W1 scenarios

- **Context:** Add `crates/oc-conformance/tests/conformance/steps/webui_approval.rs`
  with step definitions for all `@w1-*` scenarios in
  `approval_flow.feature` and `api_surface.feature`. Register in
  `crates/oc-conformance/tests/conformance/steps/mod.rs`. Steps should
  drive a real daemon instance (or in-process equivalent) + a mock WC
  relay + an HTTP client acting as the browser.
- **Verification:**
  ```bash
  cargo test -p oc-conformance --test conformance -- webui_approval
  # Expected: all @w1-* scenarios pass.
  ```
- **Status:** 🟢 DONE
- **Scenario Coverage:** all `@w1-*` tags
- **Loop Type:** BDD+TDD
- **Behavioral Contract:** Step definitions drive a real daemon instance (or in-process equivalent) + mock WC relay + HTTP client acting as browser. All `@w1-*` scenarios must pass.
- **Simplification Focus:** Thin cucumber steps — business logic routes through shared crates. Mock WC relay (not real relay).
- **BDD Verification:** `cargo test -p oc-conformance --test conformance -- webui_approval` — all @w1-* scenarios pass.
- **Advanced Test Verification:** All conformance scenarios pass.
- **Runtime Verification:** N/A (test harness)

## Task W1.15 — Phase W1 integration verification

- **Context:** Run the full W1 verification suite end-to-end. Fix any
  regressions. Ensure zero regression on existing tests.
- **Verification:**
  ```bash
  just format && just lint && just test && just bdd webui_approval
  # R56 hard gate
  cargo tree -p oc-crypto | grep -E 'evm2|axum|webauthn'  # no output
  cargo tree -p oc-policy | grep -E 'evm2|axum|webauthn'  # no output
  cargo tree -p oc-keyagent | grep -E 'evm2|axum|webauthn'  # no output
  cargo tree -p oc-session-key | grep -E 'evm2|axum|webauthn'  # no output
  # R12a source-level
  rg -n 'TcpListener|TcpStream' crates/oc-keyagent/src/ crates/oc-crypto/src/ \
                              crates/oc-policy/src/ crates/oc-session-key/src/
  # Expected: no matches.
  ```
- **Status:** 🟢 DONE
- **Scenario Coverage:** N/A
- **Loop Type:** TDD-only
- **Behavioral Contract:** Full workspace verification: format, lint, test, BDD. R56 hard gate (no forbidden deps in isolated crates). R12a source-level isolation (no TcpListener/TcpStream in isolated crates). Zero regression on existing tests.
- **Simplification Focus:** Verification-only task — no new code.
- **BDD Verification:** `just bdd webui_approval`
- **Advanced Test Verification:** `just test && just test-all`
- **Runtime Verification:** R56 + R12a hard gate checks as specified in Verification.

---

# Phase W2 — Risk Grading + Sign Gating

## Task W2.1 — Wire `oc-policy` 11-step into `WcMethodRouter` for signing methods

- **Context:** In `WcMethodRouter::handle`, for each signing method branch,
  call `self.policy.evaluate(&request).await` (or sync, depending on
  existing signature) before constructing `PendingApproval`. Map
  `Decision::Deny` → `RiskLevel::Forbidden` + immediate reject (do NOT
  enter queue); `Decision::Warn(reason)` → `RiskLevel::Warning` + push
  `RiskReason { code, level, message, source: Policy, detail }`; `Allow` →
  `RiskLevel::Safe`. Populate `PendingApproval.risk` and
  `PendingApproval.risk_reasons`.
- **Verification:**
  ```bash
  cargo test -p oc-netagent --lib wc_method_router
  # Expected: new tests assert Deny → immediate reject, Warn → Warning
  # level + reason recorded, Allow → Safe.
  ```
- **Status:** 🟢 DONE
- **Scenario Coverage:** `@w2-policy-deny-forbidden` `@w2-policy-warn`
- **Loop Type:** TDD-only
- **Behavioral Contract:** `Deny` → `RiskLevel::Forbidden` + immediate reject (no queue). `Warn(reason)` → `RiskLevel::Warning` + push `RiskReason`. `Allow` → `RiskLevel::Safe`. Populate `PendingApproval.risk` and `PendingApproval.risk_reasons`.
- **Simplification Focus:** Reuses existing `oc-policy` evaluation; just maps Decision to RiskLevel. No new policy engine.
- **BDD Verification:** `cargo test -p oc-conformance --test conformance -- risk_gate`
- **Advanced Test Verification:** `cargo test -p oc-netagent --lib wc_method_router` — Deny→reject, Warn→Warning, Allow→Safe.
- **Runtime Verification:** N/A (library crate)

## Task W2.2 — Front-end RiskCard + Sign-button state machine

- **Context:** Implement `routes/approvals/risk_card.rs` (dismissible card
  for each `RiskReason` with level Warning; "Acknowledge" button removes
  from `unprocessed_warnings` signal). Implement
  `routes/approvals/submit_actions.rs` with the Disabled → Armed →
  Submitting state machine per Section 7 of design doc. `Disabled` while:
  simulation pending (W3) OR unprocessed warnings OR Danger 5s countdown.
  `Forbidden` hides Sign, shows only Reject. Two-step: first click → Armed
  (reveal Confirm Sign + Cancel); Cancel → back to Disabled; Confirm Sign →
  Submitting + POST decision. Danger 5s countdown via `set_timeout`.
- **Verification:**
  ```bash
  cd crates/oc-webui/frontend && trunk build --release
  cargo test -p oc-webui --lib submit_actions_state_machine
  # Expected: build succeeds; unit test of state transitions passes.
  ```
- **Status:** 🟢 DONE
- **Scenario Coverage:** `@w2-policy-warn-ack` `@w2-danger-countdown` `@w2-forbidden-hides-sign` `@w2-two-step-cancel` `@w2-two-step-confirm` `@w2-color-mapping`
- **Loop Type:** TDD-only
- **Behavioral Contract:** RiskCard: dismissible card per RiskReason with "Acknowledge" button. Sign-button state machine: Disabled → Armed → Submitting. Disabled while: simulation pending OR unprocessed warnings OR Danger 5s countdown. Forbidden hides Sign, shows only Reject. Two-step: first click → Armed (Confirm Sign + Cancel); Cancel → Disabled; Confirm Sign → Submitting.
- **Simplification Focus:** `set_timeout` for Danger countdown (no custom timer). State machine is a simple enum + match.
- **BDD Verification:** `cargo test -p oc-conformance --test conformance -- risk_gate`
- **Advanced Test Verification:** `cd crates/oc-webui/frontend && trunk build --release` + `cargo test -p oc-webui --lib submit_actions_state_machine`.
- **Runtime Verification:** N/A (frontend build + library test)

## Task W2.3 — `/api/approvals/:id/simulate` placeholder endpoint

- **Context:** Add `POST /api/approvals/:id/simulate` route returning
  `TxSimulation` (or `None` for W2). This reserves the endpoint for W3.
  Document in the API contract that W2 always returns `None`.
- **Verification:**
  ```bash
  cargo test -p oc-webui --lib routes::approval::simulate
  # Expected: test asserts 200 with null simulation field.
  ```
- **Status:** 🟢 DONE
- **Scenario Coverage:** N/A
- **Loop Type:** TDD-only
- **Behavioral Contract:** `POST /api/approvals/:id/simulate` returns `TxSimulation` (or `None` for W2). Reserves the endpoint for W3.
- **Simplification Focus:** Placeholder only — returns null simulation. No actual evm2 integration.
- **BDD Verification:** N/A (placeholder)
- **Advanced Test Verification:** `cargo test -p oc-webui --lib routes::approval::simulate` — 200 with null.
- **Runtime Verification:** N/A (library crate)

## Task W2.4 — Conformance BDD step definitions for W2 scenarios

- **Context:** Extend `webui_approval.rs` step definitions (or add
  `risk_gate.rs`) to cover all `@w2-*` scenarios in `risk_gate.feature`
  except the W3-tagged simulation-result ones.
- **Verification:**
  ```bash
  cargo test -p oc-conformance --test conformance -- risk_gate
  # Expected: all @w2-* scenarios pass (W3 scenarios may be pending).
  ```
- **Status:** 🟢 DONE
- **Scenario Coverage:** all `@w2-*` tags
- **Loop Type:** BDD+TDD
- **Behavioral Contract:** Step definitions cover all `@w2-*` scenarios in `risk_gate.feature` except W3-tagged simulation-result ones.
- **Simplification Focus:** Thin steps; W3 scenarios deferred.
- **BDD Verification:** `cargo test -p oc-conformance --test conformance -- risk_gate` — all @w2-* pass.
- **Advanced Test Verification:** All conformance scenarios pass.
- **Runtime Verification:** N/A (test harness)

---

# Phase W3 — evm2 Transaction Simulation

## Task W3.1 — Create `oc-sim` crate with evm2 git pin

- **Context:** Add `crates/oc-sim/` to the workspace. `Cargo.toml`
  dependencies: `evm2 = { git = "https://github.com/alloy-rs/evm2", rev =
  "<pin>", default-features = false, features = ["std", "parse",
  "asm-keccak"] }`, `alloy-primitives`, `alloy-eips`, `tokio` (feature
  `rt-multi-thread` for `spawn_blocking`), `serde`, `serde_json`,
  `thiserror`, `tracing`, `oc-core` (for `ChainType`). Expose `pub async fn
  simulate_evm_tx(raw_tx_hex: &str, chain_id: &str) -> Result<TxSimulation,
  SimError>` wrapping the sync `evm2::Evm::transact` in
  `tokio::task::spawn_blocking`. State diff → `Vec<TokenDelta>`. Revert →
  `success=false` + `error` message.
- **Verification:**
  ```bash
  cargo build -p oc-sim
  cargo tree -p oc-crypto | grep evm2  # no output
  cargo tree -p oc-policy | grep evm2  # no output
  cargo tree -p oc-keyagent | grep evm2  # no output
  cargo tree -p oc-session-key | grep evm2  # no output
  # Expected: oc-sim builds; isolated crates do NOT pull evm2.
  cargo test -p oc-sim --lib
  # Expected: simulation tests pass for a simple ETH transfer and a
  # reverting call.
  ```
- **Status:** 🟢 DONE
- **Scenario Coverage:** `@w3-sim-balance-change` `@w3-sim-failure-degrade` `@w3-sim-gas-used`
- **Loop Type:** TDD-only
- **Behavioral Contract:** `simulate_evm_tx(raw_tx_hex, chain_id)` wraps sync `evm2::Evm::transact` in `tokio::task::spawn_blocking`. State diff → `Vec<TokenDelta>`. Revert → `success=false` + error message.
- **Simplification Focus:** Git pin for evm2 (not on crates.io). `default-features=false` with only `["std","parse","asm-keccak"]`. Abstracted behind `oc-sim` so swapping to revm only touches one crate.
- **BDD Verification:** `cargo test -p oc-conformance --test conformance -- risk_gate` (W3 scenarios)
- **Advanced Test Verification:** `cargo build -p oc-sim` + `cargo test -p oc-sim --lib` — simulation tests for simple ETH transfer and reverting call.
- **Runtime Verification:** R56 check: `cargo tree -p oc-crypto | grep evm2` — no output.

## Task W3.2 — ABI decoding with local cache

- **Context:** In `oc-sim`, add `abi_decode.rs` and `abi_cache.rs`. Curated
  ABIs ship in `crates/oc-sim/res/abis/` (ERC-20, ERC-721, ERC-1155,
  Permit2, UniswapV2Router02, UniswapV3Router, Aave V3 Pool, Comptroller).
  At runtime, look up by contract address in
  `~/.onecipher/abi_cache/<address>.json`. Optional `abi-fetch` feature
  (off by default) uses `hpx` to GET Etherscan `/api?module=contract&action=getabi`.
  Decode calldata → `DecodedAction { contract_name, function_name, args,
  human_readable }`. Unknown calldata → `None`.
- **Verification:**
  ```bash
  cargo test -p oc-sim --lib abi_decode
  # Expected: tests for known ABIs decode correctly; unknown calldata
  # returns None.
  ```
- **Status:** 🟢 DONE
- **Scenario Coverage:** `@w3-sim-decoded-action`
- **Loop Type:** TDD-only
- **Behavioral Contract:** Curated ABIs in `crates/oc-sim/res/abis/`. Runtime cache in `~/.onecipher/abi_cache/<address>.json`. Decode calldata → `DecodedAction { contract_name, function_name, args, human_readable }`. Unknown → `None`.
- **Simplification Focus:** Curated defaults (ERC-20, ERC-721, etc.). Optional `abi-fetch` feature for Etherscan (off by default).
- **BDD Verification:** N/A (covered by W3.5)
- **Advanced Test Verification:** `cargo test -p oc-sim --lib abi_decode` — known ABIs decode, unknown returns None.
- **Runtime Verification:** N/A (library crate)

## Task W3.3 — Wire `oc-sim` into `WcMethodRouter`

- **Context:** In `WcMethodRouter::handle`, for `SignTransaction` on EVM
  chains, call `self.sim.simulate_evm_tx(raw_tx, chain_id).await` before
  constructing `PendingApproval`. On success, populate
  `PendingApproval.simulation = Some(TxSimulation { ... })`. On revert,
  push `RiskReason { code: "sim_revert", level: Danger, ... }` and set
  `risk = max(risk, Danger)`. On error (sim fails), set `simulation = None`
  and `tracing::warn!` — do NOT block signing.
- **Verification:**
  ```bash
  cargo test -p oc-netagent --lib wc_method_router::sim_integration
  # Expected: tests for success path, revert path, and failure-degrade path.
  ```
- **Status:** 🟢 DONE
- **Scenario Coverage:** `@w2-sim-revert-danger` `@w3-sim-failure-degrade` `@w3-sim-balance-change` `@w3-sim-gas-used`
- **Loop Type:** TDD-only
- **Behavioral Contract:** For EVM `SignTransaction`, call `simulate_evm_tx` before constructing `PendingApproval`. Success → populate `simulation`. Revert → push `RiskReason { code: "sim_revert", level: Danger }` + set `risk = max(risk, Danger)`. Error → `simulation = None` + `tracing::warn!` (do NOT block signing).
- **Simplification Focus:** Failure-degrade path: simulation errors never block signing. `tracing::warn!` only.
- **BDD Verification:** `cargo test -p oc-conformance --test conformance -- risk_gate`
- **Advanced Test Verification:** `cargo test -p oc-netagent --lib wc_method_router::sim_integration` — success, revert, failure-degrade paths.
- **Runtime Verification:** N/A (library crate)

## Task W3.4 — Front-end SimPanel

- **Context:** Implement `routes/approvals/sim_panel.rs` rendering
  `DecodedAction.human_readable` prominently, `balance_change` as
  Send/Receive rows, `gas_used` as "N gas". On `simulation = None`, show
  raw params hex + "Decoding failed (offline)" notice. Do NOT block Sign
  button when simulation is None.
- **Verification:**
  ```bash
  cd crates/oc-webui/frontend && trunk build --release
  # Expected: build succeeds.
  ```
- **Status:** 🟢 DONE
- **Scenario Coverage:** `@w3-sim-balance-change` `@w3-sim-decoded-action` `@w3-sim-failure-degrade` `@w3-sim-gas-used`
- **Loop Type:** TDD-only
- **Behavioral Contract:** SimPanel renders `DecodedAction.human_readable` prominently, `balance_change` as Send/Receive rows, `gas_used` as "N gas". On `simulation = None`, show raw params hex + "Decoding failed (offline)" notice. Do NOT block Sign button when simulation is None.
- **Simplification Focus:** No blocking on missing simulation. Raw hex fallback (no fancy formatting).
- **BDD Verification:** N/A (frontend build verification only)
- **Advanced Test Verification:** `cd crates/oc-webui/frontend && trunk build --release` — build succeeds.
- **Runtime Verification:** N/A (build-time verification only)

## Task W3.5 — Conformance BDD step definitions for W3 scenarios

- **Context:** Extend step definitions for `@w3-*` scenarios in
  `risk_gate.feature`.
- **Verification:**
  ```bash
  cargo test -p oc-conformance --test conformance -- risk_gate
  # Expected: all @w2-* and @w3-* scenarios pass.
  ```
- **Status:** 🟢 DONE
- **Scenario Coverage:** all `@w3-*` tags
- **Loop Type:** BDD+TDD
- **Behavioral Contract:** Step definitions cover all `@w3-*` scenarios in `risk_gate.feature`.
- **Simplification Focus:** Extends existing W2 step definitions; no new step file needed if same structure.
- **BDD Verification:** `cargo test -p oc-conformance --test conformance -- risk_gate` — all @w2-* and @w3-* pass.
- **Advanced Test Verification:** All conformance scenarios pass.
- **Runtime Verification:** N/A (test harness)

---

# Phase W4 — Full Web Wallet

## Task W4.1 — Wallets routes (list/create/import/detail/balances/send/delete)

- **Context:** Implement `routes/wallets.rs` in `oc-webui`. Forward to
  Key-Agent via UDS for create/import/sign. Balances via
  `oc-wallet`'s RPC client (existing `rpc` feature). Send constructs
  `SignTransactionRequest` and forwards to Key-Agent.
- **Verification:**
  ```bash
  cargo test -p oc-webui --lib routes::wallets
  # Expected: tests for each endpoint.
  ```
- **Status:** 🟢 DONE
- **Scenario Coverage:** `@w4-wallets-list` `@w4-wallets-create` `@w4-wallets-send`
- **Loop Type:** TDD-only
- **Behavioral Contract:** Forward to Key-Agent via UDS for create/import/sign. Balances via `oc-wallet`'s existing RPC client. Send constructs `SignTransactionRequest` and forwards to Key-Agent.
- **Simplification Focus:** Reuses existing `oc-wallet` RPC client. No new signing logic — forwards to Key-Agent.
- **BDD Verification:** `cargo test -p oc-conformance --test conformance -- api_surface`
- **Advanced Test Verification:** `cargo test -p oc-webui --lib routes::wallets` — tests for each endpoint.
- **Runtime Verification:** N/A (library crate)

## Task W4.2 — WC sessions routes (list/disconnect/pair/generate)

- **Context:** Implement `routes/sessions.rs`. Forward to `WcServerHandle`
  for pair/generate. List from `WcServerHandle::sessions()`. Disconnect
  via `WcServerHandle::disconnect(topic)`.
- **Verification:**
  ```bash
  cargo test -p oc-webui --lib routes::sessions
  ```
- **Status:** 🟢 DONE
- **Scenario Coverage:** `@w4-wc-sessions-list` `@w4-wc-pair` `@w4-wc-pair-generate`
- **Loop Type:** TDD-only
- **Behavioral Contract:** Forward to `WcServerHandle` for pair/generate. List from `WcServerHandle::sessions()`. Disconnect via `WcServerHandle::disconnect(topic)`.
- **Simplification Focus:** Thin proxy to existing `WcServerHandle` — no new session management logic.
- **BDD Verification:** `cargo test -p oc-conformance --test conformance -- api_surface`
- **Advanced Test Verification:** `cargo test -p oc-webui --lib routes::sessions`
- **Runtime Verification:** N/A (library crate)

## Task W4.3 — Audit, policy, session-keys, secrets routes

- **Context:** Implement `routes/audit.rs` (read `~/.onecipher/logs/audit.jsonl`
  with pagination), `routes/settings/policy.rs` (CRUD on policy rules),
  `routes/settings/session_keys.rs` (CRUD via `oc-session-key`),
  `routes/settings/secrets.rs` (CRUD via `oc-secret`; GET requires
  step-up WebAuthn assertion in `X-WebAuthn-Assertion` header).
- **Verification:**
  ```bash
  cargo test -p oc-webui --lib routes::audit routes::settings
  ```
- **Status:** 🟢 DONE
- **Scenario Coverage:** `@w4-audit-list` `@w4-policy-rules-list` `@w4-policy-rules-patch` `@w4-session-keys-list` `@w4-session-keys-create` `@w4-secrets-list` `@w4-secrets-get-second-webauthn`
- **Loop Type:** TDD-only
- **Behavioral Contract:** Audit: read `~/.onecipher/logs/audit.jsonl` with pagination. Policy: CRUD on policy rules. Session-keys: CRUD via `oc-session-key`. Secrets: CRUD via `oc-secret`; GET requires step-up WebAuthn assertion in `X-WebAuthn-Assertion` header.
- **Simplification Focus:** Audit is file-read with pagination (no DB). Secrets GET uses step-up assertion (no persistent elevated session).
- **BDD Verification:** `cargo test -p oc-conformance --test conformance -- api_surface`
- **Advanced Test Verification:** `cargo test -p oc-webui --lib routes::audit routes::settings`
- **Runtime Verification:** N/A (library crate)

## Task W4.4 — Front-end IndexedDB cache + freshness ledger + event invalidation

- **Context:** Implement `cache/schema.rs` (Dexie via `rexie`, 7 stores),
  `cache/freshness.rs` (`read_or_fetch` with stale-while-revalidate),
  `cache/live_query.rs` (`use_live_query` Leptos hook wrapping Dexie
  `liveQuery`), `cache/invalidate.rs` (WebSocket event → scene invalidation
  per Section 4.5 of design doc).
- **Verification:**
  ```bash
  cd crates/oc-webui/frontend && trunk build --release
  cargo test -p oc-webui --lib cache
  # Expected: unit tests for freshness logic and invalidation mapping.
  ```
- **Status:** 🟢 DONE
- **Scenario Coverage:** `@w4-cache-fresh` `@w4-cache-stale` `@w4-cache-empty` `@w4-invalidate-on-sign` `@w4-invalidate-on-wc-session` `@w4-invalidate-on-policy`
- **Loop Type:** TDD-only
- **Behavioral Contract:** Dexie via `rexie`, 7 stores. `read_or_fetch` with stale-while-revalidate. `use_live_query` Leptos hook wrapping Dexie `liveQuery`. WebSocket event → scene invalidation per Section 4.5.
- **Simplification Focus:** Stale-while-revalidate (not real-time sync). Invalidation is event-driven (not polling).
- **BDD Verification:** `cargo test -p oc-conformance --test conformance -- frontend_cache`
- **Advanced Test Verification:** `cd crates/oc-webui/frontend && trunk build --release` + `cargo test -p oc-webui --lib cache`.
- **Runtime Verification:** N/A (frontend build + library test)

## Task W4.5 — Front-end persistent mounting for Sessions/History/Settings

- **Context:** Wrap Sessions, History, Settings routes in a `keep_alive`
  component that toggles `class:hidden` instead of unmounting. Verify
  WebSocket subscriptions are not torn down on route switch.
- **Verification:**
  ```bash
  cd crates/oc-webui/frontend && trunk build --release
  # Expected: build succeeds.
  ```
- **Status:** 🟢 DONE
- **Scenario Coverage:** `@w4-persistent-mount-sessions`
- **Loop Type:** TDD-only
- **Behavioral Contract:** Sessions, History, Settings routes wrapped in `keep_alive` component that toggles `class:hidden` instead of unmounting. WebSocket subscriptions not torn down on route switch.
- **Simplification Focus:** CSS class toggle (no virtual DOM keep-alive abstraction). Existing Leptos `class:` directive.
- **BDD Verification:** `cargo test -p oc-conformance --test conformance -- frontend_cache`
- **Advanced Test Verification:** `cd crates/oc-webui/frontend && trunk build --release` — build succeeds.
- **Runtime Verification:** N/A (build-time verification only)

## Task W4.6 — Front-end Dashboard + Send + Wallets views

- **Context:** Implement `routes/dashboard/` (Header + Panel + GasBar +
  CurrentConnection, composing not implementing), `routes/send/` (StrayPage
  form), `routes/wallets/{create,import,info}.rs`. Use cache layer for
  balances.
- **Verification:**
  ```bash
  cd crates/oc-webui/frontend && trunk build --release
  ```
- **Status:** 🟢 DONE
- **Scenario Coverage:** N/A
- **Loop Type:** TDD-only
- **Behavioral Contract:** Dashboard: Header + Panel + GasBar + CurrentConnection (composing not implementing). Send: StrayPage form. Wallets: create/import/info views. Use cache layer for balances.
- **Simplification Focus:** Composing existing components. No new signing or cache logic.
- **BDD Verification:** N/A (frontend build verification only)
- **Advanced Test Verification:** `cd crates/oc-webui/frontend && trunk build --release` — build succeeds.
- **Runtime Verification:** N/A (build-time verification only)

## Task W4.7 — Theming + i18n

- **Context:** Implement `theme/tokens.rs` (read from `oc-core::theme`,
  inject `<style id="oc-tokens">`), `theme/dark.rs` (toggle `html.dark`),
  `i18n/mod.rs` (`fluent-leptos` init), `i18n/locales/{en,zh-CN}.ftl`
  (lazy-loaded on first switch).
- **Verification:**
  ```bash
  cd crates/oc-webui/frontend && trunk build --release
  cargo test -p oc-webui --lib theme i18n
  ```
- **Status:** 🟢 DONE
- **Scenario Coverage:** `@w4-theme-dark` `@w4-theme-single-source` `@w4-i18n-lazy-load` `@w4-i18n-plural`
- **Loop Type:** TDD-only
- **Behavioral Contract:** Theme tokens read from `oc-core::theme`, inject `<style id="oc-tokens">`. Dark toggle: `html.dark`. i18n: `fluent-leptos` init, lazy-loaded locales on first switch.
- **Simplification Focus:** CSS variable injection (no CSS-in-JS). Lazy locale loading (no upfront bundle).
- **BDD Verification:** `cargo test -p oc-conformance --test conformance -- frontend_cache`
- **Advanced Test Verification:** `cd crates/oc-webui/frontend && trunk build --release` + `cargo test -p oc-webui --lib theme i18n`.
- **Runtime Verification:** N/A (frontend build + library test)

## Task W4.8 — Conformance BDD step definitions for W4 scenarios

- **Context:** Add `frontend_cache.rs` and `api_surface.rs` step definition
  files covering all `@w4-*` scenarios.
- **Verification:**
  ```bash
  cargo test -p oc-conformance --test conformance -- frontend_cache api_surface
  # Expected: all @w4-* scenarios pass.
  ```
- **Status:** 🟢 DONE
- **Scenario Coverage:** all `@w4-*` tags
- **Loop Type:** BDD+TDD
- **Behavioral Contract:** Step definitions cover all `@w4-*` scenarios in `frontend_cache.feature` and `api_surface.feature`.
- **Simplification Focus:** Thin steps; routes through shared crates.
- **BDD Verification:** `cargo test -p oc-conformance --test conformance -- frontend_cache api_surface` — all @w4-* pass.
- **Advanced Test Verification:** All conformance scenarios pass.
- **Runtime Verification:** N/A (test harness)

## Task W4.9 — Phase W4 integration verification

- **Context:** Full workspace verification.
- **Verification:**
  ```bash
  just format && just lint && just test && just bdd webui_approval risk_gate frontend_cache api_surface
  # R56
  cargo tree -p oc-crypto | grep -E 'evm2|axum|webauthn'  # no output
  cargo tree -p oc-policy | grep -E 'evm2|axum|webauthn'  # no output
  cargo tree -p oc-keyagent | grep -E 'evm2|axum|webauthn'  # no output
  cargo tree -p oc-session-key | grep -E 'evm2|axum|webauthn'  # no output
  # R12a
  rg -n 'TcpListener|TcpStream' crates/oc-keyagent/src/ crates/oc-crypto/src/ \
                              crates/oc-policy/src/ crates/oc-session-key/src/
  # Expected: no matches.
  ```
- **Status:** 🟢 DONE
- **Scenario Coverage:** N/A
- **Loop Type:** TDD-only
- **Behavioral Contract:** Full workspace verification: format, lint, test, BDD for all phases. R56 hard gate. R12a source-level isolation. Zero regression.
- **Simplification Focus:** Verification-only task — no new code.
- **BDD Verification:** `just bdd webui_approval risk_gate frontend_cache api_surface`
- **Advanced Test Verification:** `just test && just test-all`
- **Runtime Verification:** R56 + R12a hard gate checks as specified in Verification.

---

# DAG Summary

```
W1.0 (config) ──┐
                ├─► W1.1 (ApprovalChannel types) ─┐
                │                                  ├─► W1.3 (WcMethodRouter inject) ──► W1.4 (ApprovalLog) ──┐
                │                                  │                                                              │
W1.2 (Decision::Warn) ─────────────────────────────┤                                                              │
                                                   │                                                              │
W1.5 (oc-webui skeleton) ──► W1.6 (WebAuthn) ──► W1.7 (ApprovalQueue+REST+WS) ──► W1.8 (settings+health) ───┤
                                                   │                                                              │
                                                   ├─► W1.9 (daemon wiring) ──► W1.10 (CLI webui open)            │
                                                   │                                                              │
W1.11 (frontend skeleton + SortHat + Unlock) ──► W1.12 (frontend approvals) ─────────────────────────────────┤
                                                   │                                                              │
W1.13 (R12 revision) ──────────────────────────────┤                                                              │
                                                   └─► W1.14 (BDD steps W1) ──► W1.15 (W1 integration) ──────────┘

W1.15 ──► W2.1 (policy 11-step wiring) ──► W2.2 (RiskCard + Sign state machine) ──► W2.3 (simulate placeholder) ──► W2.4 (BDD steps W2)

W2.4 ──► W3.1 (oc-sim crate) ──► W3.2 (ABI decoding) ──► W3.3 (wire sim into WcMethodRouter) ──► W3.4 (SimPanel) ──► W3.5 (BDD steps W3)

W3.5 ──► W4.1 (wallets routes) ─┐
          W4.2 (WC routes) ─────┤
          W4.3 (audit/policy/sk/secrets) ──┤
          W4.4 (IndexedDB cache) ─────────┤
          W4.5 (persistent mount) ────────┤
          W4.6 (dashboard/send/wallets UI)┤
          W4.7 (theming + i18n) ──────────┴─► W4.8 (BDD steps W4) ──► W4.9 (W4 integration)
```

No forward references. Each phase is independently shippable.
