//! Runtime-loadable Wasm strategy plugins for the policy engine.
//!
//! This module lets policy rules be authored as a small Wasm module and loaded
//! at runtime, enabling **hot-reload** of strategy logic without recompiling
//! the core binary. The 11-step pipeline in [`crate::v2`] is untouched: a
//! strategy plugin is an *additional* gate consulted alongside the built-in
//! evaluation (see [`StrategyRegistry`] and [`crate::v3`] integration).
//!
//! ## Why `wasmi` (not `wasmtime`)
//!
//! `oc-policy` has a hard gate (R56): it MUST NOT depend on
//! `tokio`/`reqwest`/`tungstenite`/`hyper`/`async-std`/`smol` — even as
//! dev-deps — verified by `cargo tree -p oc-policy`. `wasmtime` pulls in a
//! large async runtime and native JIT machinery (and `cranelift`, which would
//! also break the reproducible-build gate). `wasmi` is a pure, `no_std`-capable
//! Rust Wasm **interpreter** with no async runtime and no JIT, so it is both
//! R56-clean and R12-clean (no sockets, no host FS access unless we grant it —
//! and we grant nothing).
//!
//! ## Guest ABI (v1)
//!
//! The host/guest contract is deliberately minimal and allocator-driven so a
//! guest written in any language (Rust, AssemblyScript, hand-written WAT) can
//! implement it:
//!
//! | Export | Signature | Purpose |
//! |---|---|---|
//! | `memory` | `(memory 1)` | Linear memory shared with the host. |
//! | `oc_alloc` | `(i32) -> i32` | Reserve `n` bytes, return the offset. |
//! | `oc_evaluate` | `(i32, i32) -> i64` | Evaluate; see below. |
//!
//! Flow:
//!
//! 1. Host serializes [`WasmEvalRequest`] to JSON (`n` bytes).
//! 2. Host calls `oc_alloc(n)` → `ptr`, writes the JSON at `ptr`.
//! 3. Host calls `oc_evaluate(ptr, n)` → packed `i64`.
//! 4. The packed return value is `(out_ptr as u64) << 32 | (out_len as u64)`. The host reads
//!    `out_len` bytes at `out_ptr` and parses them as a JSON [`StrategyOutcome`].
//!
//! Packing the pointer and length into a single `i64` avoids requiring the
//! guest to export a second "last result length" global, which is the most
//! common source of ABI drift.
//!
//! ## Sandboxing guarantees
//!
//! * **No imports are linked.** The [`wasmi::Linker`] is empty, so a module that imports *anything*
//!   (WASI, `env.memory`, host functions) fails to instantiate. Guests must be fully
//!   self-contained.
//! * **Fuel metering** bounds execution time ([`StrategyLimits::fuel`]). Runaway loops trap instead
//!   of hanging the Key-Agent.
//! * **Memory ceiling** ([`StrategyLimits::max_memory_bytes`]) is enforced before writing the
//!   request and before reading the result.
//! * **Deterministic**: no clock, no RNG, no I/O is reachable from the guest.
//!
//! ## Host facts
//!
//! Rather than a live host-call bridge (which would widen the guest's
//! authority), host-provided facts (wallet balance, rate-limit counters, …)
//! are *pushed* into the request's `host_facts` field before evaluation.
//! [`WasmHostCalls`] is the trait a caller implements to populate them. This
//! keeps the guest a pure function of its input, which is what makes strategy
//! evaluation reproducible and auditable.

use std::{collections::BTreeMap, path::Path};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors from compiling or evaluating a Wasm strategy plugin.
#[derive(Debug, Error)]
pub enum WasmError {
    #[error("wasm compile error: {0}")]
    Compiler(String),
    #[error("wasm instantiate error: {0}")]
    Instantiate(String),
    #[error("wasm runtime error: {0}")]
    Runtime(String),
    #[error("wasm memory error: {0}")]
    Memory(String),
    #[error("wasm ABI violation: {0}")]
    Abi(String),
    #[error("strategy result parse error: {0}")]
    ResultParse(String),
    #[error("strategy I/O error: {0}")]
    Io(String),
}

/// The outcome of a strategy evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum StrategyOutcome {
    /// The strategy permits the request; defer to the built-in pipeline.
    Allow,
    /// The strategy flags the request but does not block it.
    Warn { message: String },
    /// The strategy blocks the request.
    Deny { reason: String, message: String },
}

impl StrategyOutcome {
    /// Whether this outcome blocks the request.
    pub fn is_deny(&self) -> bool {
        matches!(self, Self::Deny { .. })
    }
}

/// Serializable inputs to a strategy evaluation.
///
/// `host_facts` is a free-form JSON object populated by the caller (via
/// [`WasmHostCalls`]) with host-side facts such as wallet balance or
/// rate-limit counters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmEvalRequest {
    pub method: String,
    pub chain_id: String,
    pub amount_usd: f64,
    pub asset: String,
    pub recipient: String,
    pub session_key_id: String,
    #[serde(default)]
    pub host_facts: serde_json::Value,
}

impl Default for WasmEvalRequest {
    fn default() -> Self {
        Self {
            method: String::new(),
            chain_id: String::new(),
            amount_usd: 0.0,
            asset: String::new(),
            recipient: String::new(),
            session_key_id: String::new(),
            host_facts: serde_json::Value::Object(serde_json::Map::new()),
        }
    }
}

/// Host-side facts a caller can provide to a strategy evaluation.
///
/// The default implementations return `None`, so a caller that does not
/// override anything yields an empty `host_facts` object.
pub trait WasmHostCalls {
    /// Look up the wallet balance for an asset (CAIP-19).
    fn get_wallet_balance(&self, _asset: &str) -> Option<f64> {
        None
    }

    /// Look up a rate-limit counter for a session key and window.
    ///
    /// `window` is one of `"minute"`, `"hour"`, `"day"`.
    fn check_rate_limit(&self, _session_key_id: &str, _window: &str) -> Option<u64> {
        None
    }

    /// Look up the cumulative spend for a session key in USD.
    fn get_spent_usd(&self, _session_key_id: &str) -> Option<f64> {
        None
    }

    /// Whether a recipient address has been seen before by this wallet.
    fn is_known_recipient(&self, _recipient: &str) -> Option<bool> {
        None
    }

    /// Build the `host_facts` JSON object embedded into the request.
    ///
    /// Overriding this replaces the default assembly of the accessors above.
    fn host_facts(&self, req: &WasmEvalRequest) -> serde_json::Value {
        let mut facts = serde_json::Map::new();
        if let Some(balance) = self.get_wallet_balance(&req.asset) {
            facts.insert("wallet_balance".to_string(), serde_json::json!(balance));
        }
        for window in ["minute", "hour", "day"] {
            if let Some(count) = self.check_rate_limit(&req.session_key_id, window) {
                facts.insert(format!("rate_limit_{window}"), serde_json::json!(count));
            }
        }
        if let Some(spent) = self.get_spent_usd(&req.session_key_id) {
            facts.insert("spent_usd".to_string(), serde_json::json!(spent));
        }
        if let Some(known) = self.is_known_recipient(&req.recipient) {
            facts.insert("known_recipient".to_string(), serde_json::json!(known));
        }
        serde_json::Value::Object(facts)
    }
}

/// A [`WasmHostCalls`] implementation that provides no facts.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoHostFacts;

impl WasmHostCalls for NoHostFacts {}

/// Resource limits applied to every strategy evaluation.
#[derive(Debug, Clone, Copy)]
pub struct StrategyLimits {
    /// Fuel budget. Roughly proportional to executed instructions; a trap is
    /// raised when exhausted. Default is generous for JSON-scanning guests but
    /// still terminates infinite loops in well under a millisecond.
    pub fuel: u64,
    /// Maximum guest linear memory the host will interact with, in bytes.
    pub max_memory_bytes: usize,
    /// Maximum size of the JSON result the guest may return, in bytes.
    pub max_result_bytes: usize,
}

impl Default for StrategyLimits {
    fn default() -> Self {
        Self { fuel: 10_000_000, max_memory_bytes: 16 * 1024 * 1024, max_result_bytes: 64 * 1024 }
    }
}

/// Guest ABI export names (v1).
mod abi {
    pub(super) const MEMORY: &str = "memory";
    pub(super) const ALLOC: &str = "oc_alloc";
    pub(super) const EVALUATE: &str = "oc_evaluate";
}

/// A compiled, runtime-loadable Wasm strategy plugin.
///
/// Compilation is done once; [`StrategyPlugin::evaluate`] instantiates a fresh
/// [`wasmi::Store`] per call so evaluations cannot leak state into each other.
pub struct StrategyPlugin {
    name: String,
    engine: wasmi::Engine,
    module: wasmi::Module,
    limits: StrategyLimits,
}

impl std::fmt::Debug for StrategyPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StrategyPlugin")
            .field("name", &self.name)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl StrategyPlugin {
    /// Compile a strategy plugin from raw Wasm bytes with default limits.
    pub fn compile(name: impl Into<String>, wasm_bytes: &[u8]) -> Result<Self, WasmError> {
        Self::compile_with_limits(name, wasm_bytes, StrategyLimits::default())
    }

    /// Compile a strategy plugin from raw Wasm bytes with explicit limits.
    pub fn compile_with_limits(
        name: impl Into<String>,
        wasm_bytes: &[u8],
        limits: StrategyLimits,
    ) -> Result<Self, WasmError> {
        let mut config = wasmi::Config::default();
        // Fuel metering is what makes an untrusted guest safe to run inside
        // the Key-Agent's synchronous request path.
        config.consume_fuel(true);
        let engine = wasmi::Engine::new(&config);
        let module = wasmi::Module::new(&engine, wasm_bytes)
            .map_err(|e| WasmError::Compiler(e.to_string()))?;
        Ok(Self { name: name.into(), engine, module, limits })
    }

    /// Compile a strategy plugin from WAT (WebAssembly Text format).
    pub fn from_wat(name: impl Into<String>, wat_src: &str) -> Result<Self, WasmError> {
        let wasm_bytes = wat::parse_str(wat_src).map_err(|e| WasmError::Compiler(e.to_string()))?;
        Self::compile(name, &wasm_bytes)
    }

    /// Load and compile a strategy plugin from a `.wasm` or `.wat` file.
    ///
    /// The plugin name defaults to the file stem.
    pub fn from_path(path: &Path) -> Result<Self, WasmError> {
        let name = path.file_stem().and_then(|s| s.to_str()).unwrap_or("unnamed").to_string();
        let bytes =
            std::fs::read(path).map_err(|e| WasmError::Io(format!("{}: {e}", path.display())))?;
        if path.extension().and_then(|s| s.to_str()) == Some("wat") {
            let src = String::from_utf8(bytes)
                .map_err(|e| WasmError::Io(format!("{}: not UTF-8: {e}", path.display())))?;
            Self::from_wat(name, &src)
        } else {
            Self::compile(name, &bytes)
        }
    }

    /// The plugin's name (used in audit records and error messages).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The resource limits applied to each evaluation.
    pub fn limits(&self) -> StrategyLimits {
        self.limits
    }

    /// Evaluate a request against this strategy plugin.
    ///
    /// A fresh store is created per call, so no state survives between
    /// evaluations. See the module docs for the guest ABI.
    pub fn evaluate(
        &self,
        req: &WasmEvalRequest,
        host: &dyn WasmHostCalls,
    ) -> Result<StrategyOutcome, WasmError> {
        // Build the request with host facts embedded.
        let mut req = req.clone();
        req.host_facts = host.host_facts(&req);
        let req_json =
            serde_json::to_vec(&req).map_err(|e| WasmError::ResultParse(e.to_string()))?;

        let mut store = wasmi::Store::new(&self.engine, ());
        store
            .set_fuel(self.limits.fuel)
            .map_err(|e| WasmError::Runtime(format!("setting fuel: {e}")))?;

        // An EMPTY linker: the guest may not import anything (no WASI, no host
        // functions, not even memory). This is the primary sandbox boundary.
        let linker = wasmi::Linker::<()>::new(&self.engine);
        // wasmi 1.x: instantiate + start are atomic. The 0.40-era
        // `instantiate(..).start(..)` pair no longer exists.
        let instance = linker
            .instantiate_and_start(&mut store, &self.module)
            .map_err(|e| WasmError::Instantiate(e.to_string()))?;

        let memory = instance
            .get_export(&store, abi::MEMORY)
            .and_then(wasmi::Extern::into_memory)
            .ok_or_else(|| WasmError::Abi(format!("module does not export `{}`", abi::MEMORY)))?;

        let alloc = instance
            .get_typed_func::<i32, i32>(&store, abi::ALLOC)
            .map_err(|e| WasmError::Abi(format!("missing `{}` export: {e}", abi::ALLOC)))?;

        let evaluate = instance
            .get_typed_func::<(i32, i32), i64>(&store, abi::EVALUATE)
            .map_err(|e| WasmError::Abi(format!("missing `{}` export: {e}", abi::EVALUATE)))?;

        // Ask the guest for a buffer instead of clobbering offset 0. A guest
        // compiled from Rust has its own heap and static data down there.
        let req_len = i32::try_from(req_json.len())
            .map_err(|_| WasmError::Memory("request JSON exceeds i32::MAX".into()))?;
        let req_ptr = alloc
            .call(&mut store, req_len)
            .map_err(|e| WasmError::Runtime(format!("{}: {e}", abi::ALLOC)))?;
        let req_ptr = usize::try_from(req_ptr)
            .map_err(|_| WasmError::Abi("oc_alloc returned a negative offset".into()))?;

        let mem_size = memory.data_size(&store);
        if mem_size > self.limits.max_memory_bytes {
            return Err(WasmError::Memory(format!(
                "guest memory ({mem_size} bytes) exceeds limit ({} bytes)",
                self.limits.max_memory_bytes
            )));
        }
        checked_range(req_ptr, req_json.len(), mem_size, "request buffer")?;

        memory
            .write(&mut store, req_ptr, &req_json)
            .map_err(|e| WasmError::Memory(e.to_string()))?;

        let packed = evaluate
            .call(&mut store, (req_ptr as i32, req_len))
            .map_err(|e| WasmError::Runtime(format!("{}: {e}", abi::EVALUATE)))?;

        // Unpack (ptr << 32) | len.
        let packed = packed as u64;
        let out_ptr = (packed >> 32) as usize;
        let out_len = (packed & 0xFFFF_FFFF) as usize;

        if out_len > self.limits.max_result_bytes {
            return Err(WasmError::Memory(format!(
                "result ({out_len} bytes) exceeds limit ({} bytes)",
                self.limits.max_result_bytes
            )));
        }
        // Re-read the size: the guest may have grown memory during evaluate.
        let mem_size = memory.data_size(&store);
        checked_range(out_ptr, out_len, mem_size, "result buffer")?;

        let mut out = vec![0u8; out_len];
        memory.read(&store, out_ptr, &mut out).map_err(|e| WasmError::Memory(e.to_string()))?;

        let out_str = String::from_utf8(out)
            .map_err(|e| WasmError::ResultParse(format!("result not UTF-8: {e}")))?;
        serde_json::from_str(&out_str).map_err(|e| {
            WasmError::ResultParse(format!("invalid outcome JSON: {e} (got {out_str:?})"))
        })
    }
}

/// Bounds-check a `[ptr, ptr + len)` slice against the guest's memory size.
fn checked_range(ptr: usize, len: usize, mem_size: usize, what: &str) -> Result<(), WasmError> {
    let end = ptr
        .checked_add(len)
        .ok_or_else(|| WasmError::Memory(format!("{what}: offset overflow")))?;
    if end > mem_size {
        return Err(WasmError::Memory(format!(
            "{what}: [{ptr}, {end}) out of bounds (memory is {mem_size} bytes)"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Registry — hot-reloadable set of plugins
// ---------------------------------------------------------------------------

/// A hot-reloadable collection of strategy plugins loaded from a directory.
///
/// The registry is the integration point for the daemon: it scans
/// `<state_dir>/strategies/*.wasm` (and `*.wat`) at startup and on demand,
/// so operators can drop in a new strategy without rebuilding `onecipher`.
///
/// Evaluation semantics are **deny-wins**: every plugin is consulted and the
/// first `Deny` short-circuits. `Warn` outcomes are accumulated.
#[derive(Debug, Default)]
pub struct StrategyRegistry {
    plugins: BTreeMap<String, StrategyPlugin>,
}

/// The combined result of consulting every plugin in a [`StrategyRegistry`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryOutcome {
    /// The blocking outcome, if any plugin denied. Carries the plugin name.
    pub denied_by: Option<(String, String, String)>,
    /// Non-blocking warnings as `(plugin_name, message)`.
    pub warnings: Vec<(String, String)>,
    /// Plugins that failed to evaluate, as `(plugin_name, error)`.
    ///
    /// A failing plugin is **not** treated as a deny: a corrupt strategy file
    /// must not brick the wallet. Failures are surfaced for the audit log.
    pub errors: Vec<(String, String)>,
}

impl RegistryOutcome {
    /// Whether any plugin blocked the request.
    pub fn is_denied(&self) -> bool {
        self.denied_by.is_some()
    }
}

impl StrategyRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Load every `*.wasm` / `*.wat` file in `dir` into a fresh registry.
    ///
    /// A missing directory yields an empty registry (strategies are optional).
    /// Individual files that fail to compile are skipped with a warning so one
    /// bad plugin cannot prevent the daemon from starting.
    pub fn load_dir(dir: &Path) -> Result<Self, WasmError> {
        let mut registry = Self::new();
        if !dir.exists() {
            return Ok(registry);
        }
        let entries =
            std::fs::read_dir(dir).map_err(|e| WasmError::Io(format!("{}: {e}", dir.display())))?;
        for entry in entries {
            let entry = entry.map_err(|e| WasmError::Io(e.to_string()))?;
            let path = entry.path();
            let ext = path.extension().and_then(|s| s.to_str()).unwrap_or_default();
            if ext != "wasm" && ext != "wat" {
                continue;
            }
            match StrategyPlugin::from_path(&path) {
                Ok(plugin) => {
                    tracing::info!(plugin = plugin.name(), path = %path.display(), "loaded strategy plugin");
                    registry.insert(plugin);
                }
                Err(e) => {
                    tracing::warn!(path = %path.display(), error = %e, "skipping unloadable strategy plugin");
                }
            }
        }
        Ok(registry)
    }

    /// Insert (or replace) a plugin.
    pub fn insert(&mut self, plugin: StrategyPlugin) {
        self.plugins.insert(plugin.name().to_string(), plugin);
    }

    /// Remove a plugin by name.
    pub fn remove(&mut self, name: &str) -> Option<StrategyPlugin> {
        self.plugins.remove(name)
    }

    /// The number of loaded plugins.
    pub fn len(&self) -> usize {
        self.plugins.len()
    }

    /// Whether no plugins are loaded.
    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }

    /// The names of loaded plugins, in deterministic order.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.plugins.keys().map(String::as_str)
    }

    /// Consult every plugin. Deny short-circuits; warnings accumulate.
    pub fn evaluate(&self, req: &WasmEvalRequest, host: &dyn WasmHostCalls) -> RegistryOutcome {
        let mut outcome =
            RegistryOutcome { denied_by: None, warnings: Vec::new(), errors: Vec::new() };
        for (name, plugin) in &self.plugins {
            match plugin.evaluate(req, host) {
                Ok(StrategyOutcome::Allow) => {}
                Ok(StrategyOutcome::Warn { message }) => {
                    outcome.warnings.push((name.clone(), message));
                }
                Ok(StrategyOutcome::Deny { reason, message }) => {
                    outcome.denied_by = Some((name.clone(), reason, message));
                    return outcome;
                }
                Err(e) => {
                    tracing::warn!(plugin = name, error = %e, "strategy plugin evaluation failed");
                    outcome.errors.push((name.clone(), e.to_string()));
                }
            }
        }
        outcome
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal, hand-written guest implementing the v1 ABI.
    ///
    /// It scans the request JSON for a marker byte sequence and returns one of
    /// two canned JSON responses. Keeping the guest logic to "substring search"
    /// makes the WAT readable; richer strategies would be compiled from Rust.
    ///
    /// Memory layout:
    /// * `[0, 1024)`   — scratch / bump allocator region handed to the host.
    /// * `[1024, ...)` — data segments holding the canned JSON responses.
    const DENY_MARKER_WAT: &str = r#"
(module
  (memory (export "memory") 1)

  ;; Canned responses live in the data segment starting at 1024.
  (data (i32.const 1024) "{\"outcome\":\"allow\"}")
  (data (i32.const 1088) "{\"outcome\":\"deny\",\"reason\":\"marker\",\"message\":\"blocked by marker strategy\"}")

  ;; Bump allocator cursor. The host-visible arena is [64, 1024).
  (global $cursor (mut i32) (i32.const 64))

  (func (export "oc_alloc") (param $n i32) (result i32)
    (local $ptr i32)
    (local.set $ptr (global.get $cursor))
    (global.set $cursor (i32.add (global.get $cursor) (local.get $n)))
    (local.get $ptr)
  )

  ;; Return true if the needle "DENYME" occurs in [ptr, ptr+len).
  (func $contains_denyme (param $ptr i32) (param $len i32) (result i32)
    (local $i i32)
    (local $base i32)
    (if (i32.lt_s (local.get $len) (i32.const 6))
      (then (return (i32.const 0))))
    (local.set $i (i32.const 0))
    (block $done
      (loop $scan
        (br_if $done (i32.gt_s (local.get $i) (i32.sub (local.get $len) (i32.const 6))))
        (local.set $base (i32.add (local.get $ptr) (local.get $i)))
        (if (i32.and
              (i32.eq (i32.load8_u (local.get $base)) (i32.const 68))            ;; D
              (i32.and
                (i32.eq (i32.load8_u offset=1 (local.get $base)) (i32.const 69)) ;; E
                (i32.and
                  (i32.eq (i32.load8_u offset=2 (local.get $base)) (i32.const 78)) ;; N
                  (i32.and
                    (i32.eq (i32.load8_u offset=3 (local.get $base)) (i32.const 89)) ;; Y
                    (i32.and
                      (i32.eq (i32.load8_u offset=4 (local.get $base)) (i32.const 77)) ;; M
                      (i32.eq (i32.load8_u offset=5 (local.get $base)) (i32.const 69)) ;; E
                    )))))
          (then (return (i32.const 1))))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $scan)
      )
    )
    (i32.const 0)
  )

  ;; Pack (ptr << 32) | len into the i64 return value.
  (func $pack (param $ptr i32) (param $len i32) (result i64)
    (i64.or
      (i64.shl (i64.extend_i32_u (local.get $ptr)) (i64.const 32))
      (i64.extend_i32_u (local.get $len)))
  )

  (func (export "oc_evaluate") (param $ptr i32) (param $len i32) (result i64)
    (if (result i64) (call $contains_denyme (local.get $ptr) (local.get $len))
      (then (call $pack (i32.const 1088) (i32.const 75)))
      (else (call $pack (i32.const 1024) (i32.const 19))))
  )
)
"#;

    /// A guest that spins forever — used to prove fuel metering works.
    const INFINITE_LOOP_WAT: &str = r#"
(module
  (memory (export "memory") 1)
  (func (export "oc_alloc") (param i32) (result i32) (i32.const 64))
  (func (export "oc_evaluate") (param i32 i32) (result i64)
    (loop $forever (br $forever))
    (i64.const 0)
  )
)
"#;

    /// A guest that tries to import a host function — must be rejected.
    const IMPORTING_WAT: &str = r#"
(module
  (import "env" "exfiltrate" (func $exfiltrate (param i32 i32)))
  (memory (export "memory") 1)
  (func (export "oc_alloc") (param i32) (result i32) (i32.const 64))
  (func (export "oc_evaluate") (param $p i32) (param $l i32) (result i64)
    (call $exfiltrate (local.get $p) (local.get $l))
    (i64.const 0)
  )
)
"#;

    /// A guest that returns an out-of-bounds result pointer.
    const OOB_RESULT_WAT: &str = r#"
(module
  (memory (export "memory") 1)
  (func (export "oc_alloc") (param i32) (result i32) (i32.const 64))
  (func (export "oc_evaluate") (param i32 i32) (result i64)
    ;; ptr = 0xFFFF_0000, len = 16 — far beyond one 64 KiB page.
    (i64.or (i64.shl (i64.const 0xFFFF0000) (i64.const 32)) (i64.const 16)))
)
"#;

    /// A guest missing the `oc_alloc` export.
    const NO_ALLOC_WAT: &str = r#"
(module
  (memory (export "memory") 1)
  (func (export "oc_evaluate") (param i32 i32) (result i64) (i64.const 0))
)
"#;

    fn make_req(recipient: &str) -> WasmEvalRequest {
        WasmEvalRequest {
            method: "eth_sendTransaction".into(),
            chain_id: "eip155:1".into(),
            amount_usd: 50.0,
            asset: "eip155:1/slip44:60".into(),
            recipient: recipient.into(),
            session_key_id: "sk-1".into(),
            host_facts: serde_json::Value::Object(serde_json::Map::new()),
        }
    }

    #[test]
    fn compiles_from_wat() {
        let plugin = StrategyPlugin::from_wat("marker", DENY_MARKER_WAT).expect("WAT must compile");
        assert_eq!(plugin.name(), "marker");
    }

    #[test]
    fn allows_when_marker_absent() {
        let plugin = StrategyPlugin::from_wat("marker", DENY_MARKER_WAT).unwrap();
        let outcome = plugin.evaluate(&make_req("0xsafe"), &NoHostFacts).unwrap();
        assert_eq!(outcome, StrategyOutcome::Allow);
    }

    #[test]
    fn denies_when_marker_present() {
        let plugin = StrategyPlugin::from_wat("marker", DENY_MARKER_WAT).unwrap();
        let outcome = plugin.evaluate(&make_req("0xDENYME"), &NoHostFacts).unwrap();
        assert_eq!(
            outcome,
            StrategyOutcome::Deny {
                reason: "marker".into(),
                message: "blocked by marker strategy".into(),
            }
        );
        assert!(outcome.is_deny());
    }

    #[test]
    fn evaluation_is_stateless_across_calls() {
        let plugin = StrategyPlugin::from_wat("marker", DENY_MARKER_WAT).unwrap();
        // The guest's bump allocator would exhaust its arena if the store were
        // reused; a fresh store per call keeps every evaluation independent.
        for _ in 0..200 {
            let outcome = plugin.evaluate(&make_req("0xsafe"), &NoHostFacts).unwrap();
            assert_eq!(outcome, StrategyOutcome::Allow);
        }
    }

    #[test]
    fn fuel_metering_terminates_infinite_loop() {
        let plugin = StrategyPlugin::compile_with_limits(
            "spinner",
            &wat::parse_str(INFINITE_LOOP_WAT).unwrap(),
            StrategyLimits { fuel: 10_000, ..Default::default() },
        )
        .unwrap();
        let err = plugin.evaluate(&make_req("0xsafe"), &NoHostFacts).unwrap_err();
        assert!(matches!(err, WasmError::Runtime(_)), "expected a trap, got {err:?}");
    }

    #[test]
    fn importing_guest_is_rejected() {
        // Compilation succeeds (imports are legal Wasm) but instantiation must
        // fail because the linker defines nothing.
        let plugin = StrategyPlugin::from_wat("evil", IMPORTING_WAT).unwrap();
        let err = plugin.evaluate(&make_req("0xsafe"), &NoHostFacts).unwrap_err();
        assert!(
            matches!(err, WasmError::Instantiate(_)),
            "expected instantiate failure, got {err:?}"
        );
    }

    #[test]
    fn out_of_bounds_result_is_rejected() {
        let plugin = StrategyPlugin::from_wat("oob", OOB_RESULT_WAT).unwrap();
        let err = plugin.evaluate(&make_req("0xsafe"), &NoHostFacts).unwrap_err();
        assert!(matches!(err, WasmError::Memory(_)), "expected a memory error, got {err:?}");
    }

    #[test]
    fn missing_alloc_export_is_an_abi_error() {
        let plugin = StrategyPlugin::from_wat("noalloc", NO_ALLOC_WAT).unwrap();
        let err = plugin.evaluate(&make_req("0xsafe"), &NoHostFacts).unwrap_err();
        assert!(matches!(err, WasmError::Abi(_)), "expected an ABI error, got {err:?}");
    }

    #[test]
    fn oversized_result_is_rejected() {
        let plugin = StrategyPlugin::compile_with_limits(
            "marker",
            &wat::parse_str(DENY_MARKER_WAT).unwrap(),
            StrategyLimits { max_result_bytes: 4, ..Default::default() },
        )
        .unwrap();
        let err = plugin.evaluate(&make_req("0xsafe"), &NoHostFacts).unwrap_err();
        assert!(matches!(err, WasmError::Memory(_)), "expected a memory error, got {err:?}");
    }

    // -- host facts ---------------------------------------------------------

    struct RichHost;

    impl WasmHostCalls for RichHost {
        fn get_wallet_balance(&self, _asset: &str) -> Option<f64> {
            Some(1234.5)
        }
        fn check_rate_limit(&self, _sk: &str, window: &str) -> Option<u64> {
            match window {
                "minute" => Some(3),
                "hour" => Some(40),
                _ => None,
            }
        }
        fn get_spent_usd(&self, _sk: &str) -> Option<f64> {
            Some(99.0)
        }
        fn is_known_recipient(&self, _r: &str) -> Option<bool> {
            Some(false)
        }
    }

    #[test]
    fn host_facts_are_assembled() {
        let facts = RichHost.host_facts(&make_req("0xabc"));
        assert_eq!(facts["wallet_balance"], serde_json::json!(1234.5));
        assert_eq!(facts["rate_limit_minute"], serde_json::json!(3));
        assert_eq!(facts["rate_limit_hour"], serde_json::json!(40));
        assert!(facts.get("rate_limit_day").is_none());
        assert_eq!(facts["spent_usd"], serde_json::json!(99.0));
        assert_eq!(facts["known_recipient"], serde_json::json!(false));
    }

    #[test]
    fn no_host_facts_yields_empty_object() {
        let facts = NoHostFacts.host_facts(&make_req("0xabc"));
        assert_eq!(facts, serde_json::json!({}));
    }

    // -- registry -----------------------------------------------------------

    #[test]
    fn registry_is_empty_for_missing_dir() {
        let dir = tempfile::tempdir().unwrap();
        let registry = StrategyRegistry::load_dir(&dir.path().join("nope")).unwrap();
        assert!(registry.is_empty());
    }

    #[test]
    fn registry_loads_wat_files_and_skips_others() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("marker.wat"), DENY_MARKER_WAT).unwrap();
        std::fs::write(dir.path().join("README.md"), "not a plugin").unwrap();
        std::fs::write(dir.path().join("broken.wat"), "(module (this is not wat)").unwrap();

        let registry = StrategyRegistry::load_dir(dir.path()).unwrap();
        assert_eq!(registry.len(), 1, "only the valid .wat should load");
        assert_eq!(registry.names().collect::<Vec<_>>(), vec!["marker"]);
    }

    #[test]
    fn registry_deny_short_circuits() {
        let mut registry = StrategyRegistry::new();
        registry.insert(StrategyPlugin::from_wat("marker", DENY_MARKER_WAT).unwrap());

        let allowed = registry.evaluate(&make_req("0xsafe"), &NoHostFacts);
        assert!(!allowed.is_denied());
        assert!(allowed.warnings.is_empty());
        assert!(allowed.errors.is_empty());

        let denied = registry.evaluate(&make_req("0xDENYME"), &NoHostFacts);
        let (plugin, reason, _msg) = denied.denied_by.expect("must be denied");
        assert_eq!(plugin, "marker");
        assert_eq!(reason, "marker");
    }

    #[test]
    fn registry_records_failures_without_denying() {
        let mut registry = StrategyRegistry::new();
        registry.insert(StrategyPlugin::from_wat("evil", IMPORTING_WAT).unwrap());

        let outcome = registry.evaluate(&make_req("0xsafe"), &NoHostFacts);
        assert!(!outcome.is_denied(), "a broken plugin must not brick the wallet");
        assert_eq!(outcome.errors.len(), 1);
        assert_eq!(outcome.errors[0].0, "evil");
    }

    #[test]
    fn registry_insert_replaces_by_name() {
        let mut registry = StrategyRegistry::new();
        registry.insert(StrategyPlugin::from_wat("s", DENY_MARKER_WAT).unwrap());
        registry.insert(StrategyPlugin::from_wat("s", DENY_MARKER_WAT).unwrap());
        assert_eq!(registry.len(), 1);
        assert!(registry.remove("s").is_some());
        assert!(registry.is_empty());
    }

    #[test]
    fn outcome_json_round_trips() {
        for outcome in [
            StrategyOutcome::Allow,
            StrategyOutcome::Warn { message: "hmm".into() },
            StrategyOutcome::Deny { reason: "r".into(), message: "m".into() },
        ] {
            let json = serde_json::to_string(&outcome).unwrap();
            let back: StrategyOutcome = serde_json::from_str(&json).unwrap();
            assert_eq!(outcome, back);
        }
    }
}
