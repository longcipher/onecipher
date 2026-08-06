//! Cross-boundary telemetry: a `tracing` layer that makes Key-Agent spans and
//! events observable from the Network-Agent.
//!
//! ## The problem
//!
//! The Key-Agent is deliberately isolated: R56 forbids `tokio` / `reqwest` /
//! `hyper`, and R12 forbids sockets other than the control UDS. That rules out
//! linking an OTLP exporter here — `opentelemetry-otlp` needs tonic or reqwest,
//! either of which would break both gates. Yet the Key-Agent is exactly where
//! the security-relevant work happens (policy decisions, key derivation,
//! signing), so a trace that stops at the process boundary is close to useless.
//!
//! ## The design
//!
//! Invert the direction of the dependency. The Key-Agent does **not** export
//! anything; it *records* into a bounded in-memory ring buffer via a
//! [`tracing_subscriber`]-free, hand-rolled [`tracing::Subscriber`] layer. The
//! Network-Agent — which already has tokio and may link an OTLP exporter —
//! *drains* that buffer over the control UDS it is already connected to.
//!
//! ```text
//!   Key-Agent (sync, no tokio, no sockets but UDS)
//!     tracing::info!(...) ──► TelemetryLayer ──► ring buffer (bounded)
//!                                                     │
//!                                       DrainTelemetry IPC request
//!                                                     │
//!   Network-Agent (tokio) ◄────────────────────────────┘
//!     └─► tracing-opentelemetry / OTLP / stdout
//! ```
//!
//! Properties this buys us:
//!
//! * **R56/R12 preserved.** No new dependency, no new socket. `tracing` is a pure facade and the
//!   buffer is a `Mutex<VecDeque<_>>`.
//! * **Bounded.** The buffer has a hard capacity; on overflow the *oldest* record is dropped and a
//!   counter is incremented, so a log storm can never exhaust the Key-Agent's memory or block a
//!   signing thread.
//! * **Non-blocking.** Recording takes an uncontended mutex and pushes; it never does I/O.
//! * **Correlated.** Each record carries the span id and parent span id, so the Network-Agent can
//!   rebuild the causal tree and stitch it onto its own trace.
//!
//! ## Redaction
//!
//! A telemetry channel that leaves the Key-Agent is an exfiltration path, so
//! field capture is **deny-by-default on value content**: only fields whose
//! names are on [`SAFE_FIELDS`] have their values recorded. Everything else is
//! recorded as the field name with the value replaced by `"<redacted>"`. This
//! means adding `tracing::info!(mnemonic = %m)` somewhere cannot leak the
//! mnemonic through telemetry, even by accident.

use std::{
    collections::VecDeque,
    fmt::Write as _,
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

use serde::{Deserialize, Serialize};

/// Field names whose *values* may be recorded verbatim.
///
/// Deny-by-default: anything not listed here is redacted. Keep this list to
/// low-cardinality, non-secret operational identifiers.
pub const SAFE_FIELDS: &[&str] = &[
    "message",
    "method",
    "chain_id",
    "session_key_id",
    "wallet_id",
    "device_id",
    "status",
    "decision",
    "deny_reason",
    "plugin",
    "reason",
    "outcome",
    "duration_ms",
    "count",
    "len",
    "code",
    "kind",
    "error",
    "seq",
    "event_type",
];

/// The placeholder substituted for the value of a non-allowlisted field.
pub const REDACTED: &str = "<redacted>";

/// Severity of a telemetry record, mirroring [`tracing::Level`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum TelemetryLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl TelemetryLevel {
    fn from_tracing(level: &tracing::Level) -> Self {
        match *level {
            tracing::Level::TRACE => Self::Trace,
            tracing::Level::DEBUG => Self::Debug,
            tracing::Level::INFO => Self::Info,
            tracing::Level::WARN => Self::Warn,
            tracing::Level::ERROR => Self::Error,
        }
    }
}

impl std::fmt::Display for TelemetryLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Trace => "TRACE",
            Self::Debug => "DEBUG",
            Self::Info => "INFO",
            Self::Warn => "WARN",
            Self::Error => "ERROR",
        };
        f.write_str(s)
    }
}

/// What kind of lifecycle point a record represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordKind {
    /// A span was entered.
    SpanOpen,
    /// A span was closed. `duration_ms` is populated when known.
    SpanClose,
    /// A discrete event (`tracing::info!` and friends).
    Event,
}

/// A single telemetry record, drained across the IPC boundary.
///
/// Deliberately flat and `serde`-serializable so the Network-Agent can turn it
/// into an OTLP log record or span without needing the Key-Agent's types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetryRecord {
    /// Monotonic sequence number, unique within a Key-Agent process lifetime.
    /// Lets the consumer detect gaps that the ring buffer dropped.
    pub seq: u64,
    /// Milliseconds since the Unix epoch.
    pub timestamp_ms: u64,
    pub level: TelemetryLevel,
    pub kind: RecordKind,
    /// The tracing target (usually the module path).
    pub target: String,
    /// The span or event name.
    pub name: String,
    /// The span this record belongs to, if any.
    pub span_id: Option<u64>,
    /// The enclosing span, enabling causal-tree reconstruction.
    pub parent_span_id: Option<u64>,
    /// Wall-clock duration, only for [`RecordKind::SpanClose`].
    pub duration_ms: Option<u64>,
    /// Captured fields. Values not on [`SAFE_FIELDS`] are [`REDACTED`].
    pub fields: Vec<(String, String)>,
}

/// A batch of records plus the count lost to buffer overflow.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetryBatch {
    pub records: Vec<TelemetryRecord>,
    /// How many records were dropped since the last drain because the ring
    /// buffer was full. A non-zero value means the consumer is too slow (or
    /// the Key-Agent is unusually chatty) and the trace has gaps.
    pub dropped: u64,
}

impl TelemetryBatch {
    /// Whether the batch carries nothing at all.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty() && self.dropped == 0
    }
}

/// Default ring-buffer capacity, in records.
pub const DEFAULT_CAPACITY: usize = 2048;

/// The bounded, drainable sink the layer writes into.
///
/// Cloning is not offered on purpose: there is one process-wide buffer, reached
/// through [`global_buffer`].
#[derive(Debug)]
pub struct TelemetryBuffer {
    inner: Mutex<VecDeque<TelemetryRecord>>,
    capacity: usize,
    dropped: AtomicU64,
    next_seq: AtomicU64,
    enabled: AtomicBool,
}

impl TelemetryBuffer {
    /// A buffer holding at most `capacity` records.
    ///
    /// A capacity of 0 is coerced to 1 so `push` always has somewhere to write.
    pub fn with_capacity(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            inner: Mutex::new(VecDeque::with_capacity(capacity)),
            capacity,
            dropped: AtomicU64::new(0),
            next_seq: AtomicU64::new(0),
            // Off until `init()` runs, so merely linking the crate costs nothing.
            enabled: AtomicBool::new(false),
        }
    }

    /// Whether recording is currently on.
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// Turn recording on or off. Disabling also drops nothing already buffered.
    pub fn set_enabled(&self, on: bool) {
        self.enabled.store(on, Ordering::Relaxed);
    }

    /// The maximum number of records retained.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// How many records are currently buffered.
    pub fn len(&self) -> usize {
        self.inner.lock().map_or(0, |b| b.len())
    }

    /// Whether nothing is buffered.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Allocate the next sequence number.
    fn next_seq(&self) -> u64 {
        self.next_seq.fetch_add(1, Ordering::Relaxed)
    }

    /// Append a record, evicting the oldest if the buffer is full.
    ///
    /// Dropping the *oldest* (rather than refusing the newest) keeps the most
    /// recent — and for incident response, most relevant — history. A poisoned
    /// mutex is swallowed: telemetry must never take down a signing thread.
    pub fn push(&self, record: TelemetryRecord) {
        if !self.is_enabled() {
            return;
        }
        let Ok(mut buf) = self.inner.lock() else {
            return;
        };
        if buf.len() >= self.capacity {
            buf.pop_front();
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        buf.push_back(record);
    }

    /// Take everything buffered, resetting the drop counter.
    pub fn drain(&self) -> TelemetryBatch {
        let records = self.inner.lock().map(|mut b| b.drain(..).collect()).unwrap_or_default();
        TelemetryBatch { records, dropped: self.dropped.swap(0, Ordering::Relaxed) }
    }

    /// Take at most `max` records, oldest first.
    ///
    /// Used by the IPC path to keep a single response frame under
    /// [`crate::frame::MAX_FRAME_SIZE`].
    pub fn drain_at_most(&self, max: usize) -> TelemetryBatch {
        let Ok(mut buf) = self.inner.lock() else {
            return TelemetryBatch::default();
        };
        let take = max.min(buf.len());
        let records: Vec<_> = buf.drain(..take).collect();
        drop(buf);
        // Only clear the drop counter once the backlog is fully drained;
        // otherwise a partial drain would under-report the gap.
        let dropped =
            if take == 0 || self.is_empty() { self.dropped.swap(0, Ordering::Relaxed) } else { 0 };
        TelemetryBatch { records, dropped }
    }
}

impl Default for TelemetryBuffer {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }
}

static GLOBAL_BUFFER: OnceLock<TelemetryBuffer> = OnceLock::new();

/// The process-wide telemetry buffer.
pub fn global_buffer() -> &'static TelemetryBuffer {
    GLOBAL_BUFFER.get_or_init(TelemetryBuffer::default)
}

/// Milliseconds since the Unix epoch, saturating to 0 before it.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

// ---------------------------------------------------------------------------
// Field capture
// ---------------------------------------------------------------------------

/// Collects `tracing` field values into `(name, value)` pairs, redacting any
/// field not on [`SAFE_FIELDS`].
#[derive(Debug, Default)]
struct FieldCollector {
    fields: Vec<(String, String)>,
}

impl FieldCollector {
    fn record(&mut self, name: &str, value: impl std::fmt::Display) {
        let rendered =
            if SAFE_FIELDS.contains(&name) { value.to_string() } else { REDACTED.to_string() };
        self.fields.push((name.to_string(), rendered));
    }
}

impl tracing::field::Visit for FieldCollector {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        let name = field.name();
        if SAFE_FIELDS.contains(&name) {
            let mut s = String::new();
            let _ = write!(s, "{value:?}");
            self.fields.push((name.to_string(), s));
        } else {
            self.fields.push((name.to_string(), REDACTED.to_string()));
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.record(field.name(), value);
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.record(field.name(), value);
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.record(field.name(), value);
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.record(field.name(), value);
    }

    fn record_f64(&mut self, field: &tracing::field::Field, value: f64) {
        self.record(field.name(), value);
    }
}

// ---------------------------------------------------------------------------
// Subscriber
// ---------------------------------------------------------------------------

/// Per-span bookkeeping held while a span is alive.
#[derive(Debug)]
struct SpanState {
    name: &'static str,
    target: String,
    level: TelemetryLevel,
    parent: Option<u64>,
    opened_at_ms: u64,
    fields: Vec<(String, String)>,
}

/// A minimal [`tracing::Subscriber`] that records into a [`TelemetryBuffer`].
///
/// This is hand-rolled rather than built on `tracing-subscriber` because that
/// crate is not currently a dependency and pulling it into `oc-keyagent` would
/// enlarge the audited dependency surface of the most security-sensitive crate
/// in the workspace for very little gain: all we need is "capture and buffer".
///
/// Span parentage is tracked with a thread-local stack, which is correct for
/// the Key-Agent's thread-per-connection model (each request is handled start
/// to finish on one thread).
#[derive(Debug)]
pub struct TelemetrySubscriber {
    buffer: &'static TelemetryBuffer,
    max_level: TelemetryLevel,
    next_id: AtomicU64,
    spans: Mutex<std::collections::HashMap<u64, SpanState>>,
}

thread_local! {
    /// Stack of currently entered span ids on this thread.
    static SPAN_STACK: std::cell::RefCell<Vec<u64>> = const { std::cell::RefCell::new(Vec::new()) };
}

impl TelemetrySubscriber {
    /// A subscriber writing into the process-wide buffer at `max_level`.
    pub fn new(max_level: TelemetryLevel) -> Self {
        Self {
            buffer: global_buffer(),
            max_level,
            // Span id 0 is reserved: `tracing::span::Id` must be non-zero.
            next_id: AtomicU64::new(1),
            spans: Mutex::new(std::collections::HashMap::new()),
        }
    }

    fn current_span_id() -> Option<u64> {
        SPAN_STACK.with(|s| s.borrow().last().copied())
    }
}

impl tracing::Subscriber for TelemetrySubscriber {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        TelemetryLevel::from_tracing(metadata.level()) >= self.max_level
    }

    fn new_span(&self, span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mut collector = FieldCollector::default();
        span.record(&mut collector);

        let state = SpanState {
            name: span.metadata().name(),
            target: span.metadata().target().to_string(),
            level: TelemetryLevel::from_tracing(span.metadata().level()),
            parent: Self::current_span_id(),
            opened_at_ms: now_ms(),
            fields: collector.fields,
        };
        if let Ok(mut spans) = self.spans.lock() {
            spans.insert(id, state);
        }
        tracing::span::Id::from_u64(id)
    }

    fn record(&self, span: &tracing::span::Id, values: &tracing::span::Record<'_>) {
        let mut collector = FieldCollector::default();
        values.record(&mut collector);
        if let Ok(mut spans) = self.spans.lock() {
            if let Some(state) = spans.get_mut(&span.into_u64()) {
                state.fields.extend(collector.fields);
            }
        }
    }

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {
        // Causal links other than parentage are not modelled.
    }

    fn event(&self, event: &tracing::Event<'_>) {
        let metadata = event.metadata();
        let mut collector = FieldCollector::default();
        event.record(&mut collector);

        let span_id = Self::current_span_id();
        let parent_span_id = SPAN_STACK.with(|s| {
            let stack = s.borrow();
            if stack.len() >= 2 { stack.get(stack.len() - 2).copied() } else { None }
        });

        self.buffer.push(TelemetryRecord {
            seq: self.buffer.next_seq(),
            timestamp_ms: now_ms(),
            level: TelemetryLevel::from_tracing(metadata.level()),
            kind: RecordKind::Event,
            target: metadata.target().to_string(),
            name: metadata.name().to_string(),
            span_id,
            parent_span_id,
            duration_ms: None,
            fields: collector.fields,
        });
    }

    fn enter(&self, span: &tracing::span::Id) {
        let id = span.into_u64();
        SPAN_STACK.with(|s| s.borrow_mut().push(id));

        let Ok(spans) = self.spans.lock() else { return };
        let Some(state) = spans.get(&id) else { return };
        self.buffer.push(TelemetryRecord {
            seq: self.buffer.next_seq(),
            timestamp_ms: now_ms(),
            level: state.level,
            kind: RecordKind::SpanOpen,
            target: state.target.clone(),
            name: state.name.to_string(),
            span_id: Some(id),
            parent_span_id: state.parent,
            duration_ms: None,
            fields: state.fields.clone(),
        });
    }

    fn exit(&self, span: &tracing::span::Id) {
        let id = span.into_u64();
        SPAN_STACK.with(|s| {
            let mut stack = s.borrow_mut();
            // Pop this span, tolerating out-of-order exits.
            if let Some(pos) = stack.iter().rposition(|&x| x == id) {
                stack.remove(pos);
            }
        });

        let Ok(spans) = self.spans.lock() else { return };
        let Some(state) = spans.get(&id) else { return };
        self.buffer.push(TelemetryRecord {
            seq: self.buffer.next_seq(),
            timestamp_ms: now_ms(),
            level: state.level,
            kind: RecordKind::SpanClose,
            target: state.target.clone(),
            name: state.name.to_string(),
            span_id: Some(id),
            parent_span_id: state.parent,
            duration_ms: Some(now_ms().saturating_sub(state.opened_at_ms)),
            fields: state.fields.clone(),
        });
    }

    fn try_close(&self, span: tracing::span::Id) -> bool {
        if let Ok(mut spans) = self.spans.lock() {
            spans.remove(&span.into_u64());
        }
        true
    }
}

/// Install the telemetry subscriber process-wide and enable recording.
///
/// Idempotent in effect: `tracing` only accepts one global subscriber, so a
/// second call returns `false` and leaves the first installation in place.
///
/// # Returns
///
/// `true` if this call installed the subscriber.
pub fn init(max_level: TelemetryLevel) -> bool {
    global_buffer().set_enabled(true);
    tracing::subscriber::set_global_default(TelemetrySubscriber::new(max_level)).is_ok()
}

/// Drain at most `max` buffered records.
pub fn drain(max: usize) -> TelemetryBatch {
    global_buffer().drain_at_most(max)
}

/// Serializes every test that touches the process-wide buffer.
///
/// [`global_buffer`] is a singleton shared by the whole test binary, so
/// telemetry tests and the `handler::DrainTelemetry` tests would steal records
/// from each other if they ran concurrently. Both modules take *this* lock —
/// a per-module mutex would not help, since they guard the same state.
#[cfg(test)]
pub(crate) static TELEMETRY_TEST_LOCK: Mutex<()> = Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;

    fn record(seq: u64) -> TelemetryRecord {
        TelemetryRecord {
            seq,
            timestamp_ms: 1_700_000_000_000,
            level: TelemetryLevel::Info,
            kind: RecordKind::Event,
            target: "oc-keyagent::test".into(),
            name: "ev".into(),
            span_id: None,
            parent_span_id: None,
            duration_ms: None,
            fields: vec![],
        }
    }

    // -- buffer -------------------------------------------------------------

    #[test]
    fn buffer_starts_disabled_so_linking_is_free() {
        let buf = TelemetryBuffer::with_capacity(4);
        assert!(!buf.is_enabled());
        buf.push(record(0));
        assert!(buf.is_empty(), "a disabled buffer must record nothing");
    }

    #[test]
    fn buffer_records_when_enabled() {
        let buf = TelemetryBuffer::with_capacity(4);
        buf.set_enabled(true);
        buf.push(record(0));
        buf.push(record(1));
        assert_eq!(buf.len(), 2);
    }

    #[test]
    fn buffer_evicts_oldest_on_overflow_and_counts_drops() {
        let buf = TelemetryBuffer::with_capacity(2);
        buf.set_enabled(true);
        for i in 0..5 {
            buf.push(record(i));
        }
        let batch = buf.drain();
        assert_eq!(batch.records.len(), 2, "capacity must be respected");
        // The two most recent survive.
        assert_eq!(batch.records[0].seq, 3);
        assert_eq!(batch.records[1].seq, 4);
        assert_eq!(batch.dropped, 3, "the gap must be reported");
    }

    #[test]
    fn drain_resets_the_drop_counter() {
        let buf = TelemetryBuffer::with_capacity(1);
        buf.set_enabled(true);
        buf.push(record(0));
        buf.push(record(1));
        assert_eq!(buf.drain().dropped, 1);
        assert_eq!(buf.drain().dropped, 0, "the counter must not double-report");
    }

    #[test]
    fn zero_capacity_is_coerced_to_one() {
        let buf = TelemetryBuffer::with_capacity(0);
        buf.set_enabled(true);
        buf.push(record(0));
        assert_eq!(buf.len(), 1);
    }

    #[test]
    fn drain_at_most_takes_oldest_first_and_leaves_the_rest() {
        let buf = TelemetryBuffer::with_capacity(10);
        buf.set_enabled(true);
        for i in 0..5 {
            buf.push(record(i));
        }
        let batch = buf.drain_at_most(2);
        assert_eq!(batch.records.iter().map(|r| r.seq).collect::<Vec<_>>(), vec![0, 1]);
        assert_eq!(buf.len(), 3, "the remainder stays buffered");
    }

    #[test]
    fn drain_at_most_defers_the_drop_count_until_fully_drained() {
        let buf = TelemetryBuffer::with_capacity(2);
        buf.set_enabled(true);
        for i in 0..4 {
            buf.push(record(i));
        }
        // Partial drain: the gap is not yet reported...
        assert_eq!(buf.drain_at_most(1).dropped, 0);
        // ...and is reported once the backlog clears.
        assert_eq!(buf.drain_at_most(10).dropped, 2);
    }

    #[test]
    fn empty_batch_is_reported_as_empty() {
        assert!(TelemetryBatch::default().is_empty());
        let non_empty = TelemetryBatch { records: vec![], dropped: 1 };
        assert!(!non_empty.is_empty(), "a pure-drop batch still carries information");
    }

    // -- redaction ----------------------------------------------------------

    #[test]
    fn allowlisted_fields_keep_their_values() {
        let mut c = FieldCollector::default();
        c.record("chain_id", "eip155:1");
        assert_eq!(c.fields, vec![("chain_id".to_string(), "eip155:1".to_string())]);
    }

    #[test]
    fn non_allowlisted_fields_are_redacted() {
        let mut c = FieldCollector::default();
        c.record("mnemonic", "abandon abandon abandon");
        c.record("private_key", "0xdeadbeef");
        assert_eq!(
            c.fields,
            vec![
                ("mnemonic".to_string(), REDACTED.to_string()),
                ("private_key".to_string(), REDACTED.to_string()),
            ]
        );
    }

    #[test]
    fn the_allowlist_contains_no_secret_shaped_names() {
        // A guard against someone "helpfully" widening the allowlist.
        for banned in
            ["mnemonic", "seed", "private_key", "privkey", "secret", "passphrase", "password"]
        {
            assert!(
                !SAFE_FIELDS.contains(&banned),
                "`{banned}` must never be an allowlisted telemetry field"
            );
        }
    }

    // -- subscriber ---------------------------------------------------------

    /// The subscriber writes to the process-wide buffer, so these tests share
    /// state. They drive the subscriber directly (rather than installing it
    /// globally, which can only happen once per process) and serialize on a
    /// mutex.
    fn with_global_buffer<T>(f: impl FnOnce(&'static TelemetryBuffer) -> T) -> T {
        let _guard = TELEMETRY_TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let buf = global_buffer();
        buf.set_enabled(true);
        let _ = buf.drain();
        let out = f(buf);
        let _ = buf.drain();
        out
    }

    #[test]
    fn subscriber_level_filter_rejects_below_threshold() {
        let sub = TelemetrySubscriber::new(TelemetryLevel::Warn);
        tracing::subscriber::with_default(sub, || {
            // `enabled` is what the macros consult; assert via the callsite.
            assert!(tracing::event_enabled!(tracing::Level::ERROR));
            assert!(!tracing::event_enabled!(tracing::Level::DEBUG));
        });
    }

    #[test]
    fn subscriber_captures_events_with_redaction() {
        with_global_buffer(|buf| {
            let sub = TelemetrySubscriber::new(TelemetryLevel::Trace);
            tracing::subscriber::with_default(sub, || {
                tracing::info!(chain_id = "eip155:1", mnemonic = "leak me", "signing");
            });
            let batch = buf.drain();
            assert_eq!(batch.records.len(), 1);
            let rec = &batch.records[0];
            assert_eq!(rec.kind, RecordKind::Event);
            assert_eq!(rec.level, TelemetryLevel::Info);
            let fields: std::collections::HashMap<_, _> = rec.fields.iter().cloned().collect();
            assert_eq!(fields.get("chain_id").map(String::as_str), Some("eip155:1"));
            assert_eq!(fields.get("mnemonic").map(String::as_str), Some(REDACTED));
            assert_eq!(fields.get("message").map(String::as_str), Some("signing"));
        });
    }

    #[test]
    fn subscriber_records_span_open_and_close_with_parentage() {
        with_global_buffer(|buf| {
            let sub = TelemetrySubscriber::new(TelemetryLevel::Trace);
            tracing::subscriber::with_default(sub, || {
                let outer = tracing::info_span!("outer");
                let _o = outer.enter();
                {
                    let inner = tracing::info_span!("inner");
                    let _i = inner.enter();
                    tracing::info!("inside");
                }
            });
            let batch = buf.drain();

            let opens: Vec<_> =
                batch.records.iter().filter(|r| r.kind == RecordKind::SpanOpen).collect();
            let closes: Vec<_> =
                batch.records.iter().filter(|r| r.kind == RecordKind::SpanClose).collect();
            assert_eq!(opens.len(), 2, "both spans must be recorded");
            assert_eq!(closes.len(), 2, "both spans must be closed");

            let outer_id = opens.iter().find(|r| r.name == "outer").unwrap().span_id;
            let inner = opens.iter().find(|r| r.name == "inner").unwrap();
            assert_eq!(inner.parent_span_id, outer_id, "parentage must be reconstructable");

            let ev = batch.records.iter().find(|r| r.kind == RecordKind::Event).unwrap();
            assert_eq!(ev.span_id, inner.span_id, "the event belongs to the innermost span");
        });
    }

    #[test]
    fn span_close_carries_a_duration() {
        with_global_buffer(|buf| {
            let sub = TelemetrySubscriber::new(TelemetryLevel::Trace);
            tracing::subscriber::with_default(sub, || {
                let s = tracing::info_span!("timed");
                let _e = s.enter();
            });
            let batch = buf.drain();
            let close =
                batch.records.iter().find(|r| r.kind == RecordKind::SpanClose).expect("a close");
            assert!(close.duration_ms.is_some());
        });
    }

    #[test]
    fn sequence_numbers_are_monotonic() {
        with_global_buffer(|buf| {
            let sub = TelemetrySubscriber::new(TelemetryLevel::Trace);
            tracing::subscriber::with_default(sub, || {
                for _ in 0..5 {
                    tracing::info!("tick");
                }
            });
            let seqs: Vec<_> = buf.drain().records.iter().map(|r| r.seq).collect();
            assert_eq!(seqs.len(), 5);
            assert!(seqs.windows(2).all(|w| w[0] < w[1]), "seq must be strictly increasing");
        });
    }

    #[test]
    fn new_span_never_returns_the_reserved_zero_id() {
        let sub = TelemetrySubscriber::new(TelemetryLevel::Trace);
        tracing::subscriber::with_default(sub, || {
            // `tracing::span::Id::from_u64` panics on 0, so merely creating a
            // span exercises the invariant.
            let s = tracing::info_span!("s");
            assert_ne!(s.id().map(|i| i.into_u64()), Some(0));
        });
    }

    // -- serialization ------------------------------------------------------

    #[test]
    fn batch_json_round_trips() {
        let batch = TelemetryBatch {
            records: vec![TelemetryRecord {
                seq: 7,
                timestamp_ms: 1_700_000_000_000,
                level: TelemetryLevel::Warn,
                kind: RecordKind::SpanClose,
                target: "oc-keyagent::policy".into(),
                name: "evaluate".into(),
                span_id: Some(3),
                parent_span_id: Some(1),
                duration_ms: Some(12),
                fields: vec![("decision".into(), "deny".into())],
            }],
            dropped: 2,
        };
        let json = serde_json::to_string(&batch).unwrap();
        let back: TelemetryBatch = serde_json::from_str(&json).unwrap();
        assert_eq!(batch, back);
    }

    #[test]
    fn level_display_matches_serde() {
        for level in [
            TelemetryLevel::Trace,
            TelemetryLevel::Debug,
            TelemetryLevel::Info,
            TelemetryLevel::Warn,
            TelemetryLevel::Error,
        ] {
            let json = serde_json::to_string(&level).unwrap();
            assert_eq!(json, format!("\"{level}\""));
        }
    }

    #[test]
    fn levels_order_by_severity() {
        assert!(TelemetryLevel::Error > TelemetryLevel::Warn);
        assert!(TelemetryLevel::Warn > TelemetryLevel::Info);
        assert!(TelemetryLevel::Info > TelemetryLevel::Debug);
        assert!(TelemetryLevel::Debug > TelemetryLevel::Trace);
    }

    #[test]
    fn subscriber_survives_many_threads() {
        // The Key-Agent is thread-per-connection; the span stack is
        // thread-local, so concurrent spans must not interleave their ids.
        with_global_buffer(|buf| {
            let sub = std::sync::Arc::new(TelemetrySubscriber::new(TelemetryLevel::Trace));
            let dispatch = tracing::Dispatch::from(
                sub as std::sync::Arc<dyn tracing::Subscriber + Send + Sync>,
            );
            std::thread::scope(|scope| {
                for _ in 0..8 {
                    let d = dispatch.clone();
                    scope.spawn(move || {
                        tracing::dispatcher::with_default(&d, || {
                            let s = tracing::info_span!("worker");
                            let _e = s.enter();
                            tracing::info!("work");
                        });
                    });
                }
            });
            let batch = buf.drain();
            let events: Vec<_> =
                batch.records.iter().filter(|r| r.kind == RecordKind::Event).collect();
            assert_eq!(events.len(), 8);
            // Every event must be attributed to some span, and never to a
            // span from a different thread's stack.
            assert!(events.iter().all(|e| e.span_id.is_some()));
        });
    }
}
