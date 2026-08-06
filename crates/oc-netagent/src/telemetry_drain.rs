//! Telemetry drain: pull the Key-Agent's buffered spans and export them (P1 3.1).
//!
//! # Why a pull, not a push
//!
//! The Key-Agent is deliberately export-blind. R56 forbids it from linking
//! `tokio` / `reqwest` / any HTTP stack, and R12 plus the runtime sandbox
//! (seccomp on Linux, Seatbelt on macOS) deny it every socket that is not a
//! Unix domain socket. So it *cannot* ship spans to a collector even if we
//! wanted it to.
//!
//! What it does instead is buffer redacted, structured records in a bounded
//! ring ([`oc_keyagent::telemetry`]). This module lives on the other side of
//! the trust boundary — in the Network-Agent, which already has a tokio
//! runtime and already holds a UDS connection to the Key-Agent — and
//! periodically drains that ring, giving one coherent trace across both
//! processes.
//!
//! # Redaction
//!
//! Values are redacted *at record time*, inside the Key-Agent: only field
//! names on `oc_keyagent::telemetry::SAFE_FIELDS` keep their value, everything
//! else is stored as `<redacted>`. Nothing here can un-redact anything, and
//! this module deliberately does not add its own allowlist — a second,
//! divergent policy would be a footgun.
//!
//! # Exporters
//!
//! [`TelemetrySink`] is the seam. `StdoutSink` is provided for local
//! debugging; an OTLP exporter can be added later without touching the drain
//! loop.

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use oc_keyagent::{
    KeyAgentRequest, KeyAgentRequestKind, KeyAgentResponseKind,
    proto::{DrainTelemetryRequest, DrainTelemetryResponse},
    telemetry::{TelemetryBatch, TelemetryRecord},
};
use prost::Message;

use crate::{error::NetAgentError, key_agent_client::KeyAgentClient};

/// Default interval between drains.
pub const DEFAULT_DRAIN_INTERVAL: Duration = Duration::from_secs(5);

/// Records requested per drain. Matches the Key-Agent's own per-call cap, so
/// a full buffer is emptied in a bounded number of round trips.
pub const DEFAULT_BATCH_SIZE: u32 = 512;

/// Maximum consecutive back-to-back drains before yielding to the interval.
///
/// Without this, a Key-Agent producing records faster than we drain would keep
/// the loop spinning and starve the rest of the runtime.
const MAX_CATCHUP_ROUNDS: u32 = 8;

// ---------------------------------------------------------------------------
// Sink
// ---------------------------------------------------------------------------

/// Where drained records go.
///
/// Implementations must not block for long: the drain loop awaits them inline
/// so that a slow exporter applies natural back-pressure rather than growing
/// an unbounded queue on our side.
pub trait TelemetrySink: Send + Sync {
    /// Export one batch. Errors are logged and swallowed by the drain loop —
    /// telemetry must never take down the agent.
    fn export(&self, batch: &TelemetryBatch) -> Result<(), String>;
}

/// Writes each record as a single line to stdout. Useful for local debugging
/// and as the default when no collector is configured.
#[derive(Debug, Default, Clone, Copy)]
pub struct StdoutSink;

impl TelemetrySink for StdoutSink {
    fn export(&self, batch: &TelemetryBatch) -> Result<(), String> {
        for record in &batch.records {
            let line = serde_json::to_string(record).map_err(|e| e.to_string())?;
            println!("{line}");
        }
        if batch.dropped > 0 {
            println!(
                r#"{{"warning":"key-agent telemetry buffer overflowed","dropped":{}}}"#,
                batch.dropped
            );
        }
        Ok(())
    }
}

/// Collects records in memory. Intended for tests and for the Web UI's live
/// span view, not for production export.
#[derive(Debug, Default)]
pub struct MemorySink {
    records: std::sync::Mutex<Vec<TelemetryRecord>>,
    dropped: AtomicU64,
}

impl MemorySink {
    /// A new, empty sink.
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot everything exported so far.
    pub fn records(&self) -> Vec<TelemetryRecord> {
        self.records.lock().map(|r| r.clone()).unwrap_or_default()
    }

    /// Total records reported lost to Key-Agent buffer overflow.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

impl TelemetrySink for MemorySink {
    fn export(&self, batch: &TelemetryBatch) -> Result<(), String> {
        if let Ok(mut guard) = self.records.lock() {
            guard.extend(batch.records.iter().cloned());
        }
        self.dropped.fetch_add(batch.dropped, Ordering::Relaxed);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Drain
// ---------------------------------------------------------------------------

/// Statistics accumulated by a running drain loop.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DrainStats {
    /// Records successfully handed to the sink.
    pub exported: u64,
    /// Records the Key-Agent reported losing to ring-buffer overflow.
    pub dropped: u64,
    /// Drain round trips that failed (transport or Key-Agent error).
    pub failures: u64,
}

/// Perform exactly one drain round trip.
///
/// Returns the decoded batch. An `Ok` with an empty batch means the Key-Agent
/// had nothing buffered — the common case on an idle wallet.
pub async fn drain_once(
    client: &KeyAgentClient,
    max_records: u32,
) -> Result<TelemetryBatch, NetAgentError> {
    let req = KeyAgentRequest {
        kind: Some(KeyAgentRequestKind::DrainTelemetry(DrainTelemetryRequest { max_records })),
    };
    let resp = client.send(&req).await?;

    match resp.kind {
        Some(KeyAgentResponseKind::Ok(payload)) => {
            let decoded = DrainTelemetryResponse::decode(payload.as_slice())?;
            serde_json::from_str(&decoded.batch_json).map_err(|e| {
                NetAgentError::KeyAgentWire(format!("telemetry batch is not valid JSON: {e}"))
            })
        }
        Some(KeyAgentResponseKind::Error(msg)) => Err(NetAgentError::KeyAgentError(msg)),
        Some(KeyAgentResponseKind::Deny(payload)) => {
            // DrainTelemetry is not policy-gated, so a Deny here means the
            // Key-Agent and this client disagree about the wire contract.
            Err(NetAgentError::KeyAgentWire(format!(
                "DrainTelemetry unexpectedly denied (reason={})",
                payload.reason
            )))
        }
        None => Ok(TelemetryBatch::default()),
    }
}

/// Drain repeatedly until the Key-Agent reports an empty buffer, exporting
/// each batch.
///
/// Bounded by [`MAX_CATCHUP_ROUNDS`] so a hot producer cannot monopolize the
/// task. Returns the stats for this burst.
pub async fn drain_until_empty(
    client: &KeyAgentClient,
    sink: &dyn TelemetrySink,
    max_records: u32,
) -> DrainStats {
    let mut stats = DrainStats::default();

    for _ in 0..MAX_CATCHUP_ROUNDS {
        let batch = match drain_once(client, max_records).await {
            Ok(b) => b,
            Err(e) => {
                tracing::debug!(error = %e, "telemetry drain round trip failed");
                stats.failures += 1;
                break;
            }
        };

        if batch.is_empty() {
            break;
        }

        let count = batch.records.len() as u64;
        let dropped = batch.dropped;
        let short_batch = count < u64::from(max_records);

        if let Err(e) = sink.export(&batch) {
            tracing::debug!(error = %e, "telemetry export failed");
            stats.failures += 1;
        } else {
            stats.exported += count;
        }
        stats.dropped += dropped;

        // A partial batch means we emptied the ring; no need for another
        // round trip just to be told it is empty.
        if short_batch {
            break;
        }
    }

    stats
}

/// Run the drain loop forever, polling every `interval`.
///
/// Never returns. Intended to be `tokio::spawn`ed alongside the WC server.
/// Transport failures are expected during Key-Agent restarts and are logged
/// at debug level rather than propagated — a wallet that cannot export spans
/// must still be able to sign.
pub async fn run_drain_loop(
    client: KeyAgentClient,
    sink: Arc<dyn TelemetrySink>,
    interval: Duration,
    max_records: u32,
) -> ! {
    let batch_size = if max_records == 0 { DEFAULT_BATCH_SIZE } else { max_records };
    let mut ticker = tokio::time::interval(interval);
    // If an export overruns the interval, skip the missed ticks instead of
    // firing them back-to-back.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        ticker.tick().await;
        let stats = drain_until_empty(&client, sink.as_ref(), batch_size).await;
        if stats.dropped > 0 {
            tracing::warn!(
                dropped = stats.dropped,
                "key-agent telemetry buffer overflowed; increase the drain rate"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use oc_keyagent::{
        KeyAgentResponse,
        telemetry::{RecordKind, TelemetryLevel, TelemetryRecord},
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::UnixListener,
    };

    use super::*;

    fn record(seq: u64) -> TelemetryRecord {
        TelemetryRecord {
            seq,
            timestamp_ms: 1_700_000_000_000 + seq,
            level: TelemetryLevel::Info,
            kind: RecordKind::Event,
            target: "oc-keyagent::handler".to_string(),
            name: "sign_transaction".to_string(),
            span_id: None,
            parent_span_id: None,
            duration_ms: None,
            fields: vec![("chain_id".to_string(), "1".to_string())],
        }
    }

    fn ok_response(batch: &TelemetryBatch) -> KeyAgentResponse {
        let inner = DrainTelemetryResponse {
            batch_json: serde_json::to_string(batch).unwrap(),
            record_count: batch.records.len() as u32,
            dropped: batch.dropped,
        };
        KeyAgentResponse::ok(inner.encode_to_vec())
    }

    /// A mock Key-Agent that answers `responses` in order, one per connection,
    /// then repeats the final response forever.
    async fn spawn_mock(sock_path: String, responses: Vec<KeyAgentResponse>) {
        tokio::spawn(async move {
            let listener = UnixListener::bind(&sock_path).expect("bind mock keyagent");
            let mut i = 0usize;
            loop {
                let Ok((mut stream, _)) = listener.accept().await else { return };
                let mut len_buf = [0u8; 4];
                if stream.read_exact(&mut len_buf).await.is_err() {
                    continue;
                }
                let len = u32::from_be_bytes(len_buf) as usize;
                let mut req_buf = vec![0u8; len];
                if stream.read_exact(&mut req_buf).await.is_err() {
                    continue;
                }

                let resp = responses.get(i).or_else(|| responses.last()).cloned();
                i += 1;
                let Some(resp) = resp else { return };

                let bytes = resp.encode_to_vec();
                let _ = stream.write_all(&(bytes.len() as u32).to_be_bytes()).await;
                let _ = stream.write_all(&bytes).await;
                let _ = stream.flush().await;
            }
        });
        // Let the listener bind before the first connect.
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    fn temp_sock(dir: &tempfile::TempDir, name: &str) -> String {
        dir.path().join(name).to_string_lossy().to_string()
    }

    #[tokio::test]
    async fn drain_once_decodes_a_batch() {
        let dir = tempfile::tempdir().unwrap();
        let sock = temp_sock(&dir, "ka.sock");
        let batch = TelemetryBatch { records: vec![record(0), record(1)], dropped: 3 };
        spawn_mock(sock.clone(), vec![ok_response(&batch)]).await;

        let got = drain_once(&KeyAgentClient::new(&sock), 16).await.expect("drain");
        assert_eq!(got.records.len(), 2);
        assert_eq!(got.dropped, 3);
        assert_eq!(got.records[0].name, "sign_transaction");
    }

    #[tokio::test]
    async fn drain_once_on_an_empty_buffer_yields_an_empty_batch() {
        let dir = tempfile::tempdir().unwrap();
        let sock = temp_sock(&dir, "ka.sock");
        spawn_mock(sock.clone(), vec![ok_response(&TelemetryBatch::default())]).await;

        let got = drain_once(&KeyAgentClient::new(&sock), 16).await.expect("drain");
        assert!(got.is_empty());
    }

    #[tokio::test]
    async fn drain_once_surfaces_a_key_agent_error() {
        let dir = tempfile::tempdir().unwrap();
        let sock = temp_sock(&dir, "ka.sock");
        spawn_mock(sock.clone(), vec![KeyAgentResponse::error("telemetry encode: boom")]).await;

        let err = drain_once(&KeyAgentClient::new(&sock), 16).await.unwrap_err();
        assert!(matches!(err, NetAgentError::KeyAgentError(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn drain_once_rejects_a_malformed_batch_json() {
        let dir = tempfile::tempdir().unwrap();
        let sock = temp_sock(&dir, "ka.sock");
        let bad = DrainTelemetryResponse {
            batch_json: "{not json".to_string(),
            record_count: 0,
            dropped: 0,
        };
        spawn_mock(sock.clone(), vec![KeyAgentResponse::ok(bad.encode_to_vec())]).await;

        let err = drain_once(&KeyAgentClient::new(&sock), 16).await.unwrap_err();
        assert!(matches!(err, NetAgentError::KeyAgentWire(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn drain_once_reports_an_unreachable_key_agent() {
        let dir = tempfile::tempdir().unwrap();
        let sock = temp_sock(&dir, "missing.sock");
        let err = drain_once(&KeyAgentClient::new(&sock), 16).await.unwrap_err();
        assert!(matches!(err, NetAgentError::Io(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn drain_until_empty_exports_and_counts_drops() {
        let dir = tempfile::tempdir().unwrap();
        let sock = temp_sock(&dir, "ka.sock");
        let batch = TelemetryBatch { records: vec![record(0)], dropped: 7 };
        spawn_mock(sock.clone(), vec![ok_response(&batch)]).await;

        let sink = MemorySink::new();
        let stats = drain_until_empty(&KeyAgentClient::new(&sock), &sink, 16).await;

        assert_eq!(stats.exported, 1);
        assert_eq!(stats.dropped, 7);
        assert_eq!(stats.failures, 0);
        assert_eq!(sink.records().len(), 1);
        assert_eq!(sink.dropped(), 7);
    }

    #[tokio::test]
    async fn drain_until_empty_stops_on_a_short_batch() {
        // The mock repeats its last response forever. A short batch (1 record
        // for a request of 16) must end the burst after exactly one round
        // trip, otherwise this test would loop MAX_CATCHUP_ROUNDS times.
        let dir = tempfile::tempdir().unwrap();
        let sock = temp_sock(&dir, "ka.sock");
        let batch = TelemetryBatch { records: vec![record(0)], dropped: 0 };
        spawn_mock(sock.clone(), vec![ok_response(&batch)]).await;

        let sink = MemorySink::new();
        let stats = drain_until_empty(&KeyAgentClient::new(&sock), &sink, 16).await;
        assert_eq!(stats.exported, 1, "a short batch means the ring is empty");
    }

    #[tokio::test]
    async fn drain_until_empty_is_bounded_when_batches_stay_full() {
        // Every response is a *full* batch, so the loop always believes more
        // is pending. MAX_CATCHUP_ROUNDS must stop it anyway.
        let dir = tempfile::tempdir().unwrap();
        let sock = temp_sock(&dir, "ka.sock");
        let batch = TelemetryBatch { records: vec![record(0), record(1)], dropped: 0 };
        spawn_mock(sock.clone(), vec![ok_response(&batch)]).await;

        let sink = MemorySink::new();
        let stats = drain_until_empty(&KeyAgentClient::new(&sock), &sink, 2).await;
        assert_eq!(stats.exported, u64::from(MAX_CATCHUP_ROUNDS) * 2);
    }

    #[tokio::test]
    async fn drain_until_empty_records_a_transport_failure() {
        let dir = tempfile::tempdir().unwrap();
        let sock = temp_sock(&dir, "missing.sock");
        let sink = MemorySink::new();
        let stats = drain_until_empty(&KeyAgentClient::new(&sock), &sink, 16).await;

        assert_eq!(stats.failures, 1);
        assert_eq!(stats.exported, 0);
        assert!(sink.records().is_empty());
    }

    #[test]
    fn memory_sink_accumulates_across_batches() {
        let sink = MemorySink::new();
        sink.export(&TelemetryBatch { records: vec![record(0)], dropped: 1 }).unwrap();
        sink.export(&TelemetryBatch { records: vec![record(1)], dropped: 2 }).unwrap();
        assert_eq!(sink.records().len(), 2);
        assert_eq!(sink.dropped(), 3);
    }

    #[test]
    fn stdout_sink_handles_an_empty_batch() {
        StdoutSink.export(&TelemetryBatch::default()).expect("empty batch must export cleanly");
    }
}
