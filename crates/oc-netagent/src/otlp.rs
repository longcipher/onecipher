//! OTLP/HTTP exporter sink for the telemetry drain (P1 3.1).
//!
//! Drains records out of the Key-Agent's bounded ring buffer and ships them to
//! an OpenTelemetry Collector over OTLP/HTTP with JSON encoding — the wire
//! format Jaeger, Grafana Tempo and the OpenTelemetry Collector all accept at
//! `/v1/logs`.
//!
//! # Why hand-rolled JSON and not `opentelemetry-otlp`
//!
//! The OTLP protobuf JSON mapping is small and stable. Implementing just the
//! slice we need (logs with string attributes) avoids dragging the whole
//! `opentelemetry` / `opentelemetry-otlp` dependency tree into `oc-netagent`,
//! which already carries `hpx` for the EVM JSON-RPC client.
//!
//! # Fire-and-forget
//!
//! [`OtlpSink::export`] builds the payload synchronously, then hands the HTTP
//! POST to a background tokio task so a slow or unreachable collector can never
//! stall the drain loop. If no tokio runtime is available the batch is dropped
//! with a warning — telemetry must never break the signing path.

use std::sync::Arc;

use oc_keyagent::telemetry::{RecordKind, TelemetryBatch, TelemetryLevel};
use serde_json::{Value, json};

use crate::telemetry_drain::TelemetrySink;

/// Default collector endpoint when none is configured.
const DEFAULT_ENDPOINT: &str = "http://127.0.0.1:4318";

/// OTLP/HTTP JSON exporter configuration.
pub struct OtlpSinkConfig {
    /// Collector endpoint (scheme://host:port, no path). Default
    /// `http://127.0.0.1:4318`.
    pub endpoint: String,
}

impl Default for OtlpSinkConfig {
    fn default() -> Self {
        Self { endpoint: DEFAULT_ENDPOINT.to_string() }
    }
}

/// Exports drained telemetry to an OpenTelemetry Collector over OTLP/HTTP JSON.
pub struct OtlpSink {
    config: OtlpSinkConfig,
    client: Arc<hpx::Client>,
}

impl OtlpSink {
    /// Construct a sink targeting the configured collector.
    pub fn new(config: OtlpSinkConfig) -> Self {
        Self { config, client: Arc::new(hpx::Client::new()) }
    }

    /// The POST URL for the OTLP logs endpoint.
    fn logs_url(&self) -> String {
        format!("{}/v1/logs", self.config.endpoint.trim_end_matches('/'))
    }
}

impl Default for OtlpSink {
    fn default() -> Self {
        Self::new(OtlpSinkConfig::default())
    }
}

impl TelemetrySink for OtlpSink {
    fn export(&self, batch: &TelemetryBatch) -> Result<(), String> {
        let payload = build_otlp_logs_json(batch);
        let body = serde_json::to_string(&payload).map_err(|e| e.to_string())?;
        let url = self.logs_url();
        let client = Arc::clone(&self.client);

        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            // Fire-and-forget: the drain loop must never block on the
            // collector, so failures are logged here instead of surfaced.
            // Dropping the JoinHandle detaches the task, which keeps running.
            drop(handle.spawn(async move {
                match client
                    .post(&url)
                    .header("content-type", "application/json")
                    .body(body)
                    .send()
                    .await
                {
                    Ok(resp) if !resp.status().is_success() => {
                        tracing::warn!(status = %resp.status(), "OTLP export returned non-success status");
                    }
                    Ok(_) => {}
                    Err(e) => tracing::warn!(error = %e, "OTLP export transport failed"),
                }
            }));
            Ok(())
        } else {
            // Outside a tokio runtime (e.g. a sync caller); dropping the batch
            // is the safe degradation — telemetry is best-effort.
            tracing::warn!(records = batch.records.len(), "OTLP export skipped: no tokio runtime");
            Ok(())
        }
    }
}

/// Map a telemetry severity to the OTLP Logs `SeverityNumber`.
fn severity_number(level: TelemetryLevel) -> i64 {
    match level {
        TelemetryLevel::Trace => 1,
        TelemetryLevel::Debug => 5,
        TelemetryLevel::Info => 9,
        TelemetryLevel::Warn => 13,
        TelemetryLevel::Error => 17,
    }
}

/// Build the OTLP Logs JSON payload for a drained batch.
///
/// Pure and unit-testable. Each [`TelemetryRecord`] becomes one `logRecord`
/// with the record name as the body and every captured field as a string
/// attribute. Timestamps are nanoseconds-since-epoch, serialized as JSON
/// strings (u64 can exceed i64; the OTLP JSON mapping accepts string ints).
pub(crate) fn build_otlp_logs_json(batch: &TelemetryBatch) -> Value {
    let log_records: Vec<Value> = batch
        .records
        .iter()
        .map(|record| {
            let mut attributes = vec![
                json!({ "key": "seq", "value": { "stringValue": record.seq.to_string() } }),
                json!({ "key": "target", "value": { "stringValue": record.target } }),
                json!({ "key": "event_kind", "value": { "stringValue": kind_name(record.kind) } }),
            ];
            if let Some(span_id) = record.span_id {
                attributes.push(
                    json!({ "key": "span_id", "value": { "stringValue": format!("{span_id:x}") } }),
                );
            }
            if let Some(parent_span_id) = record.parent_span_id {
                attributes.push(json!({
                    "key": "parent_span_id",
                    "value": { "stringValue": format!("{parent_span_id:x}") },
                }));
            }
            if let Some(duration_ms) = record.duration_ms {
                attributes.push(json!({
                    "key": "duration_ms",
                    "value": { "stringValue": duration_ms.to_string() },
                }));
            }
            for (key, value) in &record.fields {
                attributes.push(json!({ "key": key, "value": { "stringValue": value } }));
            }

            let time_nano = (record.timestamp_ms * 1_000_000).to_string();
            json!({
                "timeUnixNano": time_nano,
                "observedTimeUnixNano": time_nano,
                "severityNumber": severity_number(record.level),
                "severityText": record.level.to_string(),
                "body": { "stringValue": record.name },
                "attributes": attributes,
            })
        })
        .collect();

    json!({
        "resourceLogs": [
            {
                "resource": {
                    "attributes": [
                        { "key": "service.name", "value": { "stringValue": "onecipher-keyagent" } },
                    ],
                },
                "scopeLogs": [
                    {
                        "scope": {},
                        "logRecords": log_records,
                    },
                ],
            },
        ],
    })
}

/// Stable snake_case name for a record kind.
fn kind_name(kind: RecordKind) -> &'static str {
    match kind {
        RecordKind::SpanOpen => "span_open",
        RecordKind::SpanClose => "span_close",
        RecordKind::Event => "event",
    }
}

#[cfg(test)]
mod tests {
    use oc_keyagent::telemetry::{RecordKind, TelemetryRecord};

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

    fn batch(records: Vec<TelemetryRecord>) -> TelemetryBatch {
        TelemetryBatch { records, dropped: 0 }
    }

    #[test]
    fn maps_severity_info() {
        let v = build_otlp_logs_json(&batch(vec![record(0)]));
        let lr = &v["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0];
        assert_eq!(lr["severityNumber"], 9);
        assert_eq!(lr["severityText"], "INFO");
        assert_eq!(lr["body"]["stringValue"], "sign_transaction");
    }

    #[test]
    fn maps_all_severities() {
        let cases = [
            (TelemetryLevel::Trace, 1, "TRACE"),
            (TelemetryLevel::Debug, 5, "DEBUG"),
            (TelemetryLevel::Info, 9, "INFO"),
            (TelemetryLevel::Warn, 13, "WARN"),
            (TelemetryLevel::Error, 17, "ERROR"),
        ];
        for (level, number, text) in cases {
            let mut r = record(0);
            r.level = level;
            let v = build_otlp_logs_json(&batch(vec![r]));
            let lr = &v["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0];
            assert_eq!(lr["severityNumber"], number, "for {text}");
            assert_eq!(lr["severityText"], text);
        }
    }

    #[test]
    fn includes_fields_as_string_attributes() {
        let v = build_otlp_logs_json(&batch(vec![record(0)]));
        let attrs = &v["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]["attributes"];
        let has_chain = attrs
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["key"] == "chain_id" && a["value"]["stringValue"] == "1");
        assert!(has_chain, "chain_id attribute missing: {attrs}");
    }

    #[test]
    fn encodes_span_ids_as_hex() {
        let mut r = record(0);
        r.span_id = Some(0xABCD);
        r.parent_span_id = Some(0x1234);
        let v = build_otlp_logs_json(&batch(vec![r]));
        let attrs = &v["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]["attributes"];
        let has_span = attrs
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["key"] == "span_id" && a["value"]["stringValue"] == "abcd");
        let has_parent = attrs
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["key"] == "parent_span_id" && a["value"]["stringValue"] == "1234");
        assert!(has_span, "span_id missing: {attrs}");
        assert!(has_parent, "parent_span_id missing: {attrs}");
    }

    #[test]
    fn timestamp_is_nanoseconds_string() {
        let v = build_otlp_logs_json(&batch(vec![record(0)]));
        let lr = &v["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0];
        assert_eq!(lr["timeUnixNano"], "1700000000000000000");
        assert_eq!(lr["observedTimeUnixNano"], "1700000000000000000");
    }

    #[test]
    fn empty_batch_produces_valid_shape() {
        let v = build_otlp_logs_json(&batch(vec![]));
        let records = &v["resourceLogs"][0]["scopeLogs"][0]["logRecords"];
        assert!(records.is_array());
        assert_eq!(records.as_array().unwrap().len(), 0);
    }

    #[test]
    fn record_kind_maps_to_snake_case() {
        assert_eq!(kind_name(RecordKind::SpanOpen), "span_open");
        assert_eq!(kind_name(RecordKind::SpanClose), "span_close");
        assert_eq!(kind_name(RecordKind::Event), "event");
    }

    #[test]
    fn export_outside_runtime_drops_gracefully() {
        // No tokio runtime in this (plain #[test]) thread: export must return
        // Ok without panicking or attempting I/O.
        let sink = OtlpSink::new(OtlpSinkConfig { endpoint: "http://127.0.0.1:1".to_string() });
        let result = sink.export(&batch(vec![record(0)]));
        assert!(result.is_ok());
    }
}
