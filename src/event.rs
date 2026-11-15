//! Event domain types, the ingestion entry point, and the dispatcher wake-up
//! signal.
//!
//! `tokio::sync::broadcast` is a wake-up hint only: it is not a queue and no
//! state lives in it. The durable queue is the `deliveries` table.

use std::sync::Arc;

use anyhow::{Result, bail};
use serde_json::{Value, json};
use tokio::sync::broadcast;

use crate::mcp::event_catalog;
use crate::store::{Event, IngestOutcome, NewEvent, Repository};

/// A delivered webhook body (design §2.4).
#[derive(Debug, Clone)]
pub struct EventEnvelope<'a> {
    /// The durable event.
    pub event: &'a Event,
    /// Cursor watermark; Phase 1 has no replay, so this is always `null`.
    pub cursor: Option<String>,
}

impl EventEnvelope<'_> {
    /// Serialize the envelope with the exact field names required by MCP
    /// Events.
    pub fn to_json(&self) -> Value {
        json!({
            "eventId": self.event.id,
            "name": self.event.kind,
            "timestamp": self.event.occurred_at,
            "data": self.event.payload,
            "cursor": self.cursor,
        })
    }
}

/// Wake-up bus for the delivery dispatcher.
#[derive(Clone, Debug)]
pub struct EventBus {
    tx: broadcast::Sender<()>,
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

impl EventBus {
    /// Create a bus with a small broadcast buffer. A lagging receiver only
    /// misses a wake-up hint; the periodic poll still drains the queue.
    pub fn new() -> Self {
        let (tx, _rx) = broadcast::channel(64);
        Self { tx }
    }

    /// Signal that new work may be available.
    pub fn notify(&self) {
        let _ = self.tx.send(());
    }

    /// Subscribe to wake-ups.
    pub fn subscribe(&self) -> broadcast::Receiver<()> {
        self.tx.subscribe()
    }
}

/// Validates and persists events, then wakes the dispatcher.
#[derive(Clone)]
pub struct IngestService {
    repo: Arc<Repository>,
    bus: EventBus,
}

impl IngestService {
    /// Create an ingestion service.
    pub fn new(repo: Arc<Repository>, bus: EventBus) -> Self {
        Self { repo, bus }
    }

    /// Validate an event and persist it together with its delivery rows.
    ///
    /// The event row and every `deliveries` row are written by a single
    /// repository transaction before the wake-up is sent.
    pub fn ingest(&self, new: NewEvent) -> Result<IngestOutcome> {
        event_catalog::validate_payload(&new.kind, &new.payload)
            .map_err(|error| anyhow::anyhow!(error))?;
        if let Some(id) = &new.id
            && (id.is_empty() || id.len() > 200)
        {
            bail!("event id must be between 1 and 200 characters");
        }
        let outcome = self.repo.ingest_event(new)?;
        if !outcome.duplicate {
            self.bus.notify();
        }
        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::NewEvent;
    use base64::Engine;
    use serde_json::json;

    /// Synthesize a valid webhook secret at runtime so no secret literal is
    /// committed to the repository.
    fn test_secret() -> String {
        format!(
            "whsec_{}",
            base64::engine::general_purpose::STANDARD.encode([0x11u8; 32])
        )
    }

    fn service() -> (IngestService, Arc<Repository>) {
        let repo = Arc::new(Repository::open_in_memory().unwrap());
        (IngestService::new(repo.clone(), EventBus::new()), repo)
    }

    #[test]
    fn invalid_payloads_are_rejected_before_storage() {
        let (service, repo) = service();
        let error = service
            .ingest(NewEvent {
                id: Some("evt_bad".into()),
                source: None,
                kind: "t3.run.completed".into(),
                payload: json!({"environment_id": "linux-main"}),
                occurred_at: None,
            })
            .unwrap_err();
        assert!(error.to_string().contains("invalid"));
        assert!(repo.get_event("evt_bad").unwrap().is_none());
    }

    #[test]
    fn valid_events_are_stored_and_delivery_rows_created() {
        let (service, repo) = service();
        repo.upsert_subscription(crate::store::NewSubscription {
            id: "sub_1".into(),
            principal: "local".into(),
            event_name: "t3.run.failed".into(),
            arguments: json!({"environment_id": "linux-main"}),
            filter_hash: "hash".into(),
            callback_url: "https://receiver.example.com/hook".into(),
            secret: test_secret(),
            refresh_before: None,
        })
        .unwrap();

        let outcome = service
            .ingest(NewEvent {
                id: Some("evt_ok".into()),
                source: None,
                kind: "t3.run.failed".into(),
                payload: json!({
                    "environment_id": "linux-main",
                    "project_id": "lnako",
                    "thread_id": "thread-42",
                    "run_id": "run-102",
                    "summary": "failed",
                    "error": "test failure"
                }),
                occurred_at: None,
            })
            .unwrap();
        assert_eq!(outcome.deliveries_created, 1);
        assert!(!outcome.duplicate);
    }

    #[test]
    fn envelope_uses_mcp_events_field_names() {
        let event = Event {
            id: "evt_1".into(),
            sequence: 1,
            source: "t3".into(),
            kind: "t3.run.completed".into(),
            payload: json!({"environment_id": "linux-main"}),
            occurred_at: "2026-11-16T01:00:00.000Z".into(),
        };
        let envelope = EventEnvelope {
            event: &event,
            cursor: None,
        };
        let json = envelope.to_json();
        assert_eq!(json["eventId"], "evt_1");
        assert_eq!(json["name"], "t3.run.completed");
        assert_eq!(json["data"]["environment_id"], "linux-main");
        assert!(json["cursor"].is_null());
    }
}
