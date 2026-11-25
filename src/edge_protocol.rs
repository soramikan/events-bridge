//! Authenticated Edge -> Hub forwarding protocol.
//!
//! The wire format is deliberately small and independent of the MCP surface:
//!
//! * `X-Edge-Id`, `X-Edge-Timestamp`, `X-Edge-Nonce` and
//!   `X-Edge-Signature: v1,<hex HMAC-SHA256>`.
//! * The signed bytes are `"{edge_id}.{timestamp}.{nonce}."` followed by the
//!   exact raw request body.
//! * The hub rejects a reused `(edge_id, nonce)` pair through the
//!   `edge_nonces` table.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

use crate::{
    store::{NewEvent, T3Snapshot, T3WriteBatch},
    util::{constant_time_eq, format_rfc3339},
};

/// Header carrying the edge identifier.
pub const HEADER_EDGE_ID: &str = "x-edge-id";
/// Header carrying the Unix timestamp used in the signature.
pub const HEADER_EDGE_TIMESTAMP: &str = "x-edge-timestamp";
/// Header carrying the per-request nonce.
pub const HEADER_EDGE_NONCE: &str = "x-edge-nonce";
/// Header carrying `v1,<hex HMAC-SHA256>`.
pub const HEADER_EDGE_SIGNATURE: &str = "x-edge-signature";

/// Path appended to `edge.hub_url`.
pub const EDGE_INGEST_PATH: &str = "/internal/edge/t3";
/// Path for signed Orca events.
pub const ORCA_EDGE_INGEST_PATH: &str = "/internal/edge/orca";

/// An Orca event reported by a host's Edge. The Hub derives the stored event
/// and its ID from this record, keeping free-form agent data out of the wire format.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrcaEdgeEvent {
    /// Stable installation label assigned in Edge configuration.
    pub environment_id: String,
    /// Orca conversation ID including its address prefix.
    pub session_id: String,
    /// Optional host-local Orca project ID.
    pub project_id: Option<String>,
    /// Event type.
    pub kind: OrcaEventKind,
    /// Orca's epoch-millisecond timestamp for the transition.
    pub occurred_at_ms: i64,
}

/// The Orca observations an Edge is allowed to ingest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrcaEventKind {
    /// The agent finished a turn.
    Completed,
    /// The agent failed a turn.
    Failed,
    /// The agent is waiting for a person's approval or input.
    ApprovalRequired,
}

impl OrcaEventKind {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Completed => "orca.session.completed",
            Self::Failed => "orca.session.failed",
            Self::ApprovalRequired => "orca.approval.required",
        }
    }

    pub const fn summary(self) -> &'static str {
        match self {
            Self::Completed => "An Orca agent finished a turn.",
            Self::Failed => "An Orca agent turn failed or was unexpectedly interrupted.",
            Self::ApprovalRequired => "An Orca agent is waiting for approval or input.",
        }
    }
}

impl OrcaEdgeEvent {
    pub(crate) fn validate(&self) -> Result<(), String> {
        if !valid_edge_token(&self.environment_id) {
            return Err("invalid Orca environment_id".into());
        }
        if !self
            .session_id
            .strip_prefix("orca_session_id:")
            .is_some_and(valid_edge_token)
        {
            return Err("invalid Orca session_id".into());
        }
        if self
            .project_id
            .as_deref()
            .is_some_and(|id| !valid_edge_token(id))
        {
            return Err("invalid Orca project_id".into());
        }
        if self.occurred_at_ms <= 0
            || chrono::DateTime::from_timestamp_millis(self.occurred_at_ms).is_none()
        {
            return Err("invalid Orca occurred_at_ms".into());
        }
        Ok(())
    }

    pub(crate) fn event_id(&self) -> String {
        let identity = serde_json::to_vec(&(
            &self.environment_id,
            &self.session_id,
            self.kind.name(),
            self.occurred_at_ms,
        ))
        .expect("event identity is serializable");
        format!("evt_orca_{}", hex::encode(Sha256::digest(identity)))
    }

    pub(crate) fn into_event(self) -> anyhow::Result<NewEvent> {
        let occurred_at = chrono::DateTime::from_timestamp_millis(self.occurred_at_ms)
            .ok_or_else(|| anyhow::anyhow!("invalid Orca occurred_at_ms"))?;
        let id = self.event_id();
        let requires_action = self.kind != OrcaEventKind::Completed;
        let mut payload = serde_json::json!({
            "environment_id": self.environment_id,
            "session_id": self.session_id,
            "summary": self.kind.summary(),
            "severity": if requires_action { "high" } else { "normal" },
            "requires_action": requires_action
        });
        if let Some(project_id) = self.project_id {
            payload["project_id"] = project_id.into();
        }
        Ok(NewEvent {
            id: Some(id),
            source: Some("orca".into()),
            kind: self.kind.name().into(),
            payload,
            occurred_at: Some(format_rfc3339(occurred_at)),
        })
    }
}

/// One authenticated edge ingest request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EdgeT3IngestRequest {
    /// First-start snapshot. No event is emitted.
    Snapshot {
        /// T3 environment id.
        environment_id: String,
        /// Upstream sequence covered by the snapshot.
        max_sequence: i64,
        /// Materialized projections.
        snapshot: T3Snapshot,
    },
    /// One chunk of a snapshot that is too large for a single request.
    SnapshotChunk {
        /// T3 environment id.
        environment_id: String,
        /// Stable id shared by every chunk and the commit.
        snapshot_id: String,
        /// Zero-based chunk index.
        chunk_index: usize,
        /// Projections carried by this chunk.
        snapshot: T3Snapshot,
    },
    /// One Base64-encoded JSON byte slice of a snapshot whose individual entity
    /// exceeds `edge.max_snapshot_chunk_bytes`.
    SnapshotPart {
        /// T3 environment id.
        environment_id: String,
        /// Stable id shared by every part and the commit.
        snapshot_id: String,
        /// Zero-based chunk index.
        chunk_index: usize,
        /// Standard Base64 encoding of one slice of the serialized snapshot.
        data: String,
    },
    /// Atomically finalize a chunked snapshot.
    SnapshotCommit {
        /// T3 environment id.
        environment_id: String,
        /// Stable id shared by every chunk and the commit.
        snapshot_id: String,
        /// Upstream sequence covered by the snapshot.
        max_sequence: i64,
        /// Number of chunks the hub must have staged.
        total_chunks: usize,
    },
    /// One or more incremental write batches.
    Batches {
        /// Batches applied in a single hub transaction.
        batches: Vec<T3WriteBatch>,
    },
}

/// Build the ingest endpoint URL from a validated hub base URL.
pub fn ingest_url(base: &Url) -> Url {
    edge_endpoint(base, EDGE_INGEST_PATH)
}

pub(crate) fn edge_endpoint(base: &Url, path: &str) -> Url {
    let mut url = base.clone();
    let base_path = url.path().trim_end_matches('/');
    url.set_path(&format!("{base_path}{path}"));
    url
}

/// Whether an edge id or nonce is acceptable.
///
/// Values are 1..=128 characters and contain no whitespace or control
/// characters, so they can be used verbatim in headers and log fields.
pub fn valid_edge_token(value: &str) -> bool {
    let length = value.chars().count();
    (1..=128).contains(&length)
        && !value
            .chars()
            .any(|ch| ch.is_whitespace() || ch.is_control())
}

/// Compute the `v1,<hex>` signature for one request.
pub fn sign(secret: &[u8], edge_id: &str, timestamp: i64, nonce: &str, body: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(format!("{edge_id}.{timestamp}.{nonce}.").as_bytes());
    mac.update(body);
    format!("v1,{}", hex::encode(mac.finalize().into_bytes()))
}

/// Verify a `v1,<hex>` signature in constant time.
pub fn verify(
    secret: &[u8],
    edge_id: &str,
    timestamp: i64,
    nonce: &str,
    body: &[u8],
    signature: &str,
) -> bool {
    let Some(encoded) = signature.strip_prefix("v1,") else {
        return false;
    };
    if encoded.len() != 64 || !encoded.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return false;
    }
    let Ok(expected) = hex::decode(encoded) else {
        return false;
    };
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(format!("{edge_id}.{timestamp}.{nonce}.").as_bytes());
    mac.update(body);
    let computed = mac.finalize().into_bytes();
    constant_time_eq(&computed, &expected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signatures_verify_and_reject_tampering() {
        let secret = b"shared-secret";
        let body = br#"{"type":"batches","batches":[]}"#;
        let signature = sign(secret, "edge-1", 1_700_000_000, "nonce-1", body);
        assert!(verify(
            secret,
            "edge-1",
            1_700_000_000,
            "nonce-1",
            body,
            &signature
        ));
        assert!(!verify(
            secret,
            "edge-2",
            1_700_000_000,
            "nonce-1",
            body,
            &signature
        ));
        assert!(!verify(
            secret,
            "edge-1",
            1_700_000_001,
            "nonce-1",
            body,
            &signature
        ));
        assert!(!verify(
            secret,
            "edge-1",
            1_700_000_000,
            "nonce-2",
            body,
            &signature
        ));
        assert!(!verify(
            secret,
            "edge-1",
            1_700_000_000,
            "nonce-1",
            br#"{"type":"batches","batches":[{}]}"#,
            &signature
        ));
        assert!(!verify(
            secret,
            "edge-1",
            1_700_000_000,
            "nonce-1",
            body,
            "v1,abcd"
        ));
        assert!(!verify(
            secret,
            "edge-1",
            1_700_000_000,
            "nonce-1",
            body,
            "v2,00"
        ));
    }

    #[test]
    fn edge_tokens_are_bounded_and_control_free() {
        assert!(valid_edge_token("edge-1"));
        assert!(valid_edge_token(&"a".repeat(128)));
        assert!(!valid_edge_token(""));
        assert!(!valid_edge_token(&"a".repeat(129)));
        assert!(!valid_edge_token("edge 1"));
        assert!(!valid_edge_token("edge\n1"));
    }

    #[test]
    fn ingest_url_appends_to_a_base_path() {
        let base = Url::parse("https://hub.example.com/base/").unwrap();
        assert_eq!(
            ingest_url(&base).as_str(),
            "https://hub.example.com/base/internal/edge/t3"
        );
        let root = Url::parse("http://127.0.0.1:8787").unwrap();
        assert_eq!(
            ingest_url(&root).as_str(),
            "http://127.0.0.1:8787/internal/edge/t3"
        );
    }
}
