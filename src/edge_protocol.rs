//! Authenticated Edge -> Hub T3 forwarding protocol.
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
use sha2::Sha256;
use url::Url;

use crate::{
    store::{T3Snapshot, T3WriteBatch},
    util::constant_time_eq,
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
    let mut url = base.clone();
    let base_path = url.path().trim_end_matches('/');
    url.set_path(&format!("{base_path}{EDGE_INGEST_PATH}"));
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
