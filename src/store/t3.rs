//! T3 Code collector state: materialized projects, threads, runs and approvals.
//!
//! The collector is the only writer of these tables. Every incremental step is
//! committed together with the generated events, delivery rows, source cursor
//! and collector checkpoint, so a crash can never advance the cursor past an
//! event whose state was not applied.

use anyhow::{Context, Result};
use base64::Engine;
use chrono::{Duration as ChronoDuration, Utc};
use rusqlite::{OptionalExtension, Row, params, types::Value as SqlValue};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::repository::{IngestOutcome, NewEvent, Repository, ingest_event_in_tx};
use crate::{
    mcp::event_catalog,
    util::{format_rfc3339, now_rfc3339},
};

const T3_SOURCE: &str = "t3";
const T3_COLLECTOR: &str = "t3";
const CHUNK_KIND_SNAPSHOT: &str = "snapshot";
const CHUNK_KIND_RAW_PART: &str = "raw_part";
const DEFAULT_STAGE_TTL_SECS: u64 = 3600;
const MAX_ASSEMBLED_SNAPSHOT_BYTES: usize = 128 * 1024 * 1024;

const THREAD_COLUMNS: &str =
    "environment_id, thread_id, project_id, title, branch, deleted_at, updated_at";
const RUN_COLUMNS: &str = "environment_id, run_id, thread_id, project_id, ordinal, \
     provider_instance_id, status, last_turn_status, checkpoint_id, error, summary, \
     requested_at, started_at, completed_at, updated_at";

/// A materialized T3 Code project.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct T3Project {
    /// Environment (T3 Code installation) id.
    pub environment_id: String,
    /// T3 project id.
    pub project_id: String,
    /// Display title.
    pub title: String,
    /// Workspace root.
    pub workspace_root: String,
    /// Deletion time, when known.
    pub deleted_at: Option<String>,
    /// Last upstream update time.
    pub updated_at: String,
}

/// A materialized T3 Code thread.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct T3Thread {
    /// Environment id.
    pub environment_id: String,
    /// Thread id.
    pub thread_id: String,
    /// Owning project.
    pub project_id: String,
    /// Thread title.
    pub title: String,
    /// Git branch, when the thread has one.
    pub branch: Option<String>,
    /// Deletion time, when known.
    pub deleted_at: Option<String>,
    /// Last upstream update time.
    pub updated_at: String,
}

/// A materialized T3 Code run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct T3Run {
    /// Environment id.
    pub environment_id: String,
    /// Run id.
    pub run_id: String,
    /// Thread that owns the run.
    pub thread_id: String,
    /// Project that owns the thread.
    pub project_id: String,
    /// Per-thread run ordinal.
    pub ordinal: i64,
    /// Provider instance selected for the run.
    pub provider_instance_id: Option<String>,
    /// Run lifecycle status (`running`, `completed`, `failed`, ...).
    pub status: String,
    /// Last observed provider turn / attempt / root node status.
    pub last_turn_status: Option<String>,
    /// Checkpoint captured by the run.
    pub checkpoint_id: Option<String>,
    /// Failure message extracted from the run, a failed turn item or a node.
    pub error: Option<String>,
    /// Short human-readable summary.
    pub summary: Option<String>,
    /// Queue request time.
    pub requested_at: Option<String>,
    /// Start time.
    pub started_at: Option<String>,
    /// Completion time.
    pub completed_at: Option<String>,
    /// Last time this materialized row changed.
    pub updated_at: String,
}

/// A T3 run plus its derived pending approval count.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct T3RunDetail {
    /// The run row.
    #[serde(flatten)]
    pub run: T3Run,
    /// Number of pending approvals attached to the run.
    pub pending_approvals_count: i64,
}

/// A materialized T3 runtime request / approval.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct T3Approval {
    /// Environment id.
    pub environment_id: String,
    /// Runtime request id, used as the approval id.
    pub approval_id: String,
    /// Owning thread.
    pub thread_id: String,
    /// Owning run.
    pub run_id: String,
    /// Node that raised the request.
    pub node_id: Option<String>,
    /// Request kind (`command`, `file-change`, `user_input`, ...).
    pub kind: String,
    /// `pending`, `resolved`, `expired` or `cancelled`.
    pub status: String,
    /// Human-readable summary.
    pub summary: Option<String>,
    /// Resolution decision, serialized as JSON when it is not a plain string.
    pub decision: Option<String>,
    /// Creation time.
    pub created_at: String,
    /// Resolution time, when resolved.
    pub resolved_at: Option<String>,
    /// Last time this materialized row changed.
    pub updated_at: String,
}

/// Filter for `get_t3_approvals`.
#[derive(Debug, Clone, Default)]
pub struct T3ApprovalQuery {
    /// Restrict to one environment.
    pub environment_id: Option<String>,
    /// Restrict to one project (joined through `t3_threads`).
    pub project_id: Option<String>,
    /// Restrict to one thread.
    pub thread_id: Option<String>,
    /// Exact status, or `all`. `None` means `pending`.
    pub status: Option<String>,
    /// Maximum rows.
    pub limit: i64,
}

/// A first-start snapshot of the current T3 projections.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct T3Snapshot {
    /// Current projects.
    pub projects: Vec<T3Project>,
    /// Current threads.
    pub threads: Vec<T3Thread>,
    /// Current runs.
    pub runs: Vec<T3Run>,
    /// Current runtime requests, including pending approvals.
    pub approvals: Vec<T3Approval>,
}

impl T3Snapshot {
    /// Whether the snapshot contains no projections at all.
    pub fn is_empty(&self) -> bool {
        self.projects.is_empty()
            && self.threads.is_empty()
            && self.runs.is_empty()
            && self.approvals.is_empty()
    }

    /// Append every projection from `other`.
    pub fn extend(&mut self, other: T3Snapshot) {
        self.projects.extend(other.projects);
        self.threads.extend(other.threads);
        self.runs.extend(other.runs);
        self.approvals.extend(other.approvals);
    }
}

/// An edge-local snapshot that has not been acknowledged by the hub yet.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EdgePendingSnapshot {
    /// Environment the snapshot belongs to.
    pub environment_id: String,
    /// Stable id used to correlate chunked uploads.
    pub snapshot_id: String,
    /// Upstream sequence covered by the snapshot.
    pub max_sequence: i64,
    /// Materialized projections captured at `max_sequence`.
    pub snapshot: T3Snapshot,
    /// When the pending snapshot was first captured.
    pub created_at: String,
}

/// Failure while finalizing a chunked snapshot.
#[derive(Debug, Error)]
pub enum SnapshotCommitError {
    /// One or more chunks in `0..total_chunks` were never staged.
    #[error(
        "snapshot `{snapshot_id}` is missing chunks: expected {expected} chunks, found {found}"
    )]
    MissingChunks {
        /// Snapshot id from the commit request.
        snapshot_id: String,
        /// Number of chunks the commit declared.
        expected: usize,
        /// Number of chunks actually staged.
        found: usize,
    },
    /// A staged chunk was not a valid snapshot or did not match the environment.
    #[error("invalid staged snapshot: {0}")]
    Invalid(String),
    /// A database error occurred while finalizing the snapshot.
    #[error(transparent)]
    Store(#[from] anyhow::Error),
}

/// A project deletion without a full project payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct T3ProjectDeletion {
    /// Project being deleted.
    pub project_id: String,
    /// Deletion time.
    pub deleted_at: String,
    /// Last update time.
    pub updated_at: String,
}

/// An auxiliary status update for an existing run.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct T3RunPatch {
    /// Run being updated.
    pub run_id: String,
    /// Last observed provider turn / attempt / node status.
    pub last_turn_status: String,
    /// Update time.
    pub updated_at: String,
}

/// Everything written by one collector step, committed atomically.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct T3WriteBatch {
    /// Environment id.
    pub environment_id: String,
    /// Upstream `orchestration_events.sequence` consumed by this step.
    pub sequence: i64,
    /// Full project upsert.
    pub project: Option<T3Project>,
    /// Project deletion marker.
    pub project_deleted: Option<T3ProjectDeletion>,
    /// Full thread upsert.
    pub thread: Option<T3Thread>,
    /// Full run upsert.
    pub run: Option<T3Run>,
    /// Auxiliary run status update.
    pub run_patch: Option<T3RunPatch>,
    /// Full approval upsert.
    pub approval: Option<T3Approval>,
    /// Events derived from this upstream event.
    pub events: Vec<NewEvent>,
}

/// Result of applying one collector step.
#[derive(Debug, Clone, Default)]
pub struct T3ApplyOutcome {
    /// Stored events (existing rows for duplicates).
    pub events: Vec<IngestOutcome>,
    /// Delivery rows created across all events.
    pub deliveries_created: usize,
    /// Number of events that already existed.
    pub duplicates: usize,
}

impl Repository {
    /// Record the first-start snapshot and move both cursors to `max_sequence`.
    ///
    /// No event is emitted: runs that already completed before the collector
    /// started must not wake a webhook receiver.
    pub fn apply_t3_snapshot(
        &self,
        environment_id: &str,
        snapshot: &T3Snapshot,
        max_sequence: i64,
    ) -> Result<()> {
        let mut conn = self.lock_connection();
        let tx = conn.transaction()?;
        apply_t3_snapshot_in_tx(&tx, environment_id, snapshot, max_sequence)?;
        tx.commit()?;
        Ok(())
    }

    /// Apply a snapshot and clear the edge-local pending snapshot in one
    /// transaction.
    ///
    /// The edge calls this only after the hub acknowledged the snapshot. The
    /// cursor and the pending row therefore move together: a crash either
    /// keeps both (retry the same snapshot) or commits both (resume after
    /// `max_sequence`).
    pub fn apply_t3_snapshot_and_clear_pending(
        &self,
        environment_id: &str,
        snapshot: &T3Snapshot,
        max_sequence: i64,
    ) -> Result<()> {
        let mut conn = self.lock_connection();
        let tx = conn.transaction()?;
        apply_t3_snapshot_in_tx(&tx, environment_id, snapshot, max_sequence)?;
        tx.execute(
            "DELETE FROM edge_pending_snapshots WHERE environment_id = ?1",
            params![environment_id],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Read the edge-local pending snapshot for one environment.
    pub fn get_edge_pending_snapshot(
        &self,
        environment_id: &str,
    ) -> Result<Option<EdgePendingSnapshot>> {
        let row: Option<(String, String, i64, String, String)> = self
            .lock_connection()
            .query_row(
                "SELECT environment_id, snapshot_id, max_sequence, snapshot_json, created_at \
                 FROM edge_pending_snapshots WHERE environment_id = ?1",
                params![environment_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()?;
        let Some((environment_id, snapshot_id, max_sequence, snapshot_json, created_at)) = row
        else {
            return Ok(None);
        };
        let snapshot = serde_json::from_str(&snapshot_json).with_context(|| {
            format!("invalid pending snapshot JSON for environment `{environment_id}`")
        })?;
        Ok(Some(EdgePendingSnapshot {
            environment_id,
            snapshot_id,
            max_sequence,
            snapshot,
            created_at,
        }))
    }

    /// Persist (or replace) the edge-local pending snapshot.
    pub fn save_edge_pending_snapshot(&self, pending: &EdgePendingSnapshot) -> Result<()> {
        let snapshot_json = serde_json::to_string(&pending.snapshot)?;
        self.lock_connection().execute(
            "INSERT INTO edge_pending_snapshots \
                 (environment_id, snapshot_id, max_sequence, snapshot_json, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5) \
             ON CONFLICT (environment_id) DO UPDATE SET \
                 snapshot_id = excluded.snapshot_id, \
                 max_sequence = excluded.max_sequence, \
                 snapshot_json = excluded.snapshot_json, \
                 created_at = excluded.created_at",
            params![
                pending.environment_id,
                pending.snapshot_id,
                pending.max_sequence,
                snapshot_json,
                pending.created_at
            ],
        )?;
        Ok(())
    }

    /// Stage one entity chunk of a chunked snapshot on the hub.
    pub fn stage_edge_snapshot_chunk(
        &self,
        environment_id: &str,
        snapshot_id: &str,
        chunk_index: usize,
        snapshot: &T3Snapshot,
    ) -> Result<()> {
        self.stage_edge_snapshot_chunk_with_ttl(
            environment_id,
            snapshot_id,
            chunk_index,
            snapshot,
            DEFAULT_STAGE_TTL_SECS,
        )
    }

    /// Stage one entity chunk and prune abandoned stages older than `ttl_secs`.
    pub fn stage_edge_snapshot_chunk_with_ttl(
        &self,
        environment_id: &str,
        snapshot_id: &str,
        chunk_index: usize,
        snapshot: &T3Snapshot,
        ttl_secs: u64,
    ) -> Result<()> {
        let snapshot_json = serde_json::to_string(snapshot)?;
        self.stage_edge_snapshot_row_with_ttl(
            environment_id,
            snapshot_id,
            chunk_index,
            CHUNK_KIND_SNAPSHOT,
            &snapshot_json,
            ttl_secs,
        )
    }

    /// Stage one Base64-encoded JSON byte slice of a snapshot and prune
    /// abandoned stages older than `ttl_secs`.
    pub fn stage_edge_snapshot_part_with_ttl(
        &self,
        environment_id: &str,
        snapshot_id: &str,
        chunk_index: usize,
        data_b64: &str,
        ttl_secs: u64,
    ) -> Result<()> {
        self.stage_edge_snapshot_row_with_ttl(
            environment_id,
            snapshot_id,
            chunk_index,
            CHUNK_KIND_RAW_PART,
            data_b64,
            ttl_secs,
        )
    }

    fn stage_edge_snapshot_row_with_ttl(
        &self,
        environment_id: &str,
        snapshot_id: &str,
        chunk_index: usize,
        chunk_kind: &str,
        payload: &str,
        ttl_secs: u64,
    ) -> Result<()> {
        let now = Utc::now();
        let now_str = format_rfc3339(now);
        let cutoff = stage_cutoff_rfc3339(now, ttl_secs);
        let mut conn = self.lock_connection();
        let tx = conn.transaction()?;
        tx.execute(
            "DELETE FROM edge_snapshot_stages \
             WHERE (environment_id, snapshot_id) IN ( \
                 SELECT environment_id, snapshot_id \
                 FROM edge_snapshot_stages \
                 GROUP BY environment_id, snapshot_id \
                 HAVING MAX(created_at) < ?1 \
             )",
            params![cutoff],
        )?;
        tx.execute(
            "INSERT INTO edge_snapshot_stages \
                 (environment_id, snapshot_id, chunk_index, chunk_kind, snapshot_json, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
             ON CONFLICT (environment_id, snapshot_id, chunk_index) DO UPDATE SET \
                 chunk_kind = excluded.chunk_kind, \
                 snapshot_json = excluded.snapshot_json, \
                 created_at = excluded.created_at",
            params![
                environment_id,
                snapshot_id,
                chunk_index as i64,
                chunk_kind,
                payload,
                now_str
            ],
        )?;
        tx.execute(
            "UPDATE edge_snapshot_stages SET created_at = ?3 \
             WHERE environment_id = ?1 AND snapshot_id = ?2",
            params![environment_id, snapshot_id, now_str],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Delete staged snapshot chunks older than `cutoff` (canonical UTC RFC 3339).
    pub fn prune_expired_edge_snapshot_stages(&self, cutoff: &str) -> Result<usize> {
        let deleted = self.lock_connection().execute(
            "DELETE FROM edge_snapshot_stages WHERE created_at < ?1",
            params![cutoff],
        )?;
        Ok(deleted)
    }

    /// Count currently staged snapshot chunk rows (exposed for tests and metrics).
    pub fn count_edge_snapshot_stages(&self) -> Result<usize> {
        let count: i64 = self.lock_connection().query_row(
            "SELECT COUNT(*) FROM edge_snapshot_stages",
            [],
            |row| row.get(0),
        )?;
        Ok(count.max(0) as usize)
    }

    /// Atomically merge every staged chunk and apply the snapshot.
    ///
    /// Missing chunks are reported as [`SnapshotCommitError::MissingChunks`]
    /// before any projection or cursor is touched.
    pub fn apply_t3_snapshot_chunks(
        &self,
        environment_id: &str,
        snapshot_id: &str,
        max_sequence: i64,
        total_chunks: usize,
    ) -> Result<(), SnapshotCommitError> {
        self.apply_t3_snapshot_chunks_with_ttl(
            environment_id,
            snapshot_id,
            max_sequence,
            total_chunks,
            DEFAULT_STAGE_TTL_SECS,
        )
    }

    /// Atomically merge every staged chunk, apply the snapshot, and prune
    /// abandoned stages older than `ttl_secs`.
    pub fn apply_t3_snapshot_chunks_with_ttl(
        &self,
        environment_id: &str,
        snapshot_id: &str,
        max_sequence: i64,
        total_chunks: usize,
        ttl_secs: u64,
    ) -> Result<(), SnapshotCommitError> {
        if total_chunks == 0 {
            return Err(SnapshotCommitError::Invalid(
                "total_chunks must be greater than zero".into(),
            ));
        }

        let cutoff = stage_cutoff_rfc3339(Utc::now(), ttl_secs);
        let mut conn = self.lock_connection();
        let tx = conn.transaction().map_err(anyhow::Error::from)?;

        let staged = {
            let mut stmt = tx
                .prepare(
                    "SELECT chunk_index, chunk_kind, snapshot_json FROM edge_snapshot_stages \
                     WHERE environment_id = ?1 AND snapshot_id = ?2 \
                       AND chunk_index >= 0 AND chunk_index < ?3 \
                     ORDER BY chunk_index ASC",
                )
                .map_err(anyhow::Error::from)?;
            let rows = stmt
                .query_map(
                    params![environment_id, snapshot_id, total_chunks as i64],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                        ))
                    },
                )
                .map_err(anyhow::Error::from)?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .map_err(anyhow::Error::from)?
        };

        if staged.len() != total_chunks {
            return Err(SnapshotCommitError::MissingChunks {
                snapshot_id: snapshot_id.to_string(),
                expected: total_chunks,
                found: staged.len(),
            });
        }
        for (expected, (index, _, _)) in staged.iter().enumerate() {
            if *index != expected as i64 {
                return Err(SnapshotCommitError::MissingChunks {
                    snapshot_id: snapshot_id.to_string(),
                    expected: total_chunks,
                    found: staged.len(),
                });
            }
        }

        let kind = staged[0].1.as_str();
        if staged.iter().any(|(_, k, _)| k != kind) {
            return Err(SnapshotCommitError::Invalid(
                "mixed snapshot chunk kinds are not allowed".into(),
            ));
        }

        let merged = match kind {
            CHUNK_KIND_SNAPSHOT => {
                let mut snapshot = T3Snapshot::default();
                for (_, _, snapshot_json) in staged {
                    let chunk: T3Snapshot = serde_json::from_str(&snapshot_json)
                        .map_err(|error| SnapshotCommitError::Invalid(error.to_string()))?;
                    snapshot.extend(chunk);
                }
                snapshot
            }
            CHUNK_KIND_RAW_PART => {
                let mut assembled = Vec::new();
                for (_, _, data_b64) in staged {
                    let bytes = base64::engine::general_purpose::STANDARD
                        .decode(&data_b64)
                        .map_err(|error| SnapshotCommitError::Invalid(error.to_string()))?;
                    if assembled.len().saturating_add(bytes.len()) > MAX_ASSEMBLED_SNAPSHOT_BYTES {
                        return Err(SnapshotCommitError::Invalid(
                            "assembled snapshot exceeds size limit".into(),
                        ));
                    }
                    assembled.extend_from_slice(&bytes);
                }
                serde_json::from_slice::<T3Snapshot>(&assembled)
                    .map_err(|error| SnapshotCommitError::Invalid(error.to_string()))?
            }
            other => {
                return Err(SnapshotCommitError::Invalid(format!(
                    "unknown snapshot chunk kind `{other}`"
                )));
            }
        };

        validate_snapshot_environment(environment_id, &merged)
            .map_err(|error| SnapshotCommitError::Invalid(error.to_string()))?;

        apply_t3_snapshot_in_tx(&tx, environment_id, &merged, max_sequence)
            .map_err(SnapshotCommitError::Store)?;
        tx.execute(
            "DELETE FROM edge_snapshot_stages \
             WHERE (environment_id = ?1 AND snapshot_id = ?2) \
                OR (environment_id, snapshot_id) IN ( \
                    SELECT environment_id, snapshot_id \
                    FROM edge_snapshot_stages \
                    GROUP BY environment_id, snapshot_id \
                    HAVING MAX(created_at) < ?3 \
                )",
            params![environment_id, snapshot_id, cutoff],
        )
        .map_err(anyhow::Error::from)?;
        tx.commit().map_err(anyhow::Error::from)?;
        Ok(())
    }

    /// Apply one upstream event's state changes, derived events, cursor and
    /// checkpoint in a single transaction.
    pub fn apply_t3_batch(&self, batch: &T3WriteBatch) -> Result<T3ApplyOutcome> {
        validate_t3_batch(batch)?;

        let mut conn = self.lock_connection();
        let tx = conn.transaction()?;
        let outcome = apply_t3_batch_in_tx(&tx, batch)?;
        tx.commit()?;
        Ok(outcome)
    }

    /// Apply several upstream batches in one transaction.
    ///
    /// This is the hub-side edge ingest path: a single request either applies
    /// every batch (state, events, deliveries and cursors) or none of them.
    pub fn apply_t3_batches(&self, batches: &[T3WriteBatch]) -> Result<T3ApplyOutcome> {
        for batch in batches {
            validate_t3_batch(batch)?;
        }

        let mut conn = self.lock_connection();
        let tx = conn.transaction()?;
        let mut outcome = T3ApplyOutcome::default();
        for batch in batches {
            let applied = apply_t3_batch_in_tx(&tx, batch)?;
            outcome.deliveries_created += applied.deliveries_created;
            outcome.duplicates += applied.duplicates;
            outcome.events.extend(applied.events);
        }
        tx.commit()?;
        Ok(outcome)
    }

    /// Last fully processed T3 `orchestration_events.sequence`, restored from
    /// `source_cursors` and then `collector_checkpoints`.
    pub fn get_t3_cursor(&self, environment_id: &str) -> Result<Option<i64>> {
        let conn = self.lock_connection();
        let cursor: Option<String> = conn
            .query_row(
                "SELECT cursor FROM source_cursors WHERE host = ?1 AND source = ?2",
                params![environment_id, T3_SOURCE],
                |row| row.get(0),
            )
            .optional()?;
        let raw = match cursor {
            Some(value) => Some(value),
            None => conn
                .query_row(
                    "SELECT watermark FROM collector_checkpoints \
                     WHERE collector = ?1 AND scope = ?2",
                    params![T3_COLLECTOR, environment_id],
                    |row| row.get::<_, Option<String>>(0),
                )
                .optional()?
                .flatten(),
        };
        match raw {
            Some(value) => value
                .parse::<i64>()
                .map(Some)
                .with_context(|| format!("invalid T3 cursor `{value}` for `{environment_id}`")),
            None => Ok(None),
        }
    }

    /// Fetch one run and its pending approval count.
    pub fn get_t3_run(
        &self,
        run_id: &str,
        environment_id: Option<&str>,
    ) -> Result<Option<T3RunDetail>> {
        let conn = self.lock_connection();
        let run = match environment_id {
            Some(environment_id) => {
                let sql = format!(
                    "SELECT {RUN_COLUMNS} FROM t3_runs \
                     WHERE environment_id = ?1 AND run_id = ?2 \
                     ORDER BY updated_at DESC LIMIT 1"
                );
                conn.query_row(&sql, params![environment_id, run_id], map_run)
                    .optional()?
            }
            None => {
                let sql = format!(
                    "SELECT {RUN_COLUMNS} FROM t3_runs WHERE run_id = ?1 \
                     ORDER BY updated_at DESC LIMIT 1"
                );
                conn.query_row(&sql, params![run_id], map_run).optional()?
            }
        };
        let Some(run) = run else {
            return Ok(None);
        };
        let pending: i64 = conn.query_row(
            "SELECT COUNT(*) FROM t3_approvals \
             WHERE environment_id = ?1 AND run_id = ?2 AND status = 'pending'",
            params![run.environment_id, run.run_id],
            |row| row.get(0),
        )?;
        Ok(Some(T3RunDetail {
            run,
            pending_approvals_count: pending,
        }))
    }

    /// Fetch one materialized approval.
    pub fn get_t3_approval(
        &self,
        environment_id: &str,
        approval_id: &str,
    ) -> Result<Option<T3Approval>> {
        let sql = "SELECT environment_id, approval_id, thread_id, run_id, node_id, kind, \
                          status, summary, decision, created_at, resolved_at, updated_at \
                   FROM t3_approvals WHERE environment_id = ?1 AND approval_id = ?2";
        Ok(self
            .lock_connection()
            .query_row(sql, params![environment_id, approval_id], map_approval)
            .optional()?)
    }

    /// List materialized approvals, joined to threads for project filtering.
    pub fn list_t3_approvals(&self, query: &T3ApprovalQuery) -> Result<Vec<T3Approval>> {
        let mut sql = "SELECT a.environment_id, a.approval_id, a.thread_id, a.run_id, \
                              a.node_id, a.kind, a.status, a.summary, a.decision, \
                              a.created_at, a.resolved_at, a.updated_at \
                       FROM t3_approvals a \
                       LEFT JOIN t3_threads t \
                         ON t.environment_id = a.environment_id \
                        AND t.thread_id = a.thread_id \
                       WHERE 1 = 1"
            .to_string();
        let mut args: Vec<SqlValue> = Vec::new();
        if let Some(environment_id) = &query.environment_id {
            sql.push_str(" AND a.environment_id = ?");
            args.push(SqlValue::Text(environment_id.clone()));
        }
        if let Some(project_id) = &query.project_id {
            sql.push_str(" AND t.project_id = ?");
            args.push(SqlValue::Text(project_id.clone()));
        }
        if let Some(thread_id) = &query.thread_id {
            sql.push_str(" AND a.thread_id = ?");
            args.push(SqlValue::Text(thread_id.clone()));
        }
        let status = query.status.as_deref().unwrap_or("pending");
        if status != "all" {
            sql.push_str(" AND a.status = ?");
            args.push(SqlValue::Text(status.to_string()));
        }
        sql.push_str(" ORDER BY a.created_at DESC, a.approval_id ASC LIMIT ?");
        args.push(SqlValue::Integer(query.limit.max(1)));

        let conn = self.lock_connection();
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(args.iter()), map_approval)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Fetch a materialized thread.
    pub fn get_t3_thread(&self, environment_id: &str, thread_id: &str) -> Result<Option<T3Thread>> {
        let sql = format!(
            "SELECT {THREAD_COLUMNS} FROM t3_threads \
             WHERE environment_id = ?1 AND thread_id = ?2"
        );
        Ok(self
            .lock_connection()
            .query_row(&sql, params![environment_id, thread_id], map_thread)
            .optional()?)
    }

    /// Most recent run for a thread, used to attach approvals that only name a
    /// node.
    pub fn latest_t3_run_for_thread(
        &self,
        environment_id: &str,
        thread_id: &str,
    ) -> Result<Option<T3Run>> {
        let sql = format!(
            "SELECT {RUN_COLUMNS} FROM t3_runs \
             WHERE environment_id = ?1 AND thread_id = ?2 \
             ORDER BY ordinal DESC, updated_at DESC LIMIT 1"
        );
        Ok(self
            .lock_connection()
            .query_row(&sql, params![environment_id, thread_id], map_run)
            .optional()?)
    }
}

fn stage_cutoff_rfc3339(now: chrono::DateTime<Utc>, ttl_secs: u64) -> String {
    let cutoff = i64::try_from(ttl_secs)
        .ok()
        .and_then(ChronoDuration::try_seconds)
        .and_then(|delta| now.checked_sub_signed(delta))
        .unwrap_or(chrono::DateTime::<Utc>::UNIX_EPOCH)
        .max(chrono::DateTime::<Utc>::UNIX_EPOCH);
    format_rfc3339(cutoff)
}

pub(crate) fn validate_t3_batch(batch: &T3WriteBatch) -> Result<()> {
    if batch.environment_id.trim().is_empty() {
        anyhow::bail!("T3 batch environment_id must not be empty");
    }
    if batch.sequence < 0 {
        anyhow::bail!("T3 batch sequence must not be negative");
    }
    if let Some(project) = &batch.project
        && project.environment_id != batch.environment_id
    {
        anyhow::bail!("T3 batch project environment_id mismatch");
    }
    if let Some(thread) = &batch.thread
        && thread.environment_id != batch.environment_id
    {
        anyhow::bail!("T3 batch thread environment_id mismatch");
    }
    if let Some(run) = &batch.run
        && run.environment_id != batch.environment_id
    {
        anyhow::bail!("T3 batch run environment_id mismatch");
    }
    if let Some(approval) = &batch.approval
        && approval.environment_id != batch.environment_id
    {
        anyhow::bail!("T3 batch approval environment_id mismatch");
    }
    for event in &batch.events {
        event_catalog::validate_payload(&event.kind, &event.payload)
            .map_err(|error| anyhow::anyhow!(error))?;
        if event.kind.starts_with("t3.") {
            let payload_environment = event
                .payload
                .get("environment_id")
                .and_then(serde_json::Value::as_str);
            if payload_environment != Some(batch.environment_id.as_str()) {
                anyhow::bail!(
                    "event `{}` environment_id does not match its batch",
                    event.kind
                );
            }
        }
    }
    Ok(())
}

fn validate_snapshot_environment(environment_id: &str, snapshot: &T3Snapshot) -> Result<()> {
    if environment_id.trim().is_empty() {
        anyhow::bail!("snapshot environment_id must not be empty");
    }
    for project in &snapshot.projects {
        if project.environment_id != environment_id {
            anyhow::bail!("snapshot project environment_id mismatch");
        }
    }
    for thread in &snapshot.threads {
        if thread.environment_id != environment_id {
            anyhow::bail!("snapshot thread environment_id mismatch");
        }
    }
    for run in &snapshot.runs {
        if run.environment_id != environment_id {
            anyhow::bail!("snapshot run environment_id mismatch");
        }
    }
    for approval in &snapshot.approvals {
        if approval.environment_id != environment_id {
            anyhow::bail!("snapshot approval environment_id mismatch");
        }
    }
    Ok(())
}

fn apply_t3_snapshot_in_tx(
    tx: &rusqlite::Transaction<'_>,
    environment_id: &str,
    snapshot: &T3Snapshot,
    max_sequence: i64,
) -> Result<()> {
    validate_snapshot_environment(environment_id, snapshot)?;
    for project in &snapshot.projects {
        upsert_project(tx, project)?;
    }
    for thread in &snapshot.threads {
        upsert_thread(tx, thread)?;
    }
    for run in &snapshot.runs {
        upsert_run(tx, run)?;
    }
    for approval in &snapshot.approvals {
        upsert_approval(tx, approval)?;
    }
    set_cursor(tx, environment_id, max_sequence)?;
    Ok(())
}

fn current_cursor(tx: &rusqlite::Transaction<'_>, environment_id: &str) -> Result<Option<i64>> {
    let raw: Option<String> = tx
        .query_row(
            "SELECT cursor FROM source_cursors WHERE host = ?1 AND source = ?2",
            params![environment_id, T3_SOURCE],
            |row| row.get(0),
        )
        .optional()?;
    match raw {
        Some(value) => value
            .parse::<i64>()
            .map(Some)
            .with_context(|| format!("invalid T3 cursor `{value}` for `{environment_id}`")),
        None => Ok(None),
    }
}

fn apply_t3_batch_in_tx(
    tx: &rusqlite::Transaction<'_>,
    batch: &T3WriteBatch,
) -> Result<T3ApplyOutcome> {
    // A retried or reordered batch must never roll projections or the cursor
    // backwards. A legitimate re-snapshot is an explicit reset through the
    // snapshot path, not an incremental batch.
    if let Some(current) = current_cursor(tx, &batch.environment_id)?
        && batch.sequence <= current
    {
        return Ok(T3ApplyOutcome::default());
    }

    if let Some(project) = &batch.project {
        upsert_project(tx, project)?;
    }
    if let Some(deletion) = &batch.project_deleted {
        tx.execute(
            "INSERT INTO t3_projects \
                 (environment_id, project_id, title, workspace_root, deleted_at, updated_at) \
             VALUES (?1, ?2, '', '', ?3, ?4) \
             ON CONFLICT (environment_id, project_id) DO UPDATE SET \
                 deleted_at = excluded.deleted_at, \
                 updated_at = excluded.updated_at",
            params![
                batch.environment_id,
                deletion.project_id,
                deletion.deleted_at,
                deletion.updated_at
            ],
        )?;
    }
    if let Some(thread) = &batch.thread {
        upsert_thread(tx, thread)?;
    }
    if let Some(run) = &batch.run {
        upsert_run(tx, run)?;
    }
    if let Some(patch) = &batch.run_patch {
        tx.execute(
            "UPDATE t3_runs SET last_turn_status = ?3, updated_at = ?4 \
             WHERE environment_id = ?1 AND run_id = ?2",
            params![
                batch.environment_id,
                patch.run_id,
                patch.last_turn_status,
                patch.updated_at
            ],
        )?;
    }
    if let Some(approval) = &batch.approval {
        upsert_approval(tx, approval)?;
    }

    let ingested_at = now_rfc3339();
    let mut outcome = T3ApplyOutcome::default();
    for event in &batch.events {
        let stored = ingest_event_in_tx(tx, event.clone(), &ingested_at)?;
        outcome.deliveries_created += stored.deliveries_created;
        if stored.duplicate {
            outcome.duplicates += 1;
        }
        outcome.events.push(stored);
    }

    set_cursor(tx, &batch.environment_id, batch.sequence)?;
    Ok(outcome)
}

fn upsert_project(tx: &rusqlite::Transaction<'_>, project: &T3Project) -> Result<()> {
    tx.execute(
        "INSERT INTO t3_projects \
             (environment_id, project_id, title, workspace_root, deleted_at, updated_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
         ON CONFLICT (environment_id, project_id) DO UPDATE SET \
             title = excluded.title, \
             workspace_root = excluded.workspace_root, \
             deleted_at = excluded.deleted_at, \
             updated_at = excluded.updated_at",
        params![
            project.environment_id,
            project.project_id,
            project.title,
            project.workspace_root,
            project.deleted_at,
            project.updated_at
        ],
    )?;
    Ok(())
}

fn upsert_thread(tx: &rusqlite::Transaction<'_>, thread: &T3Thread) -> Result<()> {
    tx.execute(
        "INSERT INTO t3_threads \
             (environment_id, thread_id, project_id, title, branch, deleted_at, updated_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) \
         ON CONFLICT (environment_id, thread_id) DO UPDATE SET \
             project_id = excluded.project_id, \
             title = excluded.title, \
             branch = excluded.branch, \
             deleted_at = excluded.deleted_at, \
             updated_at = excluded.updated_at",
        params![
            thread.environment_id,
            thread.thread_id,
            thread.project_id,
            thread.title,
            thread.branch,
            thread.deleted_at,
            thread.updated_at
        ],
    )?;
    Ok(())
}

fn upsert_run(tx: &rusqlite::Transaction<'_>, run: &T3Run) -> Result<()> {
    tx.execute(
        "INSERT INTO t3_runs \
             (environment_id, run_id, thread_id, project_id, ordinal, provider_instance_id, \
              status, last_turn_status, checkpoint_id, error, summary, requested_at, \
              started_at, completed_at, updated_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15) \
         ON CONFLICT (environment_id, run_id) DO UPDATE SET \
             thread_id = excluded.thread_id, \
             project_id = excluded.project_id, \
             ordinal = excluded.ordinal, \
             provider_instance_id = excluded.provider_instance_id, \
             status = excluded.status, \
             last_turn_status = excluded.last_turn_status, \
             checkpoint_id = excluded.checkpoint_id, \
             error = excluded.error, \
             summary = excluded.summary, \
             requested_at = excluded.requested_at, \
             started_at = excluded.started_at, \
             completed_at = excluded.completed_at, \
             updated_at = excluded.updated_at",
        params![
            run.environment_id,
            run.run_id,
            run.thread_id,
            run.project_id,
            run.ordinal,
            run.provider_instance_id,
            run.status,
            run.last_turn_status,
            run.checkpoint_id,
            run.error,
            run.summary,
            run.requested_at,
            run.started_at,
            run.completed_at,
            run.updated_at
        ],
    )?;
    Ok(())
}

fn upsert_approval(tx: &rusqlite::Transaction<'_>, approval: &T3Approval) -> Result<()> {
    tx.execute(
        "INSERT INTO t3_approvals \
             (environment_id, approval_id, thread_id, run_id, node_id, kind, status, \
              summary, decision, created_at, resolved_at, updated_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12) \
         ON CONFLICT (environment_id, approval_id) DO UPDATE SET \
             thread_id = excluded.thread_id, \
             run_id = excluded.run_id, \
             node_id = excluded.node_id, \
             kind = excluded.kind, \
             status = excluded.status, \
             summary = excluded.summary, \
             decision = excluded.decision, \
             created_at = excluded.created_at, \
             resolved_at = excluded.resolved_at, \
             updated_at = excluded.updated_at",
        params![
            approval.environment_id,
            approval.approval_id,
            approval.thread_id,
            approval.run_id,
            approval.node_id,
            approval.kind,
            approval.status,
            approval.summary,
            approval.decision,
            approval.created_at,
            approval.resolved_at,
            approval.updated_at
        ],
    )?;
    Ok(())
}

fn set_cursor(tx: &rusqlite::Transaction<'_>, environment_id: &str, sequence: i64) -> Result<()> {
    let now = now_rfc3339();
    let cursor = sequence.to_string();
    tx.execute(
        "INSERT INTO source_cursors (host, source, cursor, updated_at) \
         VALUES (?1, ?2, ?3, ?4) \
         ON CONFLICT (host, source) DO UPDATE SET \
             cursor = excluded.cursor, updated_at = excluded.updated_at",
        params![environment_id, T3_SOURCE, cursor, now],
    )?;
    tx.execute(
        "INSERT INTO collector_checkpoints (collector, scope, etag, watermark, updated_at) \
         VALUES (?1, ?2, NULL, ?3, ?4) \
         ON CONFLICT (collector, scope) DO UPDATE SET \
             etag = NULL, watermark = excluded.watermark, updated_at = excluded.updated_at",
        params![T3_COLLECTOR, environment_id, cursor, now],
    )?;
    Ok(())
}

fn map_thread(row: &Row<'_>) -> rusqlite::Result<T3Thread> {
    Ok(T3Thread {
        environment_id: row.get(0)?,
        thread_id: row.get(1)?,
        project_id: row.get(2)?,
        title: row.get(3)?,
        branch: row.get(4)?,
        deleted_at: row.get(5)?,
        updated_at: row.get(6)?,
    })
}

fn map_run(row: &Row<'_>) -> rusqlite::Result<T3Run> {
    Ok(T3Run {
        environment_id: row.get(0)?,
        run_id: row.get(1)?,
        thread_id: row.get(2)?,
        project_id: row.get(3)?,
        ordinal: row.get(4)?,
        provider_instance_id: row.get(5)?,
        status: row.get(6)?,
        last_turn_status: row.get(7)?,
        checkpoint_id: row.get(8)?,
        error: row.get(9)?,
        summary: row.get(10)?,
        requested_at: row.get(11)?,
        started_at: row.get(12)?,
        completed_at: row.get(13)?,
        updated_at: row.get(14)?,
    })
}

fn map_approval(row: &Row<'_>) -> rusqlite::Result<T3Approval> {
    Ok(T3Approval {
        environment_id: row.get(0)?,
        approval_id: row.get(1)?,
        thread_id: row.get(2)?,
        run_id: row.get(3)?,
        node_id: row.get(4)?,
        kind: row.get(5)?,
        status: row.get(6)?,
        summary: row.get(7)?,
        decision: row.get(8)?,
        created_at: row.get(9)?,
        resolved_at: row.get(10)?,
        updated_at: row.get(11)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_run(environment_id: &str, status: &str) -> T3Run {
        T3Run {
            environment_id: environment_id.into(),
            run_id: "run-1".into(),
            thread_id: "thread-1".into(),
            project_id: "project-1".into(),
            ordinal: 1,
            provider_instance_id: None,
            status: status.into(),
            last_turn_status: None,
            checkpoint_id: None,
            error: None,
            summary: None,
            requested_at: None,
            started_at: None,
            completed_at: None,
            updated_at: "2026-11-16T02:00:00.000Z".into(),
        }
    }

    #[test]
    fn stale_batch_is_a_noop() {
        let repo = Repository::open_in_memory().unwrap();
        let environment_id = "env-stale";
        let first = T3WriteBatch {
            environment_id: environment_id.into(),
            sequence: 5,
            run: Some(sample_run(environment_id, "completed")),
            ..Default::default()
        };
        repo.apply_t3_batch(&first).unwrap();

        let stale = T3WriteBatch {
            environment_id: environment_id.into(),
            sequence: 3,
            run: Some(sample_run(environment_id, "running")),
            ..Default::default()
        };
        let outcome = repo.apply_t3_batch(&stale).unwrap();
        assert!(outcome.events.is_empty());
        assert_eq!(
            repo.get_t3_run("run-1", Some(environment_id))
                .unwrap()
                .unwrap()
                .run
                .status,
            "completed"
        );
        assert_eq!(repo.get_t3_cursor(environment_id).unwrap(), Some(5));
    }

    #[test]
    fn chunk_commit_requires_every_chunk_before_applying() {
        let repo = Repository::open_in_memory().unwrap();
        let environment_id = "env-chunks";
        let first = T3Snapshot {
            projects: vec![T3Project {
                environment_id: environment_id.into(),
                project_id: "project-1".into(),
                title: "Project".into(),
                workspace_root: "/repo".into(),
                deleted_at: None,
                updated_at: "2026-11-16T02:00:00.000Z".into(),
            }],
            ..Default::default()
        };
        repo.stage_edge_snapshot_chunk(environment_id, "snap-1", 0, &first)
            .unwrap();

        let error = repo
            .apply_t3_snapshot_chunks(environment_id, "snap-1", 0, 2)
            .unwrap_err();
        assert!(matches!(
            error,
            SnapshotCommitError::MissingChunks {
                expected: 2,
                found: 1,
                ..
            }
        ));
        assert_eq!(repo.get_t3_cursor(environment_id).unwrap(), None);

        repo.stage_edge_snapshot_chunk(environment_id, "snap-1", 1, &T3Snapshot::default())
            .unwrap();
        repo.apply_t3_snapshot_chunks(environment_id, "snap-1", 0, 2)
            .unwrap();
        assert_eq!(repo.get_t3_cursor(environment_id).unwrap(), Some(0));
        assert_eq!(repo.count_edge_snapshot_stages().unwrap(), 0);
    }

    #[test]
    fn raw_parts_reassemble_oversized_entity_and_reject_mixed_kinds() {
        let repo = Repository::open_in_memory().unwrap();
        let environment_id = "env-raw-parts";
        let mut run = sample_run(environment_id, "failed");
        run.error = Some("x".repeat(4_000));
        let snapshot = T3Snapshot {
            runs: vec![run.clone()],
            ..Default::default()
        };
        let bytes = serde_json::to_vec(&snapshot).unwrap();
        let mid = bytes.len() / 2;
        let part0 = base64::engine::general_purpose::STANDARD.encode(&bytes[..mid]);
        let part1 = base64::engine::general_purpose::STANDARD.encode(&bytes[mid..]);

        repo.stage_edge_snapshot_part_with_ttl(environment_id, "snap-raw", 0, &part0, 3600)
            .unwrap();
        repo.stage_edge_snapshot_part_with_ttl(environment_id, "snap-raw", 1, &part1, 3600)
            .unwrap();
        repo.apply_t3_snapshot_chunks_with_ttl(environment_id, "snap-raw", 42, 2, 3600)
            .unwrap();

        let stored = repo
            .get_t3_run("run-1", Some(environment_id))
            .unwrap()
            .expect("run stored");
        assert_eq!(stored.run.error.as_deref(), run.error.as_deref());
        assert_eq!(repo.get_t3_cursor(environment_id).unwrap(), Some(42));
        assert_eq!(repo.count_edge_snapshot_stages().unwrap(), 0);

        repo.stage_edge_snapshot_chunk_with_ttl(
            environment_id,
            "snap-mixed",
            0,
            &T3Snapshot::default(),
            3600,
        )
        .unwrap();
        repo.stage_edge_snapshot_part_with_ttl(environment_id, "snap-mixed", 1, &part1, 3600)
            .unwrap();
        let error = repo
            .apply_t3_snapshot_chunks_with_ttl(environment_id, "snap-mixed", 43, 2, 3600)
            .unwrap_err();
        assert!(matches!(error, SnapshotCommitError::Invalid(_)));
    }

    #[test]
    fn expired_abandoned_stages_are_pruned_without_touching_fresh_stages() {
        let repo = Repository::open_in_memory().unwrap();
        repo.stage_edge_snapshot_chunk_with_ttl(
            "env-stale-stage",
            "snap-abandoned",
            0,
            &T3Snapshot::default(),
            3600,
        )
        .unwrap();
        let old_timestamp = format_rfc3339(Utc::now() - ChronoDuration::seconds(120));
        repo.lock_connection()
            .execute(
                "UPDATE edge_snapshot_stages SET created_at = ?1 WHERE snapshot_id = 'snap-abandoned'",
                params![old_timestamp],
            )
            .unwrap();

        repo.stage_edge_snapshot_chunk_with_ttl(
            "env-active-stage",
            "snap-fresh",
            0,
            &T3Snapshot::default(),
            60,
        )
        .unwrap();
        assert_eq!(
            repo.count_edge_snapshot_stages().unwrap(),
            1,
            "staging a fresh chunk must prune the expired abandoned chunk while keeping the fresh one"
        );

        let remaining_id: String = repo
            .lock_connection()
            .query_row(
                "SELECT snapshot_id FROM edge_snapshot_stages LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(remaining_id, "snap-fresh");

        // An active multi-chunk upload whose earlier chunk is older than TTL
        // must keep all chunks alive while subsequent chunks arrive within TTL.
        repo.stage_edge_snapshot_chunk_with_ttl(
            "env-active-stage",
            "snap-fresh",
            1,
            &T3Snapshot::default(),
            60,
        )
        .unwrap();
        let active_old = format_rfc3339(Utc::now() - ChronoDuration::seconds(120));
        repo.lock_connection()
            .execute(
                "UPDATE edge_snapshot_stages SET created_at = ?1 \
                 WHERE snapshot_id = 'snap-fresh' AND chunk_index = 0",
                params![active_old],
            )
            .unwrap();
        repo.stage_edge_snapshot_chunk_with_ttl(
            "env-active-stage",
            "snap-fresh",
            2,
            &T3Snapshot {
                projects: vec![T3Project {
                    environment_id: "env-active-stage".into(),
                    project_id: "p-active".into(),
                    title: "Active".into(),
                    workspace_root: "/repo".into(),
                    deleted_at: None,
                    updated_at: "2026-11-16T02:00:00.000Z".into(),
                }],
                ..Default::default()
            },
            60,
        )
        .unwrap();
        assert_eq!(
            repo.count_edge_snapshot_stages().unwrap(),
            3,
            "active multi-chunk upload must retain earlier chunks"
        );
        repo.apply_t3_snapshot_chunks_with_ttl("env-active-stage", "snap-fresh", 7, 3, 60)
            .unwrap();
        assert_eq!(repo.get_t3_cursor("env-active-stage").unwrap(), Some(7));
        assert_eq!(repo.count_edge_snapshot_stages().unwrap(), 0);
    }

    #[test]
    fn extreme_stage_ttl_values_do_not_panic() {
        let repo = Repository::open_in_memory().unwrap();
        for (index, ttl) in [i64::MAX as u64, u64::MAX].into_iter().enumerate() {
            let snapshot_id = format!("snap-huge-{index}");
            repo.stage_edge_snapshot_chunk_with_ttl(
                "env-huge-ttl",
                &snapshot_id,
                0,
                &T3Snapshot::default(),
                ttl,
            )
            .unwrap();
            repo.apply_t3_snapshot_chunks_with_ttl(
                "env-huge-ttl",
                &snapshot_id,
                index as i64,
                1,
                ttl,
            )
            .unwrap();
        }
        assert_eq!(repo.get_t3_cursor("env-huge-ttl").unwrap(), Some(1));
    }
}
