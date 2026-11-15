//! T3 Code collector state: materialized projects, threads, runs and approvals.
//!
//! The collector is the only writer of these tables. Every incremental step is
//! committed together with the generated events, delivery rows, source cursor
//! and collector checkpoint, so a crash can never advance the cursor past an
//! event whose state was not applied.

use anyhow::{Context, Result};
use rusqlite::{OptionalExtension, Row, params, types::Value as SqlValue};
use serde::{Deserialize, Serialize};

use super::repository::{IngestOutcome, NewEvent, Repository, ingest_event_in_tx};
use crate::{mcp::event_catalog, util::now_rfc3339};

const T3_SOURCE: &str = "t3";
const T3_COLLECTOR: &str = "t3";

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
#[derive(Debug, Clone, Default)]
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

/// A project deletion without a full project payload.
#[derive(Debug, Clone)]
pub struct T3ProjectDeletion {
    /// Project being deleted.
    pub project_id: String,
    /// Deletion time.
    pub deleted_at: String,
    /// Last update time.
    pub updated_at: String,
}

/// An auxiliary status update for an existing run.
#[derive(Debug, Clone)]
pub struct T3RunPatch {
    /// Run being updated.
    pub run_id: String,
    /// Last observed provider turn / attempt / node status.
    pub last_turn_status: String,
    /// Update time.
    pub updated_at: String,
}

/// Everything written by one collector step, committed atomically.
#[derive(Debug, Clone, Default)]
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
        for project in &snapshot.projects {
            upsert_project(&tx, project)?;
        }
        for thread in &snapshot.threads {
            upsert_thread(&tx, thread)?;
        }
        for run in &snapshot.runs {
            upsert_run(&tx, run)?;
        }
        for approval in &snapshot.approvals {
            upsert_approval(&tx, approval)?;
        }
        set_cursor(&tx, environment_id, max_sequence)?;
        tx.commit()?;
        Ok(())
    }

    /// Apply one upstream event's state changes, derived events, cursor and
    /// checkpoint in a single transaction.
    pub fn apply_t3_batch(&self, batch: &T3WriteBatch) -> Result<T3ApplyOutcome> {
        for event in &batch.events {
            event_catalog::validate_payload(&event.kind, &event.payload)
                .map_err(|error| anyhow::anyhow!(error))?;
        }

        let mut conn = self.lock_connection();
        let tx = conn.transaction()?;
        if let Some(project) = &batch.project {
            upsert_project(&tx, project)?;
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
            upsert_thread(&tx, thread)?;
        }
        if let Some(run) = &batch.run {
            upsert_run(&tx, run)?;
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
            upsert_approval(&tx, approval)?;
        }

        let ingested_at = now_rfc3339();
        let mut outcome = T3ApplyOutcome::default();
        for event in &batch.events {
            let stored = ingest_event_in_tx(&tx, event.clone(), &ingested_at)?;
            outcome.deliveries_created += stored.deliveries_created;
            if stored.duplicate {
                outcome.duplicates += 1;
            }
            outcome.events.push(stored);
        }

        set_cursor(&tx, &batch.environment_id, batch.sequence)?;
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
