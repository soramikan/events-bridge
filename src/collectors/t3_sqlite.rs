//! Read-only T3 Code SQLite collector.
//!
//! T3 Code 0.1.9 does not expose a cross-thread monotonic replay RPC, so the
//! collector follows the durable `orchestration_events` log directly. The T3
//! database is always opened with `SQLITE_OPEN_READ_ONLY` and
//! `PRAGMA query_only = ON`; this process never writes to it.
//!
//! On the first start (no saved cursor) the current projection tables are
//! materialized and the cursor jumps to `MAX(sequence)`. Completed historical
//! runs therefore never produce webhook deliveries. Later starts resume from
//! `source_cursors` / `collector_checkpoints` and replay every newer event.

use std::{
    fs,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use serde_json::Value;
use tokio_util::sync::CancellationToken;
use url::Url;

use super::t3_state::{T3Reducer, T3SourceEvent, extract_error, normalize_timestamp, run_summary};
use crate::{
    config::Config,
    event::EventBus,
    store::{Repository, T3Approval, T3Project, T3Run, T3Snapshot, T3Thread},
    util::now_rfc3339,
};

/// T3 collector settings resolved from the daemon configuration.
#[derive(Debug, Clone)]
pub struct T3CollectorSettings {
    /// Environment id used in every derived event.
    pub environment_id: String,
    /// T3 Code `statev2.sqlite` path.
    pub state_db_path: PathBuf,
    /// Optional web base URL for deep links.
    pub web_base_url: Option<Url>,
    /// Full polling fallback interval.
    pub poll_interval: Duration,
    /// Probe database/WAL metadata at a short interval.
    pub watch_wal: bool,
    /// Upstream events per query.
    pub batch_size: usize,
    /// Maximum characters kept in `error_excerpt` payloads.
    pub error_excerpt_max_chars: usize,
}

impl T3CollectorSettings {
    /// Resolve settings from the daemon configuration.
    pub fn from_config(config: &Config) -> Result<Self> {
        let t3 = &config.collectors.t3;
        let state_db_path = resolve_state_db_path(t3)?;
        let environment_id = resolve_environment_id(t3, &state_db_path)?;
        Self::from_parts(t3, &config.payload, state_db_path, environment_id)
    }

    /// Resolve settings, falling back to the OS host name when no environment
    /// id is configured and the sibling `environment-id` file is unavailable.
    ///
    /// The edge subcommand uses this so an explicit `edge.edge_id` is not
    /// required just to start. The hub-local collector keeps the strict
    /// [`Self::from_config`] behavior. When neither an environment id nor a
    /// usable OS host name is available, this fails instead of silently using
    /// a shared default that would collide across hosts.
    pub fn from_config_with_hostname_fallback(config: &Config) -> Result<Self> {
        Self::from_config_with_hostname_fallback_and_hostname(config, crate::util::os_hostname())
    }

    /// Testable variant of [`Self::from_config_with_hostname_fallback`].
    #[doc(hidden)]
    pub fn from_config_with_hostname_fallback_and_hostname(
        config: &Config,
        hostname: Option<String>,
    ) -> Result<Self> {
        let t3 = &config.collectors.t3;
        let state_db_path = resolve_state_db_path(t3)?;
        let environment_id = match resolve_environment_id(t3, &state_db_path) {
            Ok(environment_id) => environment_id,
            Err(error) => {
                if t3
                    .environment_id
                    .as_deref()
                    .is_some_and(|value| !value.trim().is_empty())
                {
                    return Err(error);
                }
                let Some(hostname) = hostname else {
                    bail!(
                        "T3 environment id is unavailable and no usable OS host name was found; \
                         set collectors.t3.environment_id explicitly (or provide an \
                         environment-id file)"
                    );
                };
                tracing::warn!(
                    %error,
                    %hostname,
                    "T3 environment id is unavailable; using the OS host name"
                );
                hostname
            }
        };
        Self::from_parts(t3, &config.payload, state_db_path, environment_id)
    }

    fn from_parts(
        t3: &crate::config::T3CollectorConfig,
        payload: &crate::config::PayloadConfig,
        state_db_path: PathBuf,
        environment_id: String,
    ) -> Result<Self> {
        let web_base_url = match t3.t3_web_base_url.as_deref() {
            Some(value) => Some(Url::parse(value).with_context(|| {
                format!("collectors.t3.t3_web_base_url `{value}` is not a URL")
            })?),
            None => None,
        };

        Ok(Self {
            environment_id,
            state_db_path,
            web_base_url,
            poll_interval: Duration::from_millis(t3.poll_interval_ms.max(1)),
            watch_wal: t3.watch_wal,
            batch_size: t3.batch_size.max(1),
            error_excerpt_max_chars: payload.error_excerpt_max_chars.max(1),
        })
    }

    /// Settings suitable for collector tests.
    #[doc(hidden)]
    pub fn for_tests(state_db_path: impl Into<PathBuf>, environment_id: &str) -> Self {
        Self {
            environment_id: environment_id.to_string(),
            state_db_path: state_db_path.into(),
            web_base_url: None,
            poll_interval: Duration::from_millis(250),
            watch_wal: false,
            batch_size: 100,
            error_excerpt_max_chars: super::t3_state::DEFAULT_ERROR_EXCERPT_MAX_CHARS,
        }
    }

    /// Settings with a web base URL for deep-link tests.
    #[doc(hidden)]
    pub fn with_web_base_url(mut self, base: &str) -> Self {
        self.web_base_url = Some(Url::parse(base).expect("valid test base URL"));
        self
    }
}

/// One drain pass over the upstream event log.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct T3CollectorSummary {
    /// Upstream events processed.
    pub processed: usize,
    /// New bridge events persisted.
    pub emitted: usize,
    /// Delivery rows created.
    pub deliveries_created: usize,
}

/// T3 collector.
pub struct T3Collector {
    settings: T3CollectorSettings,
    source: std::sync::Mutex<T3SourceState>,
    repo: std::sync::Arc<Repository>,
    bus: EventBus,
}

struct T3SourceState {
    source: T3Source,
    identity: Option<FileIdentity>,
    needs_reopen: bool,
}

impl T3Collector {
    /// Open the T3 database, hydrate state on first start, and return the
    /// collector.
    pub fn new(
        settings: T3CollectorSettings,
        repo: std::sync::Arc<Repository>,
        bus: EventBus,
    ) -> Result<Self> {
        let identity = file_identity(&settings.state_db_path);
        let source = T3Source::open(&settings.state_db_path)?;
        let collector = Self {
            settings,
            source: std::sync::Mutex::new(T3SourceState {
                source,
                identity,
                needs_reopen: false,
            }),
            repo,
            bus,
        };
        collector.bootstrap()?;
        Ok(collector)
    }

    /// Build a collector from the daemon configuration.
    pub fn from_config(
        config: &Config,
        repo: std::sync::Arc<Repository>,
        bus: EventBus,
    ) -> Result<Self> {
        Self::new(T3CollectorSettings::from_config(config)?, repo, bus)
    }

    /// Resolved environment id.
    pub fn environment_id(&self) -> &str {
        &self.settings.environment_id
    }

    /// Read-only source path.
    pub fn source_path(&self) -> &Path {
        &self.settings.state_db_path
    }

    fn ensure_source<'a>(&self, guard: &'a mut T3SourceState) -> Result<&'a T3Source> {
        let current_identity = file_identity(&self.settings.state_db_path);
        if guard.needs_reopen || current_identity != guard.identity {
            let reopened = T3Source::open(&self.settings.state_db_path)?;
            guard.source = reopened;
            guard.identity = current_identity;
            guard.needs_reopen = false;
            tracing::info!(
                path = %self.settings.state_db_path.display(),
                "reopened T3 state database"
            );
        }
        Ok(&guard.source)
    }

    fn bootstrap(&self) -> Result<()> {
        if self
            .repo
            .get_t3_cursor(&self.settings.environment_id)?
            .is_some()
        {
            return Ok(());
        }
        let mut guard = self
            .source
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let source = match self.ensure_source(&mut guard) {
            Ok(source) => source,
            Err(error) => {
                guard.needs_reopen = true;
                return Err(error);
            }
        };
        let (snapshot, max_sequence) = match source.snapshot(&self.settings.environment_id) {
            Ok(result) => result,
            Err(error) => {
                guard.needs_reopen = true;
                return Err(error);
            }
        };
        self.repo
            .apply_t3_snapshot(&self.settings.environment_id, &snapshot, max_sequence)?;
        tracing::info!(
            environment_id = %self.settings.environment_id,
            sequence = max_sequence,
            projects = snapshot.projects.len(),
            threads = snapshot.threads.len(),
            runs = snapshot.runs.len(),
            approvals = snapshot.approvals.len(),
            "T3 collector hydrated from current projections"
        );
        Ok(())
    }

    /// Process every currently available upstream event.
    pub fn collect_once(&self) -> Result<T3CollectorSummary> {
        let mut cursor = match self.repo.get_t3_cursor(&self.settings.environment_id)? {
            Some(cursor) => cursor,
            None => {
                self.bootstrap()?;
                self.repo
                    .get_t3_cursor(&self.settings.environment_id)?
                    .unwrap_or(0)
            }
        };

        let mut guard = self
            .source
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let source = match self.ensure_source(&mut guard) {
            Ok(source) => source,
            Err(error) => {
                guard.needs_reopen = true;
                return Err(error);
            }
        };

        let max_sequence = match source.max_sequence() {
            Ok(seq) => seq,
            Err(error) => {
                guard.needs_reopen = true;
                return Err(error);
            }
        };
        if max_sequence < cursor {
            tracing::warn!(
                environment_id = %self.settings.environment_id,
                saved_cursor = cursor,
                upstream_max_sequence = max_sequence,
                "upstream T3 sequence regressed; re-hydrating from current projections"
            );
            let (snapshot, new_max) = match source.snapshot(&self.settings.environment_id) {
                Ok(result) => result,
                Err(error) => {
                    guard.needs_reopen = true;
                    return Err(error);
                }
            };
            self.repo
                .apply_t3_snapshot(&self.settings.environment_id, &snapshot, new_max)?;
            cursor = new_max;
        }

        let mut summary = T3CollectorSummary::default();

        loop {
            let events = match source.events_after(cursor, self.settings.batch_size) {
                Ok(events) => events,
                Err(error) => {
                    guard.needs_reopen = true;
                    return Err(error);
                }
            };
            let fetched = events.len();
            if fetched == 0 {
                break;
            }
            for event in events {
                let reducer = T3Reducer::new(
                    &self.settings.environment_id,
                    &self.repo,
                    source,
                    self.settings.web_base_url.as_ref(),
                )
                .with_error_excerpt_max_chars(self.settings.error_excerpt_max_chars);
                let outcome = match reducer.process(&event) {
                    Ok(outcome) => outcome,
                    Err(error) => {
                        guard.needs_reopen = true;
                        return Err(error);
                    }
                };
                let new_events = outcome
                    .events
                    .iter()
                    .filter(|event| !event.duplicate)
                    .count();
                if new_events > 0 {
                    self.bus.notify();
                }
                summary.processed += 1;
                summary.emitted += new_events;
                summary.deliveries_created += outcome.deliveries_created;
                cursor = event.sequence;
            }
            if fetched < self.settings.batch_size {
                break;
            }
        }

        Ok(summary)
    }

    /// Run until cancelled, polling the database and optionally probing the
    /// WAL file for lower latency.
    pub async fn run(self, cancellation: CancellationToken) -> Result<()> {
        let poll_interval = self.settings.poll_interval;
        let tick = if self.settings.watch_wal {
            poll_interval.min(Duration::from_millis(250))
        } else {
            poll_interval
        };
        let mut last_probe = wal_signature(&self.settings.state_db_path);
        let mut last_full_poll = Instant::now();

        loop {
            tokio::select! {
                _ = cancellation.cancelled() => break,
                _ = tokio::time::sleep(tick) => {}
            }

            let should_poll = if self.settings.watch_wal {
                let probe = wal_signature(&self.settings.state_db_path);
                let changed = probe != last_probe;
                last_probe = probe;
                changed || last_full_poll.elapsed() >= poll_interval
            } else {
                true
            };
            if !should_poll {
                continue;
            }
            last_full_poll = Instant::now();

            match self.collect_once() {
                Ok(summary) if summary.processed > 0 => tracing::info!(
                    processed = summary.processed,
                    emitted = summary.emitted,
                    deliveries = summary.deliveries_created,
                    "T3 collector advanced"
                ),
                Ok(_) => {}
                Err(error) => {
                    tracing::warn!(%error, "T3 collector pass failed; will reopen on retry");
                }
            }
        }
        Ok(())
    }
}

/// Read-only handle to T3 Code's SQLite database.
pub struct T3Source {
    conn: Connection,
    path: PathBuf,
}

impl T3Source {
    /// Open `path` read-only and verify the expected T3 tables exist.
    pub fn open(path: &Path) -> Result<Self> {
        if !path.is_file() {
            bail!(
                "T3 state database {} does not exist (set collectors.t3.state_db_path)",
                path.display()
            );
        }
        let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .with_context(|| format!("opening T3 database {} read-only", path.display()))?;
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.execute_batch("PRAGMA query_only = ON;")?;
        for table in [
            "orchestration_events",
            "orchestration_v2_projection_runs",
            "orchestration_v2_projection_threads",
            "orchestration_v2_projection_runtime_requests",
            "projection_projects",
        ] {
            let exists: i64 = conn.query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                params![table],
                |row| row.get(0),
            )?;
            if exists == 0 {
                bail!(
                    "T3 database {} is missing table `{table}`; is this a T3 Code 0.1.x statev2.sqlite?",
                    path.display()
                );
            }
        }
        Ok(Self {
            conn,
            path: path.to_path_buf(),
        })
    }

    /// Source path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Read a consistent snapshot of the projection tables and the current
    /// maximum event sequence.
    pub fn snapshot(&self, environment_id: &str) -> Result<(T3Snapshot, i64)> {
        let tx = self.conn.unchecked_transaction()?;

        let projects = {
            let mut stmt = tx.prepare(
                "SELECT project_id, title, workspace_root, updated_at, deleted_at \
                 FROM projection_projects",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok(T3Project {
                    environment_id: environment_id.to_string(),
                    project_id: row.get(0)?,
                    title: row.get(1)?,
                    workspace_root: row.get(2)?,
                    updated_at: row.get(3)?,
                    deleted_at: row.get(4)?,
                })
            })?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };

        let threads = {
            let mut stmt = tx.prepare(
                "SELECT thread_id, project_id, title, \
                        CASE WHEN json_valid(payload_json) \
                             THEN json_extract(payload_json, '$.branch') END, \
                        deleted_at, updated_at \
                 FROM orchestration_v2_projection_threads",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok(T3Thread {
                    environment_id: environment_id.to_string(),
                    thread_id: row.get(0)?,
                    project_id: row.get(1)?,
                    title: row.get(2)?,
                    branch: row.get(3)?,
                    deleted_at: row.get(4)?,
                    updated_at: row.get(5)?,
                })
            })?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };

        let mut runs = Vec::new();
        {
            let mut stmt = tx.prepare(
                "SELECT r.run_id, r.thread_id, COALESCE(t.project_id, ''), r.ordinal, \
                        r.provider_instance_id, r.status, r.requested_at, r.completed_at, \
                        r.payload_json \
                 FROM orchestration_v2_projection_runs r \
                 LEFT JOIN orchestration_v2_projection_threads t \
                   ON t.thread_id = r.thread_id",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, String>(8)?,
                ))
            })?;
            for row in rows {
                let (
                    run_id,
                    thread_id,
                    project_id,
                    ordinal,
                    provider_instance_id,
                    status,
                    requested_at,
                    completed_at,
                    payload_json,
                ) = row?;
                let payload: Value = serde_json::from_str(&payload_json).unwrap_or(Value::Null);
                let error = if status == "failed" {
                    extract_error(&payload).or(failure_for_run_conn(&tx, &run_id)?)
                } else {
                    None
                };
                let thread_title = threads
                    .iter()
                    .find(|thread| thread.thread_id == thread_id)
                    .map(|thread| thread.title.as_str());
                runs.push(T3Run {
                    environment_id: environment_id.to_string(),
                    run_id,
                    thread_id,
                    project_id,
                    ordinal,
                    provider_instance_id,
                    status: status.clone(),
                    last_turn_status: None,
                    checkpoint_id: text(&payload, "checkpointId"),
                    error,
                    summary: Some(run_summary(&status, ordinal, thread_title)),
                    requested_at,
                    started_at: text(&payload, "startedAt")
                        .and_then(|value| normalize_timestamp(&value)),
                    completed_at: completed_at.clone(),
                    updated_at: completed_at.unwrap_or_else(now_rfc3339),
                });
            }
        }

        let mut approvals = Vec::new();
        {
            let mut stmt = tx.prepare(
                "SELECT runtime_request_id, thread_id, node_id, kind, status, created_at, \
                        resolved_at, payload_json \
                 FROM orchestration_v2_projection_runtime_requests",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, String>(7)?,
                ))
            })?;
            for row in rows {
                let (
                    approval_id,
                    thread_id,
                    node_id,
                    kind,
                    status,
                    created_at,
                    resolved_at,
                    payload_json,
                ) = row?;
                let payload: Value = serde_json::from_str(&payload_json).unwrap_or(Value::Null);
                let run_id = text(&payload, "runId")
                    .or(run_for_node_conn(&tx, &node_id)?)
                    .or(latest_run_for_thread_conn(&tx, &thread_id)?)
                    .unwrap_or_default();
                let summary = text(&payload, "summary")
                    .or_else(|| text(&payload, "title"))
                    .or_else(|| text(&payload, "reason"))
                    .unwrap_or_else(|| format!("{kind} approval required"));
                approvals.push(T3Approval {
                    environment_id: environment_id.to_string(),
                    approval_id,
                    thread_id,
                    run_id,
                    node_id: Some(node_id),
                    kind,
                    status,
                    summary: Some(summary),
                    decision: payload.get("decision").and_then(decision_text),
                    created_at,
                    resolved_at: resolved_at.clone(),
                    updated_at: resolved_at.unwrap_or_else(now_rfc3339),
                });
            }
        }

        let max_sequence: i64 = tx.query_row(
            "SELECT COALESCE(MAX(sequence), 0) FROM orchestration_events",
            [],
            |row| row.get(0),
        )?;
        tx.commit()?;

        Ok((
            T3Snapshot {
                projects,
                threads,
                runs,
                approvals,
            },
            max_sequence,
        ))
    }

    /// Return the current maximum upstream event sequence (0 when empty).
    pub fn max_sequence(&self) -> Result<i64> {
        Ok(self.conn.query_row(
            "SELECT COALESCE(MAX(sequence), 0) FROM orchestration_events",
            [],
            |row| row.get(0),
        )?)
    }

    /// Read events newer than `sequence`, oldest first.
    pub fn events_after(&self, sequence: i64, limit: usize) -> Result<Vec<T3SourceEvent>> {
        let mut stmt = self.conn.prepare(
            "SELECT sequence, event_id, event_type, stream_id, stream_version, \
                    occurred_at, payload_json \
             FROM orchestration_events WHERE sequence > ?1 \
             ORDER BY sequence ASC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![sequence, limit.max(1) as i64], |row| {
            let payload_json: String = row.get(6)?;
            Ok(T3SourceEvent {
                sequence: row.get(0)?,
                event_id: row.get(1)?,
                event_type: row.get(2)?,
                stream_id: row.get(3)?,
                stream_version: row.get(4)?,
                occurred_at: row.get(5)?,
                payload: serde_json::from_str(&payload_json).unwrap_or(Value::Null),
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Best failure text observed for a run (turn item, node or attempt).
    pub fn failure_for_run(&self, run_id: &str) -> Result<Option<String>> {
        failure_for_run_conn(&self.conn, run_id)
    }

    /// Resolve the run that owns a node.
    pub fn run_for_node(&self, node_id: &str) -> Result<Option<String>> {
        run_for_node_conn(&self.conn, node_id)
    }

    /// Resolve the run that owns a run attempt.
    pub fn run_for_attempt(&self, attempt_id: &str) -> Result<Option<String>> {
        let value = self
            .conn
            .query_row(
                "SELECT json_extract(payload_json, '$.runId') \
                 FROM orchestration_events \
                 WHERE event_type = 'run-attempt.updated' \
                   AND json_valid(payload_json) \
                   AND json_extract(payload_json, '$.id') = ?1 \
                 ORDER BY sequence DESC LIMIT 1",
                params![attempt_id],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten();
        Ok(value.filter(|value| !value.is_empty()))
    }

    /// Resolve the thread that owns a node.
    pub fn thread_for_node(&self, node_id: &str) -> Result<Option<String>> {
        let value = self
            .conn
            .query_row(
                "SELECT json_extract(payload_json, '$.threadId') \
                 FROM orchestration_events \
                 WHERE event_type = 'node.updated' \
                   AND json_valid(payload_json) \
                   AND json_extract(payload_json, '$.id') = ?1 \
                 ORDER BY sequence DESC LIMIT 1",
                params![node_id],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten();
        Ok(value.filter(|value| !value.is_empty()))
    }

    /// Resolve a thread's project from the projection, then the event log.
    pub fn project_for_thread(&self, thread_id: &str) -> Result<Option<String>> {
        let projected = self
            .conn
            .query_row(
                "SELECT project_id FROM orchestration_v2_projection_threads \
                 WHERE thread_id = ?1",
                params![thread_id],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten()
            .filter(|value| !value.is_empty());
        if projected.is_some() {
            return Ok(projected);
        }
        let value = self
            .conn
            .query_row(
                "SELECT json_extract(payload_json, '$.projectId') \
                 FROM orchestration_events \
                 WHERE event_type IN ('thread.created', 'thread.metadata-updated') \
                   AND json_valid(payload_json) \
                   AND json_extract(payload_json, '$.id') = ?1 \
                 ORDER BY sequence DESC LIMIT 1",
                params![thread_id],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten();
        Ok(value.filter(|value| !value.is_empty()))
    }

    /// Resolve a project's title from the projection table, then the event log.
    pub fn project_title(&self, project_id: &str) -> Result<Option<String>> {
        let projected = self
            .conn
            .query_row(
                "SELECT title FROM projection_projects WHERE project_id = ?1",
                params![project_id],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten()
            .filter(|value| !value.trim().is_empty());
        if projected.is_some() {
            return Ok(projected);
        }
        let value = self
            .conn
            .query_row(
                "SELECT json_extract(payload_json, '$.title') \
                 FROM orchestration_events \
                 WHERE event_type IN ('project.created', 'project.metadata-updated') \
                   AND json_valid(payload_json) \
                   AND json_extract(payload_json, '$.projectId') = ?1 \
                 ORDER BY sequence DESC LIMIT 1",
                params![project_id],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten();
        Ok(value.filter(|value| !value.trim().is_empty()))
    }

    /// Resolve a thread's title from the projection table, then the event log.
    pub fn thread_title(&self, thread_id: &str) -> Result<Option<String>> {
        let projected = self
            .conn
            .query_row(
                "SELECT title FROM orchestration_v2_projection_threads \
                 WHERE thread_id = ?1",
                params![thread_id],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten()
            .filter(|value| !value.trim().is_empty());
        if projected.is_some() {
            return Ok(projected);
        }
        let value = self
            .conn
            .query_row(
                "SELECT json_extract(payload_json, '$.title') \
                 FROM orchestration_events \
                 WHERE event_type IN ('thread.created', 'thread.metadata-updated') \
                   AND json_valid(payload_json) \
                   AND json_extract(payload_json, '$.id') = ?1 \
                 ORDER BY sequence DESC LIMIT 1",
                params![thread_id],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten();
        Ok(value.filter(|value| !value.trim().is_empty()))
    }
}

fn failure_for_run_conn(conn: &Connection, run_id: &str) -> Result<Option<String>> {
    let mut stmt = conn.prepare(
        "SELECT payload_json FROM orchestration_events \
         WHERE event_type IN ('turn-item.updated', 'node.updated', 'run-attempt.updated') \
           AND json_valid(payload_json) \
           AND json_extract(payload_json, '$.runId') = ?1 \
           AND json_extract(payload_json, '$.status') = 'failed' \
         ORDER BY sequence DESC LIMIT 20",
    )?;
    let rows = stmt.query_map(params![run_id], |row| row.get::<_, String>(0))?;
    for row in rows {
        let payload_json = row?;
        let payload: Value = serde_json::from_str(&payload_json).unwrap_or(Value::Null);
        if let Some(error) = extract_error(&payload) {
            return Ok(Some(error));
        }
    }
    Ok(None)
}

fn run_for_node_conn(conn: &Connection, node_id: &str) -> Result<Option<String>> {
    let value = conn
        .query_row(
            "SELECT json_extract(payload_json, '$.runId') \
             FROM orchestration_events \
             WHERE event_type = 'node.updated' \
               AND json_valid(payload_json) \
               AND json_extract(payload_json, '$.id') = ?1 \
             ORDER BY sequence DESC LIMIT 1",
            params![node_id],
            |row| row.get::<_, Option<String>>(0),
        )
        .optional()?
        .flatten();
    Ok(value.filter(|value| !value.is_empty()))
}

fn latest_run_for_thread_conn(conn: &Connection, thread_id: &str) -> Result<Option<String>> {
    let value = conn
        .query_row(
            "SELECT json_extract(payload_json, '$.id') \
             FROM orchestration_events \
             WHERE event_type IN ('run.created', 'run.updated') \
               AND json_valid(payload_json) \
               AND json_extract(payload_json, '$.threadId') = ?1 \
             ORDER BY sequence DESC LIMIT 1",
            params![thread_id],
            |row| row.get::<_, Option<String>>(0),
        )
        .optional()?
        .flatten();
    Ok(value.filter(|value| !value.is_empty()))
}

fn text(payload: &Value, key: &str) -> Option<String> {
    payload
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn decision_text(value: &Value) -> Option<String> {
    match value {
        Value::Null => None,
        Value::String(text) if text.is_empty() => None,
        Value::String(text) => Some(text.clone()),
        other => serde_json::to_string(other).ok(),
    }
}

fn resolve_state_db_path(t3: &crate::config::T3CollectorConfig) -> Result<PathBuf> {
    if t3.state_db_path.as_os_str().is_empty() {
        Ok(home_directory()?.join(".t3/userdata/statev2.sqlite"))
    } else {
        expand_tilde(t3.state_db_path.clone())
    }
}

fn resolve_environment_id(
    t3: &crate::config::T3CollectorConfig,
    state_db_path: &Path,
) -> Result<String> {
    match t3
        .environment_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(value) => Ok(value.to_string()),
        None => {
            let path = match &t3.environment_id_path {
                Some(path) => expand_tilde(path.clone())?,
                None => state_db_path
                    .parent()
                    .map(|parent| parent.join("environment-id"))
                    .context("T3 state database path has no parent directory")?,
            };
            let contents = fs::read_to_string(&path).with_context(|| {
                format!(
                    "reading T3 environment id from {} (set collectors.t3.environment_id)",
                    path.display()
                )
            })?;
            let value = contents.trim().to_string();
            if value.is_empty() {
                bail!("T3 environment id file {} is empty", path.display());
            }
            Ok(value)
        }
    }
}

fn home_directory() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("HOME is unset; set collectors.t3.state_db_path explicitly")
}

fn expand_tilde(path: PathBuf) -> Result<PathBuf> {
    let Some(rest) = path.strip_prefix("~").ok() else {
        return Ok(path);
    };
    Ok(home_directory()?.join(rest))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
    #[cfg(not(unix))]
    sig: (u64, u128),
}

fn file_identity(path: &Path) -> Option<FileIdentity> {
    let metadata = fs::metadata(path).ok()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Some(FileIdentity {
            dev: metadata.dev(),
            ino: metadata.ino(),
        })
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        Some(FileIdentity {
            sig: file_signature(path)?,
        })
    }
}

fn wal_signature(state_db_path: &Path) -> Option<((u64, u128), (u64, u128))> {
    let database = file_signature(state_db_path)?;
    let mut wal = state_db_path.as_os_str().to_os_string();
    wal.push("-wal");
    let wal = file_signature(Path::new(&wal)).unwrap_or((0, 0));
    Some((database, wal))
}

fn file_signature(path: &Path) -> Option<(u64, u128)> {
    let metadata = fs::metadata(path).ok()?;
    let modified = metadata
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_nanos();
    Some((metadata.len(), modified))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tilde_expansion_uses_home() {
        let expanded = expand_tilde(PathBuf::from("~/.t3/userdata/statev2.sqlite")).unwrap();
        assert!(!expanded.starts_with("~"));
        assert!(expanded.ends_with(".t3/userdata/statev2.sqlite"));
    }

    #[test]
    fn t3_source_rejects_writes_at_the_sqlite_layer() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("statev2.sqlite");
        {
            let conn = Connection::open(&path).unwrap();
            for table in [
                "orchestration_events",
                "orchestration_v2_projection_runs",
                "orchestration_v2_projection_threads",
                "orchestration_v2_projection_runtime_requests",
                "projection_projects",
            ] {
                conn.execute_batch(&format!("CREATE TABLE {table} (x INTEGER);"))
                    .unwrap();
            }
        }
        let source = T3Source::open(&path).unwrap();
        let query_only: i64 = source
            .conn
            .query_row("PRAGMA query_only", [], |row| row.get(0))
            .unwrap();
        assert_eq!(query_only, 1);
        let error = source
            .conn
            .execute_batch("CREATE TABLE forbidden (id INTEGER);")
            .unwrap_err();
        assert!(
            error.to_string().contains("readonly"),
            "unexpected write error: {error}"
        );
    }

    #[test]
    fn edge_settings_fall_back_to_the_host_name() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut config = Config::default();
        config.collectors.t3.state_db_path = dir.path().join("statev2.sqlite");
        config.collectors.t3.environment_id = None;
        config.collectors.t3.environment_id_path = None;

        let strict = T3CollectorSettings::from_config(&config);
        assert!(strict.is_err(), "strict resolution must require an id");

        let settings = T3CollectorSettings::from_config_with_hostname_fallback_and_hostname(
            &config,
            Some("build-host".into()),
        )
        .expect("host name fallback");
        assert_eq!(settings.environment_id, "build-host");
        assert_eq!(settings.state_db_path, config.collectors.t3.state_db_path);
    }

    #[test]
    fn edge_settings_require_an_explicit_id_when_no_host_name_resolves() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut config = Config::default();
        config.collectors.t3.state_db_path = dir.path().join("statev2.sqlite");
        config.collectors.t3.environment_id = None;
        config.collectors.t3.environment_id_path = None;

        let error =
            T3CollectorSettings::from_config_with_hostname_fallback_and_hostname(&config, None)
                .expect_err("unresolved host name must fail");
        assert!(
            error.to_string().contains("collectors.t3.environment_id"),
            "{error}"
        );
    }

    #[test]
    fn collector_summary_defaults_to_zero() {
        assert_eq!(
            T3CollectorSummary::default(),
            T3CollectorSummary {
                processed: 0,
                emitted: 0,
                deliveries_created: 0
            }
        );
    }
}
