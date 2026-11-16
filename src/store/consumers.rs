//! Server-side polling consumer persistence.
//!
//! A consumer is a named cursor over the durable event log. Polling never
//! advances the cursor; only an explicit acknowledgement does. This module owns
//! the SQL that makes that contract atomic.

use anyhow::Result;
use rusqlite::{Connection, OptionalExtension, params, types::Value as SqlValue};

use super::repository::{EVENT_COLUMNS, Event, Repository, map_event};
use crate::util::now_rfc3339;

/// One row from the `consumers` table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumerRow {
    /// Consumer name (primary key).
    pub name: String,
    /// Last acknowledged event sequence.
    pub cursor_sequence: i64,
    /// Row creation timestamp.
    pub created_at: String,
    /// Last row update timestamp.
    pub updated_at: String,
    /// Last poll timestamp, when the consumer has been polled.
    pub last_polled_at: Option<String>,
    /// Last acknowledgement timestamp, when the consumer has acked.
    pub last_acked_at: Option<String>,
}

/// Payload allowlists applied while selecting consumer events.
///
/// Empty slices mean "no restriction". A non-empty filter requires the event
/// payload to contain the corresponding key with one of the listed values.
#[derive(Debug, Clone, Copy, Default)]
pub struct ConsumerEventFilter<'a> {
    /// Accepted `data.environment_id` values.
    pub environment_ids: &'a [String],
    /// Accepted `data.project_id` values.
    pub project_ids: &'a [String],
    /// Accepted `data.repository` values.
    pub repositories: &'a [String],
}

/// Result of advancing a consumer cursor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumerAckOutcome {
    /// Cursor before the acknowledgement.
    pub previous_cursor_sequence: i64,
    /// Cursor after the acknowledgement (monotonic maximum).
    pub cursor_sequence: i64,
    /// Whether the requested sequence moved the cursor forward.
    pub advanced: bool,
}

/// Consistent snapshot of a consumer's cursor, latest sequence, and unread count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumerProbeSnapshot {
    /// Last acknowledged event sequence.
    pub cursor_sequence: i64,
    /// Highest stored event sequence.
    pub latest_sequence: i64,
    /// Number of matching events after the cursor.
    pub unread_count: i64,
}

/// Parameters for reading one consistent consumer poll snapshot.
#[derive(Debug, Clone, Copy)]
pub struct ConsumerPollSnapshotQuery<'a> {
    /// Maximum number of immediate events (and combined page budget).
    pub limit: usize,
    /// Maximum number of digest events to scan when summarizing a catchup backlog.
    pub digest_catchup_limit: usize,
    /// Event kinds delivered individually.
    pub immediate_kinds: &'a [String],
    /// Event kinds aggregated into digest windows.
    pub digest_kinds: &'a [String],
    /// Union of enabled event kinds.
    pub all_kinds: &'a [String],
    /// Shared payload allowlists.
    pub filters: &'a ConsumerEventFilter<'a>,
}

/// Consistent snapshot of one consumer poll read inside a single SQLite transaction.
#[derive(Debug, Clone)]
pub struct ConsumerPollSnapshot {
    /// Last acknowledged cursor before this poll.
    pub cursor_sequence: i64,
    /// Highest stored event sequence in the snapshot.
    pub latest_sequence: i64,
    /// Individual immediate events selected for this poll.
    pub immediate_events: Vec<Event>,
    /// Digest-disposition events selected or summarized for this poll.
    pub digest_events: Vec<Event>,
    /// Whether unread matching events remain beyond the returned cursor.
    pub has_more: bool,
    /// Whether digest backlog exceeded the remaining page budget and was summarized.
    pub truncated: bool,
    /// Ceiling on `nextCursorSequence` when digest scanning stopped at the catchup cap.
    pub next_cursor_ceiling: Option<i64>,
}

/// Why a consumer acknowledgement was rejected.
#[derive(Debug, thiserror::Error)]
pub enum ConsumerAckError {
    /// The requested sequence is negative or beyond the latest stored event.
    #[error(
        "up_to_sequence {up_to_sequence} is out of range 0..={latest_sequence} for consumer `{consumer}`"
    )]
    OutOfRange {
        /// Consumer being acknowledged.
        consumer: String,
        /// Requested sequence.
        up_to_sequence: i64,
        /// Latest stored event sequence.
        latest_sequence: i64,
    },
    /// The database rejected the operation.
    #[error(transparent)]
    Database(#[from] rusqlite::Error),
}

const CONSUMER_COLUMNS: &str =
    "name, cursor_sequence, created_at, updated_at, last_polled_at, last_acked_at";

fn map_consumer(row: &rusqlite::Row<'_>) -> rusqlite::Result<ConsumerRow> {
    Ok(ConsumerRow {
        name: row.get(0)?,
        cursor_sequence: row.get(1)?,
        created_at: row.get(2)?,
        updated_at: row.get(3)?,
        last_polled_at: row.get(4)?,
        last_acked_at: row.get(5)?,
    })
}

fn load_consumer(conn: &Connection, name: &str) -> rusqlite::Result<Option<ConsumerRow>> {
    let sql = format!("SELECT {CONSUMER_COLUMNS} FROM consumers WHERE name = ?1");
    conn.query_row(&sql, params![name], map_consumer).optional()
}

/// Build the shared `cursor < sequence <= through` event restriction.
///
/// `through_sequence` is inclusive and omitted when the caller wants every
/// unread event. Digest aggregation uses it to summarize only the events a
/// cursor acknowledgement will actually cover.
fn consumer_event_sql(
    projection: &str,
    after_sequence: i64,
    through_sequence: Option<i64>,
    kinds: &[String],
    filters: &ConsumerEventFilter<'_>,
) -> (String, Vec<SqlValue>) {
    let mut sql = format!("SELECT {projection} FROM events WHERE sequence > ?");
    let mut args = vec![SqlValue::Integer(after_sequence)];
    if let Some(through_sequence) = through_sequence {
        sql.push_str(" AND sequence <= ?");
        args.push(SqlValue::Integer(through_sequence));
    }

    let placeholders = vec!["?"; kinds.len()].join(", ");
    sql.push_str(&format!(" AND kind IN ({placeholders})"));
    args.extend(kinds.iter().cloned().map(SqlValue::Text));

    for (column, values) in [
        ("$.environment_id", filters.environment_ids),
        ("$.project_id", filters.project_ids),
        ("$.repository", filters.repositories),
    ] {
        if values.is_empty() {
            continue;
        }
        let placeholders = vec!["?"; values.len()].join(", ");
        sql.push_str(&format!(
            " AND json_extract(payload, '{column}') IN ({placeholders})"
        ));
        args.extend(values.iter().cloned().map(SqlValue::Text));
    }

    (sql, args)
}

fn count_consumer_events_tx(
    conn: &Connection,
    after_sequence: i64,
    through_sequence: Option<i64>,
    kinds: &[String],
    filters: &ConsumerEventFilter<'_>,
) -> Result<i64> {
    if kinds.is_empty() {
        return Ok(0);
    }
    let (sql, args) =
        consumer_event_sql("COUNT(*)", after_sequence, through_sequence, kinds, filters);
    let mut stmt = conn.prepare(&sql)?;
    Ok(stmt.query_row(rusqlite::params_from_iter(args.iter()), |row| row.get(0))?)
}

fn list_consumer_events_tx(
    conn: &Connection,
    after_sequence: i64,
    through_sequence: Option<i64>,
    kinds: &[String],
    filters: &ConsumerEventFilter<'_>,
    limit: usize,
) -> Result<Vec<Event>> {
    if kinds.is_empty() {
        return Ok(Vec::new());
    }
    let (mut sql, mut args) = consumer_event_sql(
        EVENT_COLUMNS,
        after_sequence,
        through_sequence,
        kinds,
        filters,
    );
    sql.push_str(" ORDER BY sequence ASC LIMIT ?");
    args.push(SqlValue::Integer(limit.max(1) as i64));

    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(rusqlite::params_from_iter(args.iter()), map_event)?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

fn list_digest_catchup_tx(
    conn: &Connection,
    after_sequence: i64,
    through_sequence: Option<i64>,
    kinds: &[String],
    filters: &ConsumerEventFilter<'_>,
    catchup_limit: usize,
) -> Result<(Vec<Event>, bool)> {
    let mut events = list_consumer_events_tx(
        conn,
        after_sequence,
        through_sequence,
        kinds,
        filters,
        catchup_limit.saturating_add(1),
    )?;
    let scanned_past_cap = events.len() > catchup_limit;
    if scanned_past_cap {
        events.truncate(catchup_limit);
    }
    Ok((events, scanned_past_cap))
}

fn read_probe_snapshot(
    tx: &rusqlite::Transaction<'_>,
    cursor_sequence: i64,
    kinds: &[String],
    filters: &ConsumerEventFilter<'_>,
) -> Result<ConsumerProbeSnapshot> {
    let latest_sequence: i64 =
        tx.query_row("SELECT COALESCE(MAX(sequence), 0) FROM events", [], |row| {
            row.get(0)
        })?;
    let unread_count = count_consumer_events_tx(tx, cursor_sequence, None, kinds, filters)?;
    Ok(ConsumerProbeSnapshot {
        cursor_sequence,
        latest_sequence,
        unread_count,
    })
}

fn read_poll_snapshot(
    tx: &rusqlite::Transaction<'_>,
    cursor_sequence: i64,
    query: &ConsumerPollSnapshotQuery<'_>,
    after_immediate_read: impl FnOnce(),
) -> Result<ConsumerPollSnapshot> {
    let mut immediate_events = list_consumer_events_tx(
        tx,
        cursor_sequence,
        None,
        query.immediate_kinds,
        query.filters,
        query.limit.saturating_add(1),
    )?;
    after_immediate_read();

    let more_immediate = immediate_events.len() > query.limit;
    immediate_events.truncate(query.limit);
    let next_cursor_from_immediate = immediate_events
        .last()
        .map(|event| event.sequence)
        .unwrap_or(cursor_sequence);
    let digest_budget = query.limit.saturating_sub(immediate_events.len());

    let mut digest_events = Vec::new();
    let mut truncated = false;
    let mut has_more = more_immediate;
    let mut next_cursor_ceiling = None;

    if digest_budget == 0 {
        if next_cursor_from_immediate > cursor_sequence {
            let count = count_consumer_events_tx(
                tx,
                cursor_sequence,
                Some(next_cursor_from_immediate),
                query.digest_kinds,
                query.filters,
            )?;
            if count > 0 {
                truncated = true;
                let (mut events, scanned_past_cap) = list_digest_catchup_tx(
                    tx,
                    cursor_sequence,
                    Some(next_cursor_from_immediate),
                    query.digest_kinds,
                    query.filters,
                    query.digest_catchup_limit,
                )?;
                has_more |= scanned_past_cap;
                if scanned_past_cap {
                    next_cursor_ceiling = events.last().map(|event| event.sequence);
                }
                digest_events.append(&mut events);
            }
        }

        if !has_more {
            let remaining = count_consumer_events_tx(
                tx,
                next_cursor_from_immediate,
                None,
                query.all_kinds,
                query.filters,
            )?;
            has_more = remaining > 0;
        }
    } else if !query.digest_kinds.is_empty() {
        let unread_digest =
            count_consumer_events_tx(tx, cursor_sequence, None, query.digest_kinds, query.filters)?;
        if unread_digest > 0 && unread_digest <= digest_budget as i64 {
            digest_events = list_consumer_events_tx(
                tx,
                cursor_sequence,
                None,
                query.digest_kinds,
                query.filters,
                usize::try_from(unread_digest).unwrap_or(digest_budget),
            )?;
        } else if unread_digest > digest_budget as i64 {
            truncated = true;
            let (mut events, scanned_past_cap) = list_digest_catchup_tx(
                tx,
                cursor_sequence,
                None,
                query.digest_kinds,
                query.filters,
                query.digest_catchup_limit,
            )?;
            has_more = scanned_past_cap;
            if scanned_past_cap {
                next_cursor_ceiling = events.last().map(|event| event.sequence);
            }
            digest_events.append(&mut events);
        }
    }

    let latest_sequence: i64 =
        tx.query_row("SELECT COALESCE(MAX(sequence), 0) FROM events", [], |row| {
            row.get(0)
        })?;

    Ok(ConsumerPollSnapshot {
        cursor_sequence,
        latest_sequence,
        immediate_events,
        digest_events,
        has_more,
        truncated,
        next_cursor_ceiling,
    })
}

impl Repository {
    /// Read a consumer row without creating it.
    pub fn get_consumer(&self, name: &str) -> Result<Option<ConsumerRow>> {
        Ok(load_consumer(&self.lock_connection(), name)?)
    }

    /// Create a consumer cursor at zero when it does not exist, then return it.
    ///
    /// Probe is intentionally idempotent: the first probe of a brand-new
    /// consumer initializes its durable row without consuming any event.
    pub fn ensure_consumer(&self, name: &str) -> Result<ConsumerRow> {
        let now = now_rfc3339();
        let conn = self.lock_connection();
        conn.execute(
            "INSERT OR IGNORE INTO consumers \
             (name, cursor_sequence, created_at, updated_at) VALUES (?1, 0, ?2, ?2)",
            params![name, &now],
        )?;
        load_consumer(&conn, name)?
            .ok_or_else(|| anyhow::anyhow!("consumer `{name}` disappeared after initialization"))
    }

    /// Record that a consumer was polled without advancing its cursor.
    pub fn mark_consumer_polled(&self, name: &str) -> Result<()> {
        let now = now_rfc3339();
        let conn = self.lock_connection();
        conn.execute(
            "INSERT OR IGNORE INTO consumers \
             (name, cursor_sequence, created_at, updated_at) VALUES (?1, 0, ?2, ?2)",
            params![name, &now],
        )?;
        conn.execute(
            "UPDATE consumers SET last_polled_at = ?2, updated_at = ?2 WHERE name = ?1",
            params![name, &now],
        )?;
        Ok(())
    }

    /// Highest event sequence in the log, or zero when it is empty.
    pub fn latest_event_sequence(&self) -> Result<i64> {
        let conn = self.lock_connection();
        Ok(
            conn.query_row("SELECT COALESCE(MAX(sequence), 0) FROM events", [], |row| {
                row.get(0)
            })?,
        )
    }

    /// Count events after `after_sequence` whose name is in `kinds` and whose
    /// payload matches every non-empty filter.
    pub fn count_consumer_events(
        &self,
        after_sequence: i64,
        kinds: &[String],
        filters: &ConsumerEventFilter<'_>,
    ) -> Result<i64> {
        self.count_consumer_events_in_range(after_sequence, None, kinds, filters)
    }

    /// Count events in `(after_sequence, through_sequence]` whose name is in
    /// `kinds` and whose payload matches every non-empty filter.
    ///
    /// A `None` upper bound means "all unread events".
    pub fn count_consumer_events_in_range(
        &self,
        after_sequence: i64,
        through_sequence: Option<i64>,
        kinds: &[String],
        filters: &ConsumerEventFilter<'_>,
    ) -> Result<i64> {
        let conn = self.lock_connection();
        count_consumer_events_tx(&conn, after_sequence, through_sequence, kinds, filters)
    }

    /// Ensure a consumer row exists and read its cursor, latest event sequence,
    /// and matching unread count within a single SQLite transaction snapshot.
    pub fn probe_consumer_snapshot(
        &self,
        name: &str,
        kinds: &[String],
        filters: &ConsumerEventFilter<'_>,
    ) -> Result<ConsumerProbeSnapshot> {
        let mut conn = self.lock_connection();
        let tx = conn.transaction()?;
        if let Some(cursor_sequence) = tx
            .query_row(
                "SELECT cursor_sequence FROM consumers WHERE name = ?1",
                params![name],
                |row| row.get(0),
            )
            .optional()?
        {
            return read_probe_snapshot(&tx, cursor_sequence, kinds, filters);
        }
        drop(tx);

        let now = now_rfc3339();
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT OR IGNORE INTO consumers \
             (name, cursor_sequence, created_at, updated_at) VALUES (?1, 0, ?2, ?2)",
            params![name, &now],
        )?;
        let cursor_sequence: i64 = tx.query_row(
            "SELECT cursor_sequence FROM consumers WHERE name = ?1",
            params![name],
            |row| row.get(0),
        )?;
        let snapshot = read_probe_snapshot(&tx, cursor_sequence, kinds, filters)?;
        tx.commit()?;
        Ok(snapshot)
    }

    /// Ensure a consumer row exists, read its immediate/digest poll state and
    /// latest sequence within one SQLite transaction snapshot, and record
    /// `last_polled_at`.
    pub fn poll_consumer_snapshot(
        &self,
        name: &str,
        query: &ConsumerPollSnapshotQuery<'_>,
    ) -> Result<ConsumerPollSnapshot> {
        self.poll_consumer_snapshot_with_hook(name, query, || {})
    }

    /// Test helper variant of [`Self::poll_consumer_snapshot`] that runs
    /// `after_immediate_read` while the SQLite read snapshot transaction is
    /// still open.
    #[cfg(test)]
    pub(crate) fn poll_consumer_snapshot_with_hook(
        &self,
        name: &str,
        query: &ConsumerPollSnapshotQuery<'_>,
        after_immediate_read: impl FnOnce(),
    ) -> Result<ConsumerPollSnapshot> {
        self.poll_consumer_snapshot_inner(name, query, after_immediate_read)
    }

    #[cfg(not(test))]
    fn poll_consumer_snapshot_with_hook(
        &self,
        name: &str,
        query: &ConsumerPollSnapshotQuery<'_>,
        after_immediate_read: impl FnOnce(),
    ) -> Result<ConsumerPollSnapshot> {
        self.poll_consumer_snapshot_inner(name, query, after_immediate_read)
    }

    fn poll_consumer_snapshot_inner(
        &self,
        name: &str,
        query: &ConsumerPollSnapshotQuery<'_>,
        after_immediate_read: impl FnOnce(),
    ) -> Result<ConsumerPollSnapshot> {
        let mut conn = self.lock_connection();
        let tx = conn.transaction()?;
        if let Some(cursor_sequence) = tx
            .query_row(
                "SELECT cursor_sequence FROM consumers WHERE name = ?1",
                params![name],
                |row| row.get(0),
            )
            .optional()?
        {
            let snapshot = read_poll_snapshot(&tx, cursor_sequence, query, after_immediate_read)?;
            drop(tx);
            let now = now_rfc3339();
            conn.execute(
                "UPDATE consumers SET last_polled_at = ?2, updated_at = ?2 WHERE name = ?1",
                params![name, &now],
            )?;
            return Ok(snapshot);
        }
        drop(tx);

        let now = now_rfc3339();
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT OR IGNORE INTO consumers \
             (name, cursor_sequence, created_at, updated_at) VALUES (?1, 0, ?2, ?2)",
            params![name, &now],
        )?;
        let cursor_sequence: i64 = tx.query_row(
            "SELECT cursor_sequence FROM consumers WHERE name = ?1",
            params![name],
            |row| row.get(0),
        )?;
        let snapshot = read_poll_snapshot(&tx, cursor_sequence, query, after_immediate_read)?;
        tx.execute(
            "UPDATE consumers SET last_polled_at = ?2, updated_at = ?2 WHERE name = ?1",
            params![name, &now],
        )?;
        tx.commit()?;
        Ok(snapshot)
    }

    /// Select events after `after_sequence` in ascending sequence order.
    pub fn list_consumer_events(
        &self,
        after_sequence: i64,
        kinds: &[String],
        filters: &ConsumerEventFilter<'_>,
        limit: usize,
    ) -> Result<Vec<Event>> {
        self.list_consumer_events_in_range(after_sequence, None, kinds, filters, limit)
    }

    /// Select events in `(after_sequence, through_sequence]` in ascending
    /// sequence order.
    ///
    /// A `None` upper bound means "all unread events".
    pub fn list_consumer_events_in_range(
        &self,
        after_sequence: i64,
        through_sequence: Option<i64>,
        kinds: &[String],
        filters: &ConsumerEventFilter<'_>,
        limit: usize,
    ) -> Result<Vec<Event>> {
        let conn = self.lock_connection();
        list_consumer_events_tx(
            &conn,
            after_sequence,
            through_sequence,
            kinds,
            filters,
            limit,
        )
    }

    /// Advance a consumer cursor monotonically to `up_to_sequence`.
    ///
    /// The requested sequence must be within `0..=latest_sequence`. The cursor
    /// never moves backwards, so an older ack is accepted as a no-op instead of
    /// reopening already-processed events.
    pub fn ack_consumer(
        &self,
        name: &str,
        up_to_sequence: i64,
    ) -> Result<ConsumerAckOutcome, ConsumerAckError> {
        let now = now_rfc3339();
        let mut conn = self.lock_connection();
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT OR IGNORE INTO consumers \
             (name, cursor_sequence, created_at, updated_at) VALUES (?1, 0, ?2, ?2)",
            params![name, &now],
        )?;

        let previous_cursor_sequence: i64 = tx.query_row(
            "SELECT cursor_sequence FROM consumers WHERE name = ?1",
            params![name],
            |row| row.get(0),
        )?;
        let latest_sequence: i64 =
            tx.query_row("SELECT COALESCE(MAX(sequence), 0) FROM events", [], |row| {
                row.get(0)
            })?;

        if up_to_sequence < 0 || up_to_sequence > latest_sequence {
            return Err(ConsumerAckError::OutOfRange {
                consumer: name.to_string(),
                up_to_sequence,
                latest_sequence,
            });
        }

        let cursor_sequence = previous_cursor_sequence.max(up_to_sequence);
        let advanced = cursor_sequence > previous_cursor_sequence;
        if advanced {
            tx.execute(
                "UPDATE consumers SET cursor_sequence = ?2, last_acked_at = ?3, \
                 updated_at = ?3 WHERE name = ?1",
                params![name, cursor_sequence, &now],
            )?;
        } else {
            tx.execute(
                "UPDATE consumers SET last_acked_at = ?2, updated_at = ?2 WHERE name = ?1",
                params![name, &now],
            )?;
        }
        tx.commit()?;

        Ok(ConsumerAckOutcome {
            previous_cursor_sequence,
            cursor_sequence,
            advanced,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::NewEvent;
    use serde_json::json;

    fn repository() -> Repository {
        Repository::open_in_memory().unwrap()
    }

    fn ingest(repo: &Repository, id: &str, kind: &str) {
        repo.ingest_event(NewEvent {
            id: Some(id.into()),
            source: None,
            kind: kind.into(),
            payload: json!({"environment_id": "linux-main"}),
            occurred_at: Some("2026-11-16T01:00:00.000Z".into()),
        })
        .unwrap();
    }

    #[test]
    fn range_queries_honor_the_inclusive_upper_bound_and_ordering() {
        let repo = repository();
        for (id, kind) in [
            ("evt_1", "t3.run.failed"),
            ("evt_2", "t3.run.completed"),
            ("evt_3", "t3.run.completed"),
        ] {
            ingest(&repo, id, kind);
        }
        let kinds = vec!["t3.run.completed".to_string()];
        let filters = ConsumerEventFilter::default();

        let all = repo
            .list_consumer_events_in_range(0, None, &kinds, &filters, 10)
            .unwrap();
        assert_eq!(
            all.iter()
                .map(|event| event.id.as_str())
                .collect::<Vec<_>>(),
            vec!["evt_2", "evt_3"]
        );

        let bounded = repo
            .list_consumer_events_in_range(0, Some(2), &kinds, &filters, 10)
            .unwrap();
        assert_eq!(bounded.len(), 1);
        assert_eq!(bounded[0].id, "evt_2");

        let after = repo
            .list_consumer_events_in_range(1, Some(3), &kinds, &filters, 10)
            .unwrap();
        assert_eq!(
            after
                .iter()
                .map(|event| event.id.as_str())
                .collect::<Vec<_>>(),
            vec!["evt_2", "evt_3"]
        );
    }

    #[test]
    fn range_counts_are_bounded_and_kind_scoped() {
        let repo = repository();
        for (id, kind) in [
            ("evt_1", "t3.run.failed"),
            ("evt_2", "t3.run.completed"),
            ("evt_3", "t3.run.completed"),
        ] {
            ingest(&repo, id, kind);
        }
        let filters = ConsumerEventFilter::default();
        let immediate = vec!["t3.run.failed".to_string()];
        let digest = vec!["t3.run.completed".to_string()];

        assert_eq!(
            repo.count_consumer_events_in_range(0, None, &digest, &filters)
                .unwrap(),
            2
        );
        assert_eq!(
            repo.count_consumer_events_in_range(0, Some(2), &digest, &filters)
                .unwrap(),
            1
        );
        assert_eq!(
            repo.count_consumer_events_in_range(0, None, &immediate, &filters)
                .unwrap(),
            1
        );
        assert_eq!(
            repo.count_consumer_events_in_range(3, None, &immediate, &filters)
                .unwrap(),
            0
        );
        assert_eq!(
            repo.count_consumer_events_in_range(0, None, &[], &filters)
                .unwrap(),
            0
        );
    }
}
