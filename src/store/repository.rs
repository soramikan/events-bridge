//! SQLite persistence for events, subscriptions, deliveries and pull-tool
//! acknowledgements.
//!
//! The repository deliberately exposes synchronous methods. SQLite operations
//! are short and the daemon has a single writer, so callers may use it from
//! async tasks without a blocking pool; the connection is protected by a
//! `std::sync::Mutex` and is never held across an `.await`.

use std::{
    path::Path,
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

use anyhow::{Context, Result};
use chrono::{Duration as ChronoDuration, Utc};
use rusqlite::{Connection, OptionalExtension, Row, params, types::Value as SqlValue};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::migrations;
use crate::util::{format_rfc3339, now_rfc3339, parse_rfc3339};

/// Default lease before an abandoned `in_progress` delivery is reclaimed.
pub const DEFAULT_DELIVERY_LEASE: Duration = Duration::from_secs(300);

const EVENT_COLUMNS: &str = "id, sequence, source, kind, payload, occurred_at";

const SUBSCRIPTION_COLUMNS: &str = "id, principal, event_name, arguments, filter_hash, callback_url, \
     secret, delivery_mode, verified, active, created_at, updated_at, refresh_before, \
     last_delivery_at, last_error";

/// A durable event.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Event {
    /// Stable event identifier (`evt_...`).
    pub id: String,
    /// Local ingestion order.
    pub sequence: i64,
    /// Producing system (`t3` or `github`).
    pub source: String,
    /// Event name, e.g. `t3.run.completed`.
    pub kind: String,
    /// Validated event payload.
    pub payload: Value,
    /// When the upstream event happened (UTC RFC 3339).
    pub occurred_at: String,
}

/// An event waiting to be persisted.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewEvent {
    /// Optional caller-supplied id. Generated when absent.
    pub id: Option<String>,
    /// Optional source. Derived from the event name when absent.
    pub source: Option<String>,
    /// Event name.
    pub kind: String,
    /// Event payload.
    pub payload: Value,
    /// Upstream occurrence time. Defaults to now.
    pub occurred_at: Option<String>,
}

/// Result of persisting an event.
#[derive(Debug, Clone)]
pub struct IngestOutcome {
    /// The stored event (existing record when it was a duplicate).
    pub event: Event,
    /// Number of delivery rows created by this call.
    pub deliveries_created: usize,
    /// Whether the event id already existed.
    pub duplicate: bool,
}

/// A webhook subscription.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Subscription {
    /// Deterministic subscription id (`sub_...`).
    pub id: String,
    /// Authenticated principal that owns the subscription.
    pub principal: String,
    /// Subscribed event name.
    pub event_name: String,
    /// Normalized subscription arguments.
    pub arguments: Value,
    /// Hash of the canonical arguments.
    pub filter_hash: String,
    /// Callback URL.
    pub callback_url: String,
    /// Standard Webhooks signing secret.
    pub secret: String,
    /// Delivery mode; always `webhook` in Phase 1.
    pub delivery_mode: String,
    /// Whether the callback challenge succeeded.
    pub verified: bool,
    /// Whether delivery is enabled.
    pub active: bool,
    /// Creation timestamp.
    pub created_at: String,
    /// Last update timestamp.
    pub updated_at: String,
    /// Subscription expiry (`None` means no expiry).
    pub refresh_before: Option<String>,
    /// Last successful delivery timestamp.
    pub last_delivery_at: Option<String>,
    /// Last delivery error category.
    pub last_error: Option<String>,
}

/// Values needed to create or refresh a subscription.
#[derive(Clone)]
pub struct NewSubscription {
    /// Deterministic subscription id.
    pub id: String,
    /// Owning principal.
    pub principal: String,
    /// Event name.
    pub event_name: String,
    /// Normalized arguments.
    pub arguments: Value,
    /// Canonical-argument hash.
    pub filter_hash: String,
    /// Callback URL.
    pub callback_url: String,
    /// Signing secret.
    pub secret: String,
    /// Expiry timestamp.
    pub refresh_before: Option<String>,
}

/// A delivery that is due for an attempt.
#[derive(Debug, Clone)]
pub struct DueDelivery {
    /// Delivery row id.
    pub delivery_id: i64,
    /// Number of attempts already recorded.
    pub attempt_count: i64,
    /// Target subscription.
    pub subscription: Subscription,
    /// Event being delivered.
    pub event: Event,
}

/// Outcome of one delivery attempt, written atomically with the delivery state.
#[derive(Debug, Clone)]
pub struct AttemptOutcome<'a> {
    /// Delivery row id.
    pub delivery_id: i64,
    /// 1-based attempt number.
    pub attempt: i64,
    /// Observed HTTP status, if a response was received.
    pub status_code: Option<i64>,
    /// `success`, `retryable`, `permanent`, `network_error`, `exhausted` or `skipped`.
    pub outcome: &'a str,
    /// Error category or message.
    pub error: Option<&'a str>,
    /// New delivery status (`delivered`, `pending`, `failed`, `abandoned`).
    pub delivery_status: &'a str,
    /// Next attempt time for retryable outcomes.
    pub next_attempt_at: Option<&'a str>,
    /// Subscription the delivery belongs to.
    pub subscription_id: &'a str,
    /// Disable the subscription after a terminal failure (e.g. HTTP 410).
    pub disable_subscription: bool,
}

/// Outcome of validating and recording an edge request nonce inside the store
/// transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeNonceStatus {
    /// Nonce was accepted and persisted.
    Accepted,
    /// `(edge_id, nonce)` was already consumed and has not expired yet.
    Replayed,
    /// The request timestamp fell outside the accepted skew window by the time
    /// the transaction sampled the clock.
    TimestampOutOfWindow,
}

/// Filter for the `list_events` pull tool.
#[derive(Debug, Clone, Default)]
pub struct EventQuery {
    /// Inclusive lower bound on `occurred_at`.
    pub since: Option<String>,
    /// Inclusive upper bound on `occurred_at`.
    pub until: Option<String>,
    /// Restrict to one source.
    pub source: Option<String>,
    /// Restrict to one event name.
    pub kind: Option<String>,
    /// Restrict to a set of event names (severity filter).
    pub kinds: Option<Vec<String>>,
    /// Return events with `sequence > after_sequence`.
    pub after_sequence: Option<i64>,
    /// Maximum number of events (already clamped by the caller).
    pub limit: i64,
}

/// SQLite-backed state store.
#[derive(Clone)]
pub struct Repository {
    conn: Arc<Mutex<Connection>>,
}

impl std::fmt::Debug for Repository {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Repository").finish_non_exhaustive()
    }
}

impl Repository {
    /// Open (or create) the database at `path`, applying migrations.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating database directory {}", parent.display()))?;
        }
        let conn = Connection::open(path)
            .with_context(|| format!("opening sqlite database {}", path.display()))?;
        Self::from_connection(conn)
    }

    /// Open an in-memory database. Intended for tests.
    pub fn open_in_memory() -> Result<Self> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    fn from_connection(mut conn: Connection) -> Result<Self> {
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;
        // WAL is unavailable for in-memory databases; ignore the result there.
        let _ = conn.query_row("PRAGMA journal_mode = WAL", [], |row| {
            row.get::<_, String>(0)
        });
        migrations::run(&mut conn)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    fn lock(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().expect("sqlite mutex poisoned")
    }

    /// Borrow the writer connection for a module that owns an atomic batch.
    ///
    /// The guard must be dropped before awaiting anything. It exists so the T3
    /// collector can write its materialized state, ingested events, cursor and
    /// checkpoint in one transaction.
    pub(crate) fn lock_connection(&self) -> MutexGuard<'_, Connection> {
        self.lock()
    }

    /// Schema version currently applied.
    pub fn schema_version(&self) -> Result<i64> {
        Ok(migrations::current_version(&self.lock())?)
    }

    /// Outcome of validating and recording one edge request nonce.
    pub fn consume_edge_nonce_checked(
        &self,
        edge_id: &str,
        nonce: &str,
        timestamp: i64,
        max_skew_secs: u64,
    ) -> Result<EdgeNonceStatus> {
        self.consume_edge_nonce_checked_with_clock(edge_id, nonce, timestamp, max_skew_secs, || {
            Utc::now().timestamp()
        })
    }

    /// Deterministic clock-injected variant of [`Self::consume_edge_nonce_checked`].
    ///
    /// The clock is sampled only after acquiring the repository lock and
    /// starting the transaction, eliminating any second-boundary race between
    /// timestamp validation and nonce pruning.
    pub fn consume_edge_nonce_checked_at(
        &self,
        edge_id: &str,
        nonce: &str,
        timestamp: i64,
        max_skew_secs: u64,
        now: i64,
    ) -> Result<EdgeNonceStatus> {
        self.consume_edge_nonce_checked_with_clock(edge_id, nonce, timestamp, max_skew_secs, || now)
    }

    fn consume_edge_nonce_checked_with_clock(
        &self,
        edge_id: &str,
        nonce: &str,
        timestamp: i64,
        max_skew_secs: u64,
        now_fn: impl FnOnce() -> i64,
    ) -> Result<EdgeNonceStatus> {
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        let now = now_fn();
        if now.abs_diff(timestamp) > max_skew_secs {
            return Ok(EdgeNonceStatus::TimestampOutOfWindow);
        }
        let max_skew = max_skew_secs.min(i64::MAX as u64) as i64;
        let expires_at = timestamp.saturating_add(max_skew);
        tx.execute(
            "DELETE FROM edge_nonces WHERE expires_at < ?1",
            params![now],
        )?;
        let inserted = tx.execute(
            "INSERT OR IGNORE INTO edge_nonces (edge_id, nonce, expires_at) \
             VALUES (?1, ?2, ?3)",
            params![edge_id, nonce, expires_at],
        )?;
        tx.commit()?;
        if inserted > 0 {
            Ok(EdgeNonceStatus::Accepted)
        } else {
            Ok(EdgeNonceStatus::Replayed)
        }
    }

    /// Record an edge nonce, returning `false` when it was already used.
    ///
    /// Expired nonces are deleted in the same transaction, so the table stays
    /// bounded by the accepted timestamp window.
    pub fn consume_edge_nonce(&self, edge_id: &str, nonce: &str, expires_at: i64) -> Result<bool> {
        self.consume_edge_nonce_at(edge_id, nonce, expires_at, Utc::now().timestamp())
    }

    /// Deterministic clock-injected variant of [`Self::consume_edge_nonce`].
    pub fn consume_edge_nonce_at(
        &self,
        edge_id: &str,
        nonce: &str,
        expires_at: i64,
        now: i64,
    ) -> Result<bool> {
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        tx.execute(
            "DELETE FROM edge_nonces WHERE expires_at < ?1",
            params![now],
        )?;
        let inserted = tx.execute(
            "INSERT OR IGNORE INTO edge_nonces (edge_id, nonce, expires_at) \
             VALUES (?1, ?2, ?3)",
            params![edge_id, nonce, expires_at],
        )?;
        tx.commit()?;
        Ok(inserted > 0)
    }

    /// Number of retained edge nonces (tests and diagnostics).
    pub fn edge_nonce_count(&self) -> Result<i64> {
        Ok(self
            .lock()
            .query_row("SELECT COUNT(*) FROM edge_nonces", [], |row| row.get(0))?)
    }

    /// Persist an event and create delivery rows for every eligible
    /// subscription in one transaction.
    ///
    /// The caller is responsible for waking the dispatcher after this returns.
    pub fn ingest_event(&self, new: NewEvent) -> Result<IngestOutcome> {
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        let outcome = ingest_event_in_tx(&tx, new, &now_rfc3339())?;
        tx.commit()?;
        Ok(outcome)
    }

    /// Fetch an event by id.
    pub fn get_event(&self, id: &str) -> Result<Option<Event>> {
        Ok(load_event(&self.lock(), id)?)
    }

    /// List events for the pull tool.
    pub fn list_events(&self, query: &EventQuery) -> Result<Vec<Event>> {
        let mut sql = format!("SELECT {EVENT_COLUMNS} FROM events WHERE 1 = 1");
        let mut args: Vec<SqlValue> = Vec::new();

        if let Some(since) = &query.since {
            sql.push_str(" AND occurred_at >= ?");
            args.push(SqlValue::Text(since.clone()));
        }
        if let Some(until) = &query.until {
            sql.push_str(" AND occurred_at <= ?");
            args.push(SqlValue::Text(until.clone()));
        }
        if let Some(source) = &query.source {
            sql.push_str(" AND source = ?");
            args.push(SqlValue::Text(source.clone()));
        }
        if let Some(kind) = &query.kind {
            sql.push_str(" AND kind = ?");
            args.push(SqlValue::Text(kind.clone()));
        }
        if let Some(kinds) = &query.kinds {
            if kinds.is_empty() {
                sql.push_str(" AND 1 = 0");
            } else {
                let placeholders = vec!["?"; kinds.len()].join(", ");
                sql.push_str(&format!(" AND kind IN ({placeholders})"));
                args.extend(kinds.iter().cloned().map(SqlValue::Text));
            }
        }
        if let Some(after) = query.after_sequence {
            sql.push_str(" AND sequence > ?");
            args.push(SqlValue::Integer(after));
        }
        sql.push_str(" ORDER BY sequence ASC LIMIT ?");
        args.push(SqlValue::Integer(query.limit.max(1)));

        let conn = self.lock();
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(args.iter()), map_event)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Record user acknowledgements. Webhook delivery state is unaffected.
    pub fn ack_events(&self, principal: &str, event_ids: &[String]) -> Result<Vec<String>> {
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        let now = now_rfc3339();
        let mut acknowledged = Vec::new();
        for id in event_ids {
            let inserted = tx.execute(
                "INSERT OR IGNORE INTO acks (principal, event_id, acknowledged_at) \
                 VALUES (?1, ?2, ?3)",
                params![principal, id, now],
            )?;
            if inserted > 0 {
                acknowledged.push(id.clone());
            }
        }
        tx.commit()?;
        Ok(acknowledged)
    }

    /// Whether a principal acknowledged an event.
    pub fn is_acknowledged(&self, principal: &str, event_id: &str) -> Result<bool> {
        let conn = self.lock();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM acks WHERE principal = ?1 AND event_id = ?2",
            params![principal, event_id],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Insert or refresh a verified subscription.
    pub fn upsert_subscription(&self, new: NewSubscription) -> Result<Subscription> {
        let arguments = serde_json::to_string(&new.arguments)?;
        let now = now_rfc3339();
        let mut conn = self.lock();
        let tx = conn.transaction()?;

        // If the prior subscription had already been deactivated, unverified, or
        // expired before this refresh arrived, terminalize its stale backlog
        // before resetting `active` / `refresh_before`.
        tx.execute(
            "UPDATE deliveries SET status = 'failed', updated_at = ?2 \
             WHERE subscription_id = ?1 \
               AND status IN ('pending', 'in_progress') \
               AND EXISTS ( \
                   SELECT 1 FROM subscriptions s \
                   WHERE s.id = ?1 \
                     AND (s.active = 0 OR s.verified = 0 \
                          OR (s.refresh_before IS NOT NULL AND s.refresh_before <= ?2)) \
               )",
            params![new.id, now],
        )?;

        tx.execute(
            "INSERT INTO subscriptions \
                 (id, principal, event_name, arguments, filter_hash, callback_url, secret, \
                  delivery_mode, verified, active, created_at, updated_at, refresh_before) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'webhook', 1, 1, ?8, ?8, ?9) \
             ON CONFLICT (id) DO UPDATE SET \
                 secret = excluded.secret, \
                 verified = 1, \
                 active = 1, \
                 updated_at = excluded.updated_at, \
                 refresh_before = excluded.refresh_before, \
                 last_error = NULL",
            params![
                new.id,
                new.principal,
                new.event_name,
                arguments,
                new.filter_hash,
                new.callback_url,
                new.secret,
                now,
                new.refresh_before,
            ],
        )?;
        let subscription =
            load_subscription(&tx, &new.id)?.context("subscription disappeared after upsert")?;
        tx.commit()?;
        Ok(subscription)
    }

    /// Fetch a subscription by id.
    pub fn get_subscription(&self, id: &str) -> Result<Option<Subscription>> {
        Ok(load_subscription(&self.lock(), id)?)
    }

    /// Look up a subscription by its compound key.
    pub fn get_subscription_by_key(
        &self,
        principal: &str,
        callback_url: &str,
        event_name: &str,
        filter_hash: &str,
    ) -> Result<Option<Subscription>> {
        let conn = self.lock();
        let sql = format!(
            "SELECT {SUBSCRIPTION_COLUMNS} FROM subscriptions \
             WHERE principal = ?1 AND callback_url = ?2 AND event_name = ?3 AND filter_hash = ?4"
        );
        Ok(conn
            .query_row(
                &sql,
                params![principal, callback_url, event_name, filter_hash],
                map_subscription,
            )
            .optional()?)
    }

    /// Delete a subscription by id, scoped to its owner.
    pub fn delete_subscription_by_id(&self, principal: &str, id: &str) -> Result<bool> {
        let conn = self.lock();
        let changed = conn.execute(
            "DELETE FROM subscriptions WHERE principal = ?1 AND id = ?2",
            params![principal, id],
        )?;
        Ok(changed > 0)
    }

    /// Delete a subscription by its compound key, scoped to its owner.
    pub fn delete_subscription_by_key(
        &self,
        principal: &str,
        callback_url: &str,
        event_name: &str,
        filter_hash: &str,
    ) -> Result<bool> {
        let conn = self.lock();
        let changed = conn.execute(
            "DELETE FROM subscriptions \
             WHERE principal = ?1 AND callback_url = ?2 AND event_name = ?3 AND filter_hash = ?4",
            params![principal, callback_url, event_name, filter_hash],
        )?;
        Ok(changed > 0)
    }

    /// Enable or disable a subscription.
    pub fn set_subscription_active(&self, id: &str, active: bool) -> Result<()> {
        let conn = self.lock();
        conn.execute(
            "UPDATE subscriptions SET active = ?2, updated_at = ?3 WHERE id = ?1",
            params![id, if active { 1_i64 } else { 0_i64 }, now_rfc3339()],
        )?;
        Ok(())
    }

    /// List all subscriptions (diagnostics and tests).
    pub fn list_subscriptions(&self) -> Result<Vec<Subscription>> {
        let conn = self.lock();
        let sql =
            format!("SELECT {SUBSCRIPTION_COLUMNS} FROM subscriptions ORDER BY created_at, id");
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], map_subscription)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Mark stale `in_progress` rows as `pending`. Called once at dispatcher
    /// start so deliveries interrupted by a crash are retried. Rows whose
    /// lease has not yet expired are left untouched.
    pub fn reset_in_progress_deliveries(&self, lease: Duration) -> Result<usize> {
        let now = now_rfc3339();
        let lease_secs = lease.as_secs().min(i64::MAX as u64) as i64;
        let lease_cutoff = format_rfc3339(Utc::now() - ChronoDuration::seconds(lease_secs));
        let conn = self.lock();
        let changed = conn.execute(
            "UPDATE deliveries SET status = 'pending', updated_at = ?1 \
             WHERE status = 'in_progress' AND updated_at <= ?2",
            params![now, lease_cutoff],
        )?;
        Ok(changed)
    }

    /// Claim one due delivery for this worker using the default lease.
    pub fn claim_next_due(&self) -> Result<Option<DueDelivery>> {
        self.claim_next_due_with_lease(DEFAULT_DELIVERY_LEASE)
    }

    /// Claim one due delivery, reclaiming `in_progress` rows whose lease has
    /// expired.
    ///
    /// Only deliveries whose subscription is still verified, active and
    /// unexpired are claimable. Pending deliveries that fail those conditions
    /// are terminalized as `failed` instead of being silently retried, and a
    /// disabled or expired subscription can never deliver queued backlog.
    pub fn claim_next_due_with_lease(&self, lease: Duration) -> Result<Option<DueDelivery>> {
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        let now = now_rfc3339();
        let lease_secs = lease.as_secs().min(i64::MAX as u64) as i64;
        let lease_cutoff = format_rfc3339(Utc::now() - ChronoDuration::seconds(lease_secs));

        // A subscription that was disabled (e.g. HTTP 410), unverified or that
        // reached `refresh_before` must not deliver anything else.
        let ineligible = "SELECT id FROM subscriptions \
             WHERE active = 0 OR verified = 0 \
                OR (refresh_before IS NOT NULL AND refresh_before <= ?1)";
        tx.execute(
            &format!(
                "UPDATE deliveries SET status = 'failed', updated_at = ?1 \
                 WHERE status = 'pending' AND subscription_id IN ({ineligible})"
            ),
            params![now],
        )?;
        tx.execute(
            &format!(
                "UPDATE deliveries SET status = 'failed', updated_at = ?1 \
                 WHERE status = 'in_progress' AND subscription_id IN ({ineligible})"
            ),
            params![now],
        )?;

        // Recover rows abandoned by a crashed worker (or a failed
        // `finish_attempt`) once their lease has elapsed.
        tx.execute(
            "UPDATE deliveries SET status = 'pending', updated_at = ?1 \
             WHERE status = 'in_progress' AND updated_at <= ?2 \
               AND subscription_id IN ( \
                   SELECT id FROM subscriptions \
                   WHERE active = 1 AND verified = 1 \
                     AND (refresh_before IS NULL OR refresh_before > ?1))",
            params![now, lease_cutoff],
        )?;

        let row = tx
            .query_row(
                "SELECT d.id, d.subscription_id, d.event_id, d.attempt_count \
                 FROM deliveries d JOIN subscriptions s ON s.id = d.subscription_id \
                 WHERE d.status = 'pending' AND d.next_attempt_at <= ?1 \
                   AND s.active = 1 AND s.verified = 1 \
                   AND (s.refresh_before IS NULL OR s.refresh_before > ?1) \
                 ORDER BY d.next_attempt_at, d.id LIMIT 1",
                params![now],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()?;

        let Some((delivery_id, subscription_id, event_id, attempt_count)) = row else {
            tx.commit()?;
            return Ok(None);
        };

        let claimed = tx.execute(
            "UPDATE deliveries SET status = 'in_progress', updated_at = ?2 \
             WHERE id = ?1 AND status = 'pending'",
            params![delivery_id, now],
        )?;
        if claimed == 0 {
            tx.commit()?;
            return Ok(None);
        }

        let subscription = load_subscription(&tx, &subscription_id)?;
        let event = load_event(&tx, &event_id)?;
        tx.commit()?;

        match (subscription, event) {
            (Some(subscription), Some(event)) => Ok(Some(DueDelivery {
                delivery_id,
                attempt_count,
                subscription,
                event,
            })),
            // Foreign keys make this unreachable, but skip rather than panic.
            _ => {
                conn.execute(
                    "UPDATE deliveries SET status = 'failed', updated_at = ?2 WHERE id = ?1",
                    params![delivery_id, now_rfc3339()],
                )?;
                Ok(None)
            }
        }
    }

    /// Number of pending deliveries (tests and metrics).
    pub fn pending_delivery_count(&self) -> Result<i64> {
        let conn = self.lock();
        let count = conn.query_row(
            "SELECT COUNT(*) FROM deliveries WHERE status IN ('pending', 'in_progress')",
            [],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    /// Earliest `next_attempt_at` among pending deliveries.
    pub fn next_pending_at(&self) -> Result<Option<String>> {
        let conn = self.lock();
        Ok(conn
            .query_row(
                "SELECT MIN(next_attempt_at) FROM deliveries WHERE status = 'pending'",
                [],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten())
    }

    /// Delivery state by event id (tests).
    pub fn delivery_statuses(&self, event_id: &str) -> Result<Vec<(String, String, i64)>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT subscription_id, status, attempt_count FROM deliveries \
             WHERE event_id = ?1 ORDER BY id",
        )?;
        let rows = stmt.query_map(params![event_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Attempt history for one delivery (tests).
    pub fn attempts(&self, delivery_id: i64) -> Result<Vec<(i64, Option<i64>, String)>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT attempt, status_code, outcome FROM delivery_attempts \
             WHERE delivery_id = ?1 ORDER BY id",
        )?;
        let rows = stmt.query_map(params![delivery_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Option<i64>>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Atomically record an attempt and apply the resulting delivery state.
    pub fn finish_attempt(&self, outcome: AttemptOutcome<'_>) -> Result<()> {
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        let now = now_rfc3339();

        tx.execute(
            "INSERT INTO delivery_attempts \
                 (delivery_id, attempt, status_code, outcome, error, attempted_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                outcome.delivery_id,
                outcome.attempt,
                outcome.status_code,
                outcome.outcome,
                outcome.error,
                now
            ],
        )?;

        let next_attempt_at = outcome.next_attempt_at.unwrap_or(&now);
        let updated = tx.execute(
            "UPDATE deliveries SET status = ?2, attempt_count = ?3, next_attempt_at = ?4, \
                 updated_at = ?5 WHERE id = ?1 AND status = 'in_progress'",
            params![
                outcome.delivery_id,
                outcome.delivery_status,
                outcome.attempt,
                next_attempt_at,
                now
            ],
        )?;
        if updated == 0 {
            // The claim was lost (for example, when a subscription refresh
            // terminalized the row while a delivery attempt was in flight).
            // Keep the attempt audit row, but do not alter delivery or
            // subscription state.
            tx.commit()?;
            return Ok(());
        }

        if outcome.delivery_status == "delivered" {
            tx.execute(
                "UPDATE subscriptions SET last_delivery_at = ?2, last_error = NULL, \
                     updated_at = ?2 WHERE id = ?1",
                params![outcome.subscription_id, now],
            )?;
        } else if outcome.disable_subscription {
            tx.execute(
                "UPDATE subscriptions SET last_error = ?2, updated_at = ?3, active = 0 \
                 WHERE id = ?1",
                params![outcome.subscription_id, outcome.error, now],
            )?;
            // A 410 disables the subscription; its remaining backlog must not
            // be attempted after the endpoint said it no longer exists.
            tx.execute(
                "UPDATE deliveries SET status = 'failed', updated_at = ?2 \
                 WHERE subscription_id = ?1 AND status = 'pending'",
                params![outcome.subscription_id, now],
            )?;
        } else {
            tx.execute(
                "UPDATE subscriptions SET last_error = ?2, updated_at = ?3 WHERE id = ?1",
                params![outcome.subscription_id, outcome.error, now],
            )?;
        }

        tx.commit()?;
        Ok(())
    }
}

/// Insert one event and its delivery rows inside an existing transaction.
///
/// `ingested_at` is reused for all timestamps so an atomic collector batch has
/// a consistent ingestion time. A duplicate event id is a no-op that returns
/// the stored row.
pub(crate) fn ingest_event_in_tx(
    tx: &rusqlite::Transaction<'_>,
    new: NewEvent,
    ingested_at: &str,
) -> Result<IngestOutcome> {
    let id = new
        .id
        .unwrap_or_else(|| format!("evt_{}", crate::util::random_hex(12)));
    // `occurred_at` must be RFC 3339. It is normalized to the fixed-width UTC
    // form so range predicates are reliable and comparable as text.
    let occurred_at = match new.occurred_at {
        Some(value) => parse_rfc3339(&value)
            .map(format_rfc3339)
            .with_context(|| format!("occurred_at `{value}` is not a valid RFC 3339 timestamp"))?,
        None => now_rfc3339(),
    };
    let source = new
        .source
        .unwrap_or_else(|| new.kind.split('.').next().unwrap_or("unknown").to_owned());
    let payload = serde_json::to_string(&new.payload)?;

    if let Some(existing) = load_event(tx, &id)? {
        return Ok(IngestOutcome {
            event: existing,
            deliveries_created: 0,
            duplicate: true,
        });
    }

    let sequence: i64 = tx.query_row(
        "SELECT COALESCE(MAX(sequence), 0) + 1 FROM events",
        [],
        |row| row.get(0),
    )?;
    tx.execute(
        "INSERT INTO events (id, sequence, source, kind, payload, occurred_at, ingested_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            id,
            sequence,
            source,
            new.kind,
            payload,
            occurred_at,
            ingested_at
        ],
    )?;

    let subscriptions = {
        let mut stmt = tx.prepare(
            "SELECT id, arguments FROM subscriptions \
             WHERE event_name = ?1 AND verified = 1 AND active = 1 \
               AND (refresh_before IS NULL OR refresh_before > ?2) \
             ORDER BY id",
        )?;
        let rows = stmt.query_map(params![new.kind, ingested_at], |row| {
            let arguments: String = row.get(1)?;
            Ok((row.get::<_, String>(0)?, arguments))
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    };

    let mut deliveries_created = 0usize;
    {
        let mut stmt = tx.prepare(
            "INSERT OR IGNORE INTO deliveries \
                 (subscription_id, event_id, status, next_attempt_at, created_at, updated_at) \
             VALUES (?1, ?2, 'pending', ?3, ?3, ?3)",
        )?;
        for (subscription_id, arguments) in subscriptions {
            // A subscription only receives events whose payload satisfies
            // every filter argument. An empty filter matches everything.
            // Unparseable arguments must never match; `Null` is treated
            // as a non-object filter by `arguments_match`.
            let arguments: Value = serde_json::from_str(&arguments).unwrap_or(Value::Null);
            if !arguments_match(&arguments, &new.payload) {
                continue;
            }
            deliveries_created += stmt.execute(params![subscription_id, id, ingested_at])?;
        }
    }

    let event = load_event(tx, &id)?.expect("event inserted in this transaction");
    Ok(IngestOutcome {
        event,
        deliveries_created,
        duplicate: false,
    })
}

impl std::fmt::Debug for Subscription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Subscription")
            .field("id", &self.id)
            .field("principal", &self.principal)
            .field("event_name", &self.event_name)
            .field("callback_url", &self.callback_url)
            .field("verified", &self.verified)
            .field("active", &self.active)
            .field("secret", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for NewSubscription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewSubscription")
            .field("id", &self.id)
            .field("principal", &self.principal)
            .field("event_name", &self.event_name)
            .field("callback_url", &self.callback_url)
            .field("secret", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// Whether an event payload satisfies a subscription filter.
///
/// Every key/value pair in `arguments` must be present with an equal value in
/// the payload. An empty filter object matches every payload.
fn arguments_match(arguments: &Value, payload: &Value) -> bool {
    let Some(filter) = arguments.as_object() else {
        return false;
    };
    if filter.is_empty() {
        return true;
    }
    let Some(payload) = payload.as_object() else {
        return false;
    };
    filter
        .iter()
        .all(|(key, expected)| payload.get(key) == Some(expected))
}

fn load_event(conn: &Connection, id: &str) -> rusqlite::Result<Option<Event>> {
    let sql = format!("SELECT {EVENT_COLUMNS} FROM events WHERE id = ?1");
    conn.query_row(&sql, params![id], map_event).optional()
}

fn load_subscription(conn: &Connection, id: &str) -> rusqlite::Result<Option<Subscription>> {
    let sql = format!("SELECT {SUBSCRIPTION_COLUMNS} FROM subscriptions WHERE id = ?1");
    conn.query_row(&sql, params![id], map_subscription)
        .optional()
}

fn map_event(row: &Row<'_>) -> rusqlite::Result<Event> {
    let payload: String = row.get(4)?;
    Ok(Event {
        id: row.get(0)?,
        sequence: row.get(1)?,
        source: row.get(2)?,
        kind: row.get(3)?,
        payload: serde_json::from_str(&payload).unwrap_or(Value::Null),
        occurred_at: row.get(5)?,
    })
}

fn map_subscription(row: &Row<'_>) -> rusqlite::Result<Subscription> {
    let arguments: String = row.get(3)?;
    Ok(Subscription {
        id: row.get(0)?,
        principal: row.get(1)?,
        event_name: row.get(2)?,
        arguments: serde_json::from_str(&arguments).unwrap_or(Value::Null),
        filter_hash: row.get(4)?,
        callback_url: row.get(5)?,
        secret: row.get(6)?,
        delivery_mode: row.get(7)?,
        verified: row.get::<_, i64>(8)? != 0,
        active: row.get::<_, i64>(9)? != 0,
        created_at: row.get(10)?,
        updated_at: row.get(11)?,
        refresh_before: row.get(12)?,
        last_delivery_at: row.get(13)?,
        last_error: row.get(14)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
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

    fn repository() -> Repository {
        Repository::open_in_memory().expect("in-memory repository")
    }

    fn subscription(repo: &Repository, kind: &str) -> Subscription {
        repo.upsert_subscription(NewSubscription {
            id: format!("sub_{kind}"),
            principal: "local".into(),
            event_name: kind.into(),
            arguments: json!({"environment_id": "linux-main"}),
            filter_hash: "hash".into(),
            callback_url: "https://receiver.example.com/hook".into(),
            secret: test_secret(),
            refresh_before: None,
        })
        .expect("upsert")
    }

    #[test]
    fn migrations_create_every_table() {
        let repo = repository();
        assert_eq!(repo.schema_version().unwrap(), 4);
        let conn = repo.lock();
        let mut stmt = conn
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
            .unwrap();
        let names: Vec<String> = stmt
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        for expected in [
            "acks",
            "collector_checkpoints",
            "delivery_attempts",
            "deliveries",
            "edge_nonces",
            "edge_pending_snapshots",
            "edge_snapshot_stages",
            "events",
            "github_ci_runs",
            "github_deliveries",
            "github_pending_checks",
            "github_pull_requests",
            "source_cursors",
            "subscriptions",
            "t3_approvals",
            "t3_projects",
            "t3_runs",
            "t3_threads",
        ] {
            assert!(
                names.iter().any(|n| n == expected),
                "missing {expected}: {names:?}"
            );
        }
    }

    #[test]
    fn edge_nonces_reject_replay_and_expire() {
        let repo = repository();
        let t = 1_700_000_000_i64;
        assert!(
            repo.consume_edge_nonce_at("edge-1", "nonce-1", t + 60, t)
                .unwrap()
        );
        assert!(
            !repo
                .consume_edge_nonce_at("edge-1", "nonce-1", t + 60, t)
                .unwrap(),
            "the same (edge_id, nonce) must be rejected"
        );
        assert!(
            repo.consume_edge_nonce_at("edge-2", "nonce-1", t + 60, t)
                .unwrap(),
            "a different edge may use the same nonce"
        );

        repo.lock()
            .execute(
                "INSERT INTO edge_nonces (edge_id, nonce, expires_at) VALUES (?1, ?2, ?3)",
                params!["edge-boundary", "nonce-boundary", t],
            )
            .unwrap();
        repo.lock()
            .execute(
                "INSERT INTO edge_nonces (edge_id, nonce, expires_at) VALUES (?1, ?2, ?3)",
                params!["edge-old", "nonce-old", t - 1],
            )
            .unwrap();
        assert!(
            repo.consume_edge_nonce_at("edge-3", "nonce-3", t + 60, t)
                .unwrap()
        );
        assert!(
            !repo
                .consume_edge_nonce_at("edge-boundary", "nonce-boundary", t + 60, t)
                .unwrap(),
            "a nonce expiring at the current boundary second must still reject replay"
        );
        assert_eq!(
            repo.edge_nonce_count().unwrap(),
            4,
            "the expired row is deleted while the boundary-second and active nonces are retained"
        );
        let expired: i64 = repo
            .lock()
            .query_row(
                "SELECT COUNT(*) FROM edge_nonces WHERE edge_id = 'edge-old'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(expired, 0, "expired nonces are deleted on the next insert");

        // Boundary and second-crossing TOCTOU regression:
        // Request with `timestamp = t + 1` and `max_skew = 1` expires at `t + 2`.
        assert_eq!(
            repo.consume_edge_nonce_checked_at("edge-skew", "nonce-skew", t + 1, 1, t)
                .unwrap(),
            EdgeNonceStatus::Accepted
        );
        // At `t + 2` (exact upper skew boundary), pruning runs and replay is still rejected.
        assert_eq!(
            repo.consume_edge_nonce_checked_at("edge-skew", "nonce-other", t + 2, 1, t + 2)
                .unwrap(),
            EdgeNonceStatus::Accepted
        );
        assert_eq!(
            repo.consume_edge_nonce_checked_at("edge-skew", "nonce-skew", t + 1, 1, t + 2)
                .unwrap(),
            EdgeNonceStatus::Replayed
        );
        // If HTTP pre-checked at `t + 2` but the clock crossed to `t + 3` before the
        // DB transaction acquired the lock, the transaction rejects with
        // TimestampOutOfWindow and never deletes-and-reinserts the old nonce.
        assert_eq!(
            repo.consume_edge_nonce_checked_at("edge-skew", "nonce-skew", t + 1, 1, t + 3)
                .unwrap(),
            EdgeNonceStatus::TimestampOutOfWindow
        );
        // And `nonce-skew` is only pruned once a valid request arrives at `t + 3`.
        assert_eq!(
            repo.consume_edge_nonce_checked_at("edge-skew", "nonce-prune", t + 3, 1, t + 3)
                .unwrap(),
            EdgeNonceStatus::Accepted
        );
        let remaining_skew: i64 = repo
            .lock()
            .query_row(
                "SELECT COUNT(*) FROM edge_nonces WHERE edge_id = 'edge-skew' AND nonce = 'nonce-skew'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(remaining_skew, 0);
    }

    #[test]
    fn deliveries_are_unique_per_subscription_and_event() {
        let repo = repository();
        subscription(&repo, "t3.run.completed");
        let outcome = repo
            .ingest_event(NewEvent {
                id: Some("evt_1".into()),
                source: None,
                kind: "t3.run.completed".into(),
                payload: json!({"environment_id": "linux-main"}),
                occurred_at: None,
            })
            .unwrap();
        assert_eq!(outcome.deliveries_created, 1);

        // Re-ingesting the same event id is a no-op.
        let duplicate = repo
            .ingest_event(NewEvent {
                id: Some("evt_1".into()),
                source: None,
                kind: "t3.run.completed".into(),
                payload: json!({"environment_id": "linux-main"}),
                occurred_at: None,
            })
            .unwrap();
        assert!(duplicate.duplicate);
        assert_eq!(duplicate.deliveries_created, 0);
        assert_eq!(repo.pending_delivery_count().unwrap(), 1);
    }

    #[test]
    fn unverified_subscriptions_receive_no_deliveries() {
        let repo = repository();
        repo.upsert_subscription(NewSubscription {
            id: "sub_unverified".into(),
            principal: "local".into(),
            event_name: "t3.run.completed".into(),
            arguments: json!({}),
            filter_hash: "hash".into(),
            callback_url: "https://receiver.example.com/hook".into(),
            secret: test_secret(),
            refresh_before: None,
        })
        .unwrap();
        repo.set_subscription_active("sub_unverified", false)
            .unwrap();
        let outcome = repo
            .ingest_event(NewEvent {
                id: Some("evt_2".into()),
                source: None,
                kind: "t3.run.completed".into(),
                payload: json!({}),
                occurred_at: None,
            })
            .unwrap();
        assert_eq!(outcome.deliveries_created, 0);
    }

    #[test]
    fn list_events_filters_and_paginates() {
        let repo = repository();
        for (index, kind) in ["t3.run.completed", "github.pr.merged", "t3.run.failed"]
            .iter()
            .enumerate()
        {
            repo.ingest_event(NewEvent {
                id: Some(format!("evt_{index}")),
                source: None,
                kind: (*kind).into(),
                payload: json!({}),
                occurred_at: None,
            })
            .unwrap();
        }

        let all = repo
            .list_events(&EventQuery {
                limit: 10,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].sequence, 1);

        let t3 = repo
            .list_events(&EventQuery {
                source: Some("t3".into()),
                limit: 10,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(t3.len(), 2);

        let page = repo
            .list_events(&EventQuery {
                after_sequence: Some(1),
                limit: 1,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].id, "evt_1");
    }

    #[test]
    fn acks_are_idempotent_and_separate_from_delivery() {
        let repo = repository();
        repo.ingest_event(NewEvent {
            id: Some("evt_ack".into()),
            source: None,
            kind: "t3.run.failed".into(),
            payload: json!({}),
            occurred_at: None,
        })
        .unwrap();
        let first = repo.ack_events("local", &["evt_ack".into()]).unwrap();
        assert_eq!(first, vec!["evt_ack".to_string()]);
        let second = repo.ack_events("local", &["evt_ack".into()]).unwrap();
        assert!(second.is_empty());
        assert!(repo.is_acknowledged("local", "evt_ack").unwrap());
        assert!(!repo.is_acknowledged("other", "evt_ack").unwrap());
    }

    #[test]
    fn ack_events_rolls_back_the_batch_on_failure() {
        let repo = repository();
        for id in ["evt_ack_a", "evt_ack_b"] {
            repo.ingest_event(NewEvent {
                id: Some(id.into()),
                source: None,
                kind: "t3.run.failed".into(),
                payload: json!({}),
                occurred_at: None,
            })
            .unwrap();
        }

        let result = repo.ack_events(
            "local",
            &["evt_ack_a".into(), "evt_missing".into(), "evt_ack_b".into()],
        );
        assert!(result.is_err(), "missing event must fail the batch");
        assert!(!repo.is_acknowledged("local", "evt_ack_a").unwrap());
        assert!(!repo.is_acknowledged("local", "evt_ack_b").unwrap());
    }

    #[test]
    fn interrupted_deliveries_are_recovered() {
        let repo = repository();
        subscription(&repo, "t3.run.completed");
        repo.ingest_event(NewEvent {
            id: Some("evt_recover".into()),
            source: None,
            kind: "t3.run.completed".into(),
            payload: json!({"environment_id": "linux-main"}),
            occurred_at: None,
        })
        .unwrap();

        let due = repo.claim_next_due().unwrap().expect("due delivery");
        assert_eq!(due.delivery_id, 1);

        // An active lease must not be reset.
        assert_eq!(
            repo.reset_in_progress_deliveries(Duration::from_secs(60))
                .unwrap(),
            0
        );
        assert_eq!(
            repo.delivery_statuses("evt_recover").unwrap()[0].1,
            "in_progress"
        );

        // An expired lease is recovered.
        assert!(repo.reset_in_progress_deliveries(Duration::ZERO).unwrap() >= 1);
        let again = repo.claim_next_due().unwrap().expect("recovered delivery");
        assert_eq!(again.delivery_id, 1);
    }

    #[test]
    fn subscription_arguments_filter_delivery_targets() {
        let repo = repository();
        for (id, kind, arguments) in [
            (
                "sub_env",
                "t3.run.completed",
                json!({"environment_id": "linux-main"}),
            ),
            (
                "sub_project",
                "t3.run.completed",
                json!({"environment_id": "linux-main", "project_id": "lnako"}),
            ),
            (
                "sub_repo",
                "github.pr.merged",
                json!({"repository": "soramikan/events-bridge"}),
            ),
            ("sub_all", "t3.run.completed", json!({})),
        ] {
            repo.upsert_subscription(NewSubscription {
                id: id.into(),
                principal: "local".into(),
                event_name: kind.into(),
                arguments,
                filter_hash: format!("hash-{id}"),
                callback_url: format!("https://receiver.example.com/{id}"),
                secret: test_secret(),
                refresh_before: None,
            })
            .unwrap();
        }

        // Different environment_id and project_id must not match either filter.
        let mismatched = repo
            .ingest_event(NewEvent {
                id: Some("evt_mismatch".into()),
                source: None,
                kind: "t3.run.completed".into(),
                payload: json!({"environment_id": "other-host", "project_id": "other"}),
                occurred_at: None,
            })
            .unwrap();
        // Only the wildcard subscription matches.
        assert_eq!(mismatched.deliveries_created, 1);

        // A matching environment but a different project must not reach the
        // project-scoped subscription.
        let project_mismatch = repo
            .ingest_event(NewEvent {
                id: Some("evt_project".into()),
                source: None,
                kind: "t3.run.completed".into(),
                payload: json!({"environment_id": "linux-main", "project_id": "other"}),
                occurred_at: None,
            })
            .unwrap();
        assert_eq!(project_mismatch.deliveries_created, 2);

        // A different repository must not reach the GitHub subscription.
        let repo_mismatch = repo
            .ingest_event(NewEvent {
                id: Some("evt_repo".into()),
                source: None,
                kind: "github.pr.merged".into(),
                payload: json!({"repository": "other/repo", "pull_number": 1,
                                "title": "t", "url": "https://example.com"}),
                occurred_at: None,
            })
            .unwrap();
        assert_eq!(repo_mismatch.deliveries_created, 0);

        let matching_repo = repo
            .ingest_event(NewEvent {
                id: Some("evt_repo_ok".into()),
                source: None,
                kind: "github.pr.merged".into(),
                payload: json!({"repository": "soramikan/events-bridge", "pull_number": 2,
                                "title": "t", "url": "https://example.com"}),
                occurred_at: None,
            })
            .unwrap();
        assert_eq!(matching_repo.deliveries_created, 1);
    }

    #[test]
    fn occurred_at_is_validated_and_normalized_to_utc() {
        let repo = repository();
        let error = repo
            .ingest_event(NewEvent {
                id: Some("evt_bad_time".into()),
                source: None,
                kind: "t3.run.completed".into(),
                payload: json!({"environment_id": "linux-main"}),
                occurred_at: Some("not-a-timestamp".into()),
            })
            .expect_err("invalid occurred_at must be rejected");
        assert!(error.to_string().contains("RFC 3339"), "{error}");
        assert!(repo.get_event("evt_bad_time").unwrap().is_none());

        let stored = repo
            .ingest_event(NewEvent {
                id: Some("evt_time".into()),
                source: None,
                kind: "t3.run.completed".into(),
                payload: json!({"environment_id": "linux-main"}),
                occurred_at: Some("2026-11-16T10:00:00+09:00".into()),
            })
            .unwrap();
        assert_eq!(stored.event.occurred_at, "2026-11-16T01:00:00.000Z");
    }

    #[test]
    fn lease_expiry_reclaims_in_progress_delivery() {
        let repo = repository();
        subscription(&repo, "t3.run.completed");
        repo.ingest_event(NewEvent {
            id: Some("evt_lease".into()),
            source: None,
            kind: "t3.run.completed".into(),
            payload: json!({"environment_id": "linux-main"}),
            occurred_at: None,
        })
        .unwrap();

        let first = repo
            .claim_next_due_with_lease(Duration::from_secs(60))
            .unwrap()
            .expect("first claim");
        assert_eq!(first.event.id, "evt_lease");
        assert_eq!(
            repo.delivery_statuses("evt_lease").unwrap()[0].1,
            "in_progress"
        );

        // Not reclaimable while the lease is still valid.
        assert!(
            repo.claim_next_due_with_lease(Duration::from_secs(60))
                .unwrap()
                .is_none()
        );

        // A zero lease makes the row immediately reclaimable, without a
        // restart and with the same event id.
        let recovered = repo
            .claim_next_due_with_lease(Duration::ZERO)
            .unwrap()
            .expect("lease-expired delivery is reclaimed");
        assert_eq!(recovered.event.id, "evt_lease");
        assert_eq!(recovered.delivery_id, first.delivery_id);
    }

    #[test]
    fn disabling_a_subscription_terminalizes_its_pending_backlog() {
        let repo = repository();
        subscription(&repo, "t3.run.completed");
        for id in ["evt_backlog_1", "evt_backlog_2"] {
            repo.ingest_event(NewEvent {
                id: Some(id.into()),
                source: None,
                kind: "t3.run.completed".into(),
                payload: json!({"environment_id": "linux-main"}),
                occurred_at: None,
            })
            .unwrap();
        }

        let due = repo.claim_next_due().unwrap().expect("first delivery");
        repo.finish_attempt(AttemptOutcome {
            delivery_id: due.delivery_id,
            attempt: 1,
            status_code: Some(410),
            outcome: "permanent",
            error: Some("http_410"),
            delivery_status: "failed",
            next_attempt_at: None,
            subscription_id: &due.subscription.id,
            disable_subscription: true,
        })
        .unwrap();

        for id in ["evt_backlog_1", "evt_backlog_2"] {
            let statuses = repo.delivery_statuses(id).unwrap();
            assert_eq!(statuses.len(), 1);
            assert_eq!(statuses[0].1, "failed", "backlog for {id} is terminal");
        }
        assert!(repo.claim_next_due().unwrap().is_none());
        assert_eq!(repo.pending_delivery_count().unwrap(), 0);
    }

    #[test]
    fn expired_subscription_backlog_is_terminalized() {
        let repo = repository();
        repo.upsert_subscription(NewSubscription {
            id: "sub_expiring".into(),
            principal: "local".into(),
            event_name: "t3.run.completed".into(),
            arguments: json!({"environment_id": "linux-main"}),
            filter_hash: "hash-expiring".into(),
            callback_url: "https://receiver.example.com/hook".into(),
            secret: test_secret(),
            refresh_before: None,
        })
        .unwrap();
        repo.ingest_event(NewEvent {
            id: Some("evt_expiring".into()),
            source: None,
            kind: "t3.run.completed".into(),
            payload: json!({"environment_id": "linux-main"}),
            occurred_at: None,
        })
        .unwrap();

        // Expire the subscription after the delivery was queued.
        let past = format_rfc3339(Utc::now() - ChronoDuration::seconds(1));
        repo.lock()
            .execute(
                "UPDATE subscriptions SET refresh_before = ?2 WHERE id = ?1",
                params!["sub_expiring", past],
            )
            .unwrap();

        assert!(repo.claim_next_due().unwrap().is_none());
        assert_eq!(
            repo.delivery_statuses("evt_expiring").unwrap()[0].1,
            "failed"
        );
        assert_eq!(repo.pending_delivery_count().unwrap(), 0);
    }

    #[test]
    fn refreshing_expired_subscription_does_not_revive_old_backlog() {
        let repo = repository();
        repo.upsert_subscription(NewSubscription {
            id: "sub_reup".into(),
            principal: "local".into(),
            event_name: "t3.run.completed".into(),
            arguments: json!({"environment_id": "linux-main"}),
            filter_hash: "hash-reup".into(),
            callback_url: "https://receiver.example.com/hook".into(),
            secret: test_secret(),
            refresh_before: None,
        })
        .unwrap();
        repo.ingest_event(NewEvent {
            id: Some("evt_before_expiry".into()),
            source: None,
            kind: "t3.run.completed".into(),
            payload: json!({"environment_id": "linux-main"}),
            occurred_at: None,
        })
        .unwrap();

        // Expire the subscription before `claim_next_due` runs.
        let past = format_rfc3339(Utc::now() - ChronoDuration::seconds(1));
        repo.lock()
            .execute(
                "UPDATE subscriptions SET refresh_before = ?2 WHERE id = ?1",
                params!["sub_reup", past],
            )
            .unwrap();

        // Refresh the same subscription before any claim runs.
        let future = format_rfc3339(Utc::now() + ChronoDuration::hours(1));
        repo.upsert_subscription(NewSubscription {
            id: "sub_reup".into(),
            principal: "local".into(),
            event_name: "t3.run.completed".into(),
            arguments: json!({"environment_id": "linux-main"}),
            filter_hash: "hash-reup".into(),
            callback_url: "https://receiver.example.com/hook".into(),
            secret: test_secret(),
            refresh_before: Some(future),
        })
        .unwrap();

        assert!(repo.claim_next_due().unwrap().is_none());
        assert_eq!(
            repo.delivery_statuses("evt_before_expiry").unwrap()[0].1,
            "failed"
        );
        assert_eq!(repo.pending_delivery_count().unwrap(), 0);
    }

    #[test]
    fn finish_attempt_does_not_revive_terminalized_delivery() {
        let repo = repository();
        repo.upsert_subscription(NewSubscription {
            id: "sub_stale".into(),
            principal: "local".into(),
            event_name: "t3.run.completed".into(),
            arguments: json!({"environment_id": "linux-main"}),
            filter_hash: "hash-stale".into(),
            callback_url: "https://receiver.example.com/hook".into(),
            secret: test_secret(),
            refresh_before: None,
        })
        .unwrap();
        repo.ingest_event(NewEvent {
            id: Some("evt_stale".into()),
            source: None,
            kind: "t3.run.completed".into(),
            payload: json!({"environment_id": "linux-main"}),
            occurred_at: None,
        })
        .unwrap();

        let due = repo.claim_next_due().unwrap().expect("claimed delivery");
        // Terminalize the delivery while the attempt is in flight.
        repo.lock()
            .execute(
                "UPDATE deliveries SET status = 'failed' WHERE id = ?1",
                params![due.delivery_id],
            )
            .unwrap();

        let future = format_rfc3339(Utc::now() + ChronoDuration::seconds(30));
        repo.finish_attempt(AttemptOutcome {
            delivery_id: due.delivery_id,
            attempt: 1,
            status_code: Some(503),
            outcome: "retryable",
            error: Some("http_503"),
            delivery_status: "pending",
            next_attempt_at: Some(&future),
            subscription_id: "sub_stale",
            disable_subscription: false,
        })
        .unwrap();

        assert_eq!(
            repo.delivery_statuses("evt_stale").unwrap()[0].1,
            "failed",
            "stale retryable completion must not revive a failed delivery"
        );
        assert_eq!(repo.attempts(due.delivery_id).unwrap().len(), 1);
        assert_eq!(
            repo.get_subscription("sub_stale")
                .unwrap()
                .unwrap()
                .last_error,
            None
        );
    }
}
