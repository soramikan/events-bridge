//! GitHub collector state: webhook deliveries, materialized pull requests and
//! CI runs, and reconciliation checkpoints.
//!
//! Every webhook delivery and every poll step is committed in one SQLite
//! transaction together with the materialized rows, normalized events and
//! delivery rows. A crash can therefore never record a delivery (or advance an
//! ETag) without also applying the state it implies.

use std::collections::HashSet;

use anyhow::Result;
use rusqlite::{Connection, OptionalExtension, Row, Transaction, params, types::Value as SqlValue};
use serde::{Deserialize, Serialize};

use super::repository::{IngestOutcome, NewEvent, Repository, ingest_event_in_tx};
use crate::mcp::event_catalog;
use crate::util::{format_rfc3339, now_rfc3339, parse_rfc3339, timestamp_lt};

/// Collector name used in `collector_checkpoints`.
pub const GITHUB_COLLECTOR: &str = "github";

const PULL_REQUEST_COLUMNS: &str = "repository, pull_number, title, state, author, head_branch, \
     head_sha, base_branch, draft, merged, merged_by, merged_at, requested_reviewers, \
     last_review_state, last_activity_at, url, merged_emitted, updated_at";

const CI_RUN_COLUMNS: &str = "repository, canonical_run_id, run_attempt, check_suite_id, \
     workflow_name, head_branch, head_sha, status, conclusion, url, failure_emitted, updated_at";

const PENDING_CHECK_COLUMNS: &str = "repository, check_run_id, actions_run_id, parsed_attempt, \
     check_suite_id, check_name, head_branch, head_sha, status, conclusion, url, updated_at";

/// Checkpoint scope for a repository's pull request reconciliation.
pub fn pulls_scope(repository: &str) -> String {
    format!("pulls:{repository}")
}

/// Checkpoint scope for a repository's workflow run reconciliation.
pub fn runs_scope(repository: &str) -> String {
    format!("runs:{repository}")
}

/// A materialized pull request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GitHubPullRequest {
    /// `owner/repo`.
    pub repository: String,
    /// Pull request number.
    pub pull_number: i64,
    /// Title.
    pub title: String,
    /// GitHub state (`open` or `closed`).
    pub state: String,
    /// Author login.
    pub author: Option<String>,
    /// Head branch.
    pub head_branch: Option<String>,
    /// Head commit.
    pub head_sha: Option<String>,
    /// Base branch.
    pub base_branch: Option<String>,
    /// Draft flag.
    pub draft: bool,
    /// Whether the pull request was merged.
    pub merged: bool,
    /// Login of the user who merged it.
    pub merged_by: Option<String>,
    /// Merge time.
    pub merged_at: Option<String>,
    /// Pending requested reviewers as normalized `user:<login>` / `team:<slug>`
    /// keys.
    pub requested_reviewers: Vec<String>,
    /// State of the most recent submitted review.
    pub last_review_state: Option<String>,
    /// Timestamp of the most recent review or review comment.
    pub last_activity_at: Option<String>,
    /// Canonical web URL.
    pub url: String,
    /// Whether `github.pr.merged` was already emitted for this row.
    pub merged_emitted: bool,
    /// Last upstream update time.
    pub updated_at: String,
}

/// A materialized CI run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GitHubCiRun {
    /// `owner/repo`.
    pub repository: String,
    /// Canonical workflow run key (`<id>`, `check_suite:<id>` or `check_run:<id>`).
    pub canonical_run_id: String,
    /// Run attempt.
    pub run_attempt: i64,
    /// GitHub check suite id, when known.
    pub check_suite_id: Option<i64>,
    /// Workflow or check name.
    pub workflow_name: String,
    /// Head branch.
    pub head_branch: Option<String>,
    /// Head commit.
    pub head_sha: Option<String>,
    /// Current status.
    pub status: String,
    /// Terminal conclusion, when any.
    pub conclusion: Option<String>,
    /// Canonical web URL.
    pub url: String,
    /// Whether `github.workflow.failed` was already emitted for this attempt.
    pub failure_emitted: bool,
    /// Last upstream update time.
    pub updated_at: String,
}

/// A GitHub Actions `check_run` waiting for its canonical `workflow_run`.
///
/// The check run names a job, not a workflow, and its URL does not always
/// carry the run attempt. Parking it here lets the later `workflow_run`
/// webhook or REST poll emit exactly one failure with the true workflow name
/// and attempt.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GitHubPendingCheck {
    /// `owner/repo`.
    pub repository: String,
    /// GitHub check run id.
    pub check_run_id: i64,
    /// Actions run id parsed from the check run URL, when present.
    pub actions_run_id: Option<i64>,
    /// Attempt parsed from an explicit `/attempts/<n>` URL, when present.
    pub parsed_attempt: Option<i64>,
    /// Check suite id.
    pub check_suite_id: Option<i64>,
    /// Check run name (a job name for Actions).
    pub check_name: String,
    /// Head branch.
    pub head_branch: Option<String>,
    /// Head commit.
    pub head_sha: Option<String>,
    /// Current status.
    pub status: String,
    /// Terminal conclusion, when any.
    pub conclusion: Option<String>,
    /// Canonical web URL.
    pub url: String,
    /// Last upstream update time.
    pub updated_at: String,
}

/// One canonical workflow run that resolves parked Actions checks.
///
/// Resolution is attempt-aware: a run attempt may only delete pending checks
/// that belong to the same attempt, or attempt-less checks whose check suite
/// matches (or, when the pending check has no suite, attempt 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitHubPendingCheckResolution {
    /// Canonical Actions run id.
    pub actions_run_id: Option<i64>,
    /// Check suite id of the resolved attempt.
    pub check_suite_id: Option<i64>,
    /// Resolved run attempt.
    pub run_attempt: i64,
}

/// Pending-check mutations derived from one webhook or poll step.
#[derive(Debug, Clone, Default)]
pub struct GitHubPendingCheckUpdate {
    /// Repository the mutations belong to.
    pub repository: Option<String>,
    /// Pending checks to insert or refresh.
    pub upserts: Vec<GitHubPendingCheck>,
    /// Canonical workflow runs whose pending checks are now resolved.
    pub resolve_workflow_runs: Vec<GitHubPendingCheckResolution>,
    /// Individual check run ids that are now resolved.
    pub resolve_check_run_ids: Vec<i64>,
}

/// A stored reconciliation checkpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitHubCheckpoint {
    /// Last ETag returned by GitHub.
    pub etag: Option<String>,
    /// Last observed upstream update watermark.
    pub watermark: Option<String>,
}

/// A saved pagination continuation for a scope that hit the page cap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitHubPollContinuation {
    /// URL of the first page not yet fetched.
    pub next_url: String,
    /// ETag observed on the first page of the interrupted scan.
    pub pending_etag: Option<String>,
    /// Watermark observed across the interrupted scan.
    pub pending_watermark: Option<String>,
    /// Whether the interrupted scan was a full reconciliation.
    pub full_reconcile: bool,
}

/// How one reconciliation batch commits its checkpoint.
#[derive(Debug, Clone, Copy)]
pub enum GitHubPollCommit<'a> {
    /// Pagination completed; advance the checkpoint and clear any continuation.
    Complete {
        /// ETag to store.
        etag: Option<&'a str>,
        /// Watermark to store.
        watermark: Option<&'a str>,
    },
    /// The page cap was reached while `rel="next"` remained. Persist the
    /// continuation without advancing the checkpoint.
    Truncated {
        /// URL of the first page not yet fetched.
        next_url: &'a str,
        /// ETag to commit once the scan completes.
        pending_etag: Option<&'a str>,
        /// Watermark to commit once the scan completes.
        pending_watermark: Option<&'a str>,
        /// Whether the interrupted scan was a full reconciliation.
        full_reconcile: bool,
    },
}

/// The webhook delivery idempotency record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitHubDelivery {
    /// `X-GitHub-Delivery`.
    pub delivery_id: String,
    /// `X-GitHub-Event`.
    pub event_type: String,
    /// Repository full name, when present.
    pub repository: Option<String>,
}

/// State changes derived from one webhook delivery.
#[derive(Debug, Clone, Default)]
pub struct GitHubWebhookChanges {
    /// Pull request row to upsert.
    pub pull_request: Option<GitHubPullRequest>,
    /// CI run row to upsert.
    pub ci_run: Option<GitHubCiRun>,
    /// Pending Actions check mutations.
    pub pending_checks: GitHubPendingCheckUpdate,
    /// Normalized events.
    pub events: Vec<NewEvent>,
}

/// State changes derived from one reconciliation response.
#[derive(Debug, Clone, Default)]
pub struct GitHubPollChanges {
    /// Pull request rows to upsert.
    pub pull_requests: Vec<GitHubPullRequest>,
    /// CI run rows to upsert.
    pub ci_runs: Vec<GitHubCiRun>,
    /// Pending Actions check mutations.
    pub pending_checks: GitHubPendingCheckUpdate,
    /// Normalized events.
    pub events: Vec<NewEvent>,
}

/// Result of applying a GitHub state batch.
#[derive(Debug, Clone, Default)]
pub struct GitHubApplyOutcome {
    /// Whether the delivery id already existed.
    pub duplicate_delivery: bool,
    /// Stored events (existing rows included for duplicate ids).
    pub events: Vec<IngestOutcome>,
    /// Delivery rows created across all events.
    pub deliveries_created: usize,
    /// Number of events whose id already existed.
    pub duplicates: usize,
}

impl GitHubApplyOutcome {
    /// Number of newly stored events.
    pub fn emitted(&self) -> usize {
        self.events.iter().filter(|event| !event.duplicate).count()
    }
}

/// Filter for `get_github_status`.
#[derive(Debug, Clone, Default)]
pub struct GitHubStatusQuery {
    /// Restrict both result sets to one repository.
    pub repository: Option<String>,
    /// Restrict pull requests (and CI runs to their head commit) to one number.
    pub pull_number: Option<i64>,
    /// Restrict to one head branch.
    pub branch: Option<String>,
    /// Maximum rows returned from each table.
    pub limit: i64,
}

/// Materialized GitHub status returned by the pull tool.
#[derive(Debug, Clone, Default)]
pub struct GitHubStatus {
    /// Matching pull requests.
    pub pull_requests: Vec<GitHubPullRequest>,
    /// Matching CI runs.
    pub ci_runs: Vec<GitHubCiRun>,
}

impl Repository {
    /// Persist a webhook delivery, the state it changes and its events in one
    /// transaction.
    ///
    /// `build` runs inside the transaction so check-suite resolution and
    /// `*_emitted` checks cannot race another webhook or poll pass. It is not
    /// called at all when the delivery id already exists.
    pub(crate) fn apply_github_webhook<F>(
        &self,
        delivery: GitHubDelivery,
        build: F,
    ) -> Result<GitHubApplyOutcome>
    where
        F: FnOnce(&Transaction<'_>) -> Result<GitHubWebhookChanges>,
    {
        let mut conn = self.lock_connection();
        let tx = conn.transaction()?;
        let received_at = now_rfc3339();
        let inserted = tx.execute(
            "INSERT OR IGNORE INTO github_deliveries \
                 (delivery_id, event_type, repository, received_at) \
             VALUES (?1, ?2, ?3, ?4)",
            params![
                delivery.delivery_id,
                delivery.event_type,
                delivery.repository,
                received_at
            ],
        )?;
        if inserted == 0 {
            tx.commit()?;
            return Ok(GitHubApplyOutcome {
                duplicate_delivery: true,
                ..GitHubApplyOutcome::default()
            });
        }

        let changes = build(&tx)?;
        validate_events(&changes.events)?;
        if let Some(pull_request) = &changes.pull_request {
            upsert_pull_request(&tx, pull_request)?;
        }
        if let Some(ci_run) = &changes.ci_run {
            upsert_ci_run(&tx, ci_run)?;
        }
        apply_pending_checks(&tx, &changes.pending_checks)?;
        let outcome = ingest_events(&tx, &changes.events)?;
        tx.commit()?;
        Ok(outcome)
    }

    /// Persist one reconciliation response and its checkpoint atomically.
    ///
    /// `build` runs inside the transaction and receives whether this is the
    /// first successful poll for the scope (no checkpoint row yet). A first
    /// poll baselines existing failures and merges instead of emitting them.
    ///
    /// A truncated scan persists a continuation instead of advancing the
    /// checkpoint, so the next pass resumes exactly where this one stopped.
    pub(crate) fn apply_github_poll<F>(
        &self,
        scope: &str,
        commit: GitHubPollCommit<'_>,
        build: F,
    ) -> Result<GitHubApplyOutcome>
    where
        F: FnOnce(&Transaction<'_>, bool) -> Result<GitHubPollChanges>,
    {
        let mut conn = self.lock_connection();
        let tx = conn.transaction()?;
        let baseline = get_checkpoint(&tx, scope)?.is_none();
        let changes = build(&tx, baseline)?;
        validate_events(&changes.events)?;
        for pull_request in &changes.pull_requests {
            upsert_pull_request(&tx, pull_request)?;
        }
        for ci_run in &changes.ci_runs {
            upsert_ci_run(&tx, ci_run)?;
        }
        apply_pending_checks(&tx, &changes.pending_checks)?;
        match commit {
            GitHubPollCommit::Complete { etag, watermark } => {
                upsert_checkpoint(&tx, scope, etag, watermark)?;
                delete_continuation(&tx, scope)?;
            }
            GitHubPollCommit::Truncated {
                next_url,
                pending_etag,
                pending_watermark,
                full_reconcile,
            } => {
                upsert_continuation(
                    &tx,
                    scope,
                    next_url,
                    pending_etag,
                    pending_watermark,
                    full_reconcile,
                )?;
            }
        }
        let outcome = ingest_events(&tx, &changes.events)?;
        tx.commit()?;
        Ok(outcome)
    }

    /// Whether a webhook delivery id was already accepted.
    pub fn github_delivery_exists(&self, delivery_id: &str) -> Result<bool> {
        let conn = self.lock_connection();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM github_deliveries WHERE delivery_id = ?1",
            params![delivery_id],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Fetch a reconciliation checkpoint.
    pub fn get_github_checkpoint(&self, scope: &str) -> Result<Option<GitHubCheckpoint>> {
        get_checkpoint(&self.lock_connection(), scope)
    }

    /// Fetch one materialized pull request.
    pub fn get_github_pull_request(
        &self,
        repository: &str,
        pull_number: i64,
    ) -> Result<Option<GitHubPullRequest>> {
        load_pull_request(&self.lock_connection(), repository, pull_number)
    }

    /// Fetch one materialized CI run.
    pub fn get_github_ci_run(
        &self,
        repository: &str,
        canonical_run_id: &str,
        run_attempt: i64,
    ) -> Result<Option<GitHubCiRun>> {
        load_ci_run(
            &self.lock_connection(),
            repository,
            canonical_run_id,
            run_attempt,
        )
    }

    /// Fetch one pending Actions check.
    pub fn get_github_pending_check(
        &self,
        repository: &str,
        check_run_id: i64,
    ) -> Result<Option<GitHubPendingCheck>> {
        load_pending_check(&self.lock_connection(), repository, check_run_id)
    }

    /// List every pending Actions check for a repository.
    pub fn list_github_pending_checks(&self, repository: &str) -> Result<Vec<GitHubPendingCheck>> {
        list_pending_checks(&self.lock_connection(), repository)
    }

    /// List locally tracked CI runs that have not completed yet.
    pub fn list_active_github_ci_runs(&self, repository: &str) -> Result<Vec<GitHubCiRun>> {
        let conn = self.lock_connection();
        let sql = format!(
            "SELECT {CI_RUN_COLUMNS} FROM github_ci_runs \
             WHERE repository = ?1 AND status != 'completed' \
             ORDER BY updated_at DESC"
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(params![repository], map_ci_run)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// List CI runs whose head commit belongs to an open pull request.
    ///
    /// `/actions/runs` is ordered by `created_at` descending, so a rerun of an
    /// older completed run stays on an older page. These rows let the poller
    /// re-check the canonical run even when page 1 returns `304`.
    pub fn list_github_ci_runs_for_open_pulls(&self, repository: &str) -> Result<Vec<GitHubCiRun>> {
        let conn = self.lock_connection();
        let sql = "SELECT DISTINCT r.repository, r.canonical_run_id, r.run_attempt, r.check_suite_id, \
                 r.workflow_name, r.head_branch, r.head_sha, r.status, r.conclusion, r.url, \
                 r.failure_emitted, r.updated_at \
             FROM github_ci_runs r \
             JOIN github_pull_requests p \
               ON p.repository = r.repository AND p.head_sha = r.head_sha \
             WHERE r.repository = ?1 AND p.state = 'open' \
             ORDER BY r.updated_at DESC";
        let mut stmt = conn.prepare(sql)?;
        let rows = stmt.query_map(params![repository], map_ci_run)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Fetch a saved pagination continuation.
    pub fn get_github_poll_continuation(
        &self,
        scope: &str,
    ) -> Result<Option<GitHubPollContinuation>> {
        load_continuation(&self.lock_connection(), scope)
    }

    /// Materialized status used by `get_github_status`.
    pub fn github_status(&self, query: &GitHubStatusQuery) -> Result<GitHubStatus> {
        let conn = self.lock_connection();
        let pull_requests = list_pull_requests(&conn, query)?;
        let ci_runs = if query.pull_number.is_some() {
            // A pull number is only unique within a repository. Correlate CI
            // runs by the exact `(repository, head_sha)` pair of every matched
            // pull request, never by a bare head SHA.
            let mut seen = HashSet::new();
            let pairs: Vec<(String, String)> = pull_requests
                .iter()
                .filter_map(|pull| {
                    let head_sha = pull.head_sha.as_ref()?;
                    let pair = (pull.repository.clone(), head_sha.clone());
                    seen.insert(pair.clone()).then_some(pair)
                })
                .collect();
            list_ci_runs_for_pairs(&conn, query, &pairs)?
        } else {
            list_ci_runs(&conn, query, None)?
        };
        Ok(GitHubStatus {
            pull_requests,
            ci_runs,
        })
    }
}

fn validate_events(events: &[NewEvent]) -> Result<()> {
    for event in events {
        event_catalog::validate_payload(&event.kind, &event.payload)
            .map_err(|error| anyhow::anyhow!(error))?;
    }
    Ok(())
}

fn ingest_events(tx: &Transaction<'_>, events: &[NewEvent]) -> Result<GitHubApplyOutcome> {
    let ingested_at = now_rfc3339();
    let mut outcome = GitHubApplyOutcome::default();
    for event in events {
        let stored = ingest_event_in_tx(tx, event.clone(), &ingested_at)?;
        outcome.deliveries_created += stored.deliveries_created;
        if stored.duplicate {
            outcome.duplicates += 1;
        }
        outcome.events.push(stored);
    }
    Ok(outcome)
}

/// Load a pull request from any connection or transaction.
pub(crate) fn load_pull_request(
    conn: &Connection,
    repository: &str,
    pull_number: i64,
) -> Result<Option<GitHubPullRequest>> {
    let sql = format!(
        "SELECT {PULL_REQUEST_COLUMNS} FROM github_pull_requests \
         WHERE repository = ?1 AND pull_number = ?2"
    );
    Ok(conn
        .query_row(&sql, params![repository, pull_number], map_pull_request)
        .optional()?)
}

/// Load a CI run by its canonical key.
pub(crate) fn load_ci_run(
    conn: &Connection,
    repository: &str,
    canonical_run_id: &str,
    run_attempt: i64,
) -> Result<Option<GitHubCiRun>> {
    let sql = format!(
        "SELECT {CI_RUN_COLUMNS} FROM github_ci_runs \
         WHERE repository = ?1 AND canonical_run_id = ?2 AND run_attempt = ?3"
    );
    Ok(conn
        .query_row(
            &sql,
            params![repository, canonical_run_id, run_attempt],
            map_ci_run,
        )
        .optional()?)
}

/// Whether any row for this check suite and attempt already emitted a failure.
pub(crate) fn ci_failure_emitted_for_suite(
    conn: &Connection,
    repository: &str,
    check_suite_id: i64,
    run_attempt: i64,
) -> Result<bool> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM github_ci_runs \
         WHERE repository = ?1 AND check_suite_id = ?2 AND run_attempt = ?3 \
           AND failure_emitted = 1",
        params![repository, check_suite_id, run_attempt],
        |row| row.get(0),
    )?;
    Ok(count > 0)
}

/// Delete fallback rows for a check suite once a canonical workflow run is known.
pub(crate) fn delete_fallback_ci_runs(
    conn: &Connection,
    repository: &str,
    check_suite_id: i64,
    run_attempt: i64,
) -> Result<usize> {
    Ok(conn.execute(
        "DELETE FROM github_ci_runs \
         WHERE repository = ?1 AND check_suite_id = ?2 AND run_attempt = ?3 \
           AND (canonical_run_id LIKE 'check_suite:%' OR canonical_run_id LIKE 'check_run:%')",
        params![repository, check_suite_id, run_attempt],
    )?)
}

/// Load a pending Actions check.
pub(crate) fn load_pending_check(
    conn: &Connection,
    repository: &str,
    check_run_id: i64,
) -> Result<Option<GitHubPendingCheck>> {
    let sql = format!(
        "SELECT {PENDING_CHECK_COLUMNS} FROM github_pending_checks \
         WHERE repository = ?1 AND check_run_id = ?2"
    );
    Ok(conn
        .query_row(&sql, params![repository, check_run_id], map_pending_check)
        .optional()?)
}

/// List every pending Actions check for a repository.
pub(crate) fn list_pending_checks(
    conn: &Connection,
    repository: &str,
) -> Result<Vec<GitHubPendingCheck>> {
    let sql = format!(
        "SELECT {PENDING_CHECK_COLUMNS} FROM github_pending_checks \
         WHERE repository = ?1 ORDER BY updated_at DESC, check_run_id DESC"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params![repository], map_pending_check)?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

fn apply_pending_checks(tx: &Transaction<'_>, update: &GitHubPendingCheckUpdate) -> Result<()> {
    for check in &update.upserts {
        upsert_pending_check(tx, check)?;
    }
    let Some(repository) = update.repository.as_deref() else {
        return Ok(());
    };
    for resolution in &update.resolve_workflow_runs {
        let attempt = resolution.run_attempt.max(1);
        // Attempt-aware resolution. A pending check is deleted only when:
        //   * its parsed attempt equals the resolved attempt, or
        //   * it has no parsed attempt and its check suite matches the resolved
        //     suite (or, when the pending check has no suite, the resolved
        //     attempt is 1).
        // This prevents attempt 2 from deleting a pending attempt 1 check and
        // a late attempt 1 webhook from deleting a pending attempt 2 check.
        tx.execute(
            "DELETE FROM github_pending_checks \
             WHERE repository = ?1 AND ( \
                 (actions_run_id = ?2 AND ( \
                     parsed_attempt = ?3 \
                     OR (parsed_attempt IS NULL AND ( \
                         (check_suite_id IS NOT NULL AND check_suite_id = ?4) \
                         OR (check_suite_id IS NULL AND ?3 = 1) \
                     )) \
                 )) \
                 OR (?4 IS NOT NULL AND check_suite_id = ?4 AND ( \
                     parsed_attempt = ?3 OR parsed_attempt IS NULL \
                 )) \
             )",
            params![
                repository,
                resolution.actions_run_id,
                attempt,
                resolution.check_suite_id
            ],
        )?;
    }
    for check_run_id in &update.resolve_check_run_ids {
        tx.execute(
            "DELETE FROM github_pending_checks \
             WHERE repository = ?1 AND check_run_id = ?2",
            params![repository, check_run_id],
        )?;
    }
    Ok(())
}

fn upsert_pull_request(tx: &Transaction<'_>, pull: &GitHubPullRequest) -> Result<()> {
    let existing = load_pull_request(tx, &pull.repository, pull.pull_number)?;
    let row = match existing {
        Some(existing) if timestamp_lt(&pull.updated_at, &existing.updated_at) => {
            merge_stale_pull(existing, pull)
        }
        _ => pull.clone(),
    };
    let reviewers = serde_json::to_string(&row.requested_reviewers)?;
    tx.execute(
        "INSERT INTO github_pull_requests \
             (repository, pull_number, title, state, author, head_branch, head_sha, \
              base_branch, draft, merged, merged_by, merged_at, requested_reviewers, \
              last_review_state, last_activity_at, url, merged_emitted, updated_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18) \
         ON CONFLICT (repository, pull_number) DO UPDATE SET \
             title = excluded.title, \
             state = excluded.state, \
             author = excluded.author, \
             head_branch = excluded.head_branch, \
             head_sha = excluded.head_sha, \
             base_branch = excluded.base_branch, \
             draft = excluded.draft, \
             merged = excluded.merged, \
             merged_by = excluded.merged_by, \
             merged_at = excluded.merged_at, \
             requested_reviewers = excluded.requested_reviewers, \
             last_review_state = excluded.last_review_state, \
             last_activity_at = excluded.last_activity_at, \
             url = excluded.url, \
             merged_emitted = excluded.merged_emitted, \
             updated_at = excluded.updated_at",
        params![
            row.repository,
            row.pull_number,
            row.title,
            row.state,
            row.author,
            row.head_branch,
            row.head_sha,
            row.base_branch,
            if row.draft { 1_i64 } else { 0_i64 },
            if row.merged { 1_i64 } else { 0_i64 },
            row.merged_by,
            row.merged_at,
            reviewers,
            row.last_review_state,
            row.last_activity_at,
            row.url,
            if row.merged_emitted { 1_i64 } else { 0_i64 },
            row.updated_at
        ],
    )?;
    Ok(())
}

/// Keep the newer materialized state while preserving monotonic merge flags.
fn merge_stale_pull(
    mut existing: GitHubPullRequest,
    incoming: &GitHubPullRequest,
) -> GitHubPullRequest {
    existing.merged |= incoming.merged;
    existing.merged_emitted |= incoming.merged_emitted;
    if existing.merged_at.is_none() {
        existing.merged_at = incoming.merged_at.clone();
    }
    if existing.merged_by.is_none() {
        existing.merged_by = incoming.merged_by.clone();
    }
    let incoming_activity = incoming.last_activity_at.as_deref();
    let existing_activity = existing.last_activity_at.as_deref();
    if incoming_activity.is_some_and(|incoming| {
        existing_activity.is_none_or(|existing| timestamp_lt(existing, incoming))
    }) {
        existing.last_activity_at = incoming.last_activity_at.clone();
        existing.last_review_state = incoming.last_review_state.clone();
    }
    existing
}

fn upsert_ci_run(tx: &Transaction<'_>, run: &GitHubCiRun) -> Result<()> {
    let existing = load_ci_run(tx, &run.repository, &run.canonical_run_id, run.run_attempt)?;
    let mut row = run.clone();
    if row.check_suite_id.is_none() {
        row.check_suite_id = existing
            .as_ref()
            .and_then(|existing| existing.check_suite_id);
    }
    if let Some(existing) = &existing
        && timestamp_lt(&row.updated_at, &existing.updated_at)
    {
        let mut merged = existing.clone();
        merged.failure_emitted |= row.failure_emitted;
        row = merged;
    }
    tx.execute(
        "INSERT INTO github_ci_runs \
             (repository, canonical_run_id, run_attempt, check_suite_id, workflow_name, \
              head_branch, head_sha, status, conclusion, url, failure_emitted, updated_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12) \
         ON CONFLICT (repository, canonical_run_id, run_attempt) DO UPDATE SET \
             check_suite_id = excluded.check_suite_id, \
             workflow_name = excluded.workflow_name, \
             head_branch = excluded.head_branch, \
             head_sha = excluded.head_sha, \
             status = excluded.status, \
             conclusion = excluded.conclusion, \
             url = excluded.url, \
             failure_emitted = excluded.failure_emitted, \
             updated_at = excluded.updated_at",
        params![
            row.repository,
            row.canonical_run_id,
            row.run_attempt,
            row.check_suite_id,
            row.workflow_name,
            row.head_branch,
            row.head_sha,
            row.status,
            row.conclusion,
            row.url,
            if row.failure_emitted { 1_i64 } else { 0_i64 },
            row.updated_at
        ],
    )?;
    Ok(())
}

fn upsert_pending_check(tx: &Transaction<'_>, check: &GitHubPendingCheck) -> Result<()> {
    let existing = load_pending_check(tx, &check.repository, check.check_run_id)?;
    let row = match existing {
        Some(existing) if timestamp_lt(&check.updated_at, &existing.updated_at) => existing,
        _ => check.clone(),
    };
    tx.execute(
        "INSERT INTO github_pending_checks \
             (repository, check_run_id, actions_run_id, parsed_attempt, check_suite_id, \
              check_name, head_branch, head_sha, status, conclusion, url, updated_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12) \
         ON CONFLICT (repository, check_run_id) DO UPDATE SET \
             actions_run_id = excluded.actions_run_id, \
             parsed_attempt = excluded.parsed_attempt, \
             check_suite_id = excluded.check_suite_id, \
             check_name = excluded.check_name, \
             head_branch = excluded.head_branch, \
             head_sha = excluded.head_sha, \
             status = excluded.status, \
             conclusion = excluded.conclusion, \
             url = excluded.url, \
             updated_at = excluded.updated_at",
        params![
            row.repository,
            row.check_run_id,
            row.actions_run_id,
            row.parsed_attempt,
            row.check_suite_id,
            row.check_name,
            row.head_branch,
            row.head_sha,
            row.status,
            row.conclusion,
            row.url,
            row.updated_at
        ],
    )?;
    Ok(())
}

fn get_checkpoint(conn: &Connection, scope: &str) -> Result<Option<GitHubCheckpoint>> {
    Ok(conn
        .query_row(
            "SELECT etag, watermark FROM collector_checkpoints \
             WHERE collector = ?1 AND scope = ?2",
            params![GITHUB_COLLECTOR, scope],
            |row| {
                Ok(GitHubCheckpoint {
                    etag: row.get(0)?,
                    watermark: row.get(1)?,
                })
            },
        )
        .optional()?)
}

fn load_continuation(conn: &Connection, scope: &str) -> Result<Option<GitHubPollContinuation>> {
    Ok(conn
        .query_row(
            "SELECT next_url, pending_etag, pending_watermark, full_reconcile \
             FROM github_poll_continuations WHERE scope = ?1",
            params![scope],
            |row| {
                Ok(GitHubPollContinuation {
                    next_url: row.get(0)?,
                    pending_etag: row.get(1)?,
                    pending_watermark: row.get(2)?,
                    full_reconcile: row.get::<_, i64>(3)? != 0,
                })
            },
        )
        .optional()?)
}

fn upsert_continuation(
    tx: &Transaction<'_>,
    scope: &str,
    next_url: &str,
    pending_etag: Option<&str>,
    pending_watermark: Option<&str>,
    full_reconcile: bool,
) -> Result<()> {
    let updated_at = now_rfc3339();
    tx.execute(
        "INSERT INTO github_poll_continuations \
             (scope, next_url, pending_etag, pending_watermark, full_reconcile, updated_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
         ON CONFLICT (scope) DO UPDATE SET \
             next_url = excluded.next_url, \
             pending_etag = excluded.pending_etag, \
             pending_watermark = excluded.pending_watermark, \
             full_reconcile = excluded.full_reconcile, \
             updated_at = excluded.updated_at",
        params![
            scope,
            next_url,
            pending_etag,
            pending_watermark,
            if full_reconcile { 1_i64 } else { 0_i64 },
            updated_at
        ],
    )?;
    Ok(())
}

fn delete_continuation(tx: &Transaction<'_>, scope: &str) -> Result<()> {
    tx.execute(
        "DELETE FROM github_poll_continuations WHERE scope = ?1",
        params![scope],
    )?;
    Ok(())
}

fn upsert_checkpoint(
    tx: &Transaction<'_>,
    scope: &str,
    etag: Option<&str>,
    watermark: Option<&str>,
) -> Result<()> {
    let updated_at = now_rfc3339();
    tx.execute(
        "INSERT INTO collector_checkpoints (collector, scope, etag, watermark, updated_at) \
         VALUES (?1, ?2, ?3, ?4, ?5) \
         ON CONFLICT (collector, scope) DO UPDATE SET \
             etag = excluded.etag, \
             watermark = excluded.watermark, \
             updated_at = excluded.updated_at",
        params![GITHUB_COLLECTOR, scope, etag, watermark, updated_at],
    )?;
    Ok(())
}

fn list_pull_requests(
    conn: &Connection,
    query: &GitHubStatusQuery,
) -> Result<Vec<GitHubPullRequest>> {
    let mut sql = format!("SELECT {PULL_REQUEST_COLUMNS} FROM github_pull_requests WHERE 1 = 1");
    let mut args: Vec<SqlValue> = Vec::new();
    if let Some(repository) = &query.repository {
        sql.push_str(" AND repository = ?");
        args.push(SqlValue::Text(repository.clone()));
    }
    if let Some(pull_number) = query.pull_number {
        sql.push_str(" AND pull_number = ?");
        args.push(SqlValue::Integer(pull_number));
    }
    if let Some(branch) = &query.branch {
        sql.push_str(" AND (head_branch = ? OR base_branch = ?)");
        args.push(SqlValue::Text(branch.clone()));
        args.push(SqlValue::Text(branch.clone()));
    }
    sql.push_str(" ORDER BY updated_at DESC, pull_number DESC LIMIT ?");
    args.push(SqlValue::Integer(query.limit.max(1)));

    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(rusqlite::params_from_iter(args.iter()), map_pull_request)?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

fn list_ci_runs(
    conn: &Connection,
    query: &GitHubStatusQuery,
    head_sha: Option<&str>,
) -> Result<Vec<GitHubCiRun>> {
    let mut sql = format!("SELECT {CI_RUN_COLUMNS} FROM github_ci_runs WHERE 1 = 1");
    let mut args: Vec<SqlValue> = Vec::new();
    if let Some(repository) = &query.repository {
        sql.push_str(" AND repository = ?");
        args.push(SqlValue::Text(repository.clone()));
    }
    if let Some(branch) = &query.branch {
        sql.push_str(" AND head_branch = ?");
        args.push(SqlValue::Text(branch.clone()));
    }
    if let Some(head_sha) = head_sha {
        sql.push_str(" AND head_sha = ?");
        args.push(SqlValue::Text(head_sha.to_string()));
    }
    sql.push_str(" ORDER BY updated_at DESC, run_attempt DESC LIMIT ?");
    args.push(SqlValue::Integer(query.limit.max(1)));

    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(rusqlite::params_from_iter(args.iter()), map_ci_run)?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// List CI runs matching any exact `(repository, head_sha)` pair.
fn list_ci_runs_for_pairs(
    conn: &Connection,
    query: &GitHubStatusQuery,
    pairs: &[(String, String)],
) -> Result<Vec<GitHubCiRun>> {
    if pairs.is_empty() {
        return Ok(Vec::new());
    }
    let mut sql = format!("SELECT {CI_RUN_COLUMNS} FROM github_ci_runs WHERE 1 = 1");
    let mut args: Vec<SqlValue> = Vec::new();
    if let Some(repository) = &query.repository {
        sql.push_str(" AND repository = ?");
        args.push(SqlValue::Text(repository.clone()));
    }
    if let Some(branch) = &query.branch {
        sql.push_str(" AND head_branch = ?");
        args.push(SqlValue::Text(branch.clone()));
    }
    sql.push_str(" AND (");
    for (index, (repository, head_sha)) in pairs.iter().enumerate() {
        if index > 0 {
            sql.push_str(" OR ");
        }
        sql.push_str("(repository = ? AND head_sha = ?)");
        args.push(SqlValue::Text(repository.clone()));
        args.push(SqlValue::Text(head_sha.clone()));
    }
    sql.push_str(") ORDER BY updated_at DESC, run_attempt DESC LIMIT ?");
    args.push(SqlValue::Integer(query.limit.max(1)));

    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(rusqlite::params_from_iter(args.iter()), map_ci_run)?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

fn map_pull_request(row: &Row<'_>) -> rusqlite::Result<GitHubPullRequest> {
    let reviewers: String = row.get(12)?;
    Ok(GitHubPullRequest {
        repository: row.get(0)?,
        pull_number: row.get(1)?,
        title: row.get(2)?,
        state: row.get(3)?,
        author: row.get(4)?,
        head_branch: row.get(5)?,
        head_sha: row.get(6)?,
        base_branch: row.get(7)?,
        draft: row.get::<_, i64>(8)? != 0,
        merged: row.get::<_, i64>(9)? != 0,
        merged_by: row.get(10)?,
        merged_at: row.get(11)?,
        requested_reviewers: serde_json::from_str(&reviewers).unwrap_or_default(),
        last_review_state: row.get(13)?,
        last_activity_at: row.get(14)?,
        url: row.get(15)?,
        merged_emitted: row.get::<_, i64>(16)? != 0,
        updated_at: row.get(17)?,
    })
}

fn map_pending_check(row: &Row<'_>) -> rusqlite::Result<GitHubPendingCheck> {
    Ok(GitHubPendingCheck {
        repository: row.get(0)?,
        check_run_id: row.get(1)?,
        actions_run_id: row.get(2)?,
        parsed_attempt: row.get(3)?,
        check_suite_id: row.get(4)?,
        check_name: row.get(5)?,
        head_branch: row.get(6)?,
        head_sha: row.get(7)?,
        status: row.get(8)?,
        conclusion: row.get(9)?,
        url: row.get(10)?,
        updated_at: row.get(11)?,
    })
}

fn map_ci_run(row: &Row<'_>) -> rusqlite::Result<GitHubCiRun> {
    Ok(GitHubCiRun {
        repository: row.get(0)?,
        canonical_run_id: row.get(1)?,
        run_attempt: row.get(2)?,
        check_suite_id: row.get(3)?,
        workflow_name: row.get(4)?,
        head_branch: row.get(5)?,
        head_sha: row.get(6)?,
        status: row.get(7)?,
        conclusion: row.get(8)?,
        url: row.get(9)?,
        failure_emitted: row.get::<_, i64>(10)? != 0,
        updated_at: row.get(11)?,
    })
}

/// Normalize a timestamp for storage, falling back to `fallback`.
pub(crate) fn github_timestamp(value: Option<&str>, fallback: &str) -> String {
    value
        .and_then(parse_rfc3339)
        .map(format_rfc3339)
        .unwrap_or_else(|| fallback.to_string())
}

/// Read a string from a JSON value.
pub(crate) fn json_text(value: &serde_json::Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

/// Read an integer from a JSON number or numeric string.
pub(crate) fn json_i64(value: &serde_json::Value, key: &str) -> Option<i64> {
    value.get(key).and_then(|value| {
        value
            .as_i64()
            .or_else(|| value.as_u64().and_then(|value| i64::try_from(value).ok()))
            .or_else(|| value.as_str().and_then(|text| text.parse::<i64>().ok()))
    })
}

/// Read a boolean from a JSON value.
pub(crate) fn json_bool(value: &serde_json::Value, key: &str) -> Option<bool> {
    value.get(key).and_then(serde_json::Value::as_bool)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn repository() -> Repository {
        Repository::open_in_memory().expect("in-memory repository")
    }

    fn pull() -> GitHubPullRequest {
        GitHubPullRequest {
            repository: "o/r".into(),
            pull_number: 1,
            title: "Unit pull".into(),
            state: "closed".into(),
            author: Some("alice".into()),
            head_branch: Some("feature".into()),
            head_sha: Some("abc".into()),
            base_branch: Some("main".into()),
            draft: false,
            merged: true,
            merged_by: Some("bob".into()),
            merged_at: Some("2026-11-16T01:00:00.000Z".into()),
            requested_reviewers: vec!["user:carol".into()],
            last_review_state: Some("approved".into()),
            last_activity_at: Some("2026-11-16T01:00:00.000Z".into()),
            url: "https://github.com/o/r/pull/1".into(),
            merged_emitted: false,
            updated_at: "2026-11-16T01:00:00.000Z".into(),
        }
    }

    fn merged_event() -> NewEvent {
        NewEvent {
            id: Some("evt_unit_pr".into()),
            source: None,
            kind: "github.pr.merged".into(),
            payload: json!({
                "repository": "o/r",
                "pull_number": 1,
                "title": "Unit pull",
                "url": "https://github.com/o/r/pull/1"
            }),
            occurred_at: None,
        }
    }

    #[test]
    fn webhook_delivery_is_idempotent_and_atomic() {
        let repo = repository();
        let delivery = GitHubDelivery {
            delivery_id: "unit-delivery".into(),
            event_type: "pull_request".into(),
            repository: Some("o/r".into()),
        };
        let first = repo
            .apply_github_webhook(delivery.clone(), |_tx| {
                Ok(GitHubWebhookChanges {
                    pull_request: Some(pull()),
                    ci_run: None,
                    pending_checks: GitHubPendingCheckUpdate::default(),
                    events: vec![merged_event()],
                })
            })
            .unwrap();
        assert!(!first.duplicate_delivery);
        assert_eq!(first.emitted(), 1);
        assert_eq!(first.deliveries_created, 0, "no subscription is configured");
        assert_eq!(
            repo.get_github_pull_request("o/r", 1)
                .unwrap()
                .unwrap()
                .title,
            "Unit pull"
        );
        assert_eq!(
            repo.list_events(&crate::store::EventQuery {
                limit: 10,
                ..Default::default()
            })
            .unwrap()
            .len(),
            1
        );

        let duplicate = repo
            .apply_github_webhook(delivery, |_tx| panic!("duplicate must not build changes"))
            .unwrap();
        assert!(duplicate.duplicate_delivery);
        assert_eq!(
            repo.list_events(&crate::store::EventQuery {
                limit: 10,
                ..Default::default()
            })
            .unwrap()
            .len(),
            1
        );
    }

    #[test]
    fn poll_checkpoint_is_written_atomically_with_state() {
        let repo = repository();
        let scope = pulls_scope("o/r");
        let first = repo
            .apply_github_poll(
                &scope,
                GitHubPollCommit::Complete {
                    etag: Some("etag-1"),
                    watermark: Some("watermark-1"),
                },
                |_tx, baseline| {
                    assert!(baseline, "first poll is a baseline");
                    Ok(GitHubPollChanges {
                        pull_requests: vec![pull()],
                        ..GitHubPollChanges::default()
                    })
                },
            )
            .unwrap();
        assert_eq!(first.emitted(), 0);
        let checkpoint = repo.get_github_checkpoint(&scope).unwrap().unwrap();
        assert_eq!(checkpoint.etag.as_deref(), Some("etag-1"));
        assert_eq!(checkpoint.watermark.as_deref(), Some("watermark-1"));

        let second = repo
            .apply_github_poll(
                &scope,
                GitHubPollCommit::Complete {
                    etag: Some("etag-2"),
                    watermark: Some("watermark-2"),
                },
                |_tx, baseline| {
                    assert!(!baseline, "a checkpoint already exists");
                    Ok(GitHubPollChanges::default())
                },
            )
            .unwrap();
        assert_eq!(second.emitted(), 0);
        let checkpoint = repo.get_github_checkpoint(&scope).unwrap().unwrap();
        assert_eq!(checkpoint.etag.as_deref(), Some("etag-2"));
        assert_eq!(checkpoint.watermark.as_deref(), Some("watermark-2"));
    }

    #[test]
    fn truncated_poll_saves_a_continuation_without_advancing_the_checkpoint() {
        let repo = repository();
        let scope = pulls_scope("o/r");
        repo.apply_github_poll(
            &scope,
            GitHubPollCommit::Truncated {
                next_url: "https://api.github.com/repos/o/r/pulls?page=51",
                pending_etag: Some("etag-pending"),
                pending_watermark: Some("watermark-pending"),
                full_reconcile: false,
            },
            |_tx, baseline| {
                assert!(baseline, "no checkpoint exists yet");
                Ok(GitHubPollChanges::default())
            },
        )
        .unwrap();
        assert!(
            repo.get_github_checkpoint(&scope).unwrap().is_none(),
            "a truncated scan must not advance the checkpoint"
        );
        let continuation = repo
            .get_github_poll_continuation(&scope)
            .unwrap()
            .expect("continuation");
        assert_eq!(
            continuation.next_url,
            "https://api.github.com/repos/o/r/pulls?page=51"
        );
        assert_eq!(continuation.pending_etag.as_deref(), Some("etag-pending"));
        assert_eq!(
            continuation.pending_watermark.as_deref(),
            Some("watermark-pending")
        );

        repo.apply_github_poll(
            &scope,
            GitHubPollCommit::Complete {
                etag: Some("etag-pending"),
                watermark: Some("watermark-pending"),
            },
            |_tx, baseline| {
                assert!(baseline, "the checkpoint is still absent");
                Ok(GitHubPollChanges::default())
            },
        )
        .unwrap();
        assert!(
            repo.get_github_poll_continuation(&scope).unwrap().is_none(),
            "completing the scan clears the continuation"
        );
        let checkpoint = repo.get_github_checkpoint(&scope).unwrap().unwrap();
        assert_eq!(checkpoint.etag.as_deref(), Some("etag-pending"));
        assert_eq!(checkpoint.watermark.as_deref(), Some("watermark-pending"));
    }

    #[test]
    fn pending_check_resolution_is_attempt_aware() {
        let repo = repository();
        let scope = runs_scope("o/r");
        let pending =
            |check_run_id: i64, attempt: Option<i64>, suite: Option<i64>| GitHubPendingCheck {
                repository: "o/r".into(),
                check_run_id,
                actions_run_id: Some(42),
                parsed_attempt: attempt,
                check_suite_id: suite,
                check_name: "test".into(),
                head_branch: Some("main".into()),
                head_sha: Some("abc".into()),
                status: "completed".into(),
                conclusion: Some("failure".into()),
                url: "https://example.com".into(),
                updated_at: "2026-11-16T01:00:00.000Z".into(),
            };
        repo.apply_github_poll(
            &scope,
            GitHubPollCommit::Complete {
                etag: None,
                watermark: None,
            },
            |_tx, _baseline| {
                Ok(GitHubPollChanges {
                    pending_checks: GitHubPendingCheckUpdate {
                        repository: Some("o/r".into()),
                        upserts: vec![
                            pending(1, Some(1), Some(10)),
                            pending(2, Some(2), Some(20)),
                            pending(3, None, Some(10)),
                            pending(4, None, None),
                        ],
                        ..GitHubPendingCheckUpdate::default()
                    },
                    ..GitHubPollChanges::default()
                })
            },
        )
        .unwrap();

        // Attempt 2 must not delete the pending attempt 1 check.
        repo.apply_github_poll(
            &scope,
            GitHubPollCommit::Complete {
                etag: None,
                watermark: None,
            },
            |_tx, _baseline| {
                Ok(GitHubPollChanges {
                    pending_checks: GitHubPendingCheckUpdate {
                        repository: Some("o/r".into()),
                        resolve_workflow_runs: vec![GitHubPendingCheckResolution {
                            actions_run_id: Some(42),
                            check_suite_id: Some(20),
                            run_attempt: 2,
                        }],
                        ..GitHubPendingCheckUpdate::default()
                    },
                    ..GitHubPollChanges::default()
                })
            },
        )
        .unwrap();
        assert!(repo.get_github_pending_check("o/r", 1).unwrap().is_some());
        assert!(repo.get_github_pending_check("o/r", 2).unwrap().is_none());
        assert!(repo.get_github_pending_check("o/r", 3).unwrap().is_some());
        assert!(repo.get_github_pending_check("o/r", 4).unwrap().is_some());

        // A late attempt 1 webhook must not delete the pending attempt 2 check.
        repo.apply_github_poll(
            &scope,
            GitHubPollCommit::Complete {
                etag: None,
                watermark: None,
            },
            |_tx, _baseline| {
                Ok(GitHubPollChanges {
                    pending_checks: GitHubPendingCheckUpdate {
                        repository: Some("o/r".into()),
                        resolve_workflow_runs: vec![GitHubPendingCheckResolution {
                            actions_run_id: Some(42),
                            check_suite_id: Some(10),
                            run_attempt: 1,
                        }],
                        ..GitHubPendingCheckUpdate::default()
                    },
                    ..GitHubPollChanges::default()
                })
            },
        )
        .unwrap();
        assert!(repo.get_github_pending_check("o/r", 1).unwrap().is_none());
        assert!(repo.get_github_pending_check("o/r", 3).unwrap().is_none());
        assert!(repo.get_github_pending_check("o/r", 4).unwrap().is_none());
    }
}
