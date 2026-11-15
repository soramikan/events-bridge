//! GitHub REST API reconciliation.
//!
//! Webhooks are the fast path, but GitHub does not redeliver failed webhooks.
//! The poller therefore reconciles pull requests and workflow runs periodically.
//! Each repository/scope keeps an ETag and watermark in
//! `collector_checkpoints`; a `304 Not Modified` is a no-op, while the first
//! successful poll baselines existing history instead of notifying it.
//!
//! Pagination follows the `Link: rel="next"` header, but only to URLs on the
//! configured API origin and path prefix. The checkpoint is advanced only after
//! every page (and every tracked active run lookup) succeeds.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    sync::Mutex,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use reqwest::{
    Client,
    header::{ACCEPT, AUTHORIZATION, ETAG, HeaderMap, HeaderValue, IF_NONE_MATCH, USER_AGENT},
};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::{
    collectors::github_state::{
        bounded_display, bounded_url, is_failure_conclusion, parse_actions_run_ref,
        pr_merged_event, review_requested_event, reviewer_key, reviewer_name, valid_identifier,
        workflow_failed_event,
    },
    config::Config,
    event::EventBus,
    store::{
        GitHubCiRun, GitHubPendingCheck, GitHubPendingCheckResolution, GitHubPollChanges,
        GitHubPollCommit, GitHubPullRequest, Repository,
        github::{
            ci_failure_emitted_for_suite, delete_fallback_ci_runs, github_timestamp, load_ci_run,
            load_pull_request, pulls_scope, runs_scope,
        },
    },
    util::{format_rfc3339, now_rfc3339, parse_rfc3339, timestamp_lt},
};

/// Safety cap for one paginated list. GitHub's largest realistic backfill is
/// far below this; the cap prevents an unbounded loop on a malformed `Link`.
const MAX_PAGES: usize = 50;

/// Every N workflow-run passes, ignore the ETag and watermark and scan the
/// whole history. This catches reruns of old completed runs whose webhook was
/// missed even when page 1 is unchanged.
const FULL_RECONCILE_EVERY: u64 = 10;

/// Initial delay after a failed pass.
const INITIAL_BACKOFF: Duration = Duration::from_secs(1);

/// Maximum exponential backoff between failed passes.
const MAX_BACKOFF: Duration = Duration::from_secs(5 * 60);

/// Maximum honored `Retry-After` / rate-limit reset delay.
const MAX_RATE_LIMIT_BACKOFF: Duration = Duration::from_secs(60 * 60);

/// Resolved GitHub poller settings.
#[derive(Clone)]
pub struct GitHubPollerSettings {
    /// Watched `owner/repo` entries.
    pub repositories: Vec<String>,
    /// REST API base URL (for GitHub Enterprise or a test server).
    pub api_base_url: Url,
    /// Optional API token.
    pub token: Option<SecretString>,
    /// Reconciliation interval.
    pub poll_interval: Duration,
}

impl GitHubPollerSettings {
    /// Resolve settings from the daemon configuration and an already-read token.
    pub fn from_config(config: &Config, token: Option<SecretString>) -> Result<Self> {
        let github = &config.collectors.github;
        let api_base_url = Url::parse(&github.api_base_url).with_context(|| {
            format!(
                "collectors.github.api_base_url `{}` is not a URL",
                github.api_base_url
            )
        })?;
        Ok(Self {
            repositories: github.repositories.clone(),
            api_base_url,
            token,
            poll_interval: Duration::from_secs(github.poll_interval_secs.max(1)),
        })
    }
}

/// One reconciliation pass summary.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GitHubPollSummary {
    /// Repositories attempted.
    pub repositories: usize,
    /// Pull request rows applied.
    pub pull_requests: usize,
    /// CI run rows applied.
    pub ci_runs: usize,
    /// Newly emitted bridge events.
    pub events: usize,
    /// Delivery rows created.
    pub deliveries_created: usize,
    /// Responses that were `304 Not Modified`.
    pub not_modified: usize,
    /// Per-repository or per-scope failures that did not stop the pass.
    pub errors: usize,
}

/// Periodic GitHub REST reconciler.
pub struct GitHubPoller {
    settings: GitHubPollerSettings,
    repo: std::sync::Arc<Repository>,
    bus: EventBus,
    client: Client,
    run_poll_sequences: Mutex<HashMap<String, u64>>,
}

impl GitHubPoller {
    /// Create a poller. No network request is made until the first poll.
    pub fn new(
        settings: GitHubPollerSettings,
        repo: std::sync::Arc<Repository>,
        bus: EventBus,
    ) -> Result<Self> {
        let mut headers = HeaderMap::new();
        headers.insert(
            USER_AGENT,
            HeaderValue::from_static(concat!("events-bridge/", env!("CARGO_PKG_VERSION"))),
        );
        headers.insert(
            ACCEPT,
            HeaderValue::from_static("application/vnd.github+json"),
        );
        headers.insert(
            "x-github-api-version",
            HeaderValue::from_static("2022-11-28"),
        );
        if let Some(token) = &settings.token {
            let value = format!("Bearer {}", token.expose_secret());
            headers.insert(
                AUTHORIZATION,
                HeaderValue::from_str(&value)
                    .context("GitHub token contains characters invalid in a header")?,
            );
        }
        let client = Client::builder()
            .default_headers(headers)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .build()
            .context("building GitHub API client")?;
        Ok(Self {
            settings,
            repo,
            bus,
            client,
            run_poll_sequences: Mutex::new(HashMap::new()),
        })
    }

    fn next_run_poll_sequence(&self, repository: &str) -> u64 {
        let mut sequences = self
            .run_poll_sequences
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let entry = sequences.entry(repository.to_string()).or_insert(0);
        let current = *entry;
        *entry = current.wrapping_add(1);
        current
    }

    /// Build a poller from the daemon configuration.
    pub fn from_config(
        config: &Config,
        token: Option<SecretString>,
        repo: std::sync::Arc<Repository>,
        bus: EventBus,
    ) -> Result<Self> {
        Self::new(GitHubPollerSettings::from_config(config, token)?, repo, bus)
    }

    /// Reconcile every configured repository once.
    ///
    /// Per-repository and per-scope failures are counted and logged; only a
    /// global authentication or rate-limit failure stops the pass.
    pub async fn poll_once(&self) -> Result<GitHubPollSummary> {
        let mut summary = GitHubPollSummary::default();
        for repository in &self.settings.repositories {
            summary.repositories += 1;
            match self.poll_repository(repository).await {
                Ok(repository_summary) => {
                    summary.pull_requests += repository_summary.pull_requests;
                    summary.ci_runs += repository_summary.ci_runs;
                    summary.events += repository_summary.events;
                    summary.deliveries_created += repository_summary.deliveries_created;
                    summary.not_modified += repository_summary.not_modified;
                    summary.errors += repository_summary.errors;
                }
                Err(error) => {
                    if is_global_api_error(&error) {
                        tracing::warn!(
                            repository,
                            %error,
                            "GitHub reconciliation stopped for this pass"
                        );
                        return Err(error);
                    }
                    summary.errors += 1;
                    tracing::warn!(
                        repository,
                        %error,
                        "GitHub repository reconciliation failed"
                    );
                }
            }
        }
        Ok(summary)
    }

    /// Run until cancelled. The first pass runs immediately so startup
    /// reconciliation does not wait for one interval.
    pub async fn run(self, cancellation: CancellationToken) -> Result<()> {
        let interval = self.settings.poll_interval;
        let mut backoff = INITIAL_BACKOFF;
        loop {
            if cancellation.is_cancelled() {
                break;
            }
            let wait = match self.poll_once().await {
                Ok(summary) => {
                    backoff = INITIAL_BACKOFF;
                    if summary.events > 0 {
                        tracing::info!(
                            repositories = summary.repositories,
                            pull_requests = summary.pull_requests,
                            ci_runs = summary.ci_runs,
                            events = summary.events,
                            deliveries = summary.deliveries_created,
                            "GitHub reconciliation advanced"
                        );
                    }
                    if summary.errors > 0 {
                        tracing::warn!(
                            errors = summary.errors,
                            "GitHub reconciliation completed with per-repository errors"
                        );
                    }
                    interval
                }
                Err(error) => {
                    let retry_after = error
                        .downcast_ref::<GitHubApiError>()
                        .and_then(|error| error.retry_after)
                        .map(|retry_after| retry_after.min(MAX_RATE_LIMIT_BACKOFF));
                    let wait = retry_after.unwrap_or(backoff);
                    tracing::warn!(
                        %error,
                        wait = ?wait,
                        "GitHub reconciliation pass failed; will retry"
                    );
                    backoff = backoff.saturating_mul(2).min(MAX_BACKOFF);
                    wait
                }
            };
            tokio::select! {
                _ = cancellation.cancelled() => break,
                _ = tokio::time::sleep(wait) => {}
            }
        }
        Ok(())
    }

    async fn poll_repository(&self, repository: &str) -> Result<GitHubPollSummary> {
        let mut summary = GitHubPollSummary::default();
        match self.poll_pulls(repository, &mut summary).await {
            Ok(()) => {}
            Err(error) if is_global_api_error(&error) => return Err(error),
            Err(error) => {
                summary.errors += 1;
                tracing::warn!(
                    repository,
                    %error,
                    "GitHub pull request reconciliation failed"
                );
            }
        }
        match self.poll_runs(repository, &mut summary).await {
            Ok(()) => {}
            Err(error) if is_global_api_error(&error) => return Err(error),
            Err(error) => {
                summary.errors += 1;
                tracing::warn!(
                    repository,
                    %error,
                    "GitHub workflow run reconciliation failed"
                );
            }
        }
        Ok(summary)
    }

    async fn poll_pulls(&self, repository: &str, summary: &mut GitHubPollSummary) -> Result<()> {
        let scope = pulls_scope(repository);
        let checkpoint = self.repo.get_github_checkpoint(&scope)?;
        let continuation = self.repo.get_github_poll_continuation(&scope)?;
        let previous_watermark = checkpoint
            .as_ref()
            .and_then(|checkpoint| checkpoint.watermark.clone());
        let start_url = continuation
            .as_ref()
            .map(|continuation| continuation.next_url.as_str());
        let checkpoint_etag = if start_url.is_some() {
            None
        } else {
            checkpoint
                .as_ref()
                .and_then(|checkpoint| checkpoint.etag.as_deref())
        };
        let Some(fetched) = self
            .fetch_pulls(
                repository,
                previous_watermark.as_deref(),
                checkpoint_etag,
                start_url,
            )
            .await?
        else {
            summary.not_modified += 1;
            return Ok(());
        };

        let PullsFetch {
            etag: page_etag,
            items,
            truncated,
            next_url,
        } = fetched;
        let now = now_rfc3339();
        let base_watermark = continuation
            .as_ref()
            .and_then(|continuation| continuation.pending_watermark.clone())
            .or_else(|| previous_watermark.clone());
        let watermark = next_watermark(pulls_watermark(&items), base_watermark, &now);
        let etag = page_etag
            .or_else(|| {
                continuation
                    .as_ref()
                    .and_then(|continuation| continuation.pending_etag.clone())
            })
            .or_else(|| {
                checkpoint
                    .as_ref()
                    .and_then(|checkpoint| checkpoint.etag.clone())
            });
        let commit = match (truncated, next_url.as_deref()) {
            (true, Some(next_url)) => GitHubPollCommit::Truncated {
                next_url,
                pending_etag: etag.as_deref(),
                pending_watermark: Some(&watermark),
                full_reconcile: false,
            },
            _ => GitHubPollCommit::Complete {
                etag: etag.as_deref(),
                watermark: Some(&watermark),
            },
        };
        let outcome = self
            .repo
            .apply_github_poll(&scope, commit, |tx, baseline| {
                let mut changes = GitHubPollChanges::default();
                for dto in &items {
                    if dto.number <= 0 {
                        continue;
                    }
                    let previous = load_pull_request(tx, repository, dto.number)?;
                    if !baseline
                        && previous.is_none()
                        && previous_watermark
                            .as_deref()
                            .is_some_and(|watermark| pull_updated_before(dto, watermark))
                    {
                        // Historical item that was never seen before. It is
                        // part of the baseline, not a new notification.
                        continue;
                    }
                    let mut row = dto.to_row(repository, dto.number, previous.as_ref(), &now);
                    let stale = previous.as_ref().is_some_and(|previous| {
                        timestamp_lt(&row.updated_at, &previous.updated_at)
                    });
                    if baseline {
                        row.merged_emitted = row.merged;
                    } else {
                        let already = previous.as_ref().is_some_and(|pull| pull.merged_emitted);
                        row.merged_emitted = already;
                        if row.merged && !already {
                            row.merged_emitted = true;
                            changes.events.push(pr_merged_event(&row));
                        }
                        if !stale {
                            let previous_reviewers = previous
                                .as_ref()
                                .map(|pull| pull.requested_reviewers.as_slice())
                                .unwrap_or(&[]);
                            for reviewer in &row.requested_reviewers {
                                if !previous_reviewers.iter().any(|r| r == reviewer) {
                                    let marker = format!("poll|{}|{}", row.updated_at, reviewer);
                                    changes.events.push(review_requested_event(
                                        &row,
                                        Some(reviewer_name(reviewer)),
                                        &marker,
                                    ));
                                }
                            }
                        }
                    }
                    changes.pull_requests.push(row);
                }
                Ok(changes)
            })?;
        summary.pull_requests += items.len();
        summary.events += outcome.emitted();
        summary.deliveries_created += outcome.deliveries_created;
        if outcome.emitted() > 0 {
            self.bus.notify();
        }
        Ok(())
    }

    async fn poll_runs(&self, repository: &str, summary: &mut GitHubPollSummary) -> Result<()> {
        let scope = runs_scope(repository);
        let checkpoint = self.repo.get_github_checkpoint(&scope)?;
        let continuation = self.repo.get_github_poll_continuation(&scope)?;
        let previous_watermark = checkpoint
            .as_ref()
            .and_then(|checkpoint| checkpoint.watermark.clone());
        let scheduled_full = self
            .next_run_poll_sequence(repository)
            .is_multiple_of(FULL_RECONCILE_EVERY);
        let full_reconcile = continuation
            .as_ref()
            .is_some_and(|continuation| continuation.full_reconcile)
            || scheduled_full;
        let start_url = continuation
            .as_ref()
            .map(|continuation| continuation.next_url.as_str());
        let checkpoint_etag = if start_url.is_some() || full_reconcile {
            None
        } else {
            checkpoint
                .as_ref()
                .and_then(|checkpoint| checkpoint.etag.as_deref())
        };
        let stop_watermark = if full_reconcile {
            None
        } else {
            previous_watermark.as_deref()
        };
        let fetched = self
            .fetch_runs(repository, stop_watermark, checkpoint_etag, start_url)
            .await?;

        let mut runs: Vec<WorkflowRunDto> = fetched
            .as_ref()
            .map(|fetched| fetched.items.clone())
            .unwrap_or_default();
        let seen: HashSet<i64> = runs.iter().map(|run| run.id).collect();

        let active = self.repo.list_active_github_ci_runs(repository)?;
        let pending = self.repo.list_github_pending_checks(repository)?;
        let open_pull_runs = self.repo.list_github_ci_runs_for_open_pulls(repository)?;

        let mut extra_fetches: BTreeSet<(i64, Option<i64>)> = BTreeSet::new();
        for run in &active {
            if run.status != "completed"
                && let Ok(run_id) = run.canonical_run_id.parse::<i64>()
                && run_id > 0
            {
                extra_fetches.insert((run_id, None));
            }
        }
        for check in &pending {
            if let Some(run_id) = check.actions_run_id.filter(|run_id| *run_id > 0) {
                extra_fetches.insert((run_id, check.parsed_attempt));
            }
        }
        // `/actions/runs` is ordered by `created_at` descending. A rerun of an
        // older completed run stays on an older page, so re-check every known
        // run that belongs to an open pull request and was not seen in this
        // pass. This works even when page 1 returned `304`.
        for run in &open_pull_runs {
            if let Ok(run_id) = run.canonical_run_id.parse::<i64>()
                && run_id > 0
                && !seen.contains(&run_id)
            {
                extra_fetches.insert((run_id, None));
            }
        }

        let mut extra_errors = 0;
        for (run_id, attempt) in extra_fetches {
            if runs.iter().any(|run| {
                run.id == run_id && attempt.is_none_or(|attempt| run.run_attempt == attempt)
            }) {
                continue;
            }
            match self.fetch_run_attempt(repository, run_id, attempt).await {
                Ok(Some(dto)) => runs.push(dto),
                Ok(None) => {}
                Err(error) if is_global_api_error(&error) => return Err(error),
                Err(error) => {
                    extra_errors += 1;
                    tracing::warn!(
                        repository,
                        run_id,
                        %error,
                        "GitHub workflow run lookup failed"
                    );
                }
            }
        }

        // A pending check without an explicit attempt may belong to an earlier
        // attempt of a rerun. Fetch the earlier attempts until one matches the
        // pending check's check suite.
        for check in &pending {
            let Some(run_id) = check.actions_run_id else {
                continue;
            };
            if check.parsed_attempt.is_some() {
                continue;
            }
            let Some(latest) = runs
                .iter()
                .filter(|run| run.id == run_id)
                .max_by_key(|run| run.run_attempt)
            else {
                continue;
            };
            if latest.run_attempt <= 1 {
                continue;
            }
            if check.check_suite_id.is_some() && latest.check_suite_id == check.check_suite_id {
                continue;
            }
            for attempt in 1..latest.run_attempt {
                if runs
                    .iter()
                    .any(|run| run.id == run_id && run.run_attempt == attempt)
                {
                    continue;
                }
                match self
                    .fetch_run_attempt(repository, run_id, Some(attempt))
                    .await
                {
                    Ok(Some(dto)) => {
                        let matches = check.check_suite_id.is_none()
                            || dto.check_suite_id == check.check_suite_id;
                        runs.push(dto);
                        if matches {
                            break;
                        }
                    }
                    Ok(None) => {}
                    Err(error) if is_global_api_error(&error) => return Err(error),
                    Err(error) => {
                        extra_errors += 1;
                        tracing::warn!(
                            repository,
                            run_id,
                            attempt,
                            %error,
                            "GitHub workflow run attempt lookup failed"
                        );
                    }
                }
            }
        }

        // Pending Actions checks that never carried an actions run id can still
        // be resolved through their check suite or the check-runs endpoint.
        let mut resolved_check_run_ids = Vec::new();
        for check in &pending {
            if check.actions_run_id.is_some() {
                continue;
            }
            match self.resolve_pending_check_run(repository, check).await {
                Ok(Some(resolved)) => {
                    if pending_check_matches_run(
                        resolved.parsed_attempt,
                        resolved.check_suite_id,
                        &resolved.run,
                    ) {
                        resolved_check_run_ids.push(check.check_run_id);
                    }
                    if !runs.iter().any(|run| {
                        run.id == resolved.run.id && run.run_attempt == resolved.run.run_attempt
                    }) {
                        runs.push(resolved.run);
                    }
                }
                Ok(None) => {}
                Err(error) if is_global_api_error(&error) => return Err(error),
                Err(error) => {
                    extra_errors += 1;
                    tracing::warn!(
                        repository,
                        check_run_id = check.check_run_id,
                        %error,
                        "GitHub pending check lookup failed"
                    );
                }
            }
        }

        if extra_errors > 0 {
            // Do not advance the checkpoint when a tracked run lookup failed;
            // the next pass retries the whole scope.
            return Err(anyhow::anyhow!(
                "{extra_errors} tracked GitHub workflow run lookup(s) failed"
            ));
        }

        if fetched.is_none() && runs.is_empty() {
            summary.not_modified += 1;
            return Ok(());
        }

        // Deduplicate by (run id, attempt), preferring the most recently
        // updated observation.
        let mut deduped: BTreeMap<(i64, i64), WorkflowRunDto> = BTreeMap::new();
        for run in runs {
            let key = (run.id, run.run_attempt.max(1));
            let replace = deduped.get(&key).is_none_or(|existing| {
                existing.updated_at.as_deref().unwrap_or_default()
                    <= run.updated_at.as_deref().unwrap_or_default()
            });
            if replace {
                deduped.insert(key, run);
            }
        }
        let runs: Vec<WorkflowRunDto> = deduped.into_values().collect();

        let now = now_rfc3339();
        let base_watermark = continuation
            .as_ref()
            .and_then(|continuation| continuation.pending_watermark.clone())
            .or_else(|| previous_watermark.clone());
        let watermark = next_watermark(runs_watermark(&runs), base_watermark, &now);
        let etag = fetched
            .as_ref()
            .and_then(|fetched| fetched.etag.clone())
            .or_else(|| {
                continuation
                    .as_ref()
                    .and_then(|continuation| continuation.pending_etag.clone())
            })
            .or_else(|| {
                checkpoint
                    .as_ref()
                    .and_then(|checkpoint| checkpoint.etag.clone())
            });
        let truncated = fetched.as_ref().is_some_and(|fetched| fetched.truncated);
        let next_url = fetched
            .as_ref()
            .and_then(|fetched| fetched.next_url.clone());
        let commit = match (truncated, next_url.as_deref()) {
            (true, Some(next_url)) => GitHubPollCommit::Truncated {
                next_url,
                pending_etag: etag.as_deref(),
                pending_watermark: Some(&watermark),
                full_reconcile,
            },
            _ => GitHubPollCommit::Complete {
                etag: etag.as_deref(),
                watermark: Some(&watermark),
            },
        };
        let outcome = self
            .repo
            .apply_github_poll(&scope, commit, |tx, baseline| {
                let mut changes = GitHubPollChanges::default();
                changes.pending_checks.repository = Some(repository.to_string());
                changes.pending_checks.resolve_check_run_ids = resolved_check_run_ids;
                for dto in &runs {
                    if dto.id <= 0 {
                        continue;
                    }
                    let attempt = dto.run_attempt.max(1);
                    let canonical_run_id = dto.id.to_string();
                    let previous = load_ci_run(tx, repository, &canonical_run_id, attempt)?;
                    let workflow_name = dto
                        .name
                        .as_deref()
                        .map(bounded_display)
                        .filter(|name| !name.is_empty())
                        .or_else(|| previous.as_ref().map(|run| run.workflow_name.clone()))
                        .unwrap_or_else(|| "workflow".to_string());
                    let url = dto
                        .html_url
                        .as_deref()
                        .map(bounded_url)
                        .filter(|url| !url.is_empty())
                        .or_else(|| previous.as_ref().map(|run| run.url.clone()))
                        .unwrap_or_else(|| {
                            bounded_url(&format!(
                                "https://github.com/{repository}/actions/runs/{}",
                                dto.id
                            ))
                        });
                    let head_branch = dto
                        .head_branch
                        .as_deref()
                        .map(bounded_display)
                        .filter(|branch| !branch.is_empty())
                        .or_else(|| previous.as_ref().and_then(|run| run.head_branch.clone()));
                    let head_sha = dto
                        .head_sha
                        .as_deref()
                        .and_then(|sha| valid_identifier(sha, 128))
                        .or_else(|| previous.as_ref().and_then(|run| run.head_sha.clone()));
                    let check_suite_id = dto
                        .check_suite_id
                        .filter(|id| *id > 0)
                        .or_else(|| previous.as_ref().and_then(|run| run.check_suite_id));
                    let status = if dto.status.is_empty() {
                        previous
                            .as_ref()
                            .map(|run| run.status.clone())
                            .unwrap_or_else(|| "completed".to_string())
                    } else {
                        dto.status.clone()
                    };
                    let updated_at = github_timestamp(dto.updated_at.as_deref(), &now);
                    let stale = previous
                        .as_ref()
                        .is_some_and(|previous| timestamp_lt(&updated_at, &previous.updated_at));
                    let failure =
                        status == "completed" && is_failure_conclusion(dto.conclusion.as_deref());
                    let suite_emitted = if stale {
                        false
                    } else {
                        match check_suite_id {
                            Some(check_suite_id) => ci_failure_emitted_for_suite(
                                tx,
                                repository,
                                check_suite_id,
                                attempt,
                            )?,
                            None => false,
                        }
                    };
                    let mut failure_emitted =
                        previous.as_ref().is_some_and(|run| run.failure_emitted);
                    if baseline {
                        failure_emitted = failure_emitted || failure;
                        if suite_emitted
                            && previous.is_none()
                            && let Some(check_suite_id) = check_suite_id
                        {
                            delete_fallback_ci_runs(tx, repository, check_suite_id, attempt)?;
                        }
                    } else if failure && !stale && !failure_emitted {
                        failure_emitted = true;
                        if suite_emitted {
                            if let Some(check_suite_id) = check_suite_id {
                                delete_fallback_ci_runs(tx, repository, check_suite_id, attempt)?;
                            }
                        } else {
                            changes.events.push(workflow_failed_event(
                                repository,
                                &workflow_name,
                                &canonical_run_id,
                                attempt,
                                dto.conclusion.as_deref().unwrap_or("failure"),
                                head_branch.as_deref(),
                                &url,
                                &updated_at,
                            ));
                        }
                    }
                    if !stale {
                        changes.pending_checks.resolve_workflow_runs.push(
                            GitHubPendingCheckResolution {
                                actions_run_id: Some(dto.id),
                                check_suite_id,
                                run_attempt: attempt,
                            },
                        );
                    }
                    changes.ci_runs.push(GitHubCiRun {
                        repository: repository.to_string(),
                        canonical_run_id,
                        run_attempt: attempt,
                        check_suite_id,
                        workflow_name,
                        head_branch,
                        head_sha,
                        status,
                        conclusion: dto.conclusion.clone(),
                        url,
                        failure_emitted,
                        updated_at,
                    });
                }
                Ok(changes)
            })?;
        summary.ci_runs += runs.len();
        summary.events += outcome.emitted();
        summary.deliveries_created += outcome.deliveries_created;
        if outcome.emitted() > 0 {
            self.bus.notify();
        }
        Ok(())
    }

    fn api_base(&self) -> &str {
        self.settings.api_base_url.as_str().trim_end_matches('/')
    }

    /// Reject a URL that is not on the configured API origin and path prefix.
    fn validate_api_url(&self, url: &str) -> Result<Url> {
        let parsed = Url::parse(url).with_context(|| format!("invalid GitHub API URL `{url}`"))?;
        let base = &self.settings.api_base_url;
        if parsed.scheme() != base.scheme()
            || parsed.host_str() != base.host_str()
            || parsed.port_or_known_default() != base.port_or_known_default()
        {
            bail!("refusing GitHub API URL outside the configured origin: {url}");
        }
        if !parsed.username().is_empty() || parsed.password().is_some() {
            bail!("refusing GitHub API URL with userinfo: {url}");
        }
        let base_path = base.path().trim_end_matches('/');
        if !base_path.is_empty() && base_path != "/" {
            let path = parsed.path();
            if path != base_path && !path.starts_with(&format!("{base_path}/")) {
                bail!("refusing GitHub API URL outside the configured path prefix: {url}");
            }
        }
        Ok(parsed)
    }

    async fn fetch_pulls(
        &self,
        repository: &str,
        previous_watermark: Option<&str>,
        checkpoint_etag: Option<&str>,
        start_url: Option<&str>,
    ) -> Result<Option<PullsFetch>> {
        let mut url = match start_url {
            Some(url) => {
                self.validate_api_url(url)?;
                url.to_string()
            }
            None => format!(
                "{}/repos/{repository}/pulls?state=all&sort=updated&direction=desc&per_page=100",
                self.api_base()
            ),
        };
        let mut etag = None;
        let mut items = Vec::new();
        let mut truncated = false;
        let mut next_url = None;
        for page in 1..=MAX_PAGES {
            let page_etag = if page == 1 && start_url.is_none() {
                checkpoint_etag
            } else {
                None
            };
            let fetch = self.fetch_page::<Vec<PullDto>>(&url, page_etag).await?;
            match fetch {
                Fetch::NotModified => {
                    if page == 1 && start_url.is_none() {
                        return Ok(None);
                    }
                    break;
                }
                Fetch::Fresh {
                    etag: fetched_etag,
                    body,
                    next,
                } => {
                    if page == 1 && start_url.is_none() {
                        etag = fetched_etag;
                    }
                    let stop = previous_watermark.is_some_and(|watermark| {
                        !body.is_empty()
                            && body.iter().all(|pull| pull_updated_before(pull, watermark))
                    });
                    items.extend(body);
                    if stop {
                        break;
                    }
                    match next {
                        Some(next) => {
                            self.validate_api_url(&next)?;
                            if page == MAX_PAGES {
                                truncated = true;
                                next_url = Some(next);
                                break;
                            }
                            url = next;
                        }
                        None => break,
                    }
                }
            }
        }
        Ok(Some(PullsFetch {
            etag,
            items,
            truncated,
            next_url,
        }))
    }

    async fn fetch_runs(
        &self,
        repository: &str,
        previous_watermark: Option<&str>,
        checkpoint_etag: Option<&str>,
        start_url: Option<&str>,
    ) -> Result<Option<RunsFetch>> {
        let mut url = match start_url {
            Some(url) => {
                self.validate_api_url(url)?;
                url.to_string()
            }
            None => format!(
                "{}/repos/{repository}/actions/runs?per_page=100",
                self.api_base()
            ),
        };
        let mut etag = None;
        let mut items = Vec::new();
        let mut truncated = false;
        let mut next_url = None;
        for page in 1..=MAX_PAGES {
            let page_etag = if page == 1 && start_url.is_none() {
                checkpoint_etag
            } else {
                None
            };
            let fetch = self.fetch_page::<WorkflowRunsDto>(&url, page_etag).await?;
            match fetch {
                Fetch::NotModified => {
                    if page == 1 && start_url.is_none() {
                        return Ok(None);
                    }
                    break;
                }
                Fetch::Fresh {
                    etag: fetched_etag,
                    body,
                    next,
                } => {
                    if page == 1 && start_url.is_none() {
                        etag = fetched_etag;
                    }
                    let stop = previous_watermark.is_some_and(|watermark| {
                        !body.workflow_runs.is_empty()
                            && body
                                .workflow_runs
                                .iter()
                                .all(|run| run_before(run, watermark))
                    });
                    items.extend(body.workflow_runs);
                    if stop {
                        break;
                    }
                    match next {
                        Some(next) => {
                            self.validate_api_url(&next)?;
                            if page == MAX_PAGES {
                                truncated = true;
                                next_url = Some(next);
                                break;
                            }
                            url = next;
                        }
                        None => break,
                    }
                }
            }
        }
        Ok(Some(RunsFetch {
            etag,
            items,
            truncated,
            next_url,
        }))
    }

    async fn fetch_run_attempt(
        &self,
        repository: &str,
        run_id: i64,
        attempt: Option<i64>,
    ) -> Result<Option<WorkflowRunDto>> {
        let url = match attempt {
            Some(attempt) => format!(
                "{}/repos/{repository}/actions/runs/{run_id}/attempts/{attempt}",
                self.api_base()
            ),
            None => format!(
                "{}/repos/{repository}/actions/runs/{run_id}",
                self.api_base()
            ),
        };
        match self.fetch_page::<WorkflowRunDto>(&url, None).await {
            Ok(Fetch::Fresh { body, .. }) => Ok(Some(body)),
            Ok(Fetch::NotModified) => Ok(None),
            Err(error) if is_not_found(&error) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Resolve a pending Actions check that has no `actions_run_id`.
    async fn resolve_pending_check_run(
        &self,
        repository: &str,
        check: &GitHubPendingCheck,
    ) -> Result<Option<ResolvedPendingCheck>> {
        if let Some(suite_id) = check.check_suite_id {
            return Ok(self
                .fetch_run_for_check_suite(repository, suite_id)
                .await?
                .map(|run| ResolvedPendingCheck {
                    run,
                    parsed_attempt: check.parsed_attempt,
                    check_suite_id: Some(suite_id),
                }));
        }
        let url = format!(
            "{}/repos/{repository}/check-runs/{}",
            self.api_base(),
            check.check_run_id
        );
        let Fetch::Fresh { body, .. } = self.fetch_page::<CheckRunDto>(&url, None).await? else {
            return Ok(None);
        };
        let discovered_suite_id = body
            .check_suite
            .as_ref()
            .and_then(|suite| suite.id)
            .filter(|id| *id > 0);
        if let Some((run_id, attempt)) =
            parse_actions_run_ref(body.details_url.as_deref().or(body.html_url.as_deref()))
            && let Ok(run_id) = run_id.parse::<i64>()
            && run_id > 0
        {
            if let Some(run) = self.fetch_run_attempt(repository, run_id, attempt).await? {
                return Ok(Some(ResolvedPendingCheck {
                    run,
                    parsed_attempt: check.parsed_attempt.or(attempt),
                    check_suite_id: check.check_suite_id.or(discovered_suite_id),
                }));
            }
            if let Some(suite_id) = discovered_suite_id {
                return Ok(self
                    .fetch_run_for_check_suite(repository, suite_id)
                    .await?
                    .map(|run| ResolvedPendingCheck {
                        run,
                        parsed_attempt: check.parsed_attempt.or(attempt),
                        check_suite_id: Some(suite_id),
                    }));
            }
            return Ok(None);
        }
        if let Some(suite_id) = discovered_suite_id {
            return Ok(self
                .fetch_run_for_check_suite(repository, suite_id)
                .await?
                .map(|run| ResolvedPendingCheck {
                    run,
                    parsed_attempt: check.parsed_attempt,
                    check_suite_id: Some(suite_id),
                }));
        }
        Ok(None)
    }

    async fn fetch_run_for_check_suite(
        &self,
        repository: &str,
        suite_id: i64,
    ) -> Result<Option<WorkflowRunDto>> {
        let url = format!(
            "{}/repos/{repository}/actions/runs?check_suite_id={suite_id}&per_page=100",
            self.api_base()
        );
        match self.fetch_page::<WorkflowRunsDto>(&url, None).await? {
            Fetch::Fresh { body, .. } => Ok(body
                .workflow_runs
                .into_iter()
                .filter(|run| run.check_suite_id == Some(suite_id))
                .max_by_key(|run| run.run_attempt)),
            Fetch::NotModified => Ok(None),
        }
    }

    async fn fetch_page<T: DeserializeOwned>(
        &self,
        url: &str,
        etag: Option<&str>,
    ) -> Result<Fetch<T>> {
        let parsed = self.validate_api_url(url)?;
        let mut request = self.client.get(parsed);
        if let Some(etag) = etag {
            request = request.header(IF_NONE_MATCH, etag);
        }
        let response = request.send().await.context("GitHub API request")?;
        let status = response.status();
        let headers = response.headers().clone();
        match status.as_u16() {
            304 => Ok(Fetch::NotModified),
            200 => {
                let etag = headers
                    .get(ETAG)
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_string);
                let next = next_link(&headers);
                let body = response
                    .json::<T>()
                    .await
                    .context("decoding GitHub API response")?;
                Ok(Fetch::Fresh { etag, body, next })
            }
            401 => Err(GitHubApiError::new(
                401,
                ApiErrorKind::Auth,
                None,
                response.text().await.unwrap_or_default(),
            )
            .into()),
            403 => {
                let retry_after = rate_limit_retry_after(&headers);
                let kind = if retry_after.is_some() {
                    ApiErrorKind::RateLimited
                } else {
                    ApiErrorKind::Forbidden
                };
                Err(GitHubApiError::new(
                    403,
                    kind,
                    retry_after,
                    response.text().await.unwrap_or_default(),
                )
                .into())
            }
            404 => Err(GitHubApiError::new(
                404,
                ApiErrorKind::NotFound,
                None,
                response.text().await.unwrap_or_default(),
            )
            .into()),
            429 => {
                let retry_after =
                    rate_limit_retry_after(&headers).or(Some(Duration::from_secs(60)));
                Err(GitHubApiError::new(
                    429,
                    ApiErrorKind::RateLimited,
                    retry_after,
                    response.text().await.unwrap_or_default(),
                )
                .into())
            }
            status => {
                let retry_after = rate_limit_retry_after(&headers);
                let kind = if retry_after.is_some() {
                    ApiErrorKind::RateLimited
                } else {
                    ApiErrorKind::Other
                };
                Err(GitHubApiError::new(
                    status,
                    kind,
                    retry_after,
                    response.text().await.unwrap_or_default(),
                )
                .into())
            }
        }
    }
}

enum Fetch<T> {
    NotModified,
    Fresh {
        etag: Option<String>,
        body: T,
        next: Option<String>,
    },
}

struct PullsFetch {
    etag: Option<String>,
    items: Vec<PullDto>,
    truncated: bool,
    next_url: Option<String>,
}

struct RunsFetch {
    etag: Option<String>,
    items: Vec<WorkflowRunDto>,
    truncated: bool,
    next_url: Option<String>,
}

struct ResolvedPendingCheck {
    run: WorkflowRunDto,
    parsed_attempt: Option<i64>,
    check_suite_id: Option<i64>,
}

/// Whether a resolved run attempt corresponds to a parked check.
fn pending_check_matches_run(
    parsed_attempt: Option<i64>,
    check_suite_id: Option<i64>,
    run: &WorkflowRunDto,
) -> bool {
    if let Some(attempt) = parsed_attempt {
        return run.run_attempt == attempt;
    }
    if let Some(suite_id) = check_suite_id {
        return run.check_suite_id == Some(suite_id);
    }
    run.run_attempt == 1
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApiErrorKind {
    Auth,
    RateLimited,
    NotFound,
    Forbidden,
    Other,
}

#[derive(Debug)]
struct GitHubApiError {
    status: u16,
    kind: ApiErrorKind,
    retry_after: Option<Duration>,
    detail: String,
}

impl GitHubApiError {
    fn new(status: u16, kind: ApiErrorKind, retry_after: Option<Duration>, detail: String) -> Self {
        Self {
            status,
            kind,
            retry_after,
            detail,
        }
    }
}

impl std::fmt::Display for GitHubApiError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "GitHub API returned HTTP {} ({:?})",
            self.status, self.kind
        )?;
        if let Some(retry_after) = self.retry_after {
            write!(formatter, "; retry after {retry_after:?}")?;
        }
        if !self.detail.is_empty() {
            write!(formatter, ": {}", truncate_detail(&self.detail))?;
        }
        Ok(())
    }
}

impl std::error::Error for GitHubApiError {}

fn truncate_detail(value: &str) -> String {
    value.chars().take(512).collect()
}

fn is_global_api_error(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<GitHubApiError>()
        .is_some_and(|error| matches!(error.kind, ApiErrorKind::Auth | ApiErrorKind::RateLimited))
}

fn is_not_found(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<GitHubApiError>()
        .is_some_and(|error| error.kind == ApiErrorKind::NotFound)
}

fn rate_limit_retry_after(headers: &HeaderMap) -> Option<Duration> {
    if let Some(value) = headers
        .get("retry-after")
        .and_then(|value| value.to_str().ok())
    {
        let value = value.trim();
        if let Ok(seconds) = value.parse::<u64>() {
            return Some(Duration::from_secs(seconds));
        }
        if let Ok(date) = DateTime::parse_from_rfc2822(value) {
            let seconds = (date.with_timezone(&Utc) - Utc::now()).num_seconds().max(1) as u64;
            return Some(Duration::from_secs(seconds));
        }
    }
    let remaining = headers
        .get("x-ratelimit-remaining")
        .and_then(|value| value.to_str().ok())
        .map(str::trim);
    if remaining == Some("0") {
        let seconds = headers
            .get("x-ratelimit-reset")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse::<i64>().ok())
            .map(|reset| (reset - Utc::now().timestamp()).max(1) as u64)
            .unwrap_or(60);
        return Some(Duration::from_secs(seconds));
    }
    None
}

fn next_link(headers: &HeaderMap) -> Option<String> {
    for value in headers.get_all("link") {
        let Ok(text) = value.to_str() else {
            continue;
        };
        if let Some(next) = parse_link_next(text) {
            return Some(next);
        }
    }
    None
}

fn parse_link_next(value: &str) -> Option<String> {
    for part in value.split(',') {
        let mut pieces = part.split(';');
        let Some(target) = pieces.next() else {
            continue;
        };
        let target = target.trim();
        let Some(target) = target
            .strip_prefix('<')
            .and_then(|target| target.strip_suffix('>'))
        else {
            continue;
        };
        let mut is_next = false;
        for parameter in pieces {
            let parameter = parameter.trim();
            if let Some(rel) = parameter.strip_prefix("rel=") {
                let rel = rel.trim_matches('"');
                if rel.split_whitespace().any(|rel| rel == "next") {
                    is_next = true;
                }
            }
        }
        if is_next {
            return Some(target.to_string());
        }
    }
    None
}

fn pulls_watermark(pulls: &[PullDto]) -> Option<String> {
    max_timestamp(pulls.iter().filter_map(|pull| pull.updated_at.as_deref()))
}

fn runs_watermark(runs: &[WorkflowRunDto]) -> Option<String> {
    max_timestamp(
        runs.iter()
            .filter_map(|run| run.updated_at.as_deref().or(run.created_at.as_deref())),
    )
}

fn max_timestamp<'a>(values: impl Iterator<Item = &'a str>) -> Option<String> {
    values.filter_map(parse_rfc3339).max().map(format_rfc3339)
}

/// Never let a bounded page rewind the stored watermark.
fn next_watermark(computed: Option<String>, previous: Option<String>, now: &str) -> String {
    match (computed, previous) {
        (Some(computed), Some(previous)) => {
            if timestamp_lt(&computed, &previous) {
                previous
            } else {
                computed
            }
        }
        (Some(computed), None) => computed,
        (None, Some(previous)) => previous,
        (None, None) => now.to_string(),
    }
}

fn pull_updated_before(pull: &PullDto, watermark: &str) -> bool {
    match (
        pull.updated_at.as_deref().and_then(parse_rfc3339),
        parse_rfc3339(watermark),
    ) {
        (Some(updated_at), Some(watermark)) => updated_at < watermark,
        _ => false,
    }
}

fn run_before(run: &WorkflowRunDto, watermark: &str) -> bool {
    let created_at = run.created_at.as_deref().and_then(parse_rfc3339);
    let updated_at = run.updated_at.as_deref().and_then(parse_rfc3339);
    let Some(watermark) = parse_rfc3339(watermark) else {
        return false;
    };
    match (created_at, updated_at) {
        (Some(created_at), Some(updated_at)) => created_at < watermark && updated_at < watermark,
        (Some(created_at), None) => created_at < watermark,
        (None, Some(updated_at)) => updated_at < watermark,
        (None, None) => false,
    }
}

#[derive(Debug, Clone, Deserialize)]
struct PullDto {
    #[serde(default)]
    number: i64,
    #[serde(default)]
    title: String,
    #[serde(default)]
    state: String,
    #[serde(default)]
    user: Option<UserDto>,
    #[serde(default)]
    head: Option<RefDto>,
    #[serde(default)]
    base: Option<RefDto>,
    #[serde(default)]
    draft: Option<bool>,
    #[serde(default)]
    merged: Option<bool>,
    #[serde(default)]
    merged_by: Option<UserDto>,
    #[serde(default)]
    merged_at: Option<String>,
    #[serde(default)]
    requested_reviewers: Option<Vec<UserDto>>,
    #[serde(default)]
    requested_teams: Option<Vec<TeamDto>>,
    #[serde(default)]
    html_url: Option<String>,
    #[serde(default)]
    updated_at: Option<String>,
}

impl PullDto {
    fn to_row(
        &self,
        repository: &str,
        pull_number: i64,
        previous: Option<&GitHubPullRequest>,
        now: &str,
    ) -> GitHubPullRequest {
        let merged_at = self
            .merged_at
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let merged = self.merged.unwrap_or(false)
            || merged_at.is_some()
            || previous.is_some_and(|pull| pull.merged);
        let requested_reviewers = match (&self.requested_reviewers, &self.requested_teams) {
            (None, None) => previous
                .map(|pull| pull.requested_reviewers.clone())
                .unwrap_or_default(),
            (users, teams) => {
                let mut keys = Vec::new();
                if let Some(users) = users {
                    for user in users {
                        if let Some(login) = user
                            .login
                            .as_deref()
                            .map(str::trim)
                            .filter(|login| !login.is_empty())
                        {
                            keys.push(reviewer_key("user", login));
                        }
                    }
                } else if let Some(previous) = previous {
                    keys.extend(
                        previous
                            .requested_reviewers
                            .iter()
                            .filter(|key| key.starts_with("user:"))
                            .cloned(),
                    );
                }
                if let Some(teams) = teams {
                    for team in teams {
                        if let Some(slug) = team
                            .slug
                            .as_deref()
                            .map(str::trim)
                            .filter(|slug| !slug.is_empty())
                        {
                            keys.push(reviewer_key("team", slug));
                        }
                    }
                } else if let Some(previous) = previous {
                    keys.extend(
                        previous
                            .requested_reviewers
                            .iter()
                            .filter(|key| key.starts_with("team:"))
                            .cloned(),
                    );
                }
                dedup_keys(keys)
            }
        };
        GitHubPullRequest {
            repository: repository.to_string(),
            pull_number,
            title: if self.title.trim().is_empty() {
                previous.map(|pull| pull.title.clone()).unwrap_or_default()
            } else {
                bounded_display(&self.title)
            },
            state: if self.state.trim().is_empty() {
                previous
                    .map(|pull| pull.state.clone())
                    .unwrap_or_else(|| "open".to_string())
            } else {
                bounded_display(&self.state)
            },
            author: self
                .user
                .as_ref()
                .and_then(|user| user.login.as_deref())
                .map(bounded_display)
                .filter(|login| !login.is_empty())
                .or_else(|| previous.and_then(|pull| pull.author.clone())),
            head_branch: self
                .head
                .as_ref()
                .and_then(|head| head.branch.as_deref())
                .map(bounded_display)
                .filter(|branch| !branch.is_empty())
                .or_else(|| previous.and_then(|pull| pull.head_branch.clone())),
            head_sha: self
                .head
                .as_ref()
                .and_then(|head| head.sha.as_deref())
                .and_then(|sha| valid_identifier(sha, 128))
                .or_else(|| previous.and_then(|pull| pull.head_sha.clone())),
            base_branch: self
                .base
                .as_ref()
                .and_then(|base| base.branch.as_deref())
                .map(bounded_display)
                .filter(|branch| !branch.is_empty())
                .or_else(|| previous.and_then(|pull| pull.base_branch.clone())),
            draft: self
                .draft
                .or_else(|| previous.map(|pull| pull.draft))
                .unwrap_or(false),
            merged,
            merged_by: self
                .merged_by
                .as_ref()
                .and_then(|user| user.login.as_deref())
                .map(bounded_display)
                .filter(|login| !login.is_empty())
                .or_else(|| previous.and_then(|pull| pull.merged_by.clone())),
            merged_at: merged_at
                .map(|value| github_timestamp(Some(value), now))
                .or_else(|| previous.and_then(|pull| pull.merged_at.clone())),
            requested_reviewers,
            last_review_state: previous.and_then(|pull| pull.last_review_state.clone()),
            last_activity_at: previous.and_then(|pull| pull.last_activity_at.clone()),
            url: self
                .html_url
                .as_deref()
                .map(bounded_url)
                .filter(|url| !url.is_empty())
                .or_else(|| previous.map(|pull| pull.url.clone()))
                .unwrap_or_else(|| {
                    bounded_url(&format!(
                        "https://github.com/{repository}/pull/{pull_number}"
                    ))
                }),
            merged_emitted: previous.is_some_and(|pull| pull.merged_emitted),
            updated_at: github_timestamp(self.updated_at.as_deref(), now),
        }
    }
}

fn dedup_keys(keys: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    keys.into_iter()
        .filter(|key| seen.insert(key.clone()))
        .collect()
}

#[derive(Debug, Clone, Deserialize)]
struct UserDto {
    #[serde(default)]
    login: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct TeamDto {
    #[serde(default)]
    slug: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct RefDto {
    #[serde(default, rename = "ref")]
    branch: Option<String>,
    #[serde(default)]
    sha: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct WorkflowRunsDto {
    #[serde(default)]
    workflow_runs: Vec<WorkflowRunDto>,
}

#[derive(Debug, Clone, Deserialize)]
struct WorkflowRunDto {
    id: i64,
    #[serde(default = "default_run_attempt")]
    run_attempt: i64,
    #[serde(default)]
    check_suite_id: Option<i64>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    head_branch: Option<String>,
    #[serde(default)]
    head_sha: Option<String>,
    #[serde(default)]
    status: String,
    #[serde(default)]
    conclusion: Option<String>,
    #[serde(default)]
    html_url: Option<String>,
    #[serde(default)]
    created_at: Option<String>,
    #[serde(default)]
    updated_at: Option<String>,
}

fn default_run_attempt() -> i64 {
    1
}

#[derive(Debug, Clone, Deserialize)]
struct CheckRunDto {
    #[serde(default)]
    details_url: Option<String>,
    #[serde(default)]
    html_url: Option<String>,
    #[serde(default)]
    check_suite: Option<CheckSuiteDto>,
}

#[derive(Debug, Clone, Deserialize)]
struct CheckSuiteDto {
    #[serde(default)]
    id: Option<i64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pull_dto_maps_missing_fields_to_defaults() {
        let dto: PullDto = serde_json::from_value(serde_json::json!({
            "number": 7,
            "title": "Fix",
            "state": "open",
            "requested_reviewers": [{"login": "alice"}],
            "requested_teams": [{"slug": "platform"}],
            "head": {"ref": "feature", "sha": "abc"},
            "base": {"ref": "main"}
        }))
        .unwrap();
        let row = dto.to_row("o/r", 7, None, "2026-11-16T00:00:00.000Z");
        assert_eq!(row.pull_number, 7);
        assert_eq!(
            row.requested_reviewers,
            vec!["user:alice".to_string(), "team:platform".to_string()]
        );
        assert_eq!(row.head_branch.as_deref(), Some("feature"));
        assert_eq!(row.url, "https://github.com/o/r/pull/7");
    }

    #[test]
    fn list_pull_merged_at_marks_merged_without_merged_field() {
        let dto: PullDto = serde_json::from_value(serde_json::json!({
            "number": 8,
            "title": "Merged",
            "state": "closed",
            "merged_at": "2026-11-16T01:00:00Z",
            "updated_at": "2026-11-16T01:00:00Z"
        }))
        .unwrap();
        let row = dto.to_row("o/r", 8, None, "2026-11-16T02:00:00.000Z");
        assert!(row.merged);
        assert_eq!(row.merged_at.as_deref(), Some("2026-11-16T01:00:00.000Z"));
    }

    #[test]
    fn workflow_run_attempt_defaults_to_one() {
        let dto: WorkflowRunDto = serde_json::from_value(serde_json::json!({
            "id": 42,
            "status": "completed",
            "conclusion": "failure"
        }))
        .unwrap();
        assert_eq!(dto.run_attempt, 1);
    }

    #[test]
    fn link_next_is_parsed_and_other_relations_ignored() {
        let value = "<https://api.github.com/repos/o/r/pulls?page=2>; rel=\"next\", \
                     <https://api.github.com/repos/o/r/pulls?page=9>; rel=\"last\"";
        assert_eq!(
            parse_link_next(value).as_deref(),
            Some("https://api.github.com/repos/o/r/pulls?page=2")
        );
        assert_eq!(
            parse_link_next("<https://api.github.com/x>; rel=\"prev\""),
            None
        );
    }

    #[test]
    fn retry_after_seconds_and_rate_limit_reset_are_parsed() {
        let mut headers = HeaderMap::new();
        headers.insert("retry-after", HeaderValue::from_static("42"));
        assert_eq!(
            rate_limit_retry_after(&headers),
            Some(Duration::from_secs(42))
        );

        let mut headers = HeaderMap::new();
        headers.insert("x-ratelimit-remaining", HeaderValue::from_static("0"));
        let reset = (Utc::now().timestamp() + 30).to_string();
        headers.insert("x-ratelimit-reset", HeaderValue::from_str(&reset).unwrap());
        let retry = rate_limit_retry_after(&headers).expect("reset parsed");
        assert!(retry >= Duration::from_secs(1));
        assert!(retry <= Duration::from_secs(31));
    }

    #[test]
    fn api_url_validation_rejects_foreign_origins_and_prefixes() {
        let settings = GitHubPollerSettings {
            repositories: vec!["o/r".into()],
            api_base_url: Url::parse("https://ghe.example.com/api/v3").unwrap(),
            token: None,
            poll_interval: Duration::from_secs(1),
        };
        let poller = GitHubPoller::new(
            settings,
            std::sync::Arc::new(Repository::open_in_memory().unwrap()),
            EventBus::new(),
        )
        .unwrap();
        assert!(
            poller
                .validate_api_url("https://ghe.example.com/api/v3/repos/o/r/pulls")
                .is_ok()
        );
        assert!(
            poller
                .validate_api_url("https://evil.example.com/api/v3/repos/o/r/pulls")
                .is_err()
        );
        assert!(
            poller
                .validate_api_url("https://ghe.example.com/other/repos/o/r/pulls")
                .is_err()
        );
        assert!(
            poller
                .validate_api_url("https://ghe.example.com/api/v3@evil.example.com/x")
                .is_err()
        );
    }
}
