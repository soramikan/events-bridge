//! GitHub webhook and reconciliation normalization.
//!
//! The rules are deliberately small and explicit:
//!
//! * A failing `workflow_run` and its `check_run` sibling are one CI failure.
//!   The canonical key is `(repository, workflow run id, run attempt)`. A
//!   GitHub Actions `check_run` names a job, not a workflow, and its URL does
//!   not always carry the attempt, so it is parked in `github_pending_checks`
//!   until the canonical `workflow_run` arrives. External (non-Actions) check
//!   runs use `check_run:<id>` directly.
//! * A failure is emitted at most once per canonical attempt. The
//!   `github_ci_runs.failure_emitted` flag and a deterministic event id are two
//!   independent defenses, and a new run attempt intentionally emits again.
//! * Pull request merge events are emitted once (`merged_emitted`), while
//!   review requests are emitted for reviewers that were not already pending.
//! * `updated_at` is the PR entity timestamp. Review and comment activity is
//!   tracked separately in `last_activity_at`, so a review can never rewind a
//!   newer PR edit.
//!
//! Payloads are constructed only from the fields declared by
//! `mcp::event_catalog`; `additionalProperties: false` is enforced by
//! `validate_payload` at ingestion time.

use anyhow::Result;
use rusqlite::Connection;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::store::github::{
    ci_failure_emitted_for_suite, delete_fallback_ci_runs, github_timestamp, json_bool, json_i64,
    json_text, load_ci_run, load_pull_request,
};
use crate::store::{
    GitHubCiRun, GitHubPendingCheck, GitHubPendingCheckResolution, GitHubPendingCheckUpdate,
    GitHubPullRequest, GitHubWebhookChanges, NewEvent,
};
use crate::util::timestamp_lt;

/// Conclusions that count as a failed CI run.
pub const FAILURE_CONCLUSIONS: &[&str] =
    &["failure", "timed_out", "action_required", "startup_failure"];

/// Maximum JSON-encoded summary size (well below the 256 KiB protocol ceiling).
const MAX_SUMMARY_JSON_BYTES: usize = 1024;

/// Maximum display string size in bytes.
const MAX_DISPLAY_BYTES: usize = 512;

/// Maximum URL size in bytes.
const MAX_URL_BYTES: usize = 2048;

/// Maximum identifier size in bytes. Identifiers are rejected, never truncated.
const MAX_IDENTIFIER_BYTES: usize = 256;

/// Maximum serialized event payload size. The delivery ceiling is 256 KiB.
const MAX_EVENT_PAYLOAD_BYTES: usize = 16 * 1024;

/// Whether a conclusion is a CI failure.
pub fn is_failure_conclusion(conclusion: Option<&str>) -> bool {
    conclusion.is_some_and(|conclusion| FAILURE_CONCLUSIONS.contains(&conclusion))
}

/// Normalize one webhook delivery.
///
/// `received_at` is used only when the payload has no usable timestamp.
pub fn normalize_webhook(
    conn: &Connection,
    event_type: &str,
    payload: &Value,
    delivery_id: &str,
    received_at: &str,
) -> Result<GitHubWebhookChanges> {
    let Some(repository) = repository_full_name(payload) else {
        return Ok(GitHubWebhookChanges::default());
    };
    match event_type {
        "ping" => Ok(GitHubWebhookChanges::default()),
        "workflow_run" => normalize_workflow_run(conn, payload, &repository, received_at),
        "check_run" => normalize_check_run(conn, payload, &repository, received_at),
        "pull_request" => {
            normalize_pull_request(conn, payload, &repository, delivery_id, received_at)
        }
        "pull_request_review" => {
            normalize_pull_request_review(conn, payload, &repository, received_at)
        }
        "pull_request_review_comment" => {
            normalize_pull_request_review_comment(conn, payload, &repository, received_at)
        }
        _ => Ok(GitHubWebhookChanges::default()),
    }
}

fn normalize_workflow_run(
    conn: &Connection,
    payload: &Value,
    repository: &str,
    received_at: &str,
) -> Result<GitHubWebhookChanges> {
    let Some(run) = payload.get("workflow_run") else {
        return Ok(GitHubWebhookChanges::default());
    };
    let Some(run_id) = json_i64(run, "id").filter(|run_id| *run_id > 0) else {
        return Ok(GitHubWebhookChanges::default());
    };
    let action = json_text(payload, "action").unwrap_or_default();
    let attempt = json_i64(run, "run_attempt").unwrap_or(1).max(1);
    let check_suite_id = json_i64(run, "check_suite_id").filter(|id| *id > 0);
    let conclusion = json_text(run, "conclusion");
    let status = json_text(run, "status").unwrap_or_else(|| "completed".into());
    let canonical_run_id = run_id.to_string();
    let previous = load_ci_run(conn, repository, &canonical_run_id, attempt)?;
    let workflow_name = json_text(run, "name")
        .map(|name| bounded_display(&name))
        .filter(|name| !name.is_empty())
        .or_else(|| previous.as_ref().map(|run| run.workflow_name.clone()))
        .unwrap_or_else(|| "workflow".to_string());
    let head_branch = json_text(run, "head_branch")
        .map(|branch| bounded_display(&branch))
        .filter(|branch| !branch.is_empty());
    let head_sha = json_text(run, "head_sha").and_then(|sha| valid_identifier(&sha, 128));
    let url = bounded_url(&run_url(repository, run, run_id));
    let updated_at = github_timestamp(json_text(run, "updated_at").as_deref(), received_at);
    let stale = previous
        .as_ref()
        .is_some_and(|previous| timestamp_lt(&updated_at, &previous.updated_at));

    let mut failure_emitted = previous.as_ref().is_some_and(|run| run.failure_emitted);
    let mut events = Vec::new();
    let mut pending_checks = GitHubPendingCheckUpdate {
        repository: Some(repository.to_string()),
        ..GitHubPendingCheckUpdate::default()
    };

    let completed_failure = (action == "completed" || status == "completed")
        && is_failure_conclusion(conclusion.as_deref());
    if completed_failure && !stale {
        let suite_already = match check_suite_id {
            Some(check_suite_id) => {
                ci_failure_emitted_for_suite(conn, repository, check_suite_id, attempt)?
            }
            None => false,
        };
        if !failure_emitted && !suite_already {
            events.push(workflow_failed_event(
                repository,
                &workflow_name,
                &canonical_run_id,
                attempt,
                conclusion.as_deref().unwrap_or("failure"),
                head_branch.as_deref(),
                &url,
                &updated_at,
            ));
        }
        // Whether it came from the canonical row or a check_run fallback, this
        // attempt has now been notified. A later check_run must not repeat it.
        failure_emitted = true;
        if let Some(check_suite_id) = check_suite_id {
            delete_fallback_ci_runs(conn, repository, check_suite_id, attempt)?;
        }
    }

    if !stale {
        // A canonical workflow run resolves parked Actions checks for this
        // attempt only. Attempt-aware deletion prevents a rerun from clearing
        // an earlier attempt's pending failure.
        pending_checks
            .resolve_workflow_runs
            .push(GitHubPendingCheckResolution {
                actions_run_id: Some(run_id),
                check_suite_id,
                run_attempt: attempt,
            });
    }

    Ok(GitHubWebhookChanges {
        pull_request: None,
        ci_run: Some(GitHubCiRun {
            repository: repository.to_string(),
            canonical_run_id,
            run_attempt: attempt,
            check_suite_id,
            workflow_name,
            head_branch,
            head_sha,
            status,
            conclusion,
            url,
            failure_emitted,
            updated_at,
        }),
        pending_checks,
        events,
    })
}

fn normalize_check_run(
    conn: &Connection,
    payload: &Value,
    repository: &str,
    received_at: &str,
) -> Result<GitHubWebhookChanges> {
    let Some(run) = payload.get("check_run") else {
        return Ok(GitHubWebhookChanges::default());
    };
    let Some(check_run_id) = json_i64(run, "id").filter(|id| *id > 0) else {
        return Ok(GitHubWebhookChanges::default());
    };
    let status = json_text(run, "status").unwrap_or_else(|| "completed".into());
    let conclusion = json_text(run, "conclusion");
    let check_suite = run.get("check_suite");
    let check_suite_id = json_i64(run, "check_suite_id")
        .or_else(|| check_suite.and_then(|suite| json_i64(suite, "id")))
        .filter(|id| *id > 0);
    let details_url = json_text(run, "details_url");
    let html_url = json_text(run, "html_url");
    let parsed = parse_actions_run_ref(details_url.as_deref().or(html_url.as_deref()));
    let app_slug = run.get("app").and_then(|app| json_text(app, "slug"));
    let is_actions = app_slug.as_deref() == Some("github-actions") || parsed.is_some();
    let check_name = json_text(run, "name")
        .map(|name| bounded_display(&name))
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "check_run".to_string());
    let head_branch = check_suite
        .and_then(|suite| json_text(suite, "head_branch"))
        .or_else(|| json_text(run, "head_branch"))
        .map(|branch| bounded_display(&branch))
        .filter(|branch| !branch.is_empty());
    let head_sha = json_text(run, "head_sha")
        .or_else(|| check_suite.and_then(|suite| json_text(suite, "head_sha")))
        .and_then(|sha| valid_identifier(&sha, 128));
    let url = bounded_url(&run_url(repository, run, check_run_id));
    let updated_at = github_timestamp(
        json_text(run, "completed_at")
            .or_else(|| json_text(run, "updated_at"))
            .or_else(|| json_text(run, "started_at"))
            .as_deref(),
        received_at,
    );
    let completed_failure = status == "completed" && is_failure_conclusion(conclusion.as_deref());

    if is_actions {
        let (actions_run_id, parsed_attempt) = match parsed {
            Some((run_id, attempt)) => (
                run_id.parse::<i64>().ok().filter(|run_id| *run_id > 0),
                attempt,
            ),
            None => (None, None),
        };

        // Only an explicit `/attempts/<n>` URL can be correlated without
        // guessing. The canonical row must already carry a real workflow name
        // from a `workflow_run` webhook or REST poll.
        if let (Some(actions_run_id), Some(attempt)) = (actions_run_id, parsed_attempt)
            && load_ci_run(conn, repository, &actions_run_id.to_string(), attempt)?.is_some()
        {
            // An Actions `check_run` names one job. It must never overwrite the
            // aggregate workflow row's status, conclusion, URL or timestamp;
            // only the canonical `workflow_run` may do that. The check is
            // correlated and removed from the pending table.
            let mut pending_checks = GitHubPendingCheckUpdate {
                repository: Some(repository.to_string()),
                ..GitHubPendingCheckUpdate::default()
            };
            pending_checks.resolve_check_run_ids.push(check_run_id);
            return Ok(GitHubWebhookChanges {
                pull_request: None,
                ci_run: None,
                pending_checks,
                events: Vec::new(),
            });
        }

        // No canonical workflow run yet, or the attempt is unknown. Park the
        // check for every status and conclusion; emit nothing now.
        let mut pending_checks = GitHubPendingCheckUpdate {
            repository: Some(repository.to_string()),
            ..GitHubPendingCheckUpdate::default()
        };
        pending_checks.upserts.push(GitHubPendingCheck {
            repository: repository.to_string(),
            check_run_id,
            actions_run_id,
            parsed_attempt,
            check_suite_id,
            check_name,
            head_branch,
            head_sha,
            status,
            conclusion,
            url,
            updated_at,
        });
        return Ok(GitHubWebhookChanges {
            pull_request: None,
            ci_run: None,
            pending_checks,
            events: Vec::new(),
        });
    }

    // External, non-Actions check run. GitHub assigns a new check run id on a
    // rerun, so `check_run:<id>` with attempt 1 is the canonical key.
    let canonical_run_id = format!("check_run:{check_run_id}");
    let attempt = 1;
    let previous = load_ci_run(conn, repository, &canonical_run_id, attempt)?;
    let stale = previous
        .as_ref()
        .is_some_and(|previous| timestamp_lt(&updated_at, &previous.updated_at));
    let workflow_name = previous
        .as_ref()
        .map(|run| run.workflow_name.clone())
        .unwrap_or_else(|| check_name.clone());
    let mut failure_emitted = previous.as_ref().is_some_and(|run| run.failure_emitted);
    let mut events = Vec::new();
    if completed_failure && !stale && !failure_emitted {
        failure_emitted = true;
        events.push(workflow_failed_event(
            repository,
            &workflow_name,
            &canonical_run_id,
            attempt,
            conclusion.as_deref().unwrap_or("failure"),
            head_branch.as_deref(),
            &url,
            &updated_at,
        ));
    }
    let mut pending_checks = GitHubPendingCheckUpdate {
        repository: Some(repository.to_string()),
        ..GitHubPendingCheckUpdate::default()
    };
    pending_checks.resolve_check_run_ids.push(check_run_id);

    Ok(GitHubWebhookChanges {
        pull_request: None,
        ci_run: Some(GitHubCiRun {
            repository: repository.to_string(),
            canonical_run_id,
            run_attempt: attempt,
            check_suite_id,
            workflow_name,
            head_branch,
            head_sha,
            status: if stale {
                previous
                    .as_ref()
                    .map(|run| run.status.clone())
                    .unwrap_or(status)
            } else {
                status
            },
            conclusion: if stale {
                previous.as_ref().and_then(|run| run.conclusion.clone())
            } else {
                conclusion
            },
            url: if stale {
                previous.as_ref().map(|run| run.url.clone()).unwrap_or(url)
            } else {
                url
            },
            failure_emitted,
            updated_at: if stale {
                previous
                    .as_ref()
                    .map(|run| run.updated_at.clone())
                    .unwrap_or(updated_at)
            } else {
                updated_at
            },
        }),
        pending_checks,
        events,
    })
}

fn normalize_pull_request(
    conn: &Connection,
    payload: &Value,
    repository: &str,
    delivery_id: &str,
    received_at: &str,
) -> Result<GitHubWebhookChanges> {
    let Some(pull) = payload.get("pull_request") else {
        return Ok(GitHubWebhookChanges::default());
    };
    let Some(pull_number) = pull_number_from_payload(payload, pull, true) else {
        return Ok(GitHubWebhookChanges::default());
    };
    let previous = load_pull_request(conn, repository, pull_number)?;
    let mut row = pull_request_row(
        repository,
        pull_number,
        pull,
        previous.as_ref(),
        received_at,
    );
    let action = json_text(payload, "action").unwrap_or_default();
    let stale = previous
        .as_ref()
        .is_some_and(|previous| timestamp_lt(&row.updated_at, &previous.updated_at));
    let mut events = Vec::new();

    match action.as_str() {
        "opened" if !stale => {
            // GitHub includes pending reviewers on `opened` and then emits a
            // `review_requested` action for each of them. Notify here so the
            // later action can stay idempotent against the stored list.
            let previous_reviewers: &[String] = previous
                .as_ref()
                .map(|pull| pull.requested_reviewers.as_slice())
                .unwrap_or(&[]);
            for reviewer in &row.requested_reviewers {
                if !previous_reviewers.iter().any(|r| r == reviewer) {
                    let marker = format!("opened|{}|{}", row.updated_at, reviewer);
                    events.push(review_requested_event(
                        &row,
                        Some(reviewer_name(reviewer)),
                        &marker,
                    ));
                }
            }
        }
        "closed" => {
            if row.merged && !previous.as_ref().is_some_and(|pull| pull.merged_emitted) {
                row.merged_emitted = true;
                events.push(pr_merged_event(&row));
            } else {
                row.merged_emitted = previous.as_ref().is_some_and(|pull| pull.merged_emitted);
            }
        }
        "review_requested" if !stale => {
            let reviewer = payload
                .get("requested_reviewer")
                .and_then(login)
                .map(|login| reviewer_key("user", &login))
                .or_else(|| {
                    payload
                        .get("requested_team")
                        .and_then(|team| json_text(team, "slug"))
                        .map(|slug| reviewer_key("team", &slug))
                });
            let already_requested = reviewer.as_ref().is_some_and(|reviewer| {
                previous
                    .as_ref()
                    .is_some_and(|pull| pull.requested_reviewers.iter().any(|r| r == reviewer))
            });
            if let Some(reviewer) = &reviewer
                && !row.requested_reviewers.iter().any(|r| r == reviewer)
            {
                row.requested_reviewers.push(reviewer.clone());
            }
            if !already_requested {
                let marker = format!("{}|{}", row.updated_at, delivery_id);
                events.push(review_requested_event(
                    &row,
                    reviewer.as_deref().map(reviewer_name),
                    &marker,
                ));
            }
        }
        "review_request_removed" if !stale => {
            let reviewer = payload
                .get("requested_reviewer")
                .and_then(login)
                .map(|login| reviewer_key("user", &login))
                .or_else(|| {
                    payload
                        .get("requested_team")
                        .and_then(|team| json_text(team, "slug"))
                        .map(|slug| reviewer_key("team", &slug))
                });
            if let Some(reviewer) = reviewer {
                row.requested_reviewers.retain(|r| r != &reviewer);
            }
        }
        _ => {}
    }

    Ok(GitHubWebhookChanges {
        pull_request: Some(row),
        ci_run: None,
        pending_checks: GitHubPendingCheckUpdate::default(),
        events,
    })
}

fn normalize_pull_request_review(
    conn: &Connection,
    payload: &Value,
    repository: &str,
    received_at: &str,
) -> Result<GitHubWebhookChanges> {
    let Some(pull) = payload.get("pull_request") else {
        return Ok(GitHubWebhookChanges::default());
    };
    let Some(pull_number) = pull_number_from_payload(payload, pull, false) else {
        return Ok(GitHubWebhookChanges::default());
    };
    let previous = load_pull_request(conn, repository, pull_number)?;
    let mut row = pull_request_row(
        repository,
        pull_number,
        pull,
        previous.as_ref(),
        received_at,
    );
    if let Some(review) = payload.get("review") {
        let activity = json_text(review, "submitted_at")
            .map(|submitted_at| github_timestamp(Some(&submitted_at), received_at))
            .unwrap_or_else(|| row.updated_at.clone());
        let newer = previous
            .as_ref()
            .and_then(|pull| pull.last_activity_at.as_deref())
            .is_none_or(|previous| !timestamp_lt(&activity, previous));
        if newer {
            row.last_activity_at = Some(activity);
            row.last_review_state = json_text(review, "state")
                .map(|state| bounded_display(&state))
                .filter(|state| !state.is_empty());
        } else {
            row.last_activity_at = previous
                .as_ref()
                .and_then(|pull| pull.last_activity_at.clone());
            row.last_review_state = previous
                .as_ref()
                .and_then(|pull| pull.last_review_state.clone());
        }
    }
    Ok(GitHubWebhookChanges {
        pull_request: Some(row),
        ci_run: None,
        pending_checks: GitHubPendingCheckUpdate::default(),
        events: Vec::new(),
    })
}

fn normalize_pull_request_review_comment(
    conn: &Connection,
    payload: &Value,
    repository: &str,
    received_at: &str,
) -> Result<GitHubWebhookChanges> {
    let Some(pull) = payload.get("pull_request") else {
        return Ok(GitHubWebhookChanges::default());
    };
    let Some(pull_number) = pull_number_from_payload(payload, pull, false) else {
        return Ok(GitHubWebhookChanges::default());
    };
    let previous = load_pull_request(conn, repository, pull_number)?;
    let mut row = pull_request_row(
        repository,
        pull_number,
        pull,
        previous.as_ref(),
        received_at,
    );
    if let Some(comment) = payload.get("comment")
        && let Some(activity) = json_text(comment, "updated_at")
            .or_else(|| json_text(comment, "created_at"))
            .map(|value| github_timestamp(Some(&value), received_at))
    {
        let newer = previous
            .as_ref()
            .and_then(|pull| pull.last_activity_at.as_deref())
            .is_none_or(|previous| !timestamp_lt(&activity, previous));
        if newer {
            row.last_activity_at = Some(activity);
        } else {
            row.last_activity_at = previous
                .as_ref()
                .and_then(|pull| pull.last_activity_at.clone());
        }
    }
    Ok(GitHubWebhookChanges {
        pull_request: Some(row),
        ci_run: None,
        pending_checks: GitHubPendingCheckUpdate::default(),
        events: Vec::new(),
    })
}

fn pull_request_row(
    repository: &str,
    pull_number: i64,
    pull: &Value,
    previous: Option<&GitHubPullRequest>,
    received_at: &str,
) -> GitHubPullRequest {
    let title = json_text(pull, "title")
        .map(|title| bounded_display(&title))
        .filter(|title| !title.is_empty())
        .or_else(|| previous.map(|pull| pull.title.clone()))
        .unwrap_or_default();
    let author = pull
        .get("user")
        .and_then(login)
        .map(|login| bounded_display(&login))
        .filter(|login| !login.is_empty())
        .or_else(|| previous.and_then(|pull| pull.author.clone()));
    let head = pull.get("head");
    let base = pull.get("base");
    let head_branch = head
        .and_then(|head| json_text(head, "ref"))
        .map(|branch| bounded_display(&branch))
        .filter(|branch| !branch.is_empty())
        .or_else(|| previous.and_then(|pull| pull.head_branch.clone()));
    let head_sha = head
        .and_then(|head| json_text(head, "sha"))
        .and_then(|sha| valid_identifier(&sha, 128))
        .or_else(|| previous.and_then(|pull| pull.head_sha.clone()));
    let base_branch = base
        .and_then(|base| json_text(base, "ref"))
        .map(|branch| bounded_display(&branch))
        .filter(|branch| !branch.is_empty())
        .or_else(|| previous.and_then(|pull| pull.base_branch.clone()));
    let requested_reviewers = requested_reviewers_from_pull(pull, previous);
    let merged_at = json_text(pull, "merged_at");
    let merged = json_bool(pull, "merged").unwrap_or(false)
        || merged_at.is_some()
        || previous.is_some_and(|pull| pull.merged);
    let state = json_text(pull, "state")
        .map(|state| bounded_display(&state))
        .filter(|state| !state.is_empty())
        .or_else(|| previous.map(|pull| pull.state.clone()))
        .unwrap_or_else(|| "open".to_string());
    let url = json_text(pull, "html_url")
        .map(|url| bounded_url(&url))
        .filter(|url| !url.is_empty())
        .or_else(|| previous.map(|pull| pull.url.clone()))
        .unwrap_or_else(|| {
            bounded_url(&format!(
                "https://github.com/{repository}/pull/{pull_number}"
            ))
        });
    let updated_at = github_timestamp(json_text(pull, "updated_at").as_deref(), received_at);

    GitHubPullRequest {
        repository: repository.to_string(),
        pull_number,
        title,
        state,
        author,
        head_branch,
        head_sha,
        base_branch,
        draft: json_bool(pull, "draft").unwrap_or(false),
        merged,
        merged_by: pull
            .get("merged_by")
            .and_then(login)
            .map(|login| bounded_display(&login))
            .filter(|login| !login.is_empty())
            .or_else(|| previous.and_then(|pull| pull.merged_by.clone())),
        merged_at: merged_at
            .map(|value| github_timestamp(Some(&value), received_at))
            .or_else(|| previous.and_then(|pull| pull.merged_at.clone())),
        requested_reviewers,
        last_review_state: previous.and_then(|pull| pull.last_review_state.clone()),
        last_activity_at: previous.and_then(|pull| pull.last_activity_at.clone()),
        url,
        merged_emitted: previous.is_some_and(|pull| pull.merged_emitted),
        updated_at,
    }
}

fn requested_reviewers_from_pull(
    pull: &Value,
    previous: Option<&GitHubPullRequest>,
) -> Vec<String> {
    let users = pull.get("requested_reviewers").and_then(Value::as_array);
    let teams = pull.get("requested_teams").and_then(Value::as_array);
    if users.is_none() && teams.is_none() {
        return previous
            .map(|pull| pull.requested_reviewers.clone())
            .unwrap_or_default();
    }

    let mut keys = Vec::new();
    if let Some(users) = users {
        for user in users {
            if let Some(login) = login(user)
                .map(|login| bounded_display(&login))
                .filter(|login| !login.is_empty())
            {
                keys.push(reviewer_key("user", &login));
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
            if let Some(slug) = json_text(team, "slug")
                .map(|slug| bounded_display(&slug))
                .filter(|slug| !slug.is_empty())
            {
                keys.push(reviewer_key("team", &slug));
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

fn pull_number_from_payload(payload: &Value, pull: &Value, require_outer: bool) -> Option<i64> {
    let inner = json_i64(pull, "number").filter(|number| *number > 0)?;
    match payload.get("number") {
        Some(_) => {
            let outer = json_i64(payload, "number")?;
            (outer > 0 && outer == inner).then_some(inner)
        }
        None if !require_outer => Some(inner),
        None => None,
    }
}

/// Build a `github.workflow.failed` event with a deterministic id.
#[allow(clippy::too_many_arguments)]
pub fn workflow_failed_event(
    repository: &str,
    workflow: &str,
    run_id: &str,
    run_attempt: i64,
    conclusion: &str,
    branch: Option<&str>,
    url: &str,
    occurred_at: &str,
) -> NewEvent {
    let workflow = bounded_display(workflow);
    let workflow = if workflow.is_empty() {
        "workflow".to_string()
    } else {
        workflow
    };
    let run_id =
        valid_identifier(run_id, MAX_IDENTIFIER_BYTES).unwrap_or_else(|| "unknown".to_string());
    let conclusion = bounded_display(conclusion);
    let branch = branch
        .map(bounded_display)
        .filter(|branch| !branch.is_empty());
    let url = bounded_url(url);

    let mut payload = Map::new();
    payload.insert("repository".into(), json!(repository));
    payload.insert("workflow".into(), json!(workflow));
    payload.insert("run_id".into(), json!(run_id));
    payload.insert("conclusion".into(), json!(conclusion));
    if let Some(branch) = &branch {
        payload.insert("branch".into(), json!(branch));
    }
    let mut summary = format!("CI workflow \"{workflow}\" {conclusion}");
    if let Some(branch) = &branch {
        summary.push_str(&format!(" on {branch}"));
    }
    summary.push_str(&format!(" (attempt {run_attempt})"));
    payload.insert("summary".into(), json!(bound_summary(&summary)));
    payload.insert("url".into(), json!(url));

    bounded_event(NewEvent {
        id: Some(event_id(
            "ci",
            &[repository, &run_id, &run_attempt.to_string()],
        )),
        source: Some("github".into()),
        kind: "github.workflow.failed".into(),
        payload: Value::Object(payload),
        occurred_at: Some(occurred_at.to_string()),
    })
}

/// Build a `github.pr.merged` event with a deterministic id.
pub fn pr_merged_event(pull: &GitHubPullRequest) -> NewEvent {
    let title = bounded_display(&pull.title);
    let author = pull.author.as_deref().map(bounded_display);
    let merged_by = pull.merged_by.as_deref().map(bounded_display);
    let base_branch = pull.base_branch.as_deref().map(bounded_display);
    let url = bounded_url(&pull.url);

    let mut payload = Map::new();
    payload.insert("repository".into(), json!(pull.repository));
    payload.insert("pull_number".into(), json!(pull.pull_number));
    payload.insert("title".into(), json!(title));
    if let Some(author) = &author {
        payload.insert("author".into(), json!(author));
    }
    if let Some(merged_by) = &merged_by {
        payload.insert("merged_by".into(), json!(merged_by));
    }
    if let Some(base_branch) = &base_branch {
        payload.insert("base_branch".into(), json!(base_branch));
    }
    let mut summary = format!("#{} \"{}\" merged", pull.pull_number, truncate(&title, 120));
    if let Some(merged_by) = &merged_by {
        summary.push_str(&format!(" by {merged_by}"));
    }
    if let Some(base_branch) = &base_branch {
        summary.push_str(&format!(" into {base_branch}"));
    }
    payload.insert("summary".into(), json!(bound_summary(&summary)));
    payload.insert("url".into(), json!(url));

    bounded_event(NewEvent {
        id: Some(event_id(
            "pr",
            &[&pull.repository, &pull.pull_number.to_string()],
        )),
        source: Some("github".into()),
        kind: "github.pr.merged".into(),
        payload: Value::Object(payload),
        occurred_at: Some(
            pull.merged_at
                .clone()
                .unwrap_or_else(|| pull.updated_at.clone()),
        ),
    })
}

/// Build a `github.review.requested` event.
pub fn review_requested_event(
    pull: &GitHubPullRequest,
    reviewer: Option<&str>,
    marker: &str,
) -> NewEvent {
    let title = bounded_display(&pull.title);
    let author = pull.author.as_deref().map(bounded_display);
    let reviewer = reviewer.map(bounded_display);
    let url = bounded_url(&pull.url);

    let mut payload = Map::new();
    payload.insert("repository".into(), json!(pull.repository));
    payload.insert("pull_number".into(), json!(pull.pull_number));
    payload.insert("title".into(), json!(title));
    if let Some(author) = &author {
        payload.insert("author".into(), json!(author));
    }
    if let Some(reviewer) = &reviewer {
        payload.insert("reviewer".into(), json!(reviewer));
    }
    let mut summary = format!(
        "Review requested on #{} \"{}\"",
        pull.pull_number,
        truncate(&title, 120)
    );
    if let Some(reviewer) = &reviewer {
        summary.push_str(&format!(" from {reviewer}"));
    }
    payload.insert("summary".into(), json!(bound_summary(&summary)));
    payload.insert("url".into(), json!(url));

    bounded_event(NewEvent {
        id: Some(event_id(
            "review",
            &[
                &pull.repository,
                &pull.pull_number.to_string(),
                reviewer.as_deref().unwrap_or_default(),
                marker,
            ],
        )),
        source: Some("github".into()),
        kind: "github.review.requested".into(),
        payload: Value::Object(payload),
        occurred_at: Some(pull.updated_at.clone()),
    })
}

/// Normalized reviewer key for a user login.
pub fn reviewer_key(kind: &str, name: &str) -> String {
    format!("{kind}:{name}")
}

/// Display name of a normalized reviewer key.
pub fn reviewer_name(key: &str) -> &str {
    key.split_once(':').map(|(_, name)| name).unwrap_or(key)
}

/// Bound a summary to a small JSON-encoded size (1 KiB).
pub fn bound_summary(value: &str) -> String {
    bound_json_text(value, MAX_SUMMARY_JSON_BYTES)
}

/// Bound a display string to 512 bytes on a UTF-8 boundary.
pub(crate) fn bounded_display(value: &str) -> String {
    truncate_bytes(value.trim(), MAX_DISPLAY_BYTES)
}

/// Bound a URL to 2048 bytes on a UTF-8 boundary.
pub(crate) fn bounded_url(value: &str) -> String {
    truncate_bytes(value.trim(), MAX_URL_BYTES)
}

/// Validate an identifier without truncating it.
pub(crate) fn valid_identifier(value: &str, max_bytes: usize) -> Option<String> {
    let value = value.trim();
    if value.is_empty() || value.len() > max_bytes {
        None
    } else {
        Some(value.to_string())
    }
}

fn truncate_bytes(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}

fn dedup_keys(keys: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    keys.into_iter()
        .filter(|key| seen.insert(key.clone()))
        .collect()
}

fn bounded_event(event: NewEvent) -> NewEvent {
    let too_large = serde_json::to_vec(&event.payload)
        .map(|payload| payload.len() > MAX_EVENT_PAYLOAD_BYTES)
        .unwrap_or(true);
    if !too_large {
        return event;
    }
    let mut event = event;
    if let Some(object) = event.payload.as_object_mut() {
        object.insert("summary".into(), json!(bound_summary("")));
        if let Some(url) = object.get("url").and_then(Value::as_str) {
            object.insert("url".into(), json!(bounded_url(url)));
        }
    }
    event
}

fn bound_json_text(value: &str, max_json_bytes: usize) -> String {
    if serde_json::to_string(value)
        .map(|serialized| serialized.len() <= max_json_bytes)
        .unwrap_or(false)
    {
        return value.to_string();
    }

    let suffix = "...";
    let mut boundaries: Vec<usize> = value.char_indices().map(|(idx, _)| idx).collect();
    boundaries.push(value.len());

    let mut low = 0usize;
    let mut high = boundaries.len() - 1;
    let mut best = String::new();
    while low <= high {
        let mid = low + (high - low) / 2;
        let candidate = format!("{}{suffix}", &value[..boundaries[mid]]);
        let fits = serde_json::to_string(&candidate)
            .map(|serialized| serialized.len() <= max_json_bytes)
            .unwrap_or(false);
        if fits {
            best = candidate;
            low = mid + 1;
        } else if mid == 0 {
            break;
        } else {
            high = mid - 1;
        }
    }
    if best.is_empty() {
        truncate(suffix, max_json_bytes.saturating_sub(2))
    } else {
        best
    }
}

fn truncate(value: &str, limit: usize) -> String {
    if value.chars().count() <= limit {
        value.to_string()
    } else {
        value.chars().take(limit).collect()
    }
}

/// Deterministic, bounded event id.
fn event_id(prefix: &str, parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prefix.as_bytes());
    for part in parts {
        hasher.update([0u8]);
        hasher.update(part.as_bytes());
    }
    let digest = hex::encode(hasher.finalize());
    format!("evt_github_{prefix}_{}", &digest[..32])
}

/// Extract `owner/repo` from a webhook payload's `repository` object.
pub fn repository_full_name(payload: &Value) -> Option<String> {
    let repository = payload.get("repository")?;
    let full_name = json_text(repository, "full_name").or_else(|| {
        let name = json_text(repository, "name")?;
        let owner = repository.get("owner").and_then(login)?;
        Some(format!("{owner}/{name}"))
    })?;
    valid_identifier(&full_name, MAX_IDENTIFIER_BYTES)
}

fn login(value: &Value) -> Option<String> {
    json_text(value, "login")
}

fn run_url(repository: &str, run: &Value, run_id: i64) -> String {
    json_text(run, "html_url")
        .or_else(|| json_text(run, "details_url"))
        .unwrap_or_else(|| format!("https://github.com/{repository}/actions/runs/{run_id}"))
}

/// Parse `/actions/runs/<id>` and an optional `/attempts/<n>` from a URL.
pub(crate) fn parse_actions_run_ref(url: Option<&str>) -> Option<(String, Option<i64>)> {
    let url = url?;
    let marker = "/actions/runs/";
    let start = url.find(marker)? + marker.len();
    let rest = &url[start..];
    let run_id: String = rest.chars().take_while(char::is_ascii_digit).collect();
    if run_id.is_empty() {
        return None;
    }
    let after_id = &rest[run_id.len()..];
    let attempt = after_id
        .find("/attempts/")
        .and_then(|index| {
            let tail = &after_id[index + "/attempts/".len()..];
            let digits: String = tail.chars().take_while(char::is_ascii_digit).collect();
            digits.parse::<i64>().ok()
        })
        .filter(|attempt| *attempt > 0);
    Some((run_id, attempt))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failure_conclusions_are_recognized() {
        for conclusion in FAILURE_CONCLUSIONS {
            assert!(is_failure_conclusion(Some(conclusion)));
        }
        assert!(!is_failure_conclusion(Some("success")));
        assert!(!is_failure_conclusion(Some("cancelled")));
        assert!(!is_failure_conclusion(None));
    }

    #[test]
    fn action_run_references_parse_run_and_attempt() {
        assert_eq!(
            parse_actions_run_ref(Some("https://github.com/o/r/actions/runs/123/job/9")),
            Some(("123".into(), None))
        );
        assert_eq!(
            parse_actions_run_ref(Some(
                "https://api.github.com/repos/o/r/actions/runs/123/attempts/2"
            )),
            Some(("123".into(), Some(2)))
        );
        assert_eq!(
            parse_actions_run_ref(Some("https://example.com/none")),
            None
        );
    }

    #[test]
    fn summaries_are_bounded() {
        let summary = bound_summary(&"a".repeat(10_000));
        assert!(serde_json::to_string(&summary).unwrap().len() <= MAX_SUMMARY_JSON_BYTES);
        assert!(summary.ends_with("..."));
    }

    #[test]
    fn event_ids_are_deterministic_and_attempt_sensitive() {
        let first = event_id("ci", &["repo", "42", "1"]);
        let second = event_id("ci", &["repo", "42", "1"]);
        let rerun = event_id("ci", &["repo", "42", "2"]);
        assert_eq!(first, second);
        assert_ne!(first, rerun);
        assert!(first.len() < 200);
    }

    #[test]
    fn display_strings_and_urls_are_bounded() {
        let display = bounded_display(&"é".repeat(10_000));
        assert!(display.len() <= MAX_DISPLAY_BYTES);
        assert!(display.is_char_boundary(display.len()));
        let url = bounded_url(&"https://example.com/".repeat(1_000));
        assert!(url.len() <= MAX_URL_BYTES);
        assert!(url.is_char_boundary(url.len()));
    }

    #[test]
    fn event_payloads_stay_well_under_the_delivery_ceiling() {
        let event = workflow_failed_event(
            "o/r",
            &"w".repeat(10_000),
            "42",
            1,
            "failure",
            Some(&"b".repeat(10_000)),
            &format!("https://example.com/{}", "u".repeat(10_000)),
            "2026-11-16T01:00:00.000Z",
        );
        let serialized = serde_json::to_vec(&event.payload).unwrap();
        assert!(
            serialized.len() <= MAX_EVENT_PAYLOAD_BYTES,
            "{}",
            serialized.len()
        );
    }

    #[test]
    fn reviewer_keys_keep_users_and_teams_distinct() {
        assert_eq!(reviewer_key("user", "platform"), "user:platform");
        assert_eq!(reviewer_key("team", "platform"), "team:platform");
        assert_eq!(reviewer_name("user:platform"), "platform");
        assert_eq!(reviewer_name("team:platform"), "platform");
    }
}
