//! GitHub Collector tests.
//!
//! Webhook tests go through the real hub HTTP surface. Reconciliation tests use
//! a mock GitHub REST server that honours `If-None-Match`. The end-to-end test
//! subscribes a mock ChatGPT receiver directly in SQLite and verifies the
//! Standard Webhooks signature and the catalog payload schema.

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::{
    Json, Router,
    extract::{Path, Query, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use events_bridge::{
    config::Config,
    delivery::verification::CallbackPolicy,
    event::EventBus,
    hub::Hub,
    mcp::{event_catalog, tools},
    store::{Event, EventQuery, NewSubscription},
};
use hmac::{Hmac, Mac};
use rmcp::model::{CallToolRequestParams, CallToolResponse};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::Sha256;
use tempfile::TempDir;
use tokio::{task::JoinHandle, time::timeout};
use tokio_util::sync::CancellationToken;
use url::Url;

const REPO: &str = "soramikan/events-bridge";
const SECRET: &str = "github-webhook-test-secret";
const WHSEC: &str = "whsec_C2FVsBQIhrscChlQIMV+b5sSYspob7oD";

// ---------------------------------------------------------------------------
// Hub harness
// ---------------------------------------------------------------------------

struct TestHub {
    hub: Arc<Hub>,
    base_url: String,
    server: JoinHandle<()>,
    dispatcher: Option<(CancellationToken, JoinHandle<()>)>,
}

impl TestHub {
    async fn start(config: Config) -> Self {
        Self::start_with_dispatcher(config, false).await
    }

    async fn start_with_dispatcher(config: Config, with_dispatcher: bool) -> Self {
        let hub =
            Arc::new(Hub::with_policy(config, CallbackPolicy::for_tests()).expect("hub builds"));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let router = hub.router();
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        let dispatcher = with_dispatcher.then(|| hub.spawn_dispatcher());
        Self {
            hub,
            base_url: format!("http://{address}"),
            server,
            dispatcher,
        }
    }

    fn repo(&self) -> &events_bridge::store::Repository {
        self.hub.repository()
    }

    async fn stop(mut self) {
        if let Some((cancellation, handle)) = self.dispatcher.take() {
            cancellation.cancel();
            let _ = handle.await;
        }
        self.server.abort();
        let _ = (&mut self.server).await;
    }
}

impl Drop for TestHub {
    fn drop(&mut self) {
        if let Some((cancellation, _)) = self.dispatcher.take() {
            cancellation.cancel();
        }
        self.server.abort();
    }
}

fn github_config(db: &std::path::Path, secret_var: &str) -> Config {
    let mut config = Config::for_tests(db);
    config.collectors.github.webhook_enabled = true;
    config.collectors.github.webhook_secret_env = Some(secret_var.to_string());
    config.collectors.github.repositories = vec![REPO.to_string()];
    config.collectors.github.max_webhook_body_bytes = 2048;
    config
}

fn set_secret(variable: &str) {
    // SAFETY: each test uses a unique variable name.
    unsafe {
        std::env::set_var(variable, SECRET);
    }
}

fn sign(body: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(SECRET.as_bytes()).unwrap();
    mac.update(body);
    format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
}

async fn send_webhook(
    base_url: &str,
    delivery: &str,
    event: &str,
    body: &Value,
) -> (StatusCode, Value) {
    let bytes = serde_json::to_vec(body).unwrap();
    let headers = [
        ("X-GitHub-Delivery", delivery.to_string()),
        ("X-GitHub-Event", event.to_string()),
        ("X-Hub-Signature-256", sign(&bytes)),
    ];
    send_raw(base_url, &bytes, &headers).await
}

async fn send_raw(base_url: &str, bytes: &[u8], headers: &[(&str, String)]) -> (StatusCode, Value) {
    let mut request = reqwest::Client::new()
        .post(format!("{base_url}/webhooks/github"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(bytes.to_vec());
    for (name, value) in headers {
        request = request.header(*name, value);
    }
    let response = request.send().await.expect("webhook request");
    let status = response.status();
    let value = response.json::<Value>().await.unwrap_or(Value::Null);
    (status, value)
}

// ---------------------------------------------------------------------------
// Payload builders
// ---------------------------------------------------------------------------

fn repository() -> Value {
    json!({"full_name": REPO})
}

fn pull_payload(action: &str, number: i64, merged: bool) -> Value {
    pull_payload_at(action, number, merged, "2099-11-16T01:00:00Z", &[], &[])
}

fn pull_payload_at(
    action: &str,
    number: i64,
    merged: bool,
    updated_at: &str,
    reviewers: &[&str],
    teams: &[&str],
) -> Value {
    let state = if action == "closed" { "closed" } else { "open" };
    let reviewers: Vec<Value> = reviewers
        .iter()
        .map(|login| json!({"login": login}))
        .collect();
    let teams: Vec<Value> = teams.iter().map(|slug| json!({"slug": slug})).collect();
    let requested_reviewer = if matches!(action, "review_requested" | "review_request_removed") {
        json!({"login": "carol"})
    } else {
        Value::Null
    };
    json!({
        "action": action,
        "number": number,
        "requested_reviewer": requested_reviewer,
        "pull_request": {
            "number": number,
            "title": format!("Pull request {number}"),
            "state": state,
            "user": {"login": "alice"},
            "head": {"ref": "feature", "sha": "abc123"},
            "base": {"ref": "main"},
            "draft": false,
            "merged": merged,
            "merged_by": if merged { json!({"login": "bob"}) } else { Value::Null },
            "merged_at": if merged { json!(updated_at) } else { Value::Null },
            "requested_reviewers": reviewers,
            "requested_teams": teams,
            "html_url": format!("https://github.com/{REPO}/pull/{number}"),
            "updated_at": updated_at
        },
        "repository": repository()
    })
}

fn review_payload(number: i64, state: &str) -> Value {
    // Real `pull_request_review` webhooks have no top-level `number`; only
    // `pull_request.number` is present.
    json!({
        "action": "submitted",
        "review": {
            "state": state,
            "submitted_at": "2099-11-16T03:00:00Z"
        },
        "pull_request": {
            "number": number,
            "title": format!("Pull request {number}"),
            "state": "open",
            "user": {"login": "alice"},
            "head": {"ref": "feature", "sha": "abc123"},
            "base": {"ref": "main"},
            "merged": false,
            "requested_reviewers": [],
            "html_url": format!("https://github.com/{REPO}/pull/{number}"),
            "updated_at": "2099-11-16T03:00:00Z"
        },
        "repository": repository()
    })
}

fn review_comment_payload(number: i64) -> Value {
    // Real `pull_request_review_comment` webhooks have no top-level `number`.
    json!({
        "action": "created",
        "comment": {"updated_at": "2099-11-16T04:00:00Z"},
        "pull_request": {
            "number": number,
            "title": format!("Pull request {number}"),
            "state": "open",
            "user": {"login": "alice"},
            "head": {"ref": "feature", "sha": "abc123"},
            "base": {"ref": "main"},
            "merged": false,
            "requested_reviewers": [],
            "html_url": format!("https://github.com/{REPO}/pull/{number}"),
            "updated_at": "2099-11-16T03:30:00Z"
        },
        "repository": repository()
    })
}

fn workflow_payload(run_id: i64, attempt: i64, suite_id: i64, conclusion: &str) -> Value {
    workflow_payload_for(
        REPO,
        run_id,
        attempt,
        suite_id,
        "CI",
        "abc123",
        conclusion,
        "2099-11-16T02:00:00Z",
    )
}

#[allow(clippy::too_many_arguments)]
fn workflow_payload_for(
    repository: &str,
    run_id: i64,
    attempt: i64,
    suite_id: i64,
    name: &str,
    head_sha: &str,
    conclusion: &str,
    updated_at: &str,
) -> Value {
    json!({
        "action": "completed",
        "workflow_run": {
            "id": run_id,
            "run_attempt": attempt,
            "check_suite_id": suite_id,
            "name": name,
            "head_branch": "main",
            "head_sha": head_sha,
            "status": "completed",
            "conclusion": conclusion,
            "html_url": format!("https://github.com/{repository}/actions/runs/{run_id}"),
            "updated_at": updated_at
        },
        "repository": {"full_name": repository}
    })
}

fn check_run_payload(
    check_run_id: i64,
    suite_id: i64,
    conclusion: &str,
    details_url: Option<&str>,
) -> Value {
    check_run_payload_full(
        check_run_id,
        suite_id,
        "test",
        "completed",
        Some(conclusion),
        details_url,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn check_run_payload_full(
    check_run_id: i64,
    suite_id: i64,
    name: &str,
    status: &str,
    conclusion: Option<&str>,
    details_url: Option<&str>,
    app_slug: Option<&str>,
) -> Value {
    let mut run = json!({
        "id": check_run_id,
        "name": name,
        "status": status,
        "conclusion": conclusion,
        "head_sha": "abc123",
        "check_suite": {
            "id": suite_id,
            "head_branch": "main",
            "head_sha": "abc123"
        },
        "html_url": format!("https://github.com/{REPO}/commit/abc123#check-{check_run_id}"),
        "completed_at": "2099-11-16T02:05:00Z"
    });
    if let Some(url) = details_url {
        run["details_url"] = json!(url);
        run["html_url"] = json!(url);
    }
    if let Some(slug) = app_slug {
        run["app"] = json!({"slug": slug});
    }
    json!({
        "action": "completed",
        "check_run": run,
        "repository": repository()
    })
}

// ---------------------------------------------------------------------------
// Event helpers
// ---------------------------------------------------------------------------

fn events(repo: &events_bridge::store::Repository) -> Vec<Event> {
    repo.list_events(&EventQuery {
        limit: 200,
        ..Default::default()
    })
    .unwrap()
}

fn event_kinds(repo: &events_bridge::store::Repository) -> Vec<String> {
    events(repo).into_iter().map(|event| event.kind).collect()
}

// ---------------------------------------------------------------------------
// Webhook signature, headers, size, dedup
// ---------------------------------------------------------------------------

#[tokio::test]
async fn webhook_rejects_bad_signatures_and_missing_headers() {
    let temp = TempDir::new().unwrap();
    let variable = "EB_TEST_GH_SECRET_SIGNATURE";
    set_secret(variable);
    let hub = TestHub::start(github_config(&temp.path().join("events.db"), variable)).await;

    // Missing signature.
    let body = json!({"zen": "hello", "repository": repository()});
    let bytes = serde_json::to_vec(&body).unwrap();
    let (status, _) = send_raw(
        &hub.base_url,
        &bytes,
        &[
            ("X-GitHub-Delivery", "d-1".into()),
            ("X-GitHub-Event", "ping".into()),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Wrong secret.
    let mut mac = Hmac::<Sha256>::new_from_slice(b"wrong-secret").unwrap();
    mac.update(&bytes);
    let wrong = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));
    let (status, _) = send_raw(
        &hub.base_url,
        &bytes,
        &[
            ("X-GitHub-Delivery", "d-2".into()),
            ("X-GitHub-Event", "ping".into()),
            ("X-Hub-Signature-256", wrong),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Tampered body with a valid signature for the original bytes.
    let tampered = serde_json::to_vec(&json!({"zen": "tampered"})).unwrap();
    let (status, _) = send_raw(
        &hub.base_url,
        &tampered,
        &[
            ("X-GitHub-Delivery", "d-3".into()),
            ("X-GitHub-Event", "ping".into()),
            ("X-Hub-Signature-256", sign(&bytes)),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Valid signature but missing event / delivery headers.
    let (status, _) = send_raw(
        &hub.base_url,
        &bytes,
        &[("X-Hub-Signature-256", sign(&bytes))],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, _) = send_raw(
        &hub.base_url,
        &bytes,
        &[
            ("X-GitHub-Delivery", "  ".into()),
            ("X-GitHub-Event", "ping".into()),
            ("X-Hub-Signature-256", sign(&bytes)),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // A valid ping is accepted and recorded.
    let (status, value) = send_webhook(&hub.base_url, "d-ping", "ping", &body).await;
    assert_eq!(status, StatusCode::OK, "{value}");
    assert_eq!(value["status"], "ok");
    assert!(hub.repo().github_delivery_exists("d-ping").unwrap());
    hub.stop().await;
}

#[tokio::test]
async fn webhook_rejects_oversized_bodies() {
    let temp = TempDir::new().unwrap();
    let variable = "EB_TEST_GH_SECRET_OVERSIZED";
    set_secret(variable);
    let mut config = github_config(&temp.path().join("events.db"), variable);
    config.collectors.github.max_webhook_body_bytes = 128;
    let hub = TestHub::start(config).await;

    let body = json!({"padding": "x".repeat(512)});
    let bytes = serde_json::to_vec(&body).unwrap();
    let (status, _) = send_raw(
        &hub.base_url,
        &bytes,
        &[
            ("X-GitHub-Delivery", "d-big".into()),
            ("X-GitHub-Event", "ping".into()),
            ("X-Hub-Signature-256", sign(&bytes)),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert!(!hub.repo().github_delivery_exists("d-big").unwrap());
    hub.stop().await;
}

#[tokio::test]
async fn disabled_webhook_route_returns_404() {
    let temp = TempDir::new().unwrap();
    let mut config = Config::for_tests(temp.path().join("events.db"));
    config.collectors.github.webhook_enabled = false;
    let hub = TestHub::start(config).await;
    let body = json!({"zen": "hello"});
    let bytes = serde_json::to_vec(&body).unwrap();
    let (status, _) = send_raw(
        &hub.base_url,
        &bytes,
        &[
            ("X-GitHub-Delivery", "d-disabled".into()),
            ("X-GitHub-Event", "ping".into()),
            ("X-Hub-Signature-256", sign(&bytes)),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    hub.stop().await;
}

#[tokio::test]
async fn delivery_ids_deduplicate_across_requests_and_restart() {
    let temp = TempDir::new().unwrap();
    let database = temp.path().join("events.db");
    let variable = "EB_TEST_GH_SECRET_DEDUP";
    set_secret(variable);
    let config = github_config(&database, variable);

    let first = TestHub::start(config.clone()).await;
    let payload = pull_payload("closed", 1, true);
    let (status, value) =
        send_webhook(&first.base_url, "d-merge-1", "pull_request", &payload).await;
    assert_eq!(status, StatusCode::OK, "{value}");
    assert_eq!(event_kinds(first.repo()), vec!["github.pr.merged"]);

    let (status, value) =
        send_webhook(&first.base_url, "d-merge-1", "pull_request", &payload).await;
    assert_eq!(status, StatusCode::OK, "{value}");
    assert_eq!(value["status"], "duplicate");
    assert_eq!(event_kinds(first.repo()).len(), 1);
    first.stop().await;

    // Reopening the same database retains the delivery id.
    let second = TestHub::start(config).await;
    let (status, value) =
        send_webhook(&second.base_url, "d-merge-1", "pull_request", &payload).await;
    assert_eq!(status, StatusCode::OK, "{value}");
    assert_eq!(value["status"], "duplicate");
    assert_eq!(event_kinds(second.repo()).len(), 1);
    second.stop().await;
}

// ---------------------------------------------------------------------------
// CI deduplication
// ---------------------------------------------------------------------------

#[tokio::test]
async fn workflow_run_then_check_run_emits_once() {
    let temp = TempDir::new().unwrap();
    let variable = "EB_TEST_GH_SECRET_CI_ORDER1";
    set_secret(variable);
    let hub = TestHub::start(github_config(&temp.path().join("events.db"), variable)).await;

    let (status, _) = send_webhook(
        &hub.base_url,
        "wf-1",
        "workflow_run",
        &workflow_payload(123, 1, 700, "failure"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(event_kinds(hub.repo()), vec!["github.workflow.failed"]);

    // A job URL without `/attempts/<n>` cannot be correlated safely. It is
    // parked and emits nothing, even though the canonical run already exists.
    let (status, value) = send_webhook(
        &hub.base_url,
        "cr-1",
        "check_run",
        &check_run_payload_full(
            501,
            700,
            "test",
            "completed",
            Some("failure"),
            Some("https://github.com/soramikan/events-bridge/actions/runs/123/job/9"),
            Some("github-actions"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{value}");
    assert_eq!(
        event_kinds(hub.repo()).len(),
        1,
        "check_run repeats workflow_run"
    );
    assert!(
        hub.repo()
            .get_github_pending_check(REPO, 501)
            .unwrap()
            .is_some()
    );

    let run = hub
        .repo()
        .get_github_ci_run(REPO, "123", 1)
        .unwrap()
        .expect("canonical run");
    assert!(run.failure_emitted);
    assert_eq!(run.check_suite_id, Some(700));

    // A second Actions check_run is also parked, never emitted.
    let (status, _) = send_webhook(
        &hub.base_url,
        "cr-2",
        "check_run",
        &check_run_payload_full(
            502,
            700,
            "test",
            "completed",
            Some("failure"),
            None,
            Some("github-actions"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(event_kinds(hub.repo()).len(), 1);
    assert!(
        hub.repo()
            .get_github_pending_check(REPO, 502)
            .unwrap()
            .is_some()
    );
    hub.stop().await;
}

#[tokio::test]
async fn actions_check_run_before_workflow_run_waits_for_true_workflow_name() {
    let temp = TempDir::new().unwrap();
    let variable = "EB_TEST_GH_SECRET_CI_ORDER2";
    set_secret(variable);
    let hub = TestHub::start(github_config(&temp.path().join("events.db"), variable)).await;

    // A subscription filtered on the real workflow name must match the event
    // emitted after the workflow_run arrives.
    hub.repo()
        .upsert_subscription(NewSubscription {
            id: "sub_ci_workflow_filter".into(),
            principal: "local".into(),
            event_name: "github.workflow.failed".into(),
            arguments: json!({"repository": REPO, "workflow": "CI"}),
            filter_hash: "hash-ci-workflow-filter".into(),
            callback_url: "https://example.com/hook".into(),
            secret: WHSEC.into(),
            refresh_before: None,
        })
        .unwrap();

    let mut expected_events = 0;
    for attempt in [1_i64, 2_i64] {
        let run_id = 500 + attempt;
        let suite_id = 800 + attempt;
        let (status, value) = send_webhook(
            &hub.base_url,
            &format!("cr-before-{attempt}"),
            "check_run",
            &check_run_payload_full(
                900 + attempt,
                suite_id,
                "test",
                "completed",
                Some("failure"),
                Some(&format!(
                    "https://github.com/{REPO}/actions/runs/{run_id}/job/999"
                )),
                Some("github-actions"),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{value}");
        assert_eq!(
            event_kinds(hub.repo()).len(),
            expected_events,
            "a check_run alone must not emit a guessed workflow"
        );
        let pending = hub
            .repo()
            .get_github_pending_check(REPO, 900 + attempt)
            .unwrap()
            .expect("pending check");
        assert_eq!(pending.actions_run_id, Some(run_id));
        assert_eq!(pending.parsed_attempt, None);

        let (status, value) = send_webhook(
            &hub.base_url,
            &format!("wf-after-{attempt}"),
            "workflow_run",
            &workflow_payload(run_id, attempt, suite_id, "failure"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{value}");
        expected_events += 1;
        let stored = events(hub.repo());
        assert_eq!(
            stored.len(),
            expected_events,
            "exactly one failure for attempt {attempt}"
        );
        let event = stored.last().expect("new failure event");
        assert_eq!(event.payload["workflow"], "CI");
        assert_eq!(event.payload["run_id"], run_id.to_string());
        assert!(
            event.payload["summary"]
                .as_str()
                .unwrap()
                .contains(&format!("attempt {attempt}"))
        );
        assert!(
            !hub.repo().delivery_statuses(&event.id).unwrap().is_empty(),
            "the workflow: CI subscription filter matched"
        );
        assert!(
            hub.repo()
                .get_github_pending_check(REPO, 900 + attempt)
                .unwrap()
                .is_none(),
            "workflow_run resolves the pending check"
        );
        let run = hub
            .repo()
            .get_github_ci_run(REPO, &run_id.to_string(), attempt)
            .unwrap()
            .expect("canonical run");
        assert_eq!(run.workflow_name, "CI");
        assert!(run.failure_emitted);
    }
    hub.stop().await;
}

#[tokio::test]
async fn check_run_with_late_details_url_does_not_repeat_fallback_failure() {
    let temp = TempDir::new().unwrap();
    let variable = "EB_TEST_GH_SECRET_CI_FALLBACK_UPGRADE";
    set_secret(variable);
    let hub = TestHub::start(github_config(&temp.path().join("events.db"), variable)).await;

    // Actions check run without a usable run URL: parked, no event.
    let (status, _) = send_webhook(
        &hub.base_url,
        "cr-fallback",
        "check_run",
        &check_run_payload_full(
            801,
            703,
            "test",
            "completed",
            Some("failure"),
            None,
            Some("github-actions"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(event_kinds(hub.repo()).is_empty());
    assert!(
        hub.repo()
            .get_github_pending_check(REPO, 801)
            .unwrap()
            .is_some()
    );

    // A richer check_run reveals the workflow run id and attempt, but the
    // canonical row does not exist yet, so it is still parked.
    let (status, _) = send_webhook(
        &hub.base_url,
        "cr-canonical",
        "check_run",
        &check_run_payload_full(
            802,
            703,
            "test",
            "completed",
            Some("failure"),
            Some(
                "https://api.github.com/repos/soramikan/events-bridge/actions/runs/126/attempts/1",
            ),
            Some("github-actions"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(event_kinds(hub.repo()).is_empty());
    assert!(
        hub.repo()
            .get_github_pending_check(REPO, 802)
            .unwrap()
            .is_some()
    );

    // The canonical workflow_run emits once with the true name and attempt.
    let (status, _) = send_webhook(
        &hub.base_url,
        "wf-canonical",
        "workflow_run",
        &workflow_payload(126, 1, 703, "failure"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(event_kinds(hub.repo()), vec!["github.workflow.failed"]);
    assert!(
        hub.repo()
            .get_github_ci_run(REPO, "126", 1)
            .unwrap()
            .is_some_and(|run| run.failure_emitted)
    );
    assert!(
        hub.repo()
            .get_github_pending_check(REPO, 801)
            .unwrap()
            .is_none()
    );
    assert!(
        hub.repo()
            .get_github_pending_check(REPO, 802)
            .unwrap()
            .is_none()
    );
    hub.stop().await;
}

#[tokio::test]
async fn rerun_attempt_emits_a_new_workflow_failure() {
    let temp = TempDir::new().unwrap();
    let variable = "EB_TEST_GH_SECRET_CI_RERUN";
    set_secret(variable);
    let hub = TestHub::start(github_config(&temp.path().join("events.db"), variable)).await;

    for (delivery, attempt) in [("wf-a1", 1), ("wf-a2", 2)] {
        let (status, _) = send_webhook(
            &hub.base_url,
            delivery,
            "workflow_run",
            &workflow_payload(125, attempt, 702, "failure"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }
    assert_eq!(event_kinds(hub.repo()).len(), 2, "each attempt notifies");
    assert!(
        hub.repo()
            .get_github_ci_run(REPO, "125", 2)
            .unwrap()
            .is_some_and(|run| run.failure_emitted)
    );

    // A check_run explicitly tied to attempt 2 must not add a third event.
    let (status, _) = send_webhook(
        &hub.base_url,
        "cr-a2",
        "check_run",
        &check_run_payload(
            701,
            702,
            "failure",
            Some(
                "https://api.github.com/repos/soramikan/events-bridge/actions/runs/125/attempts/2",
            ),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(event_kinds(hub.repo()).len(), 2);
    hub.stop().await;
}

#[test]
fn webhook_secret_env_must_exist_and_be_non_empty() {
    let temp = TempDir::new().unwrap();
    let variable = "EB_TEST_GH_SECRET_MISSING";
    // SAFETY: unique variable name used only by this test.
    unsafe {
        std::env::remove_var(variable);
    }
    let config = github_config(&temp.path().join("events.db"), variable);
    let error = Hub::with_policy(config, CallbackPolicy::for_tests())
        .err()
        .expect("missing webhook secret env must fail startup");
    assert!(error.to_string().contains(variable), "{error}");

    // SAFETY: unique variable name used only by this test.
    unsafe {
        std::env::set_var(variable, "   ");
    }
    let config = github_config(&temp.path().join("events.db"), variable);
    let error = Hub::with_policy(config, CallbackPolicy::for_tests())
        .err()
        .expect("empty webhook secret env must fail startup");
    assert!(error.to_string().contains("empty"), "{error}");
    // SAFETY: unique variable name used only by this test.
    unsafe {
        std::env::remove_var(variable);
    }
}

#[test]
fn token_env_must_exist_when_configured() {
    let temp = TempDir::new().unwrap();
    let variable = "EB_TEST_GH_TOKEN_MISSING";
    // SAFETY: unique variable name used only by this test.
    unsafe {
        std::env::remove_var(variable);
    }
    let mut config = Config::for_tests(temp.path().join("events.db"));
    config.collectors.github.token_env = Some(variable.into());
    let error = Hub::with_policy(config, CallbackPolicy::for_tests())
        .err()
        .expect("missing token env must fail startup");
    assert!(error.to_string().contains(variable), "{error}");
}

#[test]
fn token_env_value_is_loaded_at_startup() {
    let temp = TempDir::new().unwrap();
    let variable = "EB_TEST_GH_TOKEN_PRESENT";
    // SAFETY: unique variable name used only by this test.
    unsafe {
        std::env::set_var(variable, "test-token");
    }
    let mut config = Config::for_tests(temp.path().join("events.db"));
    config.collectors.github.token_env = Some(variable.into());
    let hub = Hub::with_policy(config, CallbackPolicy::for_tests()).expect("hub builds");
    assert_eq!(
        hub.state()
            .github_token
            .as_ref()
            .map(|token| token.expose_secret()),
        Some("test-token")
    );
    // SAFETY: unique variable name used only by this test.
    unsafe {
        std::env::remove_var(variable);
    }
}

// ---------------------------------------------------------------------------
// Pull request events
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pull_request_review_request_merge_and_review_state() {
    let temp = TempDir::new().unwrap();
    let variable = "EB_TEST_GH_SECRET_PR";
    set_secret(variable);
    let hub = TestHub::start(github_config(&temp.path().join("events.db"), variable)).await;

    // Opening and editing does not notify.
    for (delivery, action) in [("pr-open", "opened"), ("pr-edit", "edited")] {
        let (status, _) = send_webhook(
            &hub.base_url,
            delivery,
            "pull_request",
            &pull_payload(action, 10, false),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }
    assert!(event_kinds(hub.repo()).is_empty());

    let (status, _) = send_webhook(
        &hub.base_url,
        "pr-review-req",
        "pull_request",
        &pull_payload("review_requested", 10, false),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(event_kinds(hub.repo()), vec!["github.review.requested"]);
    let pull = hub
        .repo()
        .get_github_pull_request(REPO, 10)
        .unwrap()
        .unwrap();
    assert_eq!(pull.requested_reviewers, vec!["user:carol".to_string()]);

    // Re-requesting an already pending reviewer is quiet.
    let (status, _) = send_webhook(
        &hub.base_url,
        "pr-review-req-2",
        "pull_request",
        &pull_payload("review_requested", 10, false),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(event_kinds(hub.repo()).len(), 1);

    // Removing the request clears the pending reviewer without notifying.
    let (status, _) = send_webhook(
        &hub.base_url,
        "pr-review-removed",
        "pull_request",
        &pull_payload("review_request_removed", 10, false),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let pull = hub
        .repo()
        .get_github_pull_request(REPO, 10)
        .unwrap()
        .unwrap();
    assert!(pull.requested_reviewers.is_empty());
    assert_eq!(event_kinds(hub.repo()).len(), 1);

    // A submitted review records the latest state, without an event.
    let (status, _) = send_webhook(
        &hub.base_url,
        "pr-review",
        "pull_request_review",
        &review_payload(10, "approved"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let pull = hub
        .repo()
        .get_github_pull_request(REPO, 10)
        .unwrap()
        .unwrap();
    assert_eq!(pull.last_review_state.as_deref(), Some("approved"));
    assert_eq!(event_kinds(hub.repo()).len(), 1);

    // Review comments update `last_activity_at`, never the PR entity
    // `updated_at`.
    let (status, _) = send_webhook(
        &hub.base_url,
        "pr-comment",
        "pull_request_review_comment",
        &review_comment_payload(10),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let pull = hub
        .repo()
        .get_github_pull_request(REPO, 10)
        .unwrap()
        .unwrap();
    assert_eq!(
        pull.last_activity_at.as_deref(),
        Some("2099-11-16T04:00:00.000Z")
    );
    assert_eq!(pull.updated_at, "2099-11-16T03:30:00.000Z");

    // Merged PR emits; unmerged close does not.
    let (status, _) = send_webhook(
        &hub.base_url,
        "pr-merge",
        "pull_request",
        &pull_payload("closed", 11, true),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = send_webhook(
        &hub.base_url,
        "pr-close",
        "pull_request",
        &pull_payload("closed", 12, false),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        event_kinds(hub.repo()),
        vec!["github.review.requested", "github.pr.merged"]
    );
    let merged = hub
        .repo()
        .get_github_pull_request(REPO, 11)
        .unwrap()
        .unwrap();
    assert!(merged.merged);
    assert!(merged.merged_emitted);
    let unmerged = hub
        .repo()
        .get_github_pull_request(REPO, 12)
        .unwrap()
        .unwrap();
    assert!(!unmerged.merged);
    assert!(!unmerged.merged_emitted);

    // A repository outside the allowlist is acknowledged and ignored.
    let mut other = pull_payload("closed", 13, true);
    other["repository"] = json!({"full_name": "other/repo"});
    let (status, value) = send_webhook(&hub.base_url, "pr-other", "pull_request", &other).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["status"], "ignored");
    assert!(hub.repo().github_delivery_exists("pr-other").unwrap());
    assert!(
        hub.repo()
            .get_github_pull_request("other/repo", 13)
            .unwrap()
            .is_none()
    );
    hub.stop().await;
}

#[tokio::test]
async fn opened_with_requested_reviewers_notifies_once() {
    let temp = TempDir::new().unwrap();
    let variable = "EB_TEST_GH_SECRET_OPEN_REVIEW";
    set_secret(variable);
    let hub = TestHub::start(github_config(&temp.path().join("events.db"), variable)).await;

    let mut payload = pull_payload("opened", 40, false);
    payload["pull_request"]["requested_reviewers"] = json!([{"login": "erin"}]);
    let (status, _) = send_webhook(&hub.base_url, "open-review", "pull_request", &payload).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(event_kinds(hub.repo()), vec!["github.review.requested"]);

    // A later opened/review_requested delivery does not repeat it.
    let (status, _) =
        send_webhook(&hub.base_url, "open-review-again", "pull_request", &payload).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(event_kinds(hub.repo()).len(), 1);
    hub.stop().await;
}

// ---------------------------------------------------------------------------
// get_github_status
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_github_status_tool_returns_materialized_rows() {
    let temp = TempDir::new().unwrap();
    let variable = "EB_TEST_GH_SECRET_TOOL";
    set_secret(variable);
    let hub = TestHub::start(github_config(&temp.path().join("events.db"), variable)).await;

    send_webhook(
        &hub.base_url,
        "tool-pr-1",
        "pull_request",
        &pull_payload("opened", 20, false),
    )
    .await;
    send_webhook(
        &hub.base_url,
        "tool-pr-2",
        "pull_request",
        &pull_payload("closed", 21, true),
    )
    .await;
    send_webhook(
        &hub.base_url,
        "tool-ci",
        "workflow_run",
        &workflow_payload(300, 1, 900, "timed_out"),
    )
    .await;

    assert!(
        tools::definitions()
            .iter()
            .any(|tool| tool.name == "get_github_status")
    );

    let service = hub.hub.state().tools.clone();
    let response = service
        .call(
            "local",
            CallToolRequestParams::new("get_github_status")
                .with_arguments(json!({"repository": REPO}).as_object().unwrap().clone()),
        )
        .await
        .unwrap();
    let CallToolResponse::Complete(response) = response else {
        panic!("expected a complete tool response");
    };
    let value = response.into_typed::<Value>().unwrap();
    let pulls = value["pullRequests"].as_array().unwrap();
    assert_eq!(pulls.len(), 2);
    let runs = value["ciRuns"].as_array().unwrap();
    assert_eq!(runs.len(), 1);
    assert_eq!(value["summary"]["pullRequestCount"], 2);
    assert_eq!(value["summary"]["mergedPullRequestCount"], 1);
    assert_eq!(value["summary"]["failedCiRunCount"], 1);

    let filtered = service
        .call(
            "local",
            CallToolRequestParams::new("get_github_status").with_arguments(
                json!({"repository": REPO, "pull_number": 21})
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
        )
        .await
        .unwrap();
    let CallToolResponse::Complete(filtered) = filtered else {
        panic!("expected a complete tool response");
    };
    let filtered = filtered.into_typed::<Value>().unwrap();
    assert_eq!(filtered["pullRequests"].as_array().unwrap().len(), 1);
    assert_eq!(filtered["pullRequests"][0]["pullNumber"], 21);

    let bad = service
        .call(
            "local",
            CallToolRequestParams::new("get_github_status").with_arguments(
                json!({"repository": "not-a-repository"})
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
        )
        .await
        .unwrap();
    let CallToolResponse::Complete(bad) = bad else {
        panic!("expected a complete tool response");
    };
    assert_eq!(bad.is_error, Some(true));
    hub.stop().await;
}

// ---------------------------------------------------------------------------
// Mock GitHub REST API
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct ApiRequest {
    path: String,
    query: Option<String>,
    if_none_match: Option<String>,
    authorization: Option<String>,
    user_agent: Option<String>,
    accept: Option<String>,
    api_version: Option<String>,
}

struct ApiData {
    pulls: Vec<Value>,
    runs: Vec<Value>,
    pull_pages: Option<Vec<Vec<Value>>>,
    run_pages: Option<Vec<Vec<Value>>>,
    pulls_etag: String,
    runs_etag: String,
    runs_by_id: HashMap<i64, Value>,
    run_attempts: HashMap<(i64, i64), Value>,
    check_runs_by_id: HashMap<i64, Value>,
    repo_status: HashMap<String, u16>,
    requests: Vec<ApiRequest>,
}

#[derive(Clone)]
struct ApiState {
    data: Arc<Mutex<ApiData>>,
}

struct MockGitHub {
    url: String,
    state: Arc<ApiState>,
    task: JoinHandle<()>,
}

impl MockGitHub {
    async fn start() -> Self {
        let state = Arc::new(ApiState {
            data: Arc::new(Mutex::new(ApiData {
                pulls: Vec::new(),
                runs: Vec::new(),
                pull_pages: None,
                run_pages: None,
                pulls_etag: "pulls-v1".into(),
                runs_etag: "runs-v1".into(),
                runs_by_id: HashMap::new(),
                run_attempts: HashMap::new(),
                check_runs_by_id: HashMap::new(),
                repo_status: HashMap::new(),
                requests: Vec::new(),
            })),
        });
        let app = Router::new()
            .route("/repos/{owner}/{repo}/pulls", get(pulls))
            .route("/repos/{owner}/{repo}/actions/runs", get(runs))
            .route(
                "/repos/{owner}/{repo}/actions/runs/{run_id}",
                get(run_by_id),
            )
            .route(
                "/repos/{owner}/{repo}/actions/runs/{run_id}/attempts/{attempt}",
                get(run_attempt_by_id),
            )
            .route(
                "/repos/{owner}/{repo}/check-runs/{check_run_id}",
                get(check_run_by_id),
            )
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self {
            url: format!("http://{address}"),
            state,
            task,
        }
    }

    fn set_pulls(&self, pulls: Vec<Value>, etag: &str) {
        let mut data = self.state.data.lock().unwrap();
        data.pulls = pulls;
        data.pull_pages = None;
        data.pulls_etag = etag.to_string();
    }

    fn set_pull_pages(&self, pages: Vec<Vec<Value>>, etag: &str) {
        let mut data = self.state.data.lock().unwrap();
        data.pull_pages = Some(pages);
        data.pulls_etag = etag.to_string();
    }

    fn set_runs(&self, runs: Vec<Value>, etag: &str) {
        let mut data = self.state.data.lock().unwrap();
        data.runs = runs;
        data.run_pages = None;
        data.runs_etag = etag.to_string();
    }

    fn set_run_pages(&self, pages: Vec<Vec<Value>>, etag: &str) {
        let mut data = self.state.data.lock().unwrap();
        data.run_pages = Some(pages);
        data.runs_etag = etag.to_string();
    }

    fn set_run_by_id(&self, run_id: i64, run: Value) {
        let mut data = self.state.data.lock().unwrap();
        data.runs_by_id.insert(run_id, run);
    }

    fn set_run_attempt(&self, run_id: i64, attempt: i64, run: Value) {
        let mut data = self.state.data.lock().unwrap();
        data.run_attempts.insert((run_id, attempt), run);
    }

    fn set_check_run(&self, check_run_id: i64, run: Value) {
        let mut data = self.state.data.lock().unwrap();
        data.check_runs_by_id.insert(check_run_id, run);
    }

    fn set_repo_status(&self, repository: &str, status: u16) {
        let mut data = self.state.data.lock().unwrap();
        data.repo_status.insert(repository.to_string(), status);
    }

    fn requests(&self) -> Vec<ApiRequest> {
        self.state.data.lock().unwrap().requests.clone()
    }
}

impl Drop for MockGitHub {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn api_request(path: &str, query: Option<&str>, headers: &HeaderMap) -> ApiRequest {
    ApiRequest {
        path: path.into(),
        query: query.map(str::to_string),
        if_none_match: headers
            .get(header::IF_NONE_MATCH)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string),
        authorization: headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string),
        user_agent: headers
            .get(header::USER_AGENT)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string),
        accept: headers
            .get(header::ACCEPT)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string),
        api_version: headers
            .get("x-github-api-version")
            .and_then(|value| value.to_str().ok())
            .map(str::to_string),
    }
}

#[derive(Debug, Deserialize)]
struct PageQuery {
    #[serde(default)]
    page: Option<u32>,
    #[serde(default)]
    check_suite_id: Option<i64>,
}

async fn pulls(
    State(state): State<Arc<ApiState>>,
    Path((owner, repo)): Path<(String, String)>,
    Query(query): Query<PageQuery>,
    uri: axum::http::Uri,
    headers: HeaderMap,
) -> Response {
    let repository = format!("{owner}/{repo}");
    let page = query.page.unwrap_or(1).max(1);
    let (status, etag, pages) = {
        let mut data = state.data.lock().unwrap();
        data.requests.push(api_request(
            &format!("/repos/{repository}/pulls"),
            uri.query(),
            &headers,
        ));
        let pages = data
            .pull_pages
            .clone()
            .unwrap_or_else(|| vec![data.pulls.clone()]);
        (
            data.repo_status.get(&repository).copied(),
            data.pulls_etag.clone(),
            pages,
        )
    };
    if let Some(status) = status {
        return status_response(status);
    }
    if page == 1
        && headers
            .get(header::IF_NONE_MATCH)
            .and_then(|value| value.to_str().ok())
            == Some(etag.as_str())
    {
        return not_modified(&etag);
    }
    let body = pages.get(page as usize - 1).cloned().unwrap_or_default();
    let mut response = ok_json(&etag, Value::Array(body));
    if (page as usize) < pages.len() {
        let host = headers
            .get(header::HOST)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("127.0.0.1");
        let next = format!(
            "http://{host}/repos/{repository}/pulls?state=all&sort=updated&direction=desc&per_page=100&page={}",
            page + 1
        );
        response.headers_mut().insert(
            header::LINK,
            HeaderValue::from_str(&format!("<{next}>; rel=\"next\"")).expect("link header"),
        );
    }
    response
}

async fn runs(
    State(state): State<Arc<ApiState>>,
    Path((owner, repo)): Path<(String, String)>,
    Query(query): Query<PageQuery>,
    uri: axum::http::Uri,
    headers: HeaderMap,
) -> Response {
    let repository = format!("{owner}/{repo}");
    let page = query.page.unwrap_or(1).max(1);
    let suite_filter = query.check_suite_id;
    let (status, etag, pages) = {
        let mut data = state.data.lock().unwrap();
        data.requests.push(api_request(
            &format!("/repos/{repository}/actions/runs"),
            uri.query(),
            &headers,
        ));
        let pages = data
            .run_pages
            .clone()
            .unwrap_or_else(|| vec![data.runs.clone()]);
        (
            data.repo_status.get(&repository).copied(),
            data.runs_etag.clone(),
            pages,
        )
    };
    if let Some(status) = status {
        return status_response(status);
    }
    if page == 1
        && headers
            .get(header::IF_NONE_MATCH)
            .and_then(|value| value.to_str().ok())
            == Some(etag.as_str())
    {
        return not_modified(&etag);
    }
    let mut body = pages.get(page as usize - 1).cloned().unwrap_or_default();
    if let Some(suite_id) = suite_filter {
        body.retain(|run| run["check_suite_id"].as_i64() == Some(suite_id));
    }
    let mut response = ok_json(&etag, json!({"workflow_runs": body}));
    if suite_filter.is_none() && (page as usize) < pages.len() {
        let host = headers
            .get(header::HOST)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("127.0.0.1");
        let next = format!(
            "http://{host}/repos/{repository}/actions/runs?per_page=100&page={}",
            page + 1
        );
        response.headers_mut().insert(
            header::LINK,
            HeaderValue::from_str(&format!("<{next}>; rel=\"next\"")).expect("link header"),
        );
    }
    response
}

async fn run_by_id(
    State(state): State<Arc<ApiState>>,
    Path((owner, repo, run_id)): Path<(String, String, i64)>,
    uri: axum::http::Uri,
    headers: HeaderMap,
) -> Response {
    let repository = format!("{owner}/{repo}");
    let (status, run) = {
        let mut data = state.data.lock().unwrap();
        data.requests.push(api_request(
            &format!("/repos/{repository}/actions/runs/{run_id}"),
            uri.query(),
            &headers,
        ));
        (
            data.repo_status.get(&repository).copied(),
            data.runs_by_id.get(&run_id).cloned(),
        )
    };
    if let Some(status) = status {
        return status_response(status);
    }
    match run {
        Some(run) => ok_json("run", run),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn run_attempt_by_id(
    State(state): State<Arc<ApiState>>,
    Path((owner, repo, run_id, attempt)): Path<(String, String, i64, i64)>,
    uri: axum::http::Uri,
    headers: HeaderMap,
) -> Response {
    let repository = format!("{owner}/{repo}");
    let (status, run) = {
        let mut data = state.data.lock().unwrap();
        data.requests.push(api_request(
            &format!("/repos/{repository}/actions/runs/{run_id}/attempts/{attempt}"),
            uri.query(),
            &headers,
        ));
        let run = data
            .run_attempts
            .get(&(run_id, attempt))
            .cloned()
            .or_else(|| {
                data.runs_by_id
                    .get(&run_id)
                    .cloned()
                    .filter(|run| run["run_attempt"].as_i64() == Some(attempt))
            });
        (data.repo_status.get(&repository).copied(), run)
    };
    if let Some(status) = status {
        return status_response(status);
    }
    match run {
        Some(run) => ok_json("run-attempt", run),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn check_run_by_id(
    State(state): State<Arc<ApiState>>,
    Path((owner, repo, check_run_id)): Path<(String, String, i64)>,
    uri: axum::http::Uri,
    headers: HeaderMap,
) -> Response {
    let repository = format!("{owner}/{repo}");
    let (status, run) = {
        let mut data = state.data.lock().unwrap();
        data.requests.push(api_request(
            &format!("/repos/{repository}/check-runs/{check_run_id}"),
            uri.query(),
            &headers,
        ));
        (
            data.repo_status.get(&repository).copied(),
            data.check_runs_by_id.get(&check_run_id).cloned(),
        )
    };
    if let Some(status) = status {
        return status_response(status);
    }
    match run {
        Some(run) => ok_json("check-run", run),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

fn status_response(status: u16) -> Response {
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut response = (status, Json(json!({"message": "mock error"}))).into_response();
    if status == StatusCode::TOO_MANY_REQUESTS {
        response
            .headers_mut()
            .insert("retry-after", HeaderValue::from_static("1"));
    }
    response
}

fn not_modified(etag: &str) -> Response {
    let mut response = StatusCode::NOT_MODIFIED.into_response();
    response.headers_mut().insert(
        header::ETAG,
        HeaderValue::from_str(etag).expect("etag header"),
    );
    response
}

fn ok_json(etag: &str, body: Value) -> Response {
    let mut response = Json(body).into_response();
    response.headers_mut().insert(
        header::ETAG,
        HeaderValue::from_str(etag).expect("etag header"),
    );
    response
}

fn api_pull(number: i64, merged: bool, updated_at: &str) -> Value {
    api_pull_with_reviewers(number, merged, updated_at, &[], &[])
}

fn api_pull_with_reviewers(
    number: i64,
    merged: bool,
    updated_at: &str,
    reviewers: &[&str],
    teams: &[&str],
) -> Value {
    let reviewers: Vec<Value> = reviewers
        .iter()
        .map(|login| json!({"login": login}))
        .collect();
    let teams: Vec<Value> = teams.iter().map(|slug| json!({"slug": slug})).collect();
    json!({
        "number": number,
        "title": format!("API pull {number}"),
        "state": if merged { "closed" } else { "open" },
        "user": {"login": "alice"},
        "head": {"ref": "feature", "sha": format!("sha{number}")},
        "base": {"ref": "main"},
        "draft": false,
        // The list endpoint omits `merged`; `merged_at` is the source of truth.
        "merged_by": if merged { json!({"login": "bob"}) } else { Value::Null },
        "merged_at": if merged { json!(updated_at) } else { Value::Null },
        "requested_reviewers": reviewers,
        "requested_teams": teams,
        "html_url": format!("https://github.com/{REPO}/pull/{number}"),
        "updated_at": updated_at
    })
}

fn api_run(id: i64, attempt: i64, suite: i64, conclusion: &str, updated_at: &str) -> Value {
    api_run_full(
        id,
        attempt,
        suite,
        "CI",
        "abc123",
        "completed",
        Some(conclusion),
        updated_at,
        updated_at,
    )
}

#[allow(clippy::too_many_arguments)]
fn api_run_full(
    id: i64,
    attempt: i64,
    suite: i64,
    name: &str,
    head_sha: &str,
    status: &str,
    conclusion: Option<&str>,
    created_at: &str,
    updated_at: &str,
) -> Value {
    json!({
        "id": id,
        "run_attempt": attempt,
        "check_suite_id": suite,
        "name": name,
        "head_branch": "main",
        "head_sha": head_sha,
        "status": status,
        "conclusion": conclusion,
        "html_url": format!("https://github.com/{REPO}/actions/runs/{id}"),
        "created_at": created_at,
        "updated_at": updated_at
    })
}

fn poller(
    mock: &MockGitHub,
    repo: Arc<events_bridge::store::Repository>,
) -> events_bridge::collectors::GitHubPoller {
    poller_for(mock, repo, vec![REPO.to_string()])
}

fn poller_for(
    mock: &MockGitHub,
    repo: Arc<events_bridge::store::Repository>,
    repositories: Vec<String>,
) -> events_bridge::collectors::GitHubPoller {
    events_bridge::collectors::GitHubPoller::new(
        events_bridge::collectors::GitHubPollerSettings {
            repositories,
            api_base_url: Url::parse(&mock.url).unwrap(),
            token: None,
            poll_interval: Duration::from_secs(1),
        },
        repo,
        EventBus::new(),
    )
    .unwrap()
}

// ---------------------------------------------------------------------------
// Polling reconciliation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn poll_baselines_history_then_honours_304() {
    let temp = TempDir::new().unwrap();
    let mock = MockGitHub::start().await;
    mock.set_pulls(
        vec![
            api_pull(1, true, "2099-11-16T01:00:00Z"),
            api_pull(2, false, "2099-11-16T01:01:00Z"),
        ],
        "pulls-v1",
    );
    mock.set_runs(
        vec![api_run(100, 1, 900, "failure", "2099-11-16T01:02:00Z")],
        "runs-v1",
    );

    let repo =
        Arc::new(events_bridge::store::Repository::open(temp.path().join("events.db")).unwrap());
    let poller = poller(&mock, repo.clone());

    let first = poller.poll_once().await.unwrap();
    assert_eq!(first.repositories, 1);
    assert_eq!(first.pull_requests, 2);
    assert_eq!(first.ci_runs, 1);
    assert_eq!(first.events, 0, "first poll baselines history");
    assert!(event_kinds(&repo).is_empty());

    let merged = repo.get_github_pull_request(REPO, 1).unwrap().unwrap();
    assert!(merged.merged);
    assert!(merged.merged_emitted);
    let failed = repo.get_github_ci_run(REPO, "100", 1).unwrap().unwrap();
    assert!(failed.failure_emitted);

    let pulls_checkpoint = repo
        .get_github_checkpoint(&events_bridge::store::pulls_scope(REPO))
        .unwrap()
        .expect("pulls checkpoint");
    assert_eq!(pulls_checkpoint.etag.as_deref(), Some("pulls-v1"));
    assert!(pulls_checkpoint.watermark.is_some());
    let runs_checkpoint = repo
        .get_github_checkpoint(&events_bridge::store::runs_scope(REPO))
        .unwrap()
        .expect("runs checkpoint");
    assert_eq!(runs_checkpoint.etag.as_deref(), Some("runs-v1"));

    let second = poller.poll_once().await.unwrap();
    assert_eq!(second.not_modified, 2);
    assert_eq!(second.events, 0);

    let requests = mock.requests();
    assert!(
        requests
            .iter()
            .any(|request| request.path.ends_with("/pulls")
                && request.if_none_match.as_deref() == Some("pulls-v1")),
        "{requests:?}"
    );
    assert!(
        requests
            .iter()
            .any(|request| request.path.ends_with("/actions/runs")
                && request.if_none_match.as_deref() == Some("runs-v1")),
        "{requests:?}"
    );
}

#[tokio::test]
async fn poll_sends_the_configured_github_api_headers() {
    let temp = TempDir::new().unwrap();
    let mock = MockGitHub::start().await;
    mock.set_pulls(vec![], "pulls-v1");
    mock.set_runs(vec![], "runs-v1");
    let repo =
        Arc::new(events_bridge::store::Repository::open(temp.path().join("events.db")).unwrap());
    let poller = events_bridge::collectors::GitHubPoller::new(
        events_bridge::collectors::GitHubPollerSettings {
            repositories: vec![REPO.to_string()],
            api_base_url: Url::parse(&mock.url).unwrap(),
            token: Some(SecretString::from("test-token")),
            poll_interval: Duration::from_secs(1),
        },
        repo,
        EventBus::new(),
    )
    .unwrap();

    poller.poll_once().await.unwrap();
    let requests = mock.requests();
    assert_eq!(requests.len(), 2, "{requests:?}");
    for request in requests {
        assert_eq!(
            request.user_agent.as_deref(),
            Some(concat!("events-bridge/", env!("CARGO_PKG_VERSION")))
        );
        assert_eq!(
            request.accept.as_deref(),
            Some("application/vnd.github+json")
        );
        assert_eq!(request.api_version.as_deref(), Some("2022-11-28"));
        assert_eq!(request.authorization.as_deref(), Some("Bearer test-token"));
    }
}

#[tokio::test]
async fn poll_backfills_missed_events_and_webhook_does_not_duplicate() {
    let temp = TempDir::new().unwrap();
    let database = temp.path().join("events.db");
    let variable = "EB_TEST_GH_SECRET_POLL";
    set_secret(variable);
    let mut config = github_config(&database, variable);
    config.collectors.github.poll_enabled = true;
    let hub = TestHub::start(config).await;
    let repo = hub.hub.repository().clone();

    let mock = MockGitHub::start().await;
    mock.set_pulls(vec![], "pulls-v1");
    mock.set_runs(vec![], "runs-v1");
    let poller = poller(&mock, repo.clone());
    let baseline = poller.poll_once().await.unwrap();
    assert_eq!(baseline.events, 0);
    assert!(event_kinds(&repo).is_empty());

    // Missed while the receiver/webhook was down.
    mock.set_pulls(vec![api_pull(2, true, "2099-11-16T02:00:00Z")], "pulls-v2");
    mock.set_runs(
        vec![api_run(300, 1, 950, "failure", "2099-11-16T02:01:00Z")],
        "runs-v2",
    );
    let backfill = poller.poll_once().await.unwrap();
    assert_eq!(backfill.events, 2, "{backfill:?}");
    assert_eq!(
        event_kinds(&repo),
        vec!["github.pr.merged", "github.workflow.failed"]
    );
    assert!(
        repo.get_github_pull_request(REPO, 2)
            .unwrap()
            .unwrap()
            .merged_emitted
    );
    assert!(
        repo.get_github_ci_run(REPO, "300", 1)
            .unwrap()
            .unwrap()
            .failure_emitted
    );

    // A later webhook for the same merge / failure is informed, not repeated.
    let (status, _) = send_webhook(
        &hub.base_url,
        "poll-pr-later",
        "pull_request",
        &pull_payload("closed", 2, true),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = send_webhook(
        &hub.base_url,
        "poll-ci-later",
        "workflow_run",
        &workflow_payload(300, 1, 950, "failure"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        event_kinds(&repo).len(),
        2,
        "poll and webhook share dedup flags"
    );
    hub.stop().await;
}

#[tokio::test]
async fn poll_emits_new_review_requests_once() {
    let temp = TempDir::new().unwrap();
    let mock = MockGitHub::start().await;
    mock.set_pulls(vec![api_pull(3, false, "2099-11-16T01:00:00Z")], "pulls-v1");
    mock.set_runs(vec![], "runs-v1");
    let repo =
        Arc::new(events_bridge::store::Repository::open(temp.path().join("events.db")).unwrap());
    let poller = poller(&mock, repo.clone());
    poller.poll_once().await.unwrap();
    assert!(event_kinds(&repo).is_empty());

    let mut pull = api_pull(3, false, "2099-11-16T02:00:00Z");
    pull["requested_reviewers"] = json!([{"login": "dave"}]);
    mock.set_pulls(vec![pull], "pulls-v2");
    let first = poller.poll_once().await.unwrap();
    assert_eq!(first.events, 1);
    assert_eq!(event_kinds(&repo), vec!["github.review.requested"]);

    // A second poll with the same reviewer is a duplicate (304 in this case).
    let second = poller.poll_once().await.unwrap();
    assert_eq!(second.not_modified, 2);
    assert_eq!(event_kinds(&repo).len(), 1);
}

#[tokio::test]
async fn list_api_merged_pull_without_merged_field_is_detected() {
    let temp = TempDir::new().unwrap();
    let mock = MockGitHub::start().await;
    mock.set_pulls(vec![], "pulls-v1");
    mock.set_runs(vec![], "runs-v1");
    let repo =
        Arc::new(events_bridge::store::Repository::open(temp.path().join("events.db")).unwrap());
    let poller = poller(&mock, repo.clone());
    poller.poll_once().await.unwrap();
    assert!(event_kinds(&repo).is_empty());

    // `merged` is deliberately absent, exactly like GET /pulls.
    mock.set_pulls(vec![api_pull(5, true, "2099-11-16T02:00:00Z")], "pulls-v2");
    let summary = poller.poll_once().await.unwrap();
    assert_eq!(summary.events, 1, "{summary:?}");
    assert_eq!(event_kinds(&repo), vec!["github.pr.merged"]);
    let pull = repo.get_github_pull_request(REPO, 5).unwrap().unwrap();
    assert!(pull.merged);
    assert!(pull.merged_emitted);
    assert_eq!(pull.merged_at.as_deref(), Some("2099-11-16T02:00:00.000Z"));
}

#[tokio::test]
async fn poll_follows_link_pagination_for_pulls_and_runs() {
    let temp = TempDir::new().unwrap();
    let mock = MockGitHub::start().await;
    mock.set_pull_pages(
        vec![
            vec![api_pull(1, false, "2099-11-16T01:00:00Z")],
            vec![api_pull(2, true, "2099-11-16T00:30:00Z")],
        ],
        "pulls-v1",
    );
    mock.set_run_pages(
        vec![
            vec![api_run(100, 1, 900, "failure", "2099-11-16T01:02:00Z")],
            vec![api_run(90, 1, 901, "failure", "2099-11-16T00:00:00Z")],
        ],
        "runs-v1",
    );
    let repo =
        Arc::new(events_bridge::store::Repository::open(temp.path().join("events.db")).unwrap());
    let poller = poller(&mock, repo.clone());

    let baseline = poller.poll_once().await.unwrap();
    assert_eq!(baseline.pull_requests, 2, "{baseline:?}");
    assert_eq!(baseline.ci_runs, 2, "{baseline:?}");
    assert_eq!(baseline.events, 0);
    assert!(repo.get_github_pull_request(REPO, 2).unwrap().is_some());
    assert!(repo.get_github_ci_run(REPO, "90", 1).unwrap().is_some());

    let requests = mock.requests();
    assert!(
        requests
            .iter()
            .any(|request| request.path.ends_with("/pulls")
                && request
                    .query
                    .as_deref()
                    .is_some_and(|query| query.contains("page=2"))),
        "{requests:?}"
    );
    assert!(
        requests
            .iter()
            .any(|request| request.path.ends_with("/actions/runs")
                && request
                    .query
                    .as_deref()
                    .is_some_and(|query| query.contains("page=2"))),
        "{requests:?}"
    );

    // New items on page 1 are emitted; the older page 2 is still traversed
    // because page 1 is not entirely below the watermark.
    mock.set_pull_pages(
        vec![
            vec![
                api_pull(3, true, "2099-11-16T02:00:00Z"),
                api_pull(1, false, "2099-11-16T01:00:00Z"),
            ],
            vec![api_pull(2, true, "2099-11-16T00:30:00Z")],
        ],
        "pulls-v2",
    );
    mock.set_run_pages(
        vec![
            vec![
                api_run(101, 1, 902, "failure", "2099-11-16T02:01:00Z"),
                api_run(100, 1, 900, "failure", "2099-11-16T01:02:00Z"),
            ],
            vec![api_run(90, 1, 901, "failure", "2099-11-16T00:00:00Z")],
        ],
        "runs-v2",
    );
    let second = poller.poll_once().await.unwrap();
    assert_eq!(second.events, 2, "{second:?}");
    assert_eq!(
        event_kinds(&repo),
        vec!["github.pr.merged", "github.workflow.failed"]
    );
}

#[tokio::test]
async fn poll_watermark_stops_pagination_and_skips_unseen_history() {
    let temp = TempDir::new().unwrap();
    let mock = MockGitHub::start().await;
    mock.set_pull_pages(
        vec![
            vec![api_pull(1, false, "2099-11-16T01:00:00Z")],
            vec![api_pull(2, false, "2099-11-16T00:00:00Z")],
        ],
        "pulls-v1",
    );
    mock.set_runs(vec![], "runs-v1");
    let repo =
        Arc::new(events_bridge::store::Repository::open(temp.path().join("events.db")).unwrap());
    let poller = poller(&mock, repo.clone());
    poller.poll_once().await.unwrap();

    let page_two_before = mock
        .requests()
        .iter()
        .filter(|request| {
            request.path.ends_with("/pulls")
                && request
                    .query
                    .as_deref()
                    .is_some_and(|query| query.contains("page=2"))
        })
        .count();

    // Page 1 is entirely older than the watermark. Page 2 contains a new
    // merge, but it must not be fetched or emitted.
    mock.set_pull_pages(
        vec![
            vec![api_pull(3, false, "2099-11-16T00:30:00Z")],
            vec![api_pull(4, true, "2099-11-16T02:00:00Z")],
        ],
        "pulls-v2",
    );
    let summary = poller.poll_once().await.unwrap();
    assert_eq!(summary.events, 0, "{summary:?}");
    assert!(event_kinds(&repo).is_empty());
    assert!(
        repo.get_github_pull_request(REPO, 3).unwrap().is_none(),
        "unseen historical item is not materialized"
    );
    assert!(
        repo.get_github_pull_request(REPO, 4).unwrap().is_none(),
        "page 2 was not fetched"
    );
    let page_two_after = mock
        .requests()
        .iter()
        .filter(|request| {
            request.path.ends_with("/pulls")
                && request
                    .query
                    .as_deref()
                    .is_some_and(|query| query.contains("page=2"))
        })
        .count();
    assert_eq!(page_two_before, page_two_after);
    let checkpoint = repo
        .get_github_checkpoint(&events_bridge::store::pulls_scope(REPO))
        .unwrap()
        .unwrap();
    assert_eq!(
        checkpoint.watermark.as_deref(),
        Some("2099-11-16T01:00:00.000Z"),
        "a bounded historical page must not rewind the watermark"
    );
}

#[tokio::test]
async fn poll_recovers_long_running_run_beyond_page_one() {
    let temp = TempDir::new().unwrap();
    let mock = MockGitHub::start().await;
    mock.set_pulls(vec![], "pulls-v1");
    mock.set_run_pages(
        vec![
            vec![api_run_full(
                100,
                1,
                900,
                "CI",
                "abc123",
                "in_progress",
                None,
                "2099-11-16T01:00:00Z",
                "2099-11-16T01:00:00Z",
            )],
            vec![api_run_full(
                90,
                1,
                901,
                "CI",
                "abc123",
                "in_progress",
                None,
                "2099-11-16T00:00:00Z",
                "2099-11-16T00:00:00Z",
            )],
        ],
        "runs-v1",
    );
    let repo =
        Arc::new(events_bridge::store::Repository::open(temp.path().join("events.db")).unwrap());
    let poller = poller(&mock, repo.clone());
    poller.poll_once().await.unwrap();
    assert!(
        repo.get_github_ci_run(REPO, "90", 1)
            .unwrap()
            .is_some_and(|run| run.status == "in_progress")
    );

    // The list no longer reaches page 2, but run 90 is locally tracked as
    // active and must be fetched individually.
    mock.set_runs(vec![], "runs-v2");
    mock.set_run_by_id(
        90,
        api_run_full(
            90,
            1,
            901,
            "CI",
            "abc123",
            "completed",
            Some("failure"),
            "2099-11-16T00:00:00Z",
            "2099-11-16T02:00:00Z",
        ),
    );
    let summary = poller.poll_once().await.unwrap();
    assert_eq!(summary.events, 1, "{summary:?}");
    assert_eq!(event_kinds(&repo), vec!["github.workflow.failed"]);
    let run = repo.get_github_ci_run(REPO, "90", 1).unwrap().unwrap();
    assert_eq!(run.status, "completed");
    assert_eq!(run.conclusion.as_deref(), Some("failure"));
    assert!(run.failure_emitted);
    assert!(
        mock.requests()
            .iter()
            .any(|request| request.path.ends_with("/actions/runs/90")),
        "tracked active run is fetched individually"
    );
}

#[tokio::test]
async fn stale_pull_edit_does_not_rewind_review_request() {
    let temp = TempDir::new().unwrap();
    let variable = "EB_TEST_GH_SECRET_STALE_EDIT";
    set_secret(variable);
    let hub = TestHub::start(github_config(&temp.path().join("events.db"), variable)).await;

    send_webhook(
        &hub.base_url,
        "stale-open",
        "pull_request",
        &pull_payload_at("opened", 70, false, "2099-11-16T01:00:00Z", &[], &[]),
    )
    .await;
    send_webhook(
        &hub.base_url,
        "stale-review",
        "pull_request",
        &pull_payload_at(
            "review_requested",
            70,
            false,
            "2099-11-16T02:00:00Z",
            &[],
            &[],
        ),
    )
    .await;
    assert_eq!(event_kinds(hub.repo()), vec!["github.review.requested"]);

    // An out-of-order edit from before the review request must not rewind the
    // row or emit a second review request.
    let (status, _) = send_webhook(
        &hub.base_url,
        "stale-edit",
        "pull_request",
        &pull_payload_at("edited", 70, false, "2099-11-16T01:30:00Z", &[], &[]),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(event_kinds(hub.repo()).len(), 1);
    let pull = hub
        .repo()
        .get_github_pull_request(REPO, 70)
        .unwrap()
        .unwrap();
    assert_eq!(pull.updated_at, "2099-11-16T02:00:00.000Z");
    assert_eq!(pull.requested_reviewers, vec!["user:carol".to_string()]);
    hub.stop().await;
}

#[tokio::test]
async fn stale_poll_does_not_rewind_review_request() {
    let temp = TempDir::new().unwrap();
    let variable = "EB_TEST_GH_SECRET_STALE_POLL";
    set_secret(variable);
    let hub = TestHub::start(github_config(&temp.path().join("events.db"), variable)).await;
    let repo = hub.hub.repository().clone();

    let mock = MockGitHub::start().await;
    mock.set_pulls(vec![api_pull(3, false, "2099-11-16T01:00:00Z")], "pulls-v1");
    mock.set_runs(vec![], "runs-v1");
    let poller = poller(&mock, repo.clone());
    poller.poll_once().await.unwrap();

    send_webhook(
        &hub.base_url,
        "stale-poll-review",
        "pull_request",
        &pull_payload_at(
            "review_requested",
            3,
            false,
            "2099-11-16T02:00:00Z",
            &[],
            &[],
        ),
    )
    .await;
    assert_eq!(event_kinds(&repo), vec!["github.review.requested"]);

    // A stale poll response from before the review request must not rewind.
    mock.set_pulls(vec![api_pull(3, false, "2099-11-16T01:30:00Z")], "pulls-v2");
    let summary = poller.poll_once().await.unwrap();
    assert_eq!(summary.events, 0, "{summary:?}");
    assert_eq!(event_kinds(&repo).len(), 1);
    let pull = repo.get_github_pull_request(REPO, 3).unwrap().unwrap();
    assert_eq!(pull.updated_at, "2099-11-16T02:00:00.000Z");
    assert_eq!(pull.requested_reviewers, vec!["user:carol".to_string()]);
    hub.stop().await;
}

#[tokio::test]
async fn stale_workflow_run_does_not_overwrite_newer_state() {
    let temp = TempDir::new().unwrap();
    let variable = "EB_TEST_GH_SECRET_STALE_CI";
    set_secret(variable);
    let hub = TestHub::start(github_config(&temp.path().join("events.db"), variable)).await;

    send_webhook(
        &hub.base_url,
        "ci-failure",
        "workflow_run",
        &workflow_payload_for(
            REPO,
            400,
            1,
            950,
            "CI",
            "abc123",
            "failure",
            "2099-11-16T02:00:00Z",
        ),
    )
    .await;
    assert_eq!(event_kinds(hub.repo()), vec!["github.workflow.failed"]);

    send_webhook(
        &hub.base_url,
        "ci-success",
        "workflow_run",
        &workflow_payload_for(
            REPO,
            400,
            1,
            950,
            "CI",
            "abc123",
            "success",
            "2099-11-16T03:00:00Z",
        ),
    )
    .await;
    assert_eq!(event_kinds(hub.repo()).len(), 1);

    // A stale failure from before the success must not emit or rewind state.
    send_webhook(
        &hub.base_url,
        "ci-stale-failure",
        "workflow_run",
        &workflow_payload_for(
            REPO,
            400,
            1,
            950,
            "CI",
            "abc123",
            "failure",
            "2099-11-16T02:30:00Z",
        ),
    )
    .await;
    assert_eq!(event_kinds(hub.repo()).len(), 1);
    let run = hub
        .repo()
        .get_github_ci_run(REPO, "400", 1)
        .unwrap()
        .unwrap();
    assert_eq!(run.status, "completed");
    assert_eq!(run.conclusion.as_deref(), Some("success"));
    assert_eq!(run.updated_at, "2099-11-16T03:00:00.000Z");
    assert!(run.failure_emitted);
    hub.stop().await;
}

#[tokio::test]
async fn team_review_requests_are_namespaced_and_persist() {
    let temp = TempDir::new().unwrap();
    let variable = "EB_TEST_GH_SECRET_TEAM_REVIEW";
    set_secret(variable);
    let hub = TestHub::start(github_config(&temp.path().join("events.db"), variable)).await;

    send_webhook(
        &hub.base_url,
        "team-open",
        "pull_request",
        &pull_payload_at(
            "opened",
            60,
            false,
            "2099-11-16T01:00:00Z",
            &["platform"],
            &["platform"],
        ),
    )
    .await;
    assert_eq!(event_kinds(hub.repo()).len(), 2);
    let pull = hub
        .repo()
        .get_github_pull_request(REPO, 60)
        .unwrap()
        .unwrap();
    assert_eq!(
        pull.requested_reviewers,
        vec!["user:platform".to_string(), "team:platform".to_string()]
    );

    // An edit that omits both arrays preserves the pending requests.
    let mut edited = pull_payload_at("edited", 60, false, "2099-11-16T02:00:00Z", &[], &[]);
    edited["pull_request"]
        .as_object_mut()
        .unwrap()
        .remove("requested_reviewers");
    edited["pull_request"]
        .as_object_mut()
        .unwrap()
        .remove("requested_teams");
    send_webhook(&hub.base_url, "team-edit", "pull_request", &edited).await;
    let pull = hub
        .repo()
        .get_github_pull_request(REPO, 60)
        .unwrap()
        .unwrap();
    assert_eq!(
        pull.requested_reviewers,
        vec!["user:platform".to_string(), "team:platform".to_string()]
    );
    assert_eq!(event_kinds(hub.repo()).len(), 2);

    // A poll with the same names does not duplicate the requests.
    let mock = MockGitHub::start().await;
    mock.set_pulls(
        vec![api_pull_with_reviewers(
            60,
            false,
            "2099-11-16T03:00:00Z",
            &["platform"],
            &["platform"],
        )],
        "pulls-v1",
    );
    mock.set_runs(vec![], "runs-v1");
    let poller = poller(&mock, hub.hub.repository().clone());
    poller.poll_once().await.unwrap();
    assert_eq!(event_kinds(hub.repo()).len(), 2);
    let pull = hub
        .repo()
        .get_github_pull_request(REPO, 60)
        .unwrap()
        .unwrap();
    assert_eq!(
        pull.requested_reviewers,
        vec!["user:platform".to_string(), "team:platform".to_string()]
    );

    // An authoritative empty array clears both namespaces.
    mock.set_pulls(
        vec![api_pull_with_reviewers(
            60,
            false,
            "2099-11-16T04:00:00Z",
            &[],
            &[],
        )],
        "pulls-v2",
    );
    poller.poll_once().await.unwrap();
    assert_eq!(event_kinds(hub.repo()).len(), 2);
    let pull = hub
        .repo()
        .get_github_pull_request(REPO, 60)
        .unwrap()
        .unwrap();
    assert!(pull.requested_reviewers.is_empty());
    hub.stop().await;
}

#[tokio::test]
async fn get_github_status_correlates_ci_runs_per_repository() {
    let temp = TempDir::new().unwrap();
    let variable = "EB_TEST_GH_SECRET_MULTI_REPO";
    set_secret(variable);
    let mut config = github_config(&temp.path().join("events.db"), variable);
    config.collectors.github.repositories = vec![REPO.to_string(), "other/repo".to_string()];
    let hub = TestHub::start(config).await;

    let mut first = pull_payload("opened", 50, false);
    first["pull_request"]["head"]["sha"] = json!("shared");
    send_webhook(&hub.base_url, "multi-pr-1", "pull_request", &first).await;

    let mut second = pull_payload("opened", 50, false);
    second["repository"] = json!({"full_name": "other/repo"});
    second["pull_request"]["head"]["sha"] = json!("shared");
    second["pull_request"]["html_url"] = json!("https://github.com/other/repo/pull/50");
    send_webhook(&hub.base_url, "multi-pr-2", "pull_request", &second).await;

    send_webhook(
        &hub.base_url,
        "multi-ci-1",
        "workflow_run",
        &workflow_payload_for(
            REPO,
            600,
            1,
            960,
            "CI",
            "shared",
            "failure",
            "2099-11-16T02:00:00Z",
        ),
    )
    .await;
    send_webhook(
        &hub.base_url,
        "multi-ci-2",
        "workflow_run",
        &workflow_payload_for(
            "other/repo",
            601,
            1,
            961,
            "CI",
            "shared",
            "failure",
            "2099-11-16T02:00:00Z",
        ),
    )
    .await;

    let service = hub.hub.state().tools.clone();
    let response = service
        .call(
            "local",
            CallToolRequestParams::new("get_github_status")
                .with_arguments(json!({"pull_number": 50}).as_object().unwrap().clone()),
        )
        .await
        .unwrap();
    let CallToolResponse::Complete(response) = response else {
        panic!("expected a complete tool response");
    };
    let value = response.into_typed::<Value>().unwrap();
    assert_eq!(value["pullRequests"].as_array().unwrap().len(), 2);
    let runs = value["ciRuns"].as_array().unwrap();
    assert_eq!(runs.len(), 2, "{value}");
    let run_600 = runs
        .iter()
        .find(|run| run["canonicalRunId"] == "600")
        .expect("run 600");
    assert_eq!(run_600["repository"], REPO);
    let run_601 = runs
        .iter()
        .find(|run| run["canonicalRunId"] == "601")
        .expect("run 601");
    assert_eq!(run_601["repository"], "other/repo");
    hub.stop().await;
}

#[tokio::test]
async fn pull_request_number_validation_rejects_missing_null_zero_and_mismatch() {
    let temp = TempDir::new().unwrap();
    let variable = "EB_TEST_GH_SECRET_PR_NUMBER";
    set_secret(variable);
    let hub = TestHub::start(github_config(&temp.path().join("events.db"), variable)).await;

    let mut missing = pull_payload("opened", 10, false);
    missing.as_object_mut().unwrap().remove("number");
    let mut null = pull_payload("opened", 10, false);
    null["number"] = Value::Null;
    let mut zero = pull_payload("opened", 10, false);
    zero["number"] = json!(0);
    zero["pull_request"]["number"] = json!(0);
    let mut mismatch = pull_payload("opened", 10, false);
    mismatch["pull_request"]["number"] = json!(11);

    for (delivery, payload) in [
        ("pr-number-missing", missing),
        ("pr-number-null", null),
        ("pr-number-zero", zero),
        ("pr-number-mismatch", mismatch),
    ] {
        let (status, value) = send_webhook(&hub.base_url, delivery, "pull_request", &payload).await;
        assert_eq!(status, StatusCode::OK, "{value}");
    }
    assert!(event_kinds(hub.repo()).is_empty());
    assert!(
        hub.repo()
            .get_github_pull_request(REPO, 10)
            .unwrap()
            .is_none()
    );
    assert!(
        hub.repo()
            .get_github_pull_request(REPO, 11)
            .unwrap()
            .is_none()
    );
    hub.stop().await;
}

#[tokio::test]
async fn get_github_status_rejects_invalid_arguments() {
    let temp = TempDir::new().unwrap();
    let variable = "EB_TEST_GH_SECRET_TOOL_ARGS";
    set_secret(variable);
    let hub = TestHub::start(github_config(&temp.path().join("events.db"), variable)).await;
    let service = hub.hub.state().tools.clone();

    for arguments in [
        json!({"pull_number": 0}),
        json!({"pull_number": -1}),
        json!({"limit": 0}),
        json!({"limit": 201}),
    ] {
        let response = service
            .call(
                "local",
                CallToolRequestParams::new("get_github_status")
                    .with_arguments(arguments.as_object().unwrap().clone()),
            )
            .await
            .unwrap();
        let CallToolResponse::Complete(response) = response else {
            panic!("expected a complete tool response");
        };
        assert_eq!(response.is_error, Some(true), "{arguments}");
    }

    let response = service
        .call(
            "local",
            CallToolRequestParams::new("get_github_status")
                .with_arguments(json!({"limit": 200}).as_object().unwrap().clone()),
        )
        .await
        .unwrap();
    let CallToolResponse::Complete(response) = response else {
        panic!("expected a complete tool response");
    };
    assert_ne!(response.is_error, Some(true));
    hub.stop().await;
}

#[tokio::test]
async fn poll_isolates_per_repository_errors() {
    let temp = TempDir::new().unwrap();
    let mock = MockGitHub::start().await;
    mock.set_pulls(vec![], "pulls-v1");
    mock.set_runs(vec![], "runs-v1");
    mock.set_repo_status("broken/repo", 404);
    let repo =
        Arc::new(events_bridge::store::Repository::open(temp.path().join("events.db")).unwrap());
    let poller = poller_for(
        &mock,
        repo.clone(),
        vec![REPO.to_string(), "broken/repo".to_string()],
    );

    let baseline = poller.poll_once().await.unwrap();
    assert_eq!(baseline.repositories, 2);
    assert_eq!(baseline.errors, 2, "{baseline:?}");

    mock.set_pulls(vec![api_pull(7, true, "2099-11-16T02:00:00Z")], "pulls-v2");
    mock.set_runs(
        vec![api_run(700, 1, 970, "failure", "2099-11-16T02:01:00Z")],
        "runs-v2",
    );
    let summary = poller.poll_once().await.unwrap();
    assert_eq!(summary.repositories, 2);
    assert_eq!(summary.errors, 2, "{summary:?}");
    assert_eq!(summary.events, 2, "{summary:?}");
    assert_eq!(
        event_kinds(&repo),
        vec!["github.pr.merged", "github.workflow.failed"]
    );
}

#[tokio::test]
async fn poll_stops_on_rate_limit_error_with_retry_after() {
    let temp = TempDir::new().unwrap();
    let mock = MockGitHub::start().await;
    mock.set_repo_status(REPO, 429);
    let repo =
        Arc::new(events_bridge::store::Repository::open(temp.path().join("events.db")).unwrap());
    let poller = poller(&mock, repo);
    let error = poller.poll_once().await.expect_err("429 stops the pass");
    assert!(error.to_string().contains("retry after"), "{error}");
}

#[tokio::test]
async fn poll_stops_on_global_authentication_error() {
    let temp = TempDir::new().unwrap();
    let mock = MockGitHub::start().await;
    mock.set_repo_status(REPO, 401);
    let repo =
        Arc::new(events_bridge::store::Repository::open(temp.path().join("events.db")).unwrap());
    let poller = poller_for(
        &mock,
        repo,
        vec![REPO.to_string(), "other/repo".to_string()],
    );
    let error = poller.poll_once().await.expect_err("401 stops the pass");
    assert!(error.to_string().contains("401"), "{error}");
}

#[tokio::test]
async fn not_modified_runs_still_reconcile_pending_actions_checks() {
    let temp = TempDir::new().unwrap();
    let variable = "EB_TEST_GH_SECRET_PENDING_304";
    set_secret(variable);
    let hub = TestHub::start(github_config(&temp.path().join("events.db"), variable)).await;
    let repo = hub.hub.repository().clone();

    let mock = MockGitHub::start().await;
    mock.set_pulls(vec![], "pulls-v1");
    mock.set_runs(vec![], "runs-v1");
    let poller = poller(&mock, repo.clone());
    poller.poll_once().await.unwrap();

    send_webhook(
        &hub.base_url,
        "pending-check-304",
        "check_run",
        &check_run_payload_full(
            503,
            803,
            "test",
            "completed",
            Some("failure"),
            Some(&format!(
                "https://github.com/{REPO}/actions/runs/503/job/999"
            )),
            Some("github-actions"),
        ),
    )
    .await;
    assert!(event_kinds(&repo).is_empty());

    // The list is unchanged (304), but the pending check still needs the
    // individual run lookup.
    mock.set_run_by_id(
        503,
        api_run_full(
            503,
            1,
            803,
            "CI",
            "abc123",
            "completed",
            Some("failure"),
            "2099-11-16T01:00:00Z",
            "2099-11-16T02:00:00Z",
        ),
    );
    let summary = poller.poll_once().await.unwrap();
    assert!(summary.not_modified >= 1, "{summary:?}");
    assert_eq!(summary.events, 1, "{summary:?}");
    assert_eq!(event_kinds(&repo), vec!["github.workflow.failed"]);
    assert!(repo.get_github_pending_check(REPO, 503).unwrap().is_none());
    assert!(
        repo.get_github_ci_run(REPO, "503", 1)
            .unwrap()
            .is_some_and(|run| run.failure_emitted)
    );
    hub.stop().await;
}

#[tokio::test]
async fn pending_actions_check_run_is_resolved_by_poller() {
    let temp = TempDir::new().unwrap();
    let variable = "EB_TEST_GH_SECRET_PENDING_POLL";
    set_secret(variable);
    let hub = TestHub::start(github_config(&temp.path().join("events.db"), variable)).await;
    let repo = hub.hub.repository().clone();

    let mock = MockGitHub::start().await;
    mock.set_pulls(vec![], "pulls-v1");
    mock.set_runs(vec![], "runs-v1");
    let poller = poller(&mock, repo.clone());
    poller.poll_once().await.unwrap();

    send_webhook(
        &hub.base_url,
        "pending-check",
        "check_run",
        &check_run_payload_full(
            502,
            802,
            "test",
            "completed",
            Some("failure"),
            Some(&format!(
                "https://github.com/{REPO}/actions/runs/502/job/999"
            )),
            Some("github-actions"),
        ),
    )
    .await;
    assert!(event_kinds(&repo).is_empty());
    assert!(repo.get_github_pending_check(REPO, 502).unwrap().is_some());

    mock.set_runs(vec![], "runs-v2");
    mock.set_run_by_id(
        502,
        api_run_full(
            502,
            1,
            802,
            "CI",
            "abc123",
            "completed",
            Some("failure"),
            "2099-11-16T01:00:00Z",
            "2099-11-16T02:00:00Z",
        ),
    );
    let summary = poller.poll_once().await.unwrap();
    assert_eq!(summary.events, 1, "{summary:?}");
    let stored = events(&repo);
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].payload["workflow"], "CI");
    assert!(repo.get_github_pending_check(REPO, 502).unwrap().is_none());
    assert!(
        repo.get_github_ci_run(REPO, "502", 1)
            .unwrap()
            .is_some_and(|run| run.failure_emitted)
    );
    hub.stop().await;
}

#[tokio::test]
async fn review_number_validation_uses_pull_request_number() {
    let temp = TempDir::new().unwrap();
    let variable = "EB_TEST_GH_SECRET_REVIEW_NUMBER";
    set_secret(variable);
    let hub = TestHub::start(github_config(&temp.path().join("events.db"), variable)).await;

    // Real review webhooks omit the top-level `number`.
    let (status, value) = send_webhook(
        &hub.base_url,
        "review-no-outer",
        "pull_request_review",
        &review_payload(80, "approved"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{value}");
    let pull = hub
        .repo()
        .get_github_pull_request(REPO, 80)
        .unwrap()
        .unwrap();
    assert_eq!(pull.last_review_state.as_deref(), Some("approved"));

    // A present but mismatched top-level number is rejected.
    let mut mismatch = review_payload(80, "changes_requested");
    mismatch["number"] = json!(81);
    let (status, value) = send_webhook(
        &hub.base_url,
        "review-mismatch",
        "pull_request_review",
        &mismatch,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{value}");
    let pull = hub
        .repo()
        .get_github_pull_request(REPO, 80)
        .unwrap()
        .unwrap();
    assert_eq!(pull.last_review_state.as_deref(), Some("approved"));

    // A matching top-level number is accepted.
    let mut matching = review_payload(80, "commented");
    matching["number"] = json!(80);
    let (status, value) = send_webhook(
        &hub.base_url,
        "review-matching",
        "pull_request_review",
        &matching,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{value}");
    let pull = hub
        .repo()
        .get_github_pull_request(REPO, 80)
        .unwrap()
        .unwrap();
    assert_eq!(pull.last_review_state.as_deref(), Some("commented"));
    hub.stop().await;
}

#[tokio::test]
async fn poll_resumes_after_page_cap_without_advancing_checkpoint() {
    let temp = TempDir::new().unwrap();
    let mock = MockGitHub::start().await;
    let pull_pages: Vec<Vec<Value>> = (1..=51)
        .map(|page| {
            vec![api_pull(
                page,
                false,
                &format!("2099-11-16T00:{:02}:00Z", page),
            )]
        })
        .collect();
    let run_pages: Vec<Vec<Value>> = (1..=51)
        .map(|page| {
            vec![api_run(
                1000 + page,
                1,
                2000 + page,
                "success",
                &format!("2099-11-16T00:{:02}:00Z", page),
            )]
        })
        .collect();
    mock.set_pull_pages(pull_pages, "pulls-v1");
    mock.set_run_pages(run_pages, "runs-v1");
    let repo =
        Arc::new(events_bridge::store::Repository::open(temp.path().join("events.db")).unwrap());
    let poller = poller(&mock, repo.clone());

    let first = poller.poll_once().await.unwrap();
    assert_eq!(first.events, 0, "{first:?}");
    assert!(
        repo.get_github_checkpoint(&events_bridge::store::pulls_scope(REPO))
            .unwrap()
            .is_none(),
        "a truncated pull scan must not advance the checkpoint"
    );
    assert!(
        repo.get_github_checkpoint(&events_bridge::store::runs_scope(REPO))
            .unwrap()
            .is_none(),
        "a truncated run scan must not advance the checkpoint"
    );
    let pulls_continuation = repo
        .get_github_poll_continuation(&events_bridge::store::pulls_scope(REPO))
        .unwrap()
        .expect("pull continuation");
    assert!(
        pulls_continuation.next_url.contains("page=51"),
        "{}",
        pulls_continuation.next_url
    );
    let runs_continuation = repo
        .get_github_poll_continuation(&events_bridge::store::runs_scope(REPO))
        .unwrap()
        .expect("run continuation");
    assert!(
        runs_continuation.next_url.contains("page=51"),
        "{}",
        runs_continuation.next_url
    );
    assert!(
        repo.get_github_pull_request(REPO, 51).unwrap().is_none(),
        "page 51 is not fetched on the truncated pass"
    );
    assert!(
        repo.get_github_ci_run(REPO, "1051", 1).unwrap().is_none(),
        "page 51 is not fetched on the truncated pass"
    );

    let second = poller.poll_once().await.unwrap();
    assert_eq!(second.events, 0, "{second:?}");
    assert!(
        repo.get_github_pull_request(REPO, 51).unwrap().is_some(),
        "page 51 is materialized on the resumed pass"
    );
    assert!(
        repo.get_github_ci_run(REPO, "1051", 1).unwrap().is_some(),
        "page 51 is materialized on the resumed pass"
    );
    assert!(
        repo.get_github_poll_continuation(&events_bridge::store::pulls_scope(REPO))
            .unwrap()
            .is_none()
    );
    assert!(
        repo.get_github_poll_continuation(&events_bridge::store::runs_scope(REPO))
            .unwrap()
            .is_none()
    );
    let pulls_checkpoint = repo
        .get_github_checkpoint(&events_bridge::store::pulls_scope(REPO))
        .unwrap()
        .expect("pull checkpoint after completion");
    assert_eq!(pulls_checkpoint.etag.as_deref(), Some("pulls-v1"));
    let runs_checkpoint = repo
        .get_github_checkpoint(&events_bridge::store::runs_scope(REPO))
        .unwrap()
        .expect("run checkpoint after completion");
    assert_eq!(runs_checkpoint.etag.as_deref(), Some("runs-v1"));
}

#[tokio::test]
async fn poll_detects_rerun_of_older_completed_run_when_page_one_is_304() {
    let temp = TempDir::new().unwrap();
    let mock = MockGitHub::start().await;
    mock.set_pulls(vec![api_pull(1, false, "2099-11-16T01:00:00Z")], "pulls-v1");
    mock.set_run_pages(
        vec![
            vec![api_run(200, 1, 900, "success", "2099-11-16T02:00:00Z")],
            vec![api_run_full(
                100,
                1,
                901,
                "CI",
                "sha1",
                "completed",
                Some("failure"),
                "2099-11-16T00:00:00Z",
                "2099-11-16T00:00:00Z",
            )],
        ],
        "runs-v1",
    );
    let repo =
        Arc::new(events_bridge::store::Repository::open(temp.path().join("events.db")).unwrap());
    let poller = poller(&mock, repo.clone());

    let baseline = poller.poll_once().await.unwrap();
    assert_eq!(baseline.events, 0, "{baseline:?}");
    assert!(
        repo.get_github_ci_run(REPO, "100", 1)
            .unwrap()
            .is_some_and(|run| run.failure_emitted)
    );

    // The older run is rerun and fails. Page 1 is unchanged, so the list
    // returns 304 and never reaches page 2; the open PR's head SHA still lets
    // the poller re-check the canonical run.
    mock.set_run_by_id(
        100,
        api_run_full(
            100,
            2,
            902,
            "CI",
            "sha1",
            "completed",
            Some("failure"),
            "2099-11-16T00:00:00Z",
            "2099-11-16T03:00:00Z",
        ),
    );
    let summary = poller.poll_once().await.unwrap();
    assert_eq!(summary.events, 1, "{summary:?}");
    assert_eq!(event_kinds(&repo), vec!["github.workflow.failed"]);
    let rerun = repo.get_github_ci_run(REPO, "100", 2).unwrap().unwrap();
    assert_eq!(rerun.conclusion.as_deref(), Some("failure"));
    assert!(rerun.failure_emitted);
    assert!(
        mock.requests()
            .iter()
            .any(|request| request.path.ends_with("/actions/runs/100")),
        "the canonical run is re-checked even though page 1 was 304"
    );
}

#[tokio::test]
async fn attempt_two_does_not_clear_pending_attempt_one_failure() {
    let temp = TempDir::new().unwrap();
    let variable = "EB_TEST_GH_SECRET_ATTEMPT_ONE_PENDING";
    set_secret(variable);
    let hub = TestHub::start(github_config(&temp.path().join("events.db"), variable)).await;

    // A failed attempt 1 job is parked before its workflow_run arrives.
    let (status, value) = send_webhook(
        &hub.base_url,
        "pending-a1",
        "check_run",
        &check_run_payload_full(
            900,
            800,
            "test",
            "completed",
            Some("failure"),
            Some(&format!(
                "https://api.github.com/repos/{REPO}/actions/runs/500/attempts/1"
            )),
            Some("github-actions"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{value}");
    assert_eq!(
        hub.repo()
            .get_github_pending_check(REPO, 900)
            .unwrap()
            .expect("pending attempt 1")
            .parsed_attempt,
        Some(1)
    );

    // Attempt 2 succeeds. It must not clear the pending attempt 1 failure.
    let (status, value) = send_webhook(
        &hub.base_url,
        "wf-a2-success",
        "workflow_run",
        &workflow_payload(500, 2, 802, "success"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{value}");
    assert!(
        hub.repo()
            .get_github_pending_check(REPO, 900)
            .unwrap()
            .is_some(),
        "attempt 2 must not delete the pending attempt 1 check"
    );
    assert!(event_kinds(hub.repo()).is_empty());

    // The late attempt 1 failure still notifies.
    let (status, value) = send_webhook(
        &hub.base_url,
        "wf-a1-failure",
        "workflow_run",
        &workflow_payload(500, 1, 800, "failure"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{value}");
    assert_eq!(event_kinds(hub.repo()), vec!["github.workflow.failed"]);
    assert!(
        hub.repo()
            .get_github_pending_check(REPO, 900)
            .unwrap()
            .is_none()
    );
    hub.stop().await;
}

#[tokio::test]
async fn late_attempt_one_does_not_clear_pending_attempt_two() {
    let temp = TempDir::new().unwrap();
    let variable = "EB_TEST_GH_SECRET_ATTEMPT_TWO_PENDING";
    set_secret(variable);
    let hub = TestHub::start(github_config(&temp.path().join("events.db"), variable)).await;

    // A failed attempt 2 job is parked.
    let (status, value) = send_webhook(
        &hub.base_url,
        "pending-a2",
        "check_run",
        &check_run_payload_full(
            901,
            801,
            "test",
            "completed",
            Some("failure"),
            Some(&format!(
                "https://api.github.com/repos/{REPO}/actions/runs/501/attempts/2"
            )),
            Some("github-actions"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{value}");
    assert!(
        hub.repo()
            .get_github_pending_check(REPO, 901)
            .unwrap()
            .is_some()
    );

    // A late attempt 1 success must not clear the pending attempt 2 check.
    let (status, value) = send_webhook(
        &hub.base_url,
        "wf-a1-late",
        "workflow_run",
        &workflow_payload(501, 1, 800, "success"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{value}");
    assert!(
        hub.repo()
            .get_github_pending_check(REPO, 901)
            .unwrap()
            .is_some(),
        "a late attempt 1 webhook must not delete the pending attempt 2 check"
    );
    assert!(event_kinds(hub.repo()).is_empty());

    // Attempt 2 failure notifies and resolves the pending check.
    let (status, value) = send_webhook(
        &hub.base_url,
        "wf-a2-failure",
        "workflow_run",
        &workflow_payload(501, 2, 801, "failure"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{value}");
    assert_eq!(event_kinds(hub.repo()), vec!["github.workflow.failed"]);
    assert!(
        hub.repo()
            .get_github_pending_check(REPO, 901)
            .unwrap()
            .is_none()
    );
    hub.stop().await;
}

#[tokio::test]
async fn pending_check_without_actions_run_id_is_resolved_on_304() {
    let temp = TempDir::new().unwrap();
    let variable = "EB_TEST_GH_SECRET_PENDING_NO_RUN_ID";
    set_secret(variable);
    let hub = TestHub::start(github_config(&temp.path().join("events.db"), variable)).await;
    let repo = hub.hub.repository().clone();

    let mock = MockGitHub::start().await;
    mock.set_pulls(vec![], "pulls-v1");
    mock.set_runs(vec![], "runs-v1");
    let poller = poller(&mock, repo.clone());
    poller.poll_once().await.unwrap();

    // Only `app.slug` and a check suite: no actions run id in the URL.
    let (status, value) = send_webhook(
        &hub.base_url,
        "pending-suite-only",
        "check_run",
        &check_run_payload_full(
            503,
            803,
            "test",
            "completed",
            Some("failure"),
            None,
            Some("github-actions"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{value}");
    let pending = repo
        .get_github_pending_check(REPO, 503)
        .unwrap()
        .expect("pending suite-only check");
    assert_eq!(pending.actions_run_id, None);
    assert_eq!(pending.check_suite_id, Some(803));

    // Neither an actions run id nor a check suite.
    let mut no_suite = check_run_payload_full(
        504,
        804,
        "test",
        "completed",
        Some("failure"),
        None,
        Some("github-actions"),
    );
    no_suite["check_run"]
        .as_object_mut()
        .unwrap()
        .remove("check_suite");
    let (status, value) =
        send_webhook(&hub.base_url, "pending-no-suite", "check_run", &no_suite).await;
    assert_eq!(status, StatusCode::OK, "{value}");
    let pending = repo
        .get_github_pending_check(REPO, 504)
        .unwrap()
        .expect("pending no-suite check");
    assert_eq!(pending.actions_run_id, None);
    assert_eq!(pending.check_suite_id, None);

    // The list is unchanged (304), but both pending checks are resolvable.
    mock.set_runs(
        vec![
            api_run_full(
                503,
                1,
                803,
                "CI",
                "abc123",
                "completed",
                Some("failure"),
                "2099-11-16T01:00:00Z",
                "2099-11-16T02:00:00Z",
            ),
            api_run_full(
                504,
                1,
                804,
                "CI",
                "abc123",
                "completed",
                Some("failure"),
                "2099-11-16T01:00:00Z",
                "2099-11-16T02:00:00Z",
            ),
        ],
        "runs-v1",
    );
    mock.set_check_run(
        504,
        json!({
            "details_url": format!("https://api.github.com/repos/{REPO}/actions/runs/504/attempts/1"),
            "check_suite": {"id": 804}
        }),
    );
    mock.set_run_attempt(
        504,
        1,
        api_run_full(
            504,
            1,
            804,
            "CI",
            "abc123",
            "completed",
            Some("failure"),
            "2099-11-16T01:00:00Z",
            "2099-11-16T02:00:00Z",
        ),
    );

    let summary = poller.poll_once().await.unwrap();
    assert!(summary.not_modified >= 1, "{summary:?}");
    assert_eq!(summary.events, 2, "{summary:?}");
    assert_eq!(
        event_kinds(&repo),
        vec!["github.workflow.failed", "github.workflow.failed"]
    );
    assert!(repo.get_github_pending_check(REPO, 503).unwrap().is_none());
    assert!(repo.get_github_pending_check(REPO, 504).unwrap().is_none());
    assert!(
        repo.get_github_ci_run(REPO, "503", 1)
            .unwrap()
            .is_some_and(|run| run.failure_emitted)
    );
    assert!(
        repo.get_github_ci_run(REPO, "504", 1)
            .unwrap()
            .is_some_and(|run| run.failure_emitted)
    );
    hub.stop().await;
}

#[tokio::test]
async fn actions_check_run_does_not_overwrite_aggregate_workflow_status() {
    let temp = TempDir::new().unwrap();
    let variable = "EB_TEST_GH_SECRET_CHECK_RUN_AGGREGATE";
    set_secret(variable);
    let hub = TestHub::start(github_config(&temp.path().join("events.db"), variable)).await;

    let mut in_progress = workflow_payload_for(
        REPO,
        600,
        1,
        960,
        "CI",
        "abc123",
        "success",
        "2099-11-16T02:00:00Z",
    );
    in_progress["action"] = json!("in_progress");
    in_progress["workflow_run"]["status"] = json!("in_progress");
    in_progress["workflow_run"]["conclusion"] = Value::Null;
    let (status, value) = send_webhook(
        &hub.base_url,
        "wf-in-progress",
        "workflow_run",
        &in_progress,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{value}");
    let before = hub
        .repo()
        .get_github_ci_run(REPO, "600", 1)
        .unwrap()
        .expect("workflow run");
    assert_eq!(before.status, "in_progress");
    assert_eq!(before.conclusion, None);

    // One job completes successfully. It must not turn the aggregate workflow
    // into `completed/success`.
    let (status, value) = send_webhook(
        &hub.base_url,
        "job-success",
        "check_run",
        &check_run_payload_full(
            950,
            960,
            "test",
            "completed",
            Some("success"),
            Some(&format!(
                "https://api.github.com/repos/{REPO}/actions/runs/600/attempts/1"
            )),
            Some("github-actions"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{value}");

    let after = hub
        .repo()
        .get_github_ci_run(REPO, "600", 1)
        .unwrap()
        .expect("workflow run");
    assert_eq!(after.status, "in_progress");
    assert_eq!(after.conclusion, None);
    assert_eq!(after.url, before.url);
    assert_eq!(after.updated_at, before.updated_at);
    assert!(
        hub.repo()
            .list_active_github_ci_runs(REPO)
            .unwrap()
            .iter()
            .any(|run| run.canonical_run_id == "600" && run.status == "in_progress"),
        "the poller still tracks the workflow as non-completed"
    );

    let service = hub.hub.state().tools.clone();
    let response = service
        .call(
            "local",
            CallToolRequestParams::new("get_github_status")
                .with_arguments(json!({"repository": REPO}).as_object().unwrap().clone()),
        )
        .await
        .unwrap();
    let CallToolResponse::Complete(response) = response else {
        panic!("expected a complete tool response");
    };
    let value = response.into_typed::<Value>().unwrap();
    let run = value["ciRuns"]
        .as_array()
        .unwrap()
        .iter()
        .find(|run| run["canonicalRunId"] == "600")
        .expect("status run");
    assert_eq!(run["status"], "in_progress");
    assert!(run["conclusion"].is_null());
    hub.stop().await;
}

#[tokio::test]
async fn poll_runs_periodic_full_reconcile_applies_to_every_repository() {
    let temp = TempDir::new().unwrap();
    let mock = MockGitHub::start().await;
    mock.set_pulls(vec![], "pulls-v1");
    mock.set_runs(
        vec![api_run(100, 1, 900, "success", "2099-11-16T01:00:00Z")],
        "runs-v1",
    );

    let repo =
        Arc::new(events_bridge::store::Repository::open(temp.path().join("events.db")).unwrap());
    let repo_a = "soramikan/repo-a";
    let repo_b = "soramikan/repo-b";
    let poller = poller_for(&mock, repo.clone(), vec![repo_a.into(), repo_b.into()]);

    // Pass 0 is baseline (full); passes 1..=9 use the stored ETag and get 304.
    for _ in 0..10 {
        poller.poll_once().await.unwrap();
    }
    let before = mock.requests().len();

    // Pass 10 (11th poll) triggers scheduled full reconciliation for every repo.
    poller.poll_once().await.unwrap();
    let pass_requests = &mock.requests()[before..];
    for repository in [repo_a, repo_b] {
        let runs_path = format!("/repos/{repository}/actions/runs");
        assert!(
            pass_requests
                .iter()
                .any(|request| request.path == runs_path && request.if_none_match.is_none()),
            "expected scheduled full reconcile without If-None-Match for {repository}: {pass_requests:?}"
        );
    }
}

#[tokio::test]
async fn pending_check_attempt_two_without_run_id_or_suite_is_cleared_via_check_run_lookup() {
    let temp = TempDir::new().unwrap();
    let variable = "EB_TEST_GH_SECRET_PENDING_ATTEMPT_TWO_NO_SUITE";
    set_secret(variable);
    let hub = TestHub::start(github_config(&temp.path().join("events.db"), variable)).await;
    let repo = hub.hub.repository().clone();

    let mock = MockGitHub::start().await;
    mock.set_pulls(vec![], "pulls-v1");
    mock.set_runs(vec![], "runs-v1");
    let poller = poller(&mock, repo.clone());
    poller.poll_once().await.unwrap();

    // Check run arrives with neither details_url nor check_suite.
    let mut no_suite = check_run_payload_full(
        505,
        805,
        "test",
        "completed",
        Some("failure"),
        None,
        Some("github-actions"),
    );
    no_suite["check_run"]
        .as_object_mut()
        .unwrap()
        .remove("check_suite");
    let (status, value) =
        send_webhook(&hub.base_url, "pending-a2-no-suite", "check_run", &no_suite).await;
    assert_eq!(status, StatusCode::OK, "{value}");
    let pending = repo
        .get_github_pending_check(REPO, 505)
        .unwrap()
        .expect("pending check");
    assert_eq!(pending.actions_run_id, None);
    assert_eq!(pending.parsed_attempt, None);
    assert_eq!(pending.check_suite_id, None);

    // `/check-runs/505` discovers an attempt 2 URL without a suite id, while
    // `/actions/runs` returns 304.
    mock.set_check_run(
        505,
        json!({
            "details_url": format!("https://api.github.com/repos/{REPO}/actions/runs/505/attempts/2")
        }),
    );
    mock.set_run_attempt(
        505,
        2,
        api_run_full(
            505,
            2,
            805,
            "CI",
            "abc123",
            "completed",
            Some("failure"),
            "2099-11-16T01:00:00Z",
            "2099-11-16T02:00:00Z",
        ),
    );

    let summary = poller.poll_once().await.unwrap();
    assert_eq!(summary.events, 1, "{summary:?}");
    assert_eq!(event_kinds(&repo), vec!["github.workflow.failed"]);
    assert!(
        repo.get_github_pending_check(REPO, 505).unwrap().is_none(),
        "resolved attempt 2 check must be deleted from github_pending_checks"
    );

    // A subsequent poll must not re-query `/check-runs/505` or re-emit.
    let before = mock.requests().len();
    let follow_up = poller.poll_once().await.unwrap();
    assert_eq!(follow_up.events, 0, "{follow_up:?}");
    let after_requests = &mock.requests()[before..];
    assert!(
        !after_requests
            .iter()
            .any(|request| request.path.ends_with("/check-runs/505")),
        "resolved pending check must not be polled again: {after_requests:?}"
    );
    hub.stop().await;
}

#[tokio::test]
async fn pending_check_attempt_two_resolved_via_discovered_check_suite_is_cleared() {
    let temp = TempDir::new().unwrap();
    let variable = "EB_TEST_GH_SECRET_PENDING_ATTEMPT_TWO_SUITE_DISCOVERED";
    set_secret(variable);
    let hub = TestHub::start(github_config(&temp.path().join("events.db"), variable)).await;
    let repo = hub.hub.repository().clone();

    let mock = MockGitHub::start().await;
    mock.set_pulls(vec![], "pulls-v1");
    mock.set_runs(vec![], "runs-v1");
    let poller = poller(&mock, repo.clone());
    poller.poll_once().await.unwrap();

    // Check run arrives with neither details_url nor check_suite.
    let mut no_suite = check_run_payload_full(
        506,
        806,
        "test",
        "completed",
        Some("failure"),
        None,
        Some("github-actions"),
    );
    no_suite["check_run"]
        .as_object_mut()
        .unwrap()
        .remove("check_suite");
    let (status, value) = send_webhook(
        &hub.base_url,
        "pending-a2-suite-discovered",
        "check_run",
        &no_suite,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{value}");

    // `/check-runs/506` discovers only `check_suite.id = 806` (no details_url),
    // and the suite resolves to attempt 2 while `/actions/runs` returns 304.
    mock.set_runs(
        vec![api_run_full(
            506,
            2,
            806,
            "CI",
            "abc123",
            "completed",
            Some("failure"),
            "2099-11-16T01:00:00Z",
            "2099-11-16T02:00:00Z",
        )],
        "runs-v1",
    );
    mock.set_check_run(
        506,
        json!({
            "check_suite": {"id": 806}
        }),
    );

    let summary = poller.poll_once().await.unwrap();
    assert_eq!(summary.events, 1, "{summary:?}");
    assert_eq!(event_kinds(&repo), vec!["github.workflow.failed"]);
    assert!(
        repo.get_github_pending_check(REPO, 506).unwrap().is_none(),
        "resolved suite-discovered attempt 2 check must be deleted from github_pending_checks"
    );

    // Subsequent poll neither re-queries `/check-runs/506` nor re-emits.
    let before = mock.requests().len();
    let follow_up = poller.poll_once().await.unwrap();
    assert_eq!(follow_up.events, 0, "{follow_up:?}");
    let after_requests = &mock.requests()[before..];
    assert!(
        !after_requests
            .iter()
            .any(|request| request.path.ends_with("/check-runs/506")),
        "resolved pending check must not be polled again: {after_requests:?}"
    );
    hub.stop().await;
}

// ---------------------------------------------------------------------------
// End-to-end delivery to a subscribed receiver
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct Received {
    headers: HeaderMap,
    body: Vec<u8>,
    signature_valid: bool,
}

#[derive(Clone)]
struct ReceiverState {
    records: Arc<Mutex<Vec<Received>>>,
    hits: Arc<AtomicUsize>,
}

struct MockReceiver {
    url: String,
    state: Arc<ReceiverState>,
    task: JoinHandle<()>,
}

impl MockReceiver {
    async fn start() -> Self {
        let state = Arc::new(ReceiverState {
            records: Arc::new(Mutex::new(Vec::new())),
            hits: Arc::new(AtomicUsize::new(0)),
        });
        let app = Router::new()
            .route("/hook", post(receive))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self {
            url: format!("http://{address}/hook"),
            state,
            task,
        }
    }

    fn records(&self) -> Vec<Received> {
        self.state
            .records
            .lock()
            .unwrap()
            .iter()
            .map(|record| Received {
                headers: record.headers.clone(),
                body: record.body.clone(),
                signature_valid: record.signature_valid,
            })
            .collect()
    }

    fn hits(&self) -> usize {
        self.state.hits.load(Ordering::SeqCst)
    }
}

impl Drop for MockReceiver {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn receive(State(state): State<Arc<ReceiverState>>, request: Request) -> Response {
    let headers = request.headers().clone();
    let body = axum::body::to_bytes(request.into_body(), 1024 * 1024)
        .await
        .expect("receiver body")
        .to_vec();
    let signature_valid = standardwebhooks::Webhook::new(WHSEC)
        .and_then(|webhook| webhook.verify(&body, &headers))
        .is_ok();
    state.hits.fetch_add(1, Ordering::SeqCst);
    state.records.lock().unwrap().push(Received {
        headers,
        body,
        signature_valid,
    });
    StatusCode::OK.into_response()
}

async fn wait_until(label: &str, mut condition: impl FnMut() -> bool) {
    timeout(Duration::from_secs(10), async {
        loop {
            if condition() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {label}"));
}

#[tokio::test]
async fn github_event_is_delivered_with_standard_webhooks_signature() {
    let temp = TempDir::new().unwrap();
    let variable = "EB_TEST_GH_SECRET_E2E";
    set_secret(variable);
    let receiver = MockReceiver::start().await;
    let config = github_config(&temp.path().join("events.db"), variable);
    let hub = TestHub::start_with_dispatcher(config, true).await;

    hub.repo()
        .upsert_subscription(NewSubscription {
            id: "sub_github_e2e".into(),
            principal: "local".into(),
            event_name: "github.pr.merged".into(),
            arguments: json!({"repository": REPO}),
            filter_hash: "hash-github-e2e".into(),
            callback_url: receiver.url.clone(),
            secret: WHSEC.into(),
            refresh_before: None,
        })
        .unwrap();

    let (status, _) = send_webhook(
        &hub.base_url,
        "e2e-merge",
        "pull_request",
        &pull_payload("closed", 30, true),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let records = receiver.state.records.clone();
    wait_until("signed GitHub event delivery", || {
        !records.lock().unwrap().is_empty()
    })
    .await;

    let received = receiver.records().into_iter().next().expect("delivery");
    assert!(received.signature_valid, "Standard Webhooks signature");
    let body: Value = serde_json::from_slice(&received.body).unwrap();
    assert_eq!(body["name"], "github.pr.merged");
    assert_eq!(body["data"]["repository"], REPO);
    assert_eq!(body["data"]["pull_number"], 30);
    event_catalog::validate_payload("github.pr.merged", &body["data"])
        .expect("delivered payload matches the catalog");
    assert_eq!(
        received
            .headers
            .get("webhook-id")
            .and_then(|value| value.to_str().ok()),
        Some(body["eventId"].as_str().unwrap())
    );

    let repository = hub.repo().clone();
    let event_id = body["eventId"].as_str().unwrap().to_string();
    wait_until("delivery state committed", || {
        repository
            .delivery_statuses(&event_id)
            .unwrap()
            .first()
            .is_some_and(|status| status.1 == "delivered")
    })
    .await;
    assert_eq!(receiver.hits(), 1);
    hub.stop().await;
}
