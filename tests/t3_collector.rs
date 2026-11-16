//! T3 Code 0.1.9 collector tests against a real SQLite fixture that mirrors
//! the upstream `statev2.sqlite` tables used by the collector.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use events_bridge::{
    collectors::{T3Collector, T3CollectorSettings},
    event::EventBus,
    store::{NewSubscription, Repository, T3ApprovalQuery},
};
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use tempfile::TempDir;

const ENV: &str = "env-test";

struct Fixture {
    _dir: TempDir,
    path: PathBuf,
    conn: Connection,
    next: i64,
}

impl Fixture {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("statev2.sqlite");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             CREATE TABLE orchestration_events (
                 sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                 event_id TEXT NOT NULL UNIQUE,
                 aggregate_kind TEXT NOT NULL,
                 stream_id TEXT NOT NULL,
                 stream_version INTEGER NOT NULL,
                 event_type TEXT NOT NULL,
                 occurred_at TEXT NOT NULL,
                 command_id TEXT,
                 causation_event_id TEXT,
                 correlation_id TEXT,
                 actor_kind TEXT NOT NULL,
                 payload_json TEXT NOT NULL,
                 metadata_json TEXT NOT NULL
             );
             CREATE TABLE orchestration_v2_projection_runs (
                 run_id TEXT PRIMARY KEY,
                 thread_id TEXT NOT NULL,
                 ordinal INTEGER NOT NULL,
                 provider TEXT NOT NULL DEFAULT 'test',
                 provider_thread_id TEXT,
                 status TEXT NOT NULL,
                 requested_at TEXT NOT NULL,
                 completed_at TEXT,
                 payload_json TEXT NOT NULL,
                 provider_instance_id TEXT
             );
             CREATE TABLE orchestration_v2_projection_threads (
                 thread_id TEXT PRIMARY KEY,
                 project_id TEXT NOT NULL,
                 title TEXT NOT NULL,
                 default_provider TEXT NOT NULL DEFAULT 'test',
                 runtime_mode TEXT NOT NULL DEFAULT 'default',
                 interaction_mode TEXT NOT NULL DEFAULT 'default',
                 active_provider_thread_id TEXT,
                 created_at TEXT NOT NULL,
                 updated_at TEXT NOT NULL,
                 archived_at TEXT,
                 deleted_at TEXT,
                 payload_json TEXT NOT NULL,
                 provider_instance_id TEXT
             );
             CREATE TABLE orchestration_v2_projection_runtime_requests (
                 runtime_request_id TEXT PRIMARY KEY,
                 thread_id TEXT NOT NULL,
                 node_id TEXT NOT NULL,
                 provider_turn_id TEXT,
                 kind TEXT NOT NULL,
                 status TEXT NOT NULL,
                 created_at TEXT NOT NULL,
                 resolved_at TEXT,
                 payload_json TEXT NOT NULL
             );
             CREATE TABLE projection_projects (
                 project_id TEXT PRIMARY KEY,
                 title TEXT NOT NULL,
                 workspace_root TEXT NOT NULL,
                 scripts_json TEXT NOT NULL DEFAULT '[]',
                 created_at TEXT NOT NULL,
                 updated_at TEXT NOT NULL,
                 deleted_at TEXT
             );",
        )
        .unwrap();
        Self {
            _dir: dir,
            path,
            conn,
            next: 0,
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn timestamp(&mut self) -> String {
        self.next += 1;
        let minute = (self.next / 60) % 60;
        let second = self.next % 60;
        format!("2026-11-16T01:{minute:02}:{second:02}.000Z")
    }

    fn insert_event(&mut self, event_type: &str, stream_id: &str, payload: Value) -> i64 {
        let occurred_at = self.timestamp();
        let sequence: i64 = self
            .conn
            .query_row(
                "SELECT COALESCE(MAX(sequence), 0) + 1 FROM orchestration_events",
                [],
                |row| row.get(0),
            )
            .unwrap();
        self.conn
            .execute(
                "INSERT INTO orchestration_events \
                     (event_id, aggregate_kind, stream_id, stream_version, event_type, \
                      occurred_at, actor_kind, payload_json, metadata_json) \
                 VALUES (?1, 'thread', ?2, ?3, ?4, ?5, 'user', ?6, '{}')",
                params![
                    format!("upstream-{sequence}"),
                    stream_id,
                    sequence,
                    event_type,
                    occurred_at,
                    payload.to_string()
                ],
            )
            .unwrap();
        sequence
    }

    fn seed_project_thread(&mut self) {
        self.insert_event(
            "project.created",
            "p1",
            json!({
                "projectId": "p1",
                "title": "Demo project",
                "workspaceRoot": "/repo/demo",
                "createdAt": "2026-11-16T01:00:00.000Z",
                "updatedAt": "2026-11-16T01:00:00.000Z"
            }),
        );
        self.insert_event(
            "thread.created",
            "t1",
            json!({
                "id": "t1",
                "projectId": "p1",
                "title": "Demo thread",
                "branch": "main",
                "createdAt": "2026-11-16T01:00:01.000Z",
                "updatedAt": "2026-11-16T01:00:01.000Z",
                "deletedAt": null
            }),
        );
        self.conn
            .execute(
                "INSERT INTO projection_projects \
                     (project_id, title, workspace_root, scripts_json, created_at, updated_at) \
                 VALUES ('p1', 'Demo project', '/repo/demo', '[]', \
                         '2026-11-16T01:00:00.000Z', '2026-11-16T01:00:00.000Z')",
                [],
            )
            .unwrap();
        self.conn
            .execute(
                "INSERT INTO orchestration_v2_projection_threads \
                     (thread_id, project_id, title, created_at, updated_at, payload_json) \
                 VALUES ('t1', 'p1', 'Demo thread', '2026-11-16T01:00:01.000Z', \
                         '2026-11-16T01:00:01.000Z', ?1)",
                params![json!({"id": "t1", "branch": "main"}).to_string()],
            )
            .unwrap();
    }

    fn insert_run_projection(&self, run_id: &str, ordinal: i64, status: &str, payload: Value) {
        self.conn
            .execute(
                "INSERT INTO orchestration_v2_projection_runs \
                     (run_id, thread_id, ordinal, status, requested_at, completed_at, \
                      payload_json, provider_instance_id) \
                 VALUES (?1, 't1', ?2, ?3, '2026-11-16T01:00:02.000Z', ?4, ?5, 'test-provider')",
                params![
                    run_id,
                    ordinal,
                    status,
                    (status == "completed")
                        .then_some("2026-11-16T01:00:09.000Z")
                        .map(str::to_string),
                    payload.to_string()
                ],
            )
            .unwrap();
    }

    fn seed_completed_run(&mut self) {
        self.insert_event(
            "run.created",
            "t1",
            json!({
                "id": "run-old",
                "threadId": "t1",
                "ordinal": 1,
                "providerInstanceId": "test-provider",
                "status": "running",
                "requestedAt": "2026-11-16T01:00:02.000Z"
            }),
        );
        self.insert_event(
            "run.updated",
            "t1",
            json!({
                "id": "run-old",
                "threadId": "t1",
                "ordinal": 1,
                "providerInstanceId": "test-provider",
                "status": "completed",
                "requestedAt": "2026-11-16T01:00:02.000Z",
                "startedAt": "2026-11-16T01:00:03.000Z",
                "completedAt": "2026-11-16T01:00:09.000Z",
                "checkpointId": "checkpoint:1"
            }),
        );
        self.insert_run_projection(
            "run-old",
            1,
            "completed",
            json!({
                "id": "run-old",
                "threadId": "t1",
                "ordinal": 1,
                "status": "completed",
                "completedAt": "2026-11-16T01:00:09.000Z",
                "checkpointId": "checkpoint:1"
            }),
        );
    }
}

fn bridge_repo(dir: &TempDir) -> Repository {
    Repository::open(dir.path().join("bridge.sqlite")).unwrap()
}

fn collector(fixture: &Fixture, repo: &Arc<Repository>) -> T3Collector {
    T3Collector::new(
        T3CollectorSettings::for_tests(fixture.path(), ENV),
        repo.clone(),
        EventBus::new(),
    )
    .unwrap()
}

fn subscribe(repo: &Repository) {
    repo.upsert_subscription(NewSubscription {
        id: "sub_completed".into(),
        principal: "local".into(),
        event_name: "t3.run.completed".into(),
        arguments: json!({"environment_id": ENV}),
        filter_hash: "hash".into(),
        callback_url: "https://receiver.example.com/hook".into(),
        secret: "whsec_C2FVsBQIhrscChlQIMV+b5sSYspob7oD".into(),
        refresh_before: None,
    })
    .unwrap();
}

fn event_kinds(repo: &Repository) -> Vec<String> {
    repo.list_events(&events_bridge::store::EventQuery {
        limit: 100,
        ..Default::default()
    })
    .unwrap()
    .into_iter()
    .map(|event| event.kind)
    .collect()
}

#[test]
fn provider_turn_and_attempt_completion_do_not_complete_a_run() {
    let mut fixture = Fixture::new();
    fixture.seed_project_thread();
    fixture.seed_completed_run();
    let dir = TempDir::new().unwrap();
    let repo = Arc::new(bridge_repo(&dir));
    let collector = collector(&fixture, &repo);

    // The initial snapshot must not deliver the already-completed run.
    assert!(event_kinds(&repo).is_empty());
    assert_eq!(repo.pending_delivery_count().unwrap(), 0);

    fixture.insert_event(
        "node.updated",
        "t1",
        json!({
            "id": "node-r1", "threadId": "t1", "runId": "run-r1",
            "kind": "root_turn", "status": "running"
        }),
    );
    fixture.insert_event(
        "run.created",
        "t1",
        json!({
            "id": "run-r1", "threadId": "t1", "ordinal": 2,
            "status": "running", "requestedAt": "2026-11-16T01:10:00.000Z"
        }),
    );
    fixture.insert_event(
        "provider-turn.updated",
        "t1",
        json!({
            "id": "turn-1", "nodeId": "node-r1", "runAttemptId": "attempt-1",
            "status": "completed", "completedAt": "2026-11-16T01:11:00.000Z"
        }),
    );
    fixture.insert_event(
        "run-attempt.updated",
        "t1",
        json!({
            "id": "attempt-1", "runId": "run-r1", "status": "completed",
            "completedAt": "2026-11-16T01:11:00.000Z"
        }),
    );

    let first = collector.collect_once().unwrap();
    assert_eq!(first.processed, 4);
    assert_eq!(first.emitted, 0, "turn/attempt completion must not emit");
    assert!(event_kinds(&repo).is_empty());

    let detail = repo.get_t3_run("run-r1", Some(ENV)).unwrap().unwrap();
    assert_eq!(detail.run.status, "running");
    assert_eq!(detail.run.last_turn_status.as_deref(), Some("completed"));

    fixture.insert_event(
        "run.updated",
        "t1",
        json!({
            "id": "run-r1", "threadId": "t1", "ordinal": 2, "status": "completed",
            "requestedAt": "2026-11-16T01:10:00.000Z",
            "startedAt": "2026-11-16T01:10:10.000Z",
            "completedAt": "2026-11-16T01:12:00.000Z", "checkpointId": "checkpoint:2"
        }),
    );
    let second = collector.collect_once().unwrap();
    assert_eq!(second.processed, 1);
    assert_eq!(event_kinds(&repo), vec!["t3.run.completed"]);

    let events = repo
        .list_events(&events_bridge::store::EventQuery {
            limit: 10,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(events[0].payload["run_id"], "run-r1");
    assert_eq!(events[0].payload["project_id"], "p1");
    assert!(
        events[0].payload.get("url").is_none(),
        "url requires collectors.t3.t3_web_base_url"
    );

    // Replaying the same run.updated is idempotent.
    collector.collect_once().unwrap();
    assert_eq!(event_kinds(&repo).len(), 1);
}

#[test]
fn failed_run_emits_once_and_exposes_the_error() {
    let mut fixture = Fixture::new();
    fixture.seed_project_thread();
    let dir = TempDir::new().unwrap();
    let repo = Arc::new(bridge_repo(&dir));
    let collector = collector(&fixture, &repo);

    fixture.insert_event(
        "run.created",
        "t1",
        json!({
            "id": "run-fail", "threadId": "t1", "ordinal": 1, "status": "running",
            "requestedAt": "2026-11-16T02:00:00.000Z"
        }),
    );
    fixture.insert_event(
        "node.updated",
        "t1",
        json!({
            "id": "node-fail", "threadId": "t1", "runId": "run-fail",
            "kind": "root_turn", "status": "failed"
        }),
    );
    fixture.insert_event(
        "turn-item.updated",
        "t1",
        json!({
            "id": "item-fail", "runId": "run-fail", "nodeId": "node-fail",
            "status": "failed", "type": "error", "title": "Provider error",
            "failure": {"class": "provider_error", "message": "no API key for provider route"}
        }),
    );
    fixture.insert_event(
        "run.updated",
        "t1",
        json!({
            "id": "run-fail", "threadId": "t1", "ordinal": 1, "status": "failed",
            "requestedAt": "2026-11-16T02:00:00.000Z",
            "completedAt": "2026-11-16T02:01:00.000Z"
        }),
    );

    collector.collect_once().unwrap();
    assert_eq!(event_kinds(&repo), vec!["t3.run.failed"]);

    let events = repo
        .list_events(&events_bridge::store::EventQuery {
            kind: Some("t3.run.failed".into()),
            limit: 10,
            ..Default::default()
        })
        .unwrap();
    assert!(
        events[0].payload["error"]
            .as_str()
            .unwrap()
            .contains("no API key"),
        "{}",
        events[0].payload
    );

    let detail = repo.get_t3_run("run-fail", Some(ENV)).unwrap().unwrap();
    assert_eq!(detail.run.status, "failed");
    assert!(detail.run.error.as_deref().unwrap().contains("no API key"));
}

#[test]
fn approvals_emit_on_pending_and_leave_the_pending_list_when_resolved() {
    let mut fixture = Fixture::new();
    fixture.seed_project_thread();
    let dir = TempDir::new().unwrap();
    let repo = Arc::new(bridge_repo(&dir));
    let collector = collector(&fixture, &repo);

    fixture.insert_event(
        "run.created",
        "t1",
        json!({
            "id": "run-approval", "threadId": "t1", "ordinal": 1, "status": "running",
            "requestedAt": "2026-11-16T03:00:00.000Z"
        }),
    );
    fixture.insert_event(
        "node.updated",
        "t1",
        json!({
            "id": "node-approval", "threadId": "t1", "runId": "run-approval",
            "kind": "tool_call", "status": "waiting"
        }),
    );
    fixture.insert_event(
        "runtime-request.updated",
        "t1",
        json!({
            "id": "approval-1", "nodeId": "node-approval", "kind": "command",
            "status": "pending", "createdAt": "2026-11-16T03:00:05.000Z",
            "summary": "Run a command"
        }),
    );

    collector.collect_once().unwrap();
    assert_eq!(event_kinds(&repo), vec!["t3.approval.required"]);

    let pending = repo
        .list_t3_approvals(&T3ApprovalQuery {
            environment_id: Some(ENV.into()),
            status: Some("pending".into()),
            limit: 10,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].approval_id, "approval-1");
    assert_eq!(pending[0].run_id, "run-approval");
    assert_eq!(pending[0].thread_id, "t1");

    let detail = repo.get_t3_run("run-approval", Some(ENV)).unwrap().unwrap();
    assert_eq!(detail.pending_approvals_count, 1);

    fixture.insert_event(
        "runtime-request.updated",
        "t1",
        json!({
            "id": "approval-1", "nodeId": "node-approval", "kind": "command",
            "status": "resolved", "createdAt": "2026-11-16T03:00:05.000Z",
            "resolvedAt": "2026-11-16T03:00:30.000Z", "decision": "allow"
        }),
    );
    collector.collect_once().unwrap();

    let pending = repo
        .list_t3_approvals(&T3ApprovalQuery {
            environment_id: Some(ENV.into()),
            status: Some("pending".into()),
            limit: 10,
            ..Default::default()
        })
        .unwrap();
    assert!(pending.is_empty());

    let all = repo
        .list_t3_approvals(&T3ApprovalQuery {
            environment_id: Some(ENV.into()),
            status: Some("all".into()),
            limit: 10,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].status, "resolved");
    assert_eq!(all[0].decision.as_deref(), Some("allow"));
    assert_eq!(event_kinds(&repo), vec!["t3.approval.required"]);
}

#[test]
fn restart_resumes_from_the_saved_cursor_without_redelivery() {
    let mut fixture = Fixture::new();
    fixture.seed_project_thread();
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("bridge.sqlite");

    let repo = Arc::new(Repository::open(&db_path).unwrap());
    subscribe(&repo);
    let first_collector = T3Collector::new(
        T3CollectorSettings::for_tests(fixture.path(), ENV),
        repo.clone(),
        EventBus::new(),
    )
    .unwrap();

    fixture.insert_event(
        "run.created",
        "t1",
        json!({
            "id": "run-1", "threadId": "t1", "ordinal": 1, "status": "running",
            "requestedAt": "2026-11-16T04:00:00.000Z"
        }),
    );
    fixture.insert_event(
        "run.updated",
        "t1",
        json!({
            "id": "run-1", "threadId": "t1", "ordinal": 1, "status": "completed",
            "completedAt": "2026-11-16T04:01:00.000Z"
        }),
    );
    first_collector.collect_once().unwrap();
    assert_eq!(event_kinds(&repo), vec!["t3.run.completed"]);
    assert_eq!(repo.pending_delivery_count().unwrap(), 1);
    let first_cursor = repo.get_t3_cursor(ENV).unwrap().unwrap();

    drop(first_collector);
    drop(repo);

    fixture.insert_event(
        "run.created",
        "t1",
        json!({
            "id": "run-2", "threadId": "t1", "ordinal": 2, "status": "running",
            "requestedAt": "2026-11-16T04:10:00.000Z"
        }),
    );
    fixture.insert_event(
        "run.updated",
        "t1",
        json!({
            "id": "run-2", "threadId": "t1", "ordinal": 2, "status": "completed",
            "completedAt": "2026-11-16T04:11:00.000Z"
        }),
    );

    let repo = Arc::new(Repository::open(&db_path).unwrap());
    let restarted = T3Collector::new(
        T3CollectorSettings::for_tests(fixture.path(), ENV),
        repo.clone(),
        EventBus::new(),
    )
    .unwrap();
    let summary = restarted.collect_once().unwrap();
    assert_eq!(summary.processed, 2);
    assert_eq!(summary.emitted, 1);

    let events = repo
        .list_events(&events_bridge::store::EventQuery {
            limit: 10,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(events.len(), 2);
    assert!(events.iter().all(|event| event.kind == "t3.run.completed"));
    assert!(
        events
            .iter()
            .any(|event| event.payload["run_id"] == "run-1")
    );
    assert!(
        events
            .iter()
            .any(|event| event.payload["run_id"] == "run-2")
    );

    // One delivery for each completion, and none re-created for run-1.
    assert_eq!(repo.pending_delivery_count().unwrap(), 2);
    let cursor = repo.get_t3_cursor(ENV).unwrap().unwrap();
    assert!(cursor > first_cursor);
    assert_eq!(
        cursor,
        fixture
            .conn
            .query_row(
                "SELECT MAX(sequence) FROM orchestration_events",
                [],
                |row| { row.get::<_, i64>(0) }
            )
            .unwrap()
    );
}

#[test]
fn configured_web_base_url_adds_a_thread_deep_link() {
    let mut fixture = Fixture::new();
    fixture.seed_project_thread();
    let dir = TempDir::new().unwrap();
    let repo = Arc::new(bridge_repo(&dir));
    let collector = T3Collector::new(
        T3CollectorSettings::for_tests(fixture.path(), ENV)
            .with_web_base_url("https://t3.example.com/"),
        repo.clone(),
        EventBus::new(),
    )
    .unwrap();

    fixture.insert_event(
        "run.created",
        "t1",
        json!({
            "id": "run-url", "threadId": "t1", "ordinal": 1, "status": "running",
            "requestedAt": "2026-11-16T05:00:00.000Z"
        }),
    );
    fixture.insert_event(
        "run.updated",
        "t1",
        json!({
            "id": "run-url", "threadId": "t1", "ordinal": 1, "status": "completed",
            "completedAt": "2026-11-16T05:01:00.000Z"
        }),
    );
    collector.collect_once().unwrap();

    let events = repo
        .list_events(&events_bridge::store::EventQuery {
            limit: 10,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(
        events[0].payload["url"],
        "https://t3.example.com/threads/t1"
    );
}

#[test]
fn snapshot_watermarks_without_emitting_completed_runs() {
    let mut fixture = Fixture::new();
    fixture.seed_project_thread();
    fixture.seed_completed_run();
    let dir = TempDir::new().unwrap();
    let repo = Arc::new(bridge_repo(&dir));
    subscribe(&repo);

    let collector = collector(&fixture, &repo);
    assert!(event_kinds(&repo).is_empty());
    assert_eq!(repo.pending_delivery_count().unwrap(), 0);
    let max: i64 = fixture
        .conn
        .query_row(
            "SELECT MAX(sequence) FROM orchestration_events",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(repo.get_t3_cursor(ENV).unwrap(), Some(max));

    let run = repo.get_t3_run("run-old", Some(ENV)).unwrap().unwrap();
    assert_eq!(run.run.status, "completed");

    // A new event after the watermark is still picked up.
    fixture.insert_event(
        "run.updated",
        "t1",
        json!({
            "id": "run-old", "threadId": "t1", "ordinal": 1, "status": "completed",
            "completedAt": "2026-11-16T01:00:10.000Z"
        }),
    );
    collector.collect_once().unwrap();
    // Already completed in the materialized state, so no duplicate event.
    assert!(event_kinds(&repo).is_empty());
}

#[test]
fn null_reference_fields_do_not_stall_collection() {
    let mut fixture = Fixture::new();
    fixture.seed_project_thread();
    let dir = TempDir::new().unwrap();
    let repo = Arc::new(bridge_repo(&dir));
    let collector = collector(&fixture, &repo);

    // Node exists with explicit JSON null for runId and threadId.
    fixture.insert_event(
        "node.updated",
        "t1",
        json!({
            "id": "node-null",
            "threadId": null,
            "runId": null,
            "kind": "approval_request",
            "status": "waiting"
        }),
    );
    fixture.insert_event(
        "runtime-request.updated",
        "t1",
        json!({
            "id": "req-null-ref",
            "nodeId": "node-null",
            "kind": "command",
            "status": "pending",
            "summary": "Approve command with partial metadata"
        }),
    );
    fixture.insert_event(
        "run.updated",
        "t1",
        json!({
            "id": "run-after-null",
            "threadId": "t1",
            "ordinal": 2,
            "status": "completed",
            "completedAt": "2026-11-16T06:00:00.000Z"
        }),
    );

    let summary = collector.collect_once().unwrap();
    assert_eq!(summary.processed, 3);
    assert_eq!(
        event_kinds(&repo),
        vec!["t3.approval.required", "t3.run.completed"]
    );
}

#[test]
fn replaced_db_with_regressed_sequence_recovers_via_resnapshot() {
    let mut fixture = Fixture::new();
    fixture.seed_project_thread();
    fixture.seed_completed_run();
    let dir = TempDir::new().unwrap();
    let repo = Arc::new(bridge_repo(&dir));
    let collector = collector(&fixture, &repo);

    // Advance cursor higher than what the replacement DB will have.
    for i in 0..5 {
        fixture.insert_event("thread.visited", "t1", json!({"id": "t1", "ordinal": i}));
    }
    collector.collect_once().unwrap();
    let high_cursor = repo.get_t3_cursor(ENV).unwrap().unwrap();
    assert!(high_cursor >= 8);

    // Build a fresh replacement T3 DB in a new file (new inode) with smaller sequence.
    let mut replacement = Fixture::new();
    replacement.seed_project_thread();
    replacement.insert_run_projection(
        "run-restored",
        1,
        "completed",
        json!({
            "id": "run-restored",
            "threadId": "t1",
            "ordinal": 1,
            "status": "completed",
            "completedAt": "2026-11-16T06:10:00.000Z"
        }),
    );
    let restored_max = replacement
        .conn
        .query_row(
            "SELECT MAX(sequence) FROM orchestration_events",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap();
    assert!(restored_max < high_cursor);
    replacement
        .conn
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .unwrap();
    let replacement_path = replacement.path().to_path_buf();
    drop(replacement.conn);

    // Atomically replace statev2.sqlite (remove stale WAL/SHM too).
    let wal_path = fixture.path().with_file_name("statev2.sqlite-wal");
    let shm_path = fixture.path().with_file_name("statev2.sqlite-shm");
    let _ = std::fs::remove_file(&wal_path);
    let _ = std::fs::remove_file(&shm_path);
    std::fs::rename(&replacement_path, fixture.path()).unwrap();

    // First pass detects new inode + regressed sequence and re-snapshots.
    let resnap = collector.collect_once().unwrap();
    assert_eq!(resnap.processed, 0);
    assert_eq!(repo.get_t3_cursor(ENV).unwrap(), Some(restored_max));
    assert!(
        repo.get_t3_run("run-restored", Some(ENV))
            .unwrap()
            .is_some()
    );

    // Subsequent events appended to the replaced DB are collected normally.
    let conn = Connection::open(fixture.path()).unwrap();
    conn.execute(
        "INSERT INTO orchestration_events \
             (event_id, aggregate_kind, stream_id, stream_version, event_type, \
              occurred_at, actor_kind, payload_json, metadata_json) \
         VALUES ('upstream-new', 'thread', 't1', 99, 'run.updated', \
                 '2026-11-16T06:20:00.000Z', 'user', ?1, '{}')",
        params![
            json!({
                "id": "run-after-restore",
                "threadId": "t1",
                "ordinal": 2,
                "status": "completed",
                "completedAt": "2026-11-16T06:20:00.000Z"
            })
            .to_string()
        ],
    )
    .unwrap();

    let after = collector.collect_once().unwrap();
    assert_eq!(after.processed, 1);
    assert_eq!(event_kinds(&repo), vec!["t3.run.completed"]);
}

#[test]
fn oversized_approval_summary_is_bounded_for_webhook_delivery() {
    let mut fixture = Fixture::new();
    fixture.seed_project_thread();
    let dir = TempDir::new().unwrap();
    let repo = Arc::new(bridge_repo(&dir));
    let collector = collector(&fixture, &repo);

    // Multi-byte UTF-8 and JSON-escaped characters exceeding 256 KiB if unclipped.
    let huge_summary = format!("{}\n{}", "あ\"\\".repeat(60_000), "tail");
    assert!(huge_summary.len() > 256 * 1024);

    fixture.insert_event(
        "runtime-request.updated",
        "t1",
        json!({
            "id": "req-huge",
            "threadId": "t1",
            "kind": "command",
            "status": "pending",
            "summary": huge_summary
        }),
    );
    let summary = collector.collect_once().unwrap();
    assert_eq!(summary.emitted, 1);

    let events = repo
        .list_events(&events_bridge::store::EventQuery {
            kind: Some("t3.approval.required".into()),
            limit: 10,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(events.len(), 1);
    let serialized = serde_json::to_vec(&events[0].payload).unwrap();
    assert!(
        serialized.len() <= 16 * 1024,
        "webhook payload must stay well under 256 KiB, got {}",
        serialized.len()
    );
    assert!(
        events[0].payload["summary"]
            .as_str()
            .unwrap()
            .ends_with("...")
    );

    // Pull tool still retains the full unclipped summary.
    let approvals = repo
        .list_t3_approvals(&T3ApprovalQuery {
            environment_id: Some(ENV.into()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(approvals.len(), 1);
    assert!(approvals[0].summary.as_deref().unwrap().ends_with("tail"));
}

#[test]
fn enriched_payload_fields_resolve_names_and_bound_error_excerpts() {
    let mut fixture = Fixture::new();
    fixture.seed_project_thread();
    let dir = TempDir::new().unwrap();
    let repo = Arc::new(bridge_repo(&dir));
    let mut settings = T3CollectorSettings::for_tests(fixture.path(), ENV);
    settings.error_excerpt_max_chars = 20;
    let collector = T3Collector::new(settings, repo.clone(), EventBus::new()).unwrap();

    fixture.insert_event(
        "run.created",
        "t1",
        json!({
            "id": "run-ok", "threadId": "t1", "ordinal": 1, "status": "running",
            "requestedAt": "2026-11-16T05:00:00.000Z"
        }),
    );
    fixture.insert_event(
        "run.updated",
        "t1",
        json!({
            "id": "run-ok", "threadId": "t1", "ordinal": 1, "status": "completed",
            "requestedAt": "2026-11-16T05:00:00.000Z",
            "completedAt": "2026-11-16T05:01:00.000Z"
        }),
    );
    let long_error = format!(
        "Provider error\nno API key for the selected provider route\n{}",
        "detail ".repeat(20)
    );
    fixture.insert_event(
        "run.created",
        "t1",
        json!({
            "id": "run-bad", "threadId": "t1", "ordinal": 2, "status": "running",
            "requestedAt": "2026-11-16T05:02:00.000Z"
        }),
    );
    fixture.insert_event(
        "run.updated",
        "t1",
        json!({
            "id": "run-bad", "threadId": "t1", "ordinal": 2, "status": "failed",
            "requestedAt": "2026-11-16T05:02:00.000Z",
            "completedAt": "2026-11-16T05:03:00.000Z",
            "error": long_error
        }),
    );
    fixture.insert_event(
        "runtime-request.updated",
        "t1",
        json!({
            "id": "approval-enriched", "threadId": "t1", "runId": "run-bad",
            "kind": "command", "status": "pending",
            "createdAt": "2026-11-16T05:04:00.000Z",
            "summary": "Run a command\nwith approval"
        }),
    );

    collector.collect_once().unwrap();

    let completed = repo
        .list_events(&events_bridge::store::EventQuery {
            kind: Some("t3.run.completed".into()),
            limit: 10,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(completed.len(), 1);
    let payload = &completed[0].payload;
    assert_eq!(
        payload["title"],
        "[Demo project] Run #1 completed: Demo thread"
    );
    assert_eq!(payload["project_name"], "Demo project");
    assert_eq!(payload["thread_title"], "Demo thread");
    assert_eq!(payload["severity"], "normal");
    assert_eq!(payload["requires_action"], false);
    assert!(payload.get("error_excerpt").is_none());

    let failed = repo
        .list_events(&events_bridge::store::EventQuery {
            kind: Some("t3.run.failed".into()),
            limit: 10,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(failed.len(), 1);
    let payload = &failed[0].payload;
    assert_eq!(
        payload["title"],
        "[Demo project] Run #2 failed: Demo thread"
    );
    assert_eq!(payload["project_name"], "Demo project");
    assert_eq!(payload["thread_title"], "Demo thread");
    assert_eq!(payload["severity"], "high");
    assert_eq!(payload["requires_action"], true);
    let excerpt = payload["error_excerpt"].as_str().unwrap();
    assert!(excerpt.chars().count() <= 20, "{excerpt:?}");
    assert!(excerpt.ends_with("..."), "{excerpt:?}");
    assert!(!excerpt.contains('\n'), "{excerpt:?}");

    let approvals = repo
        .list_events(&events_bridge::store::EventQuery {
            kind: Some("t3.approval.required".into()),
            limit: 10,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(approvals.len(), 1);
    let payload = &approvals[0].payload;
    assert_eq!(
        payload["title"],
        "[Demo project] Approval required: Run a command with approval"
    );
    assert_eq!(payload["project_name"], "Demo project");
    assert_eq!(payload["thread_title"], "Demo thread");
    assert_eq!(payload["severity"], "high");
    assert_eq!(payload["requires_action"], true);
}
