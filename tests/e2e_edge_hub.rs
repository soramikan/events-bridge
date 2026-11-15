//! Phase 4 end-to-end tests: Edge -> Hub authenticated T3 forwarding, local
//! collectors, GitHub webhook ingestion, signed webhook delivery, restart
//! recovery, 410 terminalization, replay rejection, and the stdio surface.
//!
//! The tests use real loopback HTTP servers and real SQLite fixtures. The
//! permissive callback policy is only used through `Hub::with_policy` /
//! `stdio::serve_with_io`, never through configuration or the CLI.

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, Once,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::{
    Json, Router,
    extract::{Path as AxumPath, Request, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use events_bridge::{
    config::Config,
    delivery::verification::CallbackPolicy,
    edge_protocol::{
        EdgeT3IngestRequest, HEADER_EDGE_ID, HEADER_EDGE_NONCE, HEADER_EDGE_SIGNATURE,
        HEADER_EDGE_TIMESTAMP, sign,
    },
    hub::Hub,
    store::{
        NewEvent, Repository, T3Approval, T3Project, T3Run, T3Snapshot, T3Thread, T3WriteBatch,
    },
    transport::edge::Edge,
};
use hmac::{Hmac, Mac};
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use sha2::Sha256;
use tempfile::TempDir;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream},
    task::JoinHandle,
    time::timeout,
};
use tokio_util::sync::CancellationToken;

const EDGE_SECRET_ENV: &str = "EVENTS_BRIDGE_E2E_EDGE_SECRET";
const EDGE_SECRET: &str = "e2e-edge-shared-secret";
const GITHUB_SECRET_ENV: &str = "EVENTS_BRIDGE_E2E_GITHUB_SECRET";
const GITHUB_SECRET: &str = "e2e-github-webhook-secret";
const INVALID_GITHUB_TOKEN_ENV: &str = "EVENTS_BRIDGE_E2E_INVALID_GITHUB_TOKEN";
const WEBHOOK_SECRET: &str = "whsec_C2FVsBQIhrscChlQIMV+b5sSYspob7oD";
const REPOSITORY: &str = "soramikan/events-bridge";

static ENV_INIT: Once = Once::new();

fn init_env() {
    ENV_INIT.call_once(|| {
        // SAFETY: the values are constant for the whole test binary and are
        // installed once before any test reads them.
        unsafe {
            std::env::set_var(EDGE_SECRET_ENV, EDGE_SECRET);
            std::env::set_var(GITHUB_SECRET_ENV, GITHUB_SECRET);
            std::env::set_var(INVALID_GITHUB_TOKEN_ENV, "bad\ntoken");
        }
    });
}

// ---------------------------------------------------------------------------
// T3 SQLite fixture
// ---------------------------------------------------------------------------

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
        format!("2026-11-16T02:{minute:02}:{second:02}.000Z")
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
                "createdAt": "2026-11-16T02:00:00.000Z",
                "updatedAt": "2026-11-16T02:00:00.000Z"
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
                "createdAt": "2026-11-16T02:00:01.000Z",
                "updatedAt": "2026-11-16T02:00:01.000Z",
                "deletedAt": null
            }),
        );
        self.conn
            .execute(
                "INSERT INTO projection_projects \
                     (project_id, title, workspace_root, scripts_json, created_at, updated_at) \
                 VALUES ('p1', 'Demo project', '/repo/demo', '[]', \
                         '2026-11-16T02:00:00.000Z', '2026-11-16T02:00:00.000Z')",
                [],
            )
            .unwrap();
        self.conn
            .execute(
                "INSERT INTO orchestration_v2_projection_threads \
                     (thread_id, project_id, title, created_at, updated_at, payload_json) \
                 VALUES ('t1', 'p1', 'Demo thread', '2026-11-16T02:00:01.000Z', \
                         '2026-11-16T02:00:01.000Z', ?1)",
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
                 VALUES (?1, 't1', ?2, ?3, '2026-11-16T02:00:02.000Z', ?4, ?5, 'test-provider')",
                params![
                    run_id,
                    ordinal,
                    status,
                    (status == "completed")
                        .then_some("2026-11-16T02:00:09.000Z")
                        .map(str::to_string),
                    payload.to_string()
                ],
            )
            .unwrap();
    }

    fn seed_existing_completed_run(&mut self) {
        self.insert_event(
            "run.created",
            "t1",
            json!({
                "id": "run-old",
                "threadId": "t1",
                "ordinal": 1,
                "providerInstanceId": "test-provider",
                "status": "running",
                "requestedAt": "2026-11-16T02:00:02.000Z"
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
                "requestedAt": "2026-11-16T02:00:02.000Z",
                "startedAt": "2026-11-16T02:00:03.000Z",
                "completedAt": "2026-11-16T02:00:09.000Z",
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
                "completedAt": "2026-11-16T02:00:09.000Z",
                "checkpointId": "checkpoint:1"
            }),
        );
    }

    fn seed_failed_run_with_error(&mut self, run_id: &str, error: &str) {
        self.insert_event(
            "run.updated",
            "t1",
            json!({
                "id": run_id,
                "threadId": "t1",
                "ordinal": 1,
                "providerInstanceId": "test-provider",
                "status": "failed",
                "error": error,
                "requestedAt": "2026-11-16T02:00:02.000Z",
                "startedAt": "2026-11-16T02:00:03.000Z",
                "completedAt": "2026-11-16T02:00:09.000Z"
            }),
        );
        self.insert_run_projection(
            run_id,
            1,
            "failed",
            json!({
                "id": run_id,
                "threadId": "t1",
                "ordinal": 1,
                "status": "failed",
                "error": error,
                "completedAt": "2026-11-16T02:00:09.000Z"
            }),
        );
    }

    fn emit_completed_run(&mut self, run_id: &str, ordinal: i64) {
        self.insert_event(
            "run.created",
            "t1",
            json!({
                "id": run_id,
                "threadId": "t1",
                "ordinal": ordinal,
                "providerInstanceId": "test-provider",
                "status": "running",
                "requestedAt": "2026-11-16T02:10:00.000Z"
            }),
        );
        self.insert_event(
            "run.updated",
            "t1",
            json!({
                "id": run_id,
                "threadId": "t1",
                "ordinal": ordinal,
                "providerInstanceId": "test-provider",
                "status": "completed",
                "requestedAt": "2026-11-16T02:10:00.000Z",
                "startedAt": "2026-11-16T02:10:01.000Z",
                "completedAt": "2026-11-16T02:10:09.000Z",
                "checkpointId": "checkpoint:2"
            }),
        );
        self.insert_run_projection(
            run_id,
            ordinal,
            "completed",
            json!({
                "id": run_id,
                "threadId": "t1",
                "ordinal": ordinal,
                "status": "completed",
                "completedAt": "2026-11-16T02:10:09.000Z",
                "checkpointId": "checkpoint:2"
            }),
        );
    }

    fn emit_pending_approval(&mut self, approval_id: &str, run_id: &str) {
        self.insert_event(
            "runtime-request.updated",
            "t1",
            json!({
                "id": approval_id,
                "threadId": "t1",
                "runId": run_id,
                "nodeId": "node-1",
                "kind": "command",
                "status": "pending",
                "summary": "Approve the test command",
                "createdAt": "2026-11-16T02:11:00.000Z"
            }),
        );
        self.conn
            .execute(
                "INSERT INTO orchestration_v2_projection_runtime_requests \
                     (runtime_request_id, thread_id, node_id, kind, status, created_at, \
                      payload_json) \
                 VALUES (?1, 't1', 'node-1', 'command', 'pending', \
                         '2026-11-16T02:11:00.000Z', ?2)",
                params![
                    approval_id,
                    json!({
                        "id": approval_id,
                        "threadId": "t1",
                        "runId": run_id,
                        "kind": "command",
                        "status": "pending",
                        "summary": "Approve the test command"
                    })
                    .to_string()
                ],
            )
            .unwrap();
    }

    /// Seed many independent projects/threads/runs/approvals so a snapshot is
    /// large enough to require chunked upload.
    fn seed_large_snapshot(&mut self, count: usize) {
        for index in 0..count {
            let project_id = format!("p{index}");
            let thread_id = format!("t{index}");
            let run_id = format!("r{index}");
            let approval_id = format!("a{index}");
            let updated_at = "2026-11-16T02:20:00.000Z";
            self.conn
                .execute(
                    "INSERT INTO projection_projects \
                         (project_id, title, workspace_root, scripts_json, created_at, updated_at) \
                     VALUES (?1, ?2, ?3, '[]', ?4, ?4)",
                    params![
                        project_id,
                        format!("Project {index}"),
                        format!("/repo/{index}"),
                        updated_at
                    ],
                )
                .unwrap();
            self.conn
                .execute(
                    "INSERT INTO orchestration_v2_projection_threads \
                         (thread_id, project_id, title, created_at, updated_at, payload_json) \
                     VALUES (?1, ?2, ?3, ?4, ?4, ?5)",
                    params![
                        thread_id,
                        project_id,
                        format!("Thread {index}"),
                        updated_at,
                        json!({"id": thread_id, "branch": "main"}).to_string()
                    ],
                )
                .unwrap();
            self.conn
                .execute(
                    "INSERT INTO orchestration_v2_projection_runs \
                         (run_id, thread_id, ordinal, status, requested_at, completed_at, \
                          payload_json, provider_instance_id) \
                     VALUES (?1, ?2, 1, 'completed', ?3, ?3, ?4, 'test-provider')",
                    params![
                        run_id,
                        thread_id,
                        updated_at,
                        json!({
                            "id": run_id,
                            "threadId": thread_id,
                            "ordinal": 1,
                            "status": "completed",
                            "completedAt": updated_at,
                            "checkpointId": format!("checkpoint:{index}")
                        })
                        .to_string()
                    ],
                )
                .unwrap();
            self.conn
                .execute(
                    "INSERT INTO orchestration_v2_projection_runtime_requests \
                         (runtime_request_id, thread_id, node_id, kind, status, created_at, \
                          payload_json) \
                     VALUES (?1, ?2, ?3, 'command', 'pending', ?4, ?5)",
                    params![
                        approval_id,
                        thread_id,
                        format!("node-{index}"),
                        updated_at,
                        json!({
                            "id": approval_id,
                            "threadId": thread_id,
                            "runId": run_id,
                            "kind": "command",
                            "status": "pending",
                            "summary": format!("Approve command {index}")
                        })
                        .to_string()
                    ],
                )
                .unwrap();
        }
    }
}

// ---------------------------------------------------------------------------
// Mock ChatGPT webhook receiver
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReceiverBehavior {
    Success,
    Gone,
}

#[derive(Debug, Clone)]
struct Received {
    subscription_id: Option<String>,
    event_name: Option<String>,
    data: Value,
    is_verification: bool,
    signature_valid: bool,
}

struct ReceiverState {
    behavior: Mutex<ReceiverBehavior>,
    records: Mutex<Vec<Received>>,
    deliveries: AtomicUsize,
}

struct MockReceiver {
    url: String,
    state: Arc<ReceiverState>,
    task: JoinHandle<()>,
}

impl MockReceiver {
    async fn start() -> Self {
        let state = Arc::new(ReceiverState {
            behavior: Mutex::new(ReceiverBehavior::Success),
            records: Mutex::new(Vec::new()),
            deliveries: AtomicUsize::new(0),
        });
        let app = Router::new()
            .route("/mcp", post(receive))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self {
            url: format!("http://{address}/mcp"),
            state,
            task,
        }
    }

    fn endpoint(&self) -> &str {
        &self.url
    }

    fn set_behavior(&self, behavior: ReceiverBehavior) {
        *self.state.behavior.lock().unwrap() = behavior;
    }

    fn records(&self) -> Vec<Received> {
        self.state.records.lock().unwrap().clone()
    }

    fn events(&self) -> Vec<Received> {
        self.records()
            .into_iter()
            .filter(|record| !record.is_verification)
            .collect()
    }

    fn deliveries(&self) -> usize {
        self.state.deliveries.load(Ordering::SeqCst)
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
        .unwrap()
        .to_vec();
    let parsed: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let is_verification = parsed.get("type").and_then(Value::as_str) == Some("verification");
    let signature_valid = standardwebhooks::Webhook::new(WEBHOOK_SECRET)
        .and_then(|webhook| webhook.verify(&body, &headers))
        .is_ok();

    if is_verification {
        let challenge = parsed.get("challenge").cloned().unwrap_or(Value::Null);
        state.records.lock().unwrap().push(Received {
            subscription_id: header(&headers, "x-mcp-subscription-id"),
            event_name: None,
            data: Value::Null,
            is_verification: true,
            signature_valid,
        });
        return (StatusCode::OK, Json(json!({"challenge": challenge}))).into_response();
    }

    state.deliveries.fetch_add(1, Ordering::SeqCst);
    state.records.lock().unwrap().push(Received {
        subscription_id: header(&headers, "x-mcp-subscription-id"),
        event_name: parsed
            .get("name")
            .and_then(Value::as_str)
            .map(str::to_string),
        data: parsed.get("data").cloned().unwrap_or(Value::Null),
        is_verification: false,
        signature_valid,
    });

    match *state.behavior.lock().unwrap() {
        ReceiverBehavior::Success => (StatusCode::OK, Json(json!({"ok": true}))).into_response(),
        ReceiverBehavior::Gone => StatusCode::GONE.into_response(),
    }
}

fn header(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

// ---------------------------------------------------------------------------
// Toggleable TCP proxy (simulates a hub outage / restart)
// ---------------------------------------------------------------------------

struct ToggleProxy {
    url: String,
    target: Arc<Mutex<Option<SocketAddr>>>,
    task: JoinHandle<()>,
}

impl ToggleProxy {
    async fn start(target: SocketAddr) -> Self {
        let target = Arc::new(Mutex::new(Some(target)));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let shared = target.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut inbound, _)) = listener.accept().await else {
                    break;
                };
                let target = *shared.lock().unwrap();
                tokio::spawn(async move {
                    let Some(target) = target else {
                        let _ = inbound
                            .write_all(
                                b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                            )
                            .await;
                        return;
                    };
                    let Ok(mut outbound) = tokio::net::TcpStream::connect(target).await else {
                        let _ = inbound
                            .write_all(
                                b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                            )
                            .await;
                        return;
                    };
                    let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                });
            }
        });
        Self {
            url: format!("http://{address}"),
            target,
            task,
        }
    }

    fn url(&self) -> &str {
        &self.url
    }

    fn pause(&self) {
        *self.target.lock().unwrap() = None;
    }

    fn point_at(&self, address: SocketAddr) {
        *self.target.lock().unwrap() = Some(address);
    }
}

impl Drop for ToggleProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

// ---------------------------------------------------------------------------
// HTTP proxy that can forward-then-fail or delay responses
// ---------------------------------------------------------------------------

struct HttpProxyState {
    target: Mutex<Option<SocketAddr>>,
    fail: AtomicBool,
    delay_ms: AtomicUsize,
    requests: AtomicUsize,
    client: reqwest::Client,
}

struct HttpProxy {
    url: String,
    state: Arc<HttpProxyState>,
    task: JoinHandle<()>,
}

impl HttpProxy {
    async fn start(target: SocketAddr) -> Self {
        let state = Arc::new(HttpProxyState {
            target: Mutex::new(Some(target)),
            fail: AtomicBool::new(false),
            delay_ms: AtomicUsize::new(0),
            requests: AtomicUsize::new(0),
            client: reqwest::Client::new(),
        });
        let app = Router::new()
            .fallback(proxy_handler)
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

    fn url(&self) -> &str {
        &self.url
    }

    fn set_fail(&self, fail: bool) {
        self.state.fail.store(fail, Ordering::SeqCst);
    }

    fn set_delay_ms(&self, delay_ms: usize) {
        self.state.delay_ms.store(delay_ms, Ordering::SeqCst);
    }

    fn requests(&self) -> usize {
        self.state.requests.load(Ordering::SeqCst)
    }
}

impl Drop for HttpProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn proxy_handler(State(state): State<Arc<HttpProxyState>>, request: Request) -> Response {
    let Some(target) = *state.target.lock().unwrap() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    state.requests.fetch_add(1, Ordering::SeqCst);
    let delay = state.delay_ms.load(Ordering::SeqCst);
    if delay > 0 {
        tokio::time::sleep(Duration::from_millis(delay as u64)).await;
    }

    let method = request.method().clone();
    let path = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    let headers = request.headers().clone();
    let body = axum::body::to_bytes(request.into_body(), 16 * 1024 * 1024)
        .await
        .unwrap_or_default();

    let method =
        reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap_or(reqwest::Method::POST);
    let mut builder = state
        .client
        .request(method, format!("http://{target}{path}"));
    for (name, value) in headers.iter() {
        if name == header::HOST || name == header::CONTENT_LENGTH || name == header::CONNECTION {
            continue;
        }
        builder = builder.header(name.as_str(), value.as_bytes());
    }
    let response = builder.body(body).send().await;

    if state.fail.load(Ordering::SeqCst) {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let Ok(response) = response else {
        return StatusCode::BAD_GATEWAY.into_response();
    };
    let status =
        StatusCode::from_u16(response.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let headers = response.headers().clone();
    let bytes = response.bytes().await.unwrap_or_default();
    let mut proxied = Response::new(axum::body::Body::from(bytes));
    *proxied.status_mut() = status;
    for (name, value) in headers.iter() {
        if name == header::CONTENT_LENGTH
            || name == header::TRANSFER_ENCODING
            || name == header::CONNECTION
        {
            continue;
        }
        proxied.headers_mut().insert(name.clone(), value.clone());
    }
    proxied
}

// ---------------------------------------------------------------------------
// Mock GitHub REST API
// ---------------------------------------------------------------------------

struct GitHubApiState {
    pulls: Mutex<Vec<Value>>,
    runs: Mutex<Vec<Value>>,
}

struct MockGitHubApi {
    url: String,
    state: Arc<GitHubApiState>,
    task: JoinHandle<()>,
}

impl MockGitHubApi {
    async fn start() -> Self {
        let state = Arc::new(GitHubApiState {
            pulls: Mutex::new(Vec::new()),
            runs: Mutex::new(Vec::new()),
        });
        let app = Router::new()
            .route("/repos/{owner}/{repo}/pulls", axum::routing::get(pulls))
            .route(
                "/repos/{owner}/{repo}/actions/runs",
                axum::routing::get(runs),
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

    fn url(&self) -> &str {
        &self.url
    }

    fn set_pulls(&self, pulls: Vec<Value>) {
        *self.state.pulls.lock().unwrap() = pulls;
    }

    fn set_runs(&self, runs: Vec<Value>) {
        *self.state.runs.lock().unwrap() = runs;
    }
}

impl Drop for MockGitHubApi {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn pulls(
    State(state): State<Arc<GitHubApiState>>,
    AxumPath((_owner, _repo)): AxumPath<(String, String)>,
) -> Json<Value> {
    Json(Value::Array(state.pulls.lock().unwrap().clone()))
}

async fn runs(
    State(state): State<Arc<GitHubApiState>>,
    AxumPath((_owner, _repo)): AxumPath<(String, String)>,
) -> Json<Value> {
    Json(json!({"workflow_runs": state.runs.lock().unwrap().clone()}))
}

fn pull_payload(number: i64, merged: bool, updated_at: &str) -> Value {
    json!({
        "number": number,
        "title": "Polled pull request",
        "state": if merged { "closed" } else { "open" },
        "user": {"login": "alice"},
        "head": {"ref": "feature", "sha": "0123456789abcdef0123456789abcdef01234567"},
        "base": {"ref": "main"},
        "draft": false,
        "merged": merged,
        "merged_by": if merged { json!({"login": "bob"}) } else { Value::Null },
        "merged_at": if merged { json!("2026-11-16T03:10:00.000Z") } else { Value::Null },
        "requested_reviewers": [],
        "requested_teams": [],
        "html_url": format!("https://github.com/{REPOSITORY}/pull/{number}"),
        "updated_at": updated_at
    })
}

fn run_payload(id: i64, conclusion: &str, updated_at: &str) -> Value {
    json!({
        "id": id,
        "run_attempt": 1,
        "check_suite_id": id + 1000,
        "name": "CI",
        "head_branch": "main",
        "head_sha": "0123456789abcdef0123456789abcdef01234567",
        "status": "completed",
        "conclusion": conclusion,
        "html_url": format!("https://github.com/{REPOSITORY}/actions/runs/{id}"),
        "created_at": updated_at,
        "updated_at": updated_at
    })
}

// ---------------------------------------------------------------------------
// Hub harness
// ---------------------------------------------------------------------------

struct RunningHub {
    hub: Arc<Hub>,
    base_url: String,
    address: SocketAddr,
    server: JoinHandle<()>,
    dispatcher: Option<(CancellationToken, JoinHandle<()>)>,
    collectors: Vec<(CancellationToken, JoinHandle<()>)>,
}

impl RunningHub {
    async fn start(config: Config, spawn_dispatcher: bool) -> Self {
        let hub =
            Arc::new(Hub::with_policy(config, CallbackPolicy::for_tests()).expect("hub builds"));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let router = hub.router();
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        let dispatcher = spawn_dispatcher.then(|| hub.spawn_dispatcher());
        let mut collectors = Vec::new();
        if let Some(collector) = hub.spawn_t3_collector().expect("T3 collector") {
            collectors.push(collector);
        }
        if let Some(poller) = hub.spawn_github_poller().expect("GitHub poller") {
            collectors.push(poller);
        }
        Self {
            hub,
            base_url: format!("http://{address}"),
            address,
            server,
            dispatcher,
            collectors,
        }
    }

    fn client(&self) -> McpClient {
        McpClient::new(self.base_url.clone())
    }

    async fn stop(mut self) {
        if let Some((cancellation, handle)) = self.dispatcher.take() {
            cancellation.cancel();
            let _ = handle.await;
        }
        for (cancellation, handle) in self.collectors.drain(..) {
            cancellation.cancel();
            let _ = handle.await;
        }
        self.server.abort();
        let _ = (&mut self.server).await;
    }
}

impl Drop for RunningHub {
    fn drop(&mut self) {
        if let Some((cancellation, _)) = self.dispatcher.take() {
            cancellation.cancel();
        }
        for (cancellation, _) in self.collectors.drain(..) {
            cancellation.cancel();
        }
        self.server.abort();
    }
}

// ---------------------------------------------------------------------------
// Minimal MCP client
// ---------------------------------------------------------------------------

struct McpClient {
    http: reqwest::Client,
    base_url: String,
    session: Option<String>,
    protocol: String,
    next_id: i64,
}

impl McpClient {
    fn new(base_url: String) -> Self {
        Self {
            http: reqwest::Client::new(),
            base_url,
            session: None,
            protocol: "2025-06-18".into(),
            next_id: 1,
        }
    }

    async fn raw(&self, body: &Value, with_protocol: bool) -> reqwest::Response {
        let mut request = self
            .http
            .post(format!("{}/mcp", self.base_url))
            .header(header::ACCEPT, "application/json, text/event-stream")
            .json(body);
        if with_protocol {
            request = request.header("MCP-Protocol-Version", &self.protocol);
        }
        if let Some(session) = &self.session {
            request = request.header("Mcp-Session-Id", session);
        }
        request.send().await.expect("MCP request")
    }

    async fn initialize(&mut self) -> Value {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 0,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "events-bridge-e2e", "version": "1.0.0"}
            }
        });
        let response = self.raw(&body, false).await;
        self.session = response
            .headers()
            .get("mcp-session-id")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let value = parse_mcp_response(response).await;
        if let Some(version) = value
            .pointer("/result/protocolVersion")
            .and_then(Value::as_str)
        {
            self.protocol = version.to_string();
        }
        let notification = json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        });
        let response = self.raw(&notification, true).await;
        assert!(
            response.status().is_success() || response.status() == StatusCode::ACCEPTED,
            "initialized notification failed: {}",
            response.status()
        );
        value
    }

    async fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        let body = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });
        parse_mcp_response(self.raw(&body, true).await).await
    }

    async fn tool_call(&mut self, name: &str, arguments: Value) -> Value {
        let response = self
            .request("tools/call", json!({"name": name, "arguments": arguments}))
            .await;
        rpc_result(response)
    }
}

async fn parse_mcp_response(response: reqwest::Response) -> Value {
    let status = response.status();
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let bytes = response.bytes().await.expect("response body");
    assert!(
        status.is_success(),
        "HTTP {status}: {}",
        String::from_utf8_lossy(&bytes)
    );
    if content_type.contains("text/event-stream") {
        let text = String::from_utf8_lossy(&bytes);
        let data = text
            .lines()
            .filter_map(|line| line.strip_prefix("data:"))
            .next_back()
            .expect("SSE data frame")
            .trim();
        serde_json::from_str(data).unwrap_or_else(|error| {
            panic!("invalid SSE JSON: {error}: {data}");
        })
    } else {
        serde_json::from_slice(&bytes).unwrap_or_else(|error| {
            panic!(
                "invalid JSON response: {error}: {}",
                String::from_utf8_lossy(&bytes)
            );
        })
    }
}

fn rpc_result(value: Value) -> Value {
    assert!(
        value.get("error").is_none(),
        "unexpected JSON-RPC error: {value}"
    );
    value.get("result").cloned().unwrap_or(Value::Null)
}

// ---------------------------------------------------------------------------
// Edge harness
// ---------------------------------------------------------------------------

struct RunningEdge {
    cancellation: CancellationToken,
    task: JoinHandle<()>,
    repo: Arc<Repository>,
}

impl RunningEdge {
    fn start(config: Config) -> Self {
        let edge = Edge::new(&config).expect("edge builds");
        let repo = edge.repository().clone();
        let cancellation = CancellationToken::new();
        let child = cancellation.clone();
        let task = tokio::spawn(async move {
            let _ = edge.run(child).await;
        });
        Self {
            cancellation,
            task,
            repo,
        }
    }

    fn repository(&self) -> &Arc<Repository> {
        &self.repo
    }

    async fn stop(self) {
        self.cancellation.cancel();
        let _ = self.task.await;
    }
}

// ---------------------------------------------------------------------------
// Configuration helpers
// ---------------------------------------------------------------------------

fn hub_config(database: PathBuf) -> Config {
    let mut config = Config::for_tests(database);
    config.server.enable_edge_ingest = true;
    config.server.edge_shared_secret_env = Some(EDGE_SECRET_ENV.into());
    config.server.edge_max_skew_secs = 300;
    config.server.max_edge_body_bytes = 4 * 1024 * 1024;
    config.collectors.github.webhook_enabled = true;
    config.collectors.github.webhook_secret_env = Some(GITHUB_SECRET_ENV.into());
    config.collectors.github.repositories = vec![REPOSITORY.into()];
    config
}

fn hub_config_with_poll(database: PathBuf, api_base_url: &str) -> Config {
    let mut config = hub_config(database);
    config.collectors.github.poll_enabled = true;
    config.collectors.github.api_base_url = api_base_url.to_string();
    config.collectors.github.poll_interval_secs = 1;
    config
}

fn edge_config(
    edge_database: PathBuf,
    t3_database: &Path,
    environment_id: &str,
    hub_url: &str,
) -> Config {
    let mut config = Config::default();
    config.database.path = edge_database;
    config.edge.hub_url = Some(hub_url.to_string());
    config.edge.shared_secret_env = Some(EDGE_SECRET_ENV.into());
    config.edge.edge_id = Some(format!("edge-{environment_id}"));
    config.edge.request_timeout_secs = 2;
    config.edge.retry_initial_ms = 20;
    config.edge.retry_max_ms = 100;
    config.collectors.t3.enabled = true;
    config.collectors.t3.state_db_path = t3_database.to_path_buf();
    config.collectors.t3.environment_id = Some(environment_id.to_string());
    config.collectors.t3.poll_interval_ms = 50;
    config.collectors.t3.watch_wal = false;
    config.collectors.t3.batch_size = 100;
    config.logging.level = "warn".into();
    config
}

async fn wait_until(label: &str, mut condition: impl FnMut() -> bool) {
    timeout(Duration::from_secs(15), async {
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

async fn subscribe(
    client: &mut McpClient,
    receiver: &MockReceiver,
    name: &str,
    arguments: Value,
) -> String {
    let result = client
        .request(
            "events/subscribe",
            json!({
                "name": name,
                "arguments": arguments,
                "delivery": {
                    "mode": "webhook",
                    "url": receiver.endpoint(),
                    "secret": WEBHOOK_SECRET,
                }
            }),
        )
        .await;
    let result = rpc_result(result);
    result
        .get("id")
        .and_then(Value::as_str)
        .expect("subscription id")
        .to_string()
}

fn github_workflow_payload(run_id: i64) -> Value {
    json!({
        "action": "completed",
        "repository": {"full_name": REPOSITORY},
        "workflow_run": {
            "id": run_id,
            "run_attempt": 1,
            "name": "CI",
            "head_branch": "main",
            "head_sha": "0123456789abcdef0123456789abcdef01234567",
            "status": "completed",
            "conclusion": "failure",
            "html_url": format!("https://github.com/{REPOSITORY}/actions/runs/{run_id}"),
            "updated_at": "2026-11-16T02:20:00.000Z"
        }
    })
}

async fn send_github_webhook(hub: &RunningHub, delivery_id: &str, payload: &Value) {
    let body = serde_json::to_vec(payload).unwrap();
    let mut mac = Hmac::<Sha256>::new_from_slice(GITHUB_SECRET.as_bytes()).unwrap();
    mac.update(&body);
    let signature = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));
    let response = reqwest::Client::new()
        .post(format!("{}/webhooks/github", hub.base_url))
        .header(header::CONTENT_TYPE, "application/json")
        .header("X-GitHub-Event", "workflow_run")
        .header("X-GitHub-Delivery", delivery_id)
        .header("X-Hub-Signature-256", signature)
        .body(body)
        .send()
        .await
        .expect("github webhook");
    assert!(
        response.status().is_success(),
        "github webhook failed: {}",
        response.status()
    );
}

async fn post_edge_request(
    client: &reqwest::Client,
    endpoint: &str,
    edge_id: &str,
    nonce: &str,
    timestamp: i64,
    request: &EdgeT3IngestRequest,
) -> reqwest::Response {
    let body = serde_json::to_vec(request).unwrap();
    let signature = sign(EDGE_SECRET.as_bytes(), edge_id, timestamp, nonce, &body);
    client
        .post(endpoint)
        .header(header::CONTENT_TYPE, "application/json")
        .header(HEADER_EDGE_ID, edge_id)
        .header(HEADER_EDGE_TIMESTAMP, timestamp.to_string())
        .header(HEADER_EDGE_NONCE, nonce)
        .header(HEADER_EDGE_SIGNATURE, signature)
        .body(body)
        .send()
        .await
        .expect("edge request")
}

fn sample_run(environment_id: &str, run_id: &str, status: &str) -> T3Run {
    T3Run {
        environment_id: environment_id.into(),
        run_id: run_id.into(),
        thread_id: "t1".into(),
        project_id: "p1".into(),
        ordinal: 1,
        provider_instance_id: Some("test-provider".into()),
        status: status.into(),
        last_turn_status: None,
        checkpoint_id: None,
        error: None,
        summary: Some("sample run".into()),
        requested_at: Some("2026-11-16T02:00:02.000Z".into()),
        started_at: Some("2026-11-16T02:00:03.000Z".into()),
        completed_at: (status == "completed").then(|| "2026-11-16T02:00:09.000Z".to_string()),
        updated_at: "2026-11-16T02:00:09.000Z".into(),
    }
}

fn sample_project(environment_id: &str, project_id: &str) -> T3Project {
    T3Project {
        environment_id: environment_id.into(),
        project_id: project_id.into(),
        title: format!("Project {project_id}"),
        workspace_root: format!("/repo/{project_id}"),
        deleted_at: None,
        updated_at: "2026-11-16T02:00:00.000Z".into(),
    }
}

fn sample_thread(environment_id: &str, thread_id: &str, project_id: &str) -> T3Thread {
    T3Thread {
        environment_id: environment_id.into(),
        thread_id: thread_id.into(),
        project_id: project_id.into(),
        title: format!("Thread {thread_id}"),
        branch: Some("main".into()),
        deleted_at: None,
        updated_at: "2026-11-16T02:00:01.000Z".into(),
    }
}

fn sample_approval(environment_id: &str, approval_id: &str, run_id: &str) -> T3Approval {
    T3Approval {
        environment_id: environment_id.into(),
        approval_id: approval_id.into(),
        thread_id: "t1".into(),
        run_id: run_id.into(),
        node_id: Some("node-1".into()),
        kind: "command".into(),
        status: "pending".into(),
        summary: Some("Approve the test command".into()),
        decision: None,
        created_at: "2026-11-16T02:11:00.000Z".into(),
        resolved_at: None,
        updated_at: "2026-11-16T02:11:00.000Z".into(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn edge_hub_github_and_multi_host_flow() {
    init_env();
    let temp = TempDir::new().unwrap();
    let receiver = MockReceiver::start().await;
    let hub = RunningHub::start(hub_config(temp.path().join("hub.db")), true).await;

    let mut client = hub.client();
    client.initialize().await;
    let env_one = "env-edge-one";
    let completed_sub = subscribe(
        &mut client,
        &receiver,
        "t3.run.completed",
        json!({"environment_id": env_one}),
    )
    .await;
    let approval_sub = subscribe(
        &mut client,
        &receiver,
        "t3.approval.required",
        json!({"environment_id": env_one}),
    )
    .await;
    let github_sub = subscribe(
        &mut client,
        &receiver,
        "github.workflow.failed",
        json!({"repository": REPOSITORY}),
    )
    .await;
    assert!(!completed_sub.is_empty());
    assert!(!approval_sub.is_empty());
    assert!(!github_sub.is_empty());

    let mut fixture = Fixture::new();
    fixture.seed_project_thread();
    fixture.seed_existing_completed_run();
    let edge = RunningEdge::start(edge_config(
        temp.path().join("edge-one.db"),
        fixture.path(),
        env_one,
        &hub.base_url,
    ));

    wait_until("edge snapshot", || {
        hub.hub
            .repository()
            .get_t3_run("run-old", Some(env_one))
            .ok()
            .flatten()
            .is_some()
    })
    .await;

    fixture.emit_completed_run("run-new", 2);
    fixture.emit_pending_approval("approval-1", "run-new");

    wait_until("edge events forwarded", || {
        hub.hub
            .repository()
            .get_t3_run("run-new", Some(env_one))
            .ok()
            .flatten()
            .is_some()
            && hub
                .hub
                .repository()
                .list_t3_approvals(&events_bridge::store::T3ApprovalQuery {
                    environment_id: Some(env_one.into()),
                    status: Some("pending".into()),
                    limit: 10,
                    ..Default::default()
                })
                .map(|rows| !rows.is_empty())
                .unwrap_or(false)
    })
    .await;

    send_github_webhook(&hub, "delivery-1", &github_workflow_payload(9001)).await;

    wait_until("receiver deliveries", || {
        let events = receiver.events();
        events.iter().any(|event| {
            event.event_name.as_deref() == Some("t3.run.completed")
                && event.data["environment_id"] == env_one
        }) && events.iter().any(|event| {
            event.event_name.as_deref() == Some("t3.approval.required")
                && event.data["environment_id"] == env_one
        }) && events.iter().any(|event| {
            event.event_name.as_deref() == Some("github.workflow.failed")
                && event.data["repository"] == REPOSITORY
        })
    })
    .await;

    for event in receiver.events() {
        assert!(event.signature_valid, "delivery signature must verify");
    }

    let run = client
        .tool_call(
            "get_t3_run",
            json!({"run_id": "run-new", "environment_id": env_one}),
        )
        .await;
    assert_eq!(run["structuredContent"]["run"]["status"], "completed");
    assert_eq!(run["structuredContent"]["run"]["environmentId"], env_one);

    let approvals = client
        .tool_call(
            "get_t3_approvals",
            json!({"environment_id": env_one, "status": "pending"}),
        )
        .await;
    assert_eq!(
        approvals["structuredContent"]["approvals"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        approvals["structuredContent"]["approvals"][0]["approvalId"],
        "approval-1"
    );

    let github = client
        .tool_call("get_github_status", json!({"repository": REPOSITORY}))
        .await;
    assert_eq!(
        github["structuredContent"]["ciRuns"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        github["structuredContent"]["ciRuns"][0]["conclusion"],
        "failure"
    );
    assert_eq!(
        github["structuredContent"]["summary"]["failedCiRunCount"],
        1
    );

    let listed = client.tool_call("list_events", json!({"limit": 50})).await;
    let kinds: Vec<_> = listed["structuredContent"]["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|event| event["kind"].as_str())
        .collect();
    assert!(kinds.contains(&"t3.run.completed"));
    assert!(kinds.contains(&"t3.approval.required"));
    assert!(kinds.contains(&"github.workflow.failed"));

    let event_id = listed["structuredContent"]["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|event| event["kind"] == "t3.run.completed")
        .and_then(|event| event["id"].as_str())
        .unwrap()
        .to_string();
    let fetched = client
        .tool_call("get_event", json!({"event_id": event_id}))
        .await;
    assert_eq!(fetched["structuredContent"]["event"]["id"], event_id);

    // A second edge with a different environment id coexists in the same hub.
    let env_two = "env-edge-two";
    let second_completed_sub = subscribe(
        &mut client,
        &receiver,
        "t3.run.completed",
        json!({"environment_id": env_two}),
    )
    .await;
    let mut second_fixture = Fixture::new();
    second_fixture.seed_project_thread();
    second_fixture.seed_existing_completed_run();
    let second_edge = RunningEdge::start(edge_config(
        temp.path().join("edge-two.db"),
        second_fixture.path(),
        env_two,
        &hub.base_url,
    ));
    wait_until("second edge snapshot", || {
        hub.hub
            .repository()
            .get_t3_run("run-old", Some(env_two))
            .ok()
            .flatten()
            .is_some()
    })
    .await;
    second_fixture.emit_completed_run("run-two", 2);
    wait_until("second edge event", || {
        receiver.events().iter().any(|event| {
            event.event_name.as_deref() == Some("t3.run.completed")
                && event.data["environment_id"] == env_two
        })
    })
    .await;

    let env_two_events: Vec<_> = receiver
        .events()
        .into_iter()
        .filter(|event| event.data["environment_id"] == env_two)
        .collect();
    assert!(!env_two_events.is_empty());
    for event in &env_two_events {
        assert_eq!(
            event.subscription_id.as_deref(),
            Some(second_completed_sub.as_str()),
            "environment filter must isolate the second edge"
        );
    }
    assert!(
        receiver
            .events()
            .iter()
            .filter(|event| event.data["environment_id"] == env_one)
            .all(|event| event.subscription_id.as_deref() != Some(second_completed_sub.as_str()))
    );

    second_edge.stop().await;
    edge.stop().await;
    hub.stop().await;
}

#[tokio::test]
async fn edge_catches_up_after_hub_restart() {
    init_env();
    let temp = TempDir::new().unwrap();
    let receiver = MockReceiver::start().await;
    let database = temp.path().join("hub.db");
    let hub = RunningHub::start(hub_config(database.clone()), true).await;
    let proxy = ToggleProxy::start(hub.address).await;

    let mut client = hub.client();
    client.initialize().await;
    subscribe(
        &mut client,
        &receiver,
        "t3.run.completed",
        json!({"environment_id": "env-restart"}),
    )
    .await;

    let mut fixture = Fixture::new();
    fixture.seed_project_thread();
    fixture.seed_existing_completed_run();
    let edge = RunningEdge::start(edge_config(
        temp.path().join("edge-restart.db"),
        fixture.path(),
        "env-restart",
        proxy.url(),
    ));
    wait_until("edge snapshot before outage", || {
        hub.hub
            .repository()
            .get_t3_run("run-old", Some("env-restart"))
            .ok()
            .flatten()
            .is_some()
    })
    .await;

    proxy.pause();
    fixture.emit_completed_run("run-after-restart", 2);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        hub.hub
            .repository()
            .get_t3_run("run-after-restart", Some("env-restart"))
            .unwrap()
            .is_none(),
        "edge must not advance while the hub is unavailable"
    );

    hub.stop().await;
    let restarted = RunningHub::start(hub_config(database), true).await;
    proxy.point_at(restarted.address);

    wait_until("edge catch-up after restart", || {
        restarted
            .hub
            .repository()
            .get_t3_run("run-after-restart", Some("env-restart"))
            .ok()
            .flatten()
            .is_some()
    })
    .await;
    wait_until("delivery after restart", || {
        receiver.events().iter().any(|event| {
            event.event_name.as_deref() == Some("t3.run.completed")
                && event.data["run_id"] == "run-after-restart"
        })
    })
    .await;

    edge.stop().await;
    restarted.stop().await;
}

#[tokio::test]
async fn pending_delivery_is_retried_after_hub_restart() {
    init_env();
    let temp = TempDir::new().unwrap();
    let receiver = MockReceiver::start().await;
    let database = temp.path().join("hub.db");
    let hub = RunningHub::start(hub_config(database.clone()), false).await;

    let mut client = hub.client();
    client.initialize().await;
    subscribe(
        &mut client,
        &receiver,
        "t3.run.completed",
        json!({"environment_id": "env-pending"}),
    )
    .await;

    let mut fixture = Fixture::new();
    fixture.seed_project_thread();
    fixture.seed_existing_completed_run();
    let edge = RunningEdge::start(edge_config(
        temp.path().join("edge-pending.db"),
        fixture.path(),
        "env-pending",
        &hub.base_url,
    ));
    wait_until("edge snapshot", || {
        hub.hub
            .repository()
            .get_t3_run("run-old", Some("env-pending"))
            .ok()
            .flatten()
            .is_some()
    })
    .await;
    fixture.emit_completed_run("run-pending", 2);
    wait_until("pending delivery queued", || {
        hub.hub
            .repository()
            .pending_delivery_count()
            .map(|count| count > 0)
            .unwrap_or(false)
    })
    .await;
    assert_eq!(receiver.deliveries(), 0);

    hub.stop().await;
    let restarted = RunningHub::start(hub_config(database), true).await;
    wait_until("pending delivery after restart", || {
        receiver.events().iter().any(|event| {
            event.event_name.as_deref() == Some("t3.run.completed")
                && event.data["run_id"] == "run-pending"
        })
    })
    .await;

    edge.stop().await;
    restarted.stop().await;
}

#[tokio::test]
async fn receiver_410_terminalizes_the_subscription_backlog() {
    init_env();
    let temp = TempDir::new().unwrap();
    let receiver = MockReceiver::start().await;
    let hub = RunningHub::start(hub_config(temp.path().join("hub.db")), true).await;

    let mut client = hub.client();
    client.initialize().await;
    let subscription_id = subscribe(
        &mut client,
        &receiver,
        "t3.run.completed",
        json!({"environment_id": "env-gone"}),
    )
    .await;
    receiver.set_behavior(ReceiverBehavior::Gone);

    let mut fixture = Fixture::new();
    fixture.seed_project_thread();
    fixture.seed_existing_completed_run();
    let edge = RunningEdge::start(edge_config(
        temp.path().join("edge-gone.db"),
        fixture.path(),
        "env-gone",
        &hub.base_url,
    ));
    wait_until("edge snapshot", || {
        hub.hub
            .repository()
            .get_t3_run("run-old", Some("env-gone"))
            .ok()
            .flatten()
            .is_some()
    })
    .await;
    fixture.emit_completed_run("run-gone", 2);

    wait_until("410 terminalized", || {
        hub.hub
            .repository()
            .get_subscription(&subscription_id)
            .ok()
            .flatten()
            .is_some_and(|subscription| !subscription.active)
            && hub
                .hub
                .repository()
                .pending_delivery_count()
                .map(|count| count == 0)
                .unwrap_or(false)
    })
    .await;

    let attempts = receiver.deliveries();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        receiver.deliveries(),
        attempts,
        "a 410 must stop further delivery attempts"
    );

    edge.stop().await;
    hub.stop().await;
}

#[tokio::test]
async fn edge_ingest_rejects_bad_signature_stale_timestamp_and_replay() {
    init_env();
    let temp = TempDir::new().unwrap();
    let hub = RunningHub::start(hub_config(temp.path().join("hub.db")), false).await;
    let client = reqwest::Client::new();
    let endpoint = format!("{}/internal/edge/t3", hub.base_url);

    let batch = T3WriteBatch {
        environment_id: "env-auth".into(),
        sequence: 1,
        events: vec![NewEvent {
            id: Some("evt_edge_auth".into()),
            source: Some("t3".into()),
            kind: "t3.run.completed".into(),
            payload: json!({
                "environment_id": "env-auth",
                "project_id": "p1",
                "thread_id": "t1",
                "run_id": "run-auth",
                "summary": "auth test"
            }),
            occurred_at: Some("2026-11-16T02:30:00.000Z".into()),
        }],
        ..Default::default()
    };
    let body = serde_json::to_vec(&EdgeT3IngestRequest::Batches {
        batches: vec![batch],
    })
    .unwrap();

    let now = chrono::Utc::now().timestamp();
    let nonce = "nonce-valid-1";
    let signature = sign(EDGE_SECRET.as_bytes(), "edge-auth", now, nonce, &body);
    let response = client
        .post(&endpoint)
        .header(header::CONTENT_TYPE, "application/json")
        .header(HEADER_EDGE_ID, "edge-auth")
        .header(HEADER_EDGE_TIMESTAMP, now.to_string())
        .header(HEADER_EDGE_NONCE, nonce)
        .header(HEADER_EDGE_SIGNATURE, &signature)
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        hub.hub
            .repository()
            .get_event("evt_edge_auth")
            .unwrap()
            .is_some()
    );

    // Replay of the same nonce.
    let response = client
        .post(&endpoint)
        .header(header::CONTENT_TYPE, "application/json")
        .header(HEADER_EDGE_ID, "edge-auth")
        .header(HEADER_EDGE_TIMESTAMP, now.to_string())
        .header(HEADER_EDGE_NONCE, nonce)
        .header(HEADER_EDGE_SIGNATURE, &signature)
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Tampered signature with a fresh nonce.
    let response = client
        .post(&endpoint)
        .header(header::CONTENT_TYPE, "application/json")
        .header(HEADER_EDGE_ID, "edge-auth")
        .header(HEADER_EDGE_TIMESTAMP, now.to_string())
        .header(HEADER_EDGE_NONCE, "nonce-tampered")
        .header(HEADER_EDGE_SIGNATURE, "v1,00")
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Stale timestamp with a valid signature for that timestamp.
    let stale = now - 1_000;
    let stale_signature = sign(
        EDGE_SECRET.as_bytes(),
        "edge-auth",
        stale,
        "nonce-stale",
        &body,
    );
    let response = client
        .post(&endpoint)
        .header(header::CONTENT_TYPE, "application/json")
        .header(HEADER_EDGE_ID, "edge-auth")
        .header(HEADER_EDGE_TIMESTAMP, stale.to_string())
        .header(HEADER_EDGE_NONCE, "nonce-stale")
        .header(HEADER_EDGE_SIGNATURE, stale_signature)
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let events = hub
        .hub
        .repository()
        .list_events(&events_bridge::store::EventQuery {
            limit: 10,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(events.len(), 1, "rejected requests must not change state");

    hub.stop().await;
}

#[tokio::test]
async fn edge_retries_pending_snapshot_without_skipping_new_events() {
    init_env();
    let temp = TempDir::new().unwrap();
    let receiver = MockReceiver::start().await;
    let hub = RunningHub::start(hub_config(temp.path().join("hub.db")), true).await;

    let mut client = hub.client();
    client.initialize().await;
    subscribe(
        &mut client,
        &receiver,
        "t3.run.completed",
        json!({"environment_id": "env-pending-snapshot"}),
    )
    .await;

    let mut fixture = Fixture::new();
    fixture.seed_project_thread();
    fixture.seed_existing_completed_run();

    let proxy = HttpProxy::start(hub.address).await;
    proxy.set_fail(true);
    let edge = RunningEdge::start(edge_config(
        temp.path().join("edge-pending-snapshot.db"),
        fixture.path(),
        "env-pending-snapshot",
        proxy.url(),
    ));

    // The hub applies the snapshot, but the edge never sees the 2xx.
    wait_until("snapshot applied before response loss", || {
        hub.hub
            .repository()
            .get_t3_run("run-old", Some("env-pending-snapshot"))
            .ok()
            .flatten()
            .is_some()
    })
    .await;
    wait_until("pending snapshot persisted", || {
        edge.repository()
            .get_edge_pending_snapshot("env-pending-snapshot")
            .ok()
            .flatten()
            .is_some()
    })
    .await;

    // A run completes while the edge still believes the snapshot failed.
    fixture.emit_completed_run("run-after-snapshot", 2);
    proxy.set_fail(false);

    wait_until("run after snapshot forwarded", || {
        hub.hub
            .repository()
            .get_t3_run("run-after-snapshot", Some("env-pending-snapshot"))
            .ok()
            .flatten()
            .is_some()
    })
    .await;
    wait_until("run completed delivery", || {
        receiver.events().iter().any(|event| {
            event.event_name.as_deref() == Some("t3.run.completed")
                && event.data["run_id"] == "run-after-snapshot"
        })
    })
    .await;
    wait_until("edge cursor catches up", || {
        edge.repository()
            .get_t3_cursor("env-pending-snapshot")
            .ok()
            .flatten()
            == Some(6)
    })
    .await;
    assert!(
        edge.repository()
            .get_edge_pending_snapshot("env-pending-snapshot")
            .unwrap()
            .is_none(),
        "the acknowledged pending snapshot must be cleared"
    );

    edge.stop().await;
    hub.stop().await;
}

#[tokio::test]
async fn edge_restart_resends_the_persisted_pending_snapshot() {
    init_env();
    let temp = TempDir::new().unwrap();
    let receiver = MockReceiver::start().await;
    let hub = RunningHub::start(hub_config(temp.path().join("hub.db")), true).await;

    let mut client = hub.client();
    client.initialize().await;
    subscribe(
        &mut client,
        &receiver,
        "t3.run.completed",
        json!({"environment_id": "env-restart-pending"}),
    )
    .await;

    let mut fixture = Fixture::new();
    fixture.seed_project_thread();
    fixture.seed_existing_completed_run();

    let proxy = HttpProxy::start(hub.address).await;
    proxy.set_fail(true);
    let config = edge_config(
        temp.path().join("edge-restart-pending.db"),
        fixture.path(),
        "env-restart-pending",
        proxy.url(),
    );
    let first = RunningEdge::start(config.clone());
    wait_until("snapshot applied before restart", || {
        hub.hub
            .repository()
            .get_t3_run("run-old", Some("env-restart-pending"))
            .ok()
            .flatten()
            .is_some()
    })
    .await;
    wait_until("pending snapshot persisted before restart", || {
        first
            .repository()
            .get_edge_pending_snapshot("env-restart-pending")
            .ok()
            .flatten()
            .is_some()
    })
    .await;
    fixture.emit_completed_run("run-after-restart-pending", 2);
    first.stop().await;

    proxy.set_fail(false);
    let second = RunningEdge::start(config);
    wait_until("restarted edge forwards the pending snapshot", || {
        hub.hub
            .repository()
            .get_t3_run("run-after-restart-pending", Some("env-restart-pending"))
            .ok()
            .flatten()
            .is_some()
    })
    .await;
    wait_until("restarted edge delivery", || {
        receiver.events().iter().any(|event| {
            event.event_name.as_deref() == Some("t3.run.completed")
                && event.data["run_id"] == "run-after-restart-pending"
        })
    })
    .await;
    assert!(
        second
            .repository()
            .get_edge_pending_snapshot("env-restart-pending")
            .unwrap()
            .is_none()
    );

    second.stop().await;
    hub.stop().await;
}

#[tokio::test]
async fn stale_batch_does_not_rewind_projection_or_cursor() {
    init_env();
    let temp = TempDir::new().unwrap();
    let hub = RunningHub::start(hub_config(temp.path().join("hub.db")), false).await;
    let client = reqwest::Client::new();
    let endpoint = format!("{}/internal/edge/t3", hub.base_url);
    let now = chrono::Utc::now().timestamp();
    let environment_id = "env-stale";

    let completed = T3WriteBatch {
        environment_id: environment_id.into(),
        sequence: 5,
        run: Some(sample_run(environment_id, "run-stale", "completed")),
        ..Default::default()
    };
    let response = post_edge_request(
        &client,
        &endpoint,
        "edge-stale",
        "nonce-stale-1",
        now,
        &EdgeT3IngestRequest::Batches {
            batches: vec![completed],
        },
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    // A retried older batch with a fresh nonce must be a no-op.
    let stale = T3WriteBatch {
        environment_id: environment_id.into(),
        sequence: 3,
        run: Some(sample_run(environment_id, "run-stale", "running")),
        ..Default::default()
    };
    let response = post_edge_request(
        &client,
        &endpoint,
        "edge-stale",
        "nonce-stale-2",
        now,
        &EdgeT3IngestRequest::Batches {
            batches: vec![stale],
        },
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let run = hub
        .hub
        .repository()
        .get_t3_run("run-stale", Some(environment_id))
        .unwrap()
        .expect("run exists");
    assert_eq!(run.run.status, "completed");
    assert_eq!(
        hub.hub.repository().get_t3_cursor(environment_id).unwrap(),
        Some(5)
    );

    hub.stop().await;
}

#[tokio::test]
async fn batch_projection_environment_mismatch_is_rejected_without_state_change() {
    init_env();
    let temp = TempDir::new().unwrap();
    let hub = RunningHub::start(hub_config(temp.path().join("hub.db")), false).await;
    let client = reqwest::Client::new();
    let endpoint = format!("{}/internal/edge/t3", hub.base_url);
    let now = chrono::Utc::now().timestamp();

    let mismatched_run = T3WriteBatch {
        environment_id: "env-a".into(),
        sequence: 1,
        run: Some(sample_run("env-b", "run-mismatch", "completed")),
        ..Default::default()
    };
    let response = post_edge_request(
        &client,
        &endpoint,
        "edge-mismatch",
        "nonce-mismatch-1",
        now,
        &EdgeT3IngestRequest::Batches {
            batches: vec![mismatched_run],
        },
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let mismatched_event = T3WriteBatch {
        environment_id: "env-a".into(),
        sequence: 1,
        events: vec![NewEvent {
            id: Some("evt_env_mismatch".into()),
            source: Some("t3".into()),
            kind: "t3.run.completed".into(),
            payload: json!({
                "environment_id": "env-b",
                "project_id": "p1",
                "thread_id": "t1",
                "run_id": "run-mismatch",
                "summary": "mismatch"
            }),
            occurred_at: Some("2026-11-16T02:30:00.000Z".into()),
        }],
        ..Default::default()
    };
    let response = post_edge_request(
        &client,
        &endpoint,
        "edge-mismatch",
        "nonce-mismatch-2",
        now,
        &EdgeT3IngestRequest::Batches {
            batches: vec![mismatched_event],
        },
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

    assert!(
        hub.hub
            .repository()
            .get_t3_run("run-mismatch", Some("env-a"))
            .unwrap()
            .is_none()
    );
    assert!(
        hub.hub
            .repository()
            .get_t3_run("run-mismatch", Some("env-b"))
            .unwrap()
            .is_none()
    );
    assert_eq!(hub.hub.repository().get_t3_cursor("env-a").unwrap(), None);
    assert!(
        hub.hub
            .repository()
            .get_event("evt_env_mismatch")
            .unwrap()
            .is_none()
    );

    hub.stop().await;
}

#[tokio::test]
async fn large_snapshot_is_uploaded_in_chunks_and_committed_atomically() {
    init_env();
    let temp = TempDir::new().unwrap();
    let hub = RunningHub::start(hub_config(temp.path().join("hub.db")), false).await;
    let proxy = HttpProxy::start(hub.address).await;

    let mut fixture = Fixture::new();
    fixture.seed_large_snapshot(20);
    let mut config = edge_config(
        temp.path().join("edge-chunked.db"),
        fixture.path(),
        "env-chunked",
        proxy.url(),
    );
    config.edge.max_snapshot_chunk_bytes = 1024;

    let edge = Edge::new(&config).expect("edge builds");
    let summary = edge.sync_once().await.expect("chunked snapshot sync");
    assert!(summary.snapshot);
    assert!(
        proxy.requests() > 2,
        "a large snapshot must use multiple chunk requests, saw {}",
        proxy.requests()
    );
    assert!(
        edge.repository()
            .get_edge_pending_snapshot("env-chunked")
            .unwrap()
            .is_none()
    );
    assert_eq!(
        edge.repository().get_t3_cursor("env-chunked").unwrap(),
        Some(0)
    );

    let conn = Connection::open(temp.path().join("hub.db")).unwrap();
    for (table, expected) in [
        ("t3_projects", 20),
        ("t3_threads", 20),
        ("t3_runs", 20),
        ("t3_approvals", 20),
    ] {
        let count: i64 = conn
            .query_row(
                &format!("SELECT COUNT(*) FROM {table} WHERE environment_id = 'env-chunked'"),
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, expected, "{table}");
    }

    hub.stop().await;
}

#[tokio::test]
async fn snapshot_commit_with_missing_chunks_is_rejected_atomically() {
    init_env();
    let temp = TempDir::new().unwrap();
    let hub = RunningHub::start(hub_config(temp.path().join("hub.db")), false).await;
    let client = reqwest::Client::new();
    let endpoint = format!("{}/internal/edge/t3", hub.base_url);
    let now = chrono::Utc::now().timestamp();
    let environment_id = "env-missing-chunk";
    let snapshot_id = "snap-missing";

    let first_chunk = T3Snapshot {
        projects: vec![sample_project(environment_id, "p1")],
        threads: vec![sample_thread(environment_id, "t1", "p1")],
        ..Default::default()
    };
    let response = post_edge_request(
        &client,
        &endpoint,
        "edge-missing",
        "nonce-missing-1",
        now,
        &EdgeT3IngestRequest::SnapshotChunk {
            environment_id: environment_id.into(),
            snapshot_id: snapshot_id.into(),
            chunk_index: 0,
            snapshot: first_chunk,
        },
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let response = post_edge_request(
        &client,
        &endpoint,
        "edge-missing",
        "nonce-missing-2",
        now,
        &EdgeT3IngestRequest::SnapshotCommit {
            environment_id: environment_id.into(),
            snapshot_id: snapshot_id.into(),
            max_sequence: 0,
            total_chunks: 2,
        },
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        hub.hub.repository().get_t3_cursor(environment_id).unwrap(),
        None
    );
    let conn = Connection::open(temp.path().join("hub.db")).unwrap();
    let projects: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM t3_projects WHERE environment_id = ?1",
            params![environment_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(projects, 0, "a missing chunk must not apply any projection");

    let second_chunk = T3Snapshot {
        runs: vec![sample_run(environment_id, "r1", "completed")],
        approvals: vec![sample_approval(environment_id, "a1", "r1")],
        ..Default::default()
    };
    let response = post_edge_request(
        &client,
        &endpoint,
        "edge-missing",
        "nonce-missing-3",
        now,
        &EdgeT3IngestRequest::SnapshotChunk {
            environment_id: environment_id.into(),
            snapshot_id: snapshot_id.into(),
            chunk_index: 1,
            snapshot: second_chunk,
        },
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let response = post_edge_request(
        &client,
        &endpoint,
        "edge-missing",
        "nonce-missing-4",
        now,
        &EdgeT3IngestRequest::SnapshotCommit {
            environment_id: environment_id.into(),
            snapshot_id: snapshot_id.into(),
            max_sequence: 0,
            total_chunks: 2,
        },
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        hub.hub.repository().get_t3_cursor(environment_id).unwrap(),
        Some(0)
    );
    let projects: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM t3_projects WHERE environment_id = ?1",
            params![environment_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(projects, 1);

    hub.stop().await;
}

#[tokio::test]
async fn edge_timestamp_extremes_do_not_panic() {
    init_env();
    let temp = TempDir::new().unwrap();
    let mut config = hub_config(temp.path().join("hub.db"));
    config.server.edge_max_skew_secs = 300;
    let hub = RunningHub::start(config, false).await;
    let client = reqwest::Client::new();
    let endpoint = format!("{}/internal/edge/t3", hub.base_url);
    let now = chrono::Utc::now().timestamp();
    let request = EdgeT3IngestRequest::Batches {
        batches: vec![T3WriteBatch {
            environment_id: "env-time".into(),
            sequence: 1,
            ..Default::default()
        }],
    };

    for (index, timestamp) in [i64::MIN, i64::MAX, now + 3600].into_iter().enumerate() {
        let response = post_edge_request(
            &client,
            &endpoint,
            "edge-time",
            &format!("nonce-time-{index}"),
            timestamp,
            &request,
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "timestamp {timestamp} must be rejected"
        );
    }

    let response = post_edge_request(
        &client,
        &endpoint,
        "edge-time",
        "nonce-time-boundary",
        now + 300,
        &request,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    hub.stop().await;
}

#[tokio::test]
async fn edge_cancellation_stops_backlog_and_keeps_acknowledged_cursor() {
    init_env();
    let temp = TempDir::new().unwrap();
    let hub = RunningHub::start(hub_config(temp.path().join("hub.db")), false).await;
    let proxy = HttpProxy::start(hub.address).await;
    proxy.set_delay_ms(20);

    let mut fixture = Fixture::new();
    fixture.seed_project_thread();
    fixture.seed_existing_completed_run();
    let edge = RunningEdge::start(edge_config(
        temp.path().join("edge-cancel.db"),
        fixture.path(),
        "env-cancel",
        proxy.url(),
    ));
    wait_until("snapshot before backlog", || {
        hub.hub
            .repository()
            .get_t3_run("run-old", Some("env-cancel"))
            .ok()
            .flatten()
            .is_some()
    })
    .await;

    for index in 0..100 {
        fixture.emit_completed_run(&format!("run-cancel-{index}"), index + 2);
    }
    wait_until("first backlog run", || {
        hub.hub
            .repository()
            .get_t3_run("run-cancel-0", Some("env-cancel"))
            .ok()
            .flatten()
            .is_some()
    })
    .await;

    let edge_repo = edge.repository().clone();
    edge.cancellation.cancel();
    timeout(Duration::from_secs(5), edge.task)
        .await
        .expect("edge stops promptly")
        .expect("edge task");

    let edge_cursor = edge_repo.get_t3_cursor("env-cancel").unwrap();
    let hub_cursor = hub.hub.repository().get_t3_cursor("env-cancel").unwrap();
    assert_eq!(edge_cursor, hub_cursor);
    assert!(
        edge_cursor.unwrap() < 204,
        "cancellation should stop before the whole backlog"
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(edge_repo.get_t3_cursor("env-cancel").unwrap(), edge_cursor);

    hub.stop().await;
}

#[tokio::test]
async fn hostname_fallback_requires_an_explicit_environment_id_when_unresolved() {
    init_env();
    let temp = TempDir::new().unwrap();
    let mut config = Config::default();
    config.collectors.t3.state_db_path = temp.path().join("statev2.sqlite");
    config.collectors.t3.environment_id = None;
    config.collectors.t3.environment_id_path = None;

    let error = events_bridge::collectors::T3CollectorSettings::
        from_config_with_hostname_fallback_and_hostname(&config, None)
        .expect_err("unresolved host name must fail");
    assert!(
        error.to_string().contains("collectors.t3.environment_id"),
        "{error}"
    );

    let settings = events_bridge::collectors::T3CollectorSettings::
        from_config_with_hostname_fallback_and_hostname(&config, Some("build-host".into()))
        .expect("resolved host name");
    assert_eq!(settings.environment_id, "build-host");
}

#[tokio::test]
async fn github_poll_reconciliation_emits_merged_and_failed_events() {
    init_env();
    let temp = TempDir::new().unwrap();
    let receiver = MockReceiver::start().await;
    let api = MockGitHubApi::start().await;
    api.set_pulls(vec![pull_payload(1, false, "2026-11-16T03:00:00.000Z")]);
    api.set_runs(vec![run_payload(
        8001,
        "success",
        "2026-11-16T03:00:00.000Z",
    )]);

    let hub = RunningHub::start(
        hub_config_with_poll(temp.path().join("hub.db"), api.url()),
        true,
    )
    .await;
    let mut client = hub.client();
    client.initialize().await;
    subscribe(
        &mut client,
        &receiver,
        "github.pr.merged",
        json!({"repository": REPOSITORY}),
    )
    .await;
    subscribe(
        &mut client,
        &receiver,
        "github.workflow.failed",
        json!({"repository": REPOSITORY}),
    )
    .await;

    wait_until("initial poll baseline", || {
        hub.hub
            .repository()
            .github_status(&events_bridge::store::GitHubStatusQuery {
                repository: Some(REPOSITORY.into()),
                limit: 10,
                ..Default::default()
            })
            .map(|status| !status.pull_requests.is_empty())
            .unwrap_or(false)
    })
    .await;

    api.set_pulls(vec![pull_payload(1, true, "2026-11-16T03:10:00.000Z")]);
    api.set_runs(vec![
        run_payload(8001, "success", "2026-11-16T03:00:00.000Z"),
        run_payload(8002, "failure", "2026-11-16T03:10:00.000Z"),
    ]);

    wait_until("poll events", || {
        let events = receiver.events();
        events
            .iter()
            .any(|event| event.event_name.as_deref() == Some("github.pr.merged"))
            && events
                .iter()
                .any(|event| event.event_name.as_deref() == Some("github.workflow.failed"))
    })
    .await;

    let status = client
        .tool_call("get_github_status", json!({"repository": REPOSITORY}))
        .await;
    let structured = &status["structuredContent"];
    assert_eq!(structured["pullRequests"][0]["merged"], true);
    assert!(
        structured["ciRuns"]
            .as_array()
            .unwrap()
            .iter()
            .any(|run| run["conclusion"] == "failure")
    );

    hub.stop().await;
}

async fn send_line(writer: &mut DuplexStream, value: Value) {
    let line = serde_json::to_string(&value).unwrap();
    writer.write_all(line.as_bytes()).await.unwrap();
    writer.write_all(b"\n").await.unwrap();
    writer.flush().await.unwrap();
}

#[tokio::test]
async fn stdio_surface_serves_tools_and_events() {
    init_env();
    let temp = TempDir::new().unwrap();
    let receiver = MockReceiver::start().await;
    let api = MockGitHubApi::start().await;
    api.set_pulls(vec![pull_payload(1, false, "2026-11-16T03:00:00.000Z")]);
    api.set_runs(vec![run_payload(
        8001,
        "success",
        "2026-11-16T03:00:00.000Z",
    )]);

    let mut fixture = Fixture::new();
    fixture.seed_project_thread();
    fixture.seed_existing_completed_run();

    let mut config = Config::for_tests(temp.path().join("stdio.db"));
    config.collectors.t3.enabled = true;
    config.collectors.t3.state_db_path = fixture.path().to_path_buf();
    config.collectors.t3.environment_id = Some("env-stdio".into());
    config.collectors.t3.poll_interval_ms = 50;
    config.collectors.t3.watch_wal = false;
    config.collectors.t3.batch_size = 100;
    config.collectors.github.poll_enabled = true;
    config.collectors.github.repositories = vec![REPOSITORY.into()];
    config.collectors.github.api_base_url = api.url().to_string();
    config.collectors.github.poll_interval_secs = 1;

    let (server_reader, mut client_writer) = tokio::io::duplex(1024 * 1024);
    let (mut client_reader, server_writer) = tokio::io::duplex(1024 * 1024);
    let server = tokio::spawn(async move {
        events_bridge::transport::stdio::serve_with_io(
            config,
            CallbackPolicy::for_tests(),
            server_reader,
            server_writer,
        )
        .await
    });

    let mut lines = BufReader::new(&mut client_reader).lines();

    send_line(
        &mut client_writer,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "stdio-e2e", "version": "1.0.0"}
            }
        }),
    )
    .await;
    let initialized: Value =
        serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
    assert!(initialized.pointer("/result/capabilities/tools").is_some());

    send_line(
        &mut client_writer,
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    )
    .await;

    send_line(
        &mut client_writer,
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
    )
    .await;
    let tools: Value = serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
    let names: Vec<_> = tools["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    assert_eq!(names.len(), 6);
    for expected in [
        "list_events",
        "get_event",
        "get_t3_run",
        "get_t3_approvals",
        "get_github_status",
        "ack_events",
    ] {
        assert!(names.contains(&expected), "missing tool {expected}");
    }

    send_line(
        &mut client_writer,
        json!({"jsonrpc": "2.0", "id": 3, "method": "events/list", "params": {}}),
    )
    .await;
    let events: Value = serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
    assert_eq!(events["result"]["events"].as_array().unwrap().len(), 6);

    send_line(
        &mut client_writer,
        json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "events/subscribe",
            "params": {
                "name": "t3.run.completed",
                "arguments": {"environment_id": "env-stdio"},
                "delivery": {
                    "mode": "webhook",
                    "url": receiver.endpoint(),
                    "secret": WEBHOOK_SECRET
                }
            }
        }),
    )
    .await;
    let subscribed: Value =
        serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
    let subscription_id = subscribed["result"]["id"]
        .as_str()
        .expect("subscription id")
        .to_string();

    fixture.emit_completed_run("run-stdio-1", 2);
    fixture.emit_pending_approval("approval-stdio-1", "run-stdio-1");
    wait_until("stdio collector delivery", || {
        receiver.events().iter().any(|event| {
            event.event_name.as_deref() == Some("t3.run.completed")
                && event.data["run_id"] == "run-stdio-1"
        })
    })
    .await;

    send_line(
        &mut client_writer,
        json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {"name": "list_events", "arguments": {"limit": 10}}
        }),
    )
    .await;
    let listed: Value = serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
    let event_id = listed["result"]["structuredContent"]["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|event| event["kind"] == "t3.run.completed")
        .and_then(|event| event["id"].as_str())
        .expect("t3.run.completed event")
        .to_string();

    send_line(
        &mut client_writer,
        json!({
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {"name": "get_event", "arguments": {"event_id": event_id}}
        }),
    )
    .await;
    let fetched: Value = serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
    assert_eq!(
        fetched["result"]["structuredContent"]["event"]["id"],
        event_id
    );

    send_line(
        &mut client_writer,
        json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {
                "name": "get_t3_run",
                "arguments": {"run_id": "run-stdio-1", "environment_id": "env-stdio"}
            }
        }),
    )
    .await;
    let run: Value = serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
    assert_eq!(
        run["result"]["structuredContent"]["run"]["status"],
        "completed"
    );

    send_line(
        &mut client_writer,
        json!({
            "jsonrpc": "2.0",
            "id": 8,
            "method": "tools/call",
            "params": {
                "name": "get_t3_approvals",
                "arguments": {"environment_id": "env-stdio", "status": "pending"}
            }
        }),
    )
    .await;
    let approvals: Value =
        serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
    assert_eq!(
        approvals["result"]["structuredContent"]["approvals"]
            .as_array()
            .unwrap()
            .len(),
        1
    );

    // Wait for the GitHub poller baseline, then exercise the status tool.
    let mut github = Value::Null;
    for _ in 0..100 {
        send_line(
            &mut client_writer,
            json!({
                "jsonrpc": "2.0",
                "id": 9,
                "method": "tools/call",
                "params": {
                    "name": "get_github_status",
                    "arguments": {"repository": REPOSITORY}
                }
            }),
        )
        .await;
        github = serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
        if github["result"]["structuredContent"]["pullRequests"]
            .as_array()
            .is_some_and(|rows| !rows.is_empty())
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(
        github["result"]["structuredContent"]["pullRequests"]
            .as_array()
            .unwrap()
            .len(),
        1
    );

    send_line(
        &mut client_writer,
        json!({
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {"name": "ack_events", "arguments": {"event_ids": [event_id]}}
        }),
    )
    .await;
    let acked: Value = serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
    assert_eq!(
        acked["result"]["structuredContent"]["acknowledged"]
            .as_array()
            .unwrap()
            .len(),
        1
    );

    send_line(
        &mut client_writer,
        json!({
            "jsonrpc": "2.0",
            "id": 11,
            "method": "events/unsubscribe",
            "params": {"id": subscription_id}
        }),
    )
    .await;
    let unsubscribed: Value =
        serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
    assert!(unsubscribed["result"].is_object(), "{unsubscribed}");

    let deliveries_before = receiver.deliveries();
    fixture.emit_completed_run("run-stdio-2", 3);

    // The collector still runs after unsubscribe; only delivery stops.
    let mut second_run_seen = false;
    for _ in 0..100 {
        send_line(
            &mut client_writer,
            json!({
                "jsonrpc": "2.0",
                "id": 12,
                "method": "tools/call",
                "params": {
                    "name": "get_t3_run",
                    "arguments": {"run_id": "run-stdio-2", "environment_id": "env-stdio"}
                }
            }),
        )
        .await;
        let second: Value =
            serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
        if second["result"]["structuredContent"]["run"]["runId"] == "run-stdio-2" {
            second_run_seen = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        second_run_seen,
        "collector must keep running after unsubscribe"
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        receiver.deliveries(),
        deliveries_before,
        "unsubscribed events must not be delivered"
    );

    drop(client_writer);
    drop(lines);
    let result = timeout(Duration::from_secs(5), server)
        .await
        .expect("stdio server exits on EOF")
        .expect("stdio task");
    assert!(result.is_ok(), "stdio server failed: {result:?}");
}

#[tokio::test]
async fn oversized_single_entity_snapshot_syncs_via_snapshot_part_and_commit() {
    init_env();
    let temp = TempDir::new().unwrap();
    let hub = RunningHub::start(hub_config(temp.path().join("hub.db")), false).await;
    let proxy = HttpProxy::start(hub.address).await;

    let long_error = "E".repeat(4_000);
    let mut fixture = Fixture::new();
    fixture.seed_project_thread();
    fixture.seed_failed_run_with_error("run-oversized", &long_error);

    let mut config = edge_config(
        temp.path().join("edge-oversized.db"),
        fixture.path(),
        "env-oversized",
        proxy.url(),
    );
    config.edge.max_snapshot_chunk_bytes = 1024;

    let edge = Edge::new(&config).expect("edge builds");
    let summary = edge.sync_once().await.expect("oversized snapshot sync");
    assert!(summary.snapshot);
    assert!(
        proxy.requests() >= 4,
        "oversized entity snapshot must be split into SnapshotPart requests + SnapshotCommit, saw {} requests",
        proxy.requests()
    );
    assert!(
        edge.repository()
            .get_edge_pending_snapshot("env-oversized")
            .unwrap()
            .is_none()
    );
    assert_eq!(
        edge.repository().get_t3_cursor("env-oversized").unwrap(),
        Some(3)
    );
    assert_eq!(
        hub.hub.repository().get_t3_cursor("env-oversized").unwrap(),
        Some(3)
    );
    assert_eq!(
        hub.hub.repository().count_edge_snapshot_stages().unwrap(),
        0
    );

    let stored = hub
        .hub
        .repository()
        .get_t3_run("run-oversized", Some("env-oversized"))
        .unwrap()
        .expect("oversized run synced to hub");
    assert_eq!(stored.run.status, "failed");
    assert_eq!(stored.run.error.as_deref(), Some(long_error.as_str()));

    fixture.emit_completed_run("run-after-oversized", 2);
    let follow_up = edge
        .sync_once()
        .await
        .expect("incremental sync after oversized snapshot");
    assert!(!follow_up.snapshot);
    assert_eq!(follow_up.processed, 2);
    assert!(
        hub.hub
            .repository()
            .get_t3_run("run-after-oversized", Some("env-oversized"))
            .unwrap()
            .is_some()
    );

    hub.stop().await;
}

#[tokio::test]
async fn abandoned_snapshot_stages_are_pruned_after_ttl_on_hub() {
    init_env();
    let temp = TempDir::new().unwrap();
    let mut config = hub_config(temp.path().join("hub.db"));
    config.server.edge_stage_ttl_secs = 1;
    let hub = RunningHub::start(config, false).await;
    let client = reqwest::Client::new();
    let endpoint = format!("{}/internal/edge/t3", hub.base_url);
    let now = chrono::Utc::now().timestamp();

    let invalid_part = post_edge_request(
        &client,
        &endpoint,
        "edge-ttl",
        "nonce-ttl-invalid",
        now,
        &EdgeT3IngestRequest::SnapshotPart {
            environment_id: "env-ttl".into(),
            snapshot_id: "snap-invalid".into(),
            chunk_index: 0,
            data: "not-valid-base64!!!".into(),
        },
    )
    .await;
    assert_eq!(invalid_part.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        hub.hub.repository().count_edge_snapshot_stages().unwrap(),
        0
    );

    let abandoned = post_edge_request(
        &client,
        &endpoint,
        "edge-ttl",
        "nonce-ttl-1",
        now,
        &EdgeT3IngestRequest::SnapshotChunk {
            environment_id: "env-abandoned".into(),
            snapshot_id: "snap-abandoned".into(),
            chunk_index: 0,
            snapshot: T3Snapshot {
                projects: vec![sample_project("env-abandoned", "p-abandoned")],
                ..Default::default()
            },
        },
    )
    .await;
    assert_eq!(abandoned.status(), StatusCode::OK);
    assert_eq!(
        hub.hub.repository().count_edge_snapshot_stages().unwrap(),
        1
    );

    tokio::time::sleep(Duration::from_millis(1_250)).await;

    let now_after = chrono::Utc::now().timestamp();
    let fresh_chunk_0 = post_edge_request(
        &client,
        &endpoint,
        "edge-ttl",
        "nonce-ttl-2",
        now_after,
        &EdgeT3IngestRequest::SnapshotChunk {
            environment_id: "env-fresh".into(),
            snapshot_id: "snap-fresh".into(),
            chunk_index: 0,
            snapshot: T3Snapshot {
                projects: vec![sample_project("env-fresh", "p-fresh")],
                ..Default::default()
            },
        },
    )
    .await;
    assert_eq!(fresh_chunk_0.status(), StatusCode::OK);
    assert_eq!(
        hub.hub.repository().count_edge_snapshot_stages().unwrap(),
        1,
        "expired abandoned stage must be pruned while the fresh chunk remains staged"
    );

    // Progressively upload chunks at 0.6s intervals with a 1s TTL so total
    // upload time exceeds TTL while per-chunk gaps stay within TTL.
    tokio::time::sleep(Duration::from_millis(600)).await;
    let fresh_chunk_1 = post_edge_request(
        &client,
        &endpoint,
        "edge-ttl",
        "nonce-ttl-3",
        chrono::Utc::now().timestamp(),
        &EdgeT3IngestRequest::SnapshotChunk {
            environment_id: "env-fresh".into(),
            snapshot_id: "snap-fresh".into(),
            chunk_index: 1,
            snapshot: T3Snapshot {
                threads: vec![sample_thread("env-fresh", "t-fresh", "p-fresh")],
                ..Default::default()
            },
        },
    )
    .await;
    assert_eq!(fresh_chunk_1.status(), StatusCode::OK);

    tokio::time::sleep(Duration::from_millis(600)).await;
    let fresh_chunk_2 = post_edge_request(
        &client,
        &endpoint,
        "edge-ttl",
        "nonce-ttl-4",
        chrono::Utc::now().timestamp(),
        &EdgeT3IngestRequest::SnapshotChunk {
            environment_id: "env-fresh".into(),
            snapshot_id: "snap-fresh".into(),
            chunk_index: 2,
            snapshot: T3Snapshot {
                runs: vec![sample_run("env-fresh", "r-fresh", "completed")],
                ..Default::default()
            },
        },
    )
    .await;
    assert_eq!(fresh_chunk_2.status(), StatusCode::OK);
    assert_eq!(
        hub.hub.repository().count_edge_snapshot_stages().unwrap(),
        3,
        "active multi-chunk upload must retain chunk 0 across >1s total duration"
    );

    let commit = post_edge_request(
        &client,
        &endpoint,
        "edge-ttl",
        "nonce-ttl-5",
        chrono::Utc::now().timestamp(),
        &EdgeT3IngestRequest::SnapshotCommit {
            environment_id: "env-fresh".into(),
            snapshot_id: "snap-fresh".into(),
            max_sequence: 0,
            total_chunks: 3,
        },
    )
    .await;
    assert_eq!(commit.status(), StatusCode::OK);
    assert_eq!(
        hub.hub.repository().count_edge_snapshot_stages().unwrap(),
        0
    );
    assert_eq!(
        hub.hub.repository().get_t3_cursor("env-fresh").unwrap(),
        Some(0)
    );
    assert!(
        hub.hub
            .repository()
            .get_t3_run("r-fresh", Some("env-fresh"))
            .unwrap()
            .is_some()
    );
    assert_eq!(
        hub.hub.repository().get_t3_cursor("env-abandoned").unwrap(),
        None
    );

    hub.stop().await;
}

#[tokio::test]
async fn stdio_partial_startup_failure_cleans_up_t3_collector() {
    init_env();
    let temp = TempDir::new().unwrap();
    let db_path = temp.path().join("stdio-fail.db");
    let mut fixture = Fixture::new();
    fixture.seed_project_thread();
    fixture.seed_existing_completed_run();

    let mut config = Config::for_tests(db_path.clone());
    config.collectors.t3.enabled = true;
    config.collectors.t3.state_db_path = fixture.path().to_path_buf();
    config.collectors.t3.environment_id = Some("env-stdio-fail".into());
    config.collectors.t3.poll_interval_ms = 50;
    config.collectors.github.poll_enabled = true;
    config.collectors.github.repositories = vec![REPOSITORY.into()];
    // Non-empty token with a newline passes `AppState::new` and fails inside
    // `hub::spawn_github_poller` after `hub::spawn_t3_collector` has already
    // started, exercising the cancel + join cleanup path.
    config.collectors.github.token_env = Some(INVALID_GITHUB_TOKEN_ENV.into());

    let (server_reader, _client_writer) = tokio::io::duplex(4096);
    let (_client_reader, server_writer) = tokio::io::duplex(4096);
    let error = events_bridge::transport::stdio::serve_with_io(
        config,
        CallbackPolicy::for_tests(),
        server_reader,
        server_writer,
    )
    .await
    .expect_err("invalid github token header must fail spawn_github_poller");
    assert!(error.to_string().contains("invalid in a header"), "{error}");

    let repo = Repository::open(&db_path).unwrap();
    assert!(
        repo.get_t3_run("run-old", Some("env-stdio-fail"))
            .unwrap()
            .is_some(),
        "t3_collector must have started and captured its initial snapshot before poller failure"
    );

    // Ensure the cancelled collector is no longer running and writing new events.
    fixture.emit_completed_run("run-after-failed-startup", 2);
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(
        repo.get_t3_run("run-after-failed-startup", Some("env-stdio-fail"))
            .unwrap()
            .is_none(),
        "cancelled t3_collector must have stopped before serve_with_io returned"
    );
}

#[tokio::test]
async fn edge_nonce_replay_is_rejected_on_the_skew_boundary_second() {
    init_env();
    let temp = TempDir::new().unwrap();
    let mut config = hub_config(temp.path().join("hub.db"));
    config.server.edge_max_skew_secs = 1;
    let hub = RunningHub::start(config, false).await;
    let client = reqwest::Client::new();
    let endpoint = format!("{}/internal/edge/t3", hub.base_url);

    // Align to the first half of a second so both the initial request at `t`
    // and the boundary requests at `t + 2` land cleanly inside their target
    // seconds.
    let now_dt = chrono::Utc::now();
    let subsec_ms = now_dt.timestamp_subsec_millis();
    if subsec_ms > 400 {
        tokio::time::sleep(Duration::from_millis(1020 - u64::from(subsec_ms))).await;
    }
    let t = chrono::Utc::now().timestamp();

    let request = EdgeT3IngestRequest::Batches {
        batches: vec![T3WriteBatch {
            environment_id: "env-skew-boundary".into(),
            sequence: 5,
            run: Some(sample_run("env-skew-boundary", "run-skew", "completed")),
            ..Default::default()
        }],
    };
    let response = post_edge_request(
        &client,
        &endpoint,
        "edge-skew-boundary",
        "nonce-skew-boundary",
        t + 1,
        &request,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    // Wait until `t + 2`, the exact upper skew boundary for timestamp `t + 1`.
    loop {
        if chrono::Utc::now().timestamp() >= t + 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    // Trigger nonce pruning at `t + 2`: `nonce-skew-boundary` has
    // `expires_at = t + 2`, so it must NOT be pruned yet.
    let unrelated = EdgeT3IngestRequest::Batches {
        batches: vec![T3WriteBatch {
            environment_id: "env-skew-boundary".into(),
            sequence: 6,
            ..Default::default()
        }],
    };
    let prune_trigger = post_edge_request(
        &client,
        &endpoint,
        "edge-skew-boundary",
        "nonce-prune-trigger",
        t + 2,
        &unrelated,
    )
    .await;
    assert_eq!(prune_trigger.status(), StatusCode::OK);

    // Replaying the original request at `t + 2` still passes the timestamp
    // window (`abs_diff(t + 2, t + 1) == 1`), so it must be rejected by the
    // retained nonce rather than re-accepted. Assert the exact error message
    // so a late timestamp-window failure cannot masquerade as replay rejection.
    let replay = post_edge_request(
        &client,
        &endpoint,
        "edge-skew-boundary",
        "nonce-skew-boundary",
        t + 1,
        &request,
    )
    .await;
    assert_eq!(
        replay.status(),
        StatusCode::UNAUTHORIZED,
        "replay at the upper skew boundary second must still be rejected"
    );
    let replay_body: Value = replay.json().await.unwrap();
    assert_eq!(
        replay_body["error"], "replayed X-Edge-Nonce",
        "unexpected rejection reason: {replay_body}"
    );

    hub.stop().await;
}
