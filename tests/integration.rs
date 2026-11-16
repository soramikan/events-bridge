//! End-to-end tests for the hub HTTP surface, subscription verification,
//! signed webhook delivery, retries, and restart recovery.
//!
//! The mock receiver is a real HTTP server on loopback. The hub is built with
//! `CallbackPolicy::for_tests`, which is not reachable from configuration; the
//! production SSRF policy is still exercised separately.

use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::{
    Json, Router,
    extract::{Request, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use base64::Engine;
use chrono::{Duration as ChronoDuration, Utc};
use events_bridge::{
    config::{Config, MAX_WEBHOOK_BODY_BYTES},
    delivery::verification::CallbackPolicy,
    hub::Hub,
    store::{NewEvent, NewSubscription, T3Approval, T3Project, T3Run, T3Snapshot, T3Thread},
    util::format_rfc3339,
};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::{task::JoinHandle, time::timeout};
use tokio_util::sync::CancellationToken;

/// Synthesize a valid webhook secret at runtime so no secret literal is
/// committed to the repository.
fn test_secret() -> String {
    format!(
        "whsec_{}",
        base64::engine::general_purpose::STANDARD.encode([0x11u8; 32])
    )
}

/// A distinct runtime-synthesized secret used for rotation tests.
fn rotated_test_secret() -> String {
    format!(
        "whsec_{}",
        base64::engine::general_purpose::STANDARD.encode([0x22u8; 32])
    )
}

fn t3_completed_payload() -> Value {
    json!({
        "environment_id": "linux-main",
        "project_id": "lnako",
        "thread_id": "thread-42",
        "run_id": "run-102",
        "summary": "Coding agent run completed",
        "url": "https://t3.example.com/threads/42"
    })
}

// ---------------------------------------------------------------------------
// Mock webhook receiver
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Behavior {
    Success,
    ChallengeMismatch,
    Redirect,
    FailThenSucceed(usize),
    Gone,
    PayloadTooLarge,
}

#[derive(Debug)]
struct Record {
    path: String,
    headers: HeaderMap,
    body: Vec<u8>,
    is_verification: bool,
    signature_valid: bool,
    status: u16,
}

impl Record {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|value| value.to_str().ok())
    }

    fn is_event(&self) -> bool {
        !self.is_verification
    }
}

struct ReceiverState {
    behavior: Mutex<Behavior>,
    secret: String,
    records: Mutex<Vec<Record>>,
    event_attempts: AtomicUsize,
}

impl ReceiverState {
    fn behavior(&self) -> Behavior {
        *self.behavior.lock().unwrap()
    }

    fn set_behavior(&self, behavior: Behavior) {
        *self.behavior.lock().unwrap() = behavior;
    }
}

struct MockReceiver {
    url: String,
    state: Arc<ReceiverState>,
    task: JoinHandle<()>,
}

impl MockReceiver {
    async fn start(behavior: Behavior) -> Self {
        let state = Arc::new(ReceiverState {
            behavior: Mutex::new(behavior),
            secret: test_secret(),
            records: Mutex::new(Vec::new()),
            event_attempts: AtomicUsize::new(0),
        });

        let app = Router::new()
            .route("/hook", post(receive))
            .route("/redirect", post(receive))
            .route("/second", post(receive))
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

    fn endpoint(&self, path: &str) -> String {
        format!("{}{path}", self.url)
    }

    fn records(&self) -> Vec<Record> {
        self.state.records.lock().unwrap().clone()
    }

    fn shared_state(&self) -> Arc<ReceiverState> {
        self.state.clone()
    }

    fn set_behavior(&self, behavior: Behavior) {
        self.state.set_behavior(behavior);
    }

    fn event_records(&self) -> Vec<Record> {
        self.records()
            .into_iter()
            .filter(Record::is_event)
            .collect()
    }

    fn verification_records(&self) -> Vec<Record> {
        self.records()
            .into_iter()
            .filter(|record| record.is_verification)
            .collect()
    }
}

impl Drop for MockReceiver {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Clone for Record {
    fn clone(&self) -> Self {
        Self {
            path: self.path.clone(),
            headers: self.headers.clone(),
            body: self.body.clone(),
            is_verification: self.is_verification,
            signature_valid: self.signature_valid,
            status: self.status,
        }
    }
}

async fn receive(State(state): State<Arc<ReceiverState>>, request: Request) -> Response {
    let path = request.uri().path().to_string();
    let headers = request.headers().clone();
    let body = axum::body::to_bytes(request.into_body(), 1024 * 1024)
        .await
        .unwrap()
        .to_vec();
    let parsed: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let is_verification = parsed.get("type").and_then(Value::as_str) == Some("verification");
    let signature_valid = standardwebhooks::Webhook::new(&state.secret)
        .and_then(|webhook| webhook.verify(&body, &headers))
        .is_ok();

    let behavior = state.behavior();
    let response = if is_verification {
        match behavior {
            Behavior::ChallengeMismatch => {
                json_status(StatusCode::OK, json!({"challenge": "wrong-challenge"}))
            }
            Behavior::Redirect => redirect_response(),
            _ => {
                let challenge = parsed.get("challenge").cloned().unwrap_or(Value::Null);
                json_status(StatusCode::OK, json!({"challenge": challenge}))
            }
        }
    } else {
        match behavior {
            Behavior::Gone => status_only(StatusCode::GONE),
            Behavior::PayloadTooLarge => status_only(StatusCode::PAYLOAD_TOO_LARGE),
            Behavior::Redirect => redirect_response(),
            Behavior::FailThenSucceed(failures) => {
                let attempt = state.event_attempts.fetch_add(1, Ordering::SeqCst);
                if attempt < failures {
                    status_only(StatusCode::INTERNAL_SERVER_ERROR)
                } else {
                    json_status(StatusCode::OK, json!({"ok": true}))
                }
            }
            _ => json_status(StatusCode::OK, json!({"ok": true})),
        }
    };

    state.records.lock().unwrap().push(Record {
        path,
        headers,
        body,
        is_verification,
        signature_valid,
        status: response.status().as_u16(),
    });

    response
}

fn json_status(status: StatusCode, value: Value) -> Response {
    (status, Json(value)).into_response()
}

fn status_only(status: StatusCode) -> Response {
    status.into_response()
}

fn redirect_response() -> Response {
    (
        StatusCode::FOUND,
        [(header::LOCATION, "/second")],
        "redirecting",
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Hub harness
// ---------------------------------------------------------------------------

struct RunningHub {
    hub: Arc<Hub>,
    base_url: String,
    server: JoinHandle<()>,
    dispatcher: Option<(CancellationToken, JoinHandle<()>)>,
}

impl RunningHub {
    async fn start(db_path: PathBuf, policy: CallbackPolicy, spawn_dispatcher: bool) -> Self {
        Self::start_with_config(Config::for_tests(db_path), policy, spawn_dispatcher).await
    }

    async fn start_with_config(
        config: Config,
        policy: CallbackPolicy,
        spawn_dispatcher: bool,
    ) -> Self {
        let hub = Arc::new(Hub::with_policy(config, policy).expect("hub builds"));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let router = hub.router();
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });

        let dispatcher = spawn_dispatcher.then(|| hub.spawn_dispatcher());

        Self {
            hub,
            base_url: format!("http://{address}"),
            server,
            dispatcher,
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
        self.server.abort();
        let _ = (&mut self.server).await;
    }
}

impl Drop for RunningHub {
    fn drop(&mut self) {
        if let Some((cancellation, _)) = self.dispatcher.take() {
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
        self.raw_with(body, with_protocol, &[]).await
    }

    async fn raw_with(
        &self,
        body: &Value,
        with_protocol: bool,
        extra_headers: &[(&str, &str)],
    ) -> reqwest::Response {
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
        for (name, value) in extra_headers {
            request = request.header(*name, *value);
        }
        request.send().await.expect("MCP request")
    }

    async fn raw_body(
        &self,
        body: &[u8],
        content_type: &str,
        extra_headers: &[(&str, &str)],
    ) -> reqwest::Response {
        let mut request = self
            .http
            .post(format!("{}/mcp", self.base_url))
            .header(header::ACCEPT, "application/json, text/event-stream")
            .header(header::CONTENT_TYPE, content_type)
            .body(body.to_vec());
        if let Some(session) = &self.session {
            request = request.header("Mcp-Session-Id", session);
        }
        for (name, value) in extra_headers {
            request = request.header(*name, *value);
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
                "clientInfo": {"name": "events-bridge-tests", "version": "1.0.0"}
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

async fn response_json(response: reqwest::Response) -> (StatusCode, Value) {
    let status = response.status();
    let value = response.json::<Value>().await.unwrap_or(Value::Null);
    (status, value)
}

fn rpc_result(value: Value) -> Value {
    assert!(
        value.get("error").is_none(),
        "unexpected JSON-RPC error: {value}"
    );
    value.get("result").cloned().unwrap_or(Value::Null)
}

fn rpc_error(value: &Value) -> (i64, Value) {
    let error = value
        .get("error")
        .unwrap_or_else(|| panic!("expected JSON-RPC error, got {value}"));
    (
        error.get("code").and_then(Value::as_i64).unwrap(),
        error.get("data").cloned().unwrap_or(Value::Null),
    )
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

fn temporary_database(temp: &TempDir) -> PathBuf {
    temp.path().join("events.db")
}

async fn subscribe(
    client: &mut McpClient,
    path: &str,
    name: &str,
    arguments: Value,
    receiver: &MockReceiver,
) -> Value {
    client
        .request(
            "events/subscribe",
            json!({
                "name": name,
                "arguments": arguments,
                "delivery": {
                    "mode": "webhook",
                    "url": receiver.endpoint(path),
                    "secret": test_secret(),
                }
            }),
        )
        .await
}

fn completed_event(id: &str) -> NewEvent {
    NewEvent {
        id: Some(id.into()),
        source: None,
        kind: "t3.run.completed".into(),
        payload: t3_completed_payload(),
        occurred_at: None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn initialize_advertises_events_and_lists_the_catalog() {
    let temp = TempDir::new().unwrap();
    let hub = RunningHub::start(
        temporary_database(&temp),
        CallbackPolicy::for_tests(),
        false,
    )
    .await;
    let mut client = hub.client();

    let initialized = client.initialize().await;
    assert_eq!(
        initialized.pointer("/result/capabilities/events/listChanged"),
        Some(&Value::Bool(false)),
        "{initialized}"
    );
    assert!(initialized.pointer("/result/capabilities/tools").is_some());
    assert!(client.session.is_some(), "session id must be issued");

    let tools = rpc_result(client.request("tools/list", json!({})).await);
    let names: Vec<_> = tools["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        vec![
            "list_events",
            "get_event",
            "get_t3_run",
            "get_t3_approvals",
            "get_github_status",
            "ack_events",
            "probe_consumer",
            "poll_consumer_events",
            "ack_consumer_events",
        ]
    );

    let listed = rpc_result(client.request("events/list", json!({})).await);
    let events = listed["events"].as_array().unwrap();
    assert_eq!(events.len(), 6);
    let names: Vec<_> = events
        .iter()
        .map(|event| event["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        vec![
            "t3.run.completed",
            "t3.run.failed",
            "t3.approval.required",
            "github.workflow.failed",
            "github.review.requested",
            "github.pr.merged",
        ]
    );
    for event in events {
        assert_eq!(event["delivery"], json!(["webhook"]));
        assert!(event["inputSchema"].is_object());
        assert!(event["payloadSchema"].is_object());
        assert!(event["description"].as_str().is_some());
    }
}

#[tokio::test]
async fn server_discover_exposes_events_capability() {
    let temp = TempDir::new().unwrap();
    let hub = RunningHub::start(
        temporary_database(&temp),
        CallbackPolicy::for_tests(),
        false,
    )
    .await;
    let mut client = hub.client();
    // Discover is a stateless MCP 2.0 request; no session is used.
    client.protocol = "2026-07-28".into();

    let body = json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "server/discover",
        "params": {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {}
            }
        }
    });
    let response = client
        .raw_with(&body, true, &[("Mcp-Method", "server/discover")])
        .await;
    let value = parse_mcp_response(response).await;
    assert_eq!(
        value.pointer("/result/capabilities/events/listChanged"),
        Some(&Value::Bool(false)),
        "{value}"
    );
    assert!(value.pointer("/result/supportedVersions").is_some());
}

#[tokio::test]
async fn subscribe_verifies_and_delivers_a_signed_webhook() {
    let temp = TempDir::new().unwrap();
    let receiver = MockReceiver::start(Behavior::Success).await;
    let hub = RunningHub::start(temporary_database(&temp), CallbackPolicy::for_tests(), true).await;
    let mut client = hub.client();
    client.initialize().await;

    let response = subscribe(
        &mut client,
        "/hook",
        "t3.run.completed",
        json!({"environment_id": "linux-main"}),
        &receiver,
    )
    .await;
    let subscription = rpc_result(response);
    let subscription_id = subscription["id"].as_str().unwrap().to_string();
    assert!(subscription_id.starts_with("sub_"));
    assert!(subscription["refreshBefore"].as_str().is_some());
    assert!(subscription["cursor"].is_null());
    assert_eq!(subscription["truncated"], false);

    let verification = receiver.verification_records();
    assert_eq!(verification.len(), 1);
    assert!(verification[0].signature_valid);
    assert!(verification[0].json()["challenge"].as_str().is_some());

    let outcome = hub
        .hub
        .ingest_event(completed_event("evt_e2e_completed"))
        .unwrap();
    assert_eq!(outcome.deliveries_created, 1);

    let records = receiver.shared_state();
    wait_until("signed event delivery", || {
        records.records.lock().unwrap().iter().any(Record::is_event)
    })
    .await;

    let event = receiver
        .event_records()
        .into_iter()
        .find(|record| record.is_event())
        .expect("event delivery");
    assert!(
        event.signature_valid,
        "Standard Webhooks signature must verify"
    );
    assert_eq!(event.header("webhook-id"), Some("evt_e2e_completed"));
    assert_eq!(
        event.header("X-MCP-Subscription-Id"),
        Some(subscription_id.as_str())
    );
    assert_eq!(event.header("content-type"), Some("application/json"));
    assert!(event.header("webhook-timestamp").is_some());

    let body = event.json();
    assert_eq!(body["eventId"], "evt_e2e_completed");
    assert_eq!(body["name"], "t3.run.completed");
    assert_eq!(body["data"]["environment_id"], "linux-main");
    assert_eq!(body["data"]["thread_id"], "thread-42");
    assert!(body["cursor"].is_null());

    // Delivery state is durably recorded. The receiver records a request
    // before acknowledging it, so wait for the dispatcher to commit.
    let repository = hub.hub.repository().clone();
    wait_until("delivery state committed", || {
        repository
            .delivery_statuses("evt_e2e_completed")
            .unwrap()
            .first()
            .is_some_and(|status| status.1 == "delivered")
    })
    .await;
    let statuses = repository.delivery_statuses("evt_e2e_completed").unwrap();
    assert_eq!(
        statuses,
        vec![(subscription_id.clone(), "delivered".into(), 1)]
    );

    // Refreshing the same subscription is idempotent and does not re-challenge.
    let refreshed = subscribe(
        &mut client,
        "/hook",
        "t3.run.completed",
        json!({"environment_id": "linux-main"}),
        &receiver,
    )
    .await;
    let refreshed = rpc_result(refreshed);
    assert_eq!(refreshed["id"], subscription_id);
    assert_eq!(receiver.verification_records().len(), 1);
}

#[tokio::test]
async fn subscribe_rejects_an_invalid_secret() {
    let temp = TempDir::new().unwrap();
    let receiver = MockReceiver::start(Behavior::Success).await;
    let hub = RunningHub::start(
        temporary_database(&temp),
        CallbackPolicy::for_tests(),
        false,
    )
    .await;
    let mut client = hub.client();
    client.initialize().await;

    let response = client
        .request(
            "events/subscribe",
            json!({
                "name": "t3.run.completed",
                "arguments": {"environment_id": "linux-main"},
                "delivery": {
                    "mode": "webhook",
                    "url": receiver.endpoint("/hook"),
                    "secret": format!("{prefix}AAAA", prefix = "whsec_"),
                }
            }),
        )
        .await;
    let (code, data) = rpc_error(&response);
    assert_eq!(code, -32015, "{response}");
    assert_eq!(data["reason"], "invalid_secret");
    assert!(
        hub.hub
            .repository()
            .list_subscriptions()
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn subscribe_rejects_plain_http_on_the_production_policy() {
    let temp = TempDir::new().unwrap();
    let hub = RunningHub::start(temporary_database(&temp), CallbackPolicy::default(), false).await;
    let mut client = hub.client();
    client.initialize().await;

    let response = client
        .request(
            "events/subscribe",
            json!({
                "name": "t3.run.completed",
                "arguments": {"environment_id": "linux-main"},
                "delivery": {
                    "mode": "webhook",
                    "url": "http://127.0.0.1:9/hook",
                    "secret": test_secret(),
                }
            }),
        )
        .await;
    let (code, data) = rpc_error(&response);
    assert_eq!(code, -32015, "{response}");
    assert_eq!(data["reason"], "insecure_url");
}

#[tokio::test]
async fn subscribe_rejects_private_addresses_on_the_production_policy() {
    let temp = TempDir::new().unwrap();
    let hub = RunningHub::start(temporary_database(&temp), CallbackPolicy::default(), false).await;
    let mut client = hub.client();
    client.initialize().await;

    let response = client
        .request(
            "events/subscribe",
            json!({
                "name": "t3.run.completed",
                "arguments": {"environment_id": "linux-main"},
                "delivery": {
                    "mode": "webhook",
                    "url": "https://127.0.0.1:9/hook",
                    "secret": test_secret(),
                }
            }),
        )
        .await;
    let (code, data) = rpc_error(&response);
    assert_eq!(code, -32015, "{response}");
    assert_eq!(data["reason"], "private_address");
}

#[tokio::test]
async fn subscribe_rejects_a_challenge_mismatch() {
    let temp = TempDir::new().unwrap();
    let receiver = MockReceiver::start(Behavior::ChallengeMismatch).await;
    let hub = RunningHub::start(
        temporary_database(&temp),
        CallbackPolicy::for_tests(),
        false,
    )
    .await;
    let mut client = hub.client();
    client.initialize().await;

    let response = subscribe(
        &mut client,
        "/hook",
        "t3.run.completed",
        json!({"environment_id": "linux-main"}),
        &receiver,
    )
    .await;
    let (code, data) = rpc_error(&response);
    assert_eq!(code, -32015, "{response}");
    assert_eq!(data["reason"], "challenge_failed");
    assert!(
        hub.hub
            .repository()
            .list_subscriptions()
            .unwrap()
            .is_empty(),
        "unverified subscriptions must not be stored"
    );
}

#[tokio::test]
async fn redirects_are_not_followed() {
    let temp = TempDir::new().unwrap();
    let receiver = MockReceiver::start(Behavior::Redirect).await;
    let hub = RunningHub::start(
        temporary_database(&temp),
        CallbackPolicy::for_tests(),
        false,
    )
    .await;
    let mut client = hub.client();
    client.initialize().await;

    let response = subscribe(
        &mut client,
        "/redirect",
        "t3.run.completed",
        json!({"environment_id": "linux-main"}),
        &receiver,
    )
    .await;
    let (code, data) = rpc_error(&response);
    assert_eq!(code, -32015, "{response}");
    assert_eq!(data["reason"], "redirect_not_followed");

    let paths: Vec<_> = receiver
        .records()
        .into_iter()
        .map(|record| record.path)
        .collect();
    assert_eq!(
        paths,
        vec!["/redirect"],
        "redirect target must not be requested"
    );
}

#[tokio::test]
async fn temporary_5xx_errors_are_retried_with_the_same_event_id() {
    let temp = TempDir::new().unwrap();
    let receiver = MockReceiver::start(Behavior::FailThenSucceed(2)).await;
    let hub = RunningHub::start(temporary_database(&temp), CallbackPolicy::for_tests(), true).await;
    let mut client = hub.client();
    client.initialize().await;

    let subscription = rpc_result(
        subscribe(
            &mut client,
            "/hook",
            "t3.run.completed",
            json!({"environment_id": "linux-main"}),
            &receiver,
        )
        .await,
    );
    let subscription_id = subscription["id"].as_str().unwrap().to_string();

    hub.hub.ingest_event(completed_event("evt_retry")).unwrap();

    let records = receiver.shared_state();
    wait_until("three delivery attempts", || {
        records
            .records
            .lock()
            .unwrap()
            .iter()
            .filter(|record| record.is_event())
            .count()
            >= 3
    })
    .await;

    let events: Vec<_> = receiver.event_records();
    assert_eq!(events.len(), 3);
    assert_eq!(events[0].status, 500);
    assert_eq!(events[1].status, 500);
    assert_eq!(events[2].status, 200);
    for event in &events {
        assert_eq!(event.header("webhook-id"), Some("evt_retry"));
        assert!(event.signature_valid);
    }

    let repository = hub.hub.repository().clone();
    wait_until("retry delivery state committed", || {
        repository
            .delivery_statuses("evt_retry")
            .unwrap()
            .first()
            .is_some_and(|status| status.1 == "delivered")
    })
    .await;
    let statuses = repository.delivery_statuses("evt_retry").unwrap();
    assert_eq!(statuses, vec![(subscription_id, "delivered".into(), 3)]);
}

#[tokio::test]
async fn http_410_stops_retries_and_disables_the_subscription() {
    let temp = TempDir::new().unwrap();
    let receiver = MockReceiver::start(Behavior::Gone).await;
    let hub = RunningHub::start(temporary_database(&temp), CallbackPolicy::for_tests(), true).await;
    let mut client = hub.client();
    client.initialize().await;

    let subscription = rpc_result(
        subscribe(
            &mut client,
            "/hook",
            "t3.run.completed",
            json!({"environment_id": "linux-main"}),
            &receiver,
        )
        .await,
    );
    let subscription_id = subscription["id"].as_str().unwrap().to_string();

    hub.hub.ingest_event(completed_event("evt_gone")).unwrap();

    let records = receiver.shared_state();
    wait_until("410 delivery", || {
        records.records.lock().unwrap().iter().any(Record::is_event)
    })
    .await;
    // Give a retryable failure a chance to appear if it were misclassified.
    tokio::time::sleep(Duration::from_millis(400)).await;

    let events = receiver.event_records();
    assert_eq!(events.len(), 1, "410 must not be retried");
    assert_eq!(events[0].status, 410);

    let repository = hub.hub.repository().clone();
    wait_until("subscription disabled", || {
        repository
            .get_subscription(&subscription_id)
            .unwrap()
            .is_some_and(|subscription| !subscription.active)
    })
    .await;
    let subscription = repository
        .get_subscription(&subscription_id)
        .unwrap()
        .expect("subscription exists");
    assert!(!subscription.active, "410 disables the subscription");
    assert_eq!(subscription.last_error.as_deref(), Some("http_410"));
}

#[tokio::test]
async fn http_413_is_not_retried() {
    let temp = TempDir::new().unwrap();
    let receiver = MockReceiver::start(Behavior::PayloadTooLarge).await;
    let hub = RunningHub::start(temporary_database(&temp), CallbackPolicy::for_tests(), true).await;
    let mut client = hub.client();
    client.initialize().await;

    rpc_result(
        subscribe(
            &mut client,
            "/hook",
            "t3.run.completed",
            json!({"environment_id": "linux-main"}),
            &receiver,
        )
        .await,
    );
    hub.hub
        .ingest_event(completed_event("evt_too_large"))
        .unwrap();

    let records = receiver.shared_state();
    wait_until("413 delivery", || {
        records.records.lock().unwrap().iter().any(Record::is_event)
    })
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    let events = receiver.event_records();
    assert_eq!(events.len(), 1, "413 must not be retried");
    assert_eq!(events[0].status, 413);

    let repository = hub.hub.repository().clone();
    wait_until("413 delivery state committed", || {
        repository
            .delivery_statuses("evt_too_large")
            .unwrap()
            .first()
            .is_some_and(|status| status.1 == "failed")
    })
    .await;
    let statuses = repository.delivery_statuses("evt_too_large").unwrap();
    assert_eq!(statuses[0].1, "failed");
    assert_eq!(statuses[0].2, 1);
}

#[tokio::test]
async fn payloads_over_256_kib_are_not_sent() {
    let temp = TempDir::new().unwrap();
    let receiver = MockReceiver::start(Behavior::Success).await;
    let hub = RunningHub::start(temporary_database(&temp), CallbackPolicy::for_tests(), true).await;
    let mut client = hub.client();
    client.initialize().await;

    rpc_result(
        subscribe(
            &mut client,
            "/hook",
            "t3.run.completed",
            json!({"environment_id": "linux-main"}),
            &receiver,
        )
        .await,
    );

    let mut payload = t3_completed_payload();
    payload["summary"] = Value::String("x".repeat(300 * 1024));
    hub.hub
        .ingest_event(NewEvent {
            id: Some("evt_oversized".into()),
            source: None,
            kind: "t3.run.completed".into(),
            payload,
            occurred_at: None,
        })
        .unwrap();

    let repository = hub.hub.repository().clone();
    wait_until("oversized delivery to be rejected locally", || {
        repository
            .delivery_statuses("evt_oversized")
            .unwrap()
            .first()
            .is_some_and(|status| status.1 != "pending")
    })
    .await;

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        receiver.event_records().is_empty(),
        "oversized body must not be delivered"
    );
    let status = hub
        .hub
        .repository()
        .delivery_statuses("evt_oversized")
        .unwrap();
    assert_eq!(status[0].1, "failed");
    assert_eq!(status[0].2, 1);
}

#[tokio::test]
async fn unsubscribe_removes_the_subscription() {
    let temp = TempDir::new().unwrap();
    let receiver = MockReceiver::start(Behavior::Success).await;
    let hub = RunningHub::start(temporary_database(&temp), CallbackPolicy::for_tests(), true).await;
    let mut client = hub.client();
    client.initialize().await;

    let subscription = rpc_result(
        subscribe(
            &mut client,
            "/hook",
            "t3.run.completed",
            json!({"environment_id": "linux-main"}),
            &receiver,
        )
        .await,
    );
    let subscription_id = subscription["id"].as_str().unwrap().to_string();

    let response = client
        .request(
            "events/unsubscribe",
            json!({
                "name": "t3.run.completed",
                "arguments": {"environment_id": "linux-main"},
                "delivery": {"url": receiver.endpoint("/hook")}
            }),
        )
        .await;
    rpc_result(response);
    assert!(
        hub.hub
            .repository()
            .get_subscription(&subscription_id)
            .unwrap()
            .is_none()
    );

    let outcome = hub
        .hub
        .ingest_event(completed_event("evt_after_unsub"))
        .unwrap();
    assert_eq!(outcome.deliveries_created, 0);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(receiver.event_records().is_empty());
}

#[tokio::test]
async fn pending_deliveries_resume_after_restart() {
    let temp = TempDir::new().unwrap();
    let database = temporary_database(&temp);
    let receiver = MockReceiver::start(Behavior::Success).await;

    // First process: subscription created, event ingested, dispatcher absent.
    let first = RunningHub::start(database.clone(), CallbackPolicy::for_tests(), false).await;
    let mut client = first.client();
    client.initialize().await;
    let subscription = rpc_result(
        subscribe(
            &mut client,
            "/hook",
            "t3.run.completed",
            json!({"environment_id": "linux-main"}),
            &receiver,
        )
        .await,
    );
    let subscription_id = subscription["id"].as_str().unwrap().to_string();
    first
        .hub
        .ingest_event(completed_event("evt_restart"))
        .unwrap();
    assert_eq!(
        first
            .hub
            .repository()
            .delivery_statuses("evt_restart")
            .unwrap()[0]
            .1,
        "pending"
    );
    first.stop().await;
    assert!(receiver.event_records().is_empty());

    // Second process: a fresh Hub over the same SQLite file resumes the queue.
    let second = RunningHub::start(database, CallbackPolicy::for_tests(), true).await;
    let records = receiver.shared_state();
    wait_until("delivery resumed after restart", || {
        records.records.lock().unwrap().iter().any(Record::is_event)
    })
    .await;

    let event = receiver.event_records().into_iter().next().unwrap();
    assert_eq!(event.header("webhook-id"), Some("evt_restart"));
    assert_eq!(
        event.header("X-MCP-Subscription-Id"),
        Some(subscription_id.as_str())
    );
    assert!(event.signature_valid);
    let repository = second.hub.repository().clone();
    wait_until("restart delivery state committed", || {
        repository
            .delivery_statuses("evt_restart")
            .unwrap()
            .first()
            .is_some_and(|status| status.1 == "delivered")
    })
    .await;
    assert_eq!(
        repository.delivery_statuses("evt_restart").unwrap()[0].1,
        "delivered"
    );
}

#[tokio::test]
async fn pull_tools_return_events_without_affecting_delivery_state() {
    let temp = TempDir::new().unwrap();
    let hub = RunningHub::start(
        temporary_database(&temp),
        CallbackPolicy::for_tests(),
        false,
    )
    .await;
    let mut client = hub.client();
    client.initialize().await;

    hub.hub
        .ingest_event(NewEvent {
            id: Some("evt_pull_failed".into()),
            source: None,
            kind: "t3.run.failed".into(),
            payload: json!({
                "environment_id": "linux-main",
                "project_id": "lnako",
                "thread_id": "thread-42",
                "run_id": "run-102",
                "summary": "failed",
                "error": "boom"
            }),
            occurred_at: Some("2026-11-16T01:00:00Z".into()),
        })
        .unwrap();
    hub.hub
        .ingest_event(completed_event("evt_pull_completed"))
        .unwrap();

    let listed = client
        .tool_call("list_events", json!({"severity": "high"}))
        .await;
    assert_eq!(listed["isError"], false, "{listed}");
    let structured = &listed["structuredContent"];
    let events = structured["events"].as_array().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["id"], "evt_pull_failed");

    let fetched = client
        .tool_call("get_event", json!({"event_id": "evt_pull_completed"}))
        .await;
    assert_eq!(fetched["isError"], false, "{fetched}");
    assert_eq!(
        fetched["structuredContent"]["event"]["payload"]["thread_id"],
        "thread-42"
    );

    let acked = client
        .tool_call("ack_events", json!({"event_ids": ["evt_pull_completed"]}))
        .await;
    assert_eq!(acked["isError"], false, "{acked}");
    assert!(
        hub.hub
            .repository()
            .is_acknowledged("local", "evt_pull_completed")
            .unwrap()
    );

    let missing = client
        .tool_call("get_event", json!({"event_id": "evt_missing"}))
        .await;
    assert_eq!(missing["isError"], true);

    // No subscription exists, so the ack path must not have created deliveries.
    assert_eq!(hub.hub.repository().pending_delivery_count().unwrap(), 0);
}

#[tokio::test]
async fn t3_pull_tools_return_materialized_run_and_pending_approvals() {
    let temp = TempDir::new().unwrap();
    let hub = RunningHub::start(
        temporary_database(&temp),
        CallbackPolicy::for_tests(),
        false,
    )
    .await;
    hub.hub
        .repository()
        .apply_t3_snapshot(
            "linux-main",
            &T3Snapshot {
                projects: vec![T3Project {
                    environment_id: "linux-main".into(),
                    project_id: "lnako".into(),
                    title: "lnako".into(),
                    workspace_root: "/repo/lnako".into(),
                    deleted_at: None,
                    updated_at: "2026-11-16T01:00:00.000Z".into(),
                }],
                threads: vec![T3Thread {
                    environment_id: "linux-main".into(),
                    thread_id: "thread-42".into(),
                    project_id: "lnako".into(),
                    title: "Fix the build".into(),
                    branch: Some("main".into()),
                    deleted_at: None,
                    updated_at: "2026-11-16T01:00:01.000Z".into(),
                }],
                runs: vec![T3Run {
                    environment_id: "linux-main".into(),
                    run_id: "run-102".into(),
                    thread_id: "thread-42".into(),
                    project_id: "lnako".into(),
                    ordinal: 1,
                    provider_instance_id: Some("test".into()),
                    status: "failed".into(),
                    last_turn_status: Some("failed".into()),
                    checkpoint_id: None,
                    error: Some("no API key".into()),
                    summary: Some("Run #1 failed".into()),
                    requested_at: Some("2026-11-16T01:00:02.000Z".into()),
                    started_at: Some("2026-11-16T01:00:03.000Z".into()),
                    completed_at: Some("2026-11-16T01:00:09.000Z".into()),
                    updated_at: "2026-11-16T01:00:09.000Z".into(),
                }],
                approvals: vec![T3Approval {
                    environment_id: "linux-main".into(),
                    approval_id: "approval-1".into(),
                    thread_id: "thread-42".into(),
                    run_id: "run-102".into(),
                    node_id: Some("node-1".into()),
                    kind: "command".into(),
                    status: "pending".into(),
                    summary: Some("Run a command".into()),
                    decision: None,
                    created_at: "2026-11-16T01:00:05.000Z".into(),
                    resolved_at: None,
                    updated_at: "2026-11-16T01:00:05.000Z".into(),
                }],
            },
            0,
        )
        .unwrap();

    let mut client = hub.client();
    client.initialize().await;

    let listed = client.request("tools/list", json!({})).await;
    let names: Vec<&str> = listed
        .pointer("/result/tools")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect();
    assert!(names.contains(&"get_t3_run"), "{listed}");
    assert!(names.contains(&"get_t3_approvals"), "{listed}");

    let run = client
        .tool_call("get_t3_run", json!({"run_id": "run-102"}))
        .await;
    assert_eq!(run["isError"], false, "{run}");
    let structured = &run["structuredContent"]["run"];
    assert_eq!(structured["status"], "failed");
    assert_eq!(structured["error"], "no API key");
    assert_eq!(structured["pendingApprovalsCount"], 1);

    let pending = client
        .tool_call("get_t3_approvals", json!({"environment_id": "linux-main"}))
        .await;
    assert_eq!(pending["isError"], false, "{pending}");
    let approvals = pending["structuredContent"]["approvals"]
        .as_array()
        .unwrap();
    assert_eq!(approvals.len(), 1);
    assert_eq!(approvals[0]["approvalId"], "approval-1");
    assert_eq!(approvals[0]["status"], "pending");

    let filtered = client
        .tool_call(
            "get_t3_approvals",
            json!({"environment_id": "linux-main", "project_id": "other"}),
        )
        .await;
    assert_eq!(filtered["isError"], false, "{filtered}");
    assert!(
        filtered["structuredContent"]["approvals"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let missing = client
        .tool_call("get_t3_run", json!({"run_id": "missing"}))
        .await;
    assert_eq!(missing["isError"], true);
}

#[tokio::test]
async fn private_resolver_is_used_for_test_only_and_public_resolver_rejects_it() {
    // Guards the test hook itself: the for_tests policy may target loopback,
    // while the default policy may not.
    let loopback: Vec<IpAddr> = vec!["127.0.0.1".parse().unwrap()];
    let sockets: Vec<SocketAddr> = loopback
        .iter()
        .map(|ip| SocketAddr::new(*ip, 8080))
        .collect();
    assert_eq!(sockets[0].port(), 8080);

    let policy = CallbackPolicy::for_tests();
    let url = url::Url::parse("http://127.0.0.1:9/hook").unwrap();
    // Only validates the scheme/address policy, not connectivity.
    let _client = events_bridge::delivery::verification::pin_client(&policy, &url)
        .await
        .expect("test policy accepts loopback");

    let production = CallbackPolicy::default();
    let error = events_bridge::delivery::verification::pin_client(&production, &url)
        .await
        .unwrap_err();
    assert_eq!(
        error.reason,
        events_bridge::delivery::verification::reason::INSECURE_URL
    );
}

// ---------------------------------------------------------------------------
// HTTP security and protocol-envelope regressions
// ---------------------------------------------------------------------------

#[tokio::test]
async fn disallowed_host_headers_are_rejected() {
    let temp = TempDir::new().unwrap();
    let mut config = Config::for_tests(temporary_database(&temp));
    config.server.allowed_hosts = vec!["localhost".into()];
    let hub = RunningHub::start_with_config(config, CallbackPolicy::for_tests(), false).await;
    let client = hub.client();
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "events/list", "params": {}});

    let response = client
        .raw_with(&body, false, &[("Host", "127.0.0.1:8787")])
        .await;
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "a Host outside allowed_hosts must be rejected"
    );

    // The allowlisted host is still served.
    let response = client
        .raw_with(&body, false, &[("Host", "localhost:8787")])
        .await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn disallowed_origins_are_rejected() {
    let temp = TempDir::new().unwrap();
    let hub = RunningHub::start(
        temporary_database(&temp),
        CallbackPolicy::for_tests(),
        false,
    )
    .await;
    let client = hub.client();
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "events/list", "params": {}});

    let response = client
        .raw_with(&body, false, &[("Origin", "https://evil.example")])
        .await;
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "an Origin that matches neither Host nor allowed_hosts must be rejected"
    );

    // A browser origin for the bridge itself remains usable.
    let response = client
        .raw_with(&body, false, &[("Origin", hub.base_url.as_str())])
        .await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn internal_ingest_rejects_disallowed_host_and_origin() {
    let temp = TempDir::new().unwrap();
    let mut config = Config::for_tests(temporary_database(&temp));
    config.server.allowed_hosts = vec!["localhost".into()];
    let hub = RunningHub::start_with_config(config, CallbackPolicy::for_tests(), false).await;

    let http = reqwest::Client::new();
    let url = format!("{}/internal/events", hub.base_url);
    let body = json!({
        "kind": "t3.run.completed",
        "payload": t3_completed_payload(),
    });

    let bad_host = http
        .post(&url)
        .header("Host", "attacker.example")
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(bad_host.status(), StatusCode::FORBIDDEN);

    let bad_origin = http
        .post(&url)
        .header("Host", "localhost:8787")
        .header("Origin", "https://evil.example")
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(bad_origin.status(), StatusCode::FORBIDDEN);

    let ok = http
        .post(&url)
        .header("Host", "localhost:8787")
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), StatusCode::OK);
}

#[test]
fn empty_internal_token_env_is_rejected_at_startup() {
    let temp = TempDir::new().unwrap();
    let var = "EVENTS_BRIDGE_TEST_EMPTY_INTERNAL_TOKEN";
    // SAFETY: unique variable name used only by this test.
    unsafe {
        std::env::set_var(var, "");
    }
    let mut config = Config::for_tests(temporary_database(&temp));
    config.server.internal_token_env = Some(var.into());
    let err = Hub::with_policy(config, CallbackPolicy::for_tests())
        .err()
        .expect("empty internal token env must fail startup");
    assert!(err.to_string().contains("empty"), "{err}");
    unsafe {
        std::env::remove_var(var);
    }
}

#[tokio::test]
async fn text_plain_events_requests_are_rejected_without_side_effects() {
    let temp = TempDir::new().unwrap();
    let receiver = MockReceiver::start(Behavior::Success).await;
    let hub = RunningHub::start(
        temporary_database(&temp),
        CallbackPolicy::for_tests(),
        false,
    )
    .await;
    let client = hub.client();

    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "events/subscribe",
        "params": {
            "name": "t3.run.completed",
            "arguments": {"environment_id": "linux-main"},
            "delivery": {
                "mode": "webhook",
                "url": receiver.endpoint("/hook"),
                "secret": test_secret(),
            }
        }
    });
    let bytes = serde_json::to_vec(&body).unwrap();
    let response = client.raw_body(&bytes, "text/plain", &[]).await;
    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);

    // Parameters are allowed on the JSON media type.
    let body = json!({"jsonrpc": "2.0", "id": 2, "method": "events/list", "params": {}});
    let bytes = serde_json::to_vec(&body).unwrap();
    let response = client
        .raw_body(&bytes, "application/json; charset=utf-8", &[])
        .await;
    assert_eq!(response.status(), StatusCode::OK);

    assert!(receiver.verification_records().is_empty());
    assert!(
        hub.hub
            .repository()
            .list_subscriptions()
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn events_methods_require_a_json_rpc_2_envelope() {
    let temp = TempDir::new().unwrap();
    let receiver = MockReceiver::start(Behavior::Success).await;
    let hub = RunningHub::start(
        temporary_database(&temp),
        CallbackPolicy::for_tests(),
        false,
    )
    .await;
    let client = hub.client();

    let params = json!({
        "name": "t3.run.completed",
        "arguments": {"environment_id": "linux-main"},
        "delivery": {
            "mode": "webhook",
            "url": receiver.endpoint("/hook"),
            "secret": test_secret(),
        }
    });
    let invalid_bodies = [
        json!({"jsonrpc": "1.0", "id": 1, "method": "events/subscribe", "params": params}),
        json!({"id": 1, "method": "events/subscribe", "params": params}),
        json!({"jsonrpc": "2.0", "id": {"nested": 1}, "method": "events/subscribe", "params": params}),
        json!({"jsonrpc": "2.0", "id": [1], "method": "events/subscribe", "params": params}),
        json!({"jsonrpc": "2.0", "id": true, "method": "events/subscribe", "params": params}),
    ];

    for body in invalid_bodies {
        let (status, value) = response_json(client.raw(&body, false).await).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(value["error"]["code"], -32600, "{value}");
        assert_eq!(value["id"], Value::Null, "{value}");
    }

    assert!(
        receiver.verification_records().is_empty(),
        "an invalid envelope must not trigger a callback challenge"
    );
    assert!(
        hub.hub
            .repository()
            .list_subscriptions()
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn events_methods_accept_mcp_meta() {
    let temp = TempDir::new().unwrap();
    let receiver = MockReceiver::start(Behavior::Success).await;
    let hub = RunningHub::start(
        temporary_database(&temp),
        CallbackPolicy::for_tests(),
        false,
    )
    .await;
    let mut client = hub.client();
    client.initialize().await;

    let response = client
        .request(
            "events/subscribe",
            json!({
                "name": "t3.run.completed",
                "arguments": {"environment_id": "linux-main"},
                "delivery": {
                    "mode": "webhook",
                    "url": receiver.endpoint("/hook"),
                    "secret": test_secret(),
                },
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "progressToken": "subscribe-1"
                }
            }),
        )
        .await;
    let subscription = rpc_result(response);
    let subscription_id = subscription["id"].as_str().unwrap().to_string();
    assert_eq!(receiver.verification_records().len(), 1);

    let response = client
        .request(
            "events/unsubscribe",
            json!({
                "id": subscription_id,
                "_meta": {"progressToken": "unsubscribe-1"}
            }),
        )
        .await;
    rpc_result(response);
    assert!(
        hub.hub
            .repository()
            .get_subscription(&subscription_id)
            .unwrap()
            .is_none()
    );
}

// ---------------------------------------------------------------------------
// Secret rotation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rotating_the_secret_reverifies_with_the_new_key() {
    let temp = TempDir::new().unwrap();
    let receiver = MockReceiver::start(Behavior::Success).await;
    let hub = RunningHub::start(
        temporary_database(&temp),
        CallbackPolicy::for_tests(),
        false,
    )
    .await;
    let mut client = hub.client();
    client.initialize().await;

    let first = rpc_result(
        subscribe(
            &mut client,
            "/hook",
            "t3.run.completed",
            json!({"environment_id": "linux-main"}),
            &receiver,
        )
        .await,
    );
    let subscription_id = first["id"].as_str().unwrap().to_string();
    assert_eq!(receiver.verification_records().len(), 1);

    let rotated = rpc_result(
        client
            .request(
                "events/subscribe",
                json!({
                    "name": "t3.run.completed",
                    "arguments": {"environment_id": "linux-main"},
                    "delivery": {
                        "mode": "webhook",
                        "url": receiver.endpoint("/hook"),
                        "secret": rotated_test_secret(),
                    }
                }),
            )
            .await,
    );
    assert_eq!(rotated["id"], subscription_id);

    let verifications = receiver.verification_records();
    assert_eq!(
        verifications.len(),
        2,
        "a secret change must re-run the challenge"
    );
    let webhook = standardwebhooks::Webhook::new(&rotated_test_secret()).unwrap();
    assert!(
        webhook
            .verify(&verifications[1].body, &verifications[1].headers)
            .is_ok(),
        "the second challenge must be signed with the new key"
    );

    let subscription = hub
        .hub
        .repository()
        .get_subscription(&subscription_id)
        .unwrap()
        .expect("subscription exists");
    assert_eq!(subscription.secret, rotated_test_secret());
    assert!(subscription.active && subscription.verified);
}

#[tokio::test]
async fn failed_secret_rotation_keeps_the_old_key_and_state() {
    let temp = TempDir::new().unwrap();
    let receiver = MockReceiver::start(Behavior::Success).await;
    let hub = RunningHub::start(
        temporary_database(&temp),
        CallbackPolicy::for_tests(),
        false,
    )
    .await;
    let mut client = hub.client();
    client.initialize().await;

    let first = rpc_result(
        subscribe(
            &mut client,
            "/hook",
            "t3.run.completed",
            json!({"environment_id": "linux-main"}),
            &receiver,
        )
        .await,
    );
    let subscription_id = first["id"].as_str().unwrap().to_string();

    receiver.set_behavior(Behavior::ChallengeMismatch);
    let response = client
        .request(
            "events/subscribe",
            json!({
                "name": "t3.run.completed",
                "arguments": {"environment_id": "linux-main"},
                "delivery": {
                    "mode": "webhook",
                    "url": receiver.endpoint("/hook"),
                    "secret": rotated_test_secret(),
                }
            }),
        )
        .await;
    let (code, data) = rpc_error(&response);
    assert_eq!(code, -32015, "{response}");
    assert_eq!(data["reason"], "challenge_failed");

    let subscription = hub
        .hub
        .repository()
        .get_subscription(&subscription_id)
        .unwrap()
        .expect("the old subscription must survive a failed rotation");
    assert_eq!(subscription.secret, test_secret());
    assert!(subscription.active && subscription.verified);
}

// ---------------------------------------------------------------------------
// Queue termination and lease recovery
// ---------------------------------------------------------------------------

#[tokio::test]
async fn http_410_disables_the_remaining_backlog() {
    let temp = TempDir::new().unwrap();
    let receiver = MockReceiver::start(Behavior::Gone).await;
    let hub = RunningHub::start(
        temporary_database(&temp),
        CallbackPolicy::for_tests(),
        false,
    )
    .await;
    let mut client = hub.client();
    client.initialize().await;

    let subscription = rpc_result(
        subscribe(
            &mut client,
            "/hook",
            "t3.run.completed",
            json!({"environment_id": "linux-main"}),
            &receiver,
        )
        .await,
    );
    let subscription_id = subscription["id"].as_str().unwrap().to_string();

    hub.hub
        .ingest_event(completed_event("evt_backlog_a"))
        .unwrap();
    hub.hub
        .ingest_event(completed_event("evt_backlog_b"))
        .unwrap();
    let repository = hub.hub.repository().clone();
    assert_eq!(repository.pending_delivery_count().unwrap(), 2);

    assert_eq!(hub.hub.deliver_due_once().await, 1);

    let events = receiver.event_records();
    assert_eq!(events.len(), 1, "the rest of the backlog must stop");
    assert_eq!(events[0].header("webhook-id"), Some("evt_backlog_a"));
    assert_eq!(repository.pending_delivery_count().unwrap(), 0);
    for id in ["evt_backlog_a", "evt_backlog_b"] {
        assert_eq!(
            repository.delivery_statuses(id).unwrap()[0].1,
            "failed",
            "{id} must be terminal"
        );
    }
    assert!(
        !repository
            .get_subscription(&subscription_id)
            .unwrap()
            .unwrap()
            .active
    );
}

#[tokio::test]
async fn expired_subscription_backlog_is_not_delivered() {
    let temp = TempDir::new().unwrap();
    let receiver = MockReceiver::start(Behavior::Success).await;
    let hub = RunningHub::start(
        temporary_database(&temp),
        CallbackPolicy::for_tests(),
        false,
    )
    .await;
    let repository = hub.hub.repository().clone();

    repository
        .upsert_subscription(NewSubscription {
            id: "sub_expiring".into(),
            principal: "local".into(),
            event_name: "t3.run.completed".into(),
            arguments: json!({"environment_id": "linux-main"}),
            filter_hash: "expiring".into(),
            callback_url: receiver.endpoint("/hook"),
            secret: test_secret(),
            refresh_before: Some(format_rfc3339(
                Utc::now() + ChronoDuration::milliseconds(400),
            )),
        })
        .unwrap();
    let outcome = hub
        .hub
        .ingest_event(completed_event("evt_expiring"))
        .unwrap();
    assert_eq!(outcome.deliveries_created, 1);

    // Cross the subscription expiry while the delivery is still queued.
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(hub.hub.deliver_due_once().await, 0);

    assert!(receiver.event_records().is_empty());
    assert_eq!(
        repository.delivery_statuses("evt_expiring").unwrap()[0].1,
        "failed"
    );
    assert_eq!(repository.pending_delivery_count().unwrap(), 0);
}

#[tokio::test]
async fn expired_lease_redelivers_without_a_restart() {
    let temp = TempDir::new().unwrap();
    let receiver = MockReceiver::start(Behavior::Success).await;
    let hub = RunningHub::start(
        temporary_database(&temp),
        CallbackPolicy::for_tests(),
        false,
    )
    .await;
    let mut client = hub.client();
    client.initialize().await;

    let subscription = rpc_result(
        subscribe(
            &mut client,
            "/hook",
            "t3.run.completed",
            json!({"environment_id": "linux-main"}),
            &receiver,
        )
        .await,
    );
    let subscription_id = subscription["id"].as_str().unwrap().to_string();
    hub.hub.ingest_event(completed_event("evt_lease")).unwrap();

    // Simulate a worker crash after claiming the delivery.
    let repository = hub.hub.repository().clone();
    let due = repository
        .claim_next_due()
        .unwrap()
        .expect("delivery claim");
    assert_eq!(due.event.id, "evt_lease");
    assert_eq!(
        repository.delivery_statuses("evt_lease").unwrap()[0].1,
        "in_progress"
    );

    // The lease configured by `Config::for_tests` has not elapsed yet.
    assert_eq!(hub.hub.deliver_due_once().await, 0);
    assert!(receiver.event_records().is_empty());

    tokio::time::sleep(Duration::from_millis(1_200)).await;
    assert_eq!(hub.hub.deliver_due_once().await, 1);

    let events = receiver.event_records();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].header("webhook-id"), Some("evt_lease"));
    assert_eq!(
        events[0].header("X-MCP-Subscription-Id"),
        Some(subscription_id.as_str())
    );
    assert_eq!(
        repository.delivery_statuses("evt_lease").unwrap()[0].1,
        "delivered"
    );
}

#[tokio::test]
async fn body_size_limit_is_enforced_at_the_256_kib_boundary() {
    let temp = TempDir::new().unwrap();
    let receiver = MockReceiver::start(Behavior::Success).await;
    let hub = RunningHub::start(
        temporary_database(&temp),
        CallbackPolicy::for_tests(),
        false,
    )
    .await;
    let mut client = hub.client();
    client.initialize().await;

    rpc_result(
        subscribe(
            &mut client,
            "/hook",
            "t3.run.completed",
            json!({"environment_id": "linux-main"}),
            &receiver,
        )
        .await,
    );

    let occurred_at = "2026-01-01T00:00:00.000Z";
    let ok_id = "evt_boundary_ok_000001";
    let too_large_id = "evt_boundary_too_large";
    assert_eq!(ok_id.len(), too_large_id.len());
    let mut payload = t3_completed_payload();
    payload["summary"] = json!("");
    let envelope_len = serde_json::to_vec(&json!({
        "eventId": ok_id,
        "name": "t3.run.completed",
        "timestamp": occurred_at,
        "data": payload,
        "cursor": Value::Null,
    }))
    .unwrap()
    .len();
    let filler = MAX_WEBHOOK_BODY_BYTES - envelope_len;
    payload["summary"] = json!("x".repeat(filler));

    hub.hub
        .ingest_event(NewEvent {
            id: Some(ok_id.into()),
            source: None,
            kind: "t3.run.completed".into(),
            payload: payload.clone(),
            occurred_at: Some(occurred_at.into()),
        })
        .unwrap();

    payload["summary"] = json!("x".repeat(filler + 1));
    let rejected_len = serde_json::to_vec(&json!({
        "eventId": too_large_id,
        "name": "t3.run.completed",
        "timestamp": occurred_at,
        "data": payload,
        "cursor": Value::Null,
    }))
    .unwrap()
    .len();
    assert_eq!(rejected_len, MAX_WEBHOOK_BODY_BYTES + 1);
    hub.hub
        .ingest_event(NewEvent {
            id: Some(too_large_id.into()),
            source: None,
            kind: "t3.run.completed".into(),
            payload,
            occurred_at: Some(occurred_at.into()),
        })
        .unwrap();

    assert_eq!(hub.hub.deliver_due_once().await, 2);

    let events = receiver.event_records();
    assert_eq!(events.len(), 1, "only the boundary-sized body is sent");
    assert_eq!(events[0].header("webhook-id"), Some(ok_id));
    assert_eq!(events[0].body.len(), MAX_WEBHOOK_BODY_BYTES);

    let repository = hub.hub.repository().clone();
    assert_eq!(
        repository.delivery_statuses(ok_id).unwrap()[0].1,
        "delivered"
    );
    assert_eq!(
        repository.delivery_statuses(too_large_id).unwrap()[0].1,
        "failed"
    );
}

fn failed_event(id: &str) -> NewEvent {
    NewEvent {
        id: Some(id.into()),
        source: None,
        kind: "t3.run.failed".into(),
        payload: json!({
            "environment_id": "linux-main",
            "project_id": "lnako",
            "thread_id": "thread-42",
            "run_id": "run-102",
            "summary": "failed",
            "error": "boom"
        }),
        occurred_at: None,
    }
}

#[tokio::test]
async fn consumer_http_endpoints_require_auth_and_support_probe_poll_ack() {
    let temp = TempDir::new().unwrap();
    let variable = format!(
        "EVENTS_BRIDGE_TEST_CONSUMER_TOKEN_{}",
        uuid::Uuid::new_v4().simple()
    );
    // Synthesize the bearer token at runtime; no secret literal is committed.
    let token = format!("token-{}", uuid::Uuid::new_v4());
    unsafe { std::env::set_var(&variable, &token) };

    let mut config = Config::for_tests(temporary_database(&temp));
    config.auth.token_env = Some(variable.clone());
    let hub = RunningHub::start_with_config(config, CallbackPolicy::for_tests(), false).await;
    hub.hub
        .ingest_event(failed_event("evt_consumer_http"))
        .unwrap();

    let http = reqwest::Client::new();
    let probe_url = format!("{}/consumers/muse/probe", hub.base_url);
    let poll_url = format!("{}/consumers/muse/poll?limit=1", hub.base_url);
    let ack_url = format!("{}/consumers/muse/ack", hub.base_url);

    let unauthorized = http.get(&probe_url).send().await.unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        unauthorized
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok()),
        Some("Bearer")
    );
    assert_eq!(
        http.get(&poll_url).send().await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        http.post(&ack_url)
            .json(&json!({"upToSequence": 1}))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );

    // Non-allowlisted Host and non-local Origin must be rejected even with a valid token.
    let bad_host = http
        .get(&probe_url)
        .header(header::HOST, "evil.example:8787")
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(bad_host.status(), StatusCode::FORBIDDEN);
    let bad_origin = http
        .post(&ack_url)
        .header(header::ORIGIN, "https://evil.example")
        .bearer_auth(&token)
        .json(&json!({"upToSequence": 1}))
        .send()
        .await
        .unwrap();
    assert_eq!(bad_origin.status(), StatusCode::FORBIDDEN);

    let (status, probe) = response_json(
        http.get(&probe_url)
            .bearer_auth(&token)
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{probe}");
    assert_eq!(probe["consumer"], "muse");
    assert_eq!(probe["cursorSequence"], 0);
    assert_eq!(probe["latestSequence"], 1);
    assert_eq!(probe["unreadCount"], 1);
    assert_eq!(probe["hasUpdates"], true);

    let (status, poll) = response_json(
        http.get(&poll_url)
            .bearer_auth(&token)
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{poll}");
    assert_eq!(poll["consumer"], "muse");
    assert_eq!(poll["cursorSequence"], 0);
    assert_eq!(poll["nextCursorSequence"], 1);
    assert_eq!(poll["hasMore"], false);
    assert_eq!(poll["truncated"], false);
    assert_eq!(poll["digests"].as_array().unwrap().len(), 0);
    assert_eq!(poll["events"].as_array().unwrap().len(), 1);
    assert_eq!(poll["events"][0]["eventId"], "evt_consumer_http");
    assert_eq!(poll["events"][0]["disposition"], "immediate");

    let (status, ack) = response_json(
        http.post(&ack_url)
            .bearer_auth(&token)
            .json(&json!({"upToSequence": 1}))
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{ack}");
    assert_eq!(ack["consumer"], "muse");
    assert_eq!(ack["previousCursorSequence"], 0);
    assert_eq!(ack["cursorSequence"], 1);
    assert_eq!(ack["advanced"], true);

    // The `cursor` alias is accepted and a repeated ack is a monotonic no-op.
    let (status, ack) = response_json(
        http.post(&ack_url)
            .bearer_auth(&token)
            .json(&json!({"cursor": 1}))
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{ack}");
    assert_eq!(ack["advanced"], false);
    assert_eq!(ack["cursorSequence"], 1);

    let (status, probe) = response_json(
        http.get(&probe_url)
            .bearer_auth(&token)
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{probe}");
    assert_eq!(probe["unreadCount"], 0);
    assert_eq!(probe["hasUpdates"], false);

    let (status, error) = response_json(
        http.get(format!("{}/consumers/missing/probe", hub.base_url))
            .bearer_auth(&token)
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{error}");
    assert!(
        error["error"]
            .as_str()
            .unwrap()
            .contains("unknown consumer")
    );

    unsafe { std::env::remove_var(&variable) };
}

#[tokio::test]
async fn consumer_mcp_tools_round_trip_without_touching_ack_events() {
    let temp = TempDir::new().unwrap();
    let hub = RunningHub::start(
        temporary_database(&temp),
        CallbackPolicy::for_tests(),
        false,
    )
    .await;
    hub.hub
        .ingest_event(failed_event("evt_consumer_failed"))
        .unwrap();
    hub.hub
        .ingest_event(completed_event("evt_consumer_completed"))
        .unwrap();

    let mut client = hub.client();
    client.initialize().await;

    let probe = client
        .tool_call("probe_consumer", json!({"consumer": "Muse"}))
        .await;
    assert_eq!(probe["isError"], false, "{probe}");
    assert_eq!(probe["structuredContent"]["consumer"], "muse");
    assert_eq!(probe["structuredContent"]["latestSequence"], 2);
    assert_eq!(probe["structuredContent"]["cursorSequence"], 0);
    assert_eq!(probe["structuredContent"]["unreadCount"], 2);
    assert_eq!(probe["structuredContent"]["hasUpdates"], true);

    let poll = client
        .tool_call(
            "poll_consumer_events",
            json!({"consumer": "muse", "limit": 1}),
        )
        .await;
    assert_eq!(poll["isError"], false, "{poll}");
    assert_eq!(poll["structuredContent"]["cursorSequence"], 0);
    assert_eq!(poll["structuredContent"]["nextCursorSequence"], 1);
    assert_eq!(poll["structuredContent"]["hasMore"], true);
    assert_eq!(
        poll["structuredContent"]["events"]
            .as_array()
            .unwrap()
            .len(),
        1
    );

    let all = client
        .tool_call("poll_consumer_events", json!({"consumer": "muse"}))
        .await;
    assert_eq!(all["isError"], false, "{all}");
    let events = all["structuredContent"]["events"].as_array().unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0]["name"], "t3.run.failed");
    assert_eq!(events[0]["disposition"], "immediate");
    assert_eq!(events[1]["name"], "t3.run.completed");
    assert_eq!(events[1]["disposition"], "digest");

    // Polling did not advance the cursor.
    assert_eq!(all["structuredContent"]["cursorSequence"], 0);

    // `ack_events` remains the user-facing acknowledgement tool and does not
    // move the consumer cursor.
    let user_ack = client
        .tool_call("ack_events", json!({"event_ids": ["evt_consumer_failed"]}))
        .await;
    assert_eq!(user_ack["isError"], false, "{user_ack}");
    assert_eq!(
        user_ack["structuredContent"]["acknowledged"],
        json!(["evt_consumer_failed"])
    );
    let probe = client
        .tool_call("probe_consumer", json!({"consumer": "muse"}))
        .await;
    assert_eq!(probe["structuredContent"]["cursorSequence"], 0);
    assert_eq!(probe["structuredContent"]["unreadCount"], 2);

    let ack = client
        .tool_call(
            "ack_consumer_events",
            json!({"consumer": "muse", "upToSequence": 2}),
        )
        .await;
    assert_eq!(ack["isError"], false, "{ack}");
    assert_eq!(ack["structuredContent"]["previousCursorSequence"], 0);
    assert_eq!(ack["structuredContent"]["cursorSequence"], 2);
    assert_eq!(ack["structuredContent"]["advanced"], true);

    let probe = client
        .tool_call("probe_consumer", json!({"consumer": "muse"}))
        .await;
    assert_eq!(probe["structuredContent"]["unreadCount"], 0);

    let missing = client
        .tool_call("probe_consumer", json!({"consumer": "missing"}))
        .await;
    assert_eq!(missing["isError"], true, "{missing}");
    assert!(
        missing["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("unknown consumer")
    );

    let invalid_limit = client
        .tool_call(
            "poll_consumer_events",
            json!({"consumer": "muse", "limit": 0}),
        )
        .await;
    assert_eq!(invalid_limit["isError"], true, "{invalid_limit}");

    let missing_ack = client
        .tool_call(
            "ack_consumer_events",
            json!({"consumer": "muse", "upToSequence": 99}),
        )
        .await;
    assert_eq!(missing_ack["isError"], true, "{missing_ack}");
}
