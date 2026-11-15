//! Streamable HTTP transport for the MCP endpoint.
//!
//! `rmcp::StreamableHttpService` owns initialization, session management
//! (`Mcp-Session-Id`), SSE framing, `tools/list`, and `tools/call`. Two gaps
//! are filled here because the SDK's typed capability model does not know the
//! MCP Events draft:
//!
//! * `capabilities.events` is injected into `initialize` and `server/discover`
//!   responses.
//! * `events/list`, `events/subscribe`, and `events/unsubscribe` are dispatched
//!   by a JSON-RPC layer before the request reaches the SDK, so they work even
//!   when the client has not retained a legacy session id.
//!
//! Everything else is forwarded byte-for-byte to the SDK service.

use std::sync::Arc;

use axum::{
    Json, Router,
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::{any, get, post},
};
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
};
use secrecy::ExposeSecret;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;
use url::Url;

use crate::{
    app::AppState,
    auth::AuthError,
    mcp::{error::INVALID_REQUEST, handler::EventsHandler},
    store::NewEvent,
    util::constant_time_eq,
};

/// Events capability advertised during initialization.
pub const EVENTS_CAPABILITY: &str = "events";

const MAX_MCP_REQUEST_BYTES: usize = 4 * 1024 * 1024 + 4096;
const MAX_MCP_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const HEADER_INTERNAL_TOKEN: &str = "x-internal-token";

struct McpHttpState {
    app: Arc<AppState>,
    service: StreamableHttpService<EventsHandler, LocalSessionManager>,
}

/// Build the hub router.
pub fn router(app: Arc<AppState>) -> Router {
    router_with_cancellation(app, CancellationToken::new())
}

/// Build the hub router with a cancellation token wired into the MCP HTTP service.
pub fn router_with_cancellation(app: Arc<AppState>, cancellation: CancellationToken) -> Router {
    let server_config = StreamableHttpServerConfig::default()
        // Prefer JSON for simple request/response traffic. This keeps the
        // initialize response patchable without parsing SSE framing.
        .with_json_response(true)
        .with_sse_keep_alive(None)
        .with_allowed_hosts(app.config.server.allowed_hosts.clone())
        .with_cancellation_token(cancellation)
        .with_max_request_body_bytes(MAX_MCP_REQUEST_BYTES);

    let service = {
        let app = app.clone();
        StreamableHttpService::new(
            move || Ok(EventsHandler::new(app.clone())),
            Arc::new(LocalSessionManager::default()),
            server_config,
        )
    };

    let state = Arc::new(McpHttpState { app, service });

    Router::new()
        .route("/mcp", any(mcp_entry))
        .route("/healthz", get(healthz))
        .route("/internal/events", post(internal_ingest))
        .with_state(state)
        .layer(tower_http::trace::TraceLayer::new_for_http())
}

async fn healthz() -> impl IntoResponse {
    Json(json!({"status": "ok"}))
}

/// A parsed HTTP authority (`host` without brackets, optional port).
#[derive(Debug, Clone, PartialEq, Eq)]
struct NormalizedAuthority {
    host: String,
    port: Option<u16>,
}

fn normalize_host(host: &str) -> String {
    host.trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase()
}

fn parse_authority(value: &str) -> Option<NormalizedAuthority> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let authority = http::uri::Authority::try_from(value).ok()?;
    Some(NormalizedAuthority {
        host: normalize_host(authority.host()),
        port: authority.port_u16(),
    })
}

/// Allowlist entries may be bare IPv6 addresses (e.g. `::1`) that are not
/// valid HTTP authorities; mirror the SDK by treating them as host-only.
fn parse_allowed_authority(value: &str) -> Option<NormalizedAuthority> {
    parse_authority(value).or_else(|| {
        let value = value.trim();
        (!value.is_empty()).then(|| NormalizedAuthority {
            host: normalize_host(value),
            port: None,
        })
    })
}

/// Resolve the request authority from `Host` (HTTP/1.1) or the URI authority
/// (HTTP/2 `:authority`).
fn request_authority(headers: &HeaderMap, uri: &Uri) -> Result<NormalizedAuthority, &'static str> {
    let raw = headers
        .get(header::HOST)
        .map(|value| {
            value
                .to_str()
                .map(str::to_owned)
                .map_err(|_| "invalid Host header encoding")
        })
        .transpose()?
        .or_else(|| uri.authority().map(|authority| authority.to_string()));
    let Some(raw) = raw else {
        return Err("missing Host header");
    };
    parse_authority(&raw).ok_or("invalid Host header")
}

fn host_is_allowed(host: &NormalizedAuthority, allowed_hosts: &[String]) -> bool {
    if allowed_hosts.is_empty() {
        // Matches the SDK's behavior: an empty allowlist disables the check.
        return true;
    }
    allowed_hosts
        .iter()
        .filter_map(|allowed| parse_allowed_authority(allowed))
        .any(|allowed| {
            allowed.host == host.host && allowed.port.is_none_or(|port| host.port == Some(port))
        })
}

fn origin_is_allowed(origin: &str, host: &NormalizedAuthority, allowed_hosts: &[String]) -> bool {
    let Ok(url) = Url::parse(origin.trim()) else {
        return false;
    };
    if !matches!(url.scheme(), "http" | "https") {
        return false;
    }
    let Some(origin_host) = url.host_str().map(normalize_host) else {
        return false;
    };
    if origin_host == host.host {
        return true;
    }
    allowed_hosts
        .iter()
        .filter_map(|allowed| parse_allowed_authority(allowed))
        .any(|allowed| allowed.host == origin_host)
}

/// Small rejection type so security helpers do not return a large `Response`
/// in their `Err` variant.
enum HttpRejection {
    BadRequest(&'static str),
    Forbidden(&'static str),
    UnsupportedMediaType(&'static str),
}

impl HttpRejection {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::BadRequest(message) => (StatusCode::BAD_REQUEST, message),
            Self::Forbidden(message) => (StatusCode::FORBIDDEN, message),
            Self::UnsupportedMediaType(message) => (StatusCode::UNSUPPORTED_MEDIA_TYPE, message),
        };
        (status, message).into_response()
    }
}

/// Common HTTP security checks shared by the Events extension and SDK
/// forwarding: Host must be allowlisted and an Origin, when present, must
/// match the request Host or one of the allowed hosts.
fn validate_http_security(
    headers: &HeaderMap,
    uri: &Uri,
    allowed_hosts: &[String],
) -> Result<(), HttpRejection> {
    let host = request_authority(headers, uri).map_err(HttpRejection::BadRequest)?;
    if !host_is_allowed(&host, allowed_hosts) {
        return Err(HttpRejection::Forbidden(
            "Forbidden: Host header is not allowed",
        ));
    }

    if let Some(origin) = headers.get(header::ORIGIN) {
        let origin = origin
            .to_str()
            .map_err(|_| HttpRejection::Forbidden("Forbidden: invalid Origin header encoding"))?;
        if !origin_is_allowed(origin, &host, allowed_hosts) {
            return Err(HttpRejection::Forbidden(
                "Forbidden: Origin header is not allowed",
            ));
        }
    }
    Ok(())
}

/// `POST /mcp` only accepts JSON. Media type parameters such as
/// `application/json; charset=utf-8` are permitted.
fn require_json_content_type(headers: &HeaderMap) -> Result<(), HttpRejection> {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let media_type = content_type.split(';').next().unwrap_or_default().trim();
    if media_type.eq_ignore_ascii_case("application/json") {
        Ok(())
    } else {
        Err(HttpRejection::UnsupportedMediaType(
            "unsupported media type; expected application/json",
        ))
    }
}

/// Validate the JSON-RPC 2.0 envelope for hub-served `events/*` methods.
fn validate_events_envelope(object: &serde_json::Map<String, Value>) -> Result<(), String> {
    match object.get("jsonrpc") {
        Some(Value::String(version)) if version == "2.0" => {}
        Some(_) => return Err("`jsonrpc` must be the string \"2.0\"".to_string()),
        None => return Err("`jsonrpc` is required".to_string()),
    }
    if let Some(id) = object.get("id") {
        match id {
            Value::String(_) | Value::Number(_) | Value::Null => {}
            _ => return Err("`id` must be a string, number, or null".to_string()),
        }
    }
    Ok(())
}

fn invalid_request(message: impl std::fmt::Display) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "jsonrpc": "2.0",
            "id": Value::Null,
            "error": {
                "code": INVALID_REQUEST,
                "message": format!("Invalid Request: {message}"),
            },
        })),
    )
        .into_response()
}

async fn mcp_entry(State(state): State<Arc<McpHttpState>>, request: Request) -> Response {
    let principal = match state.app.auth.authenticate(request.headers()) {
        Ok(principal) => principal,
        Err(error) => return unauthorized(error),
    };

    if let Err(response) = validate_http_security(
        request.headers(),
        request.uri(),
        &state.app.config.server.allowed_hosts,
    ) {
        return response.into_response();
    }

    let is_post = request.method() == Method::POST;
    if is_post && let Err(response) = require_json_content_type(request.headers()) {
        return response.into_response();
    }
    if !is_post {
        return forward(state.service.clone(), request).await;
    }

    let (parts, body) = request.into_parts();
    let bytes = match axum::body::to_bytes(body, MAX_MCP_REQUEST_BYTES).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return (StatusCode::PAYLOAD_TOO_LARGE, "request body too large").into_response();
        }
    };

    let parsed: Option<Value> = serde_json::from_slice(&bytes).ok();

    // Events extension methods are served by the hub itself. They are not
    // allowed to bypass JSON-RPC 2.0 envelope validation because invalid
    // requests must not cause side effects such as a callback challenge.
    if let Some(object) = parsed.as_ref().and_then(Value::as_object)
        && let Some(method) = object.get("method").and_then(Value::as_str)
        && method.starts_with("events/")
    {
        if let Err(message) = validate_events_envelope(object) {
            return invalid_request(message);
        }
        let id = object.get("id").cloned();
        let params = object.get("params").cloned();
        return events_jsonrpc(&state.app, method, params, id, &principal).await;
    }

    let patch_capabilities = parsed
        .as_ref()
        .and_then(|value| value.get("method"))
        .and_then(Value::as_str)
        .is_some_and(|method| method == "initialize" || method == "server/discover");

    let request = Request::from_parts(parts, Body::from(bytes));
    let response = forward(state.service.clone(), request).await;
    if patch_capabilities {
        patch_response_capabilities(response).await
    } else {
        response
    }
}

async fn forward(
    service: StreamableHttpService<EventsHandler, LocalSessionManager>,
    request: Request,
) -> Response {
    match service.oneshot(request).await {
        Ok(response) => response.map(Body::new),
        Err(infallible) => match infallible {},
    }
}

async fn events_jsonrpc(
    app: &Arc<AppState>,
    method: &str,
    params: Option<Value>,
    id: Option<Value>,
    principal: &str,
) -> Response {
    // JSON-RPC notifications have no id and expect no response body.
    let Some(id) = id else {
        return StatusCode::ACCEPTED.into_response();
    };

    let payload = match app.subscriptions.handle(method, params, principal).await {
        Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
        Err(error) => json!({"jsonrpc": "2.0", "id": id, "error": error.to_json()}),
    };
    Json(payload).into_response()
}

fn unauthorized(error: AuthError) -> Response {
    let mut response = (
        StatusCode::UNAUTHORIZED,
        Json(json!({"error": error.message()})),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    response
}

/// Inject `capabilities.events` into a JSON or SSE MCP response body.
pub fn patch_mcp_body(bytes: &[u8], content_type: &str) -> Vec<u8> {
    if content_type.contains("text/event-stream") {
        let text = String::from_utf8_lossy(bytes);
        let mut output = String::with_capacity(text.len() + 64);
        for line in text.split_inclusive('\n') {
            let content_end = line.trim_end_matches(['\r', '\n']).len();
            let (content, ending) = line.split_at(content_end);
            if let Some(data) = content.strip_prefix("data:")
                && let Ok(mut value) = serde_json::from_str::<Value>(data.trim_start())
            {
                inject_events_capability(&mut value);
                if let Ok(serialized) = serde_json::to_string(&value) {
                    output.push_str("data: ");
                    output.push_str(&serialized);
                    output.push_str(ending);
                    continue;
                }
            }
            output.push_str(line);
        }
        return output.into_bytes();
    }

    if content_type.contains("application/json")
        && let Ok(mut value) = serde_json::from_slice::<Value>(bytes)
    {
        inject_events_capability(&mut value);
        if let Ok(serialized) = serde_json::to_vec(&value) {
            return serialized;
        }
    }

    bytes.to_vec()
}

fn inject_events_capability(value: &mut Value) {
    let Some(result) = value.get_mut("result").and_then(Value::as_object_mut) else {
        return;
    };
    let capabilities = result
        .entry("capabilities")
        .or_insert_with(|| Value::Object(serde_json::Map::new()));
    if let Some(capabilities) = capabilities.as_object_mut() {
        capabilities.insert(EVENTS_CAPABILITY.to_string(), json!({"listChanged": false}));
    }
}

async fn patch_response_capabilities(response: Response) -> Response {
    let (mut parts, body) = response.into_parts();
    let content_type = parts
        .headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();

    let bytes = match axum::body::to_bytes(body, MAX_MCP_RESPONSE_BYTES).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return (StatusCode::BAD_GATEWAY, "could not buffer MCP response").into_response();
        }
    };
    let patched = patch_mcp_body(&bytes, &content_type);

    parts.headers.remove(header::CONTENT_LENGTH);
    if let Ok(length) = HeaderValue::from_str(&patched.len().to_string()) {
        parts.headers.insert(header::CONTENT_LENGTH, length);
    }
    Response::from_parts(parts, Body::from(patched))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IngestRequest {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    source: Option<String>,
    kind: String,
    payload: Value,
    #[serde(default)]
    occurred_at: Option<String>,
}

async fn internal_ingest(
    State(state): State<Arc<McpHttpState>>,
    uri: Uri,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if !state.app.config.server.enable_internal_ingest {
        return StatusCode::NOT_FOUND.into_response();
    }

    if let Err(response) =
        validate_http_security(&headers, &uri, &state.app.config.server.allowed_hosts)
    {
        return response.into_response();
    }

    if let Err(error) = state.app.auth.authenticate(&headers) {
        return unauthorized(error);
    }

    if let Some(expected) = &state.app.internal_token {
        let presented = headers
            .get(HEADER_INTERNAL_TOKEN)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        if !constant_time_eq(presented.as_bytes(), expected.expose_secret().as_bytes()) {
            return unauthorized(AuthError::InvalidToken);
        }
    }

    let request: IngestRequest = match serde_json::from_value(body) {
        Ok(request) => request,
        Err(error) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": error.to_string()})),
            )
                .into_response();
        }
    };

    let outcome = match state.app.ingest.ingest(NewEvent {
        id: request.id,
        source: request.source,
        kind: request.kind,
        payload: request.payload,
        occurred_at: request.occurred_at,
    }) {
        Ok(outcome) => outcome,
        Err(error) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({"error": error.to_string()})),
            )
                .into_response();
        }
    };

    Json(json!({
        "event": outcome.event,
        "duplicate": outcome.duplicate,
        "deliveriesCreated": outcome.deliveries_created,
    }))
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_initialize_response_gets_events_capability() {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "events-bridge", "version": "0.1.0"}
            }
        });
        let patched = patch_mcp_body(
            serde_json::to_vec(&body).unwrap().as_slice(),
            "application/json",
        );
        let value: Value = serde_json::from_slice(&patched).unwrap();
        assert_eq!(
            value["result"]["capabilities"]["events"]["listChanged"],
            false
        );
        assert!(value["result"]["capabilities"]["tools"].is_object());
    }

    #[test]
    fn discover_response_gets_events_capability() {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 2,
            "result": {
                "resultType": "complete",
                "supportedVersions": ["2026-07-28"],
                "capabilities": {},
                "ttlMs": 0,
                "cacheScope": "private"
            }
        });
        let patched = patch_mcp_body(
            serde_json::to_vec(&body).unwrap().as_slice(),
            "application/json",
        );
        let value: Value = serde_json::from_slice(&patched).unwrap();
        assert_eq!(
            value["result"]["capabilities"]["events"]["listChanged"],
            false
        );
    }

    #[test]
    fn sse_frames_are_patched_without_touching_other_lines() {
        let body = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"capabilities\":{}}}\n\n";
        let patched = patch_mcp_body(body.as_bytes(), "text/event-stream");
        let text = String::from_utf8(patched).unwrap();
        assert!(text.contains("event: message\n"));
        assert!(text.contains("\"events\":{\"listChanged\":false}"));
    }

    #[test]
    fn non_mcp_bodies_are_left_alone() {
        let body = b"not json";
        assert_eq!(patch_mcp_body(body, "text/plain"), body.to_vec());
    }

    fn authority(value: &str) -> NormalizedAuthority {
        parse_authority(value).expect("authority parses")
    }

    #[test]
    fn allowed_hosts_match_ignoring_ports_and_brackets() {
        let allowed = vec![
            "localhost".to_string(),
            "127.0.0.1".to_string(),
            "::1".to_string(),
        ];
        assert!(host_is_allowed(&authority("127.0.0.1:8787"), &allowed));
        assert!(host_is_allowed(&authority("LOCALHOST:1"), &allowed));
        assert!(host_is_allowed(&authority("[::1]:8787"), &allowed));
        assert!(!host_is_allowed(&authority("evil.example"), &allowed));

        // An allowed entry with an explicit port pins that port.
        let pinned = vec!["example.com:8443".to_string()];
        assert!(host_is_allowed(&authority("example.com:8443"), &pinned));
        assert!(!host_is_allowed(&authority("example.com:443"), &pinned));
        assert!(!host_is_allowed(&authority("example.com"), &pinned));

        // An empty allowlist disables the check, mirroring the SDK.
        assert!(host_is_allowed(&authority("anything.example"), &[]));
    }

    #[test]
    fn origins_must_match_the_host_or_an_allowed_host() {
        let host = authority("bridge.example.com:8787");
        let allowed = vec!["localhost".to_string(), "bridge.example.com".to_string()];
        assert!(origin_is_allowed(
            "https://bridge.example.com",
            &host,
            &allowed
        ));
        assert!(origin_is_allowed("http://localhost:3000", &host, &allowed));
        assert!(!origin_is_allowed("https://evil.example", &host, &allowed));
        assert!(!origin_is_allowed("null", &host, &allowed));
        assert!(!origin_is_allowed("not a URL", &host, &allowed));
    }

    #[test]
    fn json_content_type_allows_parameters() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json; charset=utf-8"),
        );
        assert!(require_json_content_type(&headers).is_ok());

        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
        assert!(matches!(
            require_json_content_type(&headers),
            Err(HttpRejection::UnsupportedMediaType(_))
        ));

        headers.remove(header::CONTENT_TYPE);
        assert!(require_json_content_type(&headers).is_err());
    }

    #[test]
    fn jsonrpc_envelope_is_validated() {
        let valid = json!({"jsonrpc": "2.0", "id": 1, "method": "events/list"});
        assert!(validate_events_envelope(valid.as_object().unwrap()).is_ok());

        let null_id = json!({"jsonrpc": "2.0", "id": null, "method": "events/list"});
        assert!(validate_events_envelope(null_id.as_object().unwrap()).is_ok());

        let missing_version = json!({"id": 1, "method": "events/list"});
        assert!(validate_events_envelope(missing_version.as_object().unwrap()).is_err());

        let wrong_version = json!({"jsonrpc": "1.0", "id": 1, "method": "events/list"});
        assert!(validate_events_envelope(wrong_version.as_object().unwrap()).is_err());

        for id in [json!({"nested": 1}), json!([1]), json!(true)] {
            let invalid = json!({"jsonrpc": "2.0", "id": id, "method": "events/list"});
            assert!(
                validate_events_envelope(invalid.as_object().unwrap()).is_err(),
                "id {id} must be rejected"
            );
        }
    }
}
