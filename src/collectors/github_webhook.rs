//! GitHub webhook receiver (`POST /webhooks/github`).
//!
//! GitHub authenticates with `X-Hub-Signature-256` (HMAC-SHA256 over the exact
//! raw body), so this endpoint deliberately does not reuse the MCP bearer token
//! or the MCP `Host` allowlist. `X-GitHub-Delivery` is the idempotency key; the
//! delivery record, materialized state and normalized events are committed in
//! one transaction by [`Repository::apply_github_webhook`].

use std::sync::Arc;

use axum::{
    Json,
    body::to_bytes,
    extract::Request,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use hmac::{Hmac, Mac};
use secrecy::ExposeSecret;
use serde_json::{Value, json};
use sha2::Sha256;

use crate::{
    app::AppState,
    collectors::github_state,
    store::GitHubDelivery,
    util::{constant_time_eq, now_rfc3339},
};

const HEADER_EVENT: &str = "x-github-event";
const HEADER_DELIVERY: &str = "x-github-delivery";
const HEADER_SIGNATURE: &str = "x-hub-signature-256";

const HANDLED_EVENTS: &[&str] = &[
    "ping",
    "workflow_run",
    "check_run",
    "pull_request",
    "pull_request_review",
    "pull_request_review_comment",
];

/// Handle one GitHub webhook request.
pub async fn handle(app: Arc<AppState>, request: Request) -> Response {
    let config = &app.config.collectors.github;
    let error_excerpt_max_chars = app.config.payload.error_excerpt_max_chars;
    if !config.webhook_enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Some(secret) = app.github_webhook_secret.as_ref() else {
        return json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"error": "github webhook secret is not configured"}),
        );
    };

    let limit = config.max_webhook_body_bytes.max(1);
    if content_length(request.headers()).is_some_and(|length| length > limit) {
        return payload_too_large();
    }

    let headers = request.headers().clone();
    let body = match to_bytes(request.into_body(), limit).await {
        Ok(body) => body,
        Err(_) => return payload_too_large(),
    };

    let signature = header_value(&headers, HEADER_SIGNATURE);
    if !verify_signature(secret.expose_secret().as_bytes(), &body, signature) {
        return json_response(
            StatusCode::UNAUTHORIZED,
            json!({"error": "invalid webhook signature"}),
        );
    }

    let Some(event_type) = non_empty_header(&headers, HEADER_EVENT) else {
        return json_response(
            StatusCode::BAD_REQUEST,
            json!({"error": "missing X-GitHub-Event header"}),
        );
    };
    let Some(delivery_id) = non_empty_header(&headers, HEADER_DELIVERY) else {
        return json_response(
            StatusCode::BAD_REQUEST,
            json!({"error": "missing X-GitHub-Delivery header"}),
        );
    };

    let payload: Value = match serde_json::from_slice(&body) {
        Ok(payload) => payload,
        Err(error) => {
            return json_response(
                StatusCode::BAD_REQUEST,
                json!({"error": format!("invalid JSON body: {error}")}),
            );
        }
    };
    if !payload.is_object() {
        return json_response(
            StatusCode::BAD_REQUEST,
            json!({"error": "webhook body must be a JSON object"}),
        );
    }

    let repository = github_state::repository_full_name(&payload);
    let ignored = !config.repositories.is_empty()
        && !repository
            .as_ref()
            .is_some_and(|repository| config.repositories.iter().any(|r| r == repository));
    let handled = HANDLED_EVENTS.contains(&event_type);

    let outcome = app.repo.apply_github_webhook(
        GitHubDelivery {
            delivery_id: delivery_id.to_string(),
            event_type: event_type.to_string(),
            repository: repository.clone(),
        },
        |tx| {
            if ignored || !handled {
                return Ok(Default::default());
            }
            github_state::normalize_webhook_with_excerpt_max_chars(
                tx,
                event_type,
                &payload,
                delivery_id,
                &now_rfc3339(),
                error_excerpt_max_chars,
            )
        },
    );

    let outcome = match outcome {
        Ok(outcome) => outcome,
        Err(error) => {
            tracing::warn!(%error, event = event_type, delivery = delivery_id, "github webhook failed");
            return json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error": "could not apply webhook"}),
            );
        }
    };

    if outcome.duplicate_delivery {
        return json_response(StatusCode::OK, json!({"status": "duplicate"}));
    }
    if outcome.emitted() > 0 {
        app.bus.notify();
    }
    if ignored || !handled {
        return json_response(StatusCode::OK, json!({"status": "ignored"}));
    }

    tracing::info!(
        event = event_type,
        delivery = delivery_id,
        repository = repository.as_deref().unwrap_or_default(),
        events = outcome.emitted(),
        "github webhook accepted"
    );
    json_response(
        StatusCode::OK,
        json!({
            "status": "ok",
            "events": outcome.emitted(),
            "deliveriesCreated": outcome.deliveries_created,
        }),
    )
}

fn content_length(headers: &HeaderMap) -> Option<usize> {
    headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
}

fn header_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

fn non_empty_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    header_value(headers, name)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn verify_signature(secret: &[u8], body: &[u8], header: Option<&str>) -> bool {
    let Some(header) = header else {
        return false;
    };
    let Some(encoded) = header.strip_prefix("sha256=") else {
        return false;
    };
    if encoded.len() != 64 || !encoded.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return false;
    }
    let Ok(expected) = hex::decode(encoded) else {
        return false;
    };
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(body);
    let computed = mac.finalize().into_bytes();
    constant_time_eq(&computed, &expected)
}

fn payload_too_large() -> Response {
    json_response(
        StatusCode::PAYLOAD_TOO_LARGE,
        json!({"error": "webhook body too large"}),
    )
}

fn json_response(status: StatusCode, value: Value) -> Response {
    (status, Json(value)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signatures_verify_and_reject_tampering() {
        let secret = b"test-secret";
        let body = br#"{"action":"completed"}"#;
        let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
        mac.update(body);
        let signature = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));
        assert!(verify_signature(secret, body, Some(&signature)));
        assert!(!verify_signature(
            secret,
            br#"{"action":"edited"}"#,
            Some(&signature)
        ));
        assert!(!verify_signature(secret, body, Some("sha256=abcd")));
        assert!(!verify_signature(secret, body, None));
        assert!(!verify_signature(secret, body, Some("v1,abcd")));
    }

    #[test]
    fn empty_headers_are_rejected() {
        let mut headers = HeaderMap::new();
        headers.insert(HEADER_EVENT, "  ".parse().unwrap());
        assert!(non_empty_header(&headers, HEADER_EVENT).is_none());
        headers.insert(HEADER_EVENT, "pull_request".parse().unwrap());
        assert_eq!(
            non_empty_header(&headers, HEADER_EVENT),
            Some("pull_request")
        );
    }
}
