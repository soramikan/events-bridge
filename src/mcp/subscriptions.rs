//! Subscription identity, TTL negotiation, and the `events/*` methods.

use std::collections::BTreeMap;
use std::sync::Arc;

use chrono::{Duration as ChronoDuration, Utc};
use serde::Deserialize;
use serde::de::Error as _;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use url::Url;

use crate::config::SubscriptionConfig;
use crate::delivery::verification::{self, CallbackPolicy};
use crate::mcp::error::RpcError;
use crate::mcp::event_catalog;
use crate::store::{Event, EventQuery, NewSubscription, Repository, arguments_match};
use crate::util::{format_rfc3339, timestamp_lt};

/// Default number of events returned by one `events/poll` response.
pub const DEFAULT_POLL_MAX_EVENTS: usize = 50;
/// Hard cap on `events/poll` `maxEvents`, matching the pull tools' page size.
pub const MAX_POLL_MAX_EVENTS: usize = 200;
/// Suggested delay before the next `events/poll`, in milliseconds.
pub const DEFAULT_NEXT_POLL_MS: u64 = 5000;
/// Events scanned per repository query while filling one poll page.
const POLL_SCAN_BATCH: i64 = 256;

/// Recursively sort object keys so logically-equal arguments hash equally.
pub fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let sorted: BTreeMap<&String, Value> = map
                .iter()
                .map(|(key, value)| (key, canonicalize(value)))
                .collect();
            Value::Object(
                sorted
                    .into_iter()
                    .map(|(key, value)| (key.clone(), value))
                    .collect(),
            )
        }
        Value::Array(items) => Value::Array(items.iter().map(canonicalize).collect()),
        other => other.clone(),
    }
}

/// Canonical JSON serialization of subscription arguments.
pub fn canonical_json(value: &Value) -> String {
    serde_json::to_string(&canonicalize(value)).unwrap_or_else(|_| "null".into())
}

/// SHA-256 hash of the canonical arguments.
pub fn filter_hash(canonical_arguments: &str) -> String {
    hex::encode(Sha256::digest(canonical_arguments.as_bytes()))
}

/// Deterministic subscription id over
/// `(principal, callback URL, event name, canonical arguments)`.
///
/// Each field is length-prefixed so concatenation cannot alias.
pub fn subscription_id(
    principal: &str,
    callback_url: &str,
    event_name: &str,
    canonical_arguments: &str,
) -> String {
    let mut hasher = Sha256::new();
    for part in [principal, callback_url, event_name, canonical_arguments] {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    let digest = hex::encode(hasher.finalize());
    format!("sub_{}", &digest[..24])
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SubscribeParams {
    name: String,
    #[serde(default)]
    arguments: Option<Value>,
    delivery: DeliveryParams,
    #[serde(default)]
    #[allow(dead_code)]
    cursor: Option<String>,
    #[serde(default, deserialize_with = "deserialize_ttl_ms")]
    ttl_ms: Option<Option<u64>>,
    #[serde(default)]
    #[allow(dead_code)]
    max_age_ms: Option<u64>,
    /// MCP 2.0 request metadata. Only a JSON object is accepted.
    #[serde(rename = "_meta", default)]
    #[allow(dead_code)]
    _meta: Option<serde_json::Map<String, Value>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DeliveryParams {
    #[serde(default)]
    mode: Option<String>,
    url: String,
    secret: String,
}

/// SEP-3415 `events/poll` parameters.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PollParams {
    name: String,
    #[serde(default)]
    arguments: Option<Value>,
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default)]
    max_age_ms: Option<u64>,
    #[serde(default)]
    max_events: Option<usize>,
    /// MCP 2.0 request metadata. Only a JSON object is accepted.
    #[serde(rename = "_meta", default)]
    #[allow(dead_code)]
    _meta: Option<serde_json::Map<String, Value>>,
}

/// Parse an opaque poll cursor of the form `seq_<non-negative integer>`.
fn parse_poll_cursor(cursor: &str) -> Option<i64> {
    let raw = cursor.strip_prefix("seq_")?;
    if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    raw.parse::<i64>().ok()
}

/// One `events/poll` event object.
fn poll_event(event: &Event) -> Value {
    json!({
        "eventId": event.id,
        "name": event.kind,
        "timestamp": event.occurred_at,
        "data": event.payload,
    })
}

/// Build the SEP-3415 `events/poll` result.
fn poll_result(events: Vec<Value>, cursor: i64, truncated: bool, has_more: bool) -> Value {
    json!({
        "events": events,
        "cursor": format!("seq_{cursor}"),
        "truncated": truncated,
        "hasMore": has_more,
        "nextPollMs": DEFAULT_NEXT_POLL_MS,
    })
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UnsubscribeParams {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    arguments: Option<Value>,
    #[serde(default)]
    delivery: Option<UnsubscribeDelivery>,
    /// MCP 2.0 request metadata. Only a JSON object is accepted.
    #[serde(rename = "_meta", default)]
    #[allow(dead_code)]
    _meta: Option<serde_json::Map<String, Value>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UnsubscribeDelivery {
    #[serde(default)]
    #[allow(dead_code)]
    mode: Option<String>,
    url: String,
}

fn deserialize_ttl_ms<'de, D>(deserializer: D) -> Result<Option<Option<u64>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Value::deserialize(deserializer)?;
    match value {
        Value::Null => Ok(Some(None)),
        Value::Number(number) => number
            .as_u64()
            .map(|ttl| Some(Some(ttl)))
            .ok_or_else(|| D::Error::custom("ttlMs must be a non-negative integer")),
        _ => Err(D::Error::custom(
            "ttlMs must be a non-negative integer or null",
        )),
    }
}

/// Owns `events/list`, `events/subscribe`, `events/unsubscribe`, and
/// `events/poll`.
#[derive(Clone)]
pub struct SubscriptionManager {
    repo: Arc<Repository>,
    config: SubscriptionConfig,
    policy: CallbackPolicy,
}

impl SubscriptionManager {
    /// Create a manager.
    pub fn new(repo: Arc<Repository>, config: SubscriptionConfig, policy: CallbackPolicy) -> Self {
        Self {
            repo,
            config,
            policy,
        }
    }

    /// Dispatch an `events/*` method.
    pub async fn handle(
        &self,
        method: &str,
        params: Option<Value>,
        principal: &str,
    ) -> Result<Value, RpcError> {
        match method {
            "events/list" => Ok(event_catalog::list_result()),
            "events/poll" => self.poll(params),
            "events/subscribe" => self.subscribe(params, principal).await,
            "events/unsubscribe" => self.unsubscribe(params, principal),
            other => Err(RpcError::new(
                crate::mcp::error::METHOD_NOT_FOUND,
                format!("method not found: {other}"),
                None,
            )),
        }
    }

    /// SEP-3415 `events/poll`.
    ///
    /// `cursor: null` starts at the current watermark, so a client only sees
    /// events ingested after its first poll. A `seq_<N>` cursor replays events
    /// of the requested type with `sequence > N`, filtered by the same
    /// predicate as webhook subscriptions.
    fn poll(&self, params: Option<Value>) -> Result<Value, RpcError> {
        let params: PollParams = serde_json::from_value(params.unwrap_or_else(|| json!({})))
            .map_err(|error| RpcError::invalid_params(error.to_string()))?;

        let definition = event_catalog::get(&params.name)
            .ok_or_else(|| RpcError::not_found("event", &params.name))?;

        let arguments = params.arguments.unwrap_or_else(|| json!({}));
        if !arguments.is_object() {
            return Err(RpcError::invalid_params(
                "`arguments` must be a JSON object",
            ));
        }
        event_catalog::validate_arguments(definition, &arguments)
            .map_err(RpcError::invalid_params)?;

        let limit = match params.max_events {
            // `maxEvents: 0` is malformed rather than "unlimited".
            Some(0) => {
                return Err(RpcError::invalid_params(
                    "`maxEvents` must be a positive integer",
                ));
            }
            Some(max_events) => max_events.min(MAX_POLL_MAX_EVENTS),
            None => DEFAULT_POLL_MAX_EVENTS,
        };

        // Sample the watermark before scanning so events inserted while this
        // request is running have a sequence above the returned cursor.
        let latest = self
            .repo
            .latest_event_sequence()
            .map_err(|error| RpcError::internal(error.to_string()))?;

        let Some(cursor) = params.cursor.as_deref() else {
            // SEP-3415: null/omitted cursor means "start from now".
            return Ok(poll_result(Vec::new(), latest, false, false));
        };
        let anchor = parse_poll_cursor(cursor).ok_or_else(|| {
            RpcError::invalid_params("`cursor` must be a `seq_<non-negative integer>` string")
        })?;

        if anchor > latest {
            // The cursor is ahead of this database (reset or foreign cursor).
            // Do not resurrect history: report truncation and restart at the
            // current watermark.
            return Ok(poll_result(Vec::new(), latest, true, false));
        }

        // A `maxAgeMs` of 0 means "no age filter". Very large values are
        // clamped so the subtraction cannot overflow.
        let cutoff = params.max_age_ms.and_then(|max_age_ms| {
            if max_age_ms == 0 {
                return None;
            }
            let milliseconds = i64::try_from(max_age_ms).unwrap_or(i64::MAX);
            Utc::now()
                .checked_sub_signed(ChronoDuration::milliseconds(milliseconds))
                .map(format_rfc3339)
        });

        let mut events: Vec<Value> = Vec::new();
        let mut last_returned = None;
        let mut truncated = false;
        let mut has_more = false;
        let mut after = anchor;

        loop {
            let batch = self
                .repo
                .list_events(&EventQuery {
                    kind: Some(params.name.clone()),
                    after_sequence: Some(after),
                    limit: POLL_SCAN_BATCH,
                    ..EventQuery::default()
                })
                .map_err(|error| RpcError::internal(error.to_string()))?;

            let batch_len = batch.len();
            for event in &batch {
                if !arguments_match(&arguments, &event.payload) {
                    continue;
                }
                if let Some(cutoff) = &cutoff
                    && timestamp_lt(&event.occurred_at, cutoff)
                {
                    // The event matched `arguments` but is older than the
                    // requested window, so the client will never see it.
                    truncated = true;
                    continue;
                }
                if events.len() == limit {
                    // One more deliverable match exists beyond this page.
                    has_more = true;
                    break;
                }
                events.push(poll_event(event));
                last_returned = Some(event.sequence);
            }

            if has_more {
                break;
            }
            let Some(last) = batch.last() else {
                break;
            };
            after = last.sequence;
            if batch_len < POLL_SCAN_BATCH as usize {
                break;
            }
        }

        let cursor_sequence = if has_more {
            // `has_more` implies at least one returned event.
            last_returned.unwrap_or(latest)
        } else {
            // No deliverable match remains after this page: advance the
            // watermark so empty and non-matching polls do not rescan.
            latest
        };

        Ok(poll_result(events, cursor_sequence, truncated, has_more))
    }

    async fn subscribe(&self, params: Option<Value>, principal: &str) -> Result<Value, RpcError> {
        let params: SubscribeParams =
            serde_json::from_value(params.unwrap_or_else(|| json!({})))
                .map_err(|error| RpcError::invalid_params(error.to_string()))?;

        let definition = event_catalog::get(&params.name)
            .ok_or_else(|| RpcError::not_found("event", &params.name))?;

        let arguments = params.arguments.unwrap_or_else(|| json!({}));
        if !arguments.is_object() {
            return Err(RpcError::invalid_params(
                "`arguments` must be a JSON object",
            ));
        }
        event_catalog::validate_arguments(definition, &arguments)
            .map_err(RpcError::invalid_params)?;

        let mode = params.delivery.mode.as_deref().unwrap_or("webhook");
        if mode != "webhook" {
            return Err(RpcError::invalid_params(format!(
                "unsupported delivery mode `{mode}`; Phase 1 supports `webhook`"
            )));
        }

        let url = Url::parse(&params.delivery.url).map_err(|error| {
            RpcError::callback(
                verification::CallbackError::new(
                    verification::reason::INVALID_URL,
                    format!("invalid callback URL: {error}"),
                ),
                &params.delivery.url,
            )
        })?;

        if !matches!(url.scheme(), "https" | "http") {
            return Err(RpcError::callback(
                verification::CallbackError::new(
                    verification::reason::INVALID_URL,
                    "callback URL must be an absolute http(s) URL",
                ),
                &params.delivery.url,
            ));
        }
        if self.policy.require_https && url.scheme() != "https" {
            return Err(RpcError::callback(
                verification::CallbackError::new(
                    verification::reason::INSECURE_URL,
                    "callback URL must use https",
                ),
                &params.delivery.url,
            ));
        }

        verification::validate_secret(&params.delivery.secret)
            .map_err(|error| RpcError::callback(error, &params.delivery.url))?;

        let canonical_arguments = canonical_json(&arguments);
        let filter_hash = filter_hash(&canonical_arguments);
        let id = subscription_id(
            principal,
            &params.delivery.url,
            &params.name,
            &canonical_arguments,
        );

        // A refresh of an already-verified subscription does not re-run the
        // challenge, but rotating the signing secret does: the endpoint must
        // prove it can receive and echo a challenge signed with the new key.
        // The old key and active state are left untouched until that succeeds.
        let existing = self
            .repo
            .get_subscription_by_key(principal, &params.delivery.url, &params.name, &filter_hash)
            .map_err(|error| RpcError::internal(error.to_string()))?;

        let needs_verification = existing.as_ref().is_none_or(|subscription| {
            !subscription.verified || subscription.secret != params.delivery.secret
        });
        if needs_verification {
            verification::verify_callback(&self.policy, &url, &params.delivery.secret, &id)
                .await
                .map_err(|error| RpcError::callback(error, &params.delivery.url))?;
        }

        let refresh_before = self.grant_ttl(params.ttl_ms);
        let subscription = self
            .repo
            .upsert_subscription(NewSubscription {
                id: id.clone(),
                principal: principal.to_owned(),
                event_name: params.name.clone(),
                arguments,
                filter_hash,
                callback_url: params.delivery.url.clone(),
                secret: params.delivery.secret,
                refresh_before,
            })
            .map_err(|error| RpcError::internal(error.to_string()))?;

        metrics::counter!("events_bridge_subscriptions_total").increment(1);
        tracing::info!(
            subscription_id = %subscription.id,
            event = %subscription.event_name,
            "subscription active"
        );

        // Phase 1 has no replayable history, so the safe-to-persist
        // watermark is always null regardless of the supplied cursor.
        Ok(json!({
            "id": subscription.id,
            "refreshBefore": subscription.refresh_before,
            "cursor": Value::Null,
            "truncated": false,
        }))
    }

    fn grant_ttl(&self, requested: Option<Option<u64>>) -> Option<String> {
        let now = Utc::now();
        match requested {
            // `ttlMs: null` explicitly requests no expiry.
            Some(None) => None,
            None => Some(format_rfc3339(
                now + ChronoDuration::seconds(self.config.default_ttl_secs as i64),
            )),
            Some(Some(ttl_ms)) => {
                let minimum = self.config.min_ttl_secs.saturating_mul(1_000);
                let maximum = self.config.max_ttl_secs.saturating_mul(1_000);
                let clamped = ttl_ms.max(minimum).min(maximum.max(minimum));
                Some(format_rfc3339(
                    now + ChronoDuration::milliseconds(clamped as i64),
                ))
            }
        }
    }

    fn unsubscribe(&self, params: Option<Value>, principal: &str) -> Result<Value, RpcError> {
        let params: UnsubscribeParams = serde_json::from_value(params.unwrap_or_else(|| json!({})))
            .map_err(|error| RpcError::invalid_params(error.to_string()))?;

        if let Some(id) = &params.id {
            let removed = self
                .repo
                .delete_subscription_by_id(principal, id)
                .map_err(|error| RpcError::internal(error.to_string()))?;
            if !removed {
                return Err(RpcError::not_found("subscription", id));
            }
            return Ok(json!({}));
        }

        let name = params
            .name
            .ok_or_else(|| RpcError::invalid_params("`name` is required"))?;
        let delivery = params
            .delivery
            .ok_or_else(|| RpcError::invalid_params("`delivery.url` is required"))?;
        let arguments = params.arguments.unwrap_or_else(|| json!({}));
        let canonical_arguments = canonical_json(&arguments);
        let filter_hash = filter_hash(&canonical_arguments);

        let removed = self
            .repo
            .delete_subscription_by_key(principal, &delivery.url, &name, &filter_hash)
            .map_err(|error| RpcError::internal(error.to_string()))?;
        if !removed {
            return Err(RpcError::not_found("subscription", &name));
        }
        Ok(json!({}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    /// Synthesize a valid webhook secret at runtime so no secret literal is
    /// committed to the repository.
    fn test_secret() -> String {
        format!(
            "whsec_{}",
            base64::engine::general_purpose::STANDARD.encode([0x11u8; 32])
        )
    }

    #[test]
    fn canonicalization_sorts_nested_keys() {
        let left = json!({"b": 1, "a": {"z": true, "y": [2, {"q": 1, "p": 2}]}});
        let right = json!({"a": {"y": [2, {"p": 2, "q": 1}], "z": true}, "b": 1});
        assert_eq!(canonical_json(&left), canonical_json(&right));
    }

    #[test]
    fn subscription_id_is_deterministic_and_key_sensitive() {
        let args = canonical_json(&json!({"environment_id": "linux-main"}));
        let base = subscription_id(
            "chatgpt",
            "https://r.example/hook",
            "t3.run.completed",
            &args,
        );
        assert!(base.starts_with("sub_"));
        assert_eq!(base.len(), 28);
        assert_eq!(
            base,
            subscription_id(
                "chatgpt",
                "https://r.example/hook",
                "t3.run.completed",
                &args
            )
        );
        assert_ne!(
            base,
            subscription_id("other", "https://r.example/hook", "t3.run.completed", &args)
        );
        assert_ne!(
            base,
            subscription_id(
                "chatgpt",
                "https://r.example/other",
                "t3.run.completed",
                &args
            )
        );
        assert_ne!(
            base,
            subscription_id("chatgpt", "https://r.example/hook", "t3.run.failed", &args)
        );
    }

    #[test]
    fn ttl_parsing_distinguishes_absent_and_null() {
        let absent: SubscribeParams = serde_json::from_value(json!({
            "name": "t3.run.completed",
            "arguments": {"environment_id": "linux-main"},
            "delivery": {"url": "https://r.example/hook", "secret": test_secret()}
        }))
        .unwrap();
        assert!(absent.ttl_ms.is_none());

        let null: SubscribeParams = serde_json::from_value(json!({
            "name": "t3.run.completed",
            "arguments": {"environment_id": "linux-main"},
            "delivery": {"url": "https://r.example/hook", "secret": test_secret()},
            "ttlMs": null
        }))
        .unwrap();
        assert_eq!(null.ttl_ms, Some(None));

        let finite: SubscribeParams = serde_json::from_value(json!({
            "name": "t3.run.completed",
            "arguments": {"environment_id": "linux-main"},
            "delivery": {"url": "https://r.example/hook", "secret": test_secret()},
            "ttlMs": 120000
        }))
        .unwrap();
        assert_eq!(finite.ttl_ms, Some(Some(120_000)));
    }

    #[test]
    fn mcp_meta_is_accepted_only_as_a_json_object() {
        let base = json!({
            "name": "t3.run.completed",
            "arguments": {"environment_id": "linux-main"},
            "delivery": {"url": "https://r.example/hook", "secret": test_secret()}
        });
        let mut with_meta = base.clone();
        with_meta["_meta"] = json!({
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "progressToken": "abc"
        });
        let params: SubscribeParams = serde_json::from_value(with_meta).unwrap();
        assert_eq!(params._meta.as_ref().map(|meta| meta.len()), Some(2));

        let mut invalid_meta = base;
        invalid_meta["_meta"] = json!(["not", "an", "object"]);
        assert!(
            serde_json::from_value::<SubscribeParams>(invalid_meta).is_err(),
            "`_meta` must be a JSON object"
        );

        let unsubscribe: UnsubscribeParams = serde_json::from_value(json!({
            "id": "sub_1",
            "_meta": {"progressToken": 1}
        }))
        .unwrap();
        assert!(unsubscribe._meta.is_some());
    }

    #[test]
    fn poll_cursor_accepts_only_seq_integers() {
        assert_eq!(parse_poll_cursor("seq_0"), Some(0));
        assert_eq!(parse_poll_cursor("seq_42"), Some(42));
        for invalid in [
            "", "seq_", "seq_-1", "seq_1.5", "seq_1x", "cursor_1", " seq_1",
        ] {
            assert_eq!(parse_poll_cursor(invalid), None, "{invalid:?}");
        }
    }

    fn poll_manager() -> (SubscriptionManager, Arc<Repository>) {
        let repo = Arc::new(Repository::open_in_memory().unwrap());
        let manager = SubscriptionManager::new(
            repo.clone(),
            SubscriptionConfig::default(),
            CallbackPolicy::default(),
        );
        (manager, repo)
    }

    fn completed_payload(environment: &str, project: &str) -> Value {
        json!({
            "environment_id": environment,
            "project_id": project,
            "thread_id": "thread-1",
            "run_id": "run-1",
            "summary": "done"
        })
    }

    fn ingest(
        repo: &Repository,
        id: &str,
        kind: &str,
        payload: Value,
        occurred_at: Option<&str>,
    ) -> i64 {
        repo.ingest_event(crate::store::NewEvent {
            id: Some(id.into()),
            source: None,
            kind: kind.into(),
            payload,
            occurred_at: occurred_at.map(str::to_owned),
        })
        .unwrap()
        .event
        .sequence
    }

    async fn poll(manager: &SubscriptionManager, params: Value) -> Result<Value, RpcError> {
        manager.handle("events/poll", Some(params), "local").await
    }

    #[tokio::test]
    async fn poll_with_null_cursor_starts_at_the_current_watermark() {
        let (manager, repo) = poll_manager();
        ingest(
            &repo,
            "evt_1",
            "t3.run.completed",
            completed_payload("linux-main", "lnako"),
            None,
        );

        let result = poll(
            &manager,
            json!({
                "name": "t3.run.completed",
                "arguments": {"environment_id": "linux-main"}
            }),
        )
        .await
        .unwrap();
        assert_eq!(result["events"], json!([]));
        assert_eq!(result["cursor"], "seq_1");
        assert_eq!(result["truncated"], false);
        assert_eq!(result["hasMore"], false);
        assert_eq!(result["nextPollMs"], DEFAULT_NEXT_POLL_MS);

        // Polling again from that cursor stays empty: "now" was the event.
        let result = poll(
            &manager,
            json!({
                "name": "t3.run.completed",
                "arguments": {"environment_id": "linux-main"},
                "cursor": "seq_1"
            }),
        )
        .await
        .unwrap();
        assert_eq!(result["events"], json!([]));
        assert_eq!(result["cursor"], "seq_1");
        assert_eq!(result["truncated"], false);
    }

    #[tokio::test]
    async fn poll_returns_matching_events_in_sequence_order_and_filters() {
        let (manager, repo) = poll_manager();
        let start = poll(
            &manager,
            json!({
                "name": "t3.run.completed",
                "arguments": {"environment_id": "linux-main"}
            }),
        )
        .await
        .unwrap();
        assert_eq!(start["cursor"], "seq_0");

        ingest(
            &repo,
            "evt_1",
            "t3.run.completed",
            completed_payload("linux-main", "lnako"),
            None,
        );
        ingest(
            &repo,
            "evt_2",
            "t3.run.completed",
            completed_payload("linux-other", "lnako"),
            None,
        );
        ingest(
            &repo,
            "evt_3",
            "t3.run.completed",
            completed_payload("linux-main", "other"),
            None,
        );

        let result = poll(
            &manager,
            json!({
                "name": "t3.run.completed",
                "arguments": {"environment_id": "linux-main", "project_id": "lnako"},
                "cursor": start["cursor"],
            }),
        )
        .await
        .unwrap();
        let events = result["events"].as_array().unwrap();
        assert_eq!(events.len(), 1, "{result}");
        assert_eq!(events[0]["eventId"], "evt_1");
        assert_eq!(events[0]["name"], "t3.run.completed");
        assert!(events[0]["timestamp"].as_str().is_some());
        assert_eq!(events[0]["data"]["project_id"], "lnako");
        // No deliverable match remains, so the watermark advances past the
        // non-matching events too.
        assert_eq!(result["cursor"], "seq_3");
        assert_eq!(result["truncated"], false);
        assert_eq!(result["hasMore"], false);

        // Empty poll from the advanced cursor must not rescan.
        let result = poll(
            &manager,
            json!({
                "name": "t3.run.completed",
                "arguments": {"environment_id": "linux-main"},
                "cursor": result["cursor"],
            }),
        )
        .await
        .unwrap();
        assert_eq!(result["events"], json!([]));
        assert_eq!(result["cursor"], "seq_3");
    }

    #[tokio::test]
    async fn poll_paginates_with_max_events_and_drains() {
        let (manager, repo) = poll_manager();
        let start = poll(
            &manager,
            json!({
                "name": "t3.run.completed",
                "arguments": {"environment_id": "linux-main"}
            }),
        )
        .await
        .unwrap();

        for index in 0..5 {
            ingest(
                &repo,
                &format!("evt_{index}"),
                "t3.run.completed",
                completed_payload("linux-main", "lnako"),
                None,
            );
        }

        let mut cursor = start["cursor"].as_str().unwrap().to_string();
        let mut seen = Vec::new();
        let mut pages = 0;
        loop {
            let result = poll(
                &manager,
                json!({
                    "name": "t3.run.completed",
                    "arguments": {"environment_id": "linux-main"},
                    "cursor": cursor,
                    "maxEvents": 2
                }),
            )
            .await
            .unwrap();
            pages += 1;
            seen.extend(
                result["events"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|event| event["eventId"].as_str().unwrap().to_string()),
            );
            cursor = result["cursor"].as_str().unwrap().to_string();
            if result["hasMore"] == false {
                break;
            }
            assert_eq!(result["events"].as_array().unwrap().len(), 2, "{result}");
        }

        assert_eq!(pages, 3, "two events per page over five events");
        assert_eq!(seen, ["evt_0", "evt_1", "evt_2", "evt_3", "evt_4"]);
        assert_eq!(cursor, "seq_5");
    }

    #[tokio::test]
    async fn poll_clamps_max_events_to_the_hard_cap() {
        let (manager, repo) = poll_manager();
        let start = poll(
            &manager,
            json!({
                "name": "t3.run.completed",
                "arguments": {"environment_id": "linux-main"}
            }),
        )
        .await
        .unwrap();
        for index in 0..3 {
            ingest(
                &repo,
                &format!("evt_{index}"),
                "t3.run.completed",
                completed_payload("linux-main", "lnako"),
                None,
            );
        }
        let result = poll(
            &manager,
            json!({
                "name": "t3.run.completed",
                "arguments": {"environment_id": "linux-main"},
                "cursor": start["cursor"],
                "maxEvents": 10_000
            }),
        )
        .await
        .unwrap();
        assert_eq!(result["events"].as_array().unwrap().len(), 3);
        assert_eq!(result["hasMore"], false);
    }

    #[tokio::test]
    async fn poll_max_age_skips_older_events_and_marks_truncation() {
        let (manager, repo) = poll_manager();
        let start = poll(
            &manager,
            json!({
                "name": "t3.run.completed",
                "arguments": {"environment_id": "linux-main"}
            }),
        )
        .await
        .unwrap();

        ingest(
            &repo,
            "evt_old",
            "t3.run.completed",
            completed_payload("linux-main", "lnako"),
            Some("2020-01-01T00:00:00.000Z"),
        );
        let recent = crate::util::now_rfc3339();
        ingest(
            &repo,
            "evt_recent",
            "t3.run.completed",
            completed_payload("linux-main", "lnako"),
            Some(&recent),
        );

        let result = poll(
            &manager,
            json!({
                "name": "t3.run.completed",
                "arguments": {"environment_id": "linux-main"},
                "cursor": start["cursor"],
                "maxAgeMs": 60_000
            }),
        )
        .await
        .unwrap();
        let events = result["events"].as_array().unwrap();
        assert_eq!(events.len(), 1, "{result}");
        assert_eq!(events[0]["eventId"], "evt_recent");
        assert_eq!(result["truncated"], true);
        assert_eq!(result["cursor"], "seq_2");

        // The skipped event is behind the watermark and is not replayed.
        let result = poll(
            &manager,
            json!({
                "name": "t3.run.completed",
                "arguments": {"environment_id": "linux-main"},
                "cursor": "seq_2",
                "maxAgeMs": 60_000
            }),
        )
        .await
        .unwrap();
        assert_eq!(result["events"], json!([]));
        assert_eq!(result["truncated"], false);
    }

    #[tokio::test]
    async fn poll_future_cursor_resets_to_the_watermark_with_truncation() {
        let (manager, repo) = poll_manager();
        ingest(
            &repo,
            "evt_1",
            "t3.run.completed",
            completed_payload("linux-main", "lnako"),
            None,
        );
        let result = poll(
            &manager,
            json!({
                "name": "t3.run.completed",
                "arguments": {"environment_id": "linux-main"},
                "cursor": "seq_99"
            }),
        )
        .await
        .unwrap();
        assert_eq!(result["events"], json!([]));
        assert_eq!(result["cursor"], "seq_1");
        assert_eq!(result["truncated"], true);
        assert_eq!(result["hasMore"], false);
    }

    #[tokio::test]
    async fn poll_rejects_unknown_events_and_invalid_parameters() {
        let (manager, _) = poll_manager();

        let error = poll(&manager, json!({"name": "unknown.event"}))
            .await
            .unwrap_err();
        assert_eq!(error.code, crate::mcp::error::NOT_FOUND);
        assert_eq!(error.data, Some(json!({"kind": "event"})));

        for params in [
            json!({"name": "t3.run.completed"}),
            json!({
                "name": "t3.run.completed",
                "arguments": {"environment_id": 1}
            }),
            json!({
                "name": "t3.run.completed",
                "arguments": {"environment_id": "linux-main"},
                "cursor": "not-a-cursor"
            }),
            json!({
                "name": "t3.run.completed",
                "arguments": {"environment_id": "linux-main"},
                "maxEvents": 0
            }),
            json!({
                "name": "t3.run.completed",
                "arguments": {"environment_id": "linux-main"},
                "_meta": ["not", "an", "object"]
            }),
        ] {
            let error = poll(&manager, params.clone())
                .await
                .expect_err("expected invalid params");
            assert_eq!(
                error.code,
                crate::mcp::error::INVALID_PARAMS,
                "params {params}"
            );
        }
    }

    #[tokio::test]
    async fn poll_max_age_zero_disables_the_filter() {
        let (manager, repo) = poll_manager();
        let start = poll(
            &manager,
            json!({
                "name": "t3.run.completed",
                "arguments": {"environment_id": "linux-main"}
            }),
        )
        .await
        .unwrap();
        ingest(
            &repo,
            "evt_old",
            "t3.run.completed",
            completed_payload("linux-main", "lnako"),
            Some("2020-01-01T00:00:00.000Z"),
        );
        let result = poll(
            &manager,
            json!({
                "name": "t3.run.completed",
                "arguments": {"environment_id": "linux-main"},
                "cursor": start["cursor"],
                "maxAgeMs": 0
            }),
        )
        .await
        .unwrap();
        assert_eq!(result["events"].as_array().unwrap().len(), 1);
        assert_eq!(result["truncated"], false);
    }
}
