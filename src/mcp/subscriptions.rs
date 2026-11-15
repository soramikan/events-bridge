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
use crate::store::{NewSubscription, Repository};
use crate::util::format_rfc3339;

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

/// Owns `events/list`, `events/subscribe`, and `events/unsubscribe`.
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
            "events/subscribe" => self.subscribe(params, principal).await,
            "events/unsubscribe" => self.unsubscribe(params, principal),
            other => Err(RpcError::new(
                crate::mcp::error::METHOD_NOT_FOUND,
                format!("method not found: {other}"),
                None,
            )),
        }
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
}
