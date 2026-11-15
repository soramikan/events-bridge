//! Durable webhook dispatcher.
//!
//! The SQLite `deliveries` table is the queue. `tokio::sync::broadcast` only
//! wakes the worker; all delivery state is persisted. On startup, rows left in
//! `in_progress` by a crash are reset to `pending`, so a restart resumes the
//! backlog.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use chrono::{Duration as ChronoDuration, Utc};
use tokio::sync::broadcast::error::RecvError;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::config::{DeliveryConfig, MAX_WEBHOOK_BODY_BYTES};
use crate::delivery::{
    retry::{self, FailureKind},
    signing,
    verification::{self, CallbackError, CallbackPolicy, reason},
};
use crate::event::{EventBus, EventEnvelope};
use crate::store::{AttemptOutcome, DueDelivery, Repository};
use crate::util::{format_rfc3339, parse_rfc3339};

/// Background delivery worker.
#[derive(Clone)]
pub struct Dispatcher {
    repo: Arc<Repository>,
    bus: EventBus,
    config: DeliveryConfig,
    policy: CallbackPolicy,
}

impl Dispatcher {
    /// Create a dispatcher.
    pub fn new(
        repo: Arc<Repository>,
        bus: EventBus,
        config: DeliveryConfig,
        policy: CallbackPolicy,
    ) -> Self {
        Self {
            repo,
            bus,
            config,
            policy,
        }
    }

    /// Run until cancellation.
    pub async fn run(&self, cancellation: CancellationToken) {
        match self.repo.reset_in_progress_deliveries() {
            Ok(0) => {}
            Ok(count) => tracing::info!(count, "recovered interrupted deliveries"),
            Err(error) => tracing::error!(%error, "could not reset interrupted deliveries"),
        }

        let mut wakeups = self.bus.subscribe();
        loop {
            if cancellation.is_cancelled() {
                break;
            }
            if self.drain_until(&cancellation).await > 0 {
                continue;
            }
            if cancellation.is_cancelled() {
                break;
            }

            let delay = self.next_delay();
            tokio::select! {
                _ = cancellation.cancelled() => break,
                _ = tokio::time::sleep(delay) => {}
                result = wakeups.recv() => {
                    match result {
                        Ok(()) | Err(RecvError::Lagged(_)) => {}
                        Err(RecvError::Closed) => break,
                    }
                }
            }
        }
    }

    fn next_delay(&self) -> Duration {
        let poll = Duration::from_millis(self.config.poll_interval_ms.max(1));
        let Some(next) = self.repo.next_pending_at().ok().flatten() else {
            return poll;
        };
        let Some(next) = parse_rfc3339(&next) else {
            return poll;
        };
        let wait = next - Utc::now();
        if wait <= ChronoDuration::zero() {
            return Duration::from_millis(1);
        }
        wait.to_std().unwrap_or(poll).min(poll)
    }

    /// Lease after which this worker treats an `in_progress` delivery as
    /// abandoned and reclaims it. `finish_attempt` failures therefore recover
    /// automatically without a restart.
    fn lease(&self) -> Duration {
        Duration::from_secs(self.config.lease_secs.max(1))
    }

    /// Deliver every currently-due record. Returns the number processed.
    pub async fn drain(&self) -> usize {
        self.drain_until(&CancellationToken::new()).await
    }

    /// Deliver currently-due records until the queue is empty or `cancellation` fires.
    pub async fn drain_until(&self, cancellation: &CancellationToken) -> usize {
        let mut processed = 0usize;
        loop {
            if cancellation.is_cancelled() {
                break;
            }
            let due = match self.repo.claim_next_due_with_lease(self.lease()) {
                Ok(Some(due)) => due,
                Ok(None) => break,
                Err(error) => {
                    tracing::error!(%error, "could not claim delivery");
                    break;
                }
            };
            processed += 1;
            if let Err(error) = self.deliver(due).await {
                tracing::error!(%error, "delivery attempt failed internally");
            }
        }
        if processed > 0 {
            metrics::counter!("events_bridge_delivery_batch_total").increment(1);
        }
        processed
    }

    async fn deliver(&self, due: DueDelivery) -> Result<()> {
        let attempt = due.attempt_count + 1;
        let body = serde_json::to_vec(
            &EventEnvelope {
                event: &due.event,
                cursor: None,
            }
            .to_json(),
        )?;

        // Optional defense in depth: even a configuration constructed without
        // `Config::validate` can never exceed the protocol ceiling.
        let max_body_bytes = self.config.max_body_bytes.min(MAX_WEBHOOK_BODY_BYTES);
        if body.len() > max_body_bytes {
            return self
                .finish(
                    &due,
                    attempt,
                    None,
                    "skipped",
                    "failed",
                    Some("payload_too_large"),
                    None,
                    false,
                )
                .await;
        }

        let url = match Url::parse(&due.subscription.callback_url) {
            Ok(url) => url,
            Err(error) => {
                return self
                    .finish(
                        &due,
                        attempt,
                        None,
                        "permanent",
                        "failed",
                        Some(&format!("invalid_url: {error}")),
                        None,
                        false,
                    )
                    .await;
            }
        };

        // Re-validate the destination at send time. The client pins the
        // validated address and never follows redirects.
        let client = match verification::pin_client(&self.policy, &url).await {
            Ok(client) => client,
            Err(error) => {
                return self
                    .handle_transport_failure(&due, attempt, &error, None)
                    .await;
            }
        };

        let timestamp = Utc::now().timestamp();
        // `webhook-id` is stable across retries: it is the event id.
        let signature =
            match signing::sign(&due.subscription.secret, &due.event.id, timestamp, &body) {
                Ok(signature) => signature,
                Err(error) => {
                    return self
                        .finish(
                            &due,
                            attempt,
                            None,
                            "permanent",
                            "failed",
                            Some(&format!("invalid_secret: {error}")),
                            None,
                            false,
                        )
                        .await;
                }
            };

        let response = client
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(signing::HEADER_WEBHOOK_ID, &due.event.id)
            .header(signing::HEADER_WEBHOOK_TIMESTAMP, timestamp.to_string())
            .header(signing::HEADER_WEBHOOK_SIGNATURE, signature)
            .header(signing::HEADER_SUBSCRIPTION_ID, &due.subscription.id)
            .body(body)
            .send()
            .await;

        let response = match response {
            Ok(response) => response,
            Err(error) => {
                let mapped = verification::map_transport_error(&error);
                return self
                    .handle_transport_failure(&due, attempt, &mapped, None)
                    .await;
            }
        };

        let status = response.status();
        let status_code = i64::from(status.as_u16());
        if status.is_success() {
            return self
                .finish(
                    &due,
                    attempt,
                    Some(status_code),
                    "success",
                    "delivered",
                    None,
                    None,
                    false,
                )
                .await;
        }
        match retry::classify_status(status) {
            FailureKind::Permanent | FailureKind::DisableSubscription => {
                let disable = retry::classify_status(status) == FailureKind::DisableSubscription;
                let error = if status == reqwest::StatusCode::GONE {
                    "http_410".to_string()
                } else if status == reqwest::StatusCode::PAYLOAD_TOO_LARGE {
                    "http_413".to_string()
                } else {
                    format!("http_{}", status.as_u16())
                };
                tracing::warn!(
                    subscription_id = %due.subscription.id,
                    event_id = %due.event.id,
                    %status,
                    "webhook delivery rejected permanently"
                );
                self.finish(
                    &due,
                    attempt,
                    Some(status_code),
                    "permanent",
                    "failed",
                    Some(&error),
                    None,
                    disable,
                )
                .await
            }
            FailureKind::Retryable => {
                self.handle_retryable(
                    &due,
                    attempt,
                    Some(status_code),
                    &format!("http_{}", status.as_u16()),
                )
                .await
            }
        }
    }

    async fn handle_transport_failure(
        &self,
        due: &DueDelivery,
        attempt: i64,
        error: &CallbackError,
        status_code: Option<i64>,
    ) -> Result<()> {
        // A callback that is statically disallowed (private address, insecure
        // URL) must not be retried. DNS and transport failures are transient.
        let retryable = matches!(
            error.reason,
            reason::DNS_FAILURE
                | reason::TIMEOUT
                | reason::CONNECTION_REFUSED
                | reason::NETWORK_ERROR
                | reason::TLS_ERROR
                | reason::HTTP_5XX
        );
        if retryable {
            self.handle_retryable(due, attempt, status_code, error.reason)
                .await
        } else {
            self.finish(
                due,
                attempt,
                status_code,
                "permanent",
                "failed",
                Some(error.reason),
                None,
                false,
            )
            .await
        }
    }

    async fn handle_retryable(
        &self,
        due: &DueDelivery,
        attempt: i64,
        status_code: Option<i64>,
        error: &str,
    ) -> Result<()> {
        if attempt >= self.config.max_attempts {
            tracing::warn!(
                subscription_id = %due.subscription.id,
                event_id = %due.event.id,
                attempt,
                error,
                "webhook delivery attempts exhausted"
            );
            return self
                .finish(
                    due,
                    attempt,
                    status_code,
                    "exhausted",
                    "abandoned",
                    Some(error),
                    None,
                    false,
                )
                .await;
        }

        let delay = retry::backoff_delay(
            attempt,
            self.config.base_backoff_ms,
            self.config.max_backoff_ms,
        );
        let next = format_rfc3339(Utc::now() + ChronoDuration::from_std(delay)?);
        tracing::info!(
            subscription_id = %due.subscription.id,
            event_id = %due.event.id,
            attempt,
            delay_ms = delay.as_millis(),
            error,
            "webhook delivery scheduled for retry"
        );
        self.finish(
            due,
            attempt,
            status_code,
            if status_code.is_some() {
                "retryable"
            } else {
                "network_error"
            },
            "pending",
            Some(error),
            Some(&next),
            false,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn finish(
        &self,
        due: &DueDelivery,
        attempt: i64,
        status_code: Option<i64>,
        outcome: &str,
        delivery_status: &str,
        error: Option<&str>,
        next_attempt_at: Option<&str>,
        disable_subscription: bool,
    ) -> Result<()> {
        metrics::counter!(
            "events_bridge_delivery_attempts_total",
            "outcome" => outcome.to_string()
        )
        .increment(1);

        // Persisting the outcome is what releases the delivery. SQLite writes
        // are short, so a bounded retry handles transient `busy`/I/O errors;
        // if every attempt fails the row stays `in_progress` and the lease in
        // `claim_next_due_with_lease` reclaims it automatically.
        const FINISH_ATTEMPTS: usize = 3;
        let mut last_error = None;
        for attempt_index in 0..FINISH_ATTEMPTS {
            let result = self.repo.finish_attempt(AttemptOutcome {
                delivery_id: due.delivery_id,
                attempt,
                status_code,
                outcome,
                error,
                delivery_status,
                next_attempt_at,
                subscription_id: &due.subscription.id,
                disable_subscription,
            });
            match result {
                Ok(()) => {
                    last_error = None;
                    break;
                }
                Err(error) => {
                    last_error = Some(error);
                    if attempt_index + 1 < FINISH_ATTEMPTS {
                        tracing::warn!(
                            delivery_id = due.delivery_id,
                            attempt = attempt_index + 1,
                            "could not persist delivery outcome; retrying"
                        );
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                }
            }
        }
        if let Some(error) = last_error {
            return Err(error);
        }

        if delivery_status == "delivered" {
            tracing::info!(
                subscription_id = %due.subscription.id,
                event_id = %due.event.id,
                "webhook delivered"
            );
        }
        Ok(())
    }
}
