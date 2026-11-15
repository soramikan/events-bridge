//! Retry classification and exponential backoff.

use std::time::Duration;

use http::StatusCode;

/// How a failed delivery attempt should be treated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
    /// Retry with backoff (5xx, 429, transport errors).
    Retryable,
    /// Do not retry this event (413 and other non-retryable 4xx).
    Permanent,
    /// Do not retry and disable the subscription (410 Gone).
    DisableSubscription,
}

/// Classify an HTTP response status.
pub fn classify_status(status: StatusCode) -> FailureKind {
    if status == StatusCode::GONE {
        return FailureKind::DisableSubscription;
    }
    if status == StatusCode::PAYLOAD_TOO_LARGE {
        return FailureKind::Permanent;
    }
    if status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
        return FailureKind::Retryable;
    }
    // 3xx responses are never followed; they are not transient.
    FailureKind::Permanent
}

/// Exponential backoff with up to 25% jitter.
///
/// `attempt` is 1-based: attempt 1 waits `base_ms`, attempt 2 waits `2 *
/// base_ms`, and so on up to `max_ms`.
pub fn backoff_delay(attempt: i64, base_ms: u64, max_ms: u64) -> Duration {
    let jitter = rand::random::<f64>() * 0.25;
    backoff_delay_with_jitter(attempt, base_ms, max_ms, jitter)
}

/// Deterministic backoff used by tests. `jitter_ratio` is in `[0, 0.25]`.
pub fn backoff_delay_with_jitter(
    attempt: i64,
    base_ms: u64,
    max_ms: u64,
    jitter_ratio: f64,
) -> Duration {
    let exponent = attempt.saturating_sub(1).clamp(0, 32) as u32;
    let exponential = base_ms.saturating_mul(1u64.checked_shl(exponent).unwrap_or(u64::MAX));
    let capped = exponential.min(max_ms.max(base_ms));
    let jitter = (capped as f64 * jitter_ratio.clamp(0.0, 0.25)).round() as u64;
    Duration::from_millis(capped.saturating_add(jitter))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_classification() {
        assert_eq!(
            classify_status(StatusCode::INTERNAL_SERVER_ERROR),
            FailureKind::Retryable
        );
        assert_eq!(
            classify_status(StatusCode::SERVICE_UNAVAILABLE),
            FailureKind::Retryable
        );
        assert_eq!(
            classify_status(StatusCode::TOO_MANY_REQUESTS),
            FailureKind::Retryable
        );
        assert_eq!(
            classify_status(StatusCode::GONE),
            FailureKind::DisableSubscription
        );
        assert_eq!(
            classify_status(StatusCode::PAYLOAD_TOO_LARGE),
            FailureKind::Permanent
        );
        assert_eq!(
            classify_status(StatusCode::BAD_REQUEST),
            FailureKind::Permanent
        );
        assert_eq!(classify_status(StatusCode::FOUND), FailureKind::Permanent);
    }

    #[test]
    fn backoff_grows_and_caps() {
        assert_eq!(
            backoff_delay_with_jitter(1, 100, 10_000, 0.0),
            Duration::from_millis(100)
        );
        assert_eq!(
            backoff_delay_with_jitter(2, 100, 10_000, 0.0),
            Duration::from_millis(200)
        );
        assert_eq!(
            backoff_delay_with_jitter(4, 100, 10_000, 0.0),
            Duration::from_millis(800)
        );
        assert_eq!(
            backoff_delay_with_jitter(20, 100, 10_000, 0.0),
            Duration::from_millis(10_000)
        );
        assert!(backoff_delay_with_jitter(1, 100, 10_000, 0.25) >= Duration::from_millis(100));
    }
}
