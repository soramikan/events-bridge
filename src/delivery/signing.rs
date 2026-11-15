//! Standard Webhooks signing and verification.
//!
//! The HMAC computation is delegated to the `standardwebhooks` crate so the
//! signature scheme stays exactly compatible with Svix-style receivers. A thin
//! verifier with an explicit `now` is provided for the official test vector and
//! for tests that cannot control the clock.

use hmac::{Hmac, Mac};
use http::HeaderMap;
use sha2::Sha256;
use standardwebhooks::{Webhook, WebhookError};
use subtle::ConstantTimeEq;

pub use standardwebhooks::{HEADER_WEBHOOK_ID, HEADER_WEBHOOK_SIGNATURE, HEADER_WEBHOOK_TIMESTAMP};

/// Header carrying the subscription id (MCP-specific, not Standard Webhooks).
pub const HEADER_SUBSCRIPTION_ID: &str = "X-MCP-Subscription-Id";

/// Signature/verification failure.
#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    /// Secret is not a valid Standard Webhooks secret.
    #[error("invalid webhook secret: {0}")]
    InvalidSecret(String),
    /// Timestamp is outside the allowed tolerance.
    #[error("webhook timestamp outside tolerance")]
    TimestampOutOfRange,
    /// No `v1` signature matched the body.
    #[error("webhook signature mismatch")]
    InvalidSignature,
    /// Header missing or malformed.
    #[error("invalid webhook header: {0}")]
    InvalidHeader(&'static str),
    /// Payload was not UTF-8 (JSON bodies always are).
    #[error("webhook payload is not UTF-8")]
    InvalidPayload,
}

impl From<WebhookError> for SignatureError {
    fn from(error: WebhookError) -> Self {
        match error {
            WebhookError::InvalidSecret(error) => Self::InvalidSecret(error.to_string()),
            WebhookError::MissingHeader(name) | WebhookError::InvalidHeader(name) => {
                Self::InvalidHeader(name)
            }
            WebhookError::TimestampTooOldError | WebhookError::FutureTimestampError => {
                Self::TimestampOutOfRange
            }
            WebhookError::InvalidPayload => Self::InvalidPayload,
            WebhookError::InvalidTimestamp | WebhookError::InvalidSignature => {
                Self::InvalidSignature
            }
        }
    }
}

/// Compute a `v1,<base64 HMAC-SHA256>` signature for a serialized body.
pub fn sign(
    secret: &str,
    message_id: &str,
    timestamp: i64,
    body: &[u8],
) -> Result<String, SignatureError> {
    let webhook = Webhook::new(secret).map_err(SignatureError::from)?;
    webhook
        .sign(message_id, timestamp, body)
        .map_err(SignatureError::from)
}

/// Compute the raw HMAC-SHA256 used by the signature scheme.
///
/// Exposed for diagnostics; production signing uses [`sign`].
pub fn hmac_sha256(secret: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

/// Verify a signature with an explicit clock and tolerance.
///
/// The `webhook-signature` header may contain several space-separated
/// signatures (secret rotation); any matching `v1` signature is accepted.
pub fn verify_at(
    secret: &str,
    message_id: &str,
    timestamp: i64,
    signature_header: &str,
    body: &[u8],
    now: i64,
    tolerance_secs: i64,
) -> Result<(), SignatureError> {
    if (now - timestamp).abs() > tolerance_secs {
        return Err(SignatureError::TimestampOutOfRange);
    }

    let expected = sign(secret, message_id, timestamp, body)?;
    let expected = expected
        .split_once(',')
        .map(|(_, value)| value)
        .ok_or(SignatureError::InvalidSignature)?;

    let matched = signature_header
        .split(' ')
        .filter_map(|entry| entry.split_once(','))
        .filter(|(version, _)| *version == "v1")
        .any(|(_, candidate)| {
            candidate.len() == expected.len()
                && candidate.as_bytes().ct_eq(expected.as_bytes()).into()
        });

    if matched {
        Ok(())
    } else {
        Err(SignatureError::InvalidSignature)
    }
}

/// Verify incoming Standard Webhooks headers using the current clock.
///
/// This is the receiver-side helper used by the integration tests and by any
/// future inbound webhook endpoint.
pub fn verify_incoming(
    secret: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<(), SignatureError> {
    let webhook = Webhook::new(secret).map_err(SignatureError::from)?;
    webhook.verify(body, headers).map_err(SignatureError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use http::HeaderValue;

    // Official Standard Webhooks test vector.
    const VECTOR_KEY: [u8; 24] = [
        0x0b, 0x61, 0x55, 0xb0, 0x14, 0x08, 0x86, 0xbb, 0x1c, 0x0a, 0x19, 0x50, 0x20, 0xc5, 0x7e,
        0x6f, 0x9b, 0x12, 0x62, 0xca, 0x68, 0x6f, 0xba, 0x03,
    ];
    const VECTOR_ID: &str = "msg_27UH4WbU6Z5A5EzD8u03UvzRbpk";
    const VECTOR_TIMESTAMP: i64 = 1_649_367_553;
    const VECTOR_PAYLOAD: &[u8] = br#"{"email":"test@example.com","username":"test_user"}"#;
    const VECTOR_SIGNATURE: &str = "v1,tZ1I4/hDygAJgO5TYxiSd6Sd0kDW6hPenDe+bTa3Kkw=";

    /// The official test vector's signing key, synthesized at runtime so no
    /// webhook secret literal is committed to the repository.
    fn vector_secret() -> String {
        format!(
            "whsec_{}",
            base64::engine::general_purpose::STANDARD.encode(VECTOR_KEY)
        )
    }

    #[test]
    fn official_test_vector_signs_and_verifies() {
        let secret = vector_secret();
        let signature = sign(&secret, VECTOR_ID, VECTOR_TIMESTAMP, VECTOR_PAYLOAD).expect("sign");
        assert_eq!(signature, VECTOR_SIGNATURE);

        verify_at(
            &secret,
            VECTOR_ID,
            VECTOR_TIMESTAMP,
            VECTOR_SIGNATURE,
            VECTOR_PAYLOAD,
            VECTOR_TIMESTAMP,
            300,
        )
        .expect("official vector verifies");
    }

    #[test]
    fn tampered_payload_is_rejected() {
        let secret = vector_secret();
        let error = verify_at(
            &secret,
            VECTOR_ID,
            VECTOR_TIMESTAMP,
            VECTOR_SIGNATURE,
            br#"{"email":"attacker@example.com","username":"test_user"}"#,
            VECTOR_TIMESTAMP,
            300,
        )
        .unwrap_err();
        assert!(matches!(error, SignatureError::InvalidSignature));
    }

    #[test]
    fn stale_and_future_timestamps_are_rejected() {
        let secret = vector_secret();
        let now = VECTOR_TIMESTAMP + 301;
        assert!(matches!(
            verify_at(
                &secret,
                VECTOR_ID,
                VECTOR_TIMESTAMP,
                VECTOR_SIGNATURE,
                VECTOR_PAYLOAD,
                now,
                300
            ),
            Err(SignatureError::TimestampOutOfRange)
        ));
        let now = VECTOR_TIMESTAMP - 301;
        assert!(matches!(
            verify_at(
                &secret,
                VECTOR_ID,
                VECTOR_TIMESTAMP,
                VECTOR_SIGNATURE,
                VECTOR_PAYLOAD,
                now,
                300
            ),
            Err(SignatureError::TimestampOutOfRange)
        ));
    }

    #[test]
    fn multiple_signatures_are_supported() {
        let secret = vector_secret();
        let now = 1_649_367_553;
        let header = format!("v1,AAAA {VECTOR_SIGNATURE}");
        verify_at(
            &secret,
            VECTOR_ID,
            VECTOR_TIMESTAMP,
            &header,
            VECTOR_PAYLOAD,
            now,
            300,
        )
        .expect("second signature matches");
    }

    #[test]
    fn incoming_headers_verify_with_current_clock() {
        let secret = vector_secret();
        let timestamp = chrono::Utc::now().timestamp();
        let signature = sign(&secret, "evt_1", timestamp, VECTOR_PAYLOAD).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(HEADER_WEBHOOK_ID, HeaderValue::from_static("evt_1"));
        headers.insert(
            HEADER_WEBHOOK_TIMESTAMP,
            HeaderValue::from_str(&timestamp.to_string()).unwrap(),
        );
        headers.insert(
            HEADER_WEBHOOK_SIGNATURE,
            HeaderValue::from_str(&signature).unwrap(),
        );
        verify_incoming(&secret, &headers, VECTOR_PAYLOAD).expect("fresh signature");
    }

    #[test]
    fn raw_hmac_matches_standard_webhooks_construction() {
        // Sanity check for the documented construction:
        // HMAC-SHA256(secret, id.timestamp.body)
        let signed = format!(
            "{VECTOR_ID}.{VECTOR_TIMESTAMP}.{}",
            std::str::from_utf8(VECTOR_PAYLOAD).unwrap()
        );
        let expected = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            hmac_sha256(&VECTOR_KEY, signed.as_bytes()),
        );
        assert_eq!(format!("v1,{expected}"), VECTOR_SIGNATURE);
    }
}
