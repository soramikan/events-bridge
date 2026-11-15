//! Small shared helpers.

use chrono::{DateTime, SecondsFormat, Utc};
use rand::RngCore;

/// Current time as a fixed-width UTC RFC 3339 string.
///
/// The fixed-width form (`2026-11-16T01:00:00.000Z`) is lexicographically
/// sortable, which lets SQLite compare timestamps with plain string ordering.
pub fn now_rfc3339() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// Format an instant in the canonical storage form.
pub fn format_rfc3339(dt: DateTime<Utc>) -> String {
    dt.to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// Parse an RFC 3339 timestamp and normalize it to UTC.
pub fn parse_rfc3339(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

/// Cryptographically random lowercase hex string of `bytes` bytes.
pub fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

/// Constant-time byte comparison that does not leak length.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;

    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_are_fixed_width_and_sortable() {
        let now = now_rfc3339();
        assert_eq!(now.len(), 24, "{now}");
        assert!(now.ends_with('Z'));
        assert!(parse_rfc3339(&now).is_some());
    }

    #[test]
    fn random_hex_has_requested_length() {
        let value = random_hex(8);
        assert_eq!(value.len(), 16);
        assert!(value.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(value, random_hex(8));
    }

    #[test]
    fn constant_time_eq_behaves_like_eq() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }
}
