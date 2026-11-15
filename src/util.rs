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

/// Whether `left` is strictly older than `right`.
///
/// Both values are normally canonical fixed-width RFC 3339 timestamps, so a
/// lexicographic comparison is a safe fallback if either side is malformed.
pub fn timestamp_lt(left: &str, right: &str) -> bool {
    match (parse_rfc3339(left), parse_rfc3339(right)) {
        (Some(left), Some(right)) => left < right,
        _ => left < right,
    }
}

/// Normalize a candidate host name, rejecting empty and generic values.
///
/// `localhost`, `unknown` and similar placeholders are deliberately treated as
/// unresolved: using them as an environment id would make every host collide.
pub fn normalize_hostname(value: &str) -> Option<String> {
    let value = value.lines().map(str::trim).find(|line| !line.is_empty())?;
    let value = value.trim_end_matches('.').trim();
    if value.is_empty()
        || value
            .chars()
            .any(|ch| ch.is_whitespace() || ch.is_control())
    {
        return None;
    }
    let lower = value.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "localhost"
            | "localhost.localdomain"
            | "localhost6"
            | "ip6-localhost"
            | "ip6-loopback"
            | "unknown"
            | "none"
            | "(none)"
    ) {
        return None;
    }
    Some(value.to_string())
}

/// Best-effort OS host name.
///
/// Checks the conventional environment variables, the Linux host name files
/// and finally the `hostname` command. Returns `None` when no usable name is
/// available; callers must not substitute a shared default such as `"edge"`.
pub fn os_hostname() -> Option<String> {
    for variable in ["HOSTNAME", "COMPUTERNAME"] {
        if let Ok(value) = std::env::var(variable)
            && let Some(hostname) = normalize_hostname(&value)
        {
            return Some(hostname);
        }
    }
    for path in ["/proc/sys/kernel/hostname", "/etc/hostname"] {
        if let Ok(value) = std::fs::read_to_string(path)
            && let Some(hostname) = normalize_hostname(&value)
        {
            return Some(hostname);
        }
    }
    let output = std::process::Command::new("hostname").output().ok()?;
    if !output.status.success() {
        return None;
    }
    normalize_hostname(&String::from_utf8_lossy(&output.stdout))
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
    fn timestamp_ordering_handles_offsets() {
        assert!(timestamp_lt("2026-11-16T01:00:00Z", "2026-11-16T01:00:01Z"));
        assert!(!timestamp_lt(
            "2026-11-16T01:00:01Z",
            "2026-11-16T01:00:00Z"
        ));
        assert!(!timestamp_lt(
            "2026-11-16T01:00:00Z",
            "2026-11-16T01:00:00Z"
        ));
        assert!(timestamp_lt(
            "2026-11-16T00:00:00Z",
            "2026-11-16T01:00:01+01:00"
        ));
    }

    #[test]
    fn constant_time_eq_behaves_like_eq() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }

    #[test]
    fn hostname_normalization_rejects_placeholders() {
        assert_eq!(normalize_hostname("build-host"), Some("build-host".into()));
        assert_eq!(
            normalize_hostname("  build-host.example.  \n"),
            Some("build-host.example".into())
        );
        assert_eq!(normalize_hostname("first\nsecond"), Some("first".into()));
        for value in [
            "",
            "   ",
            "localhost",
            "LOCALHOST",
            "localhost.localdomain",
            "unknown",
            "none",
            "(none)",
            "bad host",
        ] {
            assert_eq!(normalize_hostname(value), None, "{value:?}");
        }
    }
}
