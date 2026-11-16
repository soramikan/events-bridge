//! Server-side polling consumers.
//!
//! This layer resolves a named [`ConsumerProfileConfig`] from configuration,
//! translates it into a durable cursor query, and renders the JSON shapes
//! shared by the CLI, HTTP endpoints and MCP tools.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use anyhow::Context;
use chrono::{DateTime, SecondsFormat, Utc};
use serde::Serialize;
use serde_json::Value;

use crate::{
    config::{Config, ConsumerProfileConfig, EventDisposition, resolve_consumer_profile},
    mcp::event_catalog,
    store::{
        ConsumerAckError, ConsumerAckOutcome, ConsumerEventFilter, ConsumerPollSnapshotQuery,
        Event, Repository,
    },
};

/// Largest page a consumer poll will return, matching the MCP pull tools.
pub const MAX_CONSUMER_POLL_LIMIT: usize = 200;

/// Upper bound on digest events inspected during one catchup poll.
///
/// A digest summary only needs counts and a bounded id sample, so a large
/// backlog can be summarized without loading every row into memory. When the
/// backlog exceeds this cap the poll reports `hasMore` and the next poll picks
/// up where the summary stopped.
pub const MAX_DIGEST_CATCHUP_EVENTS: usize = 10_000;

/// Why a consumer operation failed.
#[derive(Debug, thiserror::Error)]
pub enum ConsumerError {
    /// The name is neither configured nor the built-in `muse` profile.
    #[error(
        "unknown consumer `{0}`; configure it under [consumers.{0}] or use the built-in `muse` consumer"
    )]
    UnknownConsumer(String),
    /// The acknowledgement sequence is outside `0..=latest_sequence`.
    #[error(
        "up_to_sequence {up_to_sequence} is out of range 0..={latest_sequence} for consumer `{consumer}`"
    )]
    AckOutOfRange {
        /// Consumer being acknowledged.
        consumer: String,
        /// Requested sequence.
        up_to_sequence: i64,
        /// Latest stored event sequence.
        latest_sequence: i64,
    },
    /// The underlying store failed.
    #[error(transparent)]
    Store(#[from] anyhow::Error),
}

impl From<ConsumerAckError> for ConsumerError {
    fn from(error: ConsumerAckError) -> Self {
        match error {
            ConsumerAckError::OutOfRange {
                consumer,
                up_to_sequence,
                latest_sequence,
            } => Self::AckOutOfRange {
                consumer,
                up_to_sequence,
                latest_sequence,
            },
            ConsumerAckError::Database(error) => Self::Store(anyhow::Error::new(error)),
        }
    }
}

/// Cheap probe response used by the two-stage hook/cron pattern.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsumerProbe {
    /// Canonical consumer name.
    pub consumer: String,
    /// Highest stored event sequence.
    pub latest_sequence: i64,
    /// Last acknowledged event sequence.
    pub cursor_sequence: i64,
    /// Number of matching events after the cursor.
    pub unread_count: i64,
    /// Convenience flag: `unread_count > 0`.
    pub has_updates: bool,
}

/// One event returned by a poll.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsumerEventItem {
    /// Stable event id.
    pub event_id: String,
    /// Local ingestion sequence.
    pub sequence: i64,
    /// Event name.
    pub name: String,
    /// Producing system (`t3` or `github`).
    pub source: String,
    /// `immediate` or `digest`.
    pub disposition: String,
    /// Upstream occurrence time.
    pub occurred_at: String,
    /// Event payload.
    pub data: Value,
}

/// One aggregated digest window.
///
/// `digest`-disposition events are grouped by the time window that contains
/// their `occurredAt` value. The window is a half-open interval
/// `[windowStart, windowEnd)` whose start is floored to a multiple of the
/// profile's `digest_window_secs`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsumerDigestItem {
    /// Inclusive RFC 3339 UTC window start.
    pub window_start: String,
    /// Exclusive RFC 3339 UTC window end.
    pub window_end: String,
    /// Total digest events in the window.
    pub count: usize,
    /// Digest event counts keyed by event kind.
    pub counts_by_kind: BTreeMap<String, usize>,
    /// Ascending event ids, capped at `max_digest_event_ids`.
    pub event_ids: Vec<String>,
    /// Whether `count` exceeds the number of ids in `event_ids`.
    pub event_ids_truncated: bool,
    /// Highest event sequence in the window.
    pub max_sequence: i64,
}

/// Poll response.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsumerPoll {
    /// Canonical consumer name.
    pub consumer: String,
    /// Cursor used for this poll (unchanged by polling).
    pub cursor_sequence: i64,
    /// Highest sequence covered by this response, or the cursor when empty.
    ///
    /// This includes sequences summarized in `digests`, so an acknowledgement
    /// at this value advances past both `events` and `digests`.
    pub next_cursor_sequence: i64,
    /// Highest stored event sequence.
    pub latest_sequence: i64,
    /// Whether more matching events remain beyond this page.
    pub has_more: bool,
    /// Whether unread digest events exceeded the poll budget and were returned
    /// as aggregated summaries instead of individual events.
    pub truncated: bool,
    /// Unaggregated `immediate` events in ascending sequence order.
    pub events: Vec<ConsumerEventItem>,
    /// Aggregated `digest` events grouped by time window, oldest window first.
    pub digests: Vec<ConsumerDigestItem>,
}

/// Acknowledgement response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsumerAckResult {
    /// Canonical consumer name.
    pub consumer: String,
    /// Cursor before the acknowledgement.
    pub previous_cursor_sequence: i64,
    /// Cursor after the acknowledgement.
    pub cursor_sequence: i64,
    /// Whether the cursor moved forward.
    pub advanced: bool,
}

/// Resolves consumer profiles and executes probe/poll/ack.
#[derive(Clone)]
pub struct ConsumerService {
    repo: Arc<Repository>,
    profiles: BTreeMap<String, ConsumerProfileConfig>,
}

impl ConsumerService {
    /// Create a service from an explicit profile map.
    pub fn new(repo: Arc<Repository>, profiles: BTreeMap<String, ConsumerProfileConfig>) -> Self {
        Self { repo, profiles }
    }

    /// Create a service from the hub configuration.
    pub fn from_config(repo: Arc<Repository>, config: &Config) -> Self {
        Self::new(repo, config.consumers.clone())
    }

    /// Resolve a consumer name to its canonical name and profile.
    pub fn resolve(&self, name: &str) -> Result<(String, ConsumerProfileConfig), ConsumerError> {
        let requested = name.trim();
        resolve_consumer_profile(&self.profiles, requested).ok_or_else(|| {
            ConsumerError::UnknownConsumer(if requested.is_empty() {
                "<empty>".into()
            } else {
                requested.to_string()
            })
        })
    }

    /// Count matching events after the cursor without consuming them.
    pub fn probe(&self, name: &str) -> Result<ConsumerProbe, ConsumerError> {
        let (consumer, profile) = self.resolve(name)?;
        let kinds = enabled_kinds(&profile);
        let filters = event_filter(&profile);
        let snapshot = self
            .repo
            .probe_consumer_snapshot(&consumer, &kinds, &filters)?;
        Ok(ConsumerProbe {
            consumer,
            latest_sequence: snapshot.latest_sequence,
            cursor_sequence: snapshot.cursor_sequence,
            unread_count: snapshot.unread_count,
            has_updates: snapshot.unread_count > 0,
        })
    }

    /// Return matching events after the cursor without advancing it.
    ///
    /// At-least-once semantics: every call returns unacknowledged events, so a
    /// crash between poll and ack re-delivers rather than loses events.
    ///
    /// `immediate` events are always returned individually and are never
    /// displaced by a `digest` backlog. `digest` events are aggregated by time
    /// window and are only summarized (never dropped) when the unread digest
    /// backlog exceeds the remaining poll budget; the summary still covers
    /// every inspected digest event so `nextCursorSequence` never skips one.
    pub fn poll(
        &self,
        name: &str,
        limit_override: Option<usize>,
    ) -> Result<ConsumerPoll, ConsumerError> {
        self.poll_with_snapshot(name, limit_override, |consumer, query| {
            self.repo.poll_consumer_snapshot(consumer, query)
        })
    }

    #[cfg(test)]
    fn poll_with_snapshot_hook(
        &self,
        name: &str,
        limit_override: Option<usize>,
        after_immediate_read: impl FnOnce(),
    ) -> Result<ConsumerPoll, ConsumerError> {
        self.poll_with_snapshot(name, limit_override, |consumer, query| {
            self.repo
                .poll_consumer_snapshot_with_hook(consumer, query, after_immediate_read)
        })
    }

    fn poll_with_snapshot(
        &self,
        name: &str,
        limit_override: Option<usize>,
        read_snapshot: impl FnOnce(
            &str,
            &ConsumerPollSnapshotQuery<'_>,
        ) -> anyhow::Result<crate::store::ConsumerPollSnapshot>,
    ) -> Result<ConsumerPoll, ConsumerError> {
        let (consumer, profile) = self.resolve(name)?;
        let immediate_kinds = enabled_kinds_for(&profile, EventDisposition::Immediate);
        let digest_kinds = enabled_kinds_for(&profile, EventDisposition::Digest);
        let all_kinds = enabled_kinds(&profile);
        let filters = event_filter(&profile);

        let limit = match limit_override {
            Some(limit) => limit.clamp(1, MAX_CONSUMER_POLL_LIMIT),
            None => profile
                .max_events_per_poll
                .clamp(1, MAX_CONSUMER_POLL_LIMIT),
        };

        let query = ConsumerPollSnapshotQuery {
            limit,
            digest_catchup_limit: MAX_DIGEST_CATCHUP_EVENTS,
            immediate_kinds: &immediate_kinds,
            digest_kinds: &digest_kinds,
            all_kinds: &all_kinds,
            filters: &filters,
        };
        let snapshot = read_snapshot(&consumer, &query)?;

        let digests = aggregate_digests(&snapshot.digest_events, &profile)?;
        let next_cursor_sequence = snapshot.next_cursor_ceiling.unwrap_or_else(|| {
            snapshot
                .immediate_events
                .iter()
                .map(|event| event.sequence)
                .chain(snapshot.digest_events.iter().map(|event| event.sequence))
                .max()
                .unwrap_or(snapshot.cursor_sequence)
        });

        let events = snapshot
            .immediate_events
            .into_iter()
            .map(|event| render_event(&profile, event))
            .collect();

        Ok(ConsumerPoll {
            consumer,
            cursor_sequence: snapshot.cursor_sequence,
            next_cursor_sequence,
            latest_sequence: snapshot.latest_sequence,
            has_more: snapshot.has_more,
            truncated: snapshot.truncated,
            events,
            digests,
        })
    }

    /// Advance the consumer cursor monotonically.
    pub fn ack(&self, name: &str, up_to_sequence: i64) -> Result<ConsumerAckResult, ConsumerError> {
        let (consumer, _profile) = self.resolve(name)?;
        let ConsumerAckOutcome {
            previous_cursor_sequence,
            cursor_sequence,
            advanced,
        } = self.repo.ack_consumer(&consumer, up_to_sequence)?;
        Ok(ConsumerAckResult {
            consumer,
            previous_cursor_sequence,
            cursor_sequence,
            advanced,
        })
    }

    /// Durable repository handle, used by embedding code and tests.
    pub fn repository(&self) -> &Arc<Repository> {
        &self.repo
    }
}

fn disposition_for(profile: &ConsumerProfileConfig, name: &str) -> EventDisposition {
    profile
        .events
        .get(name)
        .copied()
        .unwrap_or(profile.default_disposition)
}

/// Names the consumer wants to receive.
///
/// The catalog gives the default-enabled set; explicit profile keys extend it
/// so a profile can opt into an event name that is not in the current catalog.
fn enabled_kinds(profile: &ConsumerProfileConfig) -> Vec<String> {
    let mut kinds = BTreeSet::new();
    for (name, disposition) in &profile.events {
        if *disposition != EventDisposition::Off {
            kinds.insert(name.clone());
        }
    }
    if profile.default_disposition != EventDisposition::Off {
        for definition in event_catalog::EVENTS.iter() {
            if disposition_for(profile, definition.name) != EventDisposition::Off {
                kinds.insert(definition.name.to_string());
            }
        }
    }
    kinds.into_iter().collect()
}

/// Names the consumer wants delivered with exactly `wanted` disposition.
fn enabled_kinds_for(profile: &ConsumerProfileConfig, wanted: EventDisposition) -> Vec<String> {
    let mut kinds = BTreeSet::new();
    for (name, disposition) in &profile.events {
        if *disposition == wanted {
            kinds.insert(name.clone());
        }
    }
    if profile.default_disposition != EventDisposition::Off {
        for definition in event_catalog::EVENTS.iter() {
            if disposition_for(profile, definition.name) == wanted {
                kinds.insert(definition.name.to_string());
            }
        }
    }
    kinds.into_iter().collect()
}

fn event_filter(profile: &ConsumerProfileConfig) -> ConsumerEventFilter<'_> {
    ConsumerEventFilter {
        environment_ids: &profile.filters.environment_ids,
        project_ids: &profile.filters.project_ids,
        repositories: &profile.filters.repositories,
    }
}

fn disposition_name(disposition: EventDisposition) -> &'static str {
    match disposition {
        EventDisposition::Immediate => "immediate",
        EventDisposition::Digest => "digest",
        EventDisposition::Off => "off",
    }
}

/// Render one immediate event for the poll response.
fn render_event(profile: &ConsumerProfileConfig, event: Event) -> ConsumerEventItem {
    let disposition = disposition_for(profile, &event.kind);
    ConsumerEventItem {
        event_id: event.id,
        sequence: event.sequence,
        name: event.kind,
        source: event.source,
        disposition: disposition_name(disposition).to_string(),
        occurred_at: event.occurred_at,
        data: event.payload,
    }
}

/// Accumulator for one digest time window while grouping rows.
struct DigestAccumulator {
    window_start: i64,
    window_end: i64,
    count: usize,
    counts_by_kind: BTreeMap<String, usize>,
    event_ids: Vec<String>,
    max_sequence: i64,
}

/// Group digest events by `digest_window_secs` and render summaries.
///
/// Events are supplied in ascending sequence order, so the retained id sample
/// is also ascending. Windows are emitted oldest first.
fn aggregate_digests(
    events: &[Event],
    profile: &ConsumerProfileConfig,
) -> anyhow::Result<Vec<ConsumerDigestItem>> {
    let window_secs = i64::try_from(profile.digest_window_secs)
        .ok()
        .filter(|secs| *secs > 0)
        .unwrap_or(600);
    let max_event_ids = profile.max_digest_event_ids;
    let mut windows: BTreeMap<i64, DigestAccumulator> = BTreeMap::new();

    for event in events {
        let occurred_at = DateTime::parse_from_rfc3339(&event.occurred_at).with_context(|| {
            format!(
                "event `{}` has an invalid occurred_at `{}`",
                event.id, event.occurred_at
            )
        })?;
        let timestamp = occurred_at.timestamp();
        let window_start = timestamp - timestamp.rem_euclid(window_secs);
        let window_end = window_start + window_secs;
        let accumulator = windows
            .entry(window_start)
            .or_insert_with(|| DigestAccumulator {
                window_start,
                window_end,
                count: 0,
                counts_by_kind: BTreeMap::new(),
                event_ids: Vec::new(),
                max_sequence: event.sequence,
            });

        accumulator.count += 1;
        *accumulator
            .counts_by_kind
            .entry(event.kind.clone())
            .or_insert(0) += 1;
        if accumulator.event_ids.len() < max_event_ids {
            accumulator.event_ids.push(event.id.clone());
        }
        accumulator.max_sequence = accumulator.max_sequence.max(event.sequence);
    }

    windows
        .into_values()
        .map(|accumulator| {
            Ok(ConsumerDigestItem {
                window_start: format_window_timestamp(accumulator.window_start)?,
                window_end: format_window_timestamp(accumulator.window_end)?,
                count: accumulator.count,
                event_ids_truncated: accumulator.count > accumulator.event_ids.len(),
                counts_by_kind: accumulator.counts_by_kind,
                event_ids: accumulator.event_ids,
                max_sequence: accumulator.max_sequence,
            })
        })
        .collect()
}

/// Format an epoch second as a canonical RFC 3339 UTC timestamp.
fn format_window_timestamp(epoch_seconds: i64) -> anyhow::Result<String> {
    let timestamp = DateTime::<Utc>::from_timestamp(epoch_seconds, 0).ok_or_else(|| {
        anyhow::anyhow!("digest window timestamp {epoch_seconds} is out of range")
    })?;
    Ok(timestamp.to_rfc3339_opts(SecondsFormat::Secs, true))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{NewEvent, Repository};
    use serde_json::json;

    fn service() -> (ConsumerService, Arc<Repository>) {
        let repo = Arc::new(Repository::open_in_memory().unwrap());
        let service = ConsumerService::new(repo.clone(), Config::default().consumers);
        (service, repo)
    }

    fn ingest(repo: &Repository, id: &str, kind: &str, payload: Value) {
        ingest_at(repo, id, kind, "2026-11-16T01:00:00.000Z", payload);
    }

    fn ingest_at(repo: &Repository, id: &str, kind: &str, occurred_at: &str, payload: Value) {
        repo.ingest_event(NewEvent {
            id: Some(id.into()),
            source: None,
            kind: kind.into(),
            payload,
            occurred_at: Some(occurred_at.into()),
        })
        .unwrap();
    }

    fn custom_profile(
        default_disposition: EventDisposition,
        events: &[(&str, EventDisposition)],
    ) -> ConsumerProfileConfig {
        ConsumerProfileConfig {
            default_disposition,
            events: events
                .iter()
                .map(|(name, disposition)| ((*name).to_string(), *disposition))
                .collect(),
            ..ConsumerProfileConfig::default()
        }
    }

    #[test]
    fn probe_initializes_a_cursor_and_counts_only_enabled_events() {
        let (service, repo) = service();
        let first = service.probe("muse").unwrap();
        assert_eq!(first.consumer, "muse");
        assert_eq!(first.cursor_sequence, 0);
        assert_eq!(first.latest_sequence, 0);
        assert_eq!(first.unread_count, 0);
        assert!(!first.has_updates);

        ingest(
            &repo,
            "evt_approval",
            "t3.approval.required",
            json!({"environment_id": "linux-main", "project_id": "lnako"}),
        );
        ingest(
            &repo,
            "evt_off",
            "some.unknown.event",
            json!({"environment_id": "linux-main"}),
        );

        let probe = service.probe("Muse").unwrap();
        assert_eq!(probe.consumer, "muse");
        assert_eq!(probe.latest_sequence, 2);
        assert_eq!(probe.unread_count, 1);
        assert!(probe.has_updates);
    }

    #[test]
    fn muse_default_profile_assigns_immediate_and_digest() {
        let (service, repo) = service();
        ingest(
            &repo,
            "evt_failed",
            "t3.run.failed",
            json!({
                "environment_id": "linux-main",
                "project_id": "lnako",
                "thread_id": "thread-1",
                "run_id": "run-1",
                "summary": "failed",
                "error": "boom"
            }),
        );
        ingest(
            &repo,
            "evt_review",
            "github.review.requested",
            json!({
                "repository": "soramikan/events-bridge",
                "pull_number": 7,
                "title": "Review me",
                "url": "https://github.com/soramikan/events-bridge/pull/7"
            }),
        );

        let poll = service.poll("muse", None).unwrap();
        let dispositions: Vec<_> = poll
            .events
            .iter()
            .map(|event| (event.name.as_str(), event.disposition.as_str()))
            .collect();
        assert_eq!(dispositions, vec![("t3.run.failed", "immediate")]);
        assert_eq!(poll.digests.len(), 1);
        assert_eq!(poll.digests[0].count, 1);
        assert_eq!(
            poll.digests[0]
                .counts_by_kind
                .get("github.review.requested"),
            Some(&1)
        );
        assert_eq!(poll.next_cursor_sequence, 2);
        assert!(!poll.has_more);
        assert!(!poll.truncated);
    }

    #[test]
    fn polling_does_not_advance_the_cursor_but_ack_does() {
        let (service, repo) = service();
        ingest(
            &repo,
            "evt_failed",
            "t3.run.failed",
            json!({
                "environment_id": "linux-main",
                "project_id": "lnako",
                "thread_id": "thread-1",
                "run_id": "run-1",
                "summary": "failed",
                "error": "boom"
            }),
        );

        let first = service.poll("muse", None).unwrap();
        assert_eq!(first.cursor_sequence, 0);
        assert_eq!(first.next_cursor_sequence, 1);
        assert_eq!(first.events.len(), 1);
        assert!(!first.has_more);
        assert!(first.digests.is_empty());

        // At-least-once: without an ack the same event is returned again.
        let second = service.poll("muse", None).unwrap();
        assert_eq!(second.events, first.events);
        assert_eq!(second.cursor_sequence, 0);

        let ack = service.ack("muse", 1).unwrap();
        assert_eq!(ack.previous_cursor_sequence, 0);
        assert_eq!(ack.cursor_sequence, 1);
        assert!(ack.advanced);

        let third = service.poll("muse", None).unwrap();
        assert!(third.events.is_empty());
        assert_eq!(third.cursor_sequence, 1);
        assert_eq!(third.next_cursor_sequence, 1);
        assert_eq!(service.probe("muse").unwrap().unread_count, 0);
    }

    #[test]
    fn ack_is_monotonic_and_rejects_out_of_range_sequences() {
        let (service, repo) = service();
        for index in 0..3 {
            ingest(
                &repo,
                &format!("evt_{index}"),
                "t3.run.completed",
                json!({
                    "environment_id": "linux-main",
                    "project_id": "lnako",
                    "thread_id": "thread-1",
                    "run_id": format!("run-{index}"),
                    "summary": "done"
                }),
            );
        }

        let ack = service.ack("muse", 2).unwrap();
        assert_eq!(ack.cursor_sequence, 2);
        assert!(ack.advanced);

        let older = service.ack("muse", 1).unwrap();
        assert_eq!(older.previous_cursor_sequence, 2);
        assert_eq!(older.cursor_sequence, 2);
        assert!(!older.advanced);

        for sequence in [-1, 4] {
            let error = service.ack("muse", sequence).unwrap_err();
            assert!(
                matches!(error, ConsumerError::AckOutOfRange { .. }),
                "{error}"
            );
        }
        assert_eq!(service.probe("muse").unwrap().cursor_sequence, 2);
    }

    #[test]
    fn consumers_keep_independent_cursors() {
        let repo = Arc::new(Repository::open_in_memory().unwrap());
        let mut profiles = BTreeMap::new();
        profiles.insert(
            "alpha".into(),
            custom_profile(
                EventDisposition::Off,
                &[("t3.run.failed", EventDisposition::Immediate)],
            ),
        );
        profiles.insert(
            "beta".into(),
            custom_profile(
                EventDisposition::Off,
                &[("t3.run.completed", EventDisposition::Digest)],
            ),
        );
        let service = ConsumerService::new(repo.clone(), profiles);

        ingest(
            &repo,
            "evt_failed",
            "t3.run.failed",
            json!({
                "environment_id": "linux-main",
                "project_id": "lnako",
                "thread_id": "thread-1",
                "run_id": "run-1",
                "summary": "failed",
                "error": "boom"
            }),
        );
        ingest(
            &repo,
            "evt_completed",
            "t3.run.completed",
            json!({
                "environment_id": "linux-main",
                "project_id": "lnako",
                "thread_id": "thread-1",
                "run_id": "run-2",
                "summary": "done"
            }),
        );

        let alpha_poll = service.poll("alpha", None).unwrap();
        assert_eq!(alpha_poll.events.len(), 1);
        assert!(alpha_poll.digests.is_empty());
        let beta_poll = service.poll("beta", None).unwrap();
        assert!(beta_poll.events.is_empty());
        assert_eq!(beta_poll.digests.len(), 1);
        assert_eq!(beta_poll.digests[0].count, 1);

        service.ack("alpha", 2).unwrap();
        assert_eq!(service.probe("alpha").unwrap().unread_count, 0);
        let beta = service.probe("beta").unwrap();
        assert_eq!(beta.cursor_sequence, 0);
        assert_eq!(beta.unread_count, 1);
    }

    #[test]
    fn custom_off_profile_excludes_events_from_probe_and_poll() {
        let repo = Arc::new(Repository::open_in_memory().unwrap());
        let mut profiles = BTreeMap::new();
        profiles.insert("quiet".into(), custom_profile(EventDisposition::Off, &[]));
        let service = ConsumerService::new(repo.clone(), profiles);

        ingest(
            &repo,
            "evt_failed",
            "t3.run.failed",
            json!({
                "environment_id": "linux-main",
                "project_id": "lnako",
                "thread_id": "thread-1",
                "run_id": "run-1",
                "summary": "failed",
                "error": "boom"
            }),
        );

        let probe = service.probe("quiet").unwrap();
        assert_eq!(probe.unread_count, 0);
        assert!(!probe.has_updates);
        let poll = service.poll("quiet", None).unwrap();
        assert!(poll.events.is_empty());
    }

    #[test]
    fn filters_restrict_probe_and_poll() {
        let repo = Arc::new(Repository::open_in_memory().unwrap());
        let profile = ConsumerProfileConfig {
            filters: crate::config::ConsumerFiltersConfig {
                environment_ids: vec!["linux-main".into()],
                project_ids: vec!["lnako".into()],
                repositories: Vec::new(),
            },
            ..ConsumerProfileConfig::muse_default()
        };
        let mut profiles = BTreeMap::new();
        profiles.insert("muse".into(), profile);
        let service = ConsumerService::new(repo.clone(), profiles);

        ingest(
            &repo,
            "evt_match",
            "t3.run.failed",
            json!({
                "environment_id": "linux-main",
                "project_id": "lnako",
                "thread_id": "thread-1",
                "run_id": "run-1",
                "summary": "failed",
                "error": "boom"
            }),
        );
        ingest(
            &repo,
            "evt_wrong_env",
            "t3.run.failed",
            json!({
                "environment_id": "other-host",
                "project_id": "lnako",
                "thread_id": "thread-1",
                "run_id": "run-2",
                "summary": "failed",
                "error": "boom"
            }),
        );

        let probe = service.probe("muse").unwrap();
        assert_eq!(probe.unread_count, 1);
        let poll = service.poll("muse", None).unwrap();
        assert_eq!(poll.events.len(), 1);
        assert_eq!(poll.events[0].event_id, "evt_match");
    }

    #[test]
    fn repository_filters_match_github_payloads() {
        let repo = Arc::new(Repository::open_in_memory().unwrap());
        let profile = ConsumerProfileConfig {
            filters: crate::config::ConsumerFiltersConfig {
                repositories: vec!["soramikan/events-bridge".into()],
                ..crate::config::ConsumerFiltersConfig::default()
            },
            ..ConsumerProfileConfig::muse_default()
        };
        let mut profiles = BTreeMap::new();
        profiles.insert("muse".into(), profile);
        let service = ConsumerService::new(repo.clone(), profiles);

        for (id, repository) in [
            ("evt_match", "soramikan/events-bridge"),
            ("evt_other", "other/repository"),
        ] {
            ingest(
                &repo,
                id,
                "github.workflow.failed",
                json!({
                    "repository": repository,
                    "workflow": "ci",
                    "run_id": 1,
                    "conclusion": "failure",
                    "url": format!("https://github.com/{repository}/actions/runs/1")
                }),
            );
        }

        let probe = service.probe("muse").unwrap();
        assert_eq!(probe.unread_count, 1);
        let poll = service.poll("muse", None).unwrap();
        assert_eq!(poll.events.len(), 1);
        assert_eq!(poll.events[0].event_id, "evt_match");
    }

    #[test]
    fn poll_limit_sets_has_more_and_next_cursor() {
        let (service, repo) = service();
        for index in 0..3 {
            ingest(
                &repo,
                &format!("evt_{index}"),
                "t3.run.failed",
                json!({
                    "environment_id": "linux-main",
                    "project_id": "lnako",
                    "thread_id": "thread-1",
                    "run_id": format!("run-{index}"),
                    "summary": "failed",
                    "error": "boom"
                }),
            );
        }

        let poll = service.poll("muse", Some(2)).unwrap();
        assert_eq!(poll.events.len(), 2);
        assert!(poll.has_more);
        assert_eq!(poll.next_cursor_sequence, 2);
        assert_eq!(poll.cursor_sequence, 0);
    }

    fn failed_payload(run_id: &str) -> Value {
        json!({
            "environment_id": "linux-main",
            "project_id": "lnako",
            "thread_id": "thread-1",
            "run_id": run_id,
            "summary": "failed",
            "error": "boom"
        })
    }

    fn completed_payload(run_id: &str) -> Value {
        json!({
            "environment_id": "linux-main",
            "project_id": "lnako",
            "thread_id": "thread-1",
            "run_id": run_id,
            "summary": "done"
        })
    }

    fn review_payload() -> Value {
        json!({
            "repository": "soramikan/events-bridge",
            "pull_number": 7,
            "title": "Review me",
            "url": "https://github.com/soramikan/events-bridge/pull/7"
        })
    }

    fn service_with_profile(profile: ConsumerProfileConfig) -> (ConsumerService, Arc<Repository>) {
        let repo = Arc::new(Repository::open_in_memory().unwrap());
        let mut profiles = BTreeMap::new();
        profiles.insert("muse".into(), profile);
        let service = ConsumerService::new(repo.clone(), profiles);
        (service, repo)
    }

    #[test]
    fn digest_windows_group_by_configured_boundary() {
        let (service, repo) = service();
        ingest_at(
            &repo,
            "evt_d1",
            "t3.run.completed",
            "2026-11-16T01:00:00.000Z",
            completed_payload("run-1"),
        );
        ingest_at(
            &repo,
            "evt_d2",
            "github.review.requested",
            "2026-11-16T01:05:00.000Z",
            review_payload(),
        );
        ingest_at(
            &repo,
            "evt_d3",
            "t3.run.completed",
            "2026-11-16T01:09:59.999Z",
            completed_payload("run-2"),
        );
        ingest_at(
            &repo,
            "evt_d4",
            "t3.run.completed",
            "2026-11-16T01:10:00.000Z",
            completed_payload("run-3"),
        );
        ingest_at(
            &repo,
            "evt_d5",
            "github.pr.merged",
            "2026-11-16T02:00:00.000Z",
            json!({
                "repository": "soramikan/events-bridge",
                "pull_number": 8,
                "title": "Merged",
                "url": "https://github.com/soramikan/events-bridge/pull/8"
            }),
        );

        let poll = service.poll("muse", None).unwrap();
        assert!(poll.events.is_empty());
        assert_eq!(poll.digests.len(), 3);

        let first = &poll.digests[0];
        assert_eq!(first.window_start, "2026-11-16T01:00:00Z");
        assert_eq!(first.window_end, "2026-11-16T01:10:00Z");
        assert_eq!(first.count, 3);
        assert_eq!(first.event_ids, vec!["evt_d1", "evt_d2", "evt_d3"]);
        assert!(!first.event_ids_truncated);
        assert_eq!(first.max_sequence, 3);
        assert_eq!(first.counts_by_kind.get("t3.run.completed"), Some(&2));
        assert_eq!(
            first.counts_by_kind.get("github.review.requested"),
            Some(&1)
        );

        assert_eq!(poll.digests[1].window_start, "2026-11-16T01:10:00Z");
        assert_eq!(poll.digests[1].window_end, "2026-11-16T01:20:00Z");
        assert_eq!(poll.digests[1].count, 1);
        assert_eq!(poll.digests[1].max_sequence, 4);

        assert_eq!(poll.digests[2].window_start, "2026-11-16T02:00:00Z");
        assert_eq!(poll.digests[2].window_end, "2026-11-16T02:10:00Z");
        assert_eq!(poll.digests[2].count, 1);
        assert_eq!(poll.digests[2].max_sequence, 5);

        // Cursor advances past every sequence covered by the digest summaries.
        assert_eq!(poll.next_cursor_sequence, 5);
        assert!(!poll.has_more);
        assert!(!poll.truncated);
    }

    #[test]
    fn digest_event_ids_are_capped_and_flag_truncation() {
        let profile = ConsumerProfileConfig {
            max_digest_event_ids: 2,
            ..ConsumerProfileConfig::muse_default()
        };
        let (service, repo) = service_with_profile(profile);
        for index in 1..=3 {
            ingest_at(
                &repo,
                &format!("evt_d{index}"),
                "t3.run.completed",
                "2026-11-16T01:00:00.000Z",
                completed_payload(&format!("run-{index}")),
            );
        }

        let poll = service.poll("muse", None).unwrap();
        assert_eq!(poll.digests.len(), 1);
        let digest = &poll.digests[0];
        assert_eq!(digest.count, 3);
        assert_eq!(digest.event_ids, vec!["evt_d1", "evt_d2"]);
        assert!(digest.event_ids_truncated);
        assert_eq!(digest.max_sequence, 3);
    }

    #[test]
    fn immediate_events_survive_a_larger_digest_backlog() {
        let profile = ConsumerProfileConfig {
            max_events_per_poll: 2,
            ..ConsumerProfileConfig::muse_default()
        };
        let (service, repo) = service_with_profile(profile);
        ingest(
            &repo,
            "evt_immediate",
            "t3.run.failed",
            failed_payload("run-immediate"),
        );
        for index in 0..5 {
            ingest(
                &repo,
                &format!("evt_digest_{index}"),
                "t3.run.completed",
                completed_payload(&format!("run-{index}")),
            );
        }

        let poll = service.poll("muse", None).unwrap();
        assert_eq!(poll.events.len(), 1);
        assert_eq!(poll.events[0].event_id, "evt_immediate");
        assert_eq!(poll.events[0].disposition, "immediate");
        assert_eq!(poll.digests.len(), 1);
        assert_eq!(poll.digests[0].count, 5);
        assert_eq!(
            poll.digests[0].counts_by_kind.get("t3.run.completed"),
            Some(&5)
        );
        assert!(poll.truncated);
        assert!(!poll.has_more);
        assert_eq!(poll.next_cursor_sequence, 6);

        // One acknowledgement covers the immediate event and every summarized
        // digest event.
        service.ack("muse", poll.next_cursor_sequence).unwrap();
        assert_eq!(service.probe("muse").unwrap().unread_count, 0);
    }

    #[test]
    fn immediate_event_after_digest_backlog_is_never_dropped() {
        let (service, repo) = service();
        for index in 0..5 {
            ingest(
                &repo,
                &format!("evt_digest_{index}"),
                "github.review.requested",
                review_payload(),
            );
        }
        ingest(
            &repo,
            "evt_immediate",
            "t3.run.failed",
            failed_payload("run-immediate"),
        );

        let poll = service.poll("muse", Some(1)).unwrap();
        assert_eq!(poll.events.len(), 1);
        assert_eq!(poll.events[0].event_id, "evt_immediate");
        assert_eq!(poll.digests.len(), 1);
        assert_eq!(poll.digests[0].count, 5);
        assert!(poll.truncated);
        assert!(!poll.has_more);
        assert_eq!(poll.next_cursor_sequence, 6);

        // The digest events precede the immediate event, so acking the
        // immediate sequence must still cover them.
        service.ack("muse", poll.next_cursor_sequence).unwrap();
        assert_eq!(service.probe("muse").unwrap().unread_count, 0);
    }

    #[test]
    fn poll_limit_pages_immediate_events_without_skipping_digests() {
        let (service, repo) = service();
        for index in 0..3 {
            ingest(
                &repo,
                &format!("evt_{index}"),
                "t3.run.failed",
                failed_payload(&format!("run-{index}")),
            );
        }
        ingest(
            &repo,
            "evt_digest",
            "t3.run.completed",
            completed_payload("run-digest"),
        );

        let first = service.poll("muse", Some(2)).unwrap();
        assert_eq!(first.events.len(), 2);
        assert!(first.digests.is_empty());
        assert!(first.has_more);
        assert!(!first.truncated);
        assert_eq!(first.next_cursor_sequence, 2);

        service.ack("muse", first.next_cursor_sequence).unwrap();

        let second = service.poll("muse", Some(2)).unwrap();
        assert_eq!(second.events.len(), 1);
        assert_eq!(second.events[0].event_id, "evt_2");
        assert_eq!(second.digests.len(), 1);
        assert_eq!(second.digests[0].count, 1);
        assert!(!second.has_more);
        assert!(!second.truncated);
        assert_eq!(second.next_cursor_sequence, 4);

        service.ack("muse", second.next_cursor_sequence).unwrap();
        let empty = service.poll("muse", Some(2)).unwrap();
        assert!(empty.events.is_empty());
        assert!(empty.digests.is_empty());
        assert_eq!(empty.next_cursor_sequence, 4);
        assert!(!empty.has_more);
        assert!(!empty.truncated);
    }

    #[test]
    fn unknown_consumers_are_rejected_clearly() {
        let (service, _) = service();
        let error = service.probe("does-not-exist").unwrap_err();
        assert!(matches!(error, ConsumerError::UnknownConsumer(_)));
        assert!(error.to_string().contains("[consumers.does-not-exist]"));
    }

    #[test]
    fn probe_reads_consistent_snapshot_under_concurrent_ingest_and_ack() {
        struct StopOnDrop(Arc<std::sync::atomic::AtomicBool>);
        impl Drop for StopOnDrop {
            fn drop(&mut self) {
                self.0.store(true, std::sync::atomic::Ordering::Release);
            }
        }

        let temp = tempfile::NamedTempFile::new().unwrap();
        let writer_repo = Arc::new(Repository::open(temp.path()).unwrap());
        let reader_repo = Arc::new(Repository::open(temp.path()).unwrap());
        let writer_service = ConsumerService::new(writer_repo.clone(), Config::default().consumers);
        let reader_service = ConsumerService::new(reader_repo, Config::default().consumers);
        assert_eq!(reader_service.probe("muse").unwrap().latest_sequence, 0);

        let total = 80;
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_reader = stop.clone();

        let writer = std::thread::spawn(move || {
            let _guard = StopOnDrop(stop);
            for index in 1..=total {
                ingest(
                    &writer_repo,
                    &format!("evt_conc_{index}"),
                    "t3.run.failed",
                    json!({
                        "environment_id": "linux-main",
                        "project_id": "lnako",
                        "thread_id": "thread-1",
                        "run_id": format!("run-{index}"),
                        "summary": "failed",
                        "error": "boom"
                    }),
                );
                if index % 3 == 0 {
                    writer_service.ack("muse", index).unwrap();
                }
            }
        });

        while !stop_reader.load(std::sync::atomic::Ordering::Acquire) {
            let probe = reader_service.probe("muse").unwrap();
            assert!(
                probe.cursor_sequence <= probe.latest_sequence,
                "cursor {} > latest {}",
                probe.cursor_sequence,
                probe.latest_sequence
            );
            assert!(
                probe.unread_count <= probe.latest_sequence - probe.cursor_sequence,
                "unread {} > window ({}..={})",
                probe.unread_count,
                probe.cursor_sequence,
                probe.latest_sequence
            );
            assert_eq!(probe.has_updates, probe.unread_count > 0);
            std::thread::yield_now();
        }

        writer.join().unwrap();
        let final_probe = reader_service.probe("muse").unwrap();
        assert_eq!(final_probe.latest_sequence, total);
        assert_eq!(
            final_probe.unread_count,
            final_probe.latest_sequence - final_probe.cursor_sequence
        );
    }

    #[test]
    fn poll_shares_one_snapshot_so_concurrent_ingest_never_skips_immediate_events() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        let writer_repo = Arc::new(Repository::open(temp.path()).unwrap());
        let reader_repo = Arc::new(Repository::open(temp.path()).unwrap());
        let service = ConsumerService::new(reader_repo, Config::default().consumers);

        // Initialize the durable consumer row at cursor 0 so poll uses a
        // read-only WAL snapshot while the concurrent writer commits.
        assert_eq!(service.probe("muse").unwrap().cursor_sequence, 0);
        ingest(
            &writer_repo,
            "evt_digest_1",
            "t3.run.completed",
            completed_payload("run-1"),
        );

        let first = service
            .poll_with_snapshot_hook("muse", Some(2), || {
                ingest(
                    &writer_repo,
                    "evt_immediate_2",
                    "t3.run.failed",
                    failed_payload("run-2"),
                );
                ingest(
                    &writer_repo,
                    "evt_digest_3",
                    "t3.run.completed",
                    completed_payload("run-3"),
                );
            })
            .unwrap();

        // Snapshot sees only sequence 1: cursor does not jump to 3 past
        // immediate sequence 2.
        assert!(first.events.is_empty());
        assert_eq!(first.digests.len(), 1);
        assert_eq!(first.digests[0].count, 1);
        assert_eq!(first.digests[0].max_sequence, 1);
        assert_eq!(first.next_cursor_sequence, 1);
        assert_eq!(first.latest_sequence, 1);
        assert!(!first.has_more);

        service.ack("muse", first.next_cursor_sequence).unwrap();

        let second = service.poll("muse", Some(2)).unwrap();
        assert_eq!(second.events.len(), 1);
        assert_eq!(second.events[0].event_id, "evt_immediate_2");
        assert_eq!(second.digests.len(), 1);
        assert_eq!(second.digests[0].count, 1);
        assert_eq!(second.digests[0].max_sequence, 3);
        assert_eq!(second.next_cursor_sequence, 3);
        assert!(!second.has_more);
    }
}
