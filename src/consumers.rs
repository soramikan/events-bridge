//! Server-side polling consumers.
//!
//! This layer resolves a named [`ConsumerProfileConfig`] from configuration,
//! translates it into a durable cursor query, and renders the JSON shapes
//! shared by the CLI, HTTP endpoints and MCP tools.

use std::{collections::BTreeMap, sync::Arc};

use serde::Serialize;
use serde_json::Value;

use crate::{
    config::{Config, ConsumerProfileConfig, EventDisposition, resolve_consumer_profile},
    mcp::event_catalog,
    store::{ConsumerAckError, ConsumerAckOutcome, ConsumerEventFilter, Repository},
};

/// Largest page a consumer poll will return, matching the MCP pull tools.
pub const MAX_CONSUMER_POLL_LIMIT: usize = 200;

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

/// Poll response.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsumerPoll {
    /// Canonical consumer name.
    pub consumer: String,
    /// Cursor used for this poll (unchanged by polling).
    pub cursor_sequence: i64,
    /// Highest sequence included in this response, or the cursor when empty.
    pub next_cursor_sequence: i64,
    /// Highest stored event sequence.
    pub latest_sequence: i64,
    /// Whether more matching events remain beyond this page.
    pub has_more: bool,
    /// Whether the response was truncated for a reason other than `limit`.
    ///
    /// Phase A always returns `false`; the field exists so clients can rely on
    /// it when digest-aware paging lands.
    pub truncated: bool,
    /// Matching events in ascending sequence order.
    pub events: Vec<ConsumerEventItem>,
    /// Reserved for Phase A2 digest summaries.
    pub digests: Vec<Value>,
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
        let row = self.repo.ensure_consumer(&consumer)?;
        let kinds = enabled_kinds(&profile);
        let filters = event_filter(&profile);
        let latest_sequence = self.repo.latest_event_sequence()?;
        let unread_count =
            self.repo
                .count_consumer_events(row.cursor_sequence, &kinds, &filters)?;
        Ok(ConsumerProbe {
            consumer,
            latest_sequence,
            cursor_sequence: row.cursor_sequence,
            unread_count,
            has_updates: unread_count > 0,
        })
    }

    /// Return matching events after the cursor without advancing it.
    ///
    /// At-least-once semantics: every call returns unacknowledged events, so a
    /// crash between poll and ack re-delivers rather than loses events.
    pub fn poll(
        &self,
        name: &str,
        limit_override: Option<usize>,
    ) -> Result<ConsumerPoll, ConsumerError> {
        let (consumer, profile) = self.resolve(name)?;
        let row = self.repo.ensure_consumer(&consumer)?;
        let kinds = enabled_kinds(&profile);
        let filters = event_filter(&profile);

        let limit = match limit_override {
            Some(limit) => limit.clamp(1, MAX_CONSUMER_POLL_LIMIT),
            None => profile
                .max_events_per_poll
                .clamp(1, MAX_CONSUMER_POLL_LIMIT),
        };

        let mut events = self.repo.list_consumer_events(
            row.cursor_sequence,
            &kinds,
            &filters,
            limit.saturating_add(1),
        )?;
        let has_more = events.len() > limit;
        events.truncate(limit);

        let next_cursor_sequence = events
            .last()
            .map(|event| event.sequence)
            .unwrap_or(row.cursor_sequence);
        self.repo.mark_consumer_polled(&consumer)?;
        let latest_sequence = self.repo.latest_event_sequence()?;

        let events = events
            .into_iter()
            .map(|event| {
                let disposition = profile
                    .events
                    .get(&event.kind)
                    .copied()
                    .unwrap_or(profile.default_disposition);
                ConsumerEventItem {
                    event_id: event.id,
                    sequence: event.sequence,
                    name: event.kind,
                    source: event.source,
                    disposition: disposition_name(disposition).to_string(),
                    occurred_at: event.occurred_at,
                    data: event.payload,
                }
            })
            .collect();

        Ok(ConsumerPoll {
            consumer,
            cursor_sequence: row.cursor_sequence,
            next_cursor_sequence,
            latest_sequence,
            has_more,
            truncated: false,
            events,
            digests: Vec::new(),
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
    let mut kinds = std::collections::BTreeSet::new();
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
        repo.ingest_event(NewEvent {
            id: Some(id.into()),
            source: None,
            kind: kind.into(),
            payload,
            occurred_at: Some("2026-11-16T01:00:00.000Z".into()),
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
        assert_eq!(
            dispositions,
            vec![
                ("t3.run.failed", "immediate"),
                ("github.review.requested", "digest"),
            ]
        );
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

        assert_eq!(service.poll("alpha", None).unwrap().events.len(), 1);
        assert_eq!(service.poll("beta", None).unwrap().events.len(), 1);

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

    #[test]
    fn unknown_consumers_are_rejected_clearly() {
        let (service, _) = service();
        let error = service.probe("does-not-exist").unwrap_err();
        assert!(matches!(error, ConsumerError::UnknownConsumer(_)));
        assert!(error.to_string().contains("[consumers.does-not-exist]"));
    }
}
