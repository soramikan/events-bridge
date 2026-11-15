//! Upstream event collectors.
//!
//! Phase 2 implements the T3 Code collector and Phase 3 adds GitHub webhook
//! ingestion plus REST reconciliation.

pub mod github_poll;
pub mod github_state;
pub mod github_webhook;
pub mod t3_sqlite;
pub mod t3_state;

pub use github_poll::{GitHubPollSummary, GitHubPoller, GitHubPollerSettings};
pub use t3_sqlite::{T3Collector, T3CollectorSettings, T3CollectorSummary, T3Source};
pub use t3_state::T3SourceEvent;
