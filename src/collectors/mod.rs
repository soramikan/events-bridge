//! Upstream event collectors.
//!
//! Orca observations, GitHub webhook ingestion and REST reconciliation,
//! and the legacy T3 implementation used for compatibility tests.

pub mod github_poll;
pub mod github_state;
pub mod github_webhook;
pub(crate) mod orca;
pub mod t3_sqlite;
pub mod t3_state;

pub use github_poll::{GitHubPollSummary, GitHubPoller, GitHubPollerSettings};
pub use t3_sqlite::{T3Collector, T3CollectorSettings, T3CollectorSummary, T3Source};
pub use t3_state::T3SourceEvent;
