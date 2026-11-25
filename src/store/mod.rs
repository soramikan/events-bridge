//! SQLite-backed state store.

pub mod consumers;
pub mod github;
pub mod migrations;
pub mod oauth;
pub(crate) mod orca;
pub mod repository;
pub mod t3;

pub use consumers::{
    ConsumerAckError, ConsumerAckOutcome, ConsumerEventFilter, ConsumerPollSnapshot,
    ConsumerPollSnapshotQuery, ConsumerProbeSnapshot, ConsumerRow,
};
pub use github::{
    GITHUB_COLLECTOR, GitHubApplyOutcome, GitHubCheckpoint, GitHubCiRun, GitHubDelivery,
    GitHubPendingCheck, GitHubPendingCheckResolution, GitHubPendingCheckUpdate, GitHubPollChanges,
    GitHubPollCommit, GitHubPollContinuation, GitHubPullRequest, GitHubStatus, GitHubStatusQuery,
    GitHubWebhookChanges, pulls_scope, runs_scope,
};
pub use oauth::{
    AccessTokenRecord, AuthorizationCodeRecord, ConsumeCodeOutcome, NewAccessToken,
    NewAuthorizationCode, NewRefreshToken, OAuthStore, RefreshTokenRecord, RotateRefreshOutcome,
};
pub(crate) use repository::arguments_match;
pub use repository::{
    AttemptOutcome, DueDelivery, EdgeNonceStatus, Event, EventQuery, IngestOutcome, NewEvent,
    NewSubscription, Repository, Subscription,
};
pub use t3::{
    EdgePendingSnapshot, SnapshotCommitError, T3ApplyOutcome, T3Approval, T3ApprovalQuery,
    T3Project, T3ProjectDeletion, T3Run, T3RunDetail, T3RunPatch, T3Snapshot, T3Thread,
    T3WriteBatch,
};
