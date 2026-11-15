-- GitHub Collector state (Phase 3).
--
-- `github_deliveries` is the X-GitHub-Delivery idempotency boundary for the
-- webhook receiver. Pull requests and CI runs are materialized projections used
-- by `get_github_status`; the `*_emitted` flags make the corresponding
-- normalized event idempotent across webhook and REST reconciliation.
--
-- The schema is applied inside a transaction by `store::migrations`.

CREATE TABLE github_deliveries (
    delivery_id TEXT PRIMARY KEY,
    event_type  TEXT NOT NULL,
    repository  TEXT,
    received_at TEXT NOT NULL
);

CREATE INDEX idx_github_deliveries_received ON github_deliveries (received_at);

CREATE TABLE github_pull_requests (
    repository          TEXT NOT NULL,
    pull_number         INTEGER NOT NULL,
    title               TEXT NOT NULL,
    state               TEXT NOT NULL,
    author              TEXT,
    head_branch         TEXT,
    head_sha            TEXT,
    base_branch         TEXT,
    draft               INTEGER NOT NULL DEFAULT 0 CHECK (draft IN (0, 1)),
    merged              INTEGER NOT NULL DEFAULT 0 CHECK (merged IN (0, 1)),
    merged_by           TEXT,
    merged_at           TEXT,
    -- Normalized keys: `user:<login>` and `team:<slug>`. Keeping the two
    -- namespaces separate prevents a user and a team with the same name from
    -- colliding.
    requested_reviewers TEXT NOT NULL DEFAULT '[]',
    last_review_state   TEXT,
    -- Timestamp of the most recent review or review comment. `updated_at`
    -- remains the PR entity timestamp and must never be advanced by review
    -- activity.
    last_activity_at    TEXT,
    url                 TEXT NOT NULL,
    merged_emitted      INTEGER NOT NULL DEFAULT 0 CHECK (merged_emitted IN (0, 1)),
    updated_at          TEXT NOT NULL,
    PRIMARY KEY (repository, pull_number)
);

CREATE INDEX idx_github_pull_requests_updated
    ON github_pull_requests (repository, updated_at);
CREATE INDEX idx_github_pull_requests_branch
    ON github_pull_requests (repository, head_branch, updated_at);

CREATE TABLE github_ci_runs (
    repository        TEXT NOT NULL,
    canonical_run_id  TEXT NOT NULL,
    run_attempt       INTEGER NOT NULL DEFAULT 1,
    check_suite_id    INTEGER,
    workflow_name     TEXT NOT NULL,
    head_branch       TEXT,
    head_sha          TEXT,
    status            TEXT NOT NULL,
    conclusion        TEXT,
    url               TEXT NOT NULL,
    failure_emitted   INTEGER NOT NULL DEFAULT 0 CHECK (failure_emitted IN (0, 1)),
    updated_at        TEXT NOT NULL,
    PRIMARY KEY (repository, canonical_run_id, run_attempt)
);

CREATE INDEX idx_github_ci_runs_suite
    ON github_ci_runs (repository, check_suite_id);
CREATE INDEX idx_github_ci_runs_updated
    ON github_ci_runs (repository, updated_at);

-- A GitHub Actions `check_run` normally names a job, not a workflow. Its
-- `details_url` also does not always contain the run attempt. Such a check is
-- parked here until the canonical `workflow_run` (webhook or REST poll) tells
-- us the real workflow name, attempt and conclusion. External, non-Actions
-- check runs never use this table; they are materialized directly with the
-- `check_run:<id>` canonical key.
CREATE TABLE github_pending_checks (
    repository      TEXT NOT NULL,
    check_run_id    INTEGER NOT NULL,
    actions_run_id  INTEGER,
    parsed_attempt  INTEGER,
    check_suite_id  INTEGER,
    check_name      TEXT NOT NULL,
    head_branch     TEXT,
    head_sha        TEXT,
    status          TEXT NOT NULL,
    conclusion      TEXT,
    url             TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    PRIMARY KEY (repository, check_run_id)
);

CREATE INDEX idx_github_pending_checks_run
    ON github_pending_checks (repository, actions_run_id);
CREATE INDEX idx_github_pending_checks_suite
    ON github_pending_checks (repository, check_suite_id);

-- When a paginated reconciliation reaches the page cap while GitHub still
-- advertises `rel="next"`, the fetched rows are committed but the checkpoint
-- must not advance. This row records where the next pass resumes and the
-- ETag/watermark that become committed only once the scan completes.
CREATE TABLE github_poll_continuations (
    scope             TEXT PRIMARY KEY,
    next_url          TEXT NOT NULL,
    pending_etag      TEXT,
    pending_watermark TEXT,
    -- A full reconciliation must keep scanning without the watermark stop
    -- when it resumes after the page cap.
    full_reconcile    INTEGER NOT NULL DEFAULT 0 CHECK (full_reconcile IN (0, 1)),
    updated_at        TEXT NOT NULL
);
