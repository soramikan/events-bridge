-- T3 Code Collector materialized state (Phase 2).
--
-- These tables are projections of the read-only T3 Code `statev2.sqlite`
-- database. They are written only by the T3 collector in `src/collectors/`;
-- the hub's MCP pull tools read them. The schema is applied inside a
-- transaction by `store::migrations`.

CREATE TABLE t3_projects (
    environment_id TEXT NOT NULL,
    project_id     TEXT NOT NULL,
    title          TEXT NOT NULL,
    workspace_root TEXT NOT NULL,
    deleted_at     TEXT,
    updated_at     TEXT NOT NULL,
    PRIMARY KEY (environment_id, project_id)
);

CREATE INDEX idx_t3_projects_updated ON t3_projects (environment_id, updated_at);

CREATE TABLE t3_threads (
    environment_id TEXT NOT NULL,
    thread_id      TEXT NOT NULL,
    project_id     TEXT NOT NULL,
    title          TEXT NOT NULL,
    branch         TEXT,
    deleted_at     TEXT,
    updated_at     TEXT NOT NULL,
    PRIMARY KEY (environment_id, thread_id)
);

CREATE INDEX idx_t3_threads_project ON t3_threads (environment_id, project_id, updated_at);
CREATE INDEX idx_t3_threads_updated ON t3_threads (environment_id, updated_at);

CREATE TABLE t3_runs (
    environment_id        TEXT NOT NULL,
    run_id                TEXT NOT NULL,
    thread_id             TEXT NOT NULL,
    project_id            TEXT NOT NULL DEFAULT '',
    ordinal               INTEGER NOT NULL DEFAULT 0,
    provider_instance_id  TEXT,
    status                TEXT NOT NULL,
    last_turn_status      TEXT,
    checkpoint_id         TEXT,
    error                 TEXT,
    summary               TEXT,
    requested_at          TEXT,
    started_at            TEXT,
    completed_at          TEXT,
    updated_at            TEXT NOT NULL,
    PRIMARY KEY (environment_id, run_id)
);

CREATE INDEX idx_t3_runs_thread ON t3_runs (environment_id, thread_id, ordinal);
CREATE INDEX idx_t3_runs_status ON t3_runs (environment_id, status, updated_at);

CREATE TABLE t3_approvals (
    environment_id TEXT NOT NULL,
    approval_id    TEXT NOT NULL,
    thread_id      TEXT NOT NULL DEFAULT '',
    run_id         TEXT NOT NULL DEFAULT '',
    node_id        TEXT,
    kind           TEXT NOT NULL,
    status         TEXT NOT NULL,
    summary        TEXT,
    decision       TEXT,
    created_at     TEXT NOT NULL,
    resolved_at    TEXT,
    updated_at     TEXT NOT NULL,
    PRIMARY KEY (environment_id, approval_id)
);

CREATE INDEX idx_t3_approvals_status ON t3_approvals (environment_id, status, created_at);
CREATE INDEX idx_t3_approvals_run ON t3_approvals (environment_id, run_id, status);
CREATE INDEX idx_t3_approvals_thread ON t3_approvals (environment_id, thread_id, status);
