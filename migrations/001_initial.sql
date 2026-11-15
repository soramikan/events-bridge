-- Initial schema for events-bridge (design §5.3).
--
-- The schema is applied inside a transaction by `store::migrations`. Do not add
-- `BEGIN`/`COMMIT` here.

-- Durable event log. `sequence` is the local ingestion order and is distinct
-- from any upstream sequence (T3 Code) or cursor exposed to MCP clients.
CREATE TABLE events (
    id          TEXT PRIMARY KEY,
    sequence    INTEGER NOT NULL UNIQUE,
    source      TEXT NOT NULL,
    kind        TEXT NOT NULL,
    payload     TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    ingested_at TEXT NOT NULL
);

CREATE INDEX idx_events_source_sequence ON events (source, sequence);
CREATE INDEX idx_events_kind_sequence ON events (kind, sequence);
CREATE INDEX idx_events_occurred_at ON events (occurred_at);

-- Per-host, per-source position of the last processed upstream item.
CREATE TABLE source_cursors (
    host       TEXT NOT NULL,
    source     TEXT NOT NULL,
    cursor     TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (host, source)
);

-- Webhook subscriptions. `id` is deterministic over
-- (principal, callback_url, event_name, normalized arguments).
CREATE TABLE subscriptions (
    id             TEXT PRIMARY KEY,
    principal      TEXT NOT NULL,
    event_name     TEXT NOT NULL,
    arguments      TEXT NOT NULL,
    filter_hash    TEXT NOT NULL,
    callback_url   TEXT NOT NULL,
    secret         TEXT NOT NULL,
    delivery_mode  TEXT NOT NULL DEFAULT 'webhook',
    verified       INTEGER NOT NULL DEFAULT 0 CHECK (verified IN (0, 1)),
    active         INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL,
    refresh_before TEXT,
    last_delivery_at TEXT,
    last_error     TEXT,
    UNIQUE (principal, callback_url, event_name, filter_hash)
);

CREATE INDEX idx_subscriptions_event ON subscriptions (event_name, verified, active);
CREATE INDEX idx_subscriptions_principal ON subscriptions (principal);

-- One delivery per (subscription, event). The unique constraint is the
-- idempotency boundary for event ingestion.
CREATE TABLE deliveries (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    subscription_id TEXT NOT NULL REFERENCES subscriptions (id) ON DELETE CASCADE,
    event_id        TEXT NOT NULL REFERENCES events (id) ON DELETE CASCADE,
    status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'in_progress', 'delivered', 'failed', 'abandoned')),
    attempt_count   INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    UNIQUE (subscription_id, event_id)
);

CREATE INDEX idx_deliveries_due ON deliveries (status, next_attempt_at);
CREATE INDEX idx_deliveries_event ON deliveries (event_id);
CREATE INDEX idx_deliveries_subscription ON deliveries (subscription_id, status);

-- Audit trail of every HTTP attempt. `outcome` distinguishes retryable and
-- permanent failures from success.
CREATE TABLE delivery_attempts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    delivery_id  INTEGER NOT NULL REFERENCES deliveries (id) ON DELETE CASCADE,
    attempt      INTEGER NOT NULL,
    status_code  INTEGER,
    outcome      TEXT NOT NULL
                 CHECK (outcome IN ('success', 'retryable', 'permanent', 'network_error', 'exhausted', 'skipped')),
    error        TEXT,
    attempted_at TEXT NOT NULL
);

CREATE INDEX idx_delivery_attempts_delivery ON delivery_attempts (delivery_id, attempt);

-- Collector checkpoints (GitHub ETag, T3 Code fetch position, ...).
CREATE TABLE collector_checkpoints (
    collector  TEXT NOT NULL,
    scope      TEXT NOT NULL,
    etag       TEXT,
    watermark  TEXT,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (collector, scope)
);

-- Optional user acknowledgement history. This is intentionally separate from
-- webhook delivery state: a 2xx from a webhook receiver is not a user ack.
CREATE TABLE acks (
    principal       TEXT NOT NULL,
    event_id        TEXT NOT NULL REFERENCES events (id) ON DELETE CASCADE,
    acknowledged_at TEXT NOT NULL,
    PRIMARY KEY (principal, event_id)
);
