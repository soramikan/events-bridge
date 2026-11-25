-- Each Edge records its observation cutoff and keeps signed-ingest events
-- pending until a Hub acknowledges them. Sent IDs suppress repeated snapshots.
CREATE TABLE orca_edge_baselines (
    environment_id TEXT PRIMARY KEY NOT NULL,
    first_poll_ms  INTEGER NOT NULL
);

CREATE TABLE orca_edge_outbox (
    event_id       TEXT PRIMARY KEY NOT NULL,
    environment_id TEXT NOT NULL REFERENCES orca_edge_baselines(environment_id),
    occurred_at_ms INTEGER NOT NULL,
    body           BLOB
);

CREATE INDEX orca_edge_outbox_pending
    ON orca_edge_outbox (environment_id, occurred_at_ms, event_id) WHERE body IS NOT NULL;
