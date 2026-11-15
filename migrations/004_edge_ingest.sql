-- Edge ingest replay protection and snapshot staging (Phase 4).
--
-- Every authenticated edge request carries a unique nonce. The primary key on
-- `(edge_id, nonce)` makes a replay a no-op, and `expires_at` lets the hub
-- delete nonces once the accepted timestamp window has passed. The schema is
-- applied inside a transaction by `store::migrations`.

CREATE TABLE edge_nonces (
    edge_id    TEXT NOT NULL,
    nonce      TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (edge_id, nonce)
);

CREATE INDEX idx_edge_nonces_expires ON edge_nonces (expires_at);

-- Edge-local pending snapshot. The edge stores the exact snapshot it is about
-- to send (including its base sequence) before the first POST, so a retry or a
-- restart re-sends the same snapshot instead of taking a newer one that would
-- silently skip events between the two snapshots.
CREATE TABLE edge_pending_snapshots (
    environment_id TEXT PRIMARY KEY,
    snapshot_id    TEXT NOT NULL,
    max_sequence   INTEGER NOT NULL,
    snapshot_json  TEXT NOT NULL,
    created_at     TEXT NOT NULL
);

-- Hub-side staging for chunked snapshots. Chunks are written here first and
-- only merged into the projection tables by an atomic `SnapshotCommit`.
CREATE TABLE edge_snapshot_stages (
    environment_id TEXT NOT NULL,
    snapshot_id    TEXT NOT NULL,
    chunk_index    INTEGER NOT NULL,
    chunk_kind     TEXT NOT NULL DEFAULT 'snapshot',
    snapshot_json  TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    PRIMARY KEY (environment_id, snapshot_id, chunk_index)
);

CREATE INDEX idx_edge_snapshot_stages_created
    ON edge_snapshot_stages (created_at);
