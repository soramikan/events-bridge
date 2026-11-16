-- Server-side polling consumers (Phase A).
--
-- A consumer is a named, server-side cursor shared by every client that polls
-- the same name. The cursor only moves on an explicit acknowledgement, which
-- gives poll/ack at-least-once semantics: a poll never consumes events.
--
-- `consumers` is intentionally independent from ChatGPT webhook
-- `subscriptions`: subscriptions are client-driven, TTL-scoped and push events
-- to a callback URL, while consumers are server-side cursors filtered by a
-- configured event profile.

CREATE TABLE consumers (
    name            TEXT PRIMARY KEY,
    cursor_sequence INTEGER NOT NULL DEFAULT 0 CHECK (cursor_sequence >= 0),
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    last_polled_at  TEXT,
    last_acked_at   TEXT
);
