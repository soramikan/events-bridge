-- OAuth 2.1 authorization server state (Phase C2).
--
-- Only SHA-256 hashes of authorization codes, access tokens, and refresh
-- tokens are stored. A database leak therefore does not expose a usable
-- bearer credential. Timestamps use the same fixed-width UTC RFC 3339 form as
-- the rest of the schema so string comparisons are chronological.
--
-- `family_id` groups one authorization-code grant and every token rotated from
-- it. Reuse of a consumed code or rotated refresh token revokes the whole
-- family. `rotated_from_hash` records the predecessor of a rotated refresh
-- token for audit and replay detection.

CREATE TABLE oauth_authorization_codes (
    code_hash             TEXT PRIMARY KEY,
    client_id             TEXT NOT NULL,
    principal             TEXT NOT NULL,
    redirect_uri          TEXT NOT NULL,
    scopes                TEXT NOT NULL,
    code_challenge        TEXT NOT NULL,
    code_challenge_method TEXT NOT NULL CHECK (code_challenge_method = 'S256'),
    resource              TEXT,
    family_id             TEXT NOT NULL,
    created_at            TEXT NOT NULL,
    expires_at            TEXT NOT NULL,
    used_at               TEXT
);

CREATE INDEX idx_oauth_authorization_codes_family
    ON oauth_authorization_codes (family_id);
CREATE INDEX idx_oauth_authorization_codes_expires
    ON oauth_authorization_codes (expires_at);

CREATE TABLE oauth_access_tokens (
    token_hash              TEXT PRIMARY KEY,
    client_id               TEXT NOT NULL,
    principal               TEXT NOT NULL,
    scopes                  TEXT NOT NULL,
    family_id               TEXT NOT NULL,
    authorization_code_hash TEXT NOT NULL,
    created_at              TEXT NOT NULL,
    expires_at              TEXT NOT NULL,
    revoked_at              TEXT
);

CREATE INDEX idx_oauth_access_tokens_family ON oauth_access_tokens (family_id);
CREATE INDEX idx_oauth_access_tokens_client ON oauth_access_tokens (client_id);
CREATE INDEX idx_oauth_access_tokens_expires ON oauth_access_tokens (expires_at);

CREATE TABLE oauth_refresh_tokens (
    token_hash              TEXT PRIMARY KEY,
    client_id               TEXT NOT NULL,
    principal               TEXT NOT NULL,
    scopes                  TEXT NOT NULL,
    family_id               TEXT NOT NULL,
    authorization_code_hash TEXT NOT NULL,
    rotated_from_hash       TEXT,
    created_at              TEXT NOT NULL,
    expires_at              TEXT NOT NULL,
    used_at                 TEXT,
    revoked_at              TEXT
);

CREATE INDEX idx_oauth_refresh_tokens_family ON oauth_refresh_tokens (family_id);
CREATE INDEX idx_oauth_refresh_tokens_client ON oauth_refresh_tokens (client_id);
CREATE INDEX idx_oauth_refresh_tokens_expires ON oauth_refresh_tokens (expires_at);
