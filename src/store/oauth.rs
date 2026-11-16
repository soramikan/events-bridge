//! OAuth 2.1 authorization-server persistence.
//!
//! The service layer generates opaque codes and tokens; this module only ever
//! receives their SHA-256 hex digests. Atomic methods consume authorization
//! codes and rotate refresh tokens so replay detection cannot be bypassed by a
//! concurrent request.

use std::sync::Arc;

use anyhow::Result;
use rusqlite::{Connection, OptionalExtension, params};

use super::Repository;

/// A stored authorization code. `code_hash` is the SHA-256 hex digest of the
/// opaque code handed to the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationCodeRecord {
    pub code_hash: String,
    pub client_id: String,
    pub principal: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub code_challenge: String,
    pub family_id: String,
    pub created_at: String,
    pub expires_at: String,
    pub used_at: Option<String>,
}

/// Values inserted when an authorization code is issued.
#[derive(Debug, Clone)]
pub struct NewAuthorizationCode {
    pub code_hash: String,
    pub client_id: String,
    pub principal: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub code_challenge: String,
    pub resource: Option<String>,
    pub family_id: String,
    pub created_at: String,
    pub expires_at: String,
}

/// A stored access token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessTokenRecord {
    pub token_hash: String,
    pub client_id: String,
    pub principal: String,
    pub scopes: Vec<String>,
    pub family_id: String,
    pub expires_at: String,
    pub revoked_at: Option<String>,
}

/// A stored refresh token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshTokenRecord {
    pub token_hash: String,
    pub client_id: String,
    pub principal: String,
    pub scopes: Vec<String>,
    pub family_id: String,
    pub authorization_code_hash: String,
    pub rotated_from_hash: Option<String>,
    pub expires_at: String,
    pub used_at: Option<String>,
    pub revoked_at: Option<String>,
}

/// New access-token row.
#[derive(Debug, Clone)]
pub struct NewAccessToken {
    pub token_hash: String,
    pub client_id: String,
    pub principal: String,
    pub scopes: Vec<String>,
    pub family_id: String,
    pub authorization_code_hash: String,
    pub created_at: String,
    pub expires_at: String,
}

/// New refresh-token row.
#[derive(Debug, Clone)]
pub struct NewRefreshToken {
    pub token_hash: String,
    pub client_id: String,
    pub principal: String,
    pub scopes: Vec<String>,
    pub family_id: String,
    pub authorization_code_hash: String,
    pub rotated_from_hash: Option<String>,
    pub created_at: String,
    pub expires_at: String,
}

/// Result of atomically consuming an authorization code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsumeCodeOutcome {
    /// The code was consumed and both token rows were inserted.
    Issued,
    /// The code had already been consumed. The family was revoked.
    Replayed { family_id: String },
    /// The code exists but its TTL elapsed.
    Expired,
    /// No such code hash exists.
    NotFound,
}

/// Result of atomically rotating a refresh token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RotateRefreshOutcome {
    /// The old token was consumed and the replacement pair was inserted.
    Rotated,
    /// The refresh token had already been used or revoked. The family was
    /// revoked.
    Replayed { family_id: String },
    /// The refresh token exists but its TTL elapsed.
    Expired,
    /// No such refresh-token hash exists.
    NotFound,
}

/// OAuth persistence facade over the shared SQLite connection.
#[derive(Clone)]
pub struct OAuthStore {
    repo: Arc<Repository>,
}

impl OAuthStore {
    /// Create a store over the repository.
    pub fn new(repo: Arc<Repository>) -> Self {
        Self { repo }
    }

    /// Insert a freshly issued authorization code.
    pub fn insert_authorization_code(&self, code: &NewAuthorizationCode) -> Result<()> {
        let conn = self.repo.lock_connection();
        conn.execute(
            "INSERT INTO oauth_authorization_codes \
             (code_hash, client_id, principal, redirect_uri, scopes, code_challenge, \
              code_challenge_method, resource, family_id, created_at, expires_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'S256', ?7, ?8, ?9, ?10)",
            params![
                code.code_hash,
                code.client_id,
                code.principal,
                code.redirect_uri,
                encode_scopes(&code.scopes),
                code.code_challenge,
                code.resource,
                code.family_id,
                code.created_at,
                code.expires_at,
            ],
        )?;
        Ok(())
    }

    /// Look up an authorization code by digest.
    pub fn authorization_code(&self, code_hash: &str) -> Result<Option<AuthorizationCodeRecord>> {
        let conn = self.repo.lock_connection();
        conn.query_row(
            "SELECT code_hash, client_id, principal, redirect_uri, scopes, code_challenge, \
                    family_id, created_at, expires_at, used_at \
             FROM oauth_authorization_codes WHERE code_hash = ?1",
            params![code_hash],
            |row| {
                Ok(AuthorizationCodeRecord {
                    code_hash: row.get(0)?,
                    client_id: row.get(1)?,
                    principal: row.get(2)?,
                    redirect_uri: row.get(3)?,
                    scopes: decode_scopes(row.get::<_, String>(4)?),
                    code_challenge: row.get(5)?,
                    family_id: row.get(6)?,
                    created_at: row.get(7)?,
                    expires_at: row.get(8)?,
                    used_at: row.get(9)?,
                })
            },
        )
        .optional()
        .map_err(Into::into)
    }

    /// Atomically consume a code and insert its access/refresh tokens.
    pub fn consume_authorization_code(
        &self,
        code_hash: &str,
        now: &str,
        access: &NewAccessToken,
        refresh: &NewRefreshToken,
    ) -> Result<ConsumeCodeOutcome> {
        let mut conn = self.repo.lock_connection();
        let tx = conn.transaction()?;
        let row: Option<(String, Option<String>, String)> = tx
            .query_row(
                "SELECT family_id, used_at, expires_at FROM oauth_authorization_codes \
                 WHERE code_hash = ?1",
                params![code_hash],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;

        let Some((family_id, used_at, expires_at)) = row else {
            tx.commit()?;
            return Ok(ConsumeCodeOutcome::NotFound);
        };

        if used_at.is_some() {
            revoke_family(&tx, &family_id, now)?;
            tx.commit()?;
            return Ok(ConsumeCodeOutcome::Replayed { family_id });
        }
        if expires_at.as_str() <= now {
            tx.commit()?;
            return Ok(ConsumeCodeOutcome::Expired);
        }

        let updated = tx.execute(
            "UPDATE oauth_authorization_codes SET used_at = ?1 \
             WHERE code_hash = ?2 AND used_at IS NULL",
            params![now, code_hash],
        )?;
        if updated == 0 {
            revoke_family(&tx, &family_id, now)?;
            tx.commit()?;
            return Ok(ConsumeCodeOutcome::Replayed { family_id });
        }

        insert_access_token(&tx, access)?;
        insert_refresh_token(&tx, refresh)?;
        tx.commit()?;
        Ok(ConsumeCodeOutcome::Issued)
    }

    /// Revoke the family associated with a consumed authorization code.
    ///
    /// This supports explicit replay rejection before PKCE verification. The
    /// atomic consume path still performs its own replay check for races.
    pub fn revoke_code_family(&self, code_hash: &str, now: &str) -> Result<()> {
        let mut conn = self.repo.lock_connection();
        let tx = conn.transaction()?;
        let family_id: Option<String> = tx
            .query_row(
                "SELECT family_id FROM oauth_authorization_codes WHERE code_hash = ?1",
                params![code_hash],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(family_id) = family_id {
            revoke_family(&tx, &family_id, now)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Look up an access token by digest.
    pub fn access_token(&self, token_hash: &str) -> Result<Option<AccessTokenRecord>> {
        let conn = self.repo.lock_connection();
        conn.query_row(
            "SELECT token_hash, client_id, principal, scopes, family_id, expires_at, revoked_at \
             FROM oauth_access_tokens WHERE token_hash = ?1",
            params![token_hash],
            |row| {
                Ok(AccessTokenRecord {
                    token_hash: row.get(0)?,
                    client_id: row.get(1)?,
                    principal: row.get(2)?,
                    scopes: decode_scopes(row.get::<_, String>(3)?),
                    family_id: row.get(4)?,
                    expires_at: row.get(5)?,
                    revoked_at: row.get(6)?,
                })
            },
        )
        .optional()
        .map_err(Into::into)
    }

    /// Look up a refresh token by digest.
    pub fn refresh_token(&self, token_hash: &str) -> Result<Option<RefreshTokenRecord>> {
        let conn = self.repo.lock_connection();
        conn.query_row(
            "SELECT token_hash, client_id, principal, scopes, family_id, \
                    authorization_code_hash, rotated_from_hash, expires_at, used_at, revoked_at \
             FROM oauth_refresh_tokens WHERE token_hash = ?1",
            params![token_hash],
            |row| {
                Ok(RefreshTokenRecord {
                    token_hash: row.get(0)?,
                    client_id: row.get(1)?,
                    principal: row.get(2)?,
                    scopes: decode_scopes(row.get::<_, String>(3)?),
                    family_id: row.get(4)?,
                    authorization_code_hash: row.get(5)?,
                    rotated_from_hash: row.get(6)?,
                    expires_at: row.get(7)?,
                    used_at: row.get(8)?,
                    revoked_at: row.get(9)?,
                })
            },
        )
        .optional()
        .map_err(Into::into)
    }

    /// Atomically consume a refresh token and insert its replacement pair.
    pub fn rotate_refresh_token(
        &self,
        old_hash: &str,
        now: &str,
        access: &NewAccessToken,
        refresh: &NewRefreshToken,
    ) -> Result<RotateRefreshOutcome> {
        let mut conn = self.repo.lock_connection();
        let tx = conn.transaction()?;
        let row: Option<(String, Option<String>, Option<String>, String)> = tx
            .query_row(
                "SELECT family_id, used_at, revoked_at, expires_at FROM oauth_refresh_tokens \
                 WHERE token_hash = ?1",
                params![old_hash],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;

        let Some((family_id, used_at, revoked_at, expires_at)) = row else {
            tx.commit()?;
            return Ok(RotateRefreshOutcome::NotFound);
        };

        if used_at.is_some() || revoked_at.is_some() {
            revoke_family(&tx, &family_id, now)?;
            tx.commit()?;
            return Ok(RotateRefreshOutcome::Replayed { family_id });
        }
        if expires_at.as_str() <= now {
            tx.commit()?;
            return Ok(RotateRefreshOutcome::Expired);
        }

        let updated = tx.execute(
            "UPDATE oauth_refresh_tokens SET used_at = ?1 \
             WHERE token_hash = ?2 AND used_at IS NULL AND revoked_at IS NULL",
            params![now, old_hash],
        )?;
        if updated == 0 {
            revoke_family(&tx, &family_id, now)?;
            tx.commit()?;
            return Ok(RotateRefreshOutcome::Replayed { family_id });
        }

        insert_access_token(&tx, access)?;
        insert_refresh_token(&tx, refresh)?;
        tx.commit()?;
        Ok(RotateRefreshOutcome::Rotated)
    }

    /// Revoke an access token and its family only when it belongs to
    /// `client_id`. Revoking either credential invalidates the grant.
    pub fn revoke_access_token(&self, token_hash: &str, client_id: &str, now: &str) -> Result<()> {
        let mut conn = self.repo.lock_connection();
        let tx = conn.transaction()?;
        let family_id: Option<String> = tx
            .query_row(
                "SELECT family_id FROM oauth_access_tokens \
                 WHERE token_hash = ?1 AND client_id = ?2",
                params![token_hash, client_id],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(family_id) = family_id {
            revoke_family(&tx, &family_id, now)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Revoke a refresh token and its entire family only when the refresh token
    /// belongs to `client_id`.
    pub fn revoke_refresh_family(
        &self,
        token_hash: &str,
        client_id: &str,
        now: &str,
    ) -> Result<()> {
        let mut conn = self.repo.lock_connection();
        let tx = conn.transaction()?;
        let family_id: Option<String> = tx
            .query_row(
                "SELECT family_id FROM oauth_refresh_tokens \
                 WHERE token_hash = ?1 AND client_id = ?2",
                params![token_hash, client_id],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(family_id) = family_id {
            revoke_family(&tx, &family_id, now)?;
        }
        tx.commit()?;
        Ok(())
    }
}

fn insert_access_token(conn: &Connection, token: &NewAccessToken) -> Result<()> {
    conn.execute(
        "INSERT INTO oauth_access_tokens \
         (token_hash, client_id, principal, scopes, family_id, authorization_code_hash, \
          created_at, expires_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            token.token_hash,
            token.client_id,
            token.principal,
            encode_scopes(&token.scopes),
            token.family_id,
            token.authorization_code_hash,
            token.created_at,
            token.expires_at,
        ],
    )?;
    Ok(())
}

fn insert_refresh_token(conn: &Connection, token: &NewRefreshToken) -> Result<()> {
    conn.execute(
        "INSERT INTO oauth_refresh_tokens \
         (token_hash, client_id, principal, scopes, family_id, authorization_code_hash, \
          rotated_from_hash, created_at, expires_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            token.token_hash,
            token.client_id,
            token.principal,
            encode_scopes(&token.scopes),
            token.family_id,
            token.authorization_code_hash,
            token.rotated_from_hash,
            token.created_at,
            token.expires_at,
        ],
    )?;
    Ok(())
}

fn revoke_family(conn: &Connection, family_id: &str, now: &str) -> Result<()> {
    conn.execute(
        "UPDATE oauth_access_tokens SET revoked_at = ?1 \
         WHERE family_id = ?2 AND revoked_at IS NULL",
        params![now, family_id],
    )?;
    conn.execute(
        "UPDATE oauth_refresh_tokens SET revoked_at = ?1 \
         WHERE family_id = ?2 AND revoked_at IS NULL",
        params![now, family_id],
    )?;
    Ok(())
}

fn encode_scopes(scopes: &[String]) -> String {
    scopes.join(" ")
}

fn decode_scopes(value: String) -> Vec<String> {
    value.split_whitespace().map(ToOwned::to_owned).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo() -> Arc<Repository> {
        Arc::new(Repository::open_in_memory().unwrap())
    }

    fn code() -> NewAuthorizationCode {
        NewAuthorizationCode {
            code_hash: "code-hash".into(),
            client_id: "client".into(),
            principal: "user".into(),
            redirect_uri: "https://client.example/callback".into(),
            scopes: vec!["events.read".into()],
            code_challenge: "challenge".into(),
            resource: None,
            family_id: "family".into(),
            created_at: "2026-01-01T00:00:00.000Z".into(),
            expires_at: "2099-01-01T00:00:00.000Z".into(),
        }
    }

    fn tokens() -> (NewAccessToken, NewRefreshToken) {
        (
            NewAccessToken {
                token_hash: "access-hash".into(),
                client_id: "client".into(),
                principal: "user".into(),
                scopes: vec!["events.read".into()],
                family_id: "family".into(),
                authorization_code_hash: "code-hash".into(),
                created_at: "2026-01-01T00:00:00.000Z".into(),
                expires_at: "2099-01-01T00:00:00.000Z".into(),
            },
            NewRefreshToken {
                token_hash: "refresh-hash".into(),
                client_id: "client".into(),
                principal: "user".into(),
                scopes: vec!["events.read".into()],
                family_id: "family".into(),
                authorization_code_hash: "code-hash".into(),
                rotated_from_hash: None,
                created_at: "2026-01-01T00:00:00.000Z".into(),
                expires_at: "2099-01-01T00:00:00.000Z".into(),
            },
        )
    }

    #[test]
    fn code_is_consumed_once_and_replay_revokes_family() {
        let store = OAuthStore::new(repo());
        store.insert_authorization_code(&code()).unwrap();
        let (access, refresh) = tokens();
        assert_eq!(
            store
                .consume_authorization_code(
                    "code-hash",
                    "2026-01-01T00:00:01.000Z",
                    &access,
                    &refresh
                )
                .unwrap(),
            ConsumeCodeOutcome::Issued
        );
        assert!(
            store
                .access_token("access-hash")
                .unwrap()
                .unwrap()
                .revoked_at
                .is_none()
        );
        assert_eq!(
            store
                .consume_authorization_code(
                    "code-hash",
                    "2026-01-01T00:00:02.000Z",
                    &access,
                    &refresh
                )
                .unwrap(),
            ConsumeCodeOutcome::Replayed {
                family_id: "family".into()
            }
        );
        assert!(
            store
                .access_token("access-hash")
                .unwrap()
                .unwrap()
                .revoked_at
                .is_some()
        );
        assert!(
            store
                .refresh_token("refresh-hash")
                .unwrap()
                .unwrap()
                .revoked_at
                .is_some()
        );
    }

    #[test]
    fn refresh_rotation_links_predecessor_and_replay_revokes_family() {
        let store = OAuthStore::new(repo());
        store.insert_authorization_code(&code()).unwrap();
        let (access, refresh) = tokens();
        store
            .consume_authorization_code("code-hash", "2026-01-01T00:00:01.000Z", &access, &refresh)
            .unwrap();

        let next_access = NewAccessToken {
            token_hash: "access-two".into(),
            ..access
        };
        let next_refresh = NewRefreshToken {
            token_hash: "refresh-two".into(),
            rotated_from_hash: Some("refresh-hash".into()),
            ..refresh
        };
        assert_eq!(
            store
                .rotate_refresh_token(
                    "refresh-hash",
                    "2026-01-01T00:00:02.000Z",
                    &next_access,
                    &next_refresh
                )
                .unwrap(),
            RotateRefreshOutcome::Rotated
        );
        let stored = store.refresh_token("refresh-two").unwrap().unwrap();
        assert_eq!(stored.rotated_from_hash.as_deref(), Some("refresh-hash"));

        assert_eq!(
            store
                .rotate_refresh_token(
                    "refresh-hash",
                    "2026-01-01T00:00:03.000Z",
                    &next_access,
                    &next_refresh
                )
                .unwrap(),
            RotateRefreshOutcome::Replayed {
                family_id: "family".into()
            }
        );
        assert!(
            store
                .refresh_token("refresh-two")
                .unwrap()
                .unwrap()
                .revoked_at
                .is_some()
        );
    }
}
