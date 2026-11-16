//! Inbound bearer authentication for the HTTP transport.
//!
//! The static `[auth].token_env` token and OAuth 2.1 access tokens can
//! coexist. A static token always grants every scope; an OAuth token carries
//! only the scopes granted by its authorization code or refresh rotation.
//! When OAuth is enabled and no static token is configured, HTTP MCP and
//! consumer endpoints never fall back to unauthenticated access.

use std::{collections::BTreeSet, sync::Arc};

use anyhow::{Context, Result, bail};
use axum::http::HeaderMap;
use secrecy::{ExposeSecret, SecretString};

use crate::{
    config::AuthConfig,
    oauth::{ALL_SCOPES, OAuthService},
    util::constant_time_eq,
};

/// Authenticated request identity with its granted scopes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedPrincipal {
    /// Principal used for ownership and acknowledgements.
    pub principal: String,
    /// Granted OAuth scopes. Static bearer tokens receive every scope.
    pub scopes: BTreeSet<String>,
    /// OAuth client id when the request used an OAuth access token.
    pub oauth_client_id: Option<String>,
}

impl AuthenticatedPrincipal {
    /// Identity carrying every scope.
    pub fn full(principal: impl Into<String>) -> Self {
        Self {
            principal: principal.into(),
            scopes: ALL_SCOPES
                .iter()
                .map(|scope| (*scope).to_string())
                .collect(),
            oauth_client_id: None,
        }
    }

    /// Whether the identity has `scope`.
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.contains(scope)
    }
}

/// Why a request was not authenticated or authorized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    /// No `Authorization` header or not a Bearer token.
    MissingCredentials,
    /// The presented token did not match.
    InvalidToken,
    /// A valid token lacks the scope required by the endpoint.
    InsufficientScope(&'static str),
}

impl AuthError {
    /// Message suitable for a JSON error response.
    pub fn message(self) -> &'static str {
        match self {
            Self::MissingCredentials => "missing bearer token",
            Self::InvalidToken => "invalid bearer token",
            Self::InsufficientScope(_) => "insufficient scope",
        }
    }
}

/// Bearer-token authenticator.
#[derive(Clone)]
pub struct Auth {
    token: Option<SecretString>,
    principal: String,
    oauth: Option<Arc<OAuthService>>,
}

impl std::fmt::Debug for Auth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Auth")
            .field("configured", &self.token.is_some())
            .field("oauth", &self.oauth.is_some())
            .field("principal", &self.principal)
            .finish()
    }
}

impl Auth {
    /// Build a static-token authenticator from configuration.
    pub fn from_config(config: &AuthConfig) -> Result<Self> {
        let token = match &config.token_env {
            Some(variable) => {
                let value = std::env::var(variable).with_context(|| {
                    format!(
                        "authentication is enabled but environment variable `{variable}` is unset"
                    )
                })?;
                if value.is_empty() {
                    bail!("environment variable `{variable}` is empty");
                }
                Some(SecretString::from(value))
            }
            None => None,
        };
        Ok(Self {
            token,
            principal: config.principal.clone(),
            oauth: None,
        })
    }

    /// Attach an OAuth 2.1 service to the authenticator.
    pub fn with_oauth(mut self, oauth: Option<Arc<OAuthService>>) -> Self {
        self.oauth = oauth;
        self
    }

    /// Authenticator that accepts every request as `principal`. Tests only.
    #[doc(hidden)]
    pub fn disabled(principal: impl Into<String>) -> Self {
        Self {
            token: None,
            principal: principal.into(),
            oauth: None,
        }
    }

    /// Whether any credential is required.
    pub fn is_enabled(&self) -> bool {
        self.token.is_some() || self.oauth.is_some()
    }

    /// OAuth service when enabled.
    pub fn oauth(&self) -> Option<&Arc<OAuthService>> {
        self.oauth.as_ref()
    }

    /// Static-token authentication used by internal ingest.
    ///
    /// This intentionally does not accept OAuth tokens: the internal ingest
    /// endpoint has its own separate token and must not widen an OAuth grant.
    pub fn authenticate(&self, headers: &HeaderMap) -> Result<String, AuthError> {
        let Some(expected) = &self.token else {
            return Ok(self.principal.clone());
        };

        let presented = bearer_token(headers)?;
        if constant_time_eq(presented.as_bytes(), expected.expose_secret().as_bytes()) {
            Ok(self.principal.clone())
        } else {
            Err(AuthError::InvalidToken)
        }
    }

    /// Authenticate an HTTP request against the static token and/or OAuth.
    ///
    /// The static token grants every scope. OAuth tokens carry only their
    /// stored grant. When neither mechanism is configured the request is
    /// attributed to the configured principal, preserving loopback/local
    /// behavior.
    pub fn authenticate_request(
        &self,
        headers: &HeaderMap,
    ) -> Result<AuthenticatedPrincipal, AuthError> {
        let has_authorization = headers.contains_key(axum::http::header::AUTHORIZATION);
        if !self.is_enabled() {
            return Ok(AuthenticatedPrincipal::full(self.principal.clone()));
        }

        let presented = if has_authorization {
            Some(bearer_token(headers)?)
        } else {
            None
        };

        if let Some(expected) = &self.token
            && let Some(presented) = presented
            && constant_time_eq(presented.as_bytes(), expected.expose_secret().as_bytes())
        {
            return Ok(AuthenticatedPrincipal::full(self.principal.clone()));
        }

        let Some(oauth) = &self.oauth else {
            return Err(if presented.is_some() {
                AuthError::InvalidToken
            } else {
                AuthError::MissingCredentials
            });
        };

        let presented = presented.ok_or(AuthError::MissingCredentials)?;
        match oauth.authenticate_access_token(presented) {
            Ok(identity) => Ok(AuthenticatedPrincipal {
                principal: identity.principal,
                scopes: identity.scopes,
                oauth_client_id: Some(identity.client_id),
            }),
            Err(error) => {
                if let crate::oauth::OAuthError::Server(error) = error {
                    tracing::error!(%error, "OAuth access-token lookup failed");
                }
                Err(AuthError::InvalidToken)
            }
        }
    }

    /// Check that an authenticated identity has the required scope.
    pub fn require_scope(
        identity: &AuthenticatedPrincipal,
        scope: &'static str,
    ) -> Result<(), AuthError> {
        if identity.has_scope(scope) {
            Ok(())
        } else {
            Err(AuthError::InsufficientScope(scope))
        }
    }
}

fn bearer_token(headers: &HeaderMap) -> Result<&str, AuthError> {
    let header = headers
        .get(axum::http::header::AUTHORIZATION)
        .ok_or(AuthError::MissingCredentials)?
        .to_str()
        .map_err(|_| AuthError::MissingCredentials)?;
    let token = header
        .strip_prefix("Bearer ")
        .ok_or(AuthError::MissingCredentials)?;
    if token.is_empty() {
        return Err(AuthError::MissingCredentials);
    }
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header::AUTHORIZATION;

    fn headers(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, value.parse().unwrap());
        headers
    }

    #[test]
    fn disabled_auth_attributes_every_request() {
        let auth = Auth::disabled("tests");
        let identity = auth.authenticate_request(&HeaderMap::new()).unwrap();
        assert_eq!(identity.principal, "tests");
        assert!(identity.has_scope(crate::oauth::SCOPE_EVENTS_ACK));
    }

    #[test]
    fn bearer_token_is_compared_exactly() {
        let auth = Auth {
            token: Some(SecretString::from("test-token".to_string())),
            principal: "chatgpt".into(),
            oauth: None,
        };
        let identity = auth
            .authenticate_request(&headers("Bearer test-token"))
            .unwrap();
        assert_eq!(identity.principal, "chatgpt");
        assert!(identity.has_scope(crate::oauth::SCOPE_EVENTS_SUBSCRIBE));
        assert_eq!(
            auth.authenticate_request(&headers("Bearer nope")),
            Err(AuthError::InvalidToken)
        );
        assert_eq!(
            auth.authenticate_request(&HeaderMap::new()),
            Err(AuthError::MissingCredentials)
        );
        assert_eq!(
            auth.authenticate_request(&headers("Basic test-token")),
            Err(AuthError::MissingCredentials)
        );
    }

    #[test]
    fn scope_check_reports_the_missing_scope() {
        let identity = AuthenticatedPrincipal {
            principal: "oauth".into(),
            scopes: [crate::oauth::SCOPE_EVENTS_READ.to_string()]
                .into_iter()
                .collect(),
            oauth_client_id: Some("client".into()),
        };
        assert!(Auth::require_scope(&identity, crate::oauth::SCOPE_EVENTS_READ).is_ok());
        assert_eq!(
            Auth::require_scope(&identity, crate::oauth::SCOPE_EVENTS_ACK),
            Err(AuthError::InsufficientScope(crate::oauth::SCOPE_EVENTS_ACK))
        );
    }
}
