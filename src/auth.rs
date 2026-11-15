//! Inbound bearer authentication for the HTTP transport.
//!
//! ChatGPT should ultimately reach the hub through Secure MCP Tunnel or OAuth
//! 2.1 (design §7). Phase 1 supports a single bearer token from the
//! environment; the authenticated principal is what scopes subscription ids.

use anyhow::{Context, Result, bail};
use axum::http::HeaderMap;
use secrecy::{ExposeSecret, SecretString};

use crate::config::AuthConfig;
use crate::util::constant_time_eq;

/// Why a request was not authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    /// No `Authorization` header or not a Bearer token.
    MissingCredentials,
    /// The presented token did not match.
    InvalidToken,
}

impl AuthError {
    /// Message suitable for a `WWW-Authenticate` response.
    pub fn message(self) -> &'static str {
        match self {
            Self::MissingCredentials => "missing bearer token",
            Self::InvalidToken => "invalid bearer token",
        }
    }
}

/// Bearer-token authenticator.
#[derive(Clone)]
pub struct Auth {
    token: Option<SecretString>,
    principal: String,
}

impl std::fmt::Debug for Auth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Auth")
            .field("configured", &self.token.is_some())
            .field("principal", &self.principal)
            .finish()
    }
}

impl Auth {
    /// Build an authenticator from configuration.
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
        })
    }

    /// Authenticator that accepts every request as `principal`. Tests only.
    #[doc(hidden)]
    pub fn disabled(principal: impl Into<String>) -> Self {
        Self {
            token: None,
            principal: principal.into(),
        }
    }

    /// Whether a token is required.
    pub fn is_enabled(&self) -> bool {
        self.token.is_some()
    }

    /// Authenticate the request headers and return the principal.
    pub fn authenticate(&self, headers: &HeaderMap) -> Result<String, AuthError> {
        let Some(expected) = &self.token else {
            return Ok(self.principal.clone());
        };

        let header = headers
            .get(axum::http::header::AUTHORIZATION)
            .ok_or(AuthError::MissingCredentials)?
            .to_str()
            .map_err(|_| AuthError::MissingCredentials)?;
        let presented = header
            .strip_prefix("Bearer ")
            .ok_or(AuthError::MissingCredentials)?;

        if constant_time_eq(presented.as_bytes(), expected.expose_secret().as_bytes()) {
            Ok(self.principal.clone())
        } else {
            Err(AuthError::InvalidToken)
        }
    }
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
        assert_eq!(auth.authenticate(&HeaderMap::new()).unwrap(), "tests");
    }

    #[test]
    fn bearer_token_is_compared_exactly() {
        let auth = Auth {
            token: Some(SecretString::from("s3cret".to_string())),
            principal: "chatgpt".into(),
        };
        assert_eq!(
            auth.authenticate(&headers("Bearer s3cret")).unwrap(),
            "chatgpt"
        );
        assert_eq!(
            auth.authenticate(&headers("Bearer nope")),
            Err(AuthError::InvalidToken)
        );
        assert_eq!(
            auth.authenticate(&HeaderMap::new()),
            Err(AuthError::MissingCredentials)
        );
        assert_eq!(
            auth.authenticate(&headers("Basic s3cret")),
            Err(AuthError::MissingCredentials)
        );
    }
}
