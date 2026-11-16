//! OAuth 2.1 authorization server with mandatory PKCE S256.
//!
//! The server is intentionally pre-registration only: operators list clients
//! in `[oauth.clients]` instead of exposing dynamic client registration. Every
//! code, access token, and refresh token is stored as a SHA-256 digest in
//! SQLite; the raw values are returned once to the client and never persisted.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use anyhow::{Context, Result, bail};
use axum::http::{HeaderMap, header};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use rand::RngCore;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use url::Url;

use crate::{
    config::{OAuthClientConfig, OAuthConfig},
    store::{
        ConsumeCodeOutcome, NewAccessToken, NewAuthorizationCode, NewRefreshToken, OAuthStore,
        Repository, RotateRefreshOutcome,
    },
    util::{constant_time_eq, now_rfc3339},
};

/// Scope allowing read-only pull tools and consumer probe/poll endpoints.
pub const SCOPE_EVENTS_READ: &str = "events.read";
/// Scope allowing push-subscription management.
pub const SCOPE_EVENTS_SUBSCRIBE: &str = "events.subscribe";
/// Scope allowing event and consumer acknowledgements.
pub const SCOPE_EVENTS_ACK: &str = "events.ack";

/// Every scope the server understands.
pub const ALL_SCOPES: [&str; 3] = [SCOPE_EVENTS_READ, SCOPE_EVENTS_SUBSCRIBE, SCOPE_EVENTS_ACK];

/// CSRF cookie name used by the consent page.
pub const CSRF_COOKIE: &str = "oauth_csrf";
/// Consent form field carrying the same CSRF token.
pub const CSRF_FIELD: &str = "csrf_token";
/// Consent form field carrying the administrator approval secret.
pub const ADMIN_SECRET_FIELD: &str = "admin_secret";
/// Consent form field carrying the approve/deny decision.
pub const DECISION_FIELD: &str = "decision";

/// Maximum accepted length of an opaque OAuth parameter such as `state`.
const MAX_OPTIONAL_PARAM_LEN: usize = 2048;

/// Map an MCP tool name to its required scope.
pub fn required_scope_for_tool(name: &str) -> Option<&'static str> {
    match name {
        "list_events"
        | "get_event"
        | "get_t3_run"
        | "get_t3_approvals"
        | "get_github_status"
        | "probe_consumer"
        | "poll_consumer_events" => Some(SCOPE_EVENTS_READ),
        "ack_events" | "ack_consumer_events" => Some(SCOPE_EVENTS_ACK),
        _ => None,
    }
}

/// Map an `events/*` JSON-RPC method to its required scope.
pub fn required_scope_for_method(method: &str) -> Option<&'static str> {
    match method {
        "events/list" | "events/poll" => Some(SCOPE_EVENTS_READ),
        "events/subscribe" | "events/unsubscribe" => Some(SCOPE_EVENTS_SUBSCRIBE),
        _ => None,
    }
}

/// Authenticated OAuth identity attached to a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthIdentity {
    /// Client that owns the access token.
    pub client_id: String,
    /// Principal attributed to the token.
    pub principal: String,
    /// Granted scopes.
    pub scopes: BTreeSet<String>,
}

/// Failure from an OAuth endpoint or access-token validation.
#[derive(Debug)]
pub enum OAuthError {
    /// The request parameters are missing or malformed.
    InvalidRequest(String),
    /// Client authentication failed or the client is unknown.
    InvalidClient,
    /// The grant or code is invalid, expired, or replayed.
    InvalidGrant(String),
    /// A requested scope is unknown or exceeds the grant.
    InvalidScope(String),
    /// The grant type is not implemented.
    UnsupportedGrantType,
    /// Durable state could not be read or written.
    Server(anyhow::Error),
}

impl OAuthError {
    /// HTTP status for this failure.
    pub fn status(&self) -> axum::http::StatusCode {
        use axum::http::StatusCode;

        match self {
            Self::InvalidClient => StatusCode::UNAUTHORIZED,
            Self::Server(_) => StatusCode::INTERNAL_SERVER_ERROR,
            _ => StatusCode::BAD_REQUEST,
        }
    }

    /// OAuth error code returned in the JSON body.
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidRequest(_) => "invalid_request",
            Self::InvalidClient => "invalid_client",
            Self::InvalidGrant(_) => "invalid_grant",
            Self::InvalidScope(_) => "invalid_scope",
            Self::UnsupportedGrantType => "unsupported_grant_type",
            Self::Server(_) => "server_error",
        }
    }

    /// Safe human-readable description. Server errors are intentionally opaque.
    pub fn description(&self) -> String {
        match self {
            Self::InvalidRequest(message)
            | Self::InvalidGrant(message)
            | Self::InvalidScope(message) => message.clone(),
            Self::InvalidClient => "client authentication failed".into(),
            Self::UnsupportedGrantType => "unsupported grant type".into(),
            Self::Server(_) => "the authorization server could not complete the request".into(),
        }
    }

    /// JSON error document.
    pub fn body(&self) -> Value {
        json!({
            "error": self.code(),
            "error_description": self.description(),
        })
    }
}

impl From<anyhow::Error> for OAuthError {
    fn from(error: anyhow::Error) -> Self {
        Self::Server(error)
    }
}

/// Query/form parameters accepted by `GET` and `POST /oauth/authorize`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct AuthorizationParams {
    #[serde(default)]
    pub response_type: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub redirect_uri: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub resource: Option<String>,
    #[serde(default)]
    pub code_challenge: Option<String>,
    #[serde(default)]
    pub code_challenge_method: Option<String>,
    #[serde(default)]
    pub csrf_token: Option<String>,
    #[serde(default)]
    pub admin_secret: Option<String>,
    #[serde(default)]
    pub decision: Option<String>,
}

/// A validated authorization request presented on the consent page.
#[derive(Debug, Clone)]
pub struct AuthorizedRequest {
    /// Registered client id.
    pub client_id: String,
    /// Principal the resulting token will carry.
    pub principal: String,
    /// Exact registered redirect URI.
    pub redirect_uri: Url,
    /// Exact redirect URI string as registered.
    pub redirect_uri_raw: String,
    /// Granted scopes.
    pub scopes: Vec<String>,
    /// Opaque state echoed on the final redirect.
    pub state: Option<String>,
    /// Optional RFC 8707 resource indicator.
    pub resource: Option<String>,
    /// S256 challenge.
    pub code_challenge: String,
}

impl AuthorizedRequest {
    /// Space-delimited scope string.
    pub fn scope_string(&self) -> String {
        self.scopes.join(" ")
    }
}

/// Form parameters accepted by `POST /oauth/token`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct TokenParams {
    #[serde(default)]
    pub grant_type: Option<String>,
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub redirect_uri: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub code_verifier: Option<String>,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
}

/// Form parameters accepted by `POST /oauth/revoke`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RevokeParams {
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub token_type_hint: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
}

/// Client authentication material collected from Basic auth or the form body.
#[derive(Debug, Clone, Default)]
pub struct ClientAuthentication {
    /// Decoded `(client_id, client_secret)` Basic credential.
    pub basic: Option<(String, String)>,
    /// `client_id` submitted in the form body.
    pub form_client_id: Option<String>,
    /// `client_secret` submitted in the form body.
    pub form_client_secret: Option<String>,
}

impl ClientAuthentication {
    /// Parse an `Authorization: Basic ...` header.
    pub fn from_headers(headers: &HeaderMap) -> Result<Self, OAuthError> {
        let Some(value) = headers.get(header::AUTHORIZATION) else {
            return Ok(Self::default());
        };
        let value = value.to_str().map_err(|_| OAuthError::InvalidClient)?;
        let (scheme, encoded) = value.split_once(' ').ok_or(OAuthError::InvalidClient)?;
        if !scheme.eq_ignore_ascii_case("basic") {
            return Err(OAuthError::InvalidClient);
        }
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| OAuthError::InvalidClient)?;
        let decoded = String::from_utf8(decoded).map_err(|_| OAuthError::InvalidClient)?;
        let (client_id, client_secret) =
            decoded.split_once(':').ok_or(OAuthError::InvalidClient)?;
        if client_id.is_empty() {
            return Err(OAuthError::InvalidClient);
        }
        Ok(Self {
            basic: Some((client_id.to_string(), client_secret.to_string())),
            ..Self::default()
        })
    }
}

/// Successful token response.
#[derive(Debug, Clone, Serialize)]
pub struct TokenResponse {
    /// Bearer access token.
    pub access_token: String,
    /// Always `Bearer`.
    pub token_type: &'static str,
    /// Access-token lifetime in seconds.
    pub expires_in: u64,
    /// Rotating refresh token.
    pub refresh_token: String,
    /// Granted scope.
    pub scope: String,
}

#[derive(Debug, Clone)]
struct OAuthClient {
    client_id: String,
    client_secret: Option<SecretString>,
    redirect_uris: Vec<String>,
    scopes: Vec<String>,
    principal: String,
}

/// OAuth 2.1 service: configuration, secrets, grants, and token validation.
#[derive(Clone)]
pub struct OAuthService {
    issuer: String,
    store: OAuthStore,
    admin_secret: SecretString,
    clients: BTreeMap<String, OAuthClient>,
    access_token_ttl_secs: u64,
    refresh_token_ttl_secs: u64,
    authorization_code_ttl_secs: u64,
}

impl std::fmt::Debug for OAuthService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthService")
            .field("issuer", &self.issuer)
            .field("clients", &self.clients.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl OAuthService {
    /// Build the service, reading the administrator and client secrets from the
    /// environment. Returns `None` when OAuth is disabled.
    pub fn from_config(config: &OAuthConfig, repo: Arc<Repository>) -> Result<Option<Self>> {
        if !config.enabled {
            return Ok(None);
        }
        let issuer = config
            .issuer
            .as_deref()
            .context("oauth.issuer is required when oauth.enabled is true")?
            .trim_end_matches('/')
            .to_string();
        if issuer.is_empty() {
            bail!("oauth.issuer must not be empty");
        }
        let admin_variable = config
            .admin_secret_env
            .as_deref()
            .context("oauth.admin_secret_env is required when oauth.enabled is true")?;
        let admin_secret = read_secret(admin_variable, "OAuth administrator")?;

        let mut clients = BTreeMap::new();
        for client in &config.clients {
            let runtime = client_from_config(client)?;
            if clients.insert(runtime.client_id.clone(), runtime).is_some() {
                bail!(
                    "oauth client_id `{}` is registered more than once",
                    client.client_id
                );
            }
        }
        if clients.is_empty() {
            bail!("oauth.clients must contain at least one client when oauth.enabled is true");
        }

        Ok(Some(Self {
            issuer,
            store: OAuthStore::new(repo),
            admin_secret,
            clients,
            access_token_ttl_secs: config.access_token_ttl_secs,
            refresh_token_ttl_secs: config.refresh_token_ttl_secs,
            authorization_code_ttl_secs: config.authorization_code_ttl_secs,
        }))
    }

    /// Normalized issuer identifier (no trailing slash).
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// RFC 9728 protected-resource metadata document.
    pub fn protected_resource_metadata(&self) -> Value {
        json!({
            "resource": self.issuer,
            "authorization_servers": [self.issuer],
            "scopes_supported": ALL_SCOPES,
            "bearer_methods_supported": ["header"],
        })
    }

    /// RFC 8414 authorization-server metadata document.
    pub fn authorization_server_metadata(&self) -> Value {
        json!({
            "issuer": self.issuer,
            "authorization_endpoint": self.endpoint("/oauth/authorize"),
            "token_endpoint": self.endpoint("/oauth/token"),
            "revocation_endpoint": self.endpoint("/oauth/revoke"),
            "response_types_supported": ["code"],
            "response_modes_supported": ["query"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "client_secret_post",
                "none"
            ],
            "revocation_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "client_secret_post",
                "none"
            ],
            "scopes_supported": ALL_SCOPES,
        })
    }

    /// URL advertised in `WWW-Authenticate: Bearer`.
    pub fn protected_resource_metadata_url(&self) -> String {
        self.endpoint("/.well-known/oauth-protected-resource")
    }

    fn endpoint(&self, path: &str) -> String {
        format!("{}{path}", self.issuer)
    }

    /// Generate an unguessable double-submit token.
    pub fn new_csrf_token() -> String {
        random_token("csrf_")
    }

    /// `Set-Cookie` value for the double-submit token.
    pub fn csrf_cookie(&self, token: &str) -> String {
        let secure = if self.issuer.starts_with("https://") {
            "; Secure"
        } else {
            ""
        };
        format!(
            "{CSRF_COOKIE}={token}; HttpOnly; SameSite=Lax; Path=/oauth/authorize; Max-Age=600{secure}"
        )
    }

    /// Extract the double-submit cookie from request headers.
    pub fn csrf_cookie_value(headers: &HeaderMap) -> Option<String> {
        let header = headers.get(header::COOKIE)?.to_str().ok()?;
        for part in header.split(';') {
            let Some((name, value)) = part.trim().split_once('=') else {
                continue;
            };
            if name.trim() == CSRF_COOKIE {
                let value = value.trim().trim_matches('"');
                if !value.is_empty() {
                    return Some(value.to_string());
                }
            }
        }
        None
    }

    /// Constant-time double-submit check.
    pub fn verify_csrf(&self, headers: &HeaderMap, form_token: Option<&str>) -> bool {
        let Some(cookie) = Self::csrf_cookie_value(headers) else {
            return false;
        };
        let Some(form_token) = form_token else {
            return false;
        };
        !form_token.is_empty() && constant_time_eq(cookie.as_bytes(), form_token.as_bytes())
    }

    /// Constant-time administrator-secret check.
    pub fn verify_admin_secret(&self, presented: Option<&str>) -> bool {
        let Some(presented) = presented else {
            return false;
        };
        !presented.is_empty()
            && constant_time_eq(
                presented.as_bytes(),
                self.admin_secret.expose_secret().as_bytes(),
            )
    }

    /// Validate an authorization request before showing the consent page.
    pub fn validate_authorization(
        &self,
        params: &AuthorizationParams,
    ) -> Result<AuthorizedRequest, OAuthError> {
        if params.response_type.as_deref() != Some("code") {
            return Err(OAuthError::InvalidRequest(
                "response_type must be `code`".into(),
            ));
        }
        let client_id = required(params.client_id.as_deref(), "client_id")?;
        let client = self
            .clients
            .get(client_id)
            .ok_or_else(|| OAuthError::InvalidRequest("unknown client_id".into()))?;
        let redirect_raw = required(params.redirect_uri.as_deref(), "redirect_uri")?;
        if !client
            .redirect_uris
            .iter()
            .any(|registered| registered == redirect_raw)
        {
            return Err(OAuthError::InvalidRequest(
                "redirect_uri is not registered for this client".into(),
            ));
        }
        let redirect_uri = Url::parse(redirect_raw)
            .map_err(|_| OAuthError::InvalidRequest("redirect_uri is not a URL".into()))?;

        if params.code_challenge_method.as_deref() != Some("S256") {
            return Err(OAuthError::InvalidRequest(
                "code_challenge_method must be `S256`".into(),
            ));
        }
        let code_challenge = required(params.code_challenge.as_deref(), "code_challenge")?;
        if !valid_s256_challenge(code_challenge) {
            return Err(OAuthError::InvalidRequest(
                "code_challenge must be a 43-character base64url S256 digest".into(),
            ));
        }
        let scopes = resolve_scopes(params.scope.as_deref(), &client.scopes)?;
        let state = optional_bounded(params.state.as_deref(), "state")?;
        let resource = optional_bounded(params.resource.as_deref(), "resource")?;
        if resource.is_some_and(|value| Url::parse(value).is_err()) {
            return Err(OAuthError::InvalidRequest(
                "resource must be an absolute URI".into(),
            ));
        }

        Ok(AuthorizedRequest {
            client_id: client.client_id.clone(),
            principal: client.principal.clone(),
            redirect_uri,
            redirect_uri_raw: redirect_raw.to_string(),
            scopes,
            state: state.map(ToOwned::to_owned),
            resource: resource.map(ToOwned::to_owned),
            code_challenge: code_challenge.to_string(),
        })
    }

    /// Render the consent page. Every dynamic value is HTML-escaped.
    pub fn render_consent(&self, request: &AuthorizedRequest, csrf_token: &str) -> String {
        let hidden = |name: &str, value: &str| {
            format!(
                "<input type=\"hidden\" name=\"{}\" value=\"{}\">",
                escape_html(name),
                escape_html(value)
            )
        };
        let scope = request.scope_string();
        format!(
            "<!doctype html>\n\
<html lang=\"en\">\n\
<head>\n\
<meta charset=\"utf-8\">\n\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
<title>Authorize {client}</title>\n\
<style>\n\
:root {{ color-scheme: light dark; font-family: system-ui, sans-serif; }}\n\
body {{ margin: 0; min-height: 100vh; display: grid; place-items: center; background: Canvas; color: CanvasText; }}\n\
main {{ width: min(34rem, calc(100% - 2rem)); padding: 1.5rem; border: 1px solid color-mix(in srgb, CanvasText 20%, transparent); border-radius: 0.75rem; }}\n\
code {{ overflow-wrap: anywhere; }}\n\
label {{ display: block; margin-top: 1rem; font-weight: 600; }}\n\
input[type=password] {{ width: 100%; box-sizing: border-box; margin-top: 0.35rem; padding: 0.5rem; }}\n\
.actions {{ display: flex; gap: 0.75rem; margin-top: 1.25rem; }}\n\
button {{ padding: 0.6rem 1rem; border-radius: 0.4rem; border: 1px solid color-mix(in srgb, CanvasText 30%, transparent); cursor: pointer; }}\n\
button[value=approve] {{ background: #0969da; color: white; border-color: #0969da; }}\n\
</style>\n\
</head>\n\
<body>\n\
<main>\n\
<h1>Authorize {client}</h1>\n\
<p><strong>{client}</strong> is requesting access as principal <code>{principal}</code>.</p>\n\
<p>Redirect URI:<br><code>{redirect}</code></p>\n\
<p>Requested scopes:<br><code>{scope}</code></p>\n\
<form method=\"post\" action=\"/oauth/authorize\">\n\
{response_type}{client_field}{redirect_field}{scope_field}{state_field}{resource_field}{challenge_field}{method_field}{csrf_field}\n\
<label for=\"admin-secret\">Administrator approval secret</label>\n\
<input id=\"admin-secret\" type=\"password\" name=\"{admin_field}\" autocomplete=\"current-password\" required>\n\
<div class=\"actions\">\n\
<button type=\"submit\" name=\"{decision_field}\" value=\"approve\">Approve</button>\n\
<button type=\"submit\" name=\"{decision_field}\" value=\"deny\">Deny</button>\n\
</div>\n\
</form>\n\
</main>\n\
</body>\n\
</html>\n",
            client = escape_html(&request.client_id),
            principal = escape_html(&request.principal),
            redirect = escape_html(request.redirect_uri.as_str()),
            scope = escape_html(&scope),
            response_type = hidden("response_type", "code"),
            client_field = hidden("client_id", &request.client_id),
            redirect_field = hidden("redirect_uri", &request.redirect_uri_raw),
            scope_field = if scope.is_empty() {
                String::new()
            } else {
                hidden("scope", &scope)
            },
            state_field = hidden("state", request.state.as_deref().unwrap_or_default()),
            resource_field = hidden("resource", request.resource.as_deref().unwrap_or_default()),
            challenge_field = hidden("code_challenge", &request.code_challenge),
            method_field = hidden("code_challenge_method", "S256"),
            csrf_field = hidden(CSRF_FIELD, csrf_token),
            admin_field = ADMIN_SECRET_FIELD,
            decision_field = DECISION_FIELD,
        )
    }

    /// Build an approval redirect containing a fresh authorization code.
    pub fn approve_redirect(&self, request: &AuthorizedRequest) -> Result<Url, OAuthError> {
        let code = self.issue_authorization_code(request)?;
        let mut url = request.redirect_uri.clone();
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("code", &code);
            if let Some(state) = request.state.as_deref() {
                query.append_pair("state", state);
            }
        }
        Ok(url)
    }

    /// Build a denial redirect. This is only called after the client and
    /// redirect URI have both been validated.
    pub fn deny_redirect(&self, request: &AuthorizedRequest) -> Url {
        let mut url = request.redirect_uri.clone();
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("error", "access_denied");
            if let Some(state) = request.state.as_deref() {
                query.append_pair("state", state);
            }
        }
        url
    }

    fn issue_authorization_code(&self, request: &AuthorizedRequest) -> Result<String, OAuthError> {
        let code = random_token("ebc_");
        let now = now_rfc3339();
        let expires_at = expiry(Utc::now(), self.authorization_code_ttl_secs);
        let code_hash = hash_secret(&code);
        let family_id = format!("fam_{}", random_token(""));
        self.store
            .insert_authorization_code(&NewAuthorizationCode {
                code_hash,
                client_id: request.client_id.clone(),
                principal: request.principal.clone(),
                redirect_uri: request.redirect_uri_raw.clone(),
                scopes: request.scopes.clone(),
                code_challenge: request.code_challenge.clone(),
                resource: request.resource.clone(),
                family_id,
                created_at: now,
                expires_at,
            })
            .map_err(OAuthError::Server)?;
        Ok(code)
    }

    /// Exchange an authorization code for an access/refresh token pair.
    pub fn exchange_authorization_code(
        &self,
        params: &TokenParams,
        authentication: &ClientAuthentication,
    ) -> Result<TokenResponse, OAuthError> {
        let client = self.authenticate_client(authentication)?;
        let code = required(params.code.as_deref(), "code")?;
        let redirect_uri = required(params.redirect_uri.as_deref(), "redirect_uri")?;
        let verifier = required(params.code_verifier.as_deref(), "code_verifier")?;
        if !valid_code_verifier(verifier) {
            return Err(OAuthError::InvalidGrant(
                "code_verifier is malformed".into(),
            ));
        }

        let code_hash = hash_secret(code);
        let record = self
            .store
            .authorization_code(&code_hash)
            .map_err(OAuthError::Server)?
            .ok_or_else(|| OAuthError::InvalidGrant("authorization code is invalid".into()))?;
        if record.client_id != client.client_id {
            return Err(OAuthError::InvalidGrant(
                "authorization code was not issued to this client".into(),
            ));
        }
        if record.redirect_uri != redirect_uri {
            return Err(OAuthError::InvalidGrant(
                "redirect_uri does not match the authorization request".into(),
            ));
        }
        if record.used_at.is_some() {
            self.store
                .revoke_code_family(&code_hash, &now_rfc3339())
                .map_err(OAuthError::Server)?;
            return Err(OAuthError::InvalidGrant(
                "authorization code has already been used".into(),
            ));
        }
        let computed = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        if !constant_time_eq(computed.as_bytes(), record.code_challenge.as_bytes()) {
            return Err(OAuthError::InvalidGrant("PKCE verification failed".into()));
        }

        let now = now_rfc3339();
        let (refresh_raw, access, refresh) = self.token_material(
            &record.family_id,
            &code_hash,
            &record.client_id,
            &record.principal,
            &record.scopes,
            &now,
        );
        let access_raw = random_token("eba_");
        let access_record = NewAccessToken {
            token_hash: hash_secret(&access_raw),
            ..access
        };
        let outcome = self
            .store
            .consume_authorization_code(&code_hash, &now, &access_record, &refresh)
            .map_err(OAuthError::Server)?;
        match outcome {
            ConsumeCodeOutcome::Issued => {}
            ConsumeCodeOutcome::Replayed { .. } => {
                return Err(OAuthError::InvalidGrant(
                    "authorization code has already been used".into(),
                ));
            }
            ConsumeCodeOutcome::Expired => {
                return Err(OAuthError::InvalidGrant(
                    "authorization code has expired".into(),
                ));
            }
            ConsumeCodeOutcome::NotFound => {
                return Err(OAuthError::InvalidGrant(
                    "authorization code is invalid".into(),
                ));
            }
        }

        Ok(TokenResponse {
            access_token: access_raw,
            token_type: "Bearer",
            expires_in: self.access_token_ttl_secs,
            refresh_token: refresh_raw,
            scope: record.scopes.join(" "),
        })
    }

    /// Rotate a refresh token, optionally reducing its scopes.
    pub fn refresh_token(
        &self,
        params: &TokenParams,
        authentication: &ClientAuthentication,
    ) -> Result<TokenResponse, OAuthError> {
        let client = self.authenticate_client(authentication)?;
        let refresh_token = required(params.refresh_token.as_deref(), "refresh_token")?;
        let refresh_hash = hash_secret(refresh_token);
        let record = self
            .store
            .refresh_token(&refresh_hash)
            .map_err(OAuthError::Server)?
            .ok_or_else(|| OAuthError::InvalidGrant("refresh token is invalid".into()))?;
        if record.client_id != client.client_id {
            return Err(OAuthError::InvalidGrant(
                "refresh token was not issued to this client".into(),
            ));
        }
        if record.used_at.is_some() || record.revoked_at.is_some() {
            self.store
                .revoke_refresh_family(&refresh_hash, &client.client_id, &now_rfc3339())
                .map_err(OAuthError::Server)?;
            return Err(OAuthError::InvalidGrant(
                "refresh token reuse detected; the token family was revoked".into(),
            ));
        }

        let scopes = match params.scope.as_deref() {
            None => record.scopes.clone(),
            Some(value) => {
                let requested = parse_scope_list(value)?;
                if requested.is_empty()
                    || !requested.iter().all(|scope| record.scopes.contains(scope))
                {
                    return Err(OAuthError::InvalidScope(
                        "requested scope exceeds the original grant".into(),
                    ));
                }
                requested
            }
        };

        let now = now_rfc3339();
        let (new_refresh_raw, access, refresh) = self.token_material(
            &record.family_id,
            &record.authorization_code_hash,
            &record.client_id,
            &record.principal,
            &scopes,
            &now,
        );
        let access_raw = random_token("eba_");
        let access_record = NewAccessToken {
            token_hash: hash_secret(&access_raw),
            ..access
        };
        let refresh = NewRefreshToken {
            rotated_from_hash: Some(refresh_hash.clone()),
            ..refresh
        };
        let outcome = self
            .store
            .rotate_refresh_token(&refresh_hash, &now, &access_record, &refresh)
            .map_err(OAuthError::Server)?;
        match outcome {
            RotateRefreshOutcome::Rotated => {}
            RotateRefreshOutcome::Replayed { .. } => {
                return Err(OAuthError::InvalidGrant(
                    "refresh token reuse detected; the token family was revoked".into(),
                ));
            }
            RotateRefreshOutcome::Expired => {
                return Err(OAuthError::InvalidGrant("refresh token has expired".into()));
            }
            RotateRefreshOutcome::NotFound => {
                return Err(OAuthError::InvalidGrant("refresh token is invalid".into()));
            }
        }

        Ok(TokenResponse {
            access_token: access_raw,
            token_type: "Bearer",
            expires_in: self.access_token_ttl_secs,
            refresh_token: new_refresh_raw,
            scope: scopes.join(" "),
        })
    }

    /// Revoke a token. Unknown tokens and tokens owned by another client are
    /// intentionally indistinguishable from a successful no-op.
    pub fn revoke(
        &self,
        params: &RevokeParams,
        authentication: &ClientAuthentication,
    ) -> Result<(), OAuthError> {
        let client = self.authenticate_client(authentication)?;
        let token = required(params.token.as_deref(), "token")?;
        let token_hash = hash_secret(token);
        let now = now_rfc3339();

        let prefer_refresh = params.token_type_hint.as_deref() == Some("refresh_token");
        if prefer_refresh {
            self.store
                .revoke_refresh_family(&token_hash, &client.client_id, &now)
                .map_err(OAuthError::Server)?;
            self.store
                .revoke_access_token(&token_hash, &client.client_id, &now)
                .map_err(OAuthError::Server)?;
        } else {
            self.store
                .revoke_access_token(&token_hash, &client.client_id, &now)
                .map_err(OAuthError::Server)?;
            self.store
                .revoke_refresh_family(&token_hash, &client.client_id, &now)
                .map_err(OAuthError::Server)?;
        }
        Ok(())
    }

    /// Validate an OAuth bearer access token.
    pub fn authenticate_access_token(&self, token: &str) -> Result<OAuthIdentity, OAuthError> {
        if token.is_empty() {
            return Err(OAuthError::InvalidGrant("access token is missing".into()));
        }
        let record = self
            .store
            .access_token(&hash_secret(token))
            .map_err(OAuthError::Server)?
            .ok_or_else(|| OAuthError::InvalidGrant("access token is invalid".into()))?;
        if record.revoked_at.is_some() || record.expires_at <= now_rfc3339() {
            return Err(OAuthError::InvalidGrant(
                "access token is expired or revoked".into(),
            ));
        }
        if !self.clients.contains_key(&record.client_id) {
            return Err(OAuthError::InvalidGrant(
                "access token client is no longer registered".into(),
            ));
        }
        Ok(OAuthIdentity {
            client_id: record.client_id,
            principal: record.principal,
            scopes: record.scopes.into_iter().collect(),
        })
    }

    fn authenticate_client(
        &self,
        authentication: &ClientAuthentication,
    ) -> Result<&OAuthClient, OAuthError> {
        if authentication.basic.is_some() && authentication.form_client_secret.is_some() {
            return Err(OAuthError::InvalidRequest(
                "multiple client authentication methods were supplied".into(),
            ));
        }
        let (client_id, presented_secret) = match &authentication.basic {
            Some((client_id, secret)) => (client_id.as_str(), Some(secret.as_str())),
            None => (
                authentication
                    .form_client_id
                    .as_deref()
                    .ok_or(OAuthError::InvalidClient)?,
                authentication.form_client_secret.as_deref(),
            ),
        };
        if let Some(form_id) = authentication.form_client_id.as_deref()
            && form_id != client_id
        {
            return Err(OAuthError::InvalidClient);
        }
        let client = self
            .clients
            .get(client_id)
            .ok_or(OAuthError::InvalidClient)?;
        match (&client.client_secret, presented_secret) {
            (None, None) => Ok(client),
            (None, Some(_)) => Err(OAuthError::InvalidClient),
            (Some(expected), Some(presented)) => {
                if constant_time_eq(presented.as_bytes(), expected.expose_secret().as_bytes()) {
                    Ok(client)
                } else {
                    Err(OAuthError::InvalidClient)
                }
            }
            (Some(_), None) => Err(OAuthError::InvalidClient),
        }
    }

    #[allow(clippy::type_complexity)]
    fn token_material(
        &self,
        family_id: &str,
        code_hash: &str,
        client_id: &str,
        principal: &str,
        scopes: &[String],
        now: &str,
    ) -> (String, NewAccessToken, NewRefreshToken) {
        let instant = DateTime::parse_from_rfc3339(now)
            .map(|value| value.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());
        let access_expires_at = expiry(instant, self.access_token_ttl_secs);
        let refresh_expires_at = expiry(instant, self.refresh_token_ttl_secs);
        let refresh_raw = random_token("ebr_");
        let access = NewAccessToken {
            token_hash: String::new(),
            client_id: client_id.to_string(),
            principal: principal.to_string(),
            scopes: scopes.to_vec(),
            family_id: family_id.to_string(),
            authorization_code_hash: code_hash.to_string(),
            created_at: now.to_string(),
            expires_at: access_expires_at,
        };
        let refresh = NewRefreshToken {
            token_hash: hash_secret(&refresh_raw),
            client_id: client_id.to_string(),
            principal: principal.to_string(),
            scopes: scopes.to_vec(),
            family_id: family_id.to_string(),
            authorization_code_hash: code_hash.to_string(),
            rotated_from_hash: None,
            created_at: now.to_string(),
            expires_at: refresh_expires_at,
        };
        (refresh_raw, access, refresh)
    }
}

fn client_from_config(client: &OAuthClientConfig) -> Result<OAuthClient> {
    let secret = match client.client_secret_env.as_deref() {
        Some(variable) => Some(read_secret(variable, "OAuth client")?),
        None => None,
    };
    Ok(OAuthClient {
        client_id: client.client_id.clone(),
        client_secret: secret,
        redirect_uris: client.redirect_uris.clone(),
        scopes: client.scopes.clone(),
        principal: client
            .principal
            .clone()
            .unwrap_or_else(|| client.client_id.clone()),
    })
}

fn read_secret(variable: &str, purpose: &str) -> Result<SecretString> {
    let value = std::env::var(variable).with_context(|| {
        format!("{purpose} is configured but environment variable `{variable}` is unset")
    })?;
    if value.trim().is_empty() {
        bail!("environment variable `{variable}` is empty");
    }
    Ok(SecretString::from(value))
}

fn required<'a>(value: Option<&'a str>, name: &str) -> Result<&'a str, OAuthError> {
    value
        .filter(|value| !value.is_empty())
        .ok_or_else(|| OAuthError::InvalidRequest(format!("`{name}` is required")))
}

fn optional_bounded<'a>(value: Option<&'a str>, name: &str) -> Result<Option<&'a str>, OAuthError> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_empty() {
        return Ok(None);
    }
    if value.chars().count() > MAX_OPTIONAL_PARAM_LEN {
        return Err(OAuthError::InvalidRequest(format!(
            "`{name}` must be at most {MAX_OPTIONAL_PARAM_LEN} characters"
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(OAuthError::InvalidRequest(format!(
            "`{name}` must not contain control characters"
        )));
    }
    Ok(Some(value))
}

fn resolve_scopes(requested: Option<&str>, allowed: &[String]) -> Result<Vec<String>, OAuthError> {
    let scopes = match requested {
        None => allowed.to_vec(),
        Some(value) => parse_scope_list(value)?,
    };
    if scopes.iter().any(|scope| !allowed.contains(scope)) {
        return Err(OAuthError::InvalidScope(
            "requested scope is not registered for this client".into(),
        ));
    }
    Ok(scopes)
}

fn parse_scope_list(value: &str) -> Result<Vec<String>, OAuthError> {
    if value.trim().is_empty() {
        return Err(OAuthError::InvalidScope("scope must not be empty".into()));
    }
    let mut scopes = Vec::new();
    for scope in value.split_whitespace() {
        if !ALL_SCOPES.contains(&scope) {
            return Err(OAuthError::InvalidScope(format!(
                "unsupported scope `{scope}`"
            )));
        }
        if !scopes.iter().any(|existing| existing == scope) {
            scopes.push(scope.to_string());
        }
    }
    Ok(scopes)
}

fn valid_s256_challenge(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn valid_code_verifier(value: &str) -> bool {
    (43..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
}

fn random_token(prefix: &str) -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    format!("{prefix}{}", hex::encode(bytes))
}

/// SHA-256 hex digest used for every stored secret.
pub fn hash_secret(secret: &str) -> String {
    hex::encode(Sha256::digest(secret.as_bytes()))
}

fn expiry(now: DateTime<Utc>, seconds: u64) -> String {
    let seconds = seconds.min(i64::MAX as u64) as i64;
    let delta = ChronoDuration::try_seconds(seconds).unwrap_or(ChronoDuration::MAX);
    now.checked_add_signed(delta)
        .unwrap_or(now)
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// Escape a value for HTML text or a quoted attribute.
pub fn escape_html(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            other => escaped.push(other),
        }
    }
    escaped
}

/// Build an authorization redirect URL with an error code.
pub fn redirect_with_error(uri: &Url, error: &str, state: Option<&str>) -> Url {
    let mut url = uri.clone();
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("error", error);
        if let Some(state) = state {
            query.append_pair("state", state);
        }
    }
    url
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> OAuthConfig {
        OAuthConfig {
            enabled: true,
            issuer: Some("https://issuer.example.com".into()),
            admin_secret_env: None,
            access_token_ttl_secs: 3600,
            refresh_token_ttl_secs: 86_400,
            authorization_code_ttl_secs: 300,
            clients: vec![OAuthClientConfig {
                client_id: "client-a".into(),
                client_secret_env: None,
                redirect_uris: vec!["https://client.example/callback".into()],
                scopes: vec![SCOPE_EVENTS_READ.into(), SCOPE_EVENTS_ACK.into()],
                principal: Some("alice".into()),
            }],
        }
    }

    fn service() -> OAuthService {
        let mut config = config();
        // Tests bypass environment loading so they do not mutate the process
        // environment and can run in parallel with other test binaries.
        let admin_secret = SecretString::from(crate::util::random_hex(16));
        let clients = config
            .clients
            .drain(..)
            .map(|client| {
                let runtime = OAuthClient {
                    client_id: client.client_id,
                    client_secret: None,
                    redirect_uris: client.redirect_uris,
                    scopes: client.scopes,
                    principal: client.principal.unwrap_or_default(),
                };
                (runtime.client_id.clone(), runtime)
            })
            .collect();
        OAuthService {
            issuer: config.issuer.clone().unwrap().trim_end_matches('/').into(),
            store: OAuthStore::new(Arc::new(Repository::open_in_memory().unwrap())),
            admin_secret,
            clients,
            access_token_ttl_secs: 3600,
            refresh_token_ttl_secs: 86_400,
            authorization_code_ttl_secs: 300,
        }
    }

    fn verifier() -> String {
        "a".repeat(64)
    }

    fn challenge(verifier: &str) -> String {
        URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
    }

    fn auth_params(challenge: &str) -> AuthorizationParams {
        AuthorizationParams {
            response_type: Some("code".into()),
            client_id: Some("client-a".into()),
            redirect_uri: Some("https://client.example/callback".into()),
            scope: Some(SCOPE_EVENTS_READ.into()),
            state: Some("state-1".into()),
            code_challenge: Some(challenge.into()),
            code_challenge_method: Some("S256".into()),
            ..AuthorizationParams::default()
        }
    }

    #[test]
    fn metadata_advertises_s256_and_scopes() {
        let service = service();
        let metadata = service.authorization_server_metadata();
        assert_eq!(metadata["issuer"], "https://issuer.example.com");
        assert_eq!(
            metadata["token_endpoint"],
            "https://issuer.example.com/oauth/token"
        );
        assert_eq!(metadata["code_challenge_methods_supported"][0], "S256");
        assert_eq!(metadata["scopes_supported"][0], SCOPE_EVENTS_READ);
        let resource = service.protected_resource_metadata();
        assert_eq!(resource["resource"], "https://issuer.example.com");
        assert_eq!(
            resource["authorization_servers"][0],
            "https://issuer.example.com"
        );
    }

    #[test]
    fn pkce_validation_rejects_plain_and_bad_verifiers() {
        let service = service();
        let mut params = auth_params(&challenge(&verifier()));
        params.code_challenge_method = Some("plain".into());
        assert!(matches!(
            service.validate_authorization(&params),
            Err(OAuthError::InvalidRequest(_))
        ));
        params.code_challenge_method = Some("S256".into());
        params.code_challenge = Some("short".into());
        assert!(matches!(
            service.validate_authorization(&params),
            Err(OAuthError::InvalidRequest(_))
        ));
        assert!(!valid_code_verifier("short"));
        assert!(!valid_code_verifier(&"a".repeat(129)));
        assert!(valid_code_verifier(&"a".repeat(43)));
        assert!(valid_code_verifier(&"a".repeat(128)));
    }

    #[test]
    fn authorization_code_flow_is_pkce_bound_and_replay_revokes_family() {
        let service = service();
        let verifier = verifier();
        let request = service
            .validate_authorization(&auth_params(&challenge(&verifier)))
            .unwrap();
        let code = service.issue_authorization_code(&request).unwrap();
        let auth = ClientAuthentication {
            form_client_id: Some("client-a".into()),
            ..ClientAuthentication::default()
        };
        let params = TokenParams {
            grant_type: Some("authorization_code".into()),
            code: Some(code.clone()),
            redirect_uri: Some("https://client.example/callback".into()),
            code_verifier: Some(verifier.clone()),
            ..TokenParams::default()
        };
        let token = service.exchange_authorization_code(&params, &auth).unwrap();
        assert_eq!(token.scope, SCOPE_EVENTS_READ);
        let identity = service
            .authenticate_access_token(&token.access_token)
            .unwrap();
        assert_eq!(identity.principal, "alice");
        assert!(identity.scopes.contains(SCOPE_EVENTS_READ));

        let replay = service.exchange_authorization_code(&params, &auth);
        assert!(matches!(replay, Err(OAuthError::InvalidGrant(_))));
        assert!(
            service
                .authenticate_access_token(&token.access_token)
                .is_err()
        );
        let refresh = TokenParams {
            grant_type: Some("refresh_token".into()),
            refresh_token: Some(token.refresh_token.clone()),
            ..TokenParams::default()
        };
        assert!(matches!(
            service.refresh_token(&refresh, &auth),
            Err(OAuthError::InvalidGrant(_))
        ));
    }

    #[test]
    fn redirect_uri_must_match_exactly() {
        let service = service();
        let mut params = auth_params(&challenge(&verifier()));
        params.redirect_uri = Some("https://client.example/other".into());
        assert!(matches!(
            service.validate_authorization(&params),
            Err(OAuthError::InvalidRequest(_))
        ));
    }

    #[test]
    fn consent_html_escapes_every_dynamic_value() {
        let service = service();
        let mut params = auth_params(&challenge(&verifier()));
        params.state = Some("</script><script>alert(1)</script>".into());
        params.redirect_uri = Some("https://client.example/callback".into());
        let request = service.validate_authorization(&params).unwrap();
        let html = service.render_consent(&request, "csrf-value");
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;/script&gt;"));
        assert!(!html.contains("HttpOnly"));
        assert_eq!(escape_html("\"'&<>"), "&quot;&#39;&amp;&lt;&gt;");
    }

    #[test]
    fn admin_secret_and_csrf_checks_are_constant_time_and_strict() {
        let service = service();
        let admin_secret = service.admin_secret.expose_secret().to_string();
        assert!(service.verify_admin_secret(Some(&admin_secret)));
        assert!(!service.verify_admin_secret(Some(&admin_secret[..admin_secret.len() - 1])));
        assert!(!service.verify_admin_secret(None));
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            "a=b; oauth_csrf=csrf-value; c=d".parse().unwrap(),
        );
        assert!(service.verify_csrf(&headers, Some("csrf-value")));
        assert!(!service.verify_csrf(&headers, Some("other")));
        assert!(!service.verify_csrf(&HeaderMap::new(), Some("csrf-value")));
    }

    #[test]
    fn scope_mapping_covers_http_and_pull_tools() {
        assert_eq!(
            required_scope_for_tool("list_events"),
            Some(SCOPE_EVENTS_READ)
        );
        assert_eq!(
            required_scope_for_tool("ack_events"),
            Some(SCOPE_EVENTS_ACK)
        );
        assert_eq!(
            required_scope_for_tool("ack_consumer_events"),
            Some(SCOPE_EVENTS_ACK)
        );
        assert_eq!(required_scope_for_tool("not_a_tool"), None);
        assert_eq!(
            required_scope_for_method("events/list"),
            Some(SCOPE_EVENTS_READ)
        );
        assert_eq!(
            required_scope_for_method("events/subscribe"),
            Some(SCOPE_EVENTS_SUBSCRIBE)
        );
    }
}
