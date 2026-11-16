//! End-to-end OAuth 2.1 authorization-server and scope-enforcement tests.
//!
//! Secrets are generated at runtime and placed in uniquely named environment
//! variables. No realistic credential literal is stored in the repository.

use std::{sync::Arc, time::Duration};

use base64::Engine as _;
use events_bridge::{
    config::Config,
    delivery::verification::CallbackPolicy,
    hub::Hub,
    oauth::{
        ADMIN_SECRET_FIELD, CSRF_COOKIE, CSRF_FIELD, DECISION_FIELD, SCOPE_EVENTS_ACK,
        SCOPE_EVENTS_READ, hash_secret,
    },
    store::NewEvent,
};
use reqwest::{Client, StatusCode, redirect::Policy};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::task::JoinHandle;
use url::Url;
use uuid::Uuid;

const TOKEN_PATH: &str = "/oauth/token";
const AUTHORIZE_PATH: &str = "/oauth/authorize";
const CONFIDENTIAL_REDIRECT: &str = "https://client.example/callback";
const PUBLIC_REDIRECT: &str = "http://127.0.0.1:9999/callback";

struct EnvGuard {
    names: Vec<String>,
}

impl EnvGuard {
    fn set(prefix: &str, value: &str) -> (String, Self) {
        let name = format!("EVENTS_BRIDGE_TEST_{}_{}", prefix, Uuid::new_v4().simple());
        // SAFETY: the name is unique to this test and no other thread reads it.
        unsafe { std::env::set_var(&name, value) };
        (name.clone(), Self { names: vec![name] })
    }

    fn merge(mut self, mut other: Self) -> Self {
        self.names.append(&mut other.names);
        self
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for name in &self.names {
            // SAFETY: the variable is owned by this test fixture.
            unsafe { std::env::remove_var(name) };
        }
    }
}

struct OAuthFixture {
    hub: Arc<Hub>,
    base_url: String,
    server: JoinHandle<()>,
    http: Client,
    admin_secret: String,
    confidential_secret: String,
    static_token: Option<String>,
    _temp: TempDir,
    _env: EnvGuard,
}

impl OAuthFixture {
    async fn start() -> Self {
        let temp = TempDir::new().unwrap();
        let admin_secret = Uuid::new_v4().to_string();
        let confidential_secret = Uuid::new_v4().to_string();
        let (admin_var, admin_env) = EnvGuard::set("OAUTH_ADMIN", &admin_secret);
        let (client_var, client_env) = EnvGuard::set("OAUTH_CLIENT", &confidential_secret);
        let env = admin_env.merge(client_env);
        let config = Config::parse(&format!(
            r#"
[server]
allowed_hosts = ["localhost", "127.0.0.1", "::1"]

[oauth]
enabled = true
issuer = "https://bridge.example.com"
admin_secret_env = "{admin_var}"
access_token_ttl_secs = 3600
refresh_token_ttl_secs = 3600
authorization_code_ttl_secs = 300

[[oauth.clients]]
client_id = "confidential"
client_secret_env = "{client_var}"
redirect_uris = ["{CONFIDENTIAL_REDIRECT}"]
scopes = ["events.read", "events.ack", "events.subscribe"]
principal = "alice"

[[oauth.clients]]
client_id = "public"
redirect_uris = ["{PUBLIC_REDIRECT}"]
scopes = ["events.read"]
principal = "bob"
"#
        ))
        .unwrap();
        Self::start_with_config(temp, config, env, admin_secret, confidential_secret).await
    }

    async fn start_with_static_token() -> Self {
        let temp = TempDir::new().unwrap();
        let admin_secret = Uuid::new_v4().to_string();
        let confidential_secret = Uuid::new_v4().to_string();
        let static_token = Uuid::new_v4().to_string();
        let (admin_var, admin_env) = EnvGuard::set("OAUTH_ADMIN", &admin_secret);
        let (client_var, client_env) = EnvGuard::set("OAUTH_CLIENT", &confidential_secret);
        let (static_var, static_env) = EnvGuard::set("STATIC_TOKEN", &static_token);
        let env = admin_env.merge(client_env).merge(static_env);
        let config = Config::parse(&format!(
            r#"
[auth]
token_env = "{static_var}"
principal = "legacy"

[oauth]
enabled = true
issuer = "https://bridge.example.com"
admin_secret_env = "{admin_var}"

[[oauth.clients]]
client_id = "confidential"
client_secret_env = "{client_var}"
redirect_uris = ["{CONFIDENTIAL_REDIRECT}"]
scopes = ["events.read"]
principal = "alice"
"#
        ))
        .unwrap();
        let mut fixture =
            Self::start_with_config(temp, config, env, admin_secret, confidential_secret).await;
        fixture.static_token = Some(static_token);
        fixture
    }

    async fn start_with_config(
        temp: TempDir,
        mut config: Config,
        env: EnvGuard,
        admin_secret: String,
        confidential_secret: String,
    ) -> Self {
        config.database.path = temp.path().join("oauth.db");
        let hub = Arc::new(
            Hub::with_policy(config, CallbackPolicy::for_tests()).expect("hub builds with OAuth"),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let router = hub.router();
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        let http = Client::builder()
            .redirect(Policy::none())
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        Self {
            hub,
            base_url: format!("http://{address}"),
            server,
            http,
            admin_secret,
            confidential_secret,
            static_token: None,
            _temp: temp,
            _env: env,
        }
    }

    async fn begin_authorize(
        &self,
        client_id: &str,
        redirect_uri: &str,
        scope: &str,
        state: &str,
        verifier: &str,
    ) -> reqwest::Response {
        self.http
            .get(format!("{}{AUTHORIZE_PATH}", self.base_url))
            .query(&[
                ("response_type", "code"),
                ("client_id", client_id),
                ("redirect_uri", redirect_uri),
                ("scope", scope),
                ("state", state),
                ("code_challenge", &pkce_challenge(verifier)),
                ("code_challenge_method", "S256"),
            ])
            .send()
            .await
            .unwrap()
    }

    #[allow(clippy::too_many_arguments)] // Mirrors the consent form fields under test.
    async fn approve(
        &self,
        client_id: &str,
        redirect_uri: &str,
        scope: &str,
        state: &str,
        verifier: &str,
        cookie: &str,
        csrf: &str,
        admin_secret: &str,
    ) -> reqwest::Response {
        let form = vec![
            ("response_type".to_string(), "code".to_string()),
            ("client_id".to_string(), client_id.to_string()),
            ("redirect_uri".to_string(), redirect_uri.to_string()),
            ("scope".to_string(), scope.to_string()),
            ("state".to_string(), state.to_string()),
            ("code_challenge".to_string(), pkce_challenge(verifier)),
            ("code_challenge_method".to_string(), "S256".to_string()),
            (CSRF_FIELD.to_string(), csrf.to_string()),
            (ADMIN_SECRET_FIELD.to_string(), admin_secret.to_string()),
            (DECISION_FIELD.to_string(), "approve".to_string()),
        ];
        self.http
            .post(format!("{}{AUTHORIZE_PATH}", self.base_url))
            .header(reqwest::header::COOKIE, cookie)
            .form(&form)
            .send()
            .await
            .unwrap()
    }

    async fn issue_authorization_code(
        &self,
        client_id: &str,
        redirect_uri: &str,
        scope: &str,
    ) -> (String, String) {
        let verifier = pkce_verifier();
        let state = format!("state-{}", Uuid::new_v4());
        let response = self
            .begin_authorize(client_id, redirect_uri, scope, &state, &verifier)
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        let headers = response.headers().clone();
        assert_eq!(
            headers
                .get(reqwest::header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );
        assert_eq!(
            headers
                .get(reqwest::header::X_FRAME_OPTIONS)
                .and_then(|value| value.to_str().ok()),
            Some("DENY")
        );
        assert!(
            headers
                .get(reqwest::header::CONTENT_SECURITY_POLICY)
                .is_some()
        );
        let set_cookie = headers
            .get(reqwest::header::SET_COOKIE)
            .and_then(|value| value.to_str().ok())
            .unwrap()
            .to_string();
        assert!(set_cookie.contains("HttpOnly"));
        assert!(set_cookie.contains("SameSite=Lax"));
        assert!(set_cookie.contains("Path=/oauth/authorize"));
        let cookie = set_cookie.split(';').next().unwrap().to_string();
        let html = response.text().await.unwrap();
        let csrf = hidden_value(&html, CSRF_FIELD);
        assert_eq!(cookie, format!("{CSRF_COOKIE}={csrf}"));

        let response = self
            .approve(
                client_id,
                redirect_uri,
                scope,
                &state,
                &verifier,
                &cookie,
                &csrf,
                &self.admin_secret,
            )
            .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            response
                .headers()
                .get(reqwest::header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );
        let location = response
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .unwrap();
        let location = Url::parse(location).unwrap();
        let code = query_value(&location, "code");
        assert_eq!(query_value(&location, "state"), state);
        (verifier, code)
    }

    async fn authorization_code(
        &self,
        client_id: &str,
        redirect_uri: &str,
        scope: &str,
    ) -> (String, String, Value) {
        let (verifier, code) = self
            .issue_authorization_code(client_id, redirect_uri, scope)
            .await;

        let form = vec![
            ("grant_type".to_string(), "authorization_code".to_string()),
            ("code".to_string(), code.clone()),
            ("redirect_uri".to_string(), redirect_uri.to_string()),
            ("code_verifier".to_string(), verifier.clone()),
        ];
        let response = self
            .http
            .post(format!("{}{TOKEN_PATH}", self.base_url))
            .basic_auth(client_id, Some(&self.confidential_secret))
            .form(&form)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(reqwest::header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );
        let tokens: Value = response.json().await.unwrap();
        assert_eq!(tokens["token_type"], "Bearer");
        assert!(tokens["access_token"].as_str().unwrap().starts_with("eba_"));
        assert!(
            tokens["refresh_token"]
                .as_str()
                .unwrap()
                .starts_with("ebr_")
        );
        (verifier, code, tokens)
    }

    async fn public_token_pair(&self) -> (String, String) {
        let verifier = pkce_verifier();
        let state = "public-state";
        let response = self
            .begin_authorize(
                "public",
                PUBLIC_REDIRECT,
                SCOPE_EVENTS_READ,
                state,
                &verifier,
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        let cookie = response
            .headers()
            .get(reqwest::header::SET_COOKIE)
            .and_then(|value| value.to_str().ok())
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();
        let html = response.text().await.unwrap();
        let csrf = hidden_value(&html, CSRF_FIELD);
        let response = self
            .approve(
                "public",
                PUBLIC_REDIRECT,
                SCOPE_EVENTS_READ,
                state,
                &verifier,
                &cookie,
                &csrf,
                &self.admin_secret,
            )
            .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .unwrap();
        let code = query_value(&Url::parse(location).unwrap(), "code");
        let form = vec![
            ("grant_type".to_string(), "authorization_code".to_string()),
            ("client_id".to_string(), "public".to_string()),
            ("code".to_string(), code),
            ("redirect_uri".to_string(), PUBLIC_REDIRECT.to_string()),
            ("code_verifier".to_string(), verifier),
        ];
        let response = self
            .http
            .post(format!("{}{TOKEN_PATH}", self.base_url))
            .form(&form)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let tokens: Value = response.json().await.unwrap();
        assert_eq!(tokens["scope"], SCOPE_EVENTS_READ);
        (
            tokens["access_token"].as_str().unwrap().to_string(),
            tokens["refresh_token"].as_str().unwrap().to_string(),
        )
    }

    async fn public_access_token(&self) -> String {
        self.public_token_pair().await.0
    }

    async fn consumer_probe(&self, token: &str) -> reqwest::Response {
        self.http
            .get(format!("{}/consumers/muse/probe", self.base_url))
            .bearer_auth(token)
            .send()
            .await
            .unwrap()
    }
}

impl Drop for OAuthFixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}

fn pkce_verifier() -> String {
    // Valid PKCE verifier characters and length, generated dynamically.
    format!(
        "{}{}{}",
        Uuid::new_v4().simple(),
        Uuid::new_v4().simple(),
        "abcdefghijklmnop"
    )
}

fn pkce_challenge(verifier: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn hidden_value(html: &str, name: &str) -> String {
    let marker = format!("name=\"{name}\" value=\"");
    let start = html
        .find(&marker)
        .unwrap_or_else(|| panic!("missing {name}: {html}"))
        + marker.len();
    let end = html[start..].find('"').unwrap() + start;
    html[start..end].to_string()
}

fn query_value(url: &Url, name: &str) -> String {
    url.query_pairs()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
        .unwrap_or_else(|| panic!("missing `{name}` in {url}"))
}

fn token_form(grant: &str) -> Vec<(String, String)> {
    vec![("grant_type".to_string(), grant.to_string())]
}

#[tokio::test]
async fn discovery_and_full_pkce_flow_enforces_scopes() {
    let fixture = OAuthFixture::start().await;
    let metadata: Value = fixture
        .http
        .get(format!(
            "{}/.well-known/oauth-authorization-server",
            fixture.base_url
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(metadata["issuer"], "https://bridge.example.com");
    assert_eq!(metadata["response_types_supported"][0], "code");
    assert_eq!(metadata["code_challenge_methods_supported"][0], "S256");
    assert!(
        metadata["grant_types_supported"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == "refresh_token")
    );

    let resource: Value = fixture
        .http
        .get(format!(
            "{}/.well-known/oauth-protected-resource",
            fixture.base_url
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resource["resource"], "https://bridge.example.com");
    assert_eq!(
        resource["authorization_servers"][0],
        "https://bridge.example.com"
    );

    let (_verifier, _code, tokens) = fixture
        .authorization_code(
            "confidential",
            CONFIDENTIAL_REDIRECT,
            &format!("{SCOPE_EVENTS_READ} {SCOPE_EVENTS_ACK}"),
        )
        .await;
    let access = tokens["access_token"].as_str().unwrap();
    assert_eq!(
        fixture.consumer_probe(access).await.status(),
        StatusCode::OK
    );

    // events/list is a read method and is allowed with the read scope.
    let response = fixture
        .http
        .post(format!("{}/mcp", fixture.base_url))
        .bearer_auth(access)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "events/list",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let public_access = fixture.public_access_token().await;
    let response = fixture.consumer_probe(&public_access).await;
    assert_eq!(response.status(), StatusCode::OK);

    let forbidden = fixture
        .http
        .post(format!("{}/consumers/muse/ack", fixture.base_url))
        .bearer_auth(&public_access)
        .json(&json!({"upToSequence": 0}))
        .send()
        .await
        .unwrap();
    assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        forbidden
            .headers()
            .get(reqwest::header::WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok()),
        Some("Bearer error=\"insufficient_scope\", scope=\"events.ack\"")
    );

    // The read scope is not enough to manage push subscriptions.
    let synthetic_secret = format!("whsec_{}", Uuid::new_v4().simple());
    let response = fixture
        .http
        .post(format!("{}/mcp", fixture.base_url))
        .bearer_auth(&public_access)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "events/subscribe",
            "params": {
                "name": "t3.run.failed",
                "delivery": {
                    "url": "https://callback.example/hook",
                    "secret": synthetic_secret
                }
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // tools/call is checked by tool name before rmcp sees it.
    let response = fixture
        .http
        .post(format!("{}/mcp", fixture.base_url))
        .bearer_auth(&public_access)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "ack_events", "arguments": {"event_ids": ["evt_missing"]}}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // Batch requests are checked item by item.
    let response = fixture
        .http
        .post(format!("{}/mcp", fixture.base_url))
        .bearer_auth(&public_access)
        .json(&json!([
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {"name": "list_events", "arguments": {}}
            },
            {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {"name": "ack_consumer_events", "arguments": {"consumer": "muse", "up_to_sequence": 0}}
            }
        ]))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn public_and_confidential_client_authentication_are_distinct() {
    let fixture = OAuthFixture::start().await;
    let (verifier, code, tokens) = fixture
        .authorization_code("confidential", CONFIDENTIAL_REDIRECT, SCOPE_EVENTS_READ)
        .await;

    // Form-based client authentication is supported for confidential clients.
    let refresh = tokens["refresh_token"].as_str().unwrap();
    let response = fixture
        .http
        .post(format!("{}{TOKEN_PATH}", fixture.base_url))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh),
            ("client_id", "confidential"),
            ("client_secret", fixture.confidential_secret.as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let base_form = vec![
        ("grant_type".to_string(), "authorization_code".to_string()),
        ("code".to_string(), code.clone()),
        (
            "redirect_uri".to_string(),
            CONFIDENTIAL_REDIRECT.to_string(),
        ),
        ("code_verifier".to_string(), verifier.clone()),
    ];
    let response = fixture
        .http
        .post(format!("{}{TOKEN_PATH}", fixture.base_url))
        .form(&base_form)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let mut wrong_secret = base_form.clone();
    wrong_secret.push(("client_id".to_string(), "confidential".to_string()));
    wrong_secret.push(("client_secret".to_string(), Uuid::new_v4().to_string()));
    let response = fixture
        .http
        .post(format!("{}{TOKEN_PATH}", fixture.base_url))
        .form(&wrong_secret)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = fixture
        .http
        .post(format!("{}{TOKEN_PATH}", fixture.base_url))
        .basic_auth("confidential", Some(Uuid::new_v4().to_string()))
        .form(&base_form)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let public_access = fixture.public_access_token().await;
    let mut public_with_secret = token_form("refresh_token");
    public_with_secret.push(("client_id".to_string(), "public".to_string()));
    public_with_secret.push(("client_secret".to_string(), Uuid::new_v4().to_string()));
    public_with_secret.push(("refresh_token".to_string(), Uuid::new_v4().to_string()));
    let response = fixture
        .http
        .post(format!("{}{TOKEN_PATH}", fixture.base_url))
        .form(&public_with_secret)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        fixture.consumer_probe(&public_access).await.status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn authorization_negative_cases_and_no_redirect_boundary() {
    let fixture = OAuthFixture::start().await;
    let verifier = pkce_verifier();
    let challenge = pkce_challenge(&verifier);

    // Missing and plain PKCE are rejected without a redirect.
    for query in [
        vec![
            ("response_type", "code"),
            ("client_id", "confidential"),
            ("redirect_uri", CONFIDENTIAL_REDIRECT),
            ("code_challenge_method", "S256"),
        ],
        vec![
            ("response_type", "code"),
            ("client_id", "confidential"),
            ("redirect_uri", CONFIDENTIAL_REDIRECT),
            ("code_challenge", &challenge),
            ("code_challenge_method", "plain"),
        ],
    ] {
        let response = fixture
            .http
            .get(format!("{}{AUTHORIZE_PATH}", fixture.base_url))
            .query(&query)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(response.headers().get(reqwest::header::LOCATION).is_none());
    }

    // Unknown client and unregistered redirect URI never redirect.
    for (client, redirect) in [
        ("missing", CONFIDENTIAL_REDIRECT),
        ("confidential", "https://evil.example/callback"),
    ] {
        let response = fixture
            .http
            .get(format!("{}{AUTHORIZE_PATH}", fixture.base_url))
            .query(&[
                ("response_type", "code"),
                ("client_id", client),
                ("redirect_uri", redirect),
                ("code_challenge", &challenge),
                ("code_challenge_method", "S256"),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(response.headers().get(reqwest::header::LOCATION).is_none());
    }

    // State is rendered into the consent page but HTML-escaped.
    let state = "</script><script>alert('xss')</script>";
    let response = fixture
        .begin_authorize(
            "confidential",
            CONFIDENTIAL_REDIRECT,
            SCOPE_EVENTS_READ,
            state,
            &verifier,
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let set_cookie = response
        .headers()
        .get(reqwest::header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .unwrap()
        .to_string();
    let cookie = set_cookie.split(';').next().unwrap().to_string();
    let html = response.text().await.unwrap();
    assert!(!html.contains("<script>"));
    assert!(html.contains("&lt;/script&gt;"));
    let csrf = hidden_value(&html, CSRF_FIELD);

    // Wrong CSRF token is rejected.
    let response = fixture
        .approve(
            "confidential",
            CONFIDENTIAL_REDIRECT,
            SCOPE_EVENTS_READ,
            state,
            &verifier,
            &cookie,
            &Uuid::new_v4().to_string(),
            &fixture.admin_secret,
        )
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // Wrong administrator secret is rejected even with a valid CSRF pair.
    let response = fixture
        .approve(
            "confidential",
            CONFIDENTIAL_REDIRECT,
            SCOPE_EVENTS_READ,
            state,
            &verifier,
            &cookie,
            &csrf,
            &Uuid::new_v4().to_string(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // Missing CSRF cookie is rejected even when the form field is present.
    let response = fixture
        .approve(
            "confidential",
            CONFIDENTIAL_REDIRECT,
            SCOPE_EVENTS_READ,
            state,
            &verifier,
            "",
            &csrf,
            &fixture.admin_secret,
        )
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // An explicit deny redirects with access_denied and preserves state.
    let deny_form = vec![
        ("response_type".to_string(), "code".to_string()),
        ("client_id".to_string(), "confidential".to_string()),
        (
            "redirect_uri".to_string(),
            CONFIDENTIAL_REDIRECT.to_string(),
        ),
        ("scope".to_string(), SCOPE_EVENTS_READ.to_string()),
        ("state".to_string(), state.to_string()),
        ("code_challenge".to_string(), challenge.clone()),
        ("code_challenge_method".to_string(), "S256".to_string()),
        (CSRF_FIELD.to_string(), csrf.clone()),
        (ADMIN_SECRET_FIELD.to_string(), fixture.admin_secret.clone()),
        (DECISION_FIELD.to_string(), "deny".to_string()),
    ];
    let response = fixture
        .http
        .post(format!("{}{AUTHORIZE_PATH}", fixture.base_url))
        .header(reqwest::header::COOKIE, &cookie)
        .form(&deny_form)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .unwrap();
    let location = Url::parse(location).unwrap();
    assert_eq!(query_value(&location, "error"), "access_denied");
    assert_eq!(query_value(&location, "state"), state);

    // OAuth discovery and endpoints still run the Host allowlist check.
    let response = fixture
        .http
        .get(format!(
            "{}/.well-known/oauth-authorization-server",
            fixture.base_url
        ))
        .header(reqwest::header::HOST, "evil.example")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // Origin validation runs on POST /oauth/authorize.
    let form = vec![
        ("response_type".to_string(), "code".to_string()),
        ("client_id".to_string(), "confidential".to_string()),
        (
            "redirect_uri".to_string(),
            CONFIDENTIAL_REDIRECT.to_string(),
        ),
        ("scope".to_string(), SCOPE_EVENTS_READ.to_string()),
        ("code_challenge".to_string(), challenge),
        ("code_challenge_method".to_string(), "S256".to_string()),
        (CSRF_FIELD.to_string(), csrf),
        (ADMIN_SECRET_FIELD.to_string(), fixture.admin_secret.clone()),
        (DECISION_FIELD.to_string(), "approve".to_string()),
    ];
    let response = fixture
        .http
        .post(format!("{}{AUTHORIZE_PATH}", fixture.base_url))
        .header(reqwest::header::ORIGIN, "https://evil.example")
        .header(reqwest::header::COOKIE, cookie)
        .form(&form)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // Unknown scope on a trusted request is also rejected directly.
    let response = fixture
        .begin_authorize(
            "confidential",
            CONFIDENTIAL_REDIRECT,
            "events.admin",
            "scope",
            &verifier,
        )
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn authorization_code_replay_revokes_the_family() {
    let fixture = OAuthFixture::start().await;
    let (verifier, code, tokens) = fixture
        .authorization_code(
            "confidential",
            CONFIDENTIAL_REDIRECT,
            &format!("{SCOPE_EVENTS_READ} {SCOPE_EVENTS_ACK}"),
        )
        .await;
    let access = tokens["access_token"].as_str().unwrap().to_string();
    let refresh = tokens["refresh_token"].as_str().unwrap().to_string();
    assert_eq!(
        fixture.consumer_probe(&access).await.status(),
        StatusCode::OK
    );

    let replay = fixture
        .http
        .post(format!("{}{TOKEN_PATH}", fixture.base_url))
        .basic_auth("confidential", Some(&fixture.confidential_secret))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", CONFIDENTIAL_REDIRECT),
            ("code_verifier", &verifier),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
    let body: Value = replay.json().await.unwrap();
    assert_eq!(body["error"], "invalid_grant");

    assert_eq!(
        fixture.consumer_probe(&access).await.status(),
        StatusCode::UNAUTHORIZED
    );
    let refresh_attempt = fixture
        .http
        .post(format!("{}{TOKEN_PATH}", fixture.base_url))
        .basic_auth("confidential", Some(&fixture.confidential_secret))
        .form(&[("grant_type", "refresh_token"), ("refresh_token", &refresh)])
        .send()
        .await
        .unwrap();
    assert_eq!(refresh_attempt.status(), StatusCode::BAD_REQUEST);
    let body: Value = refresh_attempt.json().await.unwrap();
    assert_eq!(body["error"], "invalid_grant");
}

#[tokio::test]
async fn refresh_rotation_downscope_and_replay_revoke_the_family() {
    let fixture = OAuthFixture::start().await;
    let (_verifier, _code, tokens) = fixture
        .authorization_code(
            "confidential",
            CONFIDENTIAL_REDIRECT,
            &format!("{SCOPE_EVENTS_READ} {SCOPE_EVENTS_ACK}"),
        )
        .await;
    let old_refresh = tokens["refresh_token"].as_str().unwrap().to_string();

    // Downscope to read only.
    let response = fixture
        .http
        .post(format!("{}{TOKEN_PATH}", fixture.base_url))
        .basic_auth("confidential", Some(&fixture.confidential_secret))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", &old_refresh),
            ("scope", SCOPE_EVENTS_READ),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let rotated: Value = response.json().await.unwrap();
    assert_eq!(rotated["scope"], SCOPE_EVENTS_READ);
    let new_access = rotated["access_token"].as_str().unwrap().to_string();
    let new_refresh = rotated["refresh_token"].as_str().unwrap().to_string();
    assert_ne!(new_refresh, old_refresh);

    // Escalation beyond the original (and now downscoped) grant is rejected.
    let escalation = fixture
        .http
        .post(format!("{}{TOKEN_PATH}", fixture.base_url))
        .basic_auth("confidential", Some(&fixture.confidential_secret))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", &new_refresh),
            ("scope", SCOPE_EVENTS_ACK),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(escalation.status(), StatusCode::BAD_REQUEST);
    let body: Value = escalation.json().await.unwrap();
    assert_eq!(body["error"], "invalid_scope");

    // Replaying the already-rotated token revokes the whole family.
    let replay = fixture
        .http
        .post(format!("{}{TOKEN_PATH}", fixture.base_url))
        .basic_auth("confidential", Some(&fixture.confidential_secret))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", &old_refresh),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
    let body: Value = replay.json().await.unwrap();
    assert_eq!(body["error"], "invalid_grant");

    assert_eq!(
        fixture.consumer_probe(&new_access).await.status(),
        StatusCode::UNAUTHORIZED
    );
    let new_refresh_attempt = fixture
        .http
        .post(format!("{}{TOKEN_PATH}", fixture.base_url))
        .basic_auth("confidential", Some(&fixture.confidential_secret))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", &new_refresh),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(new_refresh_attempt.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn revocation_respects_client_ownership_and_revokes_refresh_families() {
    let fixture = OAuthFixture::start().await;
    let (_verifier, _code, tokens) = fixture
        .authorization_code("confidential", CONFIDENTIAL_REDIRECT, SCOPE_EVENTS_READ)
        .await;
    let confidential_access = tokens["access_token"].as_str().unwrap().to_string();
    let (public_access, public_refresh) = fixture.public_token_pair().await;
    assert_eq!(
        fixture.consumer_probe(&confidential_access).await.status(),
        StatusCode::OK
    );

    // A different client cannot revoke this access token. RFC 7009 still
    // returns 200 so token existence is not disclosed.
    let response = fixture
        .http
        .post(format!("{}/oauth/revoke", fixture.base_url))
        .form(&[
            ("token", confidential_access.as_str()),
            ("client_id", "public"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        fixture.consumer_probe(&confidential_access).await.status(),
        StatusCode::OK
    );

    // Revoking the confidential access token also terminates its family.
    let response = fixture
        .http
        .post(format!("{}/oauth/revoke", fixture.base_url))
        .basic_auth("confidential", Some(&fixture.confidential_secret))
        .form(&[("token", confidential_access.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        fixture.consumer_probe(&confidential_access).await.status(),
        StatusCode::UNAUTHORIZED
    );

    // Revoke the public client's refresh token: its whole family dies.
    let response = fixture
        .http
        .post(format!("{}/oauth/revoke", fixture.base_url))
        .form(&[
            ("token", public_refresh.as_str()),
            ("token_type_hint", "refresh_token"),
            ("client_id", "public"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        fixture.consumer_probe(&public_access).await.status(),
        StatusCode::UNAUTHORIZED
    );
    let refresh_attempt = fixture
        .http
        .post(format!("{}{TOKEN_PATH}", fixture.base_url))
        .form(&[
            ("grant_type", "refresh_token"),
            ("client_id", "public"),
            ("refresh_token", public_refresh.as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(refresh_attempt.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn oauth_is_required_without_static_token_and_static_token_coexists() {
    let fixture = OAuthFixture::start().await;
    let response = fixture
        .http
        .get(format!("{}/consumers/muse/probe", fixture.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response
            .headers()
            .get(reqwest::header::WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok()),
        Some(
            "Bearer resource_metadata=\"https://bridge.example.com/.well-known/oauth-protected-resource\""
        )
    );

    let response = fixture
        .http
        .post(format!("{}/mcp", fixture.base_url))
        .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "events/list"}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let static_fixture = OAuthFixture::start_with_static_token().await;
    let static_token = static_fixture.static_token.as_deref().unwrap();
    assert_eq!(
        static_fixture.consumer_probe(static_token).await.status(),
        StatusCode::OK
    );
    let response = static_fixture
        .http
        .post(format!("{}/consumers/muse/ack", static_fixture.base_url))
        .bearer_auth(static_token)
        .json(&json!({"upToSequence": 0}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn token_redirect_and_verifier_errors_are_invalid_grant() {
    let fixture = OAuthFixture::start().await;
    let (verifier, code) = fixture
        .issue_authorization_code("confidential", CONFIDENTIAL_REDIRECT, SCOPE_EVENTS_READ)
        .await;

    let response = fixture
        .http
        .post(format!("{}{TOKEN_PATH}", fixture.base_url))
        .basic_auth("confidential", Some(&fixture.confidential_secret))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", "https://client.example/other"),
            ("code_verifier", &verifier),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["error"], "invalid_grant");
    assert!(
        body["error_description"]
            .as_str()
            .unwrap()
            .contains("redirect_uri"),
        "{body}"
    );

    let wrong_verifier = pkce_verifier();
    let response = fixture
        .http
        .post(format!("{}{TOKEN_PATH}", fixture.base_url))
        .basic_auth("confidential", Some(&fixture.confidential_secret))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", CONFIDENTIAL_REDIRECT),
            ("code_verifier", &wrong_verifier),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["error"], "invalid_grant");
    assert_eq!(body["error_description"], "PKCE verification failed");

    // Failed redirect_uri/PKCE attempts must not have consumed the code:
    // presenting the genuine verifier still succeeds.
    let response = fixture
        .http
        .post(format!("{}{TOKEN_PATH}", fixture.base_url))
        .basic_auth("confidential", Some(&fixture.confidential_secret))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", CONFIDENTIAL_REDIRECT),
            ("code_verifier", &verifier),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let tokens: Value = response.json().await.unwrap();
    assert_eq!(
        fixture
            .consumer_probe(tokens["access_token"].as_str().unwrap())
            .await
            .status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn authenticated_principal_flows_into_mcp_tools() {
    let fixture = OAuthFixture::start().await;
    fixture
        .hub
        .ingest_event(NewEvent {
            id: Some("evt_oauth_principal".into()),
            source: None,
            kind: "t3.run.failed".into(),
            payload: json!({
                "environment_id": "linux-main",
                "project_id": "lnako",
                "thread_id": "thread-42",
                "run_id": "run-102",
                "summary": "failed",
                "error": "boom"
            }),
            occurred_at: None,
        })
        .unwrap();
    let (_verifier, _code, tokens) = fixture
        .authorization_code(
            "confidential",
            CONFIDENTIAL_REDIRECT,
            &format!("{SCOPE_EVENTS_READ} {SCOPE_EVENTS_ACK}"),
        )
        .await;
    let access = tokens["access_token"].as_str().unwrap();

    let initialize = json!({
        "jsonrpc": "2.0",
        "id": 0,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "oauth-tests", "version": "1.0.0"}
        }
    });
    let response = fixture
        .http
        .post(format!("{}/mcp", fixture.base_url))
        .bearer_auth(access)
        .header(
            reqwest::header::ACCEPT,
            "application/json, text/event-stream",
        )
        .json(&initialize)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let session = response
        .headers()
        .get("mcp-session-id")
        .and_then(|value| value.to_str().ok())
        .unwrap()
        .to_string();
    let body = parse_mcp_response(response).await;
    assert!(body.get("error").is_none(), "{body}");

    let response = fixture
        .http
        .post(format!("{}/mcp", fixture.base_url))
        .bearer_auth(access)
        .header(
            reqwest::header::ACCEPT,
            "application/json, text/event-stream",
        )
        .header("MCP-Session-Id", &session)
        .header("MCP-Protocol-Version", "2025-06-18")
        .json(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        .send()
        .await
        .unwrap();
    assert!(
        response.status().is_success() || response.status() == StatusCode::ACCEPTED,
        "initialized notification failed: {}",
        response.status()
    );

    let response = fixture
        .http
        .post(format!("{}/mcp", fixture.base_url))
        .bearer_auth(access)
        .header(
            reqwest::header::ACCEPT,
            "application/json, text/event-stream",
        )
        .header("MCP-Session-Id", &session)
        .header("MCP-Protocol-Version", "2025-06-18")
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "ack_events",
                "arguments": {"event_ids": ["evt_oauth_principal"]}
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = parse_mcp_response(response).await;
    assert!(body.get("error").is_none(), "{body}");
    assert!(
        fixture
            .hub
            .repository()
            .is_acknowledged("alice", "evt_oauth_principal")
            .unwrap(),
        "the OAuth principal must own the acknowledgement: {body}"
    );
    assert!(
        !fixture
            .hub
            .repository()
            .is_acknowledged("local", "evt_oauth_principal")
            .unwrap(),
        "the server fallback principal must not receive the acknowledgement"
    );
}

async fn parse_mcp_response(response: reqwest::Response) -> Value {
    let status = response.status();
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let bytes = response.bytes().await.expect("response body");
    assert!(
        status.is_success(),
        "HTTP {status}: {}",
        String::from_utf8_lossy(&bytes)
    );
    if content_type.contains("text/event-stream") {
        let text = String::from_utf8_lossy(&bytes);
        let data = text
            .lines()
            .filter_map(|line| line.strip_prefix("data:"))
            .next_back()
            .expect("SSE data frame")
            .trim();
        serde_json::from_str(data).unwrap_or_else(|error| {
            panic!("invalid SSE JSON: {error}: {data}");
        })
    } else {
        serde_json::from_slice(&bytes).unwrap_or_else(|error| {
            panic!(
                "invalid JSON response: {error}: {}",
                String::from_utf8_lossy(&bytes)
            );
        })
    }
}

#[test]
fn stored_oauth_columns_are_hashes_not_raw_secrets() {
    let raw = format!("synthetic-{}", Uuid::new_v4());
    assert_ne!(hash_secret(&raw), raw);
    assert_eq!(hash_secret(&raw).len(), 64);

    let sql = include_str!("../migrations/006_oauth.sql");
    for column in ["code_hash", "token_hash", "rotated_from_hash", "revoked_at"] {
        assert!(sql.contains(column), "missing {column}");
    }
    assert!(!sql.contains("raw_token"));
}

#[tokio::test]
async fn startup_reads_oauth_secrets_and_rejects_missing_environment_values() {
    let temp = TempDir::new().unwrap();
    let missing = format!("EVENTS_BRIDGE_TEST_MISSING_{}", Uuid::new_v4().simple());
    let config = Config::parse(&format!(
        r#"
[oauth]
enabled = true
issuer = "https://bridge.example.com"
admin_secret_env = "{missing}"

[[oauth.clients]]
client_id = "client"
redirect_uris = ["https://client.example/callback"]
"#
    ))
    .unwrap();
    let mut config = config;
    config.database.path = temp.path().join("missing-secret.db");
    let error = match Hub::with_policy(config, CallbackPolicy::for_tests()) {
        Ok(_) => panic!("missing admin secret must fail startup"),
        Err(error) => error,
    };
    assert!(
        format!("{error:#}").contains(&missing),
        "startup error should name the variable: {error:#}"
    );
}

#[tokio::test]
async fn resource_target_is_enforced_across_authorize_token_and_refresh() {
    let fixture = OAuthFixture::start().await;
    let verifier = pkce_verifier();
    let challenge = pkce_challenge(&verifier);

    // Mismatched resource on GET /oauth/authorize fails with invalid_target.
    let bad_authz = fixture
        .http
        .get(format!("{}{AUTHORIZE_PATH}", fixture.base_url))
        .query(&[
            ("response_type", "code"),
            ("client_id", "confidential"),
            ("redirect_uri", CONFIDENTIAL_REDIRECT),
            ("scope", SCOPE_EVENTS_READ),
            ("state", "s1"),
            ("resource", "https://other-service.example"),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(bad_authz.status(), StatusCode::BAD_REQUEST);
    let body: Value = bad_authz.json().await.unwrap();
    assert_eq!(body["error"], "invalid_target");

    // Matching resource succeeds through consent, token exchange, and refresh.
    let good_authz = fixture
        .http
        .get(format!("{}{AUTHORIZE_PATH}", fixture.base_url))
        .query(&[
            ("response_type", "code"),
            ("client_id", "confidential"),
            ("redirect_uri", CONFIDENTIAL_REDIRECT),
            ("scope", SCOPE_EVENTS_READ),
            ("state", "s2"),
            ("resource", "https://bridge.example.com"),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(good_authz.status(), StatusCode::OK);
    let cookie = good_authz
        .headers()
        .get(reqwest::header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let html = good_authz.text().await.unwrap();
    assert_eq!(
        hidden_value(&html, "resource"),
        "https://bridge.example.com"
    );
    let csrf = hidden_value(&html, CSRF_FIELD);

    let approve = fixture
        .http
        .post(format!("{}{AUTHORIZE_PATH}", fixture.base_url))
        .header(reqwest::header::COOKIE, &cookie)
        .form(&[
            ("response_type", "code"),
            ("client_id", "confidential"),
            ("redirect_uri", CONFIDENTIAL_REDIRECT),
            ("scope", SCOPE_EVENTS_READ),
            ("state", "s2"),
            ("resource", "https://bridge.example.com"),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
            (CSRF_FIELD, &csrf),
            (ADMIN_SECRET_FIELD, &fixture.admin_secret),
            (DECISION_FIELD, "approve"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(approve.status(), StatusCode::SEE_OTHER);
    let code = query_value(
        &Url::parse(
            approve
                .headers()
                .get(reqwest::header::LOCATION)
                .unwrap()
                .to_str()
                .unwrap(),
        )
        .unwrap(),
        "code",
    );

    // Mismatched resource on /oauth/token is rejected without consuming the code.
    let bad_token = fixture
        .http
        .post(format!("{}{TOKEN_PATH}", fixture.base_url))
        .basic_auth("confidential", Some(&fixture.confidential_secret))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", CONFIDENTIAL_REDIRECT),
            ("code_verifier", &verifier),
            ("resource", "https://bridge.example.com/other"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(bad_token.status(), StatusCode::BAD_REQUEST);
    let body: Value = bad_token.json().await.unwrap();
    assert_eq!(body["error"], "invalid_target");

    let good_token = fixture
        .http
        .post(format!("{}{TOKEN_PATH}", fixture.base_url))
        .basic_auth("confidential", Some(&fixture.confidential_secret))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", CONFIDENTIAL_REDIRECT),
            ("code_verifier", &verifier),
            ("resource", "https://bridge.example.com"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(good_token.status(), StatusCode::OK);
    let tokens: Value = good_token.json().await.unwrap();
    let refresh = tokens["refresh_token"].as_str().unwrap();

    // Mismatched resource on refresh fails without burning the refresh token.
    let bad_refresh = fixture
        .http
        .post(format!("{}{TOKEN_PATH}", fixture.base_url))
        .basic_auth("confidential", Some(&fixture.confidential_secret))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh),
            ("resource", "https://other-service.example"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(bad_refresh.status(), StatusCode::BAD_REQUEST);
    let body: Value = bad_refresh.json().await.unwrap();
    assert_eq!(body["error"], "invalid_target");

    let good_refresh = fixture
        .http
        .post(format!("{}{TOKEN_PATH}", fixture.base_url))
        .basic_auth("confidential", Some(&fixture.confidential_secret))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh),
            ("resource", "https://bridge.example.com"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(good_refresh.status(), StatusCode::OK);
}

#[tokio::test]
async fn basic_auth_form_decodes_rfc6749_special_character_credentials() {
    let temp = TempDir::new().unwrap();
    let admin_secret = Uuid::new_v4().to_string();
    let special_id = "svc:client one";
    let special_secret = format!("s:ec+ret %✓ {}", Uuid::new_v4().simple());
    let (admin_var, admin_env) = EnvGuard::set("OAUTH_ADMIN", &admin_secret);
    let (client_var, client_env) = EnvGuard::set("OAUTH_SPECIAL_CLIENT", &special_secret);
    let env = admin_env.merge(client_env);
    let config = Config::parse(&format!(
        r#"
[server]
allowed_hosts = ["localhost", "127.0.0.1", "::1"]

[oauth]
enabled = true
issuer = "https://bridge.example.com"
admin_secret_env = "{admin_var}"

[[oauth.clients]]
client_id = "{special_id}"
client_secret_env = "{client_var}"
redirect_uris = ["{CONFIDENTIAL_REDIRECT}"]
scopes = ["events.read"]
principal = "special-svc"
"#
    ))
    .unwrap();
    let fixture =
        OAuthFixture::start_with_config(temp, config, env, admin_secret, special_secret.clone())
            .await;

    let (verifier, code) = fixture
        .issue_authorization_code(special_id, CONFIDENTIAL_REDIRECT, SCOPE_EVENTS_READ)
        .await;

    // Encode per RFC 6749 §2.3.1: application/x-www-form-urlencoded each component.
    let form_id: String = url::form_urlencoded::byte_serialize(special_id.as_bytes()).collect();
    let form_secret: String =
        url::form_urlencoded::byte_serialize(special_secret.as_bytes()).collect();
    let basic_value = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{form_id}:{form_secret}"))
    );

    let token_res = fixture
        .http
        .post(format!("{}{TOKEN_PATH}", fixture.base_url))
        .header(reqwest::header::AUTHORIZATION, &basic_value)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", CONFIDENTIAL_REDIRECT),
            ("code_verifier", &verifier),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(token_res.status(), StatusCode::OK);
    let tokens: Value = token_res.json().await.unwrap();
    let access = tokens["access_token"].as_str().unwrap();
    assert_eq!(
        fixture.consumer_probe(access).await.status(),
        StatusCode::OK
    );

    let revoke_res = fixture
        .http
        .post(format!("{}/oauth/revoke", fixture.base_url))
        .header(reqwest::header::AUTHORIZATION, &basic_value)
        .form(&[("token", access)])
        .send()
        .await
        .unwrap();
    assert_eq!(revoke_res.status(), StatusCode::OK);
    assert_eq!(
        fixture.consumer_probe(access).await.status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn path_bearing_issuer_flow_and_prefixed_well_known_work_end_to_end() {
    let temp = TempDir::new().unwrap();
    let admin_secret = Uuid::new_v4().to_string();
    let confidential_secret = Uuid::new_v4().to_string();
    let (admin_var, admin_env) = EnvGuard::set("OAUTH_ADMIN", &admin_secret);
    let (client_var, client_env) = EnvGuard::set("OAUTH_CLIENT", &confidential_secret);
    let env = admin_env.merge(client_env);
    let config = Config::parse(&format!(
        r#"
[server]
allowed_hosts = ["localhost", "127.0.0.1", "::1"]

[oauth]
enabled = true
issuer = "https://bridge.example.com/base"
admin_secret_env = "{admin_var}"

[[oauth.clients]]
client_id = "confidential"
client_secret_env = "{client_var}"
redirect_uris = ["{CONFIDENTIAL_REDIRECT}"]
scopes = ["events.read"]
principal = "alice"
"#
    ))
    .unwrap();
    let fixture =
        OAuthFixture::start_with_config(temp, config, env, admin_secret, confidential_secret).await;

    // 401 advertises RFC 9728 path-suffixed protected-resource metadata URL.
    let unauth = fixture
        .http
        .get(format!("{}/consumers/muse/probe", fixture.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        unauth
            .headers()
            .get(reqwest::header::WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok()),
        Some(
            "Bearer resource_metadata=\"https://bridge.example.com/.well-known/oauth-protected-resource/base\""
        )
    );

    // Path-suffixed well-known endpoints are served.
    let prm: Value = fixture
        .http
        .get(format!(
            "{}/.well-known/oauth-protected-resource/base",
            fixture.base_url
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(prm["resource"], "https://bridge.example.com/base");

    let asm: Value = fixture
        .http
        .get(format!(
            "{}/.well-known/oauth-authorization-server/base",
            fixture.base_url
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        asm["authorization_endpoint"],
        "https://bridge.example.com/base/oauth/authorize"
    );

    // Prefixed authorize GET renders prefixed form action and cookie Path=/base/oauth/authorize.
    let verifier = pkce_verifier();
    let challenge = pkce_challenge(&verifier);
    let authz_get = fixture
        .http
        .get(format!("{}/base/oauth/authorize", fixture.base_url))
        .query(&[
            ("response_type", "code"),
            ("client_id", "confidential"),
            ("redirect_uri", CONFIDENTIAL_REDIRECT),
            ("scope", SCOPE_EVENTS_READ),
            ("state", "prefixed"),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(authz_get.status(), StatusCode::OK);
    let set_cookie = authz_get
        .headers()
        .get(reqwest::header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        set_cookie.contains("Path=/base/oauth/authorize"),
        "{set_cookie}"
    );
    let cookie = set_cookie.split(';').next().unwrap().to_string();
    let html = authz_get.text().await.unwrap();
    assert!(
        html.contains("<form method=\"post\" action=\"/base/oauth/authorize\">"),
        "{html}"
    );
    let csrf = hidden_value(&html, CSRF_FIELD);

    // POST to /base/oauth/authorize succeeds and clears the cookie with Path=/base/oauth/authorize.
    let authz_post = fixture
        .http
        .post(format!("{}/base/oauth/authorize", fixture.base_url))
        .header(reqwest::header::COOKIE, &cookie)
        .form(&[
            ("response_type", "code"),
            ("client_id", "confidential"),
            ("redirect_uri", CONFIDENTIAL_REDIRECT),
            ("scope", SCOPE_EVENTS_READ),
            ("state", "prefixed"),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
            (CSRF_FIELD, &csrf),
            (ADMIN_SECRET_FIELD, &fixture.admin_secret),
            (DECISION_FIELD, "approve"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(authz_post.status(), StatusCode::SEE_OTHER);
    let clear_cookie = authz_post
        .headers()
        .get(reqwest::header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        clear_cookie.contains("Path=/base/oauth/authorize; Max-Age=0"),
        "{clear_cookie}"
    );
    let code = query_value(
        &Url::parse(
            authz_post
                .headers()
                .get(reqwest::header::LOCATION)
                .unwrap()
                .to_str()
                .unwrap(),
        )
        .unwrap(),
        "code",
    );

    // Prefixed /base/oauth/token issues a usable bearer token.
    let token_res = fixture
        .http
        .post(format!("{}/base/oauth/token", fixture.base_url))
        .basic_auth("confidential", Some(&fixture.confidential_secret))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", CONFIDENTIAL_REDIRECT),
            ("code_verifier", &verifier),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(token_res.status(), StatusCode::OK);
    let tokens: Value = token_res.json().await.unwrap();
    assert_eq!(
        fixture
            .consumer_probe(tokens["access_token"].as_str().unwrap())
            .await
            .status(),
        StatusCode::OK
    );
}
