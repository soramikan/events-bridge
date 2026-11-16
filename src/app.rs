//! Shared application state.

use std::sync::Arc;

use anyhow::{Context, Result};
use secrecy::SecretString;

use crate::{
    auth::Auth,
    config::Config,
    consumers::ConsumerService,
    delivery::verification::CallbackPolicy,
    event::{EventBus, IngestService},
    mcp::subscriptions::SubscriptionManager,
    mcp::tools::ToolService,
    oauth::OAuthService,
    store::Repository,
};

/// Everything the MCP surface and the delivery worker need.
pub struct AppState {
    /// Parsed configuration.
    pub config: Arc<Config>,
    /// Durable store.
    pub repo: Arc<Repository>,
    /// Dispatcher wake-up bus.
    pub bus: EventBus,
    /// Validated event ingestion.
    pub ingest: IngestService,
    /// `events/*` implementation.
    pub subscriptions: Arc<SubscriptionManager>,
    /// Server-side polling consumers.
    pub consumers: Arc<ConsumerService>,
    /// Pull tools.
    pub tools: Arc<ToolService>,
    /// Inbound authentication.
    pub auth: Auth,
    /// OAuth 2.1 authorization server, when enabled.
    pub oauth: Option<Arc<OAuthService>>,
    /// Optional token for `POST /internal/events`.
    pub internal_token: Option<SecretString>,
    /// GitHub webhook HMAC secret, read when the webhook endpoint is enabled.
    pub github_webhook_secret: Option<SecretString>,
    /// Optional GitHub REST API token.
    pub github_token: Option<SecretString>,
    /// Shared HMAC secret for authenticated edge ingest.
    pub edge_shared_secret: Option<SecretString>,
}

impl AppState {
    /// Build state, opening the database and reading configured secrets.
    pub fn new(config: Config, policy: CallbackPolicy) -> Result<Arc<Self>> {
        // Enforce cross-field invariants even when the configuration was built
        // programmatically rather than parsed from TOML.
        config.validate().context("invalid configuration")?;
        let repo =
            Arc::new(Repository::open(&config.database.path).context("opening event store")?);
        let bus = EventBus::new();
        let ingest = IngestService::new(repo.clone(), bus.clone());
        let subscriptions = Arc::new(SubscriptionManager::new(
            repo.clone(),
            config.subscriptions.clone(),
            policy,
        ));
        let consumers = Arc::new(ConsumerService::from_config(repo.clone(), &config));
        let tools = Arc::new(ToolService::with_consumers(repo.clone(), consumers.clone()));
        let oauth = OAuthService::from_config(&config.oauth, repo.clone())?.map(Arc::new);
        let auth = Auth::from_config(&config.auth)?.with_oauth(oauth.clone());

        let internal_token = if config.server.enable_internal_ingest {
            match &config.server.internal_token_env {
                Some(variable) => Some(read_secret_env(variable, "internal ingest")?),
                None => None,
            }
        } else {
            None
        };

        let github = &config.collectors.github;
        let github_webhook_secret = if github.webhook_enabled {
            let variable = github.webhook_secret_env.as_deref().context(
                "collectors.github.webhook_enabled requires \
                 collectors.github.webhook_secret_env",
            )?;
            Some(read_secret_env(variable, "GitHub webhook")?)
        } else {
            None
        };
        let github_token = match github.token_env.as_deref() {
            Some(variable) => Some(read_secret_env(variable, "GitHub API")?),
            None => None,
        };

        let edge_shared_secret = if config.server.enable_edge_ingest {
            let variable = config
                .server
                .edge_shared_secret_env
                .as_deref()
                .context("server.enable_edge_ingest requires server.edge_shared_secret_env")?;
            Some(read_secret_env(variable, "edge ingest")?)
        } else {
            None
        };

        Ok(Arc::new(Self {
            config: Arc::new(config),
            repo,
            bus,
            ingest,
            subscriptions,
            consumers,
            tools,
            auth,
            oauth,
            internal_token,
            github_webhook_secret,
            github_token,
            edge_shared_secret,
        }))
    }
}

fn read_secret_env(variable: &str, purpose: &str) -> Result<SecretString> {
    let value = std::env::var(variable).with_context(|| {
        format!("{purpose} is configured but environment variable `{variable}` is unset")
    })?;
    if value.trim().is_empty() {
        anyhow::bail!("environment variable `{variable}` is empty");
    }
    Ok(SecretString::from(value))
}
