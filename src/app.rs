//! Shared application state.

use std::sync::Arc;

use anyhow::{Context, Result};
use secrecy::SecretString;

use crate::{
    auth::Auth,
    config::Config,
    delivery::verification::CallbackPolicy,
    event::{EventBus, IngestService},
    mcp::subscriptions::SubscriptionManager,
    mcp::tools::ToolService,
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
    /// Pull tools.
    pub tools: Arc<ToolService>,
    /// Inbound authentication.
    pub auth: Auth,
    /// Optional token for `POST /internal/events`.
    pub internal_token: Option<SecretString>,
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
        let tools = Arc::new(ToolService::new(repo.clone()));
        let auth = Auth::from_config(&config.auth)?;

        let internal_token = if config.server.enable_internal_ingest {
            match &config.server.internal_token_env {
                Some(variable) => {
                    let value = std::env::var(variable).with_context(|| {
                        format!(
                            "internal ingest is configured but environment variable `{variable}` is unset"
                        )
                    })?;
                    Some(SecretString::from(value))
                }
                None => None,
            }
        } else {
            None
        };

        Ok(Arc::new(Self {
            config: Arc::new(config),
            repo,
            bus,
            ingest,
            subscriptions,
            tools,
            auth,
            internal_token,
        }))
    }
}
