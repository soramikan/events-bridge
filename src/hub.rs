//! The hub: HTTP server, MCP surface, and delivery worker.

use std::{sync::Arc, time::Duration};

use anyhow::Result;
use axum::Router;
use tokio::{net::TcpListener, task::JoinHandle};
use tokio_util::sync::CancellationToken;

use crate::{
    app::AppState,
    config::Config,
    delivery::Dispatcher,
    delivery::verification::CallbackPolicy,
    mcp::http,
    store::{IngestOutcome, NewEvent, Repository},
};

/// Fully wired hub instance.
pub struct Hub {
    state: Arc<AppState>,
    router: Router,
    dispatcher: Dispatcher,
    mcp_cancellation: CancellationToken,
}

impl Hub {
    /// Build a hub with the production callback security policy and the
    /// configured callback timeout.
    pub fn new(config: Config) -> Result<Self> {
        let policy = CallbackPolicy::default()
            .with_timeout(Duration::from_secs(config.delivery.timeout_secs.max(1)));
        Self::with_policy(config, policy)
    }

    /// Build a hub with an explicit callback policy.
    ///
    /// Only integration tests pass a non-default policy; neither configuration
    /// nor CLI flags can select an insecure policy.
    #[doc(hidden)]
    pub fn with_policy(config: Config, policy: CallbackPolicy) -> Result<Self> {
        let state = AppState::new(config, policy.clone())?;
        match state.repo.reset_in_progress_deliveries() {
            Ok(0) => {}
            Ok(count) => tracing::info!(count, "recovered interrupted deliveries"),
            Err(error) => tracing::warn!(%error, "could not recover interrupted deliveries"),
        }
        let mcp_cancellation = CancellationToken::new();
        let router = http::router_with_cancellation(state.clone(), mcp_cancellation.clone());
        let dispatcher = Dispatcher::new(
            state.repo.clone(),
            state.bus.clone(),
            state.config.delivery.clone(),
            policy,
        );
        Ok(Self {
            state,
            router,
            dispatcher,
            mcp_cancellation,
        })
    }

    /// Shared application state.
    pub fn state(&self) -> &Arc<AppState> {
        &self.state
    }

    /// Durable store.
    pub fn repository(&self) -> &Arc<Repository> {
        &self.state.repo
    }

    /// HTTP router (useful for embedding the hub in a test server).
    pub fn router(&self) -> Router {
        self.router.clone()
    }

    /// Validate and persist an event, creating deliveries in one transaction.
    pub fn ingest_event(&self, event: NewEvent) -> Result<IngestOutcome> {
        self.state.ingest.ingest(event)
    }

    /// Process all currently-due deliveries. Exposed for deterministic tests.
    pub async fn deliver_due_once(&self) -> usize {
        self.dispatcher.drain().await
    }

    /// Start the delivery worker.
    pub fn spawn_dispatcher(&self) -> (CancellationToken, JoinHandle<()>) {
        let dispatcher = self.dispatcher.clone();
        let cancellation = CancellationToken::new();
        let child = cancellation.clone();
        let handle = tokio::spawn(async move {
            dispatcher.run(child).await;
        });
        (cancellation, handle)
    }

    /// Bind the configured address and serve until SIGINT/SIGTERM.
    pub async fn serve(self) -> Result<()> {
        let listener = TcpListener::bind(&self.state.config.server.bind).await?;
        tracing::info!(
            address = %listener.local_addr()?,
            database = %self.state.config.database.path.display(),
            "events-bridge hub listening"
        );

        let (cancellation, dispatcher) = self.spawn_dispatcher();
        let mcp_cancellation = self.mcp_cancellation.clone();
        let router = self.router();
        let result = axum::serve(listener, router)
            .with_graceful_shutdown(async move {
                shutdown_signal().await;
                mcp_cancellation.cancel();
            })
            .await;
        cancellation.cancel();
        let _ = dispatcher.await;
        result?;
        Ok(())
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => {
                tracing::warn!(%error, "could not install SIGTERM handler");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
    tracing::info!("shutdown signal received");
}
