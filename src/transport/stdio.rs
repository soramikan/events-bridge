//! stdio MCP transport for generic MCP clients.

use std::{path::PathBuf, time::Duration};

use anyhow::Result;
use tokio_util::sync::CancellationToken;

use crate::{
    app::AppState,
    config::Config,
    delivery::{Dispatcher, verification::CallbackPolicy},
    mcp::handler::EventsHandler,
};

/// Serve the MCP surface over stdin/stdout.
///
/// The delivery worker runs in the background so webhook subscriptions remain
/// active while a local MCP client is connected.
pub async fn run(config_path: Option<PathBuf>) -> Result<()> {
    let config = match config_path {
        Some(path) => Config::load(path)?,
        None => Config::default(),
    };
    crate::init_tracing(&config.logging.level);

    let policy = CallbackPolicy::default()
        .with_timeout(Duration::from_secs(config.delivery.timeout_secs.max(1)));
    let state = AppState::new(config, policy.clone())?;
    let dispatcher = Dispatcher::new(
        state.repo.clone(),
        state.bus.clone(),
        state.config.delivery.clone(),
        policy,
    );

    let cancellation = CancellationToken::new();
    let worker_token = cancellation.clone();
    let worker = tokio::spawn(async move {
        dispatcher.run(worker_token).await;
    });

    let service =
        rmcp::serve_server(EventsHandler::new(state), rmcp::transport::io::stdio()).await?;
    service.waiting().await?;

    cancellation.cancel();
    let _ = worker.await;
    Ok(())
}
