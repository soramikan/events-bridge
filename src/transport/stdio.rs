//! stdio MCP transport for generic MCP clients.
//!
//! The stdio surface exposes exactly the same `EventsHandler` as the HTTP
//! transport: the six pull tools plus `events/list`, `events/poll`,
//! `events/subscribe` and `events/unsubscribe`. When a configuration file
//! enables the local T3 collector or the GitHub poller, those background tasks
//! start here too and are cancelled and joined on exit.

use std::{path::PathBuf, time::Duration};

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::sync::CancellationToken;

use crate::{
    app::AppState,
    config::Config,
    delivery::{Dispatcher, verification::CallbackPolicy},
    hub,
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
    let (reader, writer) = rmcp::transport::io::stdio();
    serve_with_io(config, policy, reader, writer).await
}

/// Serve the MCP surface over an arbitrary reader/writer pair.
///
/// This is the same code path as [`run`]; integration tests use an in-memory
/// duplex pair so they can exercise `events/subscribe` with the permissive
/// test callback policy without weakening the production `stdio` command.
#[doc(hidden)]
pub async fn serve_with_io<R, W>(
    config: Config,
    policy: CallbackPolicy,
    reader: R,
    writer: W,
) -> Result<()>
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    let state = AppState::new(config, policy.clone())?;
    let dispatcher = Dispatcher::new(
        state.repo.clone(),
        state.bus.clone(),
        state.config.delivery.clone(),
        policy,
    );

    let t3_collector = hub::spawn_t3_collector(&state)?;
    let github_poller = match hub::spawn_github_poller(&state) {
        Ok(poller) => poller,
        Err(error) => {
            if let Some((collector_cancellation, collector_handle)) = t3_collector {
                collector_cancellation.cancel();
                let _ = collector_handle.await;
            }
            return Err(error);
        }
    };

    let cancellation = CancellationToken::new();
    let worker_token = cancellation.clone();
    let worker = tokio::spawn(async move {
        dispatcher.run(worker_token).await;
    });

    let result = async {
        let service = rmcp::serve_server(EventsHandler::new(state), (reader, writer)).await?;
        service.waiting().await?;
        anyhow::Ok(())
    }
    .await;

    cancellation.cancel();
    if let Some((collector_cancellation, collector_handle)) = t3_collector {
        collector_cancellation.cancel();
        let _ = collector_handle.await;
    }
    if let Some((poller_cancellation, poller_handle)) = github_poller {
        poller_cancellation.cancel();
        let _ = poller_handle.await;
    }
    let _ = worker.await;
    result
}
