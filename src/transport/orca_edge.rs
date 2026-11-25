//! Forward observations from the local Orca runtime to the Hub.

use std::{path::PathBuf, time::Duration};

use anyhow::{Context, Result};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use crate::{
    app::read_secret_env, collectors::orca::OrcaSource, config::Config,
    edge_protocol::ORCA_EDGE_INGEST_PATH, hub::shutdown_signal, store::Repository,
};

use super::signed_edge::SignedEdgeClient;

struct OrcaEdge {
    source: OrcaSource,
    environment_id: String,
    repo: Repository,
    client: SignedEdgeClient,
    poll_interval: Duration,
    retry_initial: Duration,
    retry_max: Duration,
    queued: Notify,
}

impl OrcaEdge {
    fn new(config: &Config) -> Result<Self> {
        config.edge.validate_for_edge()?;
        let orca = &config.collectors.orca;
        let environment_id = orca
            .environment_id
            .clone()
            .context("collectors.orca.environment_id is required when running edge")?;
        let edge_id = config
            .edge
            .edge_id
            .clone()
            .unwrap_or_else(|| environment_id.clone());
        let secret_env = config
            .edge
            .shared_secret_env
            .as_deref()
            .context("edge.shared_secret_env is required")?;
        let secret = read_secret_env(secret_env, "edge forwarding")?;
        let client = SignedEdgeClient::new(&config.edge, ORCA_EDGE_INGEST_PATH, edge_id, secret)?;
        Ok(Self {
            source: OrcaSource::new(orca, secret_env),
            environment_id,
            repo: Repository::open(&config.database.path).context("opening edge local store")?,
            client,
            poll_interval: Duration::from_millis(orca.poll_interval_ms),
            retry_initial: Duration::from_millis(config.edge.retry_initial_ms),
            retry_max: Duration::from_millis(config.edge.retry_max_ms),
            queued: Notify::new(),
        })
    }

    async fn collect(&self, cancellation: &CancellationToken) {
        loop {
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => break,
                result = self.source.collect(&self.repo, &self.environment_id) => match result {
                    Ok(queued) if queued > 0 => {
                        self.queued.notify_one();
                        tracing::info!(queued, "queued Orca events");
                    }
                    Ok(_) => {}
                    Err(error) => tracing::warn!(%error, "could not poll Orca"),
                }
            }
            tokio::select! {
                _ = cancellation.cancelled() => break,
                _ = tokio::time::sleep(self.poll_interval) => {}
            }
        }
    }

    async fn forward_one(&self) -> Result<bool> {
        let Some((id, body)) = self.repo.next_orca_edge_event(&self.environment_id)? else {
            return Ok(false);
        };
        self.client.post(body).await?;
        self.repo.acknowledge_orca_edge_event(&id)?;
        Ok(true)
    }

    async fn forward(&self, cancellation: &CancellationToken) {
        let mut retry_delay = self.retry_initial;
        while !cancellation.is_cancelled() {
            match self.forward_one().await {
                Ok(true) => retry_delay = self.retry_initial,
                Ok(false) => {
                    retry_delay = self.retry_initial;
                    tokio::select! {
                        _ = cancellation.cancelled() => break,
                        _ = self.queued.notified() => {}
                        _ = tokio::time::sleep(self.poll_interval) => {}
                    }
                }
                Err(error) => {
                    tracing::warn!(%error, delay_ms = retry_delay.as_millis(), "edge forward failed; retrying");
                    tokio::select! {
                        _ = cancellation.cancelled() => break,
                        _ = tokio::time::sleep(retry_delay) => {}
                    }
                    retry_delay = retry_delay.saturating_mul(2).min(self.retry_max);
                }
            }
        }
    }

    async fn run(&self, cancellation: &CancellationToken) {
        tokio::join!(self.collect(cancellation), self.forward(cancellation));
    }
}

/// Load the Edge configuration and run the local Orca collector.
pub async fn run(config_path: PathBuf) -> Result<()> {
    let config = Config::load(config_path)?;
    crate::init_tracing(&config.logging.level);
    let edge = OrcaEdge::new(&config)?;
    tracing::info!(
        edge_id = %edge.client.edge_id(),
        environment_id = %edge.environment_id,
        endpoint = %edge.client.endpoint(),
        "events-bridge Orca edge started"
    );
    let cancellation = CancellationToken::new();
    tokio::join!(edge.run(&cancellation), async {
        shutdown_signal().await;
        cancellation.cancel();
    });
    Ok(())
}
