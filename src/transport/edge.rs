//! Legacy T3 Edge implementation retained for protocol compatibility tests.
//!
//! The edge keeps its own SQLite database with the same T3 projection tables
//! and `source_cursors` as the hub. It derives a [`T3WriteBatch`] locally,
//! POSTs it to the hub, and only commits the batch (including the cursor)
//! after the hub answered `2xx`. A hub outage therefore never advances the
//! cursor, and the next retry resumes from the last acknowledged sequence.

use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result, bail};
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::{
    app::read_secret_env,
    collectors::{
        T3CollectorSettings, T3Source,
        t3_state::{T3Reducer, T3SourceEvent},
    },
    config::Config,
    edge_protocol::{EDGE_INGEST_PATH, EdgeT3IngestRequest},
    store::{EdgePendingSnapshot, Repository, T3Snapshot},
    util::{now_rfc3339, random_hex},
};

use super::signed_edge::SignedEdgeClient;

/// One edge synchronization pass summary.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EdgeSyncSummary {
    /// A first-start snapshot was sent.
    pub snapshot: bool,
    /// Upstream events forwarded and committed locally.
    pub processed: usize,
    /// New bridge events accepted by the hub.
    pub emitted: usize,
}

/// Edge collector.
pub struct Edge {
    environment_id: String,
    retry_initial: Duration,
    retry_max: Duration,
    poll_interval: Duration,
    watch_wal: bool,
    batch_size: usize,
    error_excerpt_max_chars: usize,
    max_snapshot_chunk_bytes: usize,
    web_base_url: Option<Url>,
    state_db_path: PathBuf,
    repo: Arc<Repository>,
    source: Mutex<SourceState>,
    client: SignedEdgeClient,
}

struct SourceState {
    source: T3Source,
    identity: Option<FileIdentity>,
    needs_reopen: bool,
}

impl Edge {
    /// Build an edge collector from the daemon configuration.
    pub fn new(config: &Config) -> Result<Self> {
        config.validate().context("invalid configuration")?;
        config.edge.validate_for_edge()?;

        let secret_env = config
            .edge
            .shared_secret_env
            .as_deref()
            .context("edge.shared_secret_env is required")?;
        let secret = read_secret_env(secret_env, "edge forwarding")?;

        let settings = T3CollectorSettings::from_config_with_hostname_fallback(config)?;
        let environment_id = settings.environment_id.clone();
        let edge_id = resolve_edge_id(config, &environment_id);

        let repo =
            Arc::new(Repository::open(&config.database.path).context("opening edge local store")?);
        let identity = file_identity(&settings.state_db_path);
        let source = T3Source::open(&settings.state_db_path)?;

        let client = SignedEdgeClient::new(&config.edge, EDGE_INGEST_PATH, edge_id, secret)?;

        Ok(Self {
            environment_id,
            retry_initial: Duration::from_millis(config.edge.retry_initial_ms.max(1)),
            retry_max: Duration::from_millis(
                config
                    .edge
                    .retry_max_ms
                    .max(config.edge.retry_initial_ms.max(1)),
            ),
            poll_interval: settings.poll_interval,
            watch_wal: settings.watch_wal,
            batch_size: settings.batch_size,
            error_excerpt_max_chars: settings.error_excerpt_max_chars,
            max_snapshot_chunk_bytes: config.edge.max_snapshot_chunk_bytes,
            web_base_url: settings.web_base_url,
            state_db_path: settings.state_db_path,
            repo,
            source: Mutex::new(SourceState {
                source,
                identity,
                needs_reopen: false,
            }),
            client,
        })
    }

    /// Stable edge identifier sent in `X-Edge-Id`.
    pub fn edge_id(&self) -> &str {
        self.client.edge_id()
    }

    /// T3 environment id carried by the forwarded state.
    pub fn environment_id(&self) -> &str {
        &self.environment_id
    }

    /// Hub ingest endpoint.
    pub fn endpoint(&self) -> &Url {
        self.client.endpoint()
    }

    /// Local edge database.
    pub fn repository(&self) -> &Arc<Repository> {
        &self.repo
    }

    /// Forward everything currently available once.
    ///
    /// The local cursor is advanced only after the hub accepted the
    /// corresponding request. A failure leaves the cursor untouched.
    pub async fn sync_once(&self) -> Result<EdgeSyncSummary> {
        self.sync_once_with_cancellation(&CancellationToken::new())
            .await
    }

    /// Forward everything currently available once, stopping early when
    /// `cancellation` is triggered.
    ///
    /// Cancellation is checked before each page read and before each batch.
    /// A batch whose POST already reached the hub is always committed locally
    /// before the loop exits, so the local cursor never lags an acknowledged
    /// hub write.
    pub async fn sync_once_with_cancellation(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<EdgeSyncSummary> {
        let mut summary = EdgeSyncSummary::default();
        let pending = self.repo.get_edge_pending_snapshot(&self.environment_id)?;
        let cursor = self.repo.get_t3_cursor(&self.environment_id)?;

        if pending.is_some() || cursor.is_none() {
            if cancellation.is_cancelled() {
                return Ok(summary);
            }
            summary.snapshot = self.send_snapshot(cancellation).await?;
            return Ok(summary);
        }
        let mut cursor = cursor.expect("cursor checked above");

        let max_sequence = self.with_source(|source| source.max_sequence())?;
        if max_sequence < cursor {
            tracing::warn!(
                environment_id = %self.environment_id,
                saved_cursor = cursor,
                upstream_max_sequence = max_sequence,
                "upstream T3 sequence regressed; re-sending snapshot"
            );
            if cancellation.is_cancelled() {
                return Ok(summary);
            }
            summary.snapshot = self.send_snapshot(cancellation).await?;
            return Ok(summary);
        }

        loop {
            if cancellation.is_cancelled() {
                break;
            }
            let events = self.with_source(|source| source.events_after(cursor, self.batch_size))?;
            let fetched = events.len();
            if fetched == 0 {
                break;
            }
            for event in events {
                if cancellation.is_cancelled() {
                    break;
                }
                let batch = self.reduce(&event)?;
                self.post(&EdgeT3IngestRequest::Batches {
                    batches: vec![batch.clone()],
                })
                .await?;
                let outcome = self.repo.apply_t3_batch(&batch)?;
                summary.processed += 1;
                summary.emitted += outcome
                    .events
                    .iter()
                    .filter(|event| !event.duplicate)
                    .count();
                cursor = event.sequence;
                if cancellation.is_cancelled() {
                    break;
                }
            }
            if cancellation.is_cancelled() || fetched < self.batch_size {
                break;
            }
        }
        Ok(summary)
    }

    /// Run until cancelled, retrying failed forwards with exponential backoff.
    pub async fn run(self, cancellation: CancellationToken) -> Result<()> {
        let mut delay = self.retry_initial;
        loop {
            if cancellation.is_cancelled() {
                break;
            }
            match self.sync_once_with_cancellation(&cancellation).await {
                Ok(summary) => {
                    delay = self.retry_initial;
                    if summary.snapshot {
                        tracing::info!(
                            edge_id = %self.edge_id(),
                            environment_id = %self.environment_id,
                            "edge snapshot accepted by hub"
                        );
                    }
                    if summary.processed > 0 {
                        tracing::info!(
                            edge_id = %self.edge_id(),
                            environment_id = %self.environment_id,
                            processed = summary.processed,
                            emitted = summary.emitted,
                            "edge forwarded T3 events"
                        );
                        continue;
                    }
                }
                Err(error) => {
                    tracing::warn!(
                        edge_id = %self.edge_id(),
                        endpoint = %self.endpoint(),
                        delay_ms = delay.as_millis(),
                        %error,
                        "edge forward failed; retrying"
                    );
                    tokio::select! {
                        _ = cancellation.cancelled() => break,
                        _ = tokio::time::sleep(delay) => {}
                    }
                    delay = (delay * 2).min(self.retry_max);
                    continue;
                }
            }

            let tick = if self.watch_wal {
                self.poll_interval.min(Duration::from_millis(250))
            } else {
                self.poll_interval
            };
            tokio::select! {
                _ = cancellation.cancelled() => break,
                _ = tokio::time::sleep(tick) => {}
            }
        }
        Ok(())
    }

    /// Send the pending snapshot, or capture and persist one first.
    ///
    /// Returns `true` when the hub acknowledged the snapshot and the local
    /// cursor/pending row were committed.
    async fn send_snapshot(&self, cancellation: &CancellationToken) -> Result<bool> {
        let pending = match self.repo.get_edge_pending_snapshot(&self.environment_id)? {
            Some(pending) => pending,
            None => {
                let (snapshot, max_sequence) =
                    self.with_source(|source| source.snapshot(&self.environment_id))?;
                let pending = EdgePendingSnapshot {
                    environment_id: self.environment_id.clone(),
                    snapshot_id: random_hex(16),
                    max_sequence,
                    snapshot,
                    created_at: now_rfc3339(),
                };
                // Persist before the first POST: a crash or a lost response
                // must retry this exact snapshot, not capture a newer one.
                self.repo.save_edge_pending_snapshot(&pending)?;
                pending
            }
        };

        if cancellation.is_cancelled() {
            return Ok(false);
        }
        self.send_snapshot_payload(&pending, cancellation).await?;
        self.repo.apply_t3_snapshot_and_clear_pending(
            &self.environment_id,
            &pending.snapshot,
            pending.max_sequence,
        )?;
        Ok(true)
    }

    async fn send_snapshot_payload(
        &self,
        pending: &EdgePendingSnapshot,
        cancellation: &CancellationToken,
    ) -> Result<()> {
        let single = EdgeT3IngestRequest::Snapshot {
            environment_id: pending.environment_id.clone(),
            max_sequence: pending.max_sequence,
            snapshot: pending.snapshot.clone(),
        };
        if serde_json::to_vec(&single)?.len() <= self.max_snapshot_chunk_bytes {
            self.post(&single).await?;
            return Ok(());
        }

        let total_chunks =
            if let Some(chunks) = self.split_snapshot(&pending.snapshot, &pending.snapshot_id)? {
                let total = chunks.len();
                for (chunk_index, snapshot) in chunks.into_iter().enumerate() {
                    if cancellation.is_cancelled() {
                        bail!("edge snapshot upload cancelled before chunk {chunk_index}");
                    }
                    self.post(&EdgeT3IngestRequest::SnapshotChunk {
                        environment_id: pending.environment_id.clone(),
                        snapshot_id: pending.snapshot_id.clone(),
                        chunk_index,
                        snapshot,
                    })
                    .await?;
                }
                total
            } else {
                let parts = self.split_snapshot_raw(&pending.snapshot, &pending.snapshot_id)?;
                let total = parts.len();
                for (chunk_index, data) in parts.into_iter().enumerate() {
                    if cancellation.is_cancelled() {
                        bail!("edge snapshot upload cancelled before part {chunk_index}");
                    }
                    self.post(&EdgeT3IngestRequest::SnapshotPart {
                        environment_id: pending.environment_id.clone(),
                        snapshot_id: pending.snapshot_id.clone(),
                        chunk_index,
                        data,
                    })
                    .await?;
                }
                total
            };
        if cancellation.is_cancelled() {
            bail!("edge snapshot upload cancelled before commit");
        }
        self.post(&EdgeT3IngestRequest::SnapshotCommit {
            environment_id: pending.environment_id.clone(),
            snapshot_id: pending.snapshot_id.clone(),
            max_sequence: pending.max_sequence,
            total_chunks,
        })
        .await?;
        Ok(())
    }

    /// Split a snapshot into entity chunks that each fit within
    /// `max_snapshot_chunk_bytes`. Returns `Ok(None)` when at least one
    /// individual entity exceeds `max_snapshot_chunk_bytes`, signalling the
    /// caller to use [`Self::split_snapshot_raw`].
    fn split_snapshot(
        &self,
        snapshot: &T3Snapshot,
        snapshot_id: &str,
    ) -> Result<Option<Vec<T3Snapshot>>> {
        enum Item {
            Project(crate::store::T3Project),
            Thread(crate::store::T3Thread),
            Run(crate::store::T3Run),
            Approval(crate::store::T3Approval),
        }

        let mut items = Vec::new();
        items.extend(snapshot.projects.iter().cloned().map(Item::Project));
        items.extend(snapshot.threads.iter().cloned().map(Item::Thread));
        items.extend(snapshot.runs.iter().cloned().map(Item::Run));
        items.extend(snapshot.approvals.iter().cloned().map(Item::Approval));

        let mut chunks: Vec<T3Snapshot> = Vec::new();
        let mut current = T3Snapshot::default();
        let mut current_len = self.empty_chunk_request_len(snapshot_id, 0)?;
        let mut counts = [0usize; 4];

        for item in items {
            let (item_len, slot) = match &item {
                Item::Project(value) => (serde_json::to_vec(value)?.len(), 0),
                Item::Thread(value) => (serde_json::to_vec(value)?.len(), 1),
                Item::Run(value) => (serde_json::to_vec(value)?.len(), 2),
                Item::Approval(value) => (serde_json::to_vec(value)?.len(), 3),
            };
            let added = item_len + usize::from(counts[slot] > 0);
            if current_len + added > self.max_snapshot_chunk_bytes {
                if current.is_empty() {
                    return Ok(None);
                }
                chunks.push(std::mem::take(&mut current));
                counts = [0; 4];
                current_len = self.empty_chunk_request_len(snapshot_id, chunks.len())?;
                if current_len + item_len > self.max_snapshot_chunk_bytes {
                    return Ok(None);
                }
                current_len += item_len;
            } else {
                current_len += added;
            }
            match item {
                Item::Project(value) => current.projects.push(value),
                Item::Thread(value) => current.threads.push(value),
                Item::Run(value) => current.runs.push(value),
                Item::Approval(value) => current.approvals.push(value),
            }
            counts[slot] += 1;
        }
        if !current.is_empty() {
            chunks.push(current);
        }
        if chunks.is_empty() {
            return Ok(None);
        }
        Ok(Some(chunks))
    }

    fn split_snapshot_raw(&self, snapshot: &T3Snapshot, snapshot_id: &str) -> Result<Vec<String>> {
        use base64::Engine;

        let raw = serde_json::to_vec(snapshot)?;
        let sample = EdgeT3IngestRequest::SnapshotPart {
            environment_id: self.environment_id.clone(),
            snapshot_id: snapshot_id.to_string(),
            chunk_index: raw.len(),
            data: String::new(),
        };
        let overhead = serde_json::to_vec(&sample)?.len();
        let max_b64_len = self.max_snapshot_chunk_bytes.saturating_sub(overhead);
        let max_raw_bytes = (max_b64_len / 4) * 3;
        if max_raw_bytes == 0 {
            bail!(
                "edge.max_snapshot_chunk_bytes ({} bytes) is too small for SnapshotPart envelope ({} bytes)",
                self.max_snapshot_chunk_bytes,
                overhead
            );
        }
        Ok(raw
            .chunks(max_raw_bytes)
            .map(|slice| base64::engine::general_purpose::STANDARD.encode(slice))
            .collect())
    }

    fn empty_chunk_request_len(&self, snapshot_id: &str, chunk_index: usize) -> Result<usize> {
        let request = EdgeT3IngestRequest::SnapshotChunk {
            environment_id: self.environment_id.clone(),
            snapshot_id: snapshot_id.to_string(),
            chunk_index,
            snapshot: T3Snapshot::default(),
        };
        Ok(serde_json::to_vec(&request)?.len())
    }

    fn reduce(&self, event: &T3SourceEvent) -> Result<crate::store::T3WriteBatch> {
        self.with_source(|source| {
            let reducer = T3Reducer::new(
                &self.environment_id,
                &self.repo,
                source,
                self.web_base_url.as_ref(),
            )
            .with_error_excerpt_max_chars(self.error_excerpt_max_chars);
            reducer.reduce(event)
        })
    }

    async fn post(&self, request: &EdgeT3IngestRequest) -> Result<()> {
        self.client.post(serde_json::to_vec(request)?).await
    }

    fn with_source<T>(&self, f: impl FnOnce(&T3Source) -> Result<T>) -> Result<T> {
        let mut guard = self
            .source
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let source = match self.ensure_source(&mut guard) {
            Ok(source) => source,
            Err(error) => {
                guard.needs_reopen = true;
                return Err(error);
            }
        };
        match f(source) {
            Ok(value) => Ok(value),
            Err(error) => {
                guard.needs_reopen = true;
                Err(error)
            }
        }
    }

    fn ensure_source<'a>(&self, guard: &'a mut SourceState) -> Result<&'a T3Source> {
        let current_identity = file_identity(&self.state_db_path);
        if guard.needs_reopen || current_identity != guard.identity {
            let reopened = T3Source::open(&self.state_db_path)?;
            guard.source = reopened;
            guard.identity = current_identity;
            guard.needs_reopen = false;
            tracing::info!(
                path = %self.state_db_path.display(),
                "edge reopened T3 state database"
            );
        }
        Ok(&guard.source)
    }
}

fn resolve_edge_id(config: &Config, environment_id: &str) -> String {
    if let Some(value) = config
        .edge
        .edge_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return value.to_string();
    }
    if let Some(value) = config
        .collectors
        .t3
        .environment_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return value.to_string();
    }
    if !environment_id.trim().is_empty() {
        return environment_id.to_string();
    }
    // `Edge::new` resolves a non-empty environment id before this point, so
    // this is only a defensive fallback. Never use a shared literal such as
    // "edge": it would make independent hosts collide.
    String::new()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
    #[cfg(not(unix))]
    sig: (u64, u128),
}

fn file_identity(path: &Path) -> Option<FileIdentity> {
    let metadata = fs::metadata(path).ok()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Some(FileIdentity {
            dev: metadata.dev(),
            ino: metadata.ino(),
        })
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        Some(FileIdentity {
            sig: file_signature(path)?,
        })
    }
}

#[cfg(not(unix))]
fn file_signature(path: &Path) -> Option<(u64, u128)> {
    let metadata = fs::metadata(path).ok()?;
    let modified = metadata
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_nanos();
    Some((metadata.len(), modified))
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edge_id_prefers_explicit_configuration() {
        let mut config = Config::default();
        config.edge.edge_id = Some("mac-mini".into());
        assert_eq!(resolve_edge_id(&config, "env-1"), "mac-mini");

        config.edge.edge_id = None;
        config.collectors.t3.environment_id = Some("env-2".into());
        assert_eq!(resolve_edge_id(&config, "env-1"), "env-2");

        config.collectors.t3.environment_id = None;
        assert_eq!(resolve_edge_id(&config, "env-1"), "env-1");
    }

    #[test]
    fn edge_requires_hub_url_and_a_secret_value() {
        let mut config = Config::default();
        config.edge.shared_secret_env = Some("EVENTS_BRIDGE_TEST_EDGE_SECRET".into());
        match Edge::new(&config) {
            Ok(_) => panic!("edge without hub_url must fail"),
            Err(error) => assert!(error.to_string().contains("hub_url"), "{error}"),
        }

        config.edge.hub_url = Some("http://127.0.0.1:1".into());
        config.edge.shared_secret_env = Some("EVENTS_BRIDGE_TEST_MISSING_EDGE_SECRET".into());
        config.collectors.t3.state_db_path =
            std::env::temp_dir().join("events-bridge-missing-statev2.sqlite");
        match Edge::new(&config) {
            Ok(_) => panic!("edge without a secret value must fail"),
            Err(error) => assert!(error.to_string().contains("unset"), "{error}"),
        }
    }

    #[test]
    fn ingest_path_is_stable() {
        assert_eq!(crate::edge_protocol::EDGE_INGEST_PATH, "/internal/edge/t3");
    }
}
