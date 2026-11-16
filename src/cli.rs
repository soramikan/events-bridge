//! CLI helpers for the polling consumer commands.
//!
//! These commands write exactly one JSON document to stdout. Diagnostics and
//! tracing belong on stderr, so shell hooks can pipe stdout straight into
//! `jq` without stripping log lines.

use std::{io::Write, path::Path, sync::Arc};

use anyhow::{Context, Result};
use serde::Serialize;

use crate::{
    config::Config,
    consumers::{ConsumerAckResult, ConsumerPoll, ConsumerProbe, ConsumerService},
    store::Repository,
};

/// Default system configuration path consulted when `--config` is absent.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/events-bridge/config.toml";

/// Load effective configuration for a consumer command.
///
/// Precedence: an explicit `--config`, then `/etc/events-bridge/config.toml`
/// when it exists, then built-in defaults. `--db` always overrides
/// `database.path`.
pub fn load_config(config_path: Option<&Path>, db_path: Option<&Path>) -> Result<Config> {
    let mut config = match config_path {
        Some(path) => Config::load(path)?,
        None if Path::new(DEFAULT_CONFIG_PATH).is_file() => Config::load(DEFAULT_CONFIG_PATH)?,
        None => Config::default(),
    };
    if let Some(db) = db_path {
        config.database.path = db.to_path_buf();
    }
    config.validate().context("invalid configuration")?;
    Ok(config)
}

/// Build a consumer service backed by the configured database.
pub fn service(config: &Config) -> Result<ConsumerService> {
    let repo = Arc::new(Repository::open(&config.database.path).context("opening event store")?);
    Ok(ConsumerService::from_config(repo, config))
}

/// Probe one consumer.
pub fn probe(
    consumer: &str,
    config_path: Option<&Path>,
    db_path: Option<&Path>,
) -> Result<ConsumerProbe> {
    let config = load_config(config_path, db_path)?;
    Ok(service(&config)?.probe(consumer)?)
}

/// Poll one consumer without acknowledging.
pub fn poll(
    consumer: &str,
    config_path: Option<&Path>,
    db_path: Option<&Path>,
    limit: Option<usize>,
) -> Result<ConsumerPoll> {
    let config = load_config(config_path, db_path)?;
    Ok(service(&config)?.poll(consumer, limit)?)
}

/// Acknowledge events up to `up_to_sequence`.
pub fn ack(
    consumer: &str,
    up_to_sequence: i64,
    config_path: Option<&Path>,
    db_path: Option<&Path>,
) -> Result<ConsumerAckResult> {
    let config = load_config(config_path, db_path)?;
    Ok(service(&config)?.ack(consumer, up_to_sequence)?)
}

/// Write one compact JSON document plus a trailing newline to stdout.
pub fn write_json<T: Serialize>(value: &T) -> Result<()> {
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    serde_json::to_writer(&mut lock, value).context("serializing consumer response")?;
    lock.write_all(b"\n").context("writing consumer response")?;
    Ok(())
}
