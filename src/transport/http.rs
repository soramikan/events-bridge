//! Hub HTTP entry point.

use std::path::PathBuf;

use anyhow::Result;

use crate::{config::Config, hub::Hub};

/// Load configuration and serve the hub until shutdown.
pub async fn run(config_path: PathBuf) -> Result<()> {
    let config = Config::load(config_path)?;
    crate::init_tracing(&config.logging.level);
    Hub::new(config)?.serve().await
}
