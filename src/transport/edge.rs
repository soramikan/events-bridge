//! Edge collector skeleton.
//!
//! Phase 1 covers the hub and the MCP Events surface. The edge collector that
//! forwards T3 Code state from other hosts is implemented in a later phase.

use std::path::PathBuf;

use anyhow::{Result, bail};

use crate::config::Config;

/// Explain that the edge collector is not implemented yet.
pub async fn run(config_path: PathBuf) -> Result<()> {
    // Validate an existing configuration so deployment mistakes surface early,
    // but still print the implementation status when it does not exist yet.
    if config_path.exists() {
        let config = Config::load(config_path)?;
        tracing::debug!(bind = %config.server.bind, "edge configuration is valid");
    }
    bail!(
        "the `edge` collector is not implemented in Phase 1. \
         Run `events-bridge hub --config <path>` for the MCP Events server."
    )
}
