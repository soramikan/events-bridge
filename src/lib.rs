//! events-bridge: MCP Events webhook bridge for T3 Code and GitHub.
//!
//! The crate is split into a library and a thin CLI so integration tests can
//! drive the hub, the store, and the dispatcher directly.

pub mod app;
pub mod auth;
pub mod cli;
pub mod collectors;
pub mod config;
pub mod consumers;
pub mod delivery;
pub mod edge_protocol;
pub mod event;
pub mod hub;
pub mod mcp;
pub mod store;
pub mod transport;
pub mod util;

/// Initialize `tracing` with a stderr writer.
///
/// stdout belongs to the stdio MCP transport, so logs must never go there.
pub fn init_tracing(filter: &str) {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_new(filter).unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}
