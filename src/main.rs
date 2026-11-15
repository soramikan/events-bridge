//! CLI entry point.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "events-bridge",
    version,
    about = "MCP Events webhook bridge for T3 Code and GitHub",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Central hub: MCP Streamable HTTP server, SQLite store, webhook dispatcher.
    Hub {
        /// Path to the TOML configuration file.
        #[arg(
            long,
            env = "EVENTS_BRIDGE_CONFIG",
            default_value = "/etc/events-bridge/config.toml"
        )]
        config: PathBuf,
    },
    /// Edge collector: forward T3 Code state to a central hub.
    Edge {
        /// Path to the TOML configuration file.
        #[arg(
            long,
            env = "EVENTS_BRIDGE_CONFIG",
            default_value = "/etc/events-bridge/config.toml"
        )]
        config: PathBuf,
    },
    /// Serve the MCP surface over stdin/stdout.
    Stdio {
        /// Optional TOML configuration file.
        #[arg(long, env = "EVENTS_BRIDGE_CONFIG")]
        config: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Hub { config } => events_bridge::transport::http::run(config).await,
        Command::Edge { config } => events_bridge::transport::edge::run(config).await,
        Command::Stdio { config } => events_bridge::transport::stdio::run(config).await,
    }
}
