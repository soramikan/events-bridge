//! CLI entry point.

use std::path::PathBuf;

use anyhow::bail;
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
    /// Probe, poll, or acknowledge a server-side polling consumer.
    Poll {
        /// Consumer profile name, e.g. `muse`.
        #[arg(long)]
        consumer: String,
        /// Path to the TOML configuration file.
        #[arg(long, env = "EVENTS_BRIDGE_CONFIG")]
        config: Option<PathBuf>,
        /// Override the configured SQLite database path.
        #[arg(long)]
        db: Option<PathBuf>,
        /// Only count unread events; do not fetch them.
        #[arg(long)]
        probe: bool,
        /// Advance the consumer cursor to this sequence.
        #[arg(long)]
        ack: Option<i64>,
        /// Maximum events returned by one poll (1..=200).
        #[arg(long)]
        limit: Option<usize>,
    },
    /// Advance a polling consumer cursor (alias for `poll --ack`).
    Ack {
        /// Consumer profile name, e.g. `muse`.
        #[arg(long)]
        consumer: String,
        /// Sequence to acknowledge (0..=latest sequence).
        #[arg(long = "up-to")]
        up_to: i64,
        /// Path to the TOML configuration file.
        #[arg(long, env = "EVENTS_BRIDGE_CONFIG")]
        config: Option<PathBuf>,
        /// Override the configured SQLite database path.
        #[arg(long)]
        db: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Hub { config } => events_bridge::transport::http::run(config).await,
        Command::Edge { config } => events_bridge::transport::edge::run(config).await,
        Command::Stdio { config } => events_bridge::transport::stdio::run(config).await,
        Command::Poll {
            consumer,
            config,
            db,
            probe,
            ack,
            limit,
        } => {
            if probe && ack.is_some() {
                bail!("--probe and --ack cannot be used together");
            }
            if probe && limit.is_some() {
                bail!("--limit is only valid for polls");
            }
            if let Some(sequence) = ack {
                let result =
                    events_bridge::cli::ack(&consumer, sequence, config.as_deref(), db.as_deref())?;
                events_bridge::cli::write_json(&result)
            } else if probe {
                let result =
                    events_bridge::cli::probe(&consumer, config.as_deref(), db.as_deref())?;
                events_bridge::cli::write_json(&result)
            } else {
                let result =
                    events_bridge::cli::poll(&consumer, config.as_deref(), db.as_deref(), limit)?;
                events_bridge::cli::write_json(&result)
            }
        }
        Command::Ack {
            consumer,
            up_to,
            config,
            db,
        } => {
            let result =
                events_bridge::cli::ack(&consumer, up_to, config.as_deref(), db.as_deref())?;
            events_bridge::cli::write_json(&result)
        }
    }
}
