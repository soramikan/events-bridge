//! Daemon configuration loaded from TOML.
//!
//! Secrets are never stored in the configuration file. The only credential the
//! hub reads is a bearer token, and it is named indirectly through
//! `auth.token_env` so the value comes from the process environment.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

/// Absolute protocol ceiling for one serialized webhook body (256 KiB).
///
/// The MCP Events protocol caps a single delivery at 256 KiB. The configured
/// value may lower this bound but never raise it.
pub const MAX_WEBHOOK_BODY_BYTES: usize = 256 * 1024;

/// Top-level configuration.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// HTTP server settings.
    pub server: ServerConfig,
    /// SQLite settings.
    pub database: DatabaseConfig,
    /// Inbound MCP authentication.
    pub auth: AuthConfig,
    /// Webhook subscription defaults.
    pub subscriptions: SubscriptionConfig,
    /// Delivery worker settings.
    pub delivery: DeliveryConfig,
    /// Logging settings.
    pub logging: LoggingConfig,
    /// Upstream collectors.
    pub collectors: CollectorsConfig,
}

/// HTTP listener settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    /// Address passed to `TcpListener::bind`.
    pub bind: String,
    /// Accepted `Host` header authorities for the Streamable HTTP endpoint.
    pub allowed_hosts: Vec<String>,
    /// Public base URL, used for diagnostics only in Phase 1.
    pub public_base_url: Option<String>,
    /// Enables `POST /internal/events`.
    ///
    /// Keep this disabled unless the endpoint is reachable only from a trusted
    /// network (or protected with `internal_token_env`).
    pub enable_internal_ingest: bool,
    /// Environment variable holding the internal ingest bearer token.
    pub internal_token_env: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:8787".to_string(),
            allowed_hosts: vec!["localhost".into(), "127.0.0.1".into(), "::1".into()],
            public_base_url: None,
            enable_internal_ingest: false,
            internal_token_env: None,
        }
    }
}

/// SQLite settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DatabaseConfig {
    /// Database file path. Parent directories are created on startup.
    pub path: PathBuf,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from("events-bridge.db"),
        }
    }
}

/// Inbound authentication settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuthConfig {
    /// Environment variable holding the bearer token. When absent, the server
    /// runs unauthenticated and every request is attributed to `principal`.
    pub token_env: Option<String>,
    /// Principal used for authenticated requests and, when no token is
    /// configured, for every request.
    pub principal: String,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            token_env: None,
            principal: "local".into(),
        }
    }
}

/// Subscription lifetime settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SubscriptionConfig {
    /// TTL granted when the client omits `ttlMs`.
    pub default_ttl_secs: u64,
    /// Lower clamp for client-suggested TTLs.
    pub min_ttl_secs: u64,
    /// Upper clamp for client-suggested TTLs.
    pub max_ttl_secs: u64,
}

impl Default for SubscriptionConfig {
    fn default() -> Self {
        Self {
            default_ttl_secs: 3600,
            min_ttl_secs: 60,
            max_ttl_secs: 86_400,
        }
    }
}

/// Delivery worker settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DeliveryConfig {
    /// Per-attempt HTTP timeout.
    pub timeout_secs: u64,
    /// Attempts before an event is abandoned.
    pub max_attempts: i64,
    /// First retry delay.
    pub base_backoff_ms: u64,
    /// Retry delay ceiling.
    pub max_backoff_ms: u64,
    /// Maximum serialized webhook body size (protocol limit: 256 KiB).
    pub max_body_bytes: usize,
    /// Lease after which an `in_progress` delivery is considered abandoned
    /// and may be claimed again by the worker.
    pub lease_secs: u64,
    /// Idle poll interval, also the wake-up safety net.
    pub poll_interval_ms: u64,
}

impl Default for DeliveryConfig {
    fn default() -> Self {
        Self {
            timeout_secs: 10,
            max_attempts: 5,
            base_backoff_ms: 1_000,
            max_backoff_ms: 300_000,
            max_body_bytes: MAX_WEBHOOK_BODY_BYTES,
            lease_secs: 300,
            poll_interval_ms: 5_000,
        }
    }
}

/// Upstream collector settings.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct CollectorsConfig {
    /// T3 Code collector settings.
    pub t3: T3CollectorConfig,
}

/// T3 Code collector settings.
///
/// The collector reads the T3 Code SQLite database strictly read-only. It
/// never contains credentials: T3 Code authenticates itself and exposes no
/// token to this process.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct T3CollectorConfig {
    /// Start the collector with the hub.
    pub enabled: bool,
    /// Path to T3 Code's `statev2.sqlite`. Empty resolves to
    /// `~/.t3/userdata/statev2.sqlite`.
    pub state_db_path: PathBuf,
    /// Explicit environment id. When empty, `environment_id_path` or the
    /// `environment-id` file next to the state database is used.
    pub environment_id: Option<String>,
    /// Path to the T3 Code environment id file.
    pub environment_id_path: Option<PathBuf>,
    /// Optional T3 Code web base URL used to build deep links.
    pub t3_web_base_url: Option<String>,
    /// Full polling fallback interval.
    pub poll_interval_ms: u64,
    /// Probe the WAL/database file metadata at a short interval for lower
    /// latency. This is still polling; no inotify dependency is required.
    pub watch_wal: bool,
    /// Upstream events read per query.
    pub batch_size: usize,
}

impl Default for T3CollectorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            state_db_path: PathBuf::new(),
            environment_id: None,
            environment_id_path: None,
            t3_web_base_url: None,
            poll_interval_ms: 1_000,
            watch_wal: true,
            batch_size: 500,
        }
    }
}

/// Logging settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LoggingConfig {
    /// `tracing` filter directive.
    pub level: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".into(),
        }
    }
}

impl Config {
    /// Load configuration from a TOML file.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("reading configuration file {}", path.display()))?;
        Self::parse(&contents)
            .with_context(|| format!("parsing configuration file {}", path.display()))
    }

    /// Parse configuration from a TOML string and validate it.
    pub fn parse(contents: &str) -> Result<Self> {
        let config: Self = toml::from_str(contents)?;
        config.validate()?;
        Ok(config)
    }

    /// Validate cross-field invariants that serde cannot express.
    pub fn validate(&self) -> Result<()> {
        if self.delivery.max_body_bytes == 0 {
            bail!("delivery.max_body_bytes must be greater than zero");
        }
        if self.delivery.max_body_bytes > MAX_WEBHOOK_BODY_BYTES {
            bail!(
                "delivery.max_body_bytes must not exceed the 256 KiB protocol limit \
                 ({MAX_WEBHOOK_BODY_BYTES} bytes), got {}",
                self.delivery.max_body_bytes
            );
        }
        if self.delivery.lease_secs == 0 {
            bail!("delivery.lease_secs must be greater than zero");
        }
        if self.subscriptions.min_ttl_secs > self.subscriptions.max_ttl_secs {
            bail!(
                "subscriptions.min_ttl_secs must not exceed subscriptions.max_ttl_secs, got {} > {}",
                self.subscriptions.min_ttl_secs,
                self.subscriptions.max_ttl_secs
            );
        }
        let t3 = &self.collectors.t3;
        if t3.poll_interval_ms == 0 {
            bail!("collectors.t3.poll_interval_ms must be greater than zero");
        }
        if t3.batch_size == 0 {
            bail!("collectors.t3.batch_size must be greater than zero");
        }
        if t3
            .environment_id
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            bail!("collectors.t3.environment_id must not be empty when set");
        }
        if let Some(base) = t3.t3_web_base_url.as_deref() {
            let url = url::Url::parse(base)
                .with_context(|| format!("collectors.t3.t3_web_base_url `{base}` is not a URL"))?;
            if !matches!(url.scheme(), "http" | "https") {
                bail!("collectors.t3.t3_web_base_url must use http or https");
            }
            if url.cannot_be_a_base() || url.query().is_some() || url.fragment().is_some() {
                bail!(
                    "collectors.t3.t3_web_base_url must be a hierarchical URL without query or fragment"
                );
            }
        }
        Ok(())
    }

    /// Configuration suitable for local tests: no auth, internal ingest on.
    #[doc(hidden)]
    pub fn for_tests(database_path: impl Into<PathBuf>) -> Self {
        let mut config = Self::default();
        config.database.path = database_path.into();
        config.server.bind = "127.0.0.1:0".into();
        config.server.enable_internal_ingest = true;
        config.delivery.base_backoff_ms = 10;
        config.delivery.max_backoff_ms = 50;
        config.delivery.poll_interval_ms = 25;
        config.delivery.timeout_secs = 5;
        // Keep lease recovery observable in integration tests.
        config.delivery.lease_secs = 1;
        config.subscriptions.min_ttl_secs = 1;
        config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_configuration_parses() {
        let example = include_str!("../config.example.toml");
        let config = Config::parse(example).expect("example config parses");
        assert_eq!(config.server.bind, "127.0.0.1:8787");
        assert_eq!(config.subscriptions.max_ttl_secs, 86_400);
        assert_eq!(config.delivery.max_body_bytes, MAX_WEBHOOK_BODY_BYTES);
    }

    #[test]
    fn body_size_limit_rejects_more_than_256_kib() {
        let over = Config::parse("[delivery]\nmax_body_bytes = 262145\n")
            .expect_err("over-limit body size must fail");
        assert!(over.to_string().contains("256 KiB"), "{over}");

        // The exact protocol ceiling is accepted.
        let boundary = Config::parse("[delivery]\nmax_body_bytes = 262144\n")
            .expect("boundary body size is accepted");
        assert_eq!(boundary.delivery.max_body_bytes, MAX_WEBHOOK_BODY_BYTES);

        let zero = Config::parse("[delivery]\nmax_body_bytes = 0\n")
            .expect_err("zero body size must fail");
        assert!(zero.to_string().contains("greater than zero"), "{zero}");
    }

    #[test]
    fn zero_lease_is_rejected() {
        let error =
            Config::parse("[delivery]\nlease_secs = 0\n").expect_err("zero lease must fail");
        assert!(error.to_string().contains("lease_secs"), "{error}");
    }

    #[test]
    fn inverted_subscription_ttl_bounds_are_rejected() {
        let error = Config::parse("[subscriptions]\nmin_ttl_secs = 120\nmax_ttl_secs = 60\n")
            .expect_err("inverted subscription TTL bounds must fail");
        assert!(error.to_string().contains("min_ttl_secs"), "{error}");
    }

    #[test]
    fn unknown_keys_are_rejected() {
        let error = Config::parse("[server]\nbind = \"127.0.0.1:1\"\nsurprise = true\n")
            .expect_err("unknown key must fail");
        assert!(error.to_string().contains("surprise"), "{error}");
    }

    #[test]
    fn t3_collector_settings_parse_and_validate() {
        let config = Config::parse(
            "[collectors.t3]\n\
             enabled = true\n\
             environment_id = \"env-1\"\n\
             t3_web_base_url = \"https://t3.example.com\"\n\
             poll_interval_ms = 500\n\
             watch_wal = false\n\
             batch_size = 42\n",
        )
        .expect("collector config parses");
        let t3 = &config.collectors.t3;
        assert!(t3.enabled);
        assert_eq!(t3.environment_id.as_deref(), Some("env-1"));
        assert_eq!(
            t3.t3_web_base_url.as_deref(),
            Some("https://t3.example.com")
        );
        assert_eq!(t3.poll_interval_ms, 500);
        assert!(!t3.watch_wal);
        assert_eq!(t3.batch_size, 42);

        let error = Config::parse("[collectors.t3]\npoll_interval_ms = 0\n")
            .expect_err("zero poll interval must fail");
        assert!(error.to_string().contains("poll_interval_ms"), "{error}");

        let error = Config::parse("[collectors.t3]\nt3_web_base_url = \"ftp://example.com\"\n")
            .expect_err("non-http URL must fail");
        assert!(error.to_string().contains("http"), "{error}");

        let error = Config::parse("[collectors.t3]\nenvironment_id = \"  \"\n")
            .expect_err("blank environment id must fail");
        assert!(error.to_string().contains("environment_id"), "{error}");
    }

    #[test]
    fn defaults_are_loopback_only() {
        let config = Config::default();
        assert!(config.server.allowed_hosts.iter().any(|h| h == "127.0.0.1"));
        assert!(!config.server.enable_internal_ingest);
    }
}
