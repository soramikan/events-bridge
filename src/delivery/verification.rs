//! Callback URL validation, SSRF hardening, and the endpoint verification
//! challenge (design §2.5).
//!
//! Two properties matter:
//!
//! 1. Only `https` URLs are accepted on the production path (`CallbackPolicy`
//!    defaults). Loopback and private addresses are rejected even when the URL
//!    resolves to one.
//! 2. The address set is resolved once, validated, and then pinned into the
//!    `reqwest` client with `resolve_to_addrs`. Redirects are disabled, so a
//!    receiver cannot bounce the hub to a different (internal) address after
//!    the check.
//!
//! `CallbackPolicy::for_tests` exists so integration tests can point at a
//! local HTTP receiver. It is never constructed from configuration or the CLI.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use base64::Engine;
use serde_json::{Value, json};
use url::{Host, Url};

use crate::delivery::signing;
use crate::util::constant_time_eq;

/// Resolver used when validating a callback URL.
#[derive(Clone, Debug)]
pub enum Resolver {
    /// Operating-system resolver (`tokio::net::lookup_host`).
    System,
    /// Fixed test mapping. Unknown hosts fail resolution.
    Fixed(Arc<HashMap<String, Vec<IpAddr>>>),
}

impl Resolver {
    /// Resolve `host:port` to addresses.
    pub async fn resolve(&self, host: &str, port: u16) -> Result<Vec<IpAddr>, String> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        match self {
            Self::System => {
                let lookup = tokio::time::timeout(
                    Duration::from_secs(5),
                    tokio::net::lookup_host((host, port)),
                )
                .await
                .map_err(|_| "DNS resolution timed out".to_string())?
                .map_err(|error| error.to_string())?;
                Ok(lookup.map(|socket| socket.ip()).collect())
            }
            Self::Fixed(map) => map
                .get(&host.to_ascii_lowercase())
                .cloned()
                .ok_or_else(|| format!("no fixed resolution for `{host}`")),
        }
    }
}

/// Callback security policy.
#[derive(Clone, Debug)]
pub struct CallbackPolicy {
    /// Require the `https` scheme.
    pub require_https: bool,
    /// Permit loopback/private/link-local targets. Tests only.
    pub allow_private_addresses: bool,
    /// DNS resolver.
    pub resolver: Resolver,
    /// Connect and total request timeout.
    pub timeout: Duration,
    /// User agent sent on challenges and deliveries.
    pub user_agent: String,
}

impl Default for CallbackPolicy {
    fn default() -> Self {
        Self {
            require_https: true,
            allow_private_addresses: false,
            resolver: Resolver::System,
            timeout: Duration::from_secs(10),
            user_agent: format!("events-bridge/{}", env!("CARGO_PKG_VERSION")),
        }
    }
}

impl CallbackPolicy {
    /// Permissive policy for integration tests against a loopback receiver.
    ///
    /// This constructor is not reachable from configuration or CLI flags.
    #[doc(hidden)]
    pub fn for_tests() -> Self {
        Self {
            require_https: false,
            allow_private_addresses: true,
            resolver: Resolver::System,
            timeout: Duration::from_secs(5),
            user_agent: format!("events-bridge-tests/{}", env!("CARGO_PKG_VERSION")),
        }
    }

    /// Production policy with a test resolver and loopback allowance.
    #[doc(hidden)]
    pub fn for_tests_with_resolver(resolver: Resolver) -> Self {
        Self {
            resolver,
            ..Self::for_tests()
        }
    }

    /// Production policy with a custom timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

/// Machine-readable callback failure categories.
pub mod reason {
    /// Secret is not `whsec_` + 24–64 base64 bytes.
    pub const INVALID_SECRET: &str = "invalid_secret";
    /// URL could not be parsed or is not an absolute http(s) URL.
    pub const INVALID_URL: &str = "invalid_url";
    /// Production policy requires `https`.
    pub const INSECURE_URL: &str = "insecure_url";
    /// DNS resolution failed or returned no addresses.
    pub const DNS_FAILURE: &str = "dns_failure";
    /// Resolved to a loopback/private/link-local/otherwise non-public address.
    pub const PRIVATE_ADDRESS: &str = "private_address";
    /// Connection was refused or reset.
    pub const CONNECTION_REFUSED: &str = "connection_refused";
    /// The request timed out.
    pub const TIMEOUT: &str = "timeout";
    /// TLS handshake or certificate failure.
    pub const TLS_ERROR: &str = "tls_error";
    /// Other transport failure.
    pub const NETWORK_ERROR: &str = "network_error";
    /// The receiver answered 4xx.
    pub const HTTP_4XX: &str = "http_4xx";
    /// The receiver answered 5xx.
    pub const HTTP_5XX: &str = "http_5xx";
    /// A redirect was returned and deliberately not followed.
    pub const REDIRECT: &str = "redirect_not_followed";
    /// The response did not echo the challenge.
    pub const CHALLENGE_FAILED: &str = "challenge_failed";
    /// The receiver sent an unusable response body.
    pub const INVALID_RESPONSE: &str = "invalid_response";
    /// The stored delivery target failed validation at send time.
    pub const UNREACHABLE: &str = "unreachable";
}

/// A callback validation or verification failure.
#[derive(Debug, Clone)]
pub struct CallbackError {
    /// One of the [`reason`] constants.
    pub reason: &'static str,
    /// Human-readable detail (never contains the secret).
    pub detail: String,
}

impl CallbackError {
    /// Build an error.
    pub fn new(reason: &'static str, detail: impl Into<String>) -> Self {
        Self {
            reason,
            detail: detail.into(),
        }
    }

    /// JSON-RPC error data payload.
    pub fn to_data(&self) -> Value {
        json!({
            "reason": self.reason,
            "detail": self.detail,
        })
    }
}

impl std::fmt::Display for CallbackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.reason, self.detail)
    }
}

impl std::error::Error for CallbackError {}

/// Validate a Standard Webhooks secret.
///
/// The value must be `whsec_` followed by standard base64 that decodes to
/// 24–64 bytes.
pub fn validate_secret(secret: &str) -> Result<(), CallbackError> {
    let Some(encoded) = secret.strip_prefix("whsec_") else {
        return Err(CallbackError::new(
            reason::INVALID_SECRET,
            "secret must start with `whsec_`",
        ));
    };
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|error| {
            CallbackError::new(reason::INVALID_SECRET, format!("invalid base64: {error}"))
        })?;
    if !(24..=64).contains(&decoded.len()) {
        return Err(CallbackError::new(
            reason::INVALID_SECRET,
            format!(
                "decoded secret must be 24-64 bytes, was {} bytes",
                decoded.len()
            ),
        ));
    }
    Ok(())
}

/// Whether an address is globally routable (not loopback, private, link-local,
/// CGNAT, multicast, documentation, benchmarking, or otherwise reserved).
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_ipv4(ip),
        IpAddr::V6(ip) => is_public_ipv6(ip),
    }
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    if ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_unspecified()
        || ip.is_documentation()
    {
        return false;
    }
    // 0.0.0.0/8 ("this network").
    if octets[0] == 0 {
        return false;
    }
    // 100.64.0.0/10 carrier-grade NAT.
    if octets[0] == 100 && (64..=127).contains(&octets[1]) {
        return false;
    }
    // 192.0.0.0/24 IETF protocol assignments.
    if octets[0] == 192 && octets[1] == 0 && octets[2] == 0 {
        return false;
    }
    // 198.18.0.0/15 benchmarking.
    if octets[0] == 198 && (18..=19).contains(&octets[1]) {
        return false;
    }
    // 240.0.0.0/4 reserved (including 255.255.255.255).
    if octets[0] >= 240 {
        return false;
    }
    true
}

fn is_public_ipv6(ip: Ipv6Addr) -> bool {
    if ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || ip.is_unique_local()
        || ip.is_unicast_link_local()
    {
        return false;
    }

    // IPv4-mapped and IPv4-compatible addresses inherit IPv4 policy.
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return is_public_ipv4(mapped);
    }

    let segments = ip.segments();
    // 2001:db8::/32 documentation.
    if segments[0] == 0x2001 && segments[1] == 0x0db8 {
        return false;
    }
    // 2001::/32 Teredo and 2002::/16 6to4 embed IPv4 reachability.
    if segments[0] == 0x2001 && segments[1] == 0x0000 {
        return false;
    }
    if segments[0] == 0x2002 {
        let embedded = Ipv4Addr::new(
            (segments[1] >> 8) as u8,
            (segments[1] & 0xff) as u8,
            (segments[2] >> 8) as u8,
            (segments[2] & 0xff) as u8,
        );
        return is_public_ipv4(embedded);
    }
    // fec0::/10 is the deprecated IPv6 site-local prefix (RFC 3879).
    if (segments[0] & 0xffc0) == 0xfec0 {
        return false;
    }
    // 64:ff9b::/96 NAT64 well-known prefix.
    !(segments[0] == 0x0064 && segments[1] == 0xff9b)
}

/// Validate a callback URL and build an HTTP client pinned to its checked
/// addresses.
pub async fn pin_client(
    policy: &CallbackPolicy,
    url: &Url,
) -> Result<reqwest::Client, CallbackError> {
    if policy.require_https && url.scheme() != "https" {
        return Err(CallbackError::new(
            reason::INSECURE_URL,
            "callback URL must use https",
        ));
    }
    if !matches!(url.scheme(), "https" | "http") {
        return Err(CallbackError::new(
            reason::INVALID_URL,
            "callback URL must be an absolute http(s) URL",
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(CallbackError::new(
            reason::INVALID_URL,
            "callback URL must not contain userinfo",
        ));
    }
    let host = url
        .host()
        .ok_or_else(|| CallbackError::new(reason::INVALID_URL, "callback URL has no host"))?;
    let port = url.port_or_known_default().ok_or_else(|| {
        CallbackError::new(reason::INVALID_URL, "callback URL has no usable port")
    })?;

    let addresses = match &host {
        Host::Ipv4(ip) => vec![IpAddr::V4(*ip)],
        Host::Ipv6(ip) => vec![IpAddr::V6(*ip)],
        Host::Domain(domain) => policy
            .resolver
            .resolve(domain, port)
            .await
            .map_err(|error| {
                CallbackError::new(
                    reason::DNS_FAILURE,
                    format!("could not resolve `{domain}`: {error}"),
                )
            })?,
    };

    if addresses.is_empty() {
        return Err(CallbackError::new(
            reason::DNS_FAILURE,
            "callback host resolved to no addresses",
        ));
    }

    if !policy.allow_private_addresses
        && let Some(blocked) = addresses.iter().find(|ip| !is_public_ip(**ip))
    {
        return Err(CallbackError::new(
            reason::PRIVATE_ADDRESS,
            format!("callback host resolves to non-public address {blocked}"),
        ));
    }

    let sockets: Vec<SocketAddr> = addresses
        .iter()
        .map(|ip| SocketAddr::new(*ip, port))
        .collect();

    let mut builder = reqwest::Client::builder()
        // Never follow a redirect: the pinned address must not be bypassed.
        .redirect(reqwest::redirect::Policy::none())
        // Environment proxies would bypass the pinned address as well.
        .no_proxy()
        .timeout(policy.timeout)
        .connect_timeout(policy.timeout)
        .user_agent(policy.user_agent.clone());

    if let Host::Domain(domain) = host {
        builder = builder.resolve_to_addrs(domain, &sockets);
    }

    builder
        .build()
        .map_err(|error| CallbackError::new(reason::INVALID_URL, error.to_string()))
}

/// POST a signed `verification` control envelope and require the receiver to
/// echo the challenge.
pub async fn verify_callback(
    policy: &CallbackPolicy,
    url: &Url,
    secret: &str,
    subscription_id: &str,
) -> Result<(), CallbackError> {
    validate_secret(secret)?;
    let client = pin_client(policy, url).await?;

    let nonce = format!("challenge_{}", crate::util::random_hex(24));
    let message_id = format!("msg_verification_{}", crate::util::random_hex(8));
    let body = serde_json::to_vec(&json!({
        "type": "verification",
        "challenge": nonce,
    }))
    .map_err(|error| CallbackError::new(reason::CHALLENGE_FAILED, error.to_string()))?;
    let timestamp = chrono::Utc::now().timestamp();
    let signature = signing::sign(secret, &message_id, timestamp, &body)
        .map_err(|error| CallbackError::new(reason::INVALID_SECRET, error.to_string()))?;

    let mut response = client
        .post(url.clone())
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header(signing::HEADER_WEBHOOK_ID, &message_id)
        .header(signing::HEADER_WEBHOOK_TIMESTAMP, timestamp.to_string())
        .header(signing::HEADER_WEBHOOK_SIGNATURE, signature)
        .header(signing::HEADER_SUBSCRIPTION_ID, subscription_id)
        .body(body)
        .send()
        .await
        .map_err(|error| map_transport_error(&error))?;

    let status = response.status();
    if status.is_redirection() {
        return Err(CallbackError::new(
            reason::REDIRECT,
            format!("callback returned redirect status {status}"),
        ));
    }
    if status.is_client_error() {
        return Err(CallbackError::new(
            reason::HTTP_4XX,
            format!("callback returned status {status}"),
        ));
    }
    if status.is_server_error() {
        return Err(CallbackError::new(
            reason::HTTP_5XX,
            format!("callback returned status {status}"),
        ));
    }
    if !status.is_success() {
        return Err(CallbackError::new(
            reason::INVALID_RESPONSE,
            format!("callback returned unexpected status {status}"),
        ));
    }

    const MAX_CHALLENGE_RESPONSE: usize = 8 * 1024;
    let mut bytes = Vec::new();
    loop {
        let chunk = response.chunk().await.map_err(|error| {
            CallbackError::new(
                reason::INVALID_RESPONSE,
                format!("could not read challenge response: {error}"),
            )
        })?;
        let Some(chunk) = chunk else {
            break;
        };
        if bytes.len() + chunk.len() > MAX_CHALLENGE_RESPONSE {
            return Err(CallbackError::new(
                reason::INVALID_RESPONSE,
                "challenge response exceeded 8 KiB",
            ));
        }
        bytes.extend_from_slice(&chunk);
    }

    let value: Value = serde_json::from_slice(&bytes).map_err(|_| {
        CallbackError::new(reason::CHALLENGE_FAILED, "challenge response was not JSON")
    })?;
    let echoed = value
        .get("challenge")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !constant_time_eq(echoed.as_bytes(), nonce.as_bytes()) {
        return Err(CallbackError::new(
            reason::CHALLENGE_FAILED,
            "callback did not echo the verification challenge",
        ));
    }

    Ok(())
}

/// Map a `reqwest` transport failure to a stable category.
pub fn map_transport_error(error: &reqwest::Error) -> CallbackError {
    if error.is_timeout() {
        return CallbackError::new(reason::TIMEOUT, error.to_string());
    }
    if error.is_redirect() {
        return CallbackError::new(reason::REDIRECT, error.to_string());
    }
    let debug = format!("{error:?}").to_ascii_lowercase();
    if error.is_connect() {
        if debug.contains("tls") || debug.contains("certificate") || debug.contains("handshake") {
            return CallbackError::new(reason::TLS_ERROR, error.to_string());
        }
        return CallbackError::new(reason::CONNECTION_REFUSED, error.to_string());
    }
    CallbackError::new(reason::NETWORK_ERROR, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(bytes: usize) -> String {
        format!(
            "whsec_{}",
            base64::engine::general_purpose::STANDARD.encode(vec![7u8; bytes])
        )
    }

    #[test]
    fn secret_length_bounds_are_enforced() {
        assert!(validate_secret(&secret(24)).is_ok());
        assert!(validate_secret(&secret(64)).is_ok());
        assert!(validate_secret(&secret(23)).is_err());
        assert!(validate_secret(&secret(65)).is_err());
        assert!(validate_secret(&["whsec", "!!!!"].join("_")).is_err());
        assert!(validate_secret("not_a_whsec").is_err());
        assert!(validate_secret("").is_err());
    }

    #[test]
    fn public_address_classification() {
        for public in [
            "8.8.8.8",
            "1.1.1.1",
            "2001:4860:4860::8888",
            "2606:4700:4700::1111",
        ] {
            assert!(
                is_public_ip(public.parse().unwrap()),
                "{public} should be public"
            );
        }
        for private in [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "0.0.0.0",
            "100.64.0.1",
            "224.0.0.1",
            "255.255.255.255",
            "192.0.2.1",
            "198.18.0.1",
            "::1",
            "::",
            "fe80::1",
            "fc00::1",
            "fd12:3456::1",
            "2001:db8::1",
            "fec0::1",
            "feff::1",
            "2002:7f00:1::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(
                !is_public_ip(private.parse().unwrap()),
                "{private} should not be public"
            );
        }
    }

    #[tokio::test]
    async fn https_is_required_by_the_production_policy() {
        let policy = CallbackPolicy::default();
        let url = Url::parse("http://receiver.example.com/hook").unwrap();
        let error = pin_client(&policy, &url).await.unwrap_err();
        assert_eq!(error.reason, reason::INSECURE_URL);
    }

    #[tokio::test]
    async fn loopback_is_rejected_by_the_production_policy() {
        let policy = CallbackPolicy::default();
        let url = Url::parse("https://127.0.0.1:8443/hook").unwrap();
        let error = pin_client(&policy, &url).await.unwrap_err();
        assert_eq!(error.reason, reason::PRIVATE_ADDRESS);
    }

    #[tokio::test]
    async fn private_dns_answers_are_rejected_by_the_production_policy() {
        let mut map = HashMap::new();
        map.insert(
            "receiver.test".to_string(),
            vec!["127.0.0.1".parse::<IpAddr>().unwrap()],
        );
        let policy = CallbackPolicy {
            resolver: Resolver::Fixed(Arc::new(map)),
            ..CallbackPolicy::default()
        };
        let url = Url::parse("https://receiver.test/hook").unwrap();
        let error = pin_client(&policy, &url).await.unwrap_err();
        assert_eq!(error.reason, reason::PRIVATE_ADDRESS);
    }

    #[tokio::test]
    async fn userinfo_is_rejected() {
        let policy = CallbackPolicy::for_tests();
        let url = Url::parse("http://user:pass@127.0.0.1:1/hook").unwrap();
        let error = pin_client(&policy, &url).await.unwrap_err();
        assert_eq!(error.reason, reason::INVALID_URL);
    }
}
