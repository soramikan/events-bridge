use std::time::Duration;

use anyhow::{Context, Result, bail};
use secrecy::{ExposeSecret, SecretString};
use url::Url;

use crate::{
    config::EdgeConfig,
    edge_protocol::{
        HEADER_EDGE_ID, HEADER_EDGE_NONCE, HEADER_EDGE_SIGNATURE, HEADER_EDGE_TIMESTAMP,
        edge_endpoint, sign,
    },
    util::random_hex,
};

pub(super) struct SignedEdgeClient {
    client: reqwest::Client,
    endpoint: Url,
    edge_id: String,
    secret: SecretString,
}

impl SignedEdgeClient {
    pub(super) fn new(
        config: &EdgeConfig,
        path: &str,
        edge_id: String,
        secret: SecretString,
    ) -> Result<Self> {
        let hub_url = Url::parse(
            config
                .hub_url
                .as_deref()
                .context("edge.hub_url is required")?,
        )?;
        let timeout = Duration::from_secs(config.request_timeout_secs.max(1));
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(timeout)
            .connect_timeout(timeout)
            .user_agent(concat!("events-bridge-edge/", env!("CARGO_PKG_VERSION")))
            .build()
            .context("building edge HTTP client")?;
        Ok(Self {
            client,
            endpoint: edge_endpoint(&hub_url, path),
            edge_id,
            secret,
        })
    }

    pub(super) fn edge_id(&self) -> &str {
        &self.edge_id
    }

    pub(super) fn endpoint(&self) -> &Url {
        &self.endpoint
    }

    pub(super) async fn post(&self, body: Vec<u8>) -> Result<()> {
        let timestamp = chrono::Utc::now().timestamp();
        let nonce = random_hex(16);
        let signature = sign(
            self.secret.expose_secret().as_bytes(),
            &self.edge_id,
            timestamp,
            &nonce,
            &body,
        );
        let response = self
            .client
            .post(self.endpoint.clone())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::CONNECTION, "close")
            .header(HEADER_EDGE_ID, &self.edge_id)
            .header(HEADER_EDGE_TIMESTAMP, timestamp.to_string())
            .header(HEADER_EDGE_NONCE, &nonce)
            .header(HEADER_EDGE_SIGNATURE, signature)
            .body(body)
            .send()
            .await
            .with_context(|| format!("POST {}", self.endpoint))?;
        let status = response.status();
        if !status.is_success() {
            bail!("hub rejected edge request with HTTP {status}");
        }
        Ok(())
    }
}
