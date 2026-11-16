//! `rmcp` server handler for the hub.
//!
//! Native `rmcp` capabilities cover initialization, sessions, `tools/list`, and
//! `tools/call`. The Events extension is not part of the SDK's typed model, so
//! `events/*` methods are handled through the SDK's `on_custom_request`
//! extension point. The HTTP layer additionally injects `capabilities.events`
//! into `initialize` / `server/discover` responses (see `mcp::http`).

use std::sync::Arc;

use rmcp::{
    ErrorData as McpError, RoleServer, ServerHandler,
    model::{
        CallToolRequestParams, CallToolResponse, CustomRequest, CustomResult, ListToolsResult,
        ServerCapabilities, ServerConfig, Tool,
    },
    service::RequestContext,
};

use crate::{app::AppState, auth::AuthenticatedPrincipal, mcp::tools};

/// MCP handler backed by the shared application state.
#[derive(Clone)]
pub struct EventsHandler {
    state: Arc<AppState>,
}

impl EventsHandler {
    /// Create a handler.
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }
}

impl ServerHandler for EventsHandler {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(rmcp::model::Implementation::new(
                "events-bridge",
                env!("CARGO_PKG_VERSION"),
            ))
            .with_instructions(
                "T3 Code and GitHub events. Use tools/list for pull tools and \
                 the events/* extension for signed webhook subscriptions and \
                 cursor-based polling.",
            )
    }

    async fn list_tools(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        Ok(ListToolsResult::with_all_items(tools::definitions()))
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        tools::get(name)
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        let principal = self.principal(&context);
        self.state.tools.call(&principal.principal, request).await
    }

    async fn on_custom_request(
        &self,
        request: CustomRequest,
        context: RequestContext<RoleServer>,
    ) -> Result<CustomResult, McpError> {
        let principal = self.principal(&context);
        let result = self
            .state
            .subscriptions
            .handle(&request.method, request.params, &principal.principal)
            .await
            .map_err(McpError::from)?;
        Ok(CustomResult::new(result))
    }
}

impl EventsHandler {
    /// Resolve the authenticated HTTP identity injected into rmcp request
    /// extensions. stdio has no HTTP parts and falls back to the configured
    /// principal.
    fn principal(&self, context: &RequestContext<RoleServer>) -> AuthenticatedPrincipal {
        context
            .extensions
            .get::<axum::http::request::Parts>()
            .and_then(|parts| parts.extensions.get::<AuthenticatedPrincipal>().cloned())
            .unwrap_or_else(|| {
                AuthenticatedPrincipal::full(self.state.config.auth.principal.clone())
            })
    }
}
