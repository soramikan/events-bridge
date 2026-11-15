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

use crate::{app::AppState, mcp::tools};

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
                 the events/* extension for signed webhook subscriptions.",
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
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        self.state
            .tools
            .call(&self.state.config.auth.principal, request)
            .await
    }

    async fn on_custom_request(
        &self,
        request: CustomRequest,
        _context: RequestContext<RoleServer>,
    ) -> Result<CustomResult, McpError> {
        let principal = self.state.config.auth.principal.clone();
        let result = self
            .state
            .subscriptions
            .handle(&request.method, request.params, &principal)
            .await
            .map_err(McpError::from)?;
        Ok(CustomResult::new(result))
    }
}
