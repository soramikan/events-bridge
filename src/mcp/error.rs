//! JSON-RPC error helpers for the Events adapter.

use serde_json::{Value, json};

use crate::delivery::verification::CallbackError;

/// `CallbackEndpointError`: a client-supplied callback failed verification or
/// could not be reached (design §2.5).
pub const CALLBACK_ENDPOINT_ERROR: i32 = -32015;
/// `NotFound`.
pub const NOT_FOUND: i32 = -32023;
/// `Forbidden`.
pub const FORBIDDEN: i32 = -32024;
/// Standard JSON-RPC `InvalidRequest`.
pub const INVALID_REQUEST: i32 = -32600;
/// Standard JSON-RPC `InvalidParams`.
pub const INVALID_PARAMS: i32 = -32602;
/// Standard JSON-RPC `MethodNotFound`.
pub const METHOD_NOT_FOUND: i32 = -32601;
/// Standard JSON-RPC `InternalError`.
pub const INTERNAL_ERROR: i32 = -32603;

/// A JSON-RPC error produced by the Events adapter.
#[derive(Debug, Clone)]
pub struct RpcError {
    /// JSON-RPC error code.
    pub code: i32,
    /// Short message.
    pub message: String,
    /// Optional structured data.
    pub data: Option<Value>,
}

impl RpcError {
    /// Build an error.
    pub fn new(code: i32, message: impl Into<String>, data: Option<Value>) -> Self {
        Self {
            code,
            message: message.into(),
            data,
        }
    }

    /// Invalid parameters.
    pub fn invalid_params(message: impl Into<String>) -> Self {
        Self::new(INVALID_PARAMS, message, None)
    }

    /// Unknown event name or subscription.
    pub fn not_found(kind: &str, name: &str) -> Self {
        Self::new(
            NOT_FOUND,
            format!("{kind} `{name}` not found"),
            Some(json!({"kind": kind})),
        )
    }

    /// Callback endpoint verification failure.
    pub fn callback(error: CallbackError, url: &str) -> Self {
        let mut data = error.to_data();
        if let Some(object) = data.as_object_mut() {
            object.insert("url".into(), Value::String(url.to_string()));
        }
        Self::new(CALLBACK_ENDPOINT_ERROR, error.to_string(), Some(data))
    }

    /// Unexpected server-side failure.
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(INTERNAL_ERROR, message, None)
    }

    /// Serialize as a JSON-RPC error object.
    pub fn to_json(&self) -> Value {
        json!({
            "code": self.code,
            "message": self.message,
            "data": self.data,
        })
    }
}

impl From<RpcError> for rmcp::ErrorData {
    fn from(error: RpcError) -> Self {
        rmcp::ErrorData::new(
            rmcp::model::ErrorCode(error.code),
            error.message,
            error.data,
        )
    }
}
