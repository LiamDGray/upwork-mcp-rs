//! Streamable HTTP & SSE Transport Engine for Upwork MCP Server.
//!
//! Provides:
//! - Axum 0.8 router supporting streamable HTTP and SSE (`POST /mcp`, `GET /mcp`, `GET /sse`, `POST /message`).
//! - DNS rebinding defense rejecting any external or untrusted `Host` and `Origin` headers.
//! - MCP session-id negotiation via `mcp-session-id` header.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::Router;
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;
use tracing::debug;

use crate::dispatcher::McpDispatcher;

/// Shared application state for SSE and HTTP routing.
#[derive(Clone)]
pub struct AppState {
    pub dispatcher: Arc<McpDispatcher>,
    pub sse_sender: broadcast::Sender<String>,
}

/// Constructs an Axum HTTP Router for the Upwork MCP server.
pub fn create_router(dispatcher: Arc<McpDispatcher>) -> Router {
    let (sse_sender, _) = broadcast::channel(1024);
    let state = Arc::new(AppState {
        dispatcher,
        sse_sender,
    });

    Router::new()
        .route("/mcp", get(sse_handler).post(message_handler))
        .route("/sse", get(sse_handler).post(message_handler))
        .route("/message", post(message_handler).get(sse_handler))
        .route("/", get(sse_handler).post(message_handler))
        .with_state(state)
}

/// Runs the HTTP/SSE transport server on a local port.
pub async fn run_http_server(
    dispatcher: Arc<McpDispatcher>,
    port: u16,
) -> Result<(), std::io::Error> {
    let router = create_router(dispatcher);
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router)
        .await
        .map_err(std::io::Error::other)?;
    Ok(())
}

fn is_valid_localhost_host_or_origin(val: &str) -> bool {
    let without_scheme = val
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    let host_part = without_scheme.split('/').next().unwrap_or("").trim();
    let hostname = host_part
        .split(':')
        .next()
        .unwrap_or("")
        .trim_matches('[')
        .trim_matches(']');
    hostname == "localhost" || hostname == "127.0.0.1" || hostname == "::1" || hostname.is_empty()
}

fn validate_dns_rebinding(headers: &axum::http::HeaderMap) -> Result<(), axum::http::StatusCode> {
    if let Some(host) = headers.get("host").and_then(|v| v.to_str().ok()) {
        if !is_valid_localhost_host_or_origin(host) {
            return Err(axum::http::StatusCode::FORBIDDEN);
        }
    }
    if let Some(origin) = headers.get("origin").and_then(|v| v.to_str().ok()) {
        if !is_valid_localhost_host_or_origin(origin) {
            return Err(axum::http::StatusCode::FORBIDDEN);
        }
    }
    Ok(())
}

/// Handler for SSE streams (`GET /mcp`, `GET /sse`, `GET /`).
async fn sse_handler(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if let Err(status) = validate_dns_rebinding(&headers) {
        return axum::response::Response::builder()
            .status(status)
            .body(axum::body::Body::from("DNS rebinding forbidden"))
            .unwrap();
    }

    let session_id = headers
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    let rx = state.sse_sender.subscribe();

    let endpoint_url = format!("/message?sessionId={}", session_id);
    let initial_event: Result<Event, std::convert::Infallible> =
        Ok(Event::default().event("endpoint").data(endpoint_url));

    let rx_stream = BroadcastStream::new(rx).filter_map(|msg| match msg {
        Ok(text) => Some(Ok(Event::default().event("message").data(text))),
        Err(e) => {
            debug!("Broadcast stream lagged: {}", e);
            None
        }
    });

    let stream = tokio_stream::once(initial_event).chain(rx_stream);
    let sse_response =
        Sse::new(stream).keep_alive(KeepAlive::default().interval(Duration::from_secs(15)));

    let mut response_headers = axum::http::HeaderMap::new();
    if let Ok(val) = axum::http::HeaderValue::from_str(&session_id) {
        response_headers.insert("mcp-session-id", val);
    }
    response_headers.insert(
        "cache-control",
        axum::http::HeaderValue::from_static("no-cache"),
    );

    (response_headers, sse_response).into_response()
}

/// Handler for JSON-RPC messages (`POST /mcp`, `POST /sse`, `POST /message`, `POST /`).
async fn message_handler(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    body: String,
) -> impl IntoResponse {
    if let Err(status) = validate_dns_rebinding(&headers) {
        return axum::response::Response::builder()
            .status(status)
            .header("Content-Type", "application/json")
            .body(axum::body::Body::from(
                r#"{"error":"DNS rebinding forbidden: Host/Origin must be localhost"}"#,
            ))
            .unwrap();
    }

    let session_id = headers
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    let trimmed = body.trim();
    if let Some(response_str) = state.dispatcher.handle_jsonrpc_message(trimmed).await {
        let _ = state.sse_sender.send(response_str.clone());

        axum::response::Response::builder()
            .status(axum::http::StatusCode::OK)
            .header("Content-Type", "application/json")
            .header("mcp-session-id", session_id)
            .body(axum::body::Body::from(response_str))
            .unwrap()
    } else {
        axum::response::Response::builder()
            .status(axum::http::StatusCode::ACCEPTED)
            .header("mcp-session-id", session_id)
            .body(axum::body::Body::empty())
            .unwrap()
    }
}
