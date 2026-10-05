//! MCP Server Host Runtime.
//!
//! Provides:
//! - Standard I/O (stdio) transport for desktop MCP clients (Claude, Cursor, Zed, Cline).
//! - Streamable HTTP/SSE transport on configurable local port.
//! - Mock server or production gateway dispatch.

use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;

use upwork_mcp_core::audit::UpworkFlightRecorder;
use upwork_mcp_server::dispatcher::McpDispatcher;
use upwork_mcp_server::mock_server::MockUpworkServer;
use upwork_mcp_server::streaming::run_http_server;

use crate::cli::ServeArgs;

/// Starts the Upwork Model Context Protocol server.
pub async fn run_serve(args: &ServeArgs) -> Result<(), Box<dyn std::error::Error>> {
    let secret = std::env::var("UPWORK_SUPERVISOR_SECRET")
        .unwrap_or_else(|_| "supervisor-default-secret".to_string());
    let recorder = Arc::new(Mutex::new(UpworkFlightRecorder::new(secret.as_bytes())));
    let mock_server = Arc::new(MockUpworkServer::new(recorder.clone()));
    let dispatcher = Arc::new(McpDispatcher::new(mock_server, recorder, secret.as_bytes()));

    if args.stdio || args.port.is_none() {
        let stdin = tokio::io::stdin();
        let mut stdout = tokio::io::stdout();
        let mut lines = BufReader::new(stdin).lines();

        while let Ok(Some(line)) = lines.next_line().await {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            if let Some(resp) = dispatcher.handle_jsonrpc_message(trimmed).await {
                stdout.write_all(resp.as_bytes()).await?;
                stdout.write_all(b"\n").await?;
                stdout.flush().await?;
            }
        }
    } else if let Some(port) = args.port {
        run_http_server(dispatcher, port).await?;
    }

    Ok(())
}
