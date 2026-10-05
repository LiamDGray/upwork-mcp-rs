//! Client configuration generator for Model Context Protocol agents.
//!
//! Provides configuration manifests for:
//! - Claude Desktop
//! - Cursor
//! - Zed
//! - Cline

use serde_json::{json, Value};
use std::path::Path;

/// Supported Model Context Protocol clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientType {
    Claude,
    Cursor,
    Zed,
    Cline,
}

impl ClientType {
    /// Parses client identifier from string slice.
    pub fn parse_client(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "claude" | "claude-desktop" => Some(Self::Claude),
            "cursor" => Some(Self::Cursor),
            "zed" => Some(Self::Zed),
            "cline" => Some(Self::Cline),
            _ => None,
        }
    }
}

/// Generates client-specific configuration JSON block.
pub fn generate_client_config(client: ClientType, binary_path: &Path) -> Value {
    let bin_str = binary_path.to_string_lossy().to_string();

    match client {
        ClientType::Claude => json!({
            "mcpServers": {
                "upwork": {
                    "command": bin_str,
                    "args": ["serve", "--stdio"]
                }
            }
        }),
        ClientType::Cursor => json!({
            "mcpServers": {
                "upwork": {
                    "command": bin_str,
                    "args": ["serve", "--stdio"]
                }
            }
        }),
        ClientType::Zed => json!({
            "context_servers": {
                "upwork": {
                    "command": {
                        "path": bin_str,
                        "args": ["serve", "--stdio"]
                    }
                }
            }
        }),
        ClientType::Cline => json!({
            "mcpServers": {
                "upwork": {
                    "command": bin_str,
                    "args": ["serve", "--stdio"],
                    "disabled": false,
                    "autoApprove": []
                }
            }
        }),
    }
}

/// Generates aggregated configuration blocks for all supported MCP clients.
pub fn generate_all_configs(binary_path: &Path) -> Value {
    json!({
        "claude": generate_client_config(ClientType::Claude, binary_path),
        "cursor": generate_client_config(ClientType::Cursor, binary_path),
        "zed": generate_client_config(ClientType::Zed, binary_path),
        "cline": generate_client_config(ClientType::Cline, binary_path),
    })
}
