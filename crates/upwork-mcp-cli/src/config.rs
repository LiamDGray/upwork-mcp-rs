//! Client configuration generator for Model Context Protocol agents.
//!
//! Provides configuration manifests and automated installation for:
//! - Claude Desktop
//! - Cursor
//! - Zed
//! - Cline
//! - Codex CLI
//! - Antigravity CLI
//! - Pi Agent
//! - Hermes Agent

use serde_json::{json, Map, Value};
use std::path::{Path, PathBuf};

/// Supported Model Context Protocol clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientType {
    Claude,
    Cursor,
    Zed,
    Cline,
    Codex,
    Antigravity,
    Pi,
    Hermes,
}

impl ClientType {
    /// Parses client identifier from string slice.
    pub fn parse_client(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "claude" | "claude-desktop" => Some(Self::Claude),
            "cursor" => Some(Self::Cursor),
            "zed" => Some(Self::Zed),
            "cline" => Some(Self::Cline),
            "codex" | "codex-cli" | "openai-codex" => Some(Self::Codex),
            "antigravity" | "antigravity-cli" | "gemini" => Some(Self::Antigravity),
            "pi" | "pi-agent" => Some(Self::Pi),
            "hermes" | "hermes-agent" | "cognisynth" => Some(Self::Hermes),
            _ => None,
        }
    }
}

/// Returns the configuration file path for a given client relative to a user's home directory.
pub fn target_config_path(client: ClientType, home_dir: &Path) -> PathBuf {
    match client {
        ClientType::Claude => home_dir.join(".config/Claude/claude_desktop_config.json"),
        ClientType::Cursor => home_dir.join(".cursor/mcp.json"),
        ClientType::Zed => home_dir.join(".config/zed/settings.json"),
        ClientType::Cline => home_dir.join(
            ".config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
        ),
        ClientType::Codex => home_dir.join(".codex/config.json"),
        ClientType::Antigravity => home_dir.join(".gemini/config/mcp_config.json"),
        ClientType::Pi => home_dir.join(".pi/agent/mcp.json"),
        ClientType::Hermes => home_dir.join(".hermes/mcp.json"),
    }
}

/// Generates client-specific configuration JSON block.
pub fn generate_client_config(client: ClientType, binary_path: &Path) -> Value {
    let bin_str = binary_path.to_string_lossy().to_string();

    match client {
        ClientType::Claude
        | ClientType::Cursor
        | ClientType::Codex
        | ClientType::Antigravity
        | ClientType::Pi
        | ClientType::Hermes => json!({
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

/// Installs or merges the `upwork` MCP server block into the target client configuration file.
///
/// Creates parent directories if needed, merges with existing JSON structures,
/// or initializes a new file if one doesn't exist.
pub fn install_client_config(
    client: ClientType,
    home_dir: &Path,
    binary_path: &Path,
) -> Result<PathBuf, std::io::Error> {
    let config_path = target_config_path(client, home_dir);
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let generated = generate_client_config(client, binary_path);

    let final_val = if config_path.exists() {
        let raw = std::fs::read_to_string(&config_path)?;
        let mut existing_val: Value =
            serde_json::from_str(&raw).unwrap_or_else(|_| Value::Object(Map::new()));

        match client {
            ClientType::Zed => {
                let upwork_entry = generated["context_servers"]["upwork"].clone();
                let obj = existing_val.as_object_mut();
                if let Some(map) = obj {
                    let cs = map
                        .entry("context_servers")
                        .or_insert_with(|| Value::Object(Map::new()));
                    if let Some(cs_map) = cs.as_object_mut() {
                        cs_map.insert("upwork".to_string(), upwork_entry);
                    }
                }
            }
            _ => {
                let upwork_entry = generated["mcpServers"]["upwork"].clone();
                let obj = existing_val.as_object_mut();
                if let Some(map) = obj {
                    let mcp = map
                        .entry("mcpServers")
                        .or_insert_with(|| Value::Object(Map::new()));
                    if let Some(mcp_map) = mcp.as_object_mut() {
                        mcp_map.insert("upwork".to_string(), upwork_entry);
                    }
                }
            }
        }
        existing_val
    } else {
        generated
    };

    let formatted = serde_json::to_string_pretty(&final_val).map_err(std::io::Error::other)?;
    std::fs::write(&config_path, formatted)?;

    Ok(config_path)
}

/// Generates aggregated configuration blocks for all supported MCP clients.
pub fn generate_all_configs(binary_path: &Path) -> Value {
    json!({
        "claude": generate_client_config(ClientType::Claude, binary_path),
        "cursor": generate_client_config(ClientType::Cursor, binary_path),
        "zed": generate_client_config(ClientType::Zed, binary_path),
        "cline": generate_client_config(ClientType::Cline, binary_path),
        "codex": generate_client_config(ClientType::Codex, binary_path),
        "antigravity": generate_client_config(ClientType::Antigravity, binary_path),
        "pi": generate_client_config(ClientType::Pi, binary_path),
        "hermes": generate_client_config(ClientType::Hermes, binary_path),
    })
}
