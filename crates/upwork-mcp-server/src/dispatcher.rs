//! MCP JSON-RPC 2.0 Tool Dispatcher and Safety Gateway.
//!
//! Exposes and routes core Upwork tools:
//! - `list_accounts`: Enumerates available enterprise organizations and roles.
//! - `find_jobs`: Queries and distills jobs using token-diet tiers (`compact`, `standard`, `raw`).
//! - `manage_proposals`: Creates draft proposal previews with single-pending slot management.
//! - `confirm_preview`: Safety interlock requiring valid `OperatorWitness` cryptographic sign-off.
//! - `get_preview`: Inspects pending preview terms without consuming state.
//!
//! Neutralizes untrusted content with boundary markers (`UNTRUSTED_DATA_BEGIN`/`END`)
//! and decorates every response/error with an operational `trace_id`.

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;

use upwork_mcp_core::audit::{UpworkEventKind, UpworkFlightRecorder};
use upwork_mcp_core::safety::OperatorWitness;
use upwork_mcp_core::sanitizer::{Sanitizer, UNTRUSTED_DATA_BEGIN, UNTRUSTED_DATA_END};
use upwork_mcp_core::token_diet::{DistillationTier, TokenDietDistiller};

use crate::mock_server::MockUpworkServer;

/// JSON-RPC 2.0 Request envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpRequest {
    pub jsonrpc: String,
    pub id: serde_json::Value,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
}

/// JSON-RPC 2.0 Response envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpResponse {
    pub jsonrpc: String,
    pub id: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<serde_json::Value>,
}

/// High-assurance MCP tool dispatcher.
pub struct McpDispatcher {
    mock_server: Arc<MockUpworkServer>,
    flight_recorder: Arc<Mutex<UpworkFlightRecorder>>,
    secret: Vec<u8>,
    distiller: TokenDietDistiller,
}

impl McpDispatcher {
    /// Constructs a new `McpDispatcher`.
    pub fn new(
        mock_server: Arc<MockUpworkServer>,
        flight_recorder: Arc<Mutex<UpworkFlightRecorder>>,
        secret: &[u8],
    ) -> Self {
        Self {
            mock_server,
            flight_recorder,
            secret: secret.to_vec(),
            distiller: TokenDietDistiller::new(),
        }
    }

    /// Dispatches a strongly typed JSON-RPC request to the appropriate tool handler.
    pub async fn dispatch(&self, req: McpRequest) -> McpResponse {
        let trace_id = format!("trace_{}", uuid::Uuid::new_v4().simple());

        match req.method.as_str() {
            "initialize" => self.handle_initialize(req.id, trace_id),
            "tools/list" => self.handle_tools_list(req.id, trace_id),
            "tools/call" => self.handle_tools_call(req.id, req.params, trace_id).await,
            _ => McpResponse {
                jsonrpc: "2.0".into(),
                id: req.id,
                result: None,
                error: Some(serde_json::json!({
                    "code": -32601,
                    "message": format!("Method not found: '{}'", req.method),
                    "data": { "trace_id": trace_id }
                })),
            },
        }
    }

    /// Helper for handling raw JSON string requests (used by streaming HTTP/SSE transport).
    pub async fn handle_jsonrpc_message(&self, raw_json: &str) -> Option<String> {
        let req: McpRequest = match serde_json::from_str(raw_json) {
            Ok(r) => r,
            Err(e) => {
                let err_resp = McpResponse {
                    jsonrpc: "2.0".into(),
                    id: serde_json::Value::Null,
                    result: None,
                    error: Some(serde_json::json!({
                        "code": -32700,
                        "message": format!("Parse error: {e}"),
                        "data": { "trace_id": format!("trace_{}", uuid::Uuid::new_v4().simple()) }
                    })),
                };
                return serde_json::to_string(&err_resp).ok();
            }
        };

        let resp = self.dispatch(req).await;
        serde_json::to_string(&resp).ok()
    }

    fn handle_initialize(&self, id: serde_json::Value, trace_id: String) -> McpResponse {
        McpResponse {
            jsonrpc: "2.0".into(),
            id,
            result: Some(serde_json::json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": { "listChanged": false }
                },
                "serverInfo": {
                    "name": "upwork-mcp-server",
                    "version": env!("CARGO_PKG_VERSION")
                },
                "trace_id": trace_id
            })),
            error: None,
        }
    }

    fn handle_tools_list(&self, id: serde_json::Value, trace_id: String) -> McpResponse {
        McpResponse {
            jsonrpc: "2.0".into(),
            id,
            result: Some(serde_json::json!({
                "tools": [
                    {
                        "name": "list_accounts",
                        "description": "Lists connected Upwork enterprise accounts and organization identifiers.",
                        "inputSchema": { "type": "object", "properties": {} }
                    },
                    {
                        "name": "find_jobs",
                        "description": "Searches Upwork job postings with token diet distillation (compact, standard, raw).",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "query": { "type": "string" },
                                "detail_level": { "type": "string", "enum": ["compact", "standard", "raw"] }
                            }
                        }
                    },
                    {
                        "name": "manage_proposals",
                        "description": "Drafts and previews a proposal under single-pending preview concurrency.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "action": { "type": "string", "enum": ["create"] },
                                "job_id": { "type": "string" },
                                "cover_letter": { "type": "string" },
                                "amount": { "type": "number" },
                                "connects_cost": { "type": "integer" }
                            },
                            "required": ["action", "job_id"]
                        }
                    },
                    {
                        "name": "confirm_preview",
                        "description": "Confirms and submits a pending preview via cryptographic OperatorWitness authorization.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "preview_id": { "type": "string" },
                                "witness": { "type": "object" }
                            },
                            "required": ["preview_id", "witness"]
                        }
                    },
                    {
                        "name": "get_preview",
                        "description": "Retrieves pending preview data without consuming linear state.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "preview_id": { "type": "string" }
                            },
                            "required": ["preview_id"]
                        }
                    }
                ],
                "trace_id": trace_id
            })),
            error: None,
        }
    }

    async fn handle_tools_call(
        &self,
        id: serde_json::Value,
        params: serde_json::Value,
        trace_id: String,
    ) -> McpResponse {
        let tool_name = params["name"].as_str().unwrap_or("");
        let args = &params["arguments"];

        match tool_name {
            "list_accounts" => self.tool_list_accounts(id, trace_id),
            "find_jobs" => self.tool_find_jobs(id, args, trace_id).await,
            "manage_proposals" => self.tool_manage_proposals(id, args, trace_id).await,
            "confirm_preview" => self.tool_confirm_preview(id, args, trace_id).await,
            "get_preview" => self.tool_get_preview(id, args, trace_id).await,
            _ => McpResponse {
                jsonrpc: "2.0".into(),
                id,
                result: None,
                error: Some(serde_json::json!({
                    "code": -32602,
                    "message": format!("Unknown tool: '{tool_name}'"),
                    "data": { "trace_id": trace_id }
                })),
            },
        }
    }

    fn tool_list_accounts(&self, id: serde_json::Value, trace_id: String) -> McpResponse {
        let text = "Available accounts:\n- org_enterprise_99: Executive Systems Architecture (Admin)\n- org_default: Primary Delivery Workspace";
        McpResponse {
            jsonrpc: "2.0".into(),
            id,
            result: Some(serde_json::json!({
                "content": [{ "type": "text", "text": text }],
                "accounts": [
                    { "id": "org_enterprise_99", "name": "Executive Systems Architecture", "role": "Admin" },
                    { "id": "org_default", "name": "Primary Delivery Workspace", "role": "Owner" }
                ],
                "trace_id": trace_id
            })),
            error: None,
        }
    }

    async fn tool_find_jobs(
        &self,
        id: serde_json::Value,
        args: &serde_json::Value,
        trace_id: String,
    ) -> McpResponse {
        let query = args["query"].as_str().unwrap_or("");
        let detail_str = args["detail_level"].as_str().unwrap_or("compact");
        let tier = match detail_str {
            "compact" => DistillationTier::Compact,
            "raw" => DistillationTier::Raw,
            _ => DistillationTier::Standard,
        };

        let jobs = self.mock_server.find_jobs(query).await;
        let distilled_jobs: Vec<String> = jobs
            .iter()
            .map(|job| self.distiller.distill(job, tier))
            .collect();

        let output_text = if distilled_jobs.is_empty() {
            format!("{UNTRUSTED_DATA_BEGIN}\nNo matching jobs found.\n{UNTRUSTED_DATA_END}")
        } else {
            distilled_jobs.join("\n\n---\n\n")
        };

        McpResponse {
            jsonrpc: "2.0".into(),
            id,
            result: Some(serde_json::json!({
                "content": [{ "type": "text", "text": output_text }],
                "count": jobs.len(),
                "trace_id": trace_id
            })),
            error: None,
        }
    }

    async fn tool_manage_proposals(
        &self,
        id: serde_json::Value,
        args: &serde_json::Value,
        trace_id: String,
    ) -> McpResponse {
        let action = args["action"].as_str().unwrap_or("");
        if action != "create" {
            return McpResponse {
                jsonrpc: "2.0".into(),
                id,
                result: None,
                error: Some(serde_json::json!({
                    "code": -32602,
                    "message": format!("Unsupported proposal action: '{action}'"),
                    "data": { "trace_id": trace_id }
                })),
            };
        }

        let job_id = args["job_id"].as_str().unwrap_or("");
        let cover_letter = args["cover_letter"].as_str().unwrap_or("");
        let amount = args["amount"].as_f64().unwrap_or(0.0);
        let connects_cost = args["connects_cost"].as_u64().unwrap_or(16) as u32;

        match self
            .mock_server
            .draft_proposal(job_id, cover_letter, amount, connects_cost)
            .await
        {
            Ok(preview_id) => McpResponse {
                jsonrpc: "2.0".into(),
                id,
                result: Some(serde_json::json!({
                    "content": [{
                        "type": "text",
                        "text": format!("Proposal preview generated: {preview_id}")
                    }],
                    "preview_id": preview_id,
                    "trace_id": trace_id
                })),
                error: None,
            },
            Err(e) => McpResponse {
                jsonrpc: "2.0".into(),
                id,
                result: None,
                error: Some(serde_json::json!({
                    "code": -32000,
                    "message": format!("Failed to create draft proposal: {e}"),
                    "data": { "trace_id": trace_id }
                })),
            },
        }
    }

    async fn tool_confirm_preview(
        &self,
        id: serde_json::Value,
        args: &serde_json::Value,
        trace_id: String,
    ) -> McpResponse {
        let preview_id = args["preview_id"].as_str().unwrap_or("");
        let witness_val = &args["witness"];

        let witness: OperatorWitness = match serde_json::from_value(witness_val.clone()) {
            Ok(w) => w,
            Err(e) => {
                let mut recorder = self.flight_recorder.lock().await;
                recorder.record_event(
                    UpworkEventKind::SafetyFault,
                    1,
                    0,
                    0,
                    format!("SAFETY_FAULT:invalid_witness_format:{e}").as_bytes(),
                );
                return McpResponse {
                    jsonrpc: "2.0".into(),
                    id,
                    result: Some(serde_json::json!({
                        "isError": true,
                        "error": format!("Invalid witness structure: {e}"),
                        "trace_id": trace_id
                    })),
                    error: Some(serde_json::json!({
                        "code": -32000,
                        "message": format!("Invalid witness structure: {e}"),
                        "data": { "trace_id": trace_id }
                    })),
                };
            }
        };

        match self
            .mock_server
            .confirm_preview(preview_id, &witness, &self.secret)
            .await
        {
            Ok(submission) => McpResponse {
                jsonrpc: "2.0".into(),
                id,
                result: Some(serde_json::json!({
                    "content": [{
                        "type": "text",
                        "text": format!("Proposal successfully submitted: {}", submission.submission_id)
                    }],
                    "submission": submission,
                    "trace_id": trace_id
                })),
                error: None,
            },
            Err(e) => McpResponse {
                jsonrpc: "2.0".into(),
                id,
                result: Some(serde_json::json!({
                    "isError": true,
                    "error": e,
                    "trace_id": trace_id.clone()
                })),
                error: Some(serde_json::json!({
                    "code": -32000,
                    "message": e,
                    "data": { "trace_id": trace_id }
                })),
            },
        }
    }

    async fn tool_get_preview(
        &self,
        id: serde_json::Value,
        args: &serde_json::Value,
        trace_id: String,
    ) -> McpResponse {
        let preview_id = args["preview_id"].as_str().unwrap_or("");
        if let Some(preview) = self
            .mock_server
            .slot_manager()
            .get_preview(preview_id)
            .await
        {
            let sanitized_data = Sanitizer::sanitize(&preview.data.to_string());
            McpResponse {
                jsonrpc: "2.0".into(),
                id,
                result: Some(serde_json::json!({
                    "preview": preview,
                    "sanitized_view": sanitized_data.wrapped(),
                    "trace_id": trace_id
                })),
                error: None,
            }
        } else {
            McpResponse {
                jsonrpc: "2.0".into(),
                id,
                result: None,
                error: Some(serde_json::json!({
                    "code": -32004,
                    "message": format!("Preview '{preview_id}' not found"),
                    "data": { "trace_id": trace_id }
                })),
            }
        }
    }
}
