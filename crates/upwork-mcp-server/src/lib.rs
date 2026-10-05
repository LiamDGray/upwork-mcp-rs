//! Upwork MCP Server: High-Assurance Model Context Protocol Runtime.
//!
//! Provides:
//! - Concurrency-controlled preview slot manager.
//! - Proactive OAuth token vault with atomic lock.
//! - Virtual Upwork mock server for offline TDD.
//! - MCP JSON-RPC 2.0 tool dispatcher with prompt injection defense.
//! - Streamable HTTP/SSE transport with DNS rebinding protection.

pub mod auth;
pub mod dispatcher;
pub mod mock_server;
pub mod preview_slots;
pub mod streaming;
