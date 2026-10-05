//! Preview Slot Manager and Concurrency Controller for Upwork Operations.
//!
//! Enforces single-pending preview concurrency per `(OrgUid, PreviewType)` tuple:
//! - When a new preview of the same type is generated for an organization, any active
//!   preview is immediately superseded and invalidated.
//! - Emits a tamper-evident audit record (`UpworkEventKind::PreviewSuperseded`) in the
//!   binary flight recorder upon superseding.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

use upwork_mcp_core::audit::{UpworkEventKind, UpworkFlightRecorder};

/// Categories of previews managed by the slot controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PreviewType {
    Proposal,
    MilestoneSubmission,
    AttachmentUpload,
}

/// Active pending preview record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingPreview {
    pub preview_id: String,
    pub org_uid: String,
    pub preview_type: PreviewType,
    pub data: serde_json::Value,
    pub created_at_epoch_ms: u64,
}

/// Result of creating a preview, indicating whether a previous preview was superseded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePreviewResult {
    pub preview: PendingPreview,
    pub supersedes_previous_preview: bool,
    pub superseded_preview_id: Option<String>,
}

struct SlotState {
    /// Active preview mapping by (OrgUid, PreviewType) -> preview_id
    active_by_slot: HashMap<(String, PreviewType), String>,
    /// Previews by preview_id
    previews_by_id: HashMap<String, PendingPreview>,
}

/// Concurrency controller for pending Upwork operations.
pub struct PreviewSlotManager {
    state: Mutex<SlotState>,
    flight_recorder: Arc<Mutex<UpworkFlightRecorder>>,
}

impl PreviewSlotManager {
    /// Constructs a new `PreviewSlotManager` backed by a cryptographic flight recorder.
    pub fn new(flight_recorder: Arc<Mutex<UpworkFlightRecorder>>) -> Self {
        Self {
            state: Mutex::new(SlotState {
                active_by_slot: HashMap::new(),
                previews_by_id: HashMap::new(),
            }),
            flight_recorder,
        }
    }

    /// Creates a preview under `(org_uid, preview_type)`.
    ///
    /// If an active preview already exists for this slot, it is superseded and invalidated,
    /// and a binary audit event (`PreviewSuperseded`) is recorded.
    pub async fn create_preview(
        &self,
        org_uid: &str,
        preview_type: PreviewType,
        data: serde_json::Value,
    ) -> Result<CreatePreviewResult, String> {
        let now_ms = chrono::Utc::now().timestamp_millis().max(0) as u64;
        let preview_id = format!("prev_{}_{}", uuid::Uuid::new_v4().simple(), now_ms);

        let new_preview = PendingPreview {
            preview_id: preview_id.clone(),
            org_uid: org_uid.to_string(),
            preview_type,
            data,
            created_at_epoch_ms: now_ms,
        };

        let mut superseded_id = None;
        let mut supersedes = false;

        {
            let mut state = self.state.lock().await;
            let slot_key = (org_uid.to_string(), preview_type);

            if let Some(old_id) = state.active_by_slot.insert(slot_key, preview_id.clone()) {
                supersedes = true;
                superseded_id = Some(old_id.clone());
                state.previews_by_id.remove(&old_id);
            }

            state.previews_by_id.insert(preview_id, new_preview.clone());
        }

        if let Some(ref old_id) = superseded_id {
            let audit_payload = format!(
                "PREVIEW_SUPERSEDED:org={}:type={:?}:old={}:new={}",
                org_uid, preview_type, old_id, new_preview.preview_id
            );
            let mut recorder = self.flight_recorder.lock().await;
            recorder.record_event(
                UpworkEventKind::PreviewSuperseded,
                0, // OK status
                0, // 0 connects
                0, // 0 amount
                audit_payload.as_bytes(),
            );
        }

        Ok(CreatePreviewResult {
            preview: new_preview,
            supersedes_previous_preview: supersedes,
            superseded_preview_id: superseded_id,
        })
    }

    /// Fetches an active preview by ID without consuming it.
    pub async fn get_preview(&self, preview_id: &str) -> Option<PendingPreview> {
        let state = self.state.lock().await;
        state.previews_by_id.get(preview_id).cloned()
    }

    /// Consumes and removes an active preview by ID (single linear consumption).
    pub async fn consume_preview(&self, preview_id: &str) -> Option<PendingPreview> {
        let mut state = self.state.lock().await;
        if let Some(preview) = state.previews_by_id.remove(preview_id) {
            let slot_key = (preview.org_uid.clone(), preview.preview_type);
            if let Some(curr) = state.active_by_slot.get(&slot_key) {
                if curr == preview_id {
                    state.active_by_slot.remove(&slot_key);
                }
            }
            Some(preview)
        } else {
            None
        }
    }

    /// Returns the count of currently active previews.
    pub async fn active_previews_count(&self) -> usize {
        let state = self.state.lock().await;
        state.previews_by_id.len()
    }
}
