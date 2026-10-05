//! Virtual Upwork Mock Server for 100% Offline TDD.
//!
//! Provides realistic in-memory emulation of Upwork API endpoints:
//! - Job search (`find_jobs`) supporting both Fixed-Price and Hourly engagements.
//! - Proposal lifecycle: drafting, preview generation, and cryptographic witness confirmation.
//! - Attachment upload workflow (`start_attachment_upload`, `get_upload_status`, `confirm_attachment_upload`).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

use upwork_mcp_core::audit::{UpworkEventKind, UpworkFlightRecorder};
use upwork_mcp_core::ids::CiphertextId;
use upwork_mcp_core::policy::JobPricing;
use upwork_mcp_core::safety::{DraftProposal, OperatorWitness, SubmittedProposal};
use upwork_mcp_core::token_diet::{ClientStats, JobPosting};

use crate::preview_slots::{PreviewSlotManager, PreviewType};

/// Status descriptor for an attachment upload in progress.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadStatus {
    pub upload_id: String,
    pub filename: String,
    pub status: String,
    pub size_bytes: usize,
}

/// Permanent reference to a confirmed attachment upload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachmentReference {
    pub attachment_id: String,
    pub filename: String,
    pub confirmed_at_epoch_ms: u64,
}

/// In-memory mock server for offline verification and testing.
pub struct MockUpworkServer {
    jobs: Mutex<Vec<JobPosting>>,
    uploads: Mutex<HashMap<String, UploadStatus>>,
    slot_manager: PreviewSlotManager,
    flight_recorder: Arc<Mutex<UpworkFlightRecorder>>,
}

impl MockUpworkServer {
    /// Constructs a new `MockUpworkServer` seeded with standard commercial benchmark jobs.
    pub fn new(flight_recorder: Arc<Mutex<UpworkFlightRecorder>>) -> Self {
        let slot_manager = PreviewSlotManager::new(flight_recorder.clone());

        let default_jobs = vec![
            JobPosting {
                id: CiphertextId::new("~011234567890abcdef").unwrap(),
                title: "Senior Rust Systems Architect - Model Context Protocol Server".into(),
                description: "Design and implement a high-assurance Model Context Protocol server in async Rust with strict TDD and formal safety guarantees.".into(),
                category: "Software Development".into(),
                pricing: JobPricing::FixedPrice { budget: 4500.0 },
                skills: vec![
                    "Rust".into(),
                    "Tokio".into(),
                    "Model Context Protocol (MCP)".into(),
                    "Distributed Systems".into(),
                ],
                client: ClientStats {
                    total_spend: 150000.0,
                    rating: 4.95,
                    reviews_count: 35,
                    payment_verified: true,
                    country: "United States".into(),
                },
                screening_questions: vec![
                    "Describe your experience with async Rust and tokio streaming.".into(),
                ],
            },
            JobPosting {
                id: CiphertextId::new("~01fedcba0987654321").unwrap(),
                title: "Hourly Fullstack Support (Synchronous daily standups)".into(),
                description: "Looking for hourly dev to attend 9am daily standup video calls and log hours via tracker app.".into(),
                category: "Web Development".into(),
                pricing: JobPricing::Hourly { min_rate: 35.0, max_rate: 50.0 },
                skills: vec!["JavaScript".into(), "React".into()],
                client: ClientStats {
                    total_spend: 5000.0,
                    rating: 4.60,
                    reviews_count: 5,
                    payment_verified: true,
                    country: "Canada".into(),
                },
                screening_questions: vec![],
            },
            JobPosting {
                id: CiphertextId::new("~01aabbccddeeff0011").unwrap(),
                title: "Distributed JSON-RPC Microservice in Async Rust".into(),
                description: "Build an asynchronous high-throughput JSON-RPC service with HMAC cryptographic signing under Asynchronous Delivery Discipline.".into(),
                category: "Systems Architecture".into(),
                pricing: JobPricing::FixedPrice { budget: 3000.0 },
                skills: vec!["Rust".into(), "JSON-RPC".into(), "Axum".into()],
                client: ClientStats {
                    total_spend: 48000.0,
                    rating: 4.88,
                    reviews_count: 14,
                    payment_verified: true,
                    country: "United Kingdom".into(),
                },
                screening_questions: vec![],
            },
        ];

        Self {
            jobs: Mutex::new(default_jobs),
            uploads: Mutex::new(HashMap::new()),
            slot_manager,
            flight_recorder,
        }
    }

    /// Access reference to the preview slot manager.
    pub fn slot_manager(&self) -> &PreviewSlotManager {
        &self.slot_manager
    }

    /// Appends a custom job posting to the mock repository.
    pub async fn add_job(&self, job: JobPosting) {
        let mut jobs = self.jobs.lock().await;
        jobs.push(job);
    }

    /// Searches mock jobs by matching query against title, description, or skills.
    pub async fn find_jobs(&self, query: &str) -> Vec<JobPosting> {
        let q = query.to_lowercase();
        let jobs = self.jobs.lock().await;
        jobs.iter()
            .filter(|j| {
                q.is_empty()
                    || j.id.as_str().to_lowercase().contains(&q)
                    || j.title.to_lowercase().contains(&q)
                    || j.description.to_lowercase().contains(&q)
                    || j.skills.iter().any(|s| s.to_lowercase().contains(&q))
            })
            .cloned()
            .collect()
    }

    /// Creates an affine proposal preview for a target job.
    pub async fn draft_proposal(
        &self,
        job_id: &str,
        cover_letter: &str,
        amount: f64,
        connects_cost: u32,
    ) -> Result<String, String> {
        let cipher_id = CiphertextId::new(job_id).map_err(|e| e.to_string())?;
        let draft = DraftProposal::new(
            cipher_id.clone(),
            cover_letter.to_string(),
            amount,
            connects_cost,
        );
        let preview = draft.into_preview();
        let preview_id = preview.preview_id().to_string();

        let data = serde_json::json!({
            "preview_id": preview_id,
            "job_id": cipher_id.as_str(),
            "cover_letter": cover_letter,
            "amount": amount,
            "connects_cost": connects_cost,
        });

        // Use org_uid derived from job or default org
        let res = self
            .slot_manager
            .create_preview("org_default", PreviewType::Proposal, data)
            .await?;

        // Record flight recorder event for preview creation
        let mut recorder = self.flight_recorder.lock().await;
        let payload = format!(
            "PROPOSAL_PREVIEW:{}:{}:{:.2}",
            res.preview.preview_id, job_id, amount
        );
        recorder.record_event(
            UpworkEventKind::ProposalPreviewed,
            0,
            connects_cost,
            (amount * 100.0) as u32,
            payload.as_bytes(),
        );

        Ok(res.preview.preview_id)
    }

    /// Confirms and submits a preview using a cryptographically verified `OperatorWitness`.
    pub async fn confirm_preview(
        &self,
        preview_id: &str,
        witness: &OperatorWitness,
        secret: &[u8],
    ) -> Result<SubmittedProposal, String> {
        let now_ms = chrono::Utc::now().timestamp_millis().max(0) as u64;

        // Retrieve active pending preview
        let pending = self
            .slot_manager
            .get_preview(preview_id)
            .await
            .ok_or_else(|| format!("Preview '{preview_id}' not found or already consumed"))?;

        let job_id_str = pending.data["job_id"]
            .as_str()
            .ok_or_else(|| "Missing job_id in preview data".to_string())?;
        let cipher_id = CiphertextId::new(job_id_str).map_err(|e| e.to_string())?;
        let cover_letter = pending.data["cover_letter"].as_str().unwrap_or("");
        let amount = pending.data["amount"].as_f64().unwrap_or(0.0);
        let connects = pending.data["connects_cost"].as_u64().unwrap_or(0) as u32;

        let draft = DraftProposal::new(
            cipher_id.clone(),
            cover_letter.to_string(),
            amount,
            connects,
        );
        let preview = draft.into_preview();

        // Submit requires valid OperatorWitness
        match preview.submit(witness, secret, now_ms) {
            Ok(submitted) => {
                // Consume the preview
                self.slot_manager.consume_preview(preview_id).await;

                // Record flight recorder event
                let mut recorder = self.flight_recorder.lock().await;
                let payload = format!(
                    "PROPOSAL_SUBMITTED:{}:{}:{:.2}",
                    submitted.submission_id, submitted.job_id, submitted.amount
                );
                recorder.record_event(
                    UpworkEventKind::ProposalSubmitted,
                    0,
                    submitted.connects_spent,
                    (submitted.amount * 100.0) as u32,
                    payload.as_bytes(),
                );

                Ok(submitted)
            }
            Err(e) => {
                // Record safety fault audit event
                let mut recorder = self.flight_recorder.lock().await;
                let payload = format!("SAFETY_FAULT:confirm_preview:{}:{:?}", preview_id, e);
                recorder.record_event(
                    UpworkEventKind::SafetyFault,
                    1, // Error status
                    0,
                    0,
                    payload.as_bytes(),
                );

                Err(format!("OperatorWitness verification failed: {e}"))
            }
        }
    }

    /// Initiates an attachment upload session.
    pub async fn start_attachment_upload(
        &self,
        filename: &str,
        size_bytes: usize,
    ) -> Result<UploadStatus, String> {
        let upload_id = format!("upl_{}", uuid::Uuid::new_v4().simple());
        let status = UploadStatus {
            upload_id: upload_id.clone(),
            filename: filename.to_string(),
            status: "completed".to_string(),
            size_bytes,
        };

        let mut uploads = self.uploads.lock().await;
        uploads.insert(upload_id, status.clone());
        Ok(status)
    }

    /// Fetches the status of an ongoing or completed attachment upload.
    pub async fn get_upload_status(&self, upload_id: &str) -> Result<UploadStatus, String> {
        let uploads = self.uploads.lock().await;
        uploads
            .get(upload_id)
            .cloned()
            .ok_or_else(|| format!("Upload '{upload_id}' not found"))
    }

    /// Confirms an attachment upload, producing a permanent reference.
    pub async fn confirm_attachment_upload(
        &self,
        upload_id: &str,
    ) -> Result<AttachmentReference, String> {
        let uploads = self.uploads.lock().await;
        let upload = uploads
            .get(upload_id)
            .ok_or_else(|| format!("Upload '{upload_id}' not found"))?;

        let now_ms = chrono::Utc::now().timestamp_millis().max(0) as u64;
        Ok(AttachmentReference {
            attachment_id: format!("att_{}", upload.upload_id),
            filename: upload.filename.clone(),
            confirmed_at_epoch_ms: now_ms,
        })
    }
}
