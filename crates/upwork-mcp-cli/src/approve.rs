//! Supervisor Interlock and Cryptographic Witness Sign-off.
//!
//! Enforces:
//! - Executive High-Leverage Sentry
//! - Affine typestate consumption: preview terms are locked and single-use.
//! - Cryptographic HMAC-SHA256 OperatorWitness signatures.

use std::sync::Arc;
use thiserror::Error;

use upwork_mcp_core::safety::{OperatorWitness, SubmittedProposal};
use upwork_mcp_server::mock_server::MockUpworkServer;

use crate::cli::ApproveArgs;

/// Errors arising during supervisor approval and submission.
#[derive(Error, Debug)]
pub enum ApproveError {
    #[error("Mock server error: {0}")]
    Server(String),

    #[error("Preview '{0}' not found or already consumed")]
    PreviewNotFound(String),

    #[error("Missing or invalid field '{0}' in preview data")]
    InvalidPreviewData(String),
}

/// Structured outcome of supervisor approval and cryptographic submission.
#[derive(Debug, Clone)]
pub struct ApproveResult {
    pub submitted: SubmittedProposal,
    pub witness: OperatorWitness,
}

/// Executes supervisor verification, HMAC-SHA256 signing, and affine proposal submission.
pub async fn run_approve(
    server: Arc<MockUpworkServer>,
    args: &ApproveArgs,
) -> Result<ApproveResult, ApproveError> {
    let pending = server
        .slot_manager()
        .get_preview(&args.preview_id)
        .await
        .ok_or_else(|| ApproveError::PreviewNotFound(args.preview_id.clone()))?;

    let job_id = pending.data["job_id"]
        .as_str()
        .ok_or_else(|| ApproveError::InvalidPreviewData("job_id".to_string()))?;

    let amount = pending.data["amount"]
        .as_f64()
        .ok_or_else(|| ApproveError::InvalidPreviewData("amount".to_string()))?;

    let connects_cost = pending.data["connects_cost"]
        .as_u64()
        .ok_or_else(|| ApproveError::InvalidPreviewData("connects_cost".to_string()))?
        as u32;

    let now_ms = chrono::Utc::now().timestamp_millis().max(0) as u64;

    let witness = OperatorWitness::issue(
        &args.supervisor_id,
        job_id,
        amount,
        connects_cost,
        args.valid_for_ms,
        now_ms,
        args.secret.as_bytes(),
    );

    let submitted = server
        .confirm_preview(&args.preview_id, &witness, args.secret.as_bytes())
        .await
        .map_err(ApproveError::Server)?;

    Ok(ApproveResult { submitted, witness })
}
