//! Binary Flight Recorder Log Verifier.
//!
//! Validates the zero-copy binary flight recorder log (`audit.log`):
//! - Fixed sequential 128-byte binary headers.
//! - Monotonic sequence ID continuity.
//! - Unbroken previous block HMAC hash chains.
//! - Cryptographic HMAC-SHA256 signature authenticity.

use std::fs::File;
use std::io::Read;
use std::path::Path;
use thiserror::Error;

use upwork_mcp_core::audit::{BinaryAuditHeader, AUDIT_MAGIC};

/// Verification error conditions.
#[derive(Error, Debug)]
pub enum VerifierError {
    #[error("I/O error during log verification: {0}")]
    Io(#[from] std::io::Error),

    #[error("Verification failed: {0}")]
    VerificationFailed(String),
}

/// Structured report of an authenticated audit log verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditReport {
    pub total_frames: usize,
    pub first_sequence_id: u64,
    pub last_sequence_id: u64,
    pub total_connects_spent: u32,
    pub total_amount_cents: u32,
}

/// Reads and cryptographically verifies an audit log file.
pub fn verify_audit_log(path: &Path, secret: &[u8]) -> Result<AuditReport, VerifierError> {
    let mut file = File::open(path)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;

    if bytes.is_empty() {
        return Err(VerifierError::VerificationFailed(
            "Audit log is empty".to_string(),
        ));
    }

    if bytes.len() % 128 != 0 {
        return Err(VerifierError::VerificationFailed(format!(
            "Invalid audit log length {}: must be a multiple of 128 bytes",
            bytes.len()
        )));
    }

    let total_frames = bytes.len() / 128;
    let mut expected_seq = 1u64;
    let mut expected_prev_sig = [0u8; 32];
    let mut total_connects_spent = 0u32;
    let mut total_amount_cents = 0u32;
    let mut first_sequence_id = 0u64;
    let mut last_sequence_id = 0u64;

    for i in 0..total_frames {
        let chunk = &bytes[i * 128..(i + 1) * 128];
        let frame = BinaryAuditHeader::from_bytes_zero_copy(chunk).map_err(|e| {
            VerifierError::VerificationFailed(format!("Frame {i} failed zero-copy parsing: {e}"))
        })?;

        if frame.magic != AUDIT_MAGIC {
            return Err(VerifierError::VerificationFailed(format!(
                "Frame {i} has invalid magic header"
            )));
        }

        if frame.sequence_id != expected_seq {
            return Err(VerifierError::VerificationFailed(format!(
                "Sequence gap at frame {i}: expected {expected_seq}, found {}",
                frame.sequence_id
            )));
        }

        if frame.prev_signature != expected_prev_sig {
            return Err(VerifierError::VerificationFailed(format!(
                "Cryptographic chain broken at frame {i}: prev_signature mismatch"
            )));
        }

        if !frame.verify_signature(secret) {
            return Err(VerifierError::VerificationFailed(format!(
                "Tampered signature detected at frame {i}"
            )));
        }

        if i == 0 {
            first_sequence_id = frame.sequence_id;
        }
        last_sequence_id = frame.sequence_id;

        total_connects_spent = total_connects_spent.saturating_add(frame.connects_spent);
        total_amount_cents = total_amount_cents.saturating_add(frame.amount_cents);

        expected_prev_sig = frame.signature;
        expected_seq = expected_seq.saturating_add(1);
    }

    Ok(AuditReport {
        total_frames,
        first_sequence_id,
        last_sequence_id,
        total_connects_spent,
        total_amount_cents,
    })
}
