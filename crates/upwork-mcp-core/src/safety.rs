//! High-Assurance Operator Safety Interlock and Cryptographic Witness Typestates.
//!
//! Enforces affine (linear single-consumption) typestates for safety-critical Upwork operations:
//! `DraftProposal` -> `ProposalPreview` -> [OperatorWitness Verification] -> `SubmittedProposal`.
//! Spending Connects or binding contracts requires an HMAC-SHA256 supervisor authorization token.

use crate::ids::CiphertextId;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::marker::PhantomData;
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;

/// Errors occurring during proposal submission safety checks and witness authorization.
#[derive(Error, Debug, PartialEq, Clone)]
pub enum SafetyError {
    #[error("Supervisor authorization expired at {expires_at}, current time is {now}")]
    AuthorizationExpired { expires_at: u64, now: u64 },

    #[error("Cryptographic supervisor signature verification failed")]
    SignatureVerificationFailed,

    #[error("Target job ID mismatch: authorized for {expected}, attempted {actual}")]
    JobMismatch { expected: String, actual: String },

    #[error(
        "Proposal amount mismatch: authorized for ${authorized:.2}, attempted ${attempted:.2}"
    )]
    AmountMismatch { authorized: f64, attempted: f64 },

    #[error("Connects cost exceeds authorization: authorized {authorized}, attempted {attempted}")]
    ConnectsMismatch { authorized: u32, attempted: u32 },
}

/// Cryptographically signed supervisor witness token authorizing a proposal submission or Connects spend.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct OperatorWitness {
    pub supervisor_id: String,
    pub target_job_id: String,
    pub authorized_amount: f64,
    pub authorized_connects: u32,
    pub expires_at_epoch_ms: u64,
    pub authorization_token: String,
}

impl OperatorWitness {
    /// Formats the canonical binary payload for HMAC-SHA256 signing.
    fn canonical_payload(
        supervisor_id: &str,
        target_job_id: &str,
        authorized_amount: f64,
        authorized_connects: u32,
        expires_at_epoch_ms: u64,
    ) -> Vec<u8> {
        format!(
            "UPWORK_SUBMIT_PROPOSAL:{}:{}:{:.2}:{}:{}",
            supervisor_id,
            target_job_id,
            authorized_amount,
            authorized_connects,
            expires_at_epoch_ms
        )
        .into_bytes()
    }

    /// Issues and signs a new `OperatorWitness` using HMAC-SHA256.
    pub fn issue(
        supervisor_id: impl Into<String>,
        target_job_id: impl Into<String>,
        authorized_amount: f64,
        authorized_connects: u32,
        valid_for_ms: u64,
        current_time_ms: u64,
        secret: &[u8],
    ) -> Self {
        let supervisor_id = supervisor_id.into();
        let target_job_id = target_job_id.into();
        let expires_at_epoch_ms = current_time_ms.saturating_add(valid_for_ms);

        let payload = Self::canonical_payload(
            &supervisor_id,
            &target_job_id,
            authorized_amount,
            authorized_connects,
            expires_at_epoch_ms,
        );

        let mut mac =
            HmacSha256::new_from_slice(secret).expect("HMAC supports arbitrary key length");
        mac.update(&payload);
        let signature_bytes = mac.finalize().into_bytes();
        let authorization_token = hex::encode(signature_bytes);

        Self {
            supervisor_id,
            target_job_id,
            authorized_amount,
            authorized_connects,
            expires_at_epoch_ms,
            authorization_token,
        }
    }

    /// Access the hex authorization token.
    pub fn authorization_token(&self) -> &str {
        &self.authorization_token
    }

    /// Verifies the HMAC-SHA256 cryptographic signature and expiry against current time.
    pub fn verify(&self, secret: &[u8], current_time_ms: u64) -> Result<(), SafetyError> {
        if current_time_ms > self.expires_at_epoch_ms {
            return Err(SafetyError::AuthorizationExpired {
                expires_at: self.expires_at_epoch_ms,
                now: current_time_ms,
            });
        }

        let payload = Self::canonical_payload(
            &self.supervisor_id,
            &self.target_job_id,
            self.authorized_amount,
            self.authorized_connects,
            self.expires_at_epoch_ms,
        );

        let mut mac =
            HmacSha256::new_from_slice(secret).expect("HMAC supports arbitrary key length");
        mac.update(&payload);

        let expected_bytes = match hex::decode(&self.authorization_token) {
            Ok(b) => b,
            Err(_) => return Err(SafetyError::SignatureVerificationFailed),
        };

        mac.verify_slice(&expected_bytes)
            .map_err(|_| SafetyError::SignatureVerificationFailed)
    }
}

/// Draft Proposal Typestate: uncommitted, non-binding draft.
#[derive(Debug, Clone, PartialEq)]
pub struct DraftProposal {
    job_id: CiphertextId,
    cover_letter: String,
    amount: f64,
    connects_cost: u32,
}

impl DraftProposal {
    /// Creates a new draft proposal.
    pub fn new(
        job_id: CiphertextId,
        cover_letter: String,
        amount: f64,
        connects_cost: u32,
    ) -> Self {
        Self {
            job_id,
            cover_letter,
            amount,
            connects_cost,
        }
    }

    /// Transitions to `ProposalPreview`, freezing proposal terms for human/supervisor review.
    pub fn into_preview(self) -> ProposalPreview {
        let preview_id = format!("prev_{}", self.job_id.as_str().trim_start_matches('~'));
        ProposalPreview {
            preview_id,
            job_id: self.job_id,
            cover_letter: self.cover_letter,
            amount: self.amount,
            connects_cost: self.connects_cost,
        }
    }
}

/// Frozen Preview Typestate: terms are locked awaiting cryptographic supervisor sign-off.
#[derive(Debug, Clone, PartialEq)]
pub struct ProposalPreview {
    preview_id: String,
    job_id: CiphertextId,
    cover_letter: String,
    amount: f64,
    connects_cost: u32,
}

impl ProposalPreview {
    pub fn preview_id(&self) -> &str {
        &self.preview_id
    }

    pub fn job_id(&self) -> &CiphertextId {
        &self.job_id
    }

    pub fn cover_letter(&self) -> &str {
        &self.cover_letter
    }

    pub fn amount(&self) -> f64 {
        self.amount
    }

    pub fn connects_cost(&self) -> u32 {
        self.connects_cost
    }

    /// Submits the proposal, consuming this preview typestate (affine linear consumption).
    ///
    /// Requires a cryptographically verified `OperatorWitness` authorizing the exact job,
    /// amount, and Connects budget.
    pub fn submit(
        self,
        witness: &OperatorWitness,
        secret: &[u8],
        current_time_ms: u64,
    ) -> Result<SubmittedProposal, SafetyError> {
        // 1. Verify witness signature & expiry
        witness.verify(secret, current_time_ms)?;

        // 2. Validate job ID matches
        if witness.target_job_id != self.job_id.as_str() {
            return Err(SafetyError::JobMismatch {
                expected: witness.target_job_id.clone(),
                actual: self.job_id.as_str().to_string(),
            });
        }

        // 3. Validate authorized amount matches
        if (witness.authorized_amount - self.amount).abs() > 0.001 {
            return Err(SafetyError::AmountMismatch {
                authorized: witness.authorized_amount,
                attempted: self.amount,
            });
        }

        // 4. Validate authorized connects covers proposal cost
        if witness.authorized_connects < self.connects_cost {
            return Err(SafetyError::ConnectsMismatch {
                authorized: witness.authorized_connects,
                attempted: self.connects_cost,
            });
        }

        let submission_id = format!("sub_{}", self.preview_id);

        Ok(SubmittedProposal {
            submission_id,
            job_id: self.job_id,
            amount: self.amount,
            connects_spent: self.connects_cost,
            witness_token: witness.authorization_token.clone(),
            submitted_at_epoch_ms: current_time_ms,
        })
    }
}

/// Submitted Proposal Typestate: irreversible state after witness execution.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SubmittedProposal {
    pub submission_id: String,
    pub job_id: CiphertextId,
    pub amount: f64,
    pub connects_spent: u32,
    pub witness_token: String,
    pub submitted_at_epoch_ms: u64,
}

impl SubmittedProposal {
    pub fn job_id(&self) -> &CiphertextId {
        &self.job_id
    }

    pub fn witness_token(&self) -> &str {
        &self.witness_token
    }
}

/// Generic operator safety interlock typestate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Safe;

#[derive(Debug, PartialEq, Eq)]
pub struct Armed;

/// Affine Typestate Interlock for Connects expenditures and proposal actions.
#[derive(Debug)]
pub struct OperatorSafetyInterlock<State> {
    _state: PhantomData<State>,
}

impl OperatorSafetyInterlock<Safe> {
    pub fn new() -> Self {
        Self {
            _state: PhantomData,
        }
    }

    pub const fn is_armed(&self) -> bool {
        false
    }
}

impl Default for OperatorSafetyInterlock<Safe> {
    fn default() -> Self {
        Self::new()
    }
}

impl OperatorSafetyInterlock<Armed> {
    pub const fn is_armed(&self) -> bool {
        true
    }
}
