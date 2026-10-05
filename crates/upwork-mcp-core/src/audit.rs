//! Zero-Copy 128-Byte Binary Audit Flight Recorder for Upwork Operations.
//!
//! Provides a fixed-layout C-ABI 128-byte frame for mission-critical audit logging of proposals,
//! milestone actions, and supervisor authorizations. Employs hardware-accelerated SHA-256 digests
//! and tamper-evident cryptographic HMAC-SHA256 hash chaining.

use chrono::Utc;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

type HmacSha256 = Hmac<Sha256>;

/// Magic 4-byte header identifying Upwork MCP Audit Frame ("UPWK").
pub const AUDIT_MAGIC: [u8; 4] = *b"UPWK";

/// Binary audit frame specification version.
pub const AUDIT_VERSION: u16 = 1;

/// Event categories for Upwork audit logging.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum UpworkEventKind {
    ProposalDrafted = 1,
    ProposalPreviewed = 2,
    ProposalSubmitted = 3,
    MilestoneAction = 4,
    PreviewSuperseded = 5,
    SafetyFault = 6,
}

impl UpworkEventKind {
    pub const fn to_u8(self) -> u8 {
        self as u8
    }

    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            1 => Some(Self::ProposalDrafted),
            2 => Some(Self::ProposalPreviewed),
            3 => Some(Self::ProposalSubmitted),
            4 => Some(Self::MilestoneAction),
            5 => Some(Self::PreviewSuperseded),
            6 => Some(Self::SafetyFault),
            _ => None,
        }
    }
}

/// Errors occurring during binary audit verification or transmutation.
#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum AuditError {
    #[error("Audit verification failed: {0}")]
    VerificationFailed(String),

    #[error("Zero-copy transmutation failed: {0}")]
    TransmutationFailed(String),
}

/// Fixed-layout 128-byte C-ABI binary audit header.
///
/// Memory layout (zero uninitialized padding bytes):
/// - magic: 4 bytes (offset 0..4)
/// - version: 2 bytes (offset 4..6)
/// - event_kind: 1 byte (offset 6..7)
/// - status: 1 byte (offset 7..8)
/// - connects_spent: 4 bytes (offset 8..12)
/// - amount_cents: 4 bytes (offset 12..16)
/// - sequence_id: 8 bytes (offset 16..24)
/// - timestamp_epoch_ms: 8 bytes (offset 24..32)
/// - payload_digest: 32 bytes (offset 32..64)
/// - prev_signature: 32 bytes (offset 64..96)
/// - signature: 32 bytes (offset 96..128)
///
/// Total: exactly 128 bytes, 8-byte aligned.
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct BinaryAuditHeader {
    pub magic: [u8; 4],
    pub version: u16,
    pub event_kind: u8,
    pub status: u8,
    pub connects_spent: u32,
    pub amount_cents: u32,
    pub sequence_id: u64,
    pub timestamp_epoch_ms: u64,
    pub payload_digest: [u8; 32],
    pub prev_signature: [u8; 32],
    pub signature: [u8; 32],
}

impl BinaryAuditHeader {
    /// Constructs a new binary audit header with zero allocations.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        event_kind: UpworkEventKind,
        status: u8,
        connects_spent: u32,
        amount_cents: u32,
        sequence_id: u64,
        timestamp_epoch_ms: u64,
        payload_digest: [u8; 32],
        prev_signature: [u8; 32],
    ) -> Self {
        Self {
            magic: AUDIT_MAGIC,
            version: AUDIT_VERSION,
            event_kind: event_kind.to_u8(),
            status,
            connects_spent,
            amount_cents,
            sequence_id,
            timestamp_epoch_ms,
            payload_digest,
            prev_signature,
            signature: [0u8; 32],
        }
    }

    /// Safely transmutes a raw byte buffer into a structured `BinaryAuditHeader` zero-copy.
    pub fn from_bytes_zero_copy(bytes: &[u8]) -> Result<Self, AuditError> {
        let (header, _): (Self, &[u8]) = Self::read_from_prefix(bytes).map_err(|e| {
            AuditError::TransmutationFailed(format!("Zero-copy transmutation failed: {e:?}"))
        })?;

        if header.magic != AUDIT_MAGIC {
            return Err(AuditError::VerificationFailed(
                "Invalid audit magic header bytes".to_string(),
            ));
        }

        Ok(header)
    }

    /// Computes and signs this header in-place with HMAC-SHA256 across all header fields (offsets 0..96).
    pub fn sign(&mut self, secret: &[u8]) {
        let mut mac =
            HmacSha256::new_from_slice(secret).expect("HMAC supports arbitrary key length");
        let all_bytes = self.as_bytes();
        // Sign everything before the signature field (first 96 bytes)
        mac.update(&all_bytes[0..96]);
        let sig = mac.finalize().into_bytes();
        self.signature.copy_from_slice(&sig);
    }

    /// Verifies the cryptographic HMAC-SHA256 signature in-place.
    pub fn verify_signature(&self, secret: &[u8]) -> bool {
        let mut mac =
            HmacSha256::new_from_slice(secret).expect("HMAC supports arbitrary key length");
        let all_bytes = self.as_bytes();
        mac.update(&all_bytes[0..96]);
        mac.verify_slice(&self.signature).is_ok()
    }

    /// Verifies that a given payload slice matches the recorded `payload_digest`.
    pub fn verify_payload(&self, payload: &[u8]) -> bool {
        compute_payload_digest(payload) == self.payload_digest
    }
}

/// Computes a standard SHA-256 payload digest.
pub fn compute_payload_digest(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&result);
    digest
}

/// Cryptographic Upwork operation flight recorder.
pub struct UpworkFlightRecorder {
    secret: Vec<u8>,
    sequence_id: u64,
    last_signature: [u8; 32],
    frames: Vec<BinaryAuditHeader>,
}

impl UpworkFlightRecorder {
    /// Creates a new flight recorder initialized with a secret key.
    pub fn new(secret: &[u8]) -> Self {
        Self {
            secret: secret.to_vec(),
            sequence_id: 0,
            last_signature: [0u8; 32],
            frames: Vec::new(),
        }
    }

    /// Current sequence counter.
    pub fn sequence_id(&self) -> u64 {
        self.sequence_id
    }

    /// Records and cryptographically chains an Upwork event.
    pub fn record_event(
        &mut self,
        event_kind: UpworkEventKind,
        status: u8,
        connects_spent: u32,
        amount_cents: u32,
        payload_data: &[u8],
    ) -> BinaryAuditHeader {
        self.sequence_id = self.sequence_id.saturating_add(1);
        let timestamp_ms = Utc::now().timestamp_millis().max(0) as u64;
        let payload_digest = compute_payload_digest(payload_data);

        let mut header = BinaryAuditHeader::new(
            event_kind,
            status,
            connects_spent,
            amount_cents,
            self.sequence_id,
            timestamp_ms,
            payload_digest,
            self.last_signature,
        );

        header.sign(&self.secret);
        self.last_signature = header.signature;
        self.frames.push(header);
        header
    }

    /// Serializes a frame header to raw binary bytes zero-copy.
    pub fn export_frame_bytes(&self, header: &BinaryAuditHeader) -> Vec<u8> {
        header.as_bytes().to_vec()
    }

    /// Access the slice of recorded binary audit headers.
    pub fn frames(&self) -> &[BinaryAuditHeader] {
        &self.frames
    }

    /// Verifies the entire audit log sequence and cryptographic signature chain.
    pub fn verify_chain(&self) -> Result<(), AuditError> {
        let mut expected_seq = 1u64;
        let mut expected_prev_sig = [0u8; 32];

        for (i, frame) in self.frames.iter().enumerate() {
            if frame.magic != AUDIT_MAGIC {
                return Err(AuditError::VerificationFailed(format!(
                    "Frame {i} has invalid magic header"
                )));
            }

            if frame.sequence_id != expected_seq {
                return Err(AuditError::VerificationFailed(format!(
                    "Sequence gap detected at frame {i}: expected {expected_seq}, found {}",
                    frame.sequence_id
                )));
            }

            if frame.prev_signature != expected_prev_sig {
                return Err(AuditError::VerificationFailed(format!(
                    "Cryptographic chain broken at frame {i}: prev_signature mismatch"
                )));
            }

            if !frame.verify_signature(&self.secret) {
                return Err(AuditError::VerificationFailed(format!(
                    "Tampered signature detected at frame {i}"
                )));
            }

            expected_prev_sig = frame.signature;
            expected_seq = expected_seq.saturating_add(1);
        }

        Ok(())
    }

    /// Helper for testing: corrupts a byte in a recorded frame to verify tamper detection.
    pub fn corrupt_frame_for_test(&mut self, index: usize) {
        if let Some(frame) = self.frames.get_mut(index) {
            frame.amount_cents = frame.amount_cents.wrapping_add(1);
        }
    }

    /// Helper for testing: flips a specific bit in a frame's signature.
    pub fn flip_signature_bit_for_test(&mut self, frame_idx: usize, byte_idx: usize, bit_idx: u8) {
        if let Some(frame) = self.frames.get_mut(frame_idx) {
            if byte_idx < 32 {
                frame.signature[byte_idx] ^= 1 << (bit_idx % 8);
            }
        }
    }

    /// Helper for testing: flips a specific bit in a frame's previous signature.
    pub fn flip_prev_signature_bit_for_test(
        &mut self,
        frame_idx: usize,
        byte_idx: usize,
        bit_idx: u8,
    ) {
        if let Some(frame) = self.frames.get_mut(frame_idx) {
            if byte_idx < 32 {
                frame.prev_signature[byte_idx] ^= 1 << (bit_idx % 8);
            }
        }
    }
}
