use std::mem::{align_of, size_of};
use upwork_mcp_core::audit::{
    BinaryAuditHeader, UpworkEventKind, UpworkFlightRecorder, AUDIT_MAGIC, AUDIT_VERSION,
};

#[test]
fn test_binary_audit_header_layout_and_alignment() {
    // 1. Assert exact 128-byte size and 8-byte alignment (C-ABI standard)
    assert_eq!(
        size_of::<BinaryAuditHeader>(),
        128,
        "BinaryAuditHeader must be exactly 128 bytes"
    );
    assert_eq!(
        align_of::<BinaryAuditHeader>(),
        8,
        "BinaryAuditHeader must have 8-byte alignment"
    );
}

#[test]
fn test_binary_audit_header_zerocopy_transmutation_miri() {
    // Construct a valid header
    let payload = b"{\"event\":\"proposal_draft\",\"freelancer_id\":\"~01a2b3c4d5\"}";
    let payload_digest = upwork_mcp_core::audit::compute_payload_digest(payload);
    let prev_sig = [0x5au8; 32];

    let mut header = BinaryAuditHeader::new(
        UpworkEventKind::ProposalDrafted,
        1,
        4,
        250000,
        42,
        1728100000000,
        payload_digest,
        prev_sig,
    );
    let secret = b"miri-verification-secret-key-32b!";
    header.sign(secret);

    // 2. Transmute to bytes using zerocopy (safe, defined provenance)
    use zerocopy::IntoBytes;
    let bytes = header.as_bytes();
    assert_eq!(bytes.len(), 128);

    // 3. Round-trip transmute back using from_bytes_zero_copy
    let decoded = BinaryAuditHeader::from_bytes_zero_copy(bytes)
        .expect("zero-copy transmutation must succeed");
    assert_eq!(decoded.magic, AUDIT_MAGIC);
    assert_eq!(decoded.version, AUDIT_VERSION);
    assert_eq!(decoded.event_kind, UpworkEventKind::ProposalDrafted.to_u8());
    assert_eq!(decoded.status, 1);
    assert_eq!(decoded.connects_spent, 4);
    assert_eq!(decoded.amount_cents, 250000);
    assert_eq!(decoded.sequence_id, 42);
    assert_eq!(decoded.timestamp_epoch_ms, 1728100000000);
    assert_eq!(decoded.payload_digest, payload_digest);
    assert_eq!(decoded.prev_signature, prev_sig);
    assert_eq!(decoded.signature, header.signature);

    // 4. Verify signature validity through decoded transmutation
    assert!(decoded.verify_signature(secret));
    assert!(decoded.verify_payload(payload));
}

#[test]
fn test_binary_audit_pointer_provenance_and_buffer_slices() {
    let mut buffer = [0u8; 256];
    // Fill first 128 bytes with header data
    let header = BinaryAuditHeader::new(
        UpworkEventKind::MilestoneAction,
        0,
        0,
        50000,
        1,
        1728100050000,
        [0x11u8; 32],
        [0x22u8; 32],
    );

    use zerocopy::IntoBytes;
    buffer[..128].copy_from_slice(header.as_bytes());

    // Transmute from subslice, verifying bounds and provenance under Miri
    let parsed = BinaryAuditHeader::from_bytes_zero_copy(&buffer[..128])
        .expect("must transmute from aligned buffer prefix");
    assert_eq!(parsed.event_kind, UpworkEventKind::MilestoneAction.to_u8());
    assert_eq!(parsed.amount_cents, 50000);

    // Transmute with insufficient bytes must fail gracefully without UB
    assert!(BinaryAuditHeader::from_bytes_zero_copy(&buffer[..127]).is_err());
    assert!(BinaryAuditHeader::from_bytes_zero_copy(&buffer[..64]).is_err());
    assert!(BinaryAuditHeader::from_bytes_zero_copy(&[]).is_err());
}

#[test]
fn test_flight_recorder_cryptographic_chain_miri() {
    let secret = b"flight-recorder-miri-test-key-99";
    let mut recorder = UpworkFlightRecorder::new(secret);

    // Record sequence of chained frames
    for i in 1..=5 {
        let payload = format!("{{\"step\":{i}}}");
        recorder.record_event(
            UpworkEventKind::MilestoneAction,
            0,
            i as u32 * 2,
            i as u32 * 10000,
            payload.as_bytes(),
        );
    }

    assert_eq!(recorder.sequence_id(), 5);
    assert!(recorder.verify_chain().is_ok());

    // Export frames and verify zero-copy roundtrip of chained frames
    for frame in recorder.frames() {
        let exported = recorder.export_frame_bytes(frame);
        let parsed = BinaryAuditHeader::from_bytes_zero_copy(&exported)
            .expect("exported frame must transmute cleanly");
        assert_eq!(&parsed, frame);
        assert!(parsed.verify_signature(secret));
    }
}
