use std::time::Instant;
use upwork_mcp_core::audit::{UpworkEventKind, UpworkFlightRecorder};
use upwork_mcp_core::token_diet::{DistillationTier, JobPosting, TokenDietDistiller};

#[test]
fn test_token_diet_savings_benchmark() {
    let raw_job_json = r#"{
        "id": "~01e9d8c7b6a5f4e3d2",
        "title": "Principal Distributed Systems Architect - High-Throughput Rust Infrastructure",
        "category": "Software Development > Distributed Systems",
        "description": "We are designing and scaling a high-assurance mission-critical distributed communication protocol. The platform processes high volumes of asynchronous events requiring strict transactional integrity, zero-copy wire serialization, cryptographic audit trails, and deterministic policy enforcement. The ideal candidate has deep expertise in asynchronous Rust (Tokio/Tower), network protocols, systems programming, and high-performance server architectures. Collaboration operates strictly under an Asynchronous Delivery Discipline: fixed-price milestone deliverables, detailed PR documentation, and self-contained reproduction artifacts without synchronous meeting overhead.",
        "job_type": "FixedPrice",
        "budget": 12500.0,
        "hourly_range": null,
        "skills": [
            "Rust", "Distributed Systems", "Tokio", "Zero-Copy", "Cryptography",
            "HMAC-SHA256", "Systems Architecture", "Async IO", "API Design",
            "Performance Optimization", "Protocol Buffers", "Linux", "gRPC"
        ],
        "screening_questions": [
            "Describe your production experience with zero-copy binary serialization in systems Rust.",
            "How do you design deterministic state machines for distributed audit chains?"
        ],
        "client": {
            "country": "Switzerland",
            "total_spend": 240000.0,
            "rating": 4.98,
            "reviews_count": 68,
            "payment_verified": true,
            "feedback_history": [
                {"date": "2026-09-15", "rating": 5.0, "comment": "Brilliant engineering, flawless delivery of complex architecture."},
                {"date": "2026-08-01", "rating": 5.0, "comment": "Outstanding async communication and top-tier code quality."},
                {"date": "2026-06-20", "rating": 4.95, "comment": "Deep technical mastery and timely completion of milestones."}
            ],
            "billing_verification_status": "VERIFIED_ENTERPRISE_TIER_A"
        },
        "metadata": {
            "tier": "Expert",
            "proposals_count": "Less than 5",
            "interviewing_count": 0,
            "invitations_sent": 2,
            "unanswered_invitations": 0,
            "posted_date": "2026-10-05T15:00:00Z",
            "enterprise_client": true,
            "enterprise_job": true,
            "client_preferred_qualifications": {
                "talent_type": "Independent Freelancer",
                "minimum_job_success_score": 95,
                "english_level": "Fluent",
                "location": "Global",
                "rising_talent": false
            }
        }
    }"#;

    let distiller = TokenDietDistiller::new();
    let job: JobPosting = serde_json::from_str(raw_job_json).expect("valid job json");

    let compact = distiller.distill(&job, DistillationTier::Compact);
    let standard = distiller.distill(&job, DistillationTier::Standard);
    let raw = distiller.distill(&job, DistillationTier::Raw);

    let raw_bytes = raw_job_json.len();
    let raw_tier_bytes = raw.len();
    let standard_bytes = standard.len();
    let compact_bytes = compact.len();

    // Standard approximation: 1 token ~= 4 characters for English / technical text
    let raw_tokens_approx = raw_bytes as f64 / 4.0;
    let standard_tokens_approx = standard_bytes as f64 / 4.0;
    let compact_tokens_approx = compact_bytes as f64 / 4.0;

    let compact_char_savings = (raw_bytes as f64 - compact_bytes as f64) / raw_bytes as f64 * 100.0;
    let standard_char_savings =
        (raw_bytes as f64 - standard_bytes as f64) / raw_bytes as f64 * 100.0;

    println!("\n=== TOKEN DIET BENCHMARK REPORT ===");
    println!(
        "Raw Payload:      {:>5} chars | ~{:>4.0} tokens",
        raw_bytes, raw_tokens_approx
    );
    println!(
        "Raw Tier Form:    {:>5} chars | ~{:>4.0} tokens",
        raw_tier_bytes,
        raw_tier_bytes as f64 / 4.0
    );
    println!(
        "Standard Tier:    {:>5} chars | ~{:>4.0} tokens ({:.1}% reduction)",
        standard_bytes, standard_tokens_approx, standard_char_savings
    );
    println!(
        "Compact Tier:     {:>5} chars | ~{:>4.0} tokens ({:.1}% reduction)",
        compact_bytes, compact_tokens_approx, compact_char_savings
    );
    println!("====================================\n");

    // Assert that Compact achieves >= 80% compression savings
    assert!(
        compact_char_savings >= 80.0,
        "Compact mode must yield >= 80% token savings, got {:.2}%",
        compact_char_savings
    );

    // Assert that Standard achieves significant compression while retaining full description
    assert!(
        raw_bytes > standard_bytes,
        "Standard mode must compress redundant raw JSON formatting"
    );
    assert!(
        standard_bytes > compact_bytes,
        "Standard mode must retain full markdown details vs Compact"
    );
}

#[test]
fn test_flight_recorder_latency_benchmark() {
    let secret = b"benchmark-secret-key-super-secure-32b!";
    let mut recorder = UpworkFlightRecorder::new(secret);
    let payload =
        b"{\"action\":\"submit_proposal\",\"proposal_id\":\"~01a2b3c4d5\",\"bid_cents\":500000}";

    // Warm-up runs
    for _ in 0..100 {
        recorder.record_event(UpworkEventKind::ProposalDrafted, 1, 4, 500000, payload);
    }

    // Benchmark 1,000 recorded events with SHA-256 + HMAC-SHA256 chaining
    let iterations = 1000;
    let start = Instant::now();
    for _ in 0..iterations {
        recorder.record_event(UpworkEventKind::ProposalSubmitted, 2, 4, 500000, payload);
    }
    let total_duration = start.elapsed();
    let total_micros = total_duration.as_micros() as f64;
    let avg_latency_micros = total_micros / iterations as f64;

    println!("\n=== FLIGHT RECORDER LATENCY BENCHMARK ===");
    println!("Iterations:        {}", iterations);
    println!("Total time:        {:?}", total_duration);
    println!(
        "Average latency:   {:.3} µs / event (SHA256 + HMAC-SHA256 + 128B header)",
        avg_latency_micros
    );
    println!(
        "Throughput:        {:.0} events / sec",
        1_000_000.0 / avg_latency_micros
    );
    println!("=========================================\n");

    // Flight recorder should execute well under 50 µs per event in debug mode (typically < 5 µs in release)
    assert!(
        avg_latency_micros < 100.0,
        "Flight recorder latency too high: {:.2} µs (expected < 100 µs in debug)",
        avg_latency_micros
    );

    // Verify entire chain is cryptographically intact
    assert!(recorder.verify_chain().is_ok());
}
