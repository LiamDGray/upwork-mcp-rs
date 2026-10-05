//! Integration tests for upwork-mcp-cli.
//!
//! Enforces:
//! - Asynchronous Delivery Discipline
//! - Autonomous Delivery Policy
//! - Fixed-Price Milestone Policy
//! - Executive High-Leverage Sentry

use clap::Parser;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

use upwork_mcp_cli::approve::run_approve;
use upwork_mcp_cli::cli::{ApproveArgs, Cli, Commands, ScoutArgs};
use upwork_mcp_cli::config::{generate_all_configs, generate_client_config, ClientType};
use upwork_mcp_cli::scout::run_scout;
use upwork_mcp_cli::verifier::verify_audit_log;
use upwork_mcp_core::audit::{UpworkEventKind, UpworkFlightRecorder};
use upwork_mcp_core::policy::PolicyViolationKind;
use upwork_mcp_server::mock_server::MockUpworkServer;

#[test]
fn test_cli_parsing() {
    // 1. Test serve subcommand with stdio, mock, and custom audit log
    let args = vec![
        "upwork-mcp-rs",
        "serve",
        "--stdio",
        "--mock",
        "--audit-log",
        "custom_audit.log",
    ];
    let cli = Cli::try_parse_from(args).expect("Failed to parse serve args");
    match cli.command {
        Commands::Serve(serve) => {
            assert!(serve.stdio);
            assert!(serve.mock);
            assert_eq!(serve.audit_log, PathBuf::from("custom_audit.log"));
            assert_eq!(serve.port, None);
        }
        _ => panic!("Expected Serve command"),
    }

    // 2. Test serve with port
    let args = vec!["upwork-mcp-rs", "serve", "--port", "9090"];
    let cli = Cli::try_parse_from(args).expect("Failed to parse serve port args");
    match cli.command {
        Commands::Serve(serve) => {
            assert_eq!(serve.port, Some(9090));
            assert!(!serve.stdio);
        }
        _ => panic!("Expected Serve command"),
    }

    // 3. Test scout subcommand
    let args = vec![
        "upwork-mcp-rs",
        "scout",
        "--query",
        "Rust",
        "--mock",
        "--min-budget",
        "2000.0",
        "--min-client-spend",
        "5000.0",
        "--min-client-rating",
        "4.85",
    ];
    let cli = Cli::try_parse_from(args).expect("Failed to parse scout args");
    match cli.command {
        Commands::Scout(scout) => {
            assert_eq!(scout.query, "Rust");
            assert!(scout.mock);
            assert_eq!(scout.min_budget, 2000.0);
            assert_eq!(scout.min_client_spend, 5000.0);
            assert_eq!(scout.min_client_rating, 4.85);
        }
        _ => panic!("Expected Scout command"),
    }

    // 4. Test approve subcommand
    let args = vec![
        "upwork-mcp-rs",
        "approve",
        "--preview-id",
        "prev_12345",
        "--supervisor-id",
        "supervisor-chief-1",
        "--secret",
        "exec-secret-99",
        "--mock",
    ];
    let cli = Cli::try_parse_from(args).expect("Failed to parse approve args");
    match cli.command {
        Commands::Approve(approve) => {
            assert_eq!(approve.preview_id, "prev_12345");
            assert_eq!(approve.supervisor_id, "supervisor-chief-1");
            assert_eq!(approve.secret, "exec-secret-99");
            assert!(approve.mock);
        }
        _ => panic!("Expected Approve command"),
    }

    // 5. Test audit-verify subcommand
    let args = vec![
        "upwork-mcp-rs",
        "audit-verify",
        "--path",
        "audit_sec.log",
        "--secret",
        "audit-key-secret",
    ];
    let cli = Cli::try_parse_from(args).expect("Failed to parse audit-verify args");
    match cli.command {
        Commands::AuditVerify(audit) => {
            assert_eq!(audit.path, PathBuf::from("audit_sec.log"));
            assert_eq!(audit.secret, "audit-key-secret");
        }
        _ => panic!("Expected AuditVerify command"),
    }

    // 6. Test config subcommand
    let args = vec!["upwork-mcp-rs", "config", "--client", "claude"];
    let cli = Cli::try_parse_from(args).expect("Failed to parse config args");
    match cli.command {
        Commands::Config(cfg) => {
            assert_eq!(cfg.client.as_deref(), Some("claude"));
            assert!(!cfg.all);
        }
        _ => panic!("Expected Config command"),
    }

    let args = vec!["upwork-mcp-rs", "config", "--all"];
    let cli = Cli::try_parse_from(args).expect("Failed to parse config --all args");
    match cli.command {
        Commands::Config(cfg) => {
            assert!(cfg.all);
            assert_eq!(cfg.client, None);
        }
        _ => panic!("Expected Config command"),
    }
}

#[test]
fn test_config_generation() {
    let dummy_path = PathBuf::from("/usr/local/bin/upwork-mcp-rs");

    // Claude Desktop configuration
    let claude_cfg = generate_client_config(ClientType::Claude, &dummy_path);
    assert_eq!(
        claude_cfg["mcpServers"]["upwork"]["command"],
        "/usr/local/bin/upwork-mcp-rs"
    );
    assert_eq!(
        claude_cfg["mcpServers"]["upwork"]["args"],
        serde_json::json!(["serve", "--stdio"])
    );

    // Cursor configuration
    let cursor_cfg = generate_client_config(ClientType::Cursor, &dummy_path);
    assert_eq!(
        cursor_cfg["mcpServers"]["upwork"]["command"],
        "/usr/local/bin/upwork-mcp-rs"
    );
    assert_eq!(
        cursor_cfg["mcpServers"]["upwork"]["args"],
        serde_json::json!(["serve", "--stdio"])
    );

    // Zed configuration
    let zed_cfg = generate_client_config(ClientType::Zed, &dummy_path);
    assert_eq!(
        zed_cfg["context_servers"]["upwork"]["command"]["path"],
        "/usr/local/bin/upwork-mcp-rs"
    );
    assert_eq!(
        zed_cfg["context_servers"]["upwork"]["command"]["args"],
        serde_json::json!(["serve", "--stdio"])
    );

    // Cline configuration
    let cline_cfg = generate_client_config(ClientType::Cline, &dummy_path);
    assert_eq!(
        cline_cfg["mcpServers"]["upwork"]["command"],
        "/usr/local/bin/upwork-mcp-rs"
    );
    assert_eq!(
        cline_cfg["mcpServers"]["upwork"]["args"],
        serde_json::json!(["serve", "--stdio"])
    );
    assert_eq!(cline_cfg["mcpServers"]["upwork"]["disabled"], false);

    // All configurations combined
    let all_configs = generate_all_configs(&dummy_path);
    assert!(all_configs.get("claude").is_some());
    assert!(all_configs.get("cursor").is_some());
    assert!(all_configs.get("zed").is_some());
    assert!(all_configs.get("cline").is_some());
}

#[test]
fn test_audit_verifier() {
    let temp_dir = tempfile::tempdir().expect("Failed to create tempdir");
    let log_path = temp_dir.path().join("audit.log");
    let secret = b"executive_supervisory_secret_hmac_256";

    // 1. Build a valid flight log with 5 distinct sequential operations
    let mut recorder = UpworkFlightRecorder::new(secret);
    recorder.record_event(
        UpworkEventKind::ProposalPreviewed,
        0,
        16,
        450_000,
        b"PROPOSAL_PREVIEW:~011234567890abcdef:4500.00",
    );
    recorder.record_event(
        UpworkEventKind::ProposalSubmitted,
        0,
        16,
        450_000,
        b"PROPOSAL_SUBMITTED:sub_1:4500.00",
    );
    recorder.record_event(
        UpworkEventKind::ProposalPreviewed,
        0,
        12,
        300_000,
        b"PROPOSAL_PREVIEW:~01aabbccddeeff0011:3000.00",
    );
    recorder.record_event(
        UpworkEventKind::ProposalSubmitted,
        0,
        12,
        300_000,
        b"PROPOSAL_SUBMITTED:sub_2:3000.00",
    );
    recorder.record_event(
        UpworkEventKind::SafetyFault,
        1,
        0,
        0,
        b"SAFETY_FAULT:tamper_attempt",
    );

    // Export raw 128-byte binary frames to file
    let mut file = std::fs::File::create(&log_path).expect("Failed to create audit log file");
    for frame in recorder.frames() {
        let frame_bytes = recorder.export_frame_bytes(frame);
        assert_eq!(frame_bytes.len(), 128);
        file.write_all(&frame_bytes).expect("Failed to write frame");
    }
    file.sync_all().expect("Sync failed");
    drop(file);

    // Verify valid audit log
    let report =
        verify_audit_log(&log_path, secret).expect("Verification should succeed for authentic log");
    assert_eq!(report.total_frames, 5);
    assert_eq!(report.first_sequence_id, 1);
    assert_eq!(report.last_sequence_id, 5);
    assert_eq!(report.total_connects_spent, 56);
    assert_eq!(report.total_amount_cents, 1_500_000);

    // Wrong secret must fail verification
    let wrong_secret = b"wrong_unauthorized_key";
    let wrong_res = verify_audit_log(&log_path, wrong_secret);
    assert!(
        wrong_res.is_err(),
        "Verification must fail with invalid secret"
    );

    // Tampering test: corrupt a single byte in the binary log file
    let log_bytes = std::fs::read(&log_path).expect("Failed to read log");
    assert_eq!(log_bytes.len(), 128 * 5);

    // Flip bit in the payload digest of frame 1 (byte 40)
    let mut tampered_bytes = log_bytes.clone();
    tampered_bytes[40] ^= 0x01;
    let tampered_path = temp_dir.path().join("audit_tampered.log");
    std::fs::write(&tampered_path, &tampered_bytes).expect("Failed to write tampered file");
    let tamper_res = verify_audit_log(&tampered_path, secret);
    assert!(
        tamper_res.is_err(),
        "Verification must fail when payload digest is tampered"
    );

    // Flip bit in the HMAC signature of frame 3 (offset 128 * 2 + 100)
    let mut tampered_sig_bytes = log_bytes.clone();
    tampered_sig_bytes[128 * 2 + 100] ^= 0x80;
    let tampered_sig_path = temp_dir.path().join("audit_tampered_sig.log");
    std::fs::write(&tampered_sig_path, &tampered_sig_bytes).expect("Failed to write tampered sig");
    let tamper_sig_res = verify_audit_log(&tampered_sig_path, secret);
    assert!(
        tamper_sig_res.is_err(),
        "Verification must fail when HMAC signature is tampered"
    );

    // Truncated/corrupted length test (not a multiple of 128 bytes)
    let invalid_len_path = temp_dir.path().join("audit_invalid_len.log");
    std::fs::write(&invalid_len_path, &log_bytes[0..100]).expect("Write truncated");
    let invalid_len_res = verify_audit_log(&invalid_len_path, secret);
    assert!(
        invalid_len_res.is_err(),
        "Verification must fail on truncated binary frames"
    );
}

#[tokio::test]
async fn test_scout_and_approve_pipeline() {
    let secret = b"executive_supervisory_secret_hmac_256";
    let recorder = Arc::new(Mutex::new(UpworkFlightRecorder::new(secret)));
    let server = Arc::new(MockUpworkServer::new(recorder.clone()));

    // 1. Run autonomous scouting
    let scout_args = ScoutArgs {
        query: "".to_string(),
        tier: "compact".to_string(),
        mock: true,
        audit_log: PathBuf::from("audit.log"),
        secret: String::from_utf8_lossy(secret).to_string(),
        min_budget: 1000.0,
        min_client_spend: 1000.0,
        min_client_rating: 4.80,
    };

    let scout_report = run_scout(server.clone(), &scout_args)
        .await
        .expect("Scouting run must succeed");

    assert_eq!(scout_report.total_scouted, 3);
    assert_eq!(scout_report.accepted.len(), 2);
    assert_eq!(scout_report.rejected.len(), 1);

    // Verify non-compliant job was properly rejected
    let rejected = &scout_report.rejected[0];
    assert_eq!(rejected.job_id, "~01fedcba0987654321");
    let violation_kinds: Vec<PolicyViolationKind> = rejected
        .verdict
        .violations
        .iter()
        .map(|v| v.kind.clone())
        .collect();

    assert!(violation_kinds.contains(&PolicyViolationKind::SynchronousDemandViolation));
    assert!(violation_kinds.contains(&PolicyViolationKind::InvasiveTrackerViolation));
    assert!(violation_kinds.contains(&PolicyViolationKind::HourlyTrackingRejected));

    // Verify eligible fixed-price job was drafted as a proposal preview
    let preview_id = scout_report
        .drafted_preview_id
        .as_ref()
        .expect("Preview should be drafted for top eligible opportunity");
    assert!(preview_id.starts_with("prev_"));

    // 2. Supervisor Interlock: Approve and sign submission
    let approve_args = ApproveArgs {
        preview_id: preview_id.clone(),
        supervisor_id: "exec-supervisor-liam".to_string(),
        secret: String::from_utf8_lossy(secret).to_string(),
        valid_for_ms: 3_600_000,
        mock: true,
    };

    let approve_result = run_approve(server.clone(), &approve_args)
        .await
        .expect("Approval and submission must succeed");

    assert!(approve_result.submitted.submission_id.starts_with("sub_"));
    assert_eq!(
        approve_result.witness.authorization_token(),
        approve_result.submitted.witness_token()
    );

    // Linear typestate: Re-approving already consumed preview must fail
    let duplicate_approve = run_approve(server.clone(), &approve_args).await;
    assert!(
        duplicate_approve.is_err(),
        "Linear preview slot must reject double submission"
    );
}
