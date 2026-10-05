use clap::Parser;
use colored::*;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

use upwork_mcp_cli::approve::run_approve;
use upwork_mcp_cli::cli::{Cli, Commands};
use upwork_mcp_cli::config::{generate_all_configs, generate_client_config, ClientType};
use upwork_mcp_cli::scout::run_scout;
use upwork_mcp_cli::serve::run_serve;
use upwork_mcp_cli::verifier::verify_audit_log;
use upwork_mcp_core::audit::UpworkFlightRecorder;
use upwork_mcp_server::mock_server::MockUpworkServer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Serve(args) => {
            run_serve(&args).await?;
        }
        Commands::Scout(args) => {
            let recorder = Arc::new(Mutex::new(UpworkFlightRecorder::new(
                args.secret.as_bytes(),
            )));
            let server = Arc::new(MockUpworkServer::new(recorder));

            println!(
                "{}",
                "==> Executing Autonomous Market Scout under Commercial Delivery Policies <=="
                    .bold()
                    .cyan()
            );

            let report = run_scout(server, &args).await?;

            println!("Total jobs scouted: {}", report.total_scouted);
            println!(
                "Eligible fixed-price opportunities: {}",
                report.accepted.len().to_string().green()
            );
            println!(
                "Policy-rejected opportunities: {}",
                report.rejected.len().to_string().yellow()
            );

            if let Some(preview_id) = &report.drafted_preview_id {
                println!(
                    "\n{} Drafted proposal preview created: {}",
                    "✔".green().bold(),
                    preview_id.bold().magenta()
                );
                println!(
                    "To sign and authorize submission, run: upwork-mcp-rs approve --preview-id {}",
                    preview_id
                );
            }
        }
        Commands::Approve(args) => {
            let recorder = Arc::new(Mutex::new(UpworkFlightRecorder::new(
                args.secret.as_bytes(),
            )));
            let server = Arc::new(MockUpworkServer::new(recorder));

            println!(
                "{}",
                "==> Executing Supervisor Interlock and HMAC-SHA256 Witness Signing <=="
                    .bold()
                    .cyan()
            );

            match run_approve(server, &args).await {
                Ok(result) => {
                    println!(
                        "{} Proposal submission authorized successfully!",
                        "✔".green().bold()
                    );
                    println!(
                        "  Submission ID: {}",
                        result.submitted.submission_id.bold().green()
                    );
                    println!("  Target Job ID: {}", result.submitted.job_id);
                    println!("  Authorized Amount: ${:.2}", result.submitted.amount);
                    println!(
                        "  Connects Spent: {}",
                        result.submitted.connects_spent.to_string().yellow()
                    );
                    println!(
                        "  Witness Signature: {}",
                        result.witness.authorization_token()
                    );
                }
                Err(e) => {
                    eprintln!("{} Approval failed: {}", "✖".red().bold(), e);
                    std::process::exit(1);
                }
            }
        }
        Commands::AuditVerify(args) => {
            println!(
                "{}",
                "==> Verifying Binary Flight Recorder Log Integrity <=="
                    .bold()
                    .cyan()
            );

            match verify_audit_log(&args.path, args.secret.as_bytes()) {
                Ok(report) => {
                    println!(
                        "{} Audit trail successfully verified: all cryptographic HMAC chains intact!",
                        "✔".green().bold()
                    );
                    println!("  Total frames: {}", report.total_frames);
                    println!(
                        "  Sequence range: {} -> {}",
                        report.first_sequence_id, report.last_sequence_id
                    );
                    println!(
                        "  Total Connects spent: {}",
                        report.total_connects_spent.to_string().yellow()
                    );
                    println!(
                        "  Total value: ${:.2}",
                        report.total_amount_cents as f64 / 100.0
                    );
                }
                Err(e) => {
                    eprintln!("{} Audit log verification failed: {}", "✖".red().bold(), e);
                    std::process::exit(1);
                }
            }
        }
        Commands::Config(args) => {
            let bin_path = args.binary_path.unwrap_or_else(|| {
                std::env::current_exe().unwrap_or_else(|_| PathBuf::from("upwork-mcp-rs"))
            });

            if args.install {
                let home_dir = std::env::var_os("HOME")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from("."));

                if let Some(client_str) = &args.client {
                    if let Some(client_type) = ClientType::parse_client(client_str) {
                        let installed_path = upwork_mcp_cli::config::install_client_config(
                            client_type,
                            &home_dir,
                            &bin_path,
                        )?;
                        println!(
                            "{} Successfully installed Upwork MCP configuration to: {}",
                            "✔".green().bold(),
                            installed_path.display().to_string().cyan()
                        );
                    } else {
                        eprintln!(
                            "{} Unknown client '{}'. Supported clients: claude, cursor, zed, cline, codex, antigravity, pi, hermes",
                            "✖".red().bold(),
                            client_str
                        );
                        std::process::exit(1);
                    }
                } else if args.all {
                    let all_clients = [
                        ClientType::Claude,
                        ClientType::Cursor,
                        ClientType::Zed,
                        ClientType::Cline,
                        ClientType::Codex,
                        ClientType::Antigravity,
                        ClientType::Pi,
                        ClientType::Hermes,
                    ];
                    for client in all_clients {
                        let path = upwork_mcp_cli::config::install_client_config(
                            client, &home_dir, &bin_path,
                        )?;
                        println!(
                            "{} Installed config for {:?} to: {}",
                            "✔".green().bold(),
                            client,
                            path.display().to_string().cyan()
                        );
                    }
                } else {
                    eprintln!(
                        "{} Please specify --client <NAME> or --all when using --install.",
                        "✖".red().bold()
                    );
                    std::process::exit(1);
                }
            } else if args.all {
                let all_json = generate_all_configs(&bin_path);
                println!("{}", serde_json::to_string_pretty(&all_json)?);
            } else if let Some(client_str) = &args.client {
                if let Some(client_type) = ClientType::parse_client(client_str) {
                    let client_json = generate_client_config(client_type, &bin_path);
                    println!("{}", serde_json::to_string_pretty(&client_json)?);
                } else {
                    eprintln!(
                        "{} Unknown client '{}'. Supported clients: claude, cursor, zed, cline, codex, antigravity, pi, hermes",
                        "✖".red().bold(),
                        client_str
                    );
                    std::process::exit(1);
                }
            } else {
                let all_json = generate_all_configs(&bin_path);
                println!("{}", serde_json::to_string_pretty(&all_json)?);
            }
        }
    }

    Ok(())
}
