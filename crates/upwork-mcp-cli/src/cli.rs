use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug, Clone, PartialEq)]
#[command(
    name = "upwork-mcp-rs",
    about = "High-assurance Upwork MCP CLI",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug, Clone, PartialEq)]
pub enum Commands {
    Serve(ServeArgs),
    Scout(ScoutArgs),
    Approve(ApproveArgs),
    AuditVerify(AuditVerifyArgs),
    Config(ConfigArgs),
}

#[derive(clap::Args, Debug, Clone, PartialEq)]
pub struct ServeArgs {
    #[arg(long)]
    pub stdio: bool,

    #[arg(long)]
    pub port: Option<u16>,

    #[arg(long)]
    pub mock: bool,

    #[arg(long, default_value = "audit.log")]
    pub audit_log: PathBuf,
}

#[derive(clap::Args, Debug, Clone, PartialEq)]
pub struct ScoutArgs {
    #[arg(long, default_value = "")]
    pub query: String,

    #[arg(long, default_value = "compact")]
    pub tier: String,

    #[arg(long)]
    pub mock: bool,

    #[arg(long, default_value = "audit.log")]
    pub audit_log: PathBuf,

    #[arg(
        long,
        env = "UPWORK_SUPERVISOR_SECRET",
        default_value = "supervisor-default-secret"
    )]
    pub secret: String,

    #[arg(long, default_value = "1000.0")]
    pub min_budget: f64,

    #[arg(long, default_value = "1000.0")]
    pub min_client_spend: f64,

    #[arg(long, default_value = "4.8")]
    pub min_client_rating: f64,
}

#[derive(clap::Args, Debug, Clone, PartialEq)]
pub struct ApproveArgs {
    #[arg(long)]
    pub preview_id: String,

    #[arg(long, default_value = "supervisor-exec-1")]
    pub supervisor_id: String,

    #[arg(
        long,
        env = "UPWORK_SUPERVISOR_SECRET",
        default_value = "supervisor-default-secret"
    )]
    pub secret: String,

    #[arg(long, default_value_t = 3_600_000)]
    pub valid_for_ms: u64,

    #[arg(long)]
    pub mock: bool,
}

#[derive(clap::Args, Debug, Clone, PartialEq)]
pub struct AuditVerifyArgs {
    #[arg(long, default_value = "audit.log")]
    pub path: PathBuf,

    #[arg(
        long,
        env = "UPWORK_SUPERVISOR_SECRET",
        default_value = "supervisor-default-secret"
    )]
    pub secret: String,
}

#[derive(clap::Args, Debug, Clone, PartialEq)]
pub struct ConfigArgs {
    #[arg(long)]
    pub client: Option<String>,

    #[arg(long)]
    pub all: bool,

    #[arg(long)]
    pub binary_path: Option<PathBuf>,
}
