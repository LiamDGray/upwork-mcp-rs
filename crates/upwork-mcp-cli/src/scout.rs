//! Autonomous Market Scout.
//!
//! Enforces:
//! - Asynchronous Delivery Discipline
//! - Autonomous Delivery Policy
//! - Fixed-Price Milestone Policy
//! - Executive High-Leverage Sentry
//!
//! Evaluates candidate job postings against strict commercial policies,
//! filters out synchronous demands and surveillance trackers, ranks high-leverage
//! opportunities, and safely drafts proposal previews awaiting supervisor authorization.

use std::sync::Arc;
use thiserror::Error;

use upwork_mcp_core::policy::{CommercialPolicyEvaluator, EvaluationVerdict, JobPricing};
use upwork_mcp_server::mock_server::MockUpworkServer;

use crate::cli::ScoutArgs;

/// Errors arising during autonomous market scouting operations.
#[derive(Error, Debug)]
pub enum ScoutError {
    #[error("Mock server error: {0}")]
    Server(String),
}

/// Evaluated candidate job verdict.
#[derive(Debug, Clone)]
pub struct ScoutedJobVerdict {
    pub job_id: String,
    pub title: String,
    pub verdict: EvaluationVerdict,
}

/// Autonomous market scouting report.
#[derive(Debug, Clone)]
pub struct ScoutReport {
    pub total_scouted: usize,
    pub accepted: Vec<ScoutedJobVerdict>,
    pub rejected: Vec<ScoutedJobVerdict>,
    pub drafted_preview_id: Option<String>,
}

/// Runs the autonomous market scout pipeline against the server.
pub async fn run_scout(
    server: Arc<MockUpworkServer>,
    args: &ScoutArgs,
) -> Result<ScoutReport, ScoutError> {
    let evaluator = CommercialPolicyEvaluator {
        min_budget: args.min_budget,
        min_client_spend: args.min_client_spend,
        min_client_rating: args.min_client_rating,
    };

    let jobs = server.find_jobs(&args.query).await;
    let mut accepted = Vec::new();
    let mut rejected = Vec::new();

    for job in &jobs {
        let verdict = evaluator.evaluate(job);
        let scouted = ScoutedJobVerdict {
            job_id: job.id.as_str().to_string(),
            title: job.title.clone(),
            verdict: verdict.clone(),
        };

        if verdict.is_acceptable {
            accepted.push((job.clone(), scouted));
        } else {
            rejected.push(scouted);
        }
    }

    // Rank accepted opportunities by executive sentry score descending
    accepted.sort_by(|a, b| {
        b.1.verdict
            .score
            .partial_cmp(&a.1.verdict.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    // Draft a proposal preview for the top opportunity if one exists
    let drafted_preview_id = if let Some((top_job, _)) = accepted.first() {
        let amount = match top_job.pricing {
            JobPricing::FixedPrice { budget } => budget,
            JobPricing::Hourly { .. } => 0.0,
        };
        let connects_cost = 16;
        let cover_letter = format!(
            "Executive Proposal for '{}': Adhering to Asynchronous Delivery Discipline and Fixed-Price Milestone Policy.",
            top_job.title
        );

        let preview_id = server
            .draft_proposal(top_job.id.as_str(), &cover_letter, amount, connects_cost)
            .await
            .map_err(ScoutError::Server)?;
        Some(preview_id)
    } else {
        None
    };

    let accepted_verdicts = accepted.into_iter().map(|(_, s)| s).collect();

    Ok(ScoutReport {
        total_scouted: jobs.len(),
        accepted: accepted_verdicts,
        rejected,
        drafted_preview_id,
    })
}
