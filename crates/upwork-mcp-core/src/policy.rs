//! Executive Commercial Policy Evaluator and High-Leverage Sentry.
//!
//! Enforces high-assurance commercial criteria for client engagement:
//! - "Asynchronous Delivery Discipline": Rejects synchronous live demands (Zoom, video calls,
//!   daily live standups, rigid timezones) in favor of async written updates and GitHub PRs.
//! - "Autonomous Delivery Policy": Rejects invasive desktop screen/keystroke tracking software.
//! - "Fixed-Price Milestone Policy": Requires defined-scope fixed-price milestone delivery
//!   (rejection of hourly tracking, minimum project budget of $1,000, minimum client spend of $1,000).
//! - "Executive High-Leverage Sentry": Evaluates top-tier enterprise clients (rating >= 4.8)
//!   and prioritizes high-value systems domains (Model Context Protocol, LLM tool calling, Rust).

use crate::token_diet::JobPosting;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

/// Pricing structure for an Upwork job posting.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum JobPricing {
    FixedPrice { budget: f64 },
    Hourly { min_rate: f64, max_rate: f64 },
}

/// Enumeration of commercial policy violation categories.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PolicyViolationKind {
    /// Demands synchronous presence (Zoom, video calls, daily live standups).
    SynchronousDemandViolation,
    /// Mandates invasive desktop surveillance trackers (screen captures, keystroke logging).
    InvasiveTrackerViolation,
    /// Hourly tracking contracts rejected under Fixed-Price Milestone Policy.
    HourlyTrackingRejected,
    /// Project budget falls below executive floor threshold.
    BelowMinimumBudget { budget: f64, minimum: f64 },
    /// Client total historical spend falls below credibility threshold.
    ClientSpendBelowThreshold { spend: f64, threshold: f64 },
    /// Client historical rating falls below quality threshold.
    ClientRatingBelowThreshold { rating: f64, threshold: f64 },
}

/// Detailed policy violation record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyViolation {
    pub kind: PolicyViolationKind,
    pub detail: String,
}

/// Comprehensive outcome of executive commercial policy evaluation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvaluationVerdict {
    pub is_acceptable: bool,
    pub score: f64,
    pub async_discipline_passed: bool,
    pub autonomous_delivery_passed: bool,
    pub milestone_policy_passed: bool,
    pub executive_sentry_score: f64,
    pub violations: Vec<PolicyViolation>,
    pub high_leverage_domains: Vec<String>,
}

static SYNC_DEMAND_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(zoom|google\s+meet|teams\s+call|daily\s+(live\s+)?standup|video\s+calls?|live\s+sync|camera\s+on|mandatory\s+calls?|daily\s+sync|9\s*am\s*to\s*5\s*pm\s*(est|pst|cst|utc))\b").unwrap()
});

static TRACKER_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(desktop\s+app|upwork\s+tracker|keystroke\s+(logging|monitoring)|screen\s+(capture|monitoring|recording)|random\s+screen|time\s+tracker\s+with\s+screen|webcam\s+track(ing|er)|mouse\s+movement)\b").unwrap()
});

static HIGH_LEVERAGE_PATTERNS: LazyLock<Vec<(&'static str, Regex)>> = LazyLock::new(|| {
    vec![
        (
            "Model Context Protocol (MCP)",
            Regex::new(r"(?i)\b(mcp|model\s+context\s+protocol)\b").unwrap(),
        ),
        (
            "LLM Tool Calling",
            Regex::new(
                r"(?i)\b(llm|tool\s+calling|function\s+calling|agentic|autonomous\s+agent)\b",
            )
            .unwrap(),
        ),
        (
            "Rust Systems Architecture",
            Regex::new(r"(?i)\b(rust|tokio|async\s+rust|systems\s+programming)\b").unwrap(),
        ),
        (
            "Distributed Systems & APIs",
            Regex::new(r"(?i)\b(distributed\s+systems|json-rpc|grpc|cryptographic)\b").unwrap(),
        ),
    ]
});

/// Commercial policy evaluator enforcing asynchronous, autonomous, fixed-price discipline.
#[derive(Debug, Clone)]
pub struct CommercialPolicyEvaluator {
    pub min_budget: f64,
    pub min_client_spend: f64,
    pub min_client_rating: f64,
}

impl Default for CommercialPolicyEvaluator {
    fn default() -> Self {
        Self {
            min_budget: 1000.0,
            min_client_spend: 1000.0,
            min_client_rating: 4.80,
        }
    }
}

impl CommercialPolicyEvaluator {
    /// Creates an evaluator with standard executive thresholds.
    pub fn new() -> Self {
        Self::default()
    }

    /// Evaluates a job posting against all commercial delivery and executive policies.
    pub fn evaluate(&self, job: &JobPosting) -> EvaluationVerdict {
        let mut violations = Vec::new();
        let corpus = format!("{}\n{}", job.title, job.description);

        // 1. Asynchronous Delivery Discipline: Reject synchronous demands
        let mut async_passed = true;
        if let Some(mat) = SYNC_DEMAND_REGEX.find(&corpus) {
            async_passed = false;
            violations.push(PolicyViolation {
                kind: PolicyViolationKind::SynchronousDemandViolation,
                detail: format!("Synchronous demand detected: '{}'", mat.as_str()),
            });
        }

        // 2. Autonomous Delivery Policy: Reject invasive desktop/keystroke trackers
        let mut autonomous_passed = true;
        if let Some(mat) = TRACKER_REGEX.find(&corpus) {
            autonomous_passed = false;
            violations.push(PolicyViolation {
                kind: PolicyViolationKind::InvasiveTrackerViolation,
                detail: format!("Invasive tracking requirement detected: '{}'", mat.as_str()),
            });
        }

        // 3. Fixed-Price Milestone Policy: Reject hourly; enforce minimum project budget & client spend
        let mut milestone_passed = true;
        match &job.pricing {
            JobPricing::Hourly { .. } => {
                milestone_passed = false;
                violations.push(PolicyViolation {
                    kind: PolicyViolationKind::HourlyTrackingRejected,
                    detail: "Hourly tracking contract rejected; policy mandates fixed-price milestone delivery"
                        .into(),
                });
            }
            JobPricing::FixedPrice { budget } => {
                if *budget < self.min_budget {
                    milestone_passed = false;
                    violations.push(PolicyViolation {
                        kind: PolicyViolationKind::BelowMinimumBudget {
                            budget: *budget,
                            minimum: self.min_budget,
                        },
                        detail: format!(
                            "Project budget ${budget:.2} is below the ${:.2} threshold",
                            self.min_budget
                        ),
                    });
                }
            }
        }

        if job.client.total_spend < self.min_client_spend {
            milestone_passed = false;
            violations.push(PolicyViolation {
                kind: PolicyViolationKind::ClientSpendBelowThreshold {
                    spend: job.client.total_spend,
                    threshold: self.min_client_spend,
                },
                detail: format!(
                    "Client total spend ${:.2} is below the ${:.2} threshold",
                    job.client.total_spend, self.min_client_spend
                ),
            });
        }

        // 4. Executive High-Leverage Sentry: Check rating & score domain alignment
        if job.client.rating < self.min_client_rating {
            violations.push(PolicyViolation {
                kind: PolicyViolationKind::ClientRatingBelowThreshold {
                    rating: job.client.rating,
                    threshold: self.min_client_rating,
                },
                detail: format!(
                    "Client rating {:.2} is below the {:.2} threshold",
                    job.client.rating, self.min_client_rating
                ),
            });
        }

        let mut high_leverage_domains = Vec::new();
        for (name, pat) in HIGH_LEVERAGE_PATTERNS.iter() {
            if pat.is_match(&corpus) || job.skills.iter().any(|s| pat.is_match(s)) {
                high_leverage_domains.push((*name).to_string());
            }
        }

        let domain_weight = (high_leverage_domains.len() as f64 * 25.0).min(50.0);
        let rating_weight = ((job.client.rating / 5.0) * 30.0).clamp(0.0, 30.0);
        let spend_bonus = (job.client.total_spend / 10000.0 * 10.0).clamp(0.0, 20.0);

        let sentry_score = (domain_weight + rating_weight + spend_bonus).clamp(0.0, 100.0);

        let is_acceptable = violations.is_empty();
        let total_score = if is_acceptable { sentry_score } else { 0.0 };

        EvaluationVerdict {
            is_acceptable,
            score: total_score,
            async_discipline_passed: async_passed,
            autonomous_delivery_passed: autonomous_passed,
            milestone_policy_passed: milestone_passed,
            executive_sentry_score: sentry_score,
            violations,
            high_leverage_domains,
        }
    }
}
