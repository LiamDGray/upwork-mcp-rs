//! 3-Tier Token Distillation Engine for Upwork Jobs and Proposals.
//!
//! Provides intelligent prompt compression (Compact, Standard, Raw) to minimize LLM token bloat:
//! - `Compact`: Aggressive distillation extracting high-signal executive telemetry (title, budget,
//!   key skills, client rating, total spend, and concise scope), achieving >= 80% reduction.
//! - `Standard`: Clean structured markdown with full sanitized description, screening questions, and client stats.
//! - `Raw`: Full structured JSON representation with sanitized text boundaries.

use crate::ids::CiphertextId;
use crate::policy::JobPricing;
use crate::sanitizer::Sanitizer;
use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

/// Errors arising during token distillation.
#[derive(Error, Debug)]
pub enum TokenDietError {
    #[error("Failed to parse raw job JSON: {0}")]
    JsonParse(#[from] serde_json::Error),
}

/// Distillation tiers for controlling LLM context window consumption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DistillationTier {
    /// Extreme distillation (>= 80% token reduction) containing only essential decision criteria.
    Compact,
    /// Standard structured markdown with full description and screening questions.
    Standard,
    /// Full JSON payload with sanitized field values.
    Raw,
}

/// Client rating and spend telemetry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClientStats {
    pub total_spend: f64,
    pub rating: f64,
    pub reviews_count: u32,
    pub payment_verified: bool,
    pub country: String,
}

/// Structured representation of an Upwork job posting.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct JobPosting {
    pub id: CiphertextId,
    pub title: String,
    pub description: String,
    pub category: String,
    pub pricing: JobPricing,
    pub skills: Vec<String>,
    pub client: ClientStats,
    pub screening_questions: Vec<String>,
}

#[derive(Deserialize)]
struct JobPostingHelper {
    id: CiphertextId,
    title: String,
    description: String,
    #[serde(default)]
    category: Option<String>,
    #[serde(default)]
    pricing: Option<JobPricing>,
    #[serde(default)]
    job_type: Option<String>,
    #[serde(default)]
    budget: Option<f64>,
    #[serde(default)]
    hourly_range: Option<(f64, f64)>,
    #[serde(default)]
    skills: Vec<String>,
    client: ClientStats,
    #[serde(default)]
    screening_questions: Vec<String>,
}

impl<'de> Deserialize<'de> for JobPosting {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let helper = JobPostingHelper::deserialize(deserializer)?;
        let pricing = if let Some(p) = helper.pricing {
            p
        } else if let Some(job_type) = helper.job_type {
            if job_type.eq_ignore_ascii_case("FixedPrice") || job_type.eq_ignore_ascii_case("Fixed")
            {
                JobPricing::FixedPrice {
                    budget: helper.budget.unwrap_or(0.0),
                }
            } else if let Some((min, max)) = helper.hourly_range {
                JobPricing::Hourly {
                    min_rate: min,
                    max_rate: max,
                }
            } else {
                JobPricing::FixedPrice {
                    budget: helper.budget.unwrap_or(0.0),
                }
            }
        } else if let Some(b) = helper.budget {
            JobPricing::FixedPrice { budget: b }
        } else {
            JobPricing::FixedPrice { budget: 0.0 }
        };

        Ok(JobPosting {
            id: helper.id,
            title: helper.title,
            description: helper.description,
            category: helper.category.unwrap_or_else(|| "General".into()),
            pricing,
            skills: helper.skills,
            client: helper.client,
            screening_questions: helper.screening_questions,
        })
    }
}

/// Token distillation processor.
#[derive(Debug, Default, Clone)]
pub struct TokenDietDistiller;

impl TokenDietDistiller {
    /// Creates a new distillation processor.
    pub fn new() -> Self {
        Self
    }

    /// Distills a `JobPosting` according to the specified tier.
    pub fn distill(&self, job: &JobPosting, tier: DistillationTier) -> String {
        match tier {
            DistillationTier::Compact => self.distill_compact(job),
            DistillationTier::Standard => self.distill_standard(job),
            DistillationTier::Raw => self.distill_raw(job),
        }
    }

    /// Parses raw JSON and distills it directly.
    pub fn distill_raw_json(
        &self,
        raw_json: &str,
        tier: DistillationTier,
    ) -> Result<String, TokenDietError> {
        let job: JobPosting = serde_json::from_str(raw_json)?;
        Ok(self.distill(&job, tier))
    }

    fn distill_compact(&self, job: &JobPosting) -> String {
        let pricing_str = match &job.pricing {
            JobPricing::FixedPrice { budget } => format!("${budget:.0} (FixedPrice)"),
            JobPricing::Hourly { min_rate, max_rate } => {
                format!("${min_rate:.0}-${max_rate:.0}/hr")
            }
        };

        // Top 5 skills
        let top_skills = job
            .skills
            .iter()
            .take(5)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");

        let sanitized_desc = Sanitizer::sanitize(&job.description);
        let inner_desc = sanitized_desc.inner_cleaned();
        // Truncate scope to first 120 chars if longer
        let scope_summary = if inner_desc.len() > 120 {
            let mut end = 120;
            while !inner_desc.is_char_boundary(end) && end > 0 {
                end -= 1;
            }
            format!("{}...", &inner_desc[..end])
        } else {
            inner_desc.to_string()
        };

        format!(
            "[{}] {}\nBudget: {} | Client: {:.2}★ (${:.0} spend, {})\nSkills: {}\nScope: {}",
            job.id,
            job.title,
            pricing_str,
            job.client.rating,
            job.client.total_spend,
            job.client.country,
            top_skills,
            scope_summary
        )
    }

    fn distill_standard(&self, job: &JobPosting) -> String {
        let pricing_str = match &job.pricing {
            JobPricing::FixedPrice { budget } => format!("Fixed Price: ${budget:.2}"),
            JobPricing::Hourly { min_rate, max_rate } => {
                format!("Hourly Range: ${min_rate:.2} - ${max_rate:.2}/hr")
            }
        };

        let sanitized_desc = Sanitizer::sanitize(&job.description);
        let questions_section = if job.screening_questions.is_empty() {
            String::new()
        } else {
            let q_list = job
                .screening_questions
                .iter()
                .enumerate()
                .map(|(i, q)| format!("{}. {}", i + 1, Sanitizer::sanitize(q).inner_cleaned()))
                .collect::<Vec<_>>()
                .join("\n");
            format!("\n\n### Screening Questions\n{q_list}")
        };

        format!(
            "# [{}] {}\n\n**Category**: {}\n**Pricing**: {}\n**Client**: {:.2}★ (${:.2} total spend, verified: {}, {})\n**Skills**: {}\n\n### Scope\n{}{}",
            job.id,
            job.title,
            job.category,
            pricing_str,
            job.client.rating,
            job.client.total_spend,
            job.client.payment_verified,
            job.client.country,
            job.skills.join(", "),
            sanitized_desc.wrapped(),
            questions_section
        )
    }

    fn distill_raw(&self, job: &JobPosting) -> String {
        let mut job_sanitized = job.clone();
        job_sanitized.description = Sanitizer::sanitize(&job.description)
            .inner_cleaned()
            .to_string();
        serde_json::to_string_pretty(&job_sanitized).unwrap_or_else(|_| "{}".to_string())
    }
}
