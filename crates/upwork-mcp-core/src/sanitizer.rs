//! Untrusted Participant Data Sanitizer and Prompt Injection Neutralization.
//!
//! Provides strict boundary wrapping, delimiter escape neutralization, script tag stripping,
//! invisible character removal, and prompt injection threat detection for untrusted Upwork input.

use regex::Regex;
use std::sync::LazyLock;

/// Boundary delimiter marking the start of untrusted participant data for LLMs.
pub const UNTRUSTED_DATA_BEGIN: &str = "<!-- BEGIN UNTRUSTED PARTICIPANT DATA -->";

/// Boundary delimiter marking the end of untrusted participant data for LLMs.
pub const UNTRUSTED_DATA_END: &str = "<!-- END UNTRUSTED PARTICIPANT DATA -->";

static SCRIPT_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?is)<script\b[^>]*>.*?</script>|<script\b[^>]*>|</script>").unwrap()
});

static HTML_TAG_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?is)<iframe\b[^>]*>.*?</iframe>|<object\b[^>]*>.*?</object>").unwrap()
});

static INJECTION_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"(?i)ignore\s+(all\s+)?(previous|prior)\s+instructions").unwrap(),
        Regex::new(r"(?i)system\s+prompt\s*:").unwrap(),
        Regex::new(r"(?i)you\s+are\s+now\s+(an?\s+)?(unrestricted|jailbroken|dan)").unwrap(),
        Regex::new(r"(?i)output\s+(your\s+)?(aws\s+secrets|api\s+keys|env|credentials)").unwrap(),
        Regex::new(r"(?i)disregard\s+(all\s+)?prior\s+instructions").unwrap(),
    ]
});

/// Result of data sanitization containing cleaned inner text and wrapped LLM enclosure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SanitizedText {
    inner: String,
    wrapped: String,
    threats: Vec<String>,
}

impl SanitizedText {
    /// Returns the cleaned inner text without the boundary comments.
    pub fn inner_cleaned(&self) -> &str {
        &self.inner
    }

    /// Returns the complete boundary-wrapped string safe for LLM consumption.
    pub fn wrapped(&self) -> &str {
        &self.wrapped
    }

    /// Returns true if prompt injection vectors or malicious patterns were identified.
    pub fn has_injection_risk(&self) -> bool {
        !self.threats.is_empty()
    }

    /// List of detected prompt injection threat descriptions.
    pub fn injection_threats(&self) -> &[String] {
        &self.threats
    }
}

/// Sanitizer engine enforcing containment on all external participant data.
pub struct Sanitizer;

impl Sanitizer {
    /// Sanitizes untrusted participant text and wraps it in tamper-resistant delimiters.
    pub fn sanitize(raw: &str) -> SanitizedText {
        let mut cleaned = raw.to_string();
        let mut threats = Vec::new();

        // 1. Strip invisible, zero-width, and bidi override control characters
        cleaned = cleaned
            .chars()
            .filter(|&c| {
                !matches!(
                    c,
                    '\u{200B}'..='\u{200D}' // zero-width space, non-joiner, joiner
                    | '\u{FEFF}'            // zero-width no-break space / BOM
                    | '\u{202A}'..='\u{202E}' // bidirectional text control characters
                    | '\u{2066}'..='\u{2069}' // directional isolate controls
                )
            })
            .collect();

        // 2. Neutralize boundary delimiter escape attempts
        if cleaned.contains(UNTRUSTED_DATA_END) {
            threats.push("Detected delimiter escape attempt in participant data".to_string());
            cleaned = cleaned.replace(UNTRUSTED_DATA_END, "[DEFANGED_END_DELIMITER]");
        }
        if cleaned.contains(UNTRUSTED_DATA_BEGIN) {
            cleaned = cleaned.replace(UNTRUSTED_DATA_BEGIN, "[DEFANGED_BEGIN_DELIMITER]");
        }

        // 3. Strip script and object tags
        if SCRIPT_REGEX.is_match(&cleaned) {
            threats.push("Script tag detected and stripped".to_string());
            cleaned = SCRIPT_REGEX
                .replace_all(&cleaned, "[STRIPPED_SCRIPT]")
                .to_string();
        }
        if HTML_TAG_REGEX.is_match(&cleaned) {
            threats.push("Embedded HTML iframe/object detected and stripped".to_string());
            cleaned = HTML_TAG_REGEX
                .replace_all(&cleaned, "[STRIPPED_EMBED]")
                .to_string();
        }

        // 4. Identify and neutralize prompt injection signatures
        for pat in INJECTION_PATTERNS.iter() {
            if let Some(mat) = pat.find(&cleaned) {
                let threat_match = mat.as_str().to_string();
                threats.push(format!("Prompt injection signature: '{threat_match}'"));
                // Defang the trigger phrase
                cleaned = pat
                    .replace_all(&cleaned, "[NEUTRALIZED_PROMPT_INJECTION]")
                    .to_string();
            }
        }

        let wrapped = format!("{UNTRUSTED_DATA_BEGIN}\n{cleaned}\n{UNTRUSTED_DATA_END}");

        SanitizedText {
            inner: cleaned,
            wrapped,
            threats,
        }
    }
}
