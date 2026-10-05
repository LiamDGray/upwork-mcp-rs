//! Upwork Identifier Types and Bidirectional Resolution Mapping.
//!
//! Provides strongly typed representations for Upwork's dual identifier formats:
//! - `CiphertextId`: Opaque prefixed strings (`~01...` for job/freelancer/proposal entities,
//!   `~02...` for contract/organization entities).
//! - `NumericId`: 64-bit integer identifiers used across legacy endpoints and internal databases.
//! - `UpworkId`: Polymorphic wrapper with seamless string parsing and type discrimination.
//! - `IdResolver`: Bidirectional memory-mapped lookup between numeric and ciphertext identifiers.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

/// Errors occurring during Upwork ID parsing, validation, or resolution.
#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum IdError {
    #[error("Invalid Upwork ciphertext identifier: {0}")]
    InvalidCiphertext(String),

    #[error("Invalid Upwork numeric identifier: {0}")]
    InvalidNumeric(String),

    #[error("Unrecognized Upwork identifier format: {0}")]
    InvalidFormat(String),
}

/// Upwork Ciphertext Identifier (`~01...` or `~02...`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CiphertextId(String);

impl CiphertextId {
    /// Validates and constructs a new `CiphertextId`.
    ///
    /// Must start with `~01` or `~02`, have a minimum length of 16 characters,
    /// and contain only valid hexadecimal or alphanumeric characters.
    pub fn new(raw: impl Into<String>) -> Result<Self, IdError> {
        let s = raw.into();
        if !s.starts_with("~01") && !s.starts_with("~02") {
            return Err(IdError::InvalidCiphertext(format!(
                "CiphertextId must start with '~01' or '~02', found: '{s}'"
            )));
        }

        if s.len() < 16 {
            return Err(IdError::InvalidCiphertext(format!(
                "CiphertextId too short (minimum 16 chars): '{s}'"
            )));
        }

        let body = &s[1..];
        if !body.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err(IdError::InvalidCiphertext(format!(
                "CiphertextId body must be alphanumeric: '{s}'"
            )));
        }

        Ok(Self(s))
    }

    /// Access the underlying string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the ciphertext prefix (e.g. `~01` or `~02`).
    pub fn prefix(&self) -> &str {
        &self.0[..3]
    }
}

impl fmt::Display for CiphertextId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for CiphertextId {
    type Err = IdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

/// Upwork Numeric Identifier (64-bit integer).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NumericId(u64);

impl NumericId {
    /// Constructs a new `NumericId`.
    pub const fn new(val: u64) -> Self {
        Self(val)
    }

    /// Returns the raw `u64` value.
    pub const fn as_u64(&self) -> u64 {
        self.0
    }
}

impl fmt::Display for NumericId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for NumericId {
    type Err = IdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let val = s
            .trim()
            .parse::<u64>()
            .map_err(|e| IdError::InvalidNumeric(format!("{e}: '{s}'")))?;
        Ok(Self::new(val))
    }
}

/// Polymorphic Upwork identifier accommodating both Ciphertext and Numeric representations.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum UpworkId {
    Ciphertext(CiphertextId),
    Numeric(NumericId),
}

impl UpworkId {
    /// Returns true if this identifier is in ciphertext format.
    pub const fn is_ciphertext(&self) -> bool {
        matches!(self, Self::Ciphertext(_))
    }

    /// Returns true if this identifier is in numeric format.
    pub const fn is_numeric(&self) -> bool {
        matches!(self, Self::Numeric(_))
    }

    /// Returns a reference to the `CiphertextId` if present.
    pub fn as_ciphertext(&self) -> Option<&CiphertextId> {
        match self {
            Self::Ciphertext(c) => Some(c),
            Self::Numeric(_) => None,
        }
    }

    /// Returns a reference to the `NumericId` if present.
    pub fn as_numeric(&self) -> Option<&NumericId> {
        match self {
            Self::Numeric(n) => Some(n),
            Self::Ciphertext(_) => None,
        }
    }
}

impl fmt::Display for UpworkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ciphertext(c) => write!(f, "{c}"),
            Self::Numeric(n) => write!(f, "{n}"),
        }
    }
}

impl FromStr for UpworkId {
    type Err = IdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        if trimmed.starts_with('~') {
            CiphertextId::new(trimmed).map(Self::Ciphertext)
        } else if let Ok(num) = trimmed.parse::<u64>() {
            Ok(Self::Numeric(NumericId::new(num)))
        } else {
            Err(IdError::InvalidFormat(format!(
                "Unrecognized Upwork ID format: '{s}'"
            )))
        }
    }
}

/// Bidirectional in-memory resolver between numeric and ciphertext identifiers.
#[derive(Debug, Default, Clone)]
pub struct IdResolver {
    numeric_to_cipher: HashMap<NumericId, CiphertextId>,
    cipher_to_numeric: HashMap<CiphertextId, NumericId>,
}

impl IdResolver {
    /// Creates an empty identifier resolver.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a bidirectional association between a numeric ID and ciphertext ID.
    pub fn register_mapping(&mut self, numeric: NumericId, ciphertext: CiphertextId) {
        self.numeric_to_cipher.insert(numeric, ciphertext.clone());
        self.cipher_to_numeric.insert(ciphertext, numeric);
    }

    /// Resolves a numeric ID to its associated ciphertext representation.
    pub fn resolve_to_ciphertext(&self, numeric: &NumericId) -> Option<&CiphertextId> {
        self.numeric_to_cipher.get(numeric)
    }

    /// Resolves a ciphertext ID to its associated numeric representation.
    pub fn resolve_to_numeric(&self, ciphertext: &CiphertextId) -> Option<&NumericId> {
        self.cipher_to_numeric.get(ciphertext)
    }
}
