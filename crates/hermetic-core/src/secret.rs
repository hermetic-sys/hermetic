// Copyright (C) 2026 The Hermetic Project <dev@hermeticsys.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licenses available at hermeticsys.com/license

//! Hermetic Secret Model (v1.3.0a)
//!
//! Defines sensitivity classification and secret metadata.
//! SecretEntry holds ONLY metadata — NEVER plaintext or ciphertext.
//!
//! INVARIANTS:
//!   - No secret material (plaintext, ciphertext, keys) in this module
//!   - Sensitivity defaults to Standard (fail-closed)
//!   - SecretEntry may derive Debug — it holds no secret bytes

use crate::error::VaultError;

/// Secret sensitivity level for approval routing.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum Sensitivity {
    /// Always requires human approval before injection
    High,
    /// Default: automatic injection per policy
    #[default]
    Standard,
    /// Automatic injection with reduced audit verbosity
    Low,
}

impl Sensitivity {
    /// Database-safe string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Sensitivity::High => "high",
            Sensitivity::Standard => "standard",
            Sensitivity::Low => "low",
        }
    }

    /// Parse from string (case-insensitive). Returns error for unrecognized values.
    pub fn parse(s: &str) -> Result<Self, VaultError> {
        match s.to_lowercase().as_str() {
            "high" => Ok(Sensitivity::High),
            "standard" => Ok(Sensitivity::Standard),
            "low" => Ok(Sensitivity::Low),
            _ => Err(VaultError::Serialization(format!(
                "invalid sensitivity: {}",
                s
            ))),
        }
    }
}

/// Classify sensitivity by secret name pattern matching.
/// TC-3 compliant: derived from NAME only, never from daemon wire data.
///
/// HIGH: names matching payment, cloud, auth, or production patterns
/// LOW: names matching test, dev, sandbox, staging patterns
/// STANDARD: everything else (fail-closed default)
pub fn classify_sensitivity_by_name(name: &str) -> Sensitivity {
    let lower = name.to_lowercase();
    const HIGH: &[&str] = &[
        "stripe", "paypal", "plaid", "square", "wise", "coinbase", "shopify",
        "aws", "google_cloud", "azure", "auth0", "clerk", "salesforce", "snowflake",
        "payment", "billing", "production", "prod_", "live_",
    ];
    const LOW: &[&str] = &[
        "test", "dev", "sandbox", "staging", "demo", "mock", "local", "example",
    ];
    if HIGH.iter().any(|p| lower.contains(p)) {
        Sensitivity::High
    } else if LOW.iter().any(|p| lower.contains(p)) {
        Sensitivity::Low
    } else {
        Sensitivity::Standard
    }
}

/// Secret metadata entry — NEVER holds plaintext or ciphertext.
/// Used for listing, display, and policy decisions.
#[derive(Debug, Clone)]
pub struct SecretEntry {
    /// UUID v4 identifier
    pub id: String,
    /// Human-readable name (unique within vault)
    pub name: String,
    /// Sensitivity level for approval routing
    pub sensitivity: Sensitivity,
    /// ISO 8601 creation timestamp
    pub created_at: String,
    /// ISO 8601 last rotation timestamp (None if never rotated)
    pub rotated_at: Option<String>,
    /// Comma-separated normalized tags (Phase 3A)
    pub tags: String,
    /// Domain binding for MCP-7 enforcement. None = unrestricted (legacy).
    pub allowed_domains: Option<Vec<String>>,
    /// Secret type: "static" or "oauth2". Stored at add-time, read at list-time (no decryption).
    pub secret_type: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// T2d-1: Default sensitivity is Standard.
    #[test]
    fn default_sensitivity_is_standard() {
        assert_eq!(Sensitivity::default(), Sensitivity::Standard);
    }

    /// T2d-2: Sensitivity::parse for "high", "standard", "low" — all succeed.
    #[test]
    fn sensitivity_parse_valid() {
        assert_eq!(Sensitivity::parse("high").unwrap(), Sensitivity::High);
        assert_eq!(
            Sensitivity::parse("standard").unwrap(),
            Sensitivity::Standard
        );
        assert_eq!(Sensitivity::parse("low").unwrap(), Sensitivity::Low);
        // Case-insensitive
        assert_eq!(Sensitivity::parse("HIGH").unwrap(), Sensitivity::High);
        assert_eq!(
            Sensitivity::parse("Standard").unwrap(),
            Sensitivity::Standard
        );
        assert_eq!(Sensitivity::parse("LOW").unwrap(), Sensitivity::Low);
    }

    /// T2d-3: Sensitivity::parse for "invalid" — returns error.
    #[test]
    fn sensitivity_parse_invalid() {
        assert!(Sensitivity::parse("invalid").is_err());
        assert!(Sensitivity::parse("").is_err());
        assert!(Sensitivity::parse("medium").is_err());
    }

    /// T2d-4: Sensitivity round-trip: as_str -> parse -> original.
    #[test]
    fn sensitivity_roundtrip() {
        for expected in &[Sensitivity::High, Sensitivity::Standard, Sensitivity::Low] {
            let s = expected.as_str();
            let parsed = Sensitivity::parse(s).unwrap_or_else(|_| panic!("parse failed for {}", s));
            assert_eq!(parsed, *expected);
        }
    }

    #[test]
    fn classify_stripe_is_high() {
        assert_eq!(classify_sensitivity_by_name("stripe_live_key"), Sensitivity::High);
    }

    #[test]
    fn classify_openai_is_standard() {
        assert_eq!(classify_sensitivity_by_name("openai_key"), Sensitivity::Standard);
    }

    #[test]
    fn classify_test_is_low() {
        assert_eq!(classify_sensitivity_by_name("test_webhook"), Sensitivity::Low);
    }

    #[test]
    fn classify_case_insensitive() {
        assert_eq!(classify_sensitivity_by_name("PRODUCTION_DB"), Sensitivity::High);
    }
}
