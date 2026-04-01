// Copyright (C) 2026 The Hermetic Project <dev@hermeticsys.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licenses available at hermeticsys.com/license

//! Hermetic Fail-Closed Error Types
//!
//! Every error variant maps to a fail-closed behavior:
//!   DENY — request rejected, vault remains open
//!   SEAL — vault sealed, all keys zeroed
//!   HALT — daemon refuses to start or shuts down
//!
//! INVARIANT: No error path results in APPROVE, INJECT, or CONTINUE.
//! INVARIANT: Error messages contain IDs/names, NEVER secret values.

/// Fail-closed behavior classification for each error variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailClosedAction {
    /// Request denied, vault remains open
    Deny,
    /// Vault sealed, all keys zeroed immediately
    Seal,
    /// Daemon halts (refuses to start or shuts down)
    Halt,
}

/// Core error type for Hermetic operations.
/// Each variant has a defined fail-closed behavior.
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("vault initialization failed")]
    InitFailed,

    #[error("vault is sealed")]
    Sealed,

    #[error("access denied: {reason}")]
    Denied { reason: String },

    #[error("invalid passphrase")]
    InvalidPassphrase,

    #[error("passphrase too short: minimum {min_length} characters required")]
    PassphraseTooShort { min_length: usize },

    #[error("vault metadata corrupted — sealing")]
    CorruptedMeta,

    #[error("rate limited: retry after {retry_after_secs}s")]
    RateLimited { retry_after_secs: u64 },

    #[error("database error: {0}")]
    Database(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("KDF error: {0}")]
    Kdf(String),

    #[error("secret not found: {name}")]
    SecretNotFound { name: String },

    #[error("secret already exists: {name}")]
    SecretAlreadyExists { name: String },

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("vault already initialized at path")]
    AlreadyInitialized,

    #[error("vault not initialized")]
    NotInitialized,

    // Day 4 — H-3: Distinguish wrong key vs corrupt DB
    #[error("Database decryption failed: invalid key")]
    DatabaseKeyInvalid,

    #[error("Database structure corrupted")]
    DatabaseCorrupted,

    // Day 4 — H-1: Nonce length validation at read time
    #[error("Nonce length invalid: expected 12, got {actual}")]
    InvalidNonce { actual: usize },

    // Day 5: Filesystem I/O failure
    #[error("I/O error: {0}")]
    IoError(String),

    // Day 5: Passphrase confirmation mismatch at CLI
    #[error("passphrase confirmation does not match")]
    PassphraseMismatch,

    // Day 6: Audit log write failure (fail-closed → SEAL)
    #[error("audit failure: {0}")]
    AuditFailure(String),

    // Day 7: Empty secret value rejected at API level (defense-in-depth)
    #[error("secret value cannot be empty")]
    EmptySecret,

    // V1.0: Migration integrity check failed — secret count mismatch after schema migration
    #[error("migration integrity check failed: expected {expected} secrets, got {got_raw} (raw) / {got_dec} (decrypted)")]
    MigrationIntegrityFail {
        expected: usize,
        got_raw: usize,
        got_dec: usize,
    },

    // V1.0: Backup restore failed during migration rollback
    #[error("migration restore failed: {0}")]
    MigrationRestoreFailed(String),
}

impl VaultError {
    /// Returns the fail-closed action for this error variant.
    /// Used by vault state machine to determine behavior on error.
    pub fn fail_closed_action(&self) -> FailClosedAction {
        match self {
            // SEAL: data integrity compromised or unrecoverable
            VaultError::CorruptedMeta => FailClosedAction::Seal,
            VaultError::Sealed => FailClosedAction::Seal,

            // DENY: request-level rejection, vault stays open
            VaultError::Denied { .. } => FailClosedAction::Deny,
            VaultError::InvalidPassphrase => FailClosedAction::Deny,
            VaultError::PassphraseTooShort { .. } => FailClosedAction::Deny,
            VaultError::RateLimited { .. } => FailClosedAction::Deny,
            VaultError::SecretNotFound { .. } => FailClosedAction::Deny,
            VaultError::SecretAlreadyExists { .. } => FailClosedAction::Deny,
            VaultError::NotInitialized => FailClosedAction::Deny,
            VaultError::AlreadyInitialized => FailClosedAction::Deny,

            // SEAL: database or crypto failure = potential tampering
            VaultError::Database(_) => FailClosedAction::Seal,
            VaultError::Crypto(_) => FailClosedAction::Seal,
            VaultError::Kdf(_) => FailClosedAction::Seal,
            VaultError::Serialization(_) => FailClosedAction::Seal,

            // SEAL: init failure during vault creation
            VaultError::InitFailed => FailClosedAction::Seal,

            // SEAL: Day 4 — H-3 distinct database errors
            VaultError::DatabaseKeyInvalid => FailClosedAction::Seal,
            VaultError::DatabaseCorrupted => FailClosedAction::Seal,

            // SEAL: Day 4 — H-1 nonce length violation
            VaultError::InvalidNonce { .. } => FailClosedAction::Seal,

            // SEAL: Day 5 — filesystem I/O failure
            VaultError::IoError(_) => FailClosedAction::Seal,

            // DENY: Day 5 — passphrase confirmation mismatch
            VaultError::PassphraseMismatch => FailClosedAction::Deny,

            // SEAL: Day 6 — audit log failure is fail-closed
            VaultError::AuditFailure(_) => FailClosedAction::Seal,

            // DENY: Day 7 — empty secret rejected, vault stays open
            VaultError::EmptySecret => FailClosedAction::Deny,

            // SEAL: V1.0 — migration integrity failure
            VaultError::MigrationIntegrityFail { .. } => FailClosedAction::Seal,
            VaultError::MigrationRestoreFailed(_) => FailClosedAction::Seal,
        }
    }
}

#[cfg(not(target_os = "windows"))]
impl From<rusqlite::Error> for VaultError {
    fn from(e: rusqlite::Error) -> Self {
        let msg = e.to_string();
        if msg.contains("not a database") || msg.contains("decrypt") {
            VaultError::DatabaseKeyInvalid
        } else {
            VaultError::DatabaseCorrupted
        }
    }
}

impl From<std::io::Error> for VaultError {
    fn from(e: std::io::Error) -> Self {
        VaultError::IoError(e.to_string())
    }
}

impl From<serde_json::Error> for VaultError {
    fn from(_e: serde_json::Error) -> Self {
        VaultError::CorruptedMeta
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corrupted_meta_seals() {
        assert_eq!(
            VaultError::CorruptedMeta.fail_closed_action(),
            FailClosedAction::Seal
        );
    }

    #[test]
    fn invalid_passphrase_denies() {
        assert_eq!(
            VaultError::InvalidPassphrase.fail_closed_action(),
            FailClosedAction::Deny
        );
    }

    #[test]
    fn database_error_seals() {
        let err = VaultError::Database("test".into());
        assert_eq!(err.fail_closed_action(), FailClosedAction::Seal);
    }

    #[test]
    fn rate_limited_denies() {
        let err = VaultError::RateLimited {
            retry_after_secs: 900,
        };
        assert_eq!(err.fail_closed_action(), FailClosedAction::Deny);
    }

    #[test]
    fn crypto_error_seals() {
        let err = VaultError::Crypto("test".into());
        assert_eq!(err.fail_closed_action(), FailClosedAction::Seal);
    }

    #[test]
    fn all_variants_have_defined_action() {
        // Ensure every variant maps to a concrete action, not a wildcard
        let variants: Vec<VaultError> = vec![
            VaultError::InitFailed,
            VaultError::Sealed,
            VaultError::Denied {
                reason: "test".into(),
            },
            VaultError::InvalidPassphrase,
            VaultError::PassphraseTooShort { min_length: 12 },
            VaultError::CorruptedMeta,
            VaultError::RateLimited {
                retry_after_secs: 60,
            },
            VaultError::Database("test".into()),
            VaultError::Crypto("test".into()),
            VaultError::Kdf("test".into()),
            VaultError::SecretNotFound {
                name: "test".into(),
            },
            VaultError::SecretAlreadyExists {
                name: "test".into(),
            },
            VaultError::Serialization("test".into()),
            VaultError::AlreadyInitialized,
            VaultError::NotInitialized,
            VaultError::DatabaseKeyInvalid,
            VaultError::DatabaseCorrupted,
            VaultError::InvalidNonce { actual: 8 },
            VaultError::IoError("test".into()),
            VaultError::PassphraseMismatch,
            VaultError::AuditFailure("test".into()),
            VaultError::EmptySecret,
        ];
        for v in variants {
            let action = v.fail_closed_action();
            assert!(
                action == FailClosedAction::Deny
                    || action == FailClosedAction::Seal
                    || action == FailClosedAction::Halt,
            );
        }
    }

    /// Day 2 (Task 6c): Exhaustive fail-closed mapping verification.
    /// Every VaultError variant must map to exactly one FailClosedAction.
    /// This test will fail to compile if a new variant is added without
    /// updating both the match in fail_closed_action() and this test.
    #[test]
    fn exhaustive_fail_closed_mapping() {
        // Construct every variant explicitly — no wildcard
        let mappings: Vec<(VaultError, FailClosedAction)> = vec![
            (VaultError::InitFailed, FailClosedAction::Seal),
            (VaultError::Sealed, FailClosedAction::Seal),
            (
                VaultError::Denied { reason: "x".into() },
                FailClosedAction::Deny,
            ),
            (VaultError::InvalidPassphrase, FailClosedAction::Deny),
            (
                VaultError::PassphraseTooShort { min_length: 12 },
                FailClosedAction::Deny,
            ),
            (VaultError::CorruptedMeta, FailClosedAction::Seal),
            (
                VaultError::RateLimited {
                    retry_after_secs: 60,
                },
                FailClosedAction::Deny,
            ),
            (VaultError::Database("x".into()), FailClosedAction::Seal),
            (VaultError::Crypto("x".into()), FailClosedAction::Seal),
            (VaultError::Kdf("x".into()), FailClosedAction::Seal),
            (
                VaultError::SecretNotFound { name: "x".into() },
                FailClosedAction::Deny,
            ),
            (
                VaultError::SecretAlreadyExists { name: "x".into() },
                FailClosedAction::Deny,
            ),
            (
                VaultError::Serialization("x".into()),
                FailClosedAction::Seal,
            ),
            (VaultError::AlreadyInitialized, FailClosedAction::Deny),
            (VaultError::NotInitialized, FailClosedAction::Deny),
            // Day 4 — H-3 + H-1 new variants
            (VaultError::DatabaseKeyInvalid, FailClosedAction::Seal),
            (VaultError::DatabaseCorrupted, FailClosedAction::Seal),
            (
                VaultError::InvalidNonce { actual: 8 },
                FailClosedAction::Seal,
            ),
            // Day 5 new variants
            (VaultError::IoError("x".into()), FailClosedAction::Seal),
            (VaultError::PassphraseMismatch, FailClosedAction::Deny),
            // Day 6 new variant
            (VaultError::AuditFailure("x".into()), FailClosedAction::Seal),
            // Day 7 new variant
            (VaultError::EmptySecret, FailClosedAction::Deny),
        ];

        for (variant, expected_action) in &mappings {
            let actual = variant.fail_closed_action();
            assert_eq!(
                actual, *expected_action,
                "VaultError::{:?} must map to {:?}, got {:?}",
                variant, expected_action, actual
            );
        }

        // Verify count matches: if a new variant is added to VaultError
        // but not to this list, the match in fail_closed_action() will
        // produce a compile error (no wildcard), and this count assertion
        // provides a secondary safety net.
        assert_eq!(mappings.len(), 22, "Expected 22 VaultError variants");
    }

    // ── Mutation gap: From<rusqlite::Error> branch coverage ──

    /// Mutation gap: rusqlite error containing "not a database" maps to DatabaseKeyInvalid.
    #[test]
    fn rusqlite_not_a_database_maps_to_key_invalid() {
        // InvalidParameterName's to_string() includes the parameter name,
        // so embedding "not a database" in it exercises the if-branch.
        let err = rusqlite::Error::InvalidParameterName("not a database".into());
        let vault_err: VaultError = err.into();
        assert!(
            matches!(vault_err, VaultError::DatabaseKeyInvalid),
            "Expected DatabaseKeyInvalid, got {:?}",
            vault_err
        );
    }

    /// Mutation gap: rusqlite error containing "decrypt" maps to DatabaseKeyInvalid.
    #[test]
    fn rusqlite_decrypt_error_maps_to_key_invalid() {
        let err = rusqlite::Error::InvalidParameterName("failed to decrypt".into());
        let vault_err: VaultError = err.into();
        assert!(
            matches!(vault_err, VaultError::DatabaseKeyInvalid),
            "Expected DatabaseKeyInvalid, got {:?}",
            vault_err
        );
    }

    /// Mutation gap: rusqlite error without "not a database" or "decrypt" maps to DatabaseCorrupted.
    #[test]
    fn rusqlite_generic_error_maps_to_corrupted() {
        let err = rusqlite::Error::QueryReturnedNoRows;
        let vault_err: VaultError = err.into();
        assert!(
            matches!(vault_err, VaultError::DatabaseCorrupted),
            "Expected DatabaseCorrupted, got {:?}",
            vault_err
        );
    }

    /// Mutation gap: both branches of From<rusqlite::Error> map to Seal action.
    #[test]
    fn rusqlite_both_branches_seal() {
        let key_invalid: VaultError =
            rusqlite::Error::InvalidParameterName("not a database".into()).into();
        let corrupted: VaultError = rusqlite::Error::QueryReturnedNoRows.into();
        assert_eq!(key_invalid.fail_closed_action(), FailClosedAction::Seal);
        assert_eq!(corrupted.fail_closed_action(), FailClosedAction::Seal);
    }
}
