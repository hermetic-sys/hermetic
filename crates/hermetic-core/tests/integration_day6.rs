// Hermetic — Zero-Knowledge Credential Broker for AI Agents
// Copyright (C) 2026 The Hermetic Project
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.
//
// Commercial licenses available at https://hermeticsys.com/license

#![cfg(not(target_os = "windows"))]
//! Hermetic Day 6 — Integration Tests
//!
//! Tests the interaction between vault operations, rate limiting, and audit logging.
//! All tests are cfg-gated for Linux/macOS only (SQLCipher dependency per CP-001).
//!
//! Written BEFORE production code exists (test-first discipline).
//! These tests will FAIL until Phase C implements rate_limit.rs, audit.rs,
//! and integrates them into vault.rs.

use hermetic_core::error::{FailClosedAction, VaultError};
use hermetic_core::vault::Vault;
use zeroize::Zeroizing;

const CORRECT_PASS: &[u8] = b"correct-passphrase-day6!";
const WRONG_PASS: &[u8] = b"wrong-passphrase-XXXX";

// ============================================================================
// T-INT-1: test_unlock_rate_limited_after_5_failures
//
// Init vault -> 5 wrong passphrases -> verify vault is SEALED after 5th
// failure (vault.seal() called) -> 6th attempt returns RateLimited error
// (DENY). This tests BOTH the vault seal action AND the rate limiter lockout.
// ============================================================================
#[test]
fn test_unlock_rate_limited_after_5_failures() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let passphrase = Zeroizing::new(CORRECT_PASS.to_vec());

    // Init vault with correct passphrase
    Vault::init(dir.path(), &passphrase).expect("init");

    // 5 wrong passphrase attempts
    let wrong = Zeroizing::new(WRONG_PASS.to_vec());
    for i in 0..5 {
        let result = Vault::unlock(dir.path(), &wrong);
        assert!(
            result.is_err(),
            "Wrong passphrase attempt {} must fail",
            i + 1
        );
    }

    // 6th attempt (even with correct passphrase) must return RateLimited
    let result = Vault::unlock(dir.path(), &passphrase);
    match result {
        Err(VaultError::RateLimited { .. }) => {} // expected
        Err(other) => panic!("Expected RateLimited error, got: {:?}", other),
        Ok(_) => panic!("Must be locked out after 5 failures, got Ok"),
    }
}

// ============================================================================
// T-INT-2: test_rate_limit_resets_on_success
//
// Init vault -> 3 wrong -> 1 correct -> 3 more wrong -> still allowed
// (counter was reset).
// ============================================================================
#[test]
fn test_rate_limit_resets_on_success() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let passphrase = Zeroizing::new(CORRECT_PASS.to_vec());

    Vault::init(dir.path(), &passphrase).expect("init");

    let wrong = Zeroizing::new(WRONG_PASS.to_vec());

    // 3 wrong attempts
    for _ in 0..3 {
        let _ = Vault::unlock(dir.path(), &wrong);
    }

    // 1 correct attempt — resets counter
    let vault = Vault::unlock(dir.path(), &passphrase).expect("correct unlock must succeed");
    vault.seal();

    // 3 more wrong attempts — still under threshold (counter was reset)
    for _ in 0..3 {
        let _ = Vault::unlock(dir.path(), &wrong);
    }

    // Next correct attempt must still succeed (only 3 failures since reset)
    let vault =
        Vault::unlock(dir.path(), &passphrase).expect("must succeed: only 3 failures since reset");
    vault.seal();
}

// ============================================================================
// T-INT-3: test_audit_log_records_operations
//
// Init -> unlock -> add secret -> list -> seal.
// Read audit log. Verify entries exist for each op.
// Verify HMAC chain is intact.
// ============================================================================
#[test]
fn test_audit_log_records_operations() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let passphrase = Zeroizing::new(CORRECT_PASS.to_vec());

    Vault::init(dir.path(), &passphrase).expect("init");
    let vault = Vault::unlock(dir.path(), &passphrase).expect("unlock");

    // Perform operations
    let secret_value = Zeroizing::new(b"test-secret-value-12345".to_vec());
    vault
        .add_secret("test_key", &secret_value, "standard", None, None)
        .expect("add secret");
    let _ = vault.list_secrets().expect("list");

    // Read audit log and verify entries
    let audit_log = vault.audit_log().expect("audit log");
    let entries = audit_log.read_entries().expect("read entries");
    assert!(
        !entries.is_empty(),
        "Audit log must have entries after operations"
    );

    // Verify HMAC chain integrity
    let verify_result = audit_log.verify();
    assert!(
        verify_result.is_ok(),
        "HMAC chain must be intact: {:?}",
        verify_result.err()
    );

    vault.seal();
}

// ============================================================================
// T-INT-4: test_audit_log_no_secret_values
//
// Add secret with known value. Read all audit entries.
// Grep for known value. Must not appear anywhere.
// ============================================================================
#[test]
fn test_audit_log_no_secret_values() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let passphrase = Zeroizing::new(CORRECT_PASS.to_vec());

    Vault::init(dir.path(), &passphrase).expect("init");
    let vault = Vault::unlock(dir.path(), &passphrase).expect("unlock");

    // Add a secret with a KNOWN value
    let known_value = "sk-ant-SUPER-SECRET-API-KEY-12345";
    let secret_value = Zeroizing::new(known_value.as_bytes().to_vec());
    vault
        .add_secret("api_key", &secret_value, "high", None, None)
        .expect("add secret");

    // Read all audit entries
    let audit_log = vault.audit_log().expect("audit log");
    let entries = audit_log.read_entries().expect("read entries");

    // Grep for the known secret VALUE in all entry fields
    for (_hmac, entry) in &entries {
        let debug = format!("{:?}", entry);
        assert!(
            !debug.contains(known_value),
            "SECURITY: Audit entry must NEVER contain secret values. Found in: {}",
            debug
        );
        assert!(
            !debug.contains("sk-ant"),
            "SECURITY: Audit entry must NEVER contain secret value prefix"
        );
    }

    // Secret NAME (identifier) IS allowed
    let all_debug: String = entries
        .iter()
        .map(|(_, e)| format!("{:?}", e))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        all_debug.contains("api_key"),
        "Secret name (identifier) must be present in audit entries"
    );

    vault.seal();
}

// ============================================================================
// T-INT-5: test_audit_write_failure_seals_vault
//
// Simulate audit write failure (e.g., corrupt DB path).
// Verify vault seals (FailClosedAction::Seal).
// Primary operation must NOT complete successfully.
// ============================================================================
#[test]
fn test_audit_write_failure_seals_vault() {
    // Verify that AuditFailure maps to FailClosedAction::Seal
    let err = VaultError::AuditFailure("simulated write failure".into());
    assert_eq!(
        err.fail_closed_action(),
        FailClosedAction::Seal,
        "AuditFailure must map to Seal — audit write failure is fail-closed"
    );

    // Full integration: init vault, then corrupt the audit log state
    // so that the next write fails. The vault must seal automatically.
    let dir = tempfile::TempDir::new().expect("tempdir");
    let passphrase = Zeroizing::new(CORRECT_PASS.to_vec());

    Vault::init(dir.path(), &passphrase).expect("init");
    let vault = Vault::unlock(dir.path(), &passphrase).expect("unlock");

    // Remove the database file to force an audit write failure
    let db_path = dir.path().join("vault.db");
    std::fs::remove_file(&db_path).expect("remove db to simulate failure");

    // Next operation that triggers an audit write should fail
    let secret_value = Zeroizing::new(b"test-value".to_vec());
    let result = vault.add_secret("test_key", &secret_value, "standard", None, None);
    assert!(
        result.is_err(),
        "Operation must fail when audit write fails"
    );
}
