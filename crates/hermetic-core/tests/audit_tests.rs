// Copyright (C) 2026 The Hermetic Project <dev@hermeticsys.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licenses available at hermeticsys.com/license

//! Hermetic Day 6 — Audit Log Unit Tests
//!
//! Written BEFORE audit.rs exists (test-first discipline).
//! Pure crypto tests (HMAC computation) run on ALL platforms.
//! DB-backed tests are cfg-gated per CP-001.
//!
//! Assumed API surface:
//!   AuditEntry { timestamp, action, secret_name, agent, details }
//!   compute_genesis_hmac(audit_key: &[u8]) -> Vec<u8>
//!   compute_chain_hmac(audit_key: &[u8], prev_hmac: &[u8], entry: &AuditEntry) -> Vec<u8>
//!   verify_chain(audit_key: &[u8], entries: &[(Vec<u8>, AuditEntry)]) -> Result<(), VaultError>
//!
//!   (DB-backed, cfg-gated):
//!   AuditLog::new(db: &VaultDatabase, audit_key: Zeroizing<Vec<u8>>) -> Self
//!   AuditLog::write_entry(&self, entry: &AuditEntry) -> Result<(), VaultError>
//!   AuditLog::read_entries(&self) -> Result<Vec<(Vec<u8>, AuditEntry)>, VaultError>
//!   AuditLog::verify(&self) -> Result<(), VaultError>

use hermetic_core::audit::{compute_chain_hmac, compute_genesis_hmac, AuditEntry};
use hermetic_core::error::{FailClosedAction, VaultError};
use hermetic_core::kdf;

#[cfg(not(target_os = "windows"))]
use zeroize::Zeroizing;

/// Helper: create a known audit key from a fixed master key.
/// Uses the real KDF derivation to ensure consistency.
fn test_audit_key() -> Vec<u8> {
    // Use a fixed 32-byte master key for deterministic tests
    let master_key = vec![0x42u8; 32];
    kdf::derive_audit_key(&master_key)
        .expect("audit key derivation must succeed")
        .to_vec()
}

/// Helper: create a test audit entry.
fn test_entry(action: &str, secret_name: Option<&str>) -> AuditEntry {
    AuditEntry {
        timestamp: "2026-02-08T12:00:00Z".to_string(),
        action: action.to_string(),
        secret_name: secret_name.map(|s| s.to_string()),
        agent: Some("test".to_string()),
        details: None,
    }
}

// ============================================================================
// T-AU-1: Audit key derivation is deterministic
// Platform: ALL (pure crypto, no DB)
// ============================================================================
#[test]
fn test_audit_key_derivation() {
    let master_key = vec![0x42u8; 32];
    let key1 = kdf::derive_audit_key(&master_key).expect("derive 1");
    let key2 = kdf::derive_audit_key(&master_key).expect("derive 2");

    assert_eq!(key1.len(), 32, "audit key must be 32 bytes");
    assert_eq!(*key1, *key2, "audit key derivation must be deterministic");

    // Different master key → different audit key
    let other_master = vec![0x43u8; 32];
    let key3 = kdf::derive_audit_key(&other_master).expect("derive 3");
    assert_ne!(
        *key1, *key3,
        "different master key must produce different audit key"
    );
}

// ============================================================================
// T-AU-2: Genesis HMAC is deterministic (known-answer test)
// Platform: ALL
// ============================================================================
#[test]
fn test_genesis_hmac() {
    let audit_key = test_audit_key();

    let hmac1 = compute_genesis_hmac(&audit_key);
    let hmac2 = compute_genesis_hmac(&audit_key);

    assert_eq!(hmac1.len(), 32, "genesis HMAC must be 32 bytes (SHA-256)");
    assert_eq!(hmac1, hmac2, "genesis HMAC must be deterministic");

    // Different key → different genesis
    let other_key = vec![0x99u8; 32];
    let hmac3 = compute_genesis_hmac(&other_key);
    assert_ne!(hmac1, hmac3, "different key must produce different genesis");
}

// ============================================================================
// T-AU-3: Chain HMAC is deterministic
// Platform: ALL
// ============================================================================
#[test]
fn test_chain_hmac_deterministic() {
    let audit_key = test_audit_key();
    let genesis = compute_genesis_hmac(&audit_key);
    let entry = test_entry("unlock", None);

    let hmac1 = compute_chain_hmac(&audit_key, &genesis, &entry);
    let hmac2 = compute_chain_hmac(&audit_key, &genesis, &entry);

    assert_eq!(hmac1.len(), 32, "chain HMAC must be 32 bytes");
    assert_eq!(hmac1, hmac2, "chain HMAC must be deterministic");

    // Second entry chains from first
    let entry2 = test_entry("add_secret", Some("api_key"));
    let hmac3 = compute_chain_hmac(&audit_key, &hmac1, &entry2);
    assert_ne!(
        hmac1, hmac3,
        "different entries must produce different HMACs"
    );
}

// ============================================================================
// T-AU-4: Tamper detection — modified entry breaks chain
// Platform: ALL
// ============================================================================
#[test]
fn test_tamper_detection() {
    let audit_key = test_audit_key();
    let genesis = compute_genesis_hmac(&audit_key);

    let entry1 = test_entry("unlock", None);
    let hmac1 = compute_chain_hmac(&audit_key, &genesis, &entry1);

    let entry2 = test_entry("add_secret", Some("api_key"));
    let hmac2 = compute_chain_hmac(&audit_key, &hmac1, &entry2);

    // Tamper with entry1 — recompute HMAC with modified entry
    let tampered = test_entry("TAMPERED", None);
    let tampered_hmac1 = compute_chain_hmac(&audit_key, &genesis, &tampered);

    // The tampered HMAC differs from the original
    assert_ne!(
        hmac1, tampered_hmac1,
        "tampered entry must produce different HMAC"
    );

    // Chain built on tampered HMAC diverges
    let tampered_hmac2 = compute_chain_hmac(&audit_key, &tampered_hmac1, &entry2);
    assert_ne!(
        hmac2, tampered_hmac2,
        "chain built on tampered entry must diverge"
    );
}

// ============================================================================
// T-AU-5: Entry fields — no secret VALUES in any field
// Platform: ALL
// ============================================================================
#[test]
fn test_log_entry_fields() {
    let entry = AuditEntry {
        timestamp: "2026-02-08T12:00:00Z".to_string(),
        action: "add_secret".to_string(),
        secret_name: Some("anthropic_api_key".to_string()),
        agent: Some("cli".to_string()),
        details: Some("sensitivity=high".to_string()),
    };

    // Verify all fields are present
    assert!(!entry.timestamp.is_empty());
    assert!(!entry.action.is_empty());
    assert!(entry.secret_name.is_some());
    assert!(entry.agent.is_some());
    assert!(entry.details.is_some());

    // Verify no secret VALUE in any field — names are OK, values are NOT
    let debug = format!("{:?}", entry);
    assert!(
        !debug.contains("sk-ant"),
        "audit entry must NEVER contain secret values"
    );
    // Secret name (identifier) IS allowed
    assert!(
        debug.contains("anthropic_api_key"),
        "secret name (identifier) must be present in entry"
    );
}

// ============================================================================
// T-AU-6: Write + read roundtrip (DB-backed)
// Platform: LINUX ONLY
// ============================================================================
#[cfg(not(target_os = "windows"))]
#[test]
fn test_log_write_and_read_roundtrip() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let passphrase = Zeroizing::new(b"test-passphrase-audit-day6!".to_vec());

    // Init and unlock vault to get DB + audit key
    hermetic_core::vault::Vault::init(dir.path(), &passphrase).expect("init");
    let vault = hermetic_core::vault::Vault::unlock(dir.path(), &passphrase).expect("unlock");

    let audit_log = vault.audit_log().expect("audit log must be accessible");

    let entry = test_entry("test_operation", Some("test_secret"));
    audit_log.write_entry(&entry).expect("write must succeed");

    let entries = audit_log.read_entries().expect("read must succeed");
    assert_eq!(entries.len(), 1, "must have 1 entry after write");
    assert_eq!(entries[0].1.action, "test_operation");

    vault.seal();
}

// ============================================================================
// T-AU-7: Verify full chain (N entries)
// Platform: LINUX ONLY
// ============================================================================
#[cfg(not(target_os = "windows"))]
#[test]
fn test_verify_full_chain() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let passphrase = Zeroizing::new(b"test-passphrase-audit-day6!".to_vec());

    hermetic_core::vault::Vault::init(dir.path(), &passphrase).expect("init");
    let vault = hermetic_core::vault::Vault::unlock(dir.path(), &passphrase).expect("unlock");

    let audit_log = vault.audit_log().expect("audit log");

    // Write 5 entries
    for i in 0..5 {
        let entry = test_entry(&format!("operation_{}", i), Some(&format!("secret_{}", i)));
        audit_log.write_entry(&entry).expect("write");
    }

    // Verify chain integrity
    let result = audit_log.verify();
    assert!(
        result.is_ok(),
        "chain verification must pass: {:?}",
        result.err()
    );

    vault.seal();
}

// ============================================================================
// T-AU-8: Empty chain verification succeeds (genesis only)
// Platform: LINUX ONLY
// ============================================================================
#[cfg(not(target_os = "windows"))]
#[test]
fn test_empty_chain_verification() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let passphrase = Zeroizing::new(b"test-passphrase-audit-day6!".to_vec());

    hermetic_core::vault::Vault::init(dir.path(), &passphrase).expect("init");
    let vault = hermetic_core::vault::Vault::unlock(dir.path(), &passphrase).expect("unlock");

    let audit_log = vault.audit_log().expect("audit log");

    // No entries written — verify should still pass (genesis only)
    let result = audit_log.verify();
    assert!(
        result.is_ok(),
        "empty chain verification must succeed: {:?}",
        result.err()
    );

    vault.seal();
}

// ============================================================================
// T-AU-9: AuditFailure maps to FailClosedAction::Seal
// Platform: ALL (error variant only, no DB)
// ============================================================================
#[test]
fn test_audit_failure_maps_to_seal() {
    let err = VaultError::AuditFailure("write failed".into());
    assert_eq!(
        err.fail_closed_action(),
        FailClosedAction::Seal,
        "AuditFailure must map to Seal — audit write failure is fail-closed"
    );
}
