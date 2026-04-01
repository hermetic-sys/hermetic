// Copyright (C) 2026 The Hermetic Project <dev@hermeticsys.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licenses available at hermeticsys.com/license

//! Hermetic Day 5 — Integration Tests
//!
//! Full-stack tests: KDF → DB → crypto → Vault roundtrip.
//! Written BEFORE vault.rs exists (test-first discipline).
//!
//! Platform gate: ALL tests require SQLCipher (VaultDatabase).
//! On Windows, this entire file is cfg-skipped.

#![cfg(not(target_os = "windows"))]

use hermetic_core::secret::Sensitivity;
use hermetic_core::vault::{Vault, VaultState};
use hermetic_core::VaultError;
use zeroize::Zeroizing;

/// Shared test passphrase (>= 12 bytes).
fn test_passphrase() -> Zeroizing<Vec<u8>> {
    Zeroizing::new(b"integration-test-passphrase-day5!".to_vec())
}

/// Helper: init + unlock a fresh vault, returning the Vault and TempDir.
fn setup_vault() -> (Vault, tempfile::TempDir) {
    let dir = tempfile::TempDir::new().unwrap_or_else(|e| panic!("tempdir: {:?}", e));
    let passphrase = test_passphrase();

    Vault::init(dir.path(), &passphrase).unwrap_or_else(|e| panic!("init: {:?}", e));

    let vault =
        Vault::unlock(dir.path(), &passphrase).unwrap_or_else(|e| panic!("unlock: {:?}", e));

    (vault, dir)
}

// ============================================================================
// I-1: Full lifecycle
// init → unlock → add → list (name present, value absent) → remove → list (empty) → seal
// ============================================================================
#[test]
fn test_full_lifecycle() {
    let (vault, _dir) = setup_vault();

    // Add a secret
    let value = Zeroizing::new(b"sk-ant-test-12345".to_vec());
    vault
        .add_secret("api_key", &value, Sensitivity::Standard, None, None)
        .unwrap_or_else(|e| panic!("add: {:?}", e));

    // List — verify name present, value NOT in output
    let secrets = vault
        .list_secrets()
        .unwrap_or_else(|e| panic!("list: {:?}", e));
    assert_eq!(secrets.len(), 1, "should have 1 secret");
    assert_eq!(secrets[0].name, "api_key");

    // Verify the list output does NOT contain the secret value.
    // SecretEntry has: id, name, sensitivity, created_at, rotated_at
    // It does NOT have a value/plaintext/ciphertext field.
    let debug_output = format!("{:?}", secrets[0]);
    assert!(
        !debug_output.contains("sk-ant"),
        "list output must NEVER contain secret values"
    );

    // Remove
    vault
        .remove_secret("api_key")
        .unwrap_or_else(|e| panic!("remove: {:?}", e));

    // List again — should be empty
    let secrets = vault
        .list_secrets()
        .unwrap_or_else(|e| panic!("list after remove: {:?}", e));
    assert_eq!(secrets.len(), 0, "should have 0 secrets after remove");

    // Seal
    vault.seal();
}

// ============================================================================
// I-2: Add with sensitivity=High → list shows High
// ============================================================================
#[test]
fn test_add_high_sensitivity() {
    let (vault, _dir) = setup_vault();

    let value = Zeroizing::new(b"root-certificate-data".to_vec());
    vault
        .add_secret("root_cert", &value, Sensitivity::High, None, None)
        .unwrap_or_else(|e| panic!("add: {:?}", e));

    let secrets = vault
        .list_secrets()
        .unwrap_or_else(|e| panic!("list: {:?}", e));
    assert_eq!(secrets.len(), 1);
    assert_eq!(secrets[0].name, "root_cert");
    assert_eq!(secrets[0].sensitivity, Sensitivity::High);

    vault.seal();
}

// ============================================================================
// I-3: Status shows correct count
// init → unlock → add 3 secrets → status → assert count == 3
// ============================================================================
#[test]
fn test_status_shows_correct_count() {
    let (vault, _dir) = setup_vault();

    let v1 = Zeroizing::new(b"value-1".to_vec());
    let v2 = Zeroizing::new(b"value-2".to_vec());
    let v3 = Zeroizing::new(b"value-3".to_vec());

    vault
        .add_secret("key1", &v1, Sensitivity::Standard, None, None)
        .unwrap_or_else(|e| panic!("add 1: {:?}", e));
    vault
        .add_secret("key2", &v2, Sensitivity::Low, None, None)
        .unwrap_or_else(|e| panic!("add 2: {:?}", e));
    vault
        .add_secret("key3", &v3, Sensitivity::High, None, None)
        .unwrap_or_else(|e| panic!("add 3: {:?}", e));

    let status = vault.status();
    assert_eq!(status.state, VaultState::Unsealed);
    assert_eq!(status.secret_count, 3, "status must show 3 secrets");
    assert_eq!(status.mode, "software");

    vault.seal();
}

// ============================================================================
// I-4: Add duplicate → SecretAlreadyExists
// ============================================================================
#[test]
fn test_add_duplicate_fails() {
    let (vault, _dir) = setup_vault();

    let v1 = Zeroizing::new(b"first-value".to_vec());
    vault
        .add_secret("dup_key", &v1, Sensitivity::Standard, None, None)
        .unwrap_or_else(|e| panic!("first add: {:?}", e));

    let v2 = Zeroizing::new(b"second-value".to_vec());
    let result = vault.add_secret("dup_key", &v2, Sensitivity::Standard, None, None);
    assert!(result.is_err(), "duplicate add must fail");
    assert!(
        matches!(result.unwrap_err(), VaultError::SecretAlreadyExists { .. }),
        "must return SecretAlreadyExists"
    );

    vault.seal();
}

// ============================================================================
// I-5: Remove nonexistent → SecretNotFound
// ============================================================================
#[test]
fn test_remove_nonexistent_fails() {
    let (vault, _dir) = setup_vault();

    let result = vault.remove_secret("nonexistent");
    assert!(result.is_err(), "remove nonexistent must fail");
    assert!(
        matches!(result.unwrap_err(), VaultError::SecretNotFound { .. }),
        "must return SecretNotFound"
    );

    vault.seal();
}
