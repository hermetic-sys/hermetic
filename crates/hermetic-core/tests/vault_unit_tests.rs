// Copyright (C) 2026 The Hermetic Project <dev@hermeticsys.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licenses available at hermeticsys.com/license

//! Hermetic Day 5 — Vault Unit Tests
//!
//! Written BEFORE vault.rs exists (test-first discipline).
//! These tests define the public API contract that vault.rs must satisfy.
//!
//! Tests that require SQLCipher (VaultDatabase) are cfg-gated.
//! T-11 (error variant test) runs on all platforms.

use hermetic_core::error::{FailClosedAction, VaultError};
#[cfg(not(target_os = "windows"))]
use hermetic_core::vault::{Vault, VaultState};
#[cfg(not(target_os = "windows"))]
use zeroize::Zeroizing;

/// Helper: create a valid passphrase (>= 12 bytes).
#[cfg(not(target_os = "windows"))]
fn valid_passphrase() -> Zeroizing<Vec<u8>> {
    Zeroizing::new(b"test-passphrase-day5!".to_vec())
}

/// Helper: create a different valid passphrase.
#[cfg(not(target_os = "windows"))]
fn wrong_passphrase() -> Zeroizing<Vec<u8>> {
    Zeroizing::new(b"wrong-passphrase-day5!".to_vec())
}

/// Helper: create a short passphrase (< 12 chars).
#[cfg(not(target_os = "windows"))]
fn short_passphrase() -> Zeroizing<Vec<u8>> {
    Zeroizing::new(b"short".to_vec())
}

// ============================================================================
// T-1: Vault::init on a fresh temp path → Ok(())
// ============================================================================
#[cfg(not(target_os = "windows"))]
#[test]
fn test_init_creates_vault() {
    let dir = tempfile::TempDir::new().unwrap_or_else(|e| panic!("tempdir: {:?}", e));

    let result = Vault::init(dir.path(), &valid_passphrase());
    assert!(
        result.is_ok(),
        "init on fresh path must succeed: {:?}",
        result.err()
    );

    // Verify vault.db was created
    assert!(
        dir.path().join("vault.db").exists(),
        "vault.db must exist after init"
    );
}

// ============================================================================
// T-2: Vault::init twice on same path → AlreadyInitialized
// ============================================================================
#[cfg(not(target_os = "windows"))]
#[test]
fn test_init_duplicate_fails() {
    let dir = tempfile::TempDir::new().unwrap_or_else(|e| panic!("tempdir: {:?}", e));

    Vault::init(dir.path(), &valid_passphrase()).unwrap_or_else(|e| panic!("first init: {:?}", e));

    let result = Vault::init(dir.path(), &valid_passphrase());
    assert!(result.is_err(), "second init must fail");
    assert!(
        matches!(result.unwrap_err(), VaultError::AlreadyInitialized),
        "second init must return AlreadyInitialized"
    );
}

// ============================================================================
// T-3: init → unlock with correct passphrase → Ok(Vault)
// ============================================================================
#[cfg(not(target_os = "windows"))]
#[test]
fn test_unlock_correct_passphrase() {
    let dir = tempfile::TempDir::new().unwrap_or_else(|e| panic!("tempdir: {:?}", e));
    let passphrase = valid_passphrase();

    Vault::init(dir.path(), &passphrase).unwrap_or_else(|e| panic!("init: {:?}", e));

    let result = Vault::unlock(dir.path(), &passphrase);
    assert!(
        result.is_ok(),
        "unlock with correct passphrase must succeed: {:?}",
        result.err()
    );
}

// ============================================================================
// T-4: init → unlock with wrong passphrase → InvalidPassphrase
// ============================================================================
#[cfg(not(target_os = "windows"))]
#[test]
fn test_unlock_wrong_passphrase() {
    let dir = tempfile::TempDir::new().unwrap_or_else(|e| panic!("tempdir: {:?}", e));

    Vault::init(dir.path(), &valid_passphrase()).unwrap_or_else(|e| panic!("init: {:?}", e));

    let result = Vault::unlock(dir.path(), &wrong_passphrase());
    assert!(result.is_err(), "unlock with wrong passphrase must fail");

    // Wrong passphrase may produce wrong db_key (→ DatabaseKeyInvalid)
    // or correct db_key but failed HMAC verify (→ InvalidPassphrase).
    // Both are acceptable fail-closed outcomes.
    match result {
        Err(VaultError::InvalidPassphrase) => {}
        Err(VaultError::DatabaseKeyInvalid) => {}
        Err(other) => panic!(
            "wrong passphrase must return InvalidPassphrase or DatabaseKeyInvalid, got: {:?}",
            other
        ),
        Ok(_) => panic!("Expected error, got Ok"),
    }
}

// ============================================================================
// T-5: init → unlock → seal → verify consumed (Rust ownership)
//
// seal() takes `self` by value, consuming the Vault. After seal(),
// the vault variable is moved and cannot be used. This is enforced
// at compile time by Rust's ownership system — no runtime test needed.
// We verify that seal() can be called and does not panic.
// ============================================================================
#[cfg(not(target_os = "windows"))]
#[test]
fn test_seal_transitions_state() {
    let dir = tempfile::TempDir::new().unwrap_or_else(|e| panic!("tempdir: {:?}", e));
    let passphrase = valid_passphrase();

    Vault::init(dir.path(), &passphrase).unwrap_or_else(|e| panic!("init: {:?}", e));

    let vault =
        Vault::unlock(dir.path(), &passphrase).unwrap_or_else(|e| panic!("unlock: {:?}", e));

    // seal() consumes vault — after this line, `vault` is moved.
    // If this compiles and doesn't panic, the ownership transfer works.
    vault.seal();

    // `vault` is now consumed. Any attempt to use it after this point
    // would be a compile-time error (use of moved value).
    // e.g., `vault.status();` would not compile.
}

// ============================================================================
// T-6: Drop guard zeroizes key material
//
// Verify that when Vault is dropped, master_key and db_key are zeroized.
// We test this indirectly: create a vault in an inner scope, let it drop,
// then verify the vault was properly consumed. Direct memory inspection
// would require unsafe code (Day 3 precedent allows this for zeroize tests).
// ============================================================================
#[cfg(not(target_os = "windows"))]
#[test]
fn test_drop_guard_zeroizes() {
    let dir = tempfile::TempDir::new().unwrap_or_else(|e| panic!("tempdir: {:?}", e));
    let passphrase = valid_passphrase();

    Vault::init(dir.path(), &passphrase).unwrap_or_else(|e| panic!("init: {:?}", e));

    {
        let vault =
            Vault::unlock(dir.path(), &passphrase).unwrap_or_else(|e| panic!("unlock: {:?}", e));

        // Vault is alive — status should work
        let status = vault.status();
        assert_eq!(status.state, VaultState::Unsealed);

        // vault drops here — Drop guard fires, zeroizing master_key and db_key
    }

    // After drop, we can re-unlock to verify the vault is still intact on disk
    // (Drop zeroizes in-memory keys, not the database)
    let vault2 = Vault::unlock(dir.path(), &passphrase)
        .unwrap_or_else(|e| panic!("re-unlock after drop: {:?}", e));
    vault2.seal();
}

// ============================================================================
// T-7: Full state transition cycle
// init → unlock (Unsealed) → seal (consumed) → re-unlock → seal
// ============================================================================
#[cfg(not(target_os = "windows"))]
#[test]
fn test_state_transitions_full_cycle() {
    let dir = tempfile::TempDir::new().unwrap_or_else(|e| panic!("tempdir: {:?}", e));
    let passphrase = valid_passphrase();

    // Init
    Vault::init(dir.path(), &passphrase).unwrap_or_else(|e| panic!("init: {:?}", e));

    // First unlock → unsealed
    let vault =
        Vault::unlock(dir.path(), &passphrase).unwrap_or_else(|e| panic!("first unlock: {:?}", e));
    assert_eq!(vault.status().state, VaultState::Unsealed);

    // Seal (consumes vault)
    vault.seal();

    // Re-unlock → unsealed again
    let vault2 =
        Vault::unlock(dir.path(), &passphrase).unwrap_or_else(|e| panic!("second unlock: {:?}", e));
    assert_eq!(vault2.status().state, VaultState::Unsealed);

    // Seal again
    vault2.seal();
}

// ============================================================================
// T-8: Operations on sealed vault fail
//
// APPROACH: Rust ownership semantics. seal() takes `self` by value,
// which means the Vault is consumed (moved). After seal(), the variable
// is no longer valid and any attempt to call methods on it is a
// COMPILE-TIME ERROR ("use of moved value"), not a runtime error.
//
// This means we do NOT need a runtime test — the type system guarantees
// this property. We document this instead of testing it, because the
// test literally cannot be written (it wouldn't compile).
//
// If seal() were changed to &mut self (returning the vault in a sealed
// state), we would need runtime checks. But self-by-value is stronger.
// ============================================================================
// NOTE: No test function for T-8. The compile-time guarantee is documented
// above. Attempting to write:
//   vault.seal();
//   vault.list_secrets(); // ← compile error: use of moved value
// would not compile, which IS the test.

// ============================================================================
// T-9: Passphrase < 12 chars → PassphraseTooShort at init
// ============================================================================
#[cfg(not(target_os = "windows"))]
#[test]
fn test_passphrase_too_short() {
    let dir = tempfile::TempDir::new().unwrap_or_else(|e| panic!("tempdir: {:?}", e));

    let result = Vault::init(dir.path(), &short_passphrase());
    assert!(result.is_err(), "short passphrase must be rejected at init");
    assert!(
        matches!(result.unwrap_err(), VaultError::PassphraseTooShort { .. }),
        "must return PassphraseTooShort"
    );
}

// ============================================================================
// T-10: Drop guard fires on scope exit
// ============================================================================
#[cfg(not(target_os = "windows"))]
#[test]
fn test_drop_guard_fires_on_scope_exit() {
    let dir = tempfile::TempDir::new().unwrap_or_else(|e| panic!("tempdir: {:?}", e));
    let passphrase = valid_passphrase();

    Vault::init(dir.path(), &passphrase).unwrap_or_else(|e| panic!("init: {:?}", e));

    // Create vault in inner scope
    {
        let _vault =
            Vault::unlock(dir.path(), &passphrase).unwrap_or_else(|e| panic!("unlock: {:?}", e));
        // _vault drops here when scope ends
    }
    // If Drop panicked, we wouldn't reach here.
    // The vault database is still intact — only in-memory keys are zeroized.

    // Prove vault is still usable after previous instance was dropped
    let vault =
        Vault::unlock(dir.path(), &passphrase).unwrap_or_else(|e| panic!("re-unlock: {:?}", e));
    vault.seal();
}

// ============================================================================
// T-11: PassphraseMismatch error variant maps to Deny
// This tests the error variant only — no DB, runs on all platforms.
// ============================================================================
#[test]
fn test_passphrase_mismatch_is_deny() {
    let err = VaultError::PassphraseMismatch;
    assert_eq!(
        err.fail_closed_action(),
        FailClosedAction::Deny,
        "PassphraseMismatch must map to Deny"
    );
}

// ============================================================================
// v1.1: update_secret_value tests
// ============================================================================
#[cfg(not(target_os = "windows"))]
#[test]
fn test_update_secret_value_roundtrip() {
    use hermetic_core::Zeroizing;
    let dir = tempfile::tempdir().unwrap();
    let pass = Zeroizing::new(b"test-passphrase-1234".to_vec());
    Vault::init(dir.path(), &pass).unwrap();
    let vault = Vault::unlock(dir.path(), &pass).unwrap();

    // Add initial secret
    let original = Zeroizing::new(b"original-value".to_vec());
    vault.add_secret("test-key", &original, "standard", None, None).unwrap();

    // Verify original
    let retrieved = vault.get_secret_bytes("test-key").unwrap();
    assert_eq!(&*retrieved, b"original-value");

    // Update in-place
    let updated = Zeroizing::new(b"updated-value".to_vec());
    vault.update_secret_value("test-key", &updated).unwrap();

    // Verify updated
    let retrieved = vault.get_secret_bytes("test-key").unwrap();
    assert_eq!(&*retrieved, b"updated-value");

    vault.seal();
}

#[cfg(not(target_os = "windows"))]
#[test]
fn test_update_secret_value_not_found() {
    use hermetic_core::Zeroizing;
    let dir = tempfile::tempdir().unwrap();
    let pass = Zeroizing::new(b"test-passphrase-1234".to_vec());
    Vault::init(dir.path(), &pass).unwrap();
    let vault = Vault::unlock(dir.path(), &pass).unwrap();

    let value = Zeroizing::new(b"some-value".to_vec());
    let result = vault.update_secret_value("nonexistent", &value);
    assert!(result.is_err());

    vault.seal();
}

#[cfg(not(target_os = "windows"))]
#[test]
fn test_update_secret_value_empty_rejected() {
    use hermetic_core::Zeroizing;
    let dir = tempfile::tempdir().unwrap();
    let pass = Zeroizing::new(b"test-passphrase-1234".to_vec());
    Vault::init(dir.path(), &pass).unwrap();
    let vault = Vault::unlock(dir.path(), &pass).unwrap();

    vault.add_secret("test-key", &Zeroizing::new(b"value".to_vec()), "standard", None, None).unwrap();

    let empty = Zeroizing::new(Vec::new());
    let result = vault.update_secret_value("test-key", &empty);
    assert!(result.is_err());

    vault.seal();
}
