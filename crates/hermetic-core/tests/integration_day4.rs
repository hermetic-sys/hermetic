// Copyright (C) 2026 The Hermetic Project <dev@hermeticsys.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licenses available at hermeticsys.com/license

//! Hermetic Day 4 Integration Tests
//!
//! Proves the full pipeline: KDF → DB → AES-256-GCM → roundtrip.
//! These tests use real Argon2id derivation (expensive but authentic).
//!
//! Platform gate: ALL integration tests require SQLCipher (VaultDatabase),
//! which is only available on Linux/macOS. On Windows, this entire test
//! crate is cfg-skipped. The tests are syntactically correct and ready
//! for Linux CI verification.

// Skip entire test crate on Windows — SQLCipher requires OpenSSL
#![cfg(not(target_os = "windows"))]

use hermetic_core::crypto;
use hermetic_core::db::VaultDatabase;
use hermetic_core::error::VaultError;
use hermetic_core::kdf;
use hermetic_core::vault_meta::VaultMeta;
use tempfile::NamedTempFile;

/// Shared test passphrase (>= 12 bytes as required by KDF).
const TEST_PASSPHRASE: &[u8] = b"integration-test-passphrase-day4";

/// Derive a full key chain for integration testing.
fn derive_test_chain() -> (kdf::DerivedKeys, [u8; 32]) {
    let salt = kdf::generate_vault_salt()
        .unwrap_or_else(|e| panic!("generate_vault_salt failed: {:?}", e));
    let keys = kdf::derive_full_chain(TEST_PASSPHRASE, &salt)
        .unwrap_or_else(|e| panic!("derive_full_chain failed: {:?}", e));
    (keys, salt)
}

/// T-INT-1: FULL ROUNDTRIP
/// passphrase → derive_full_chain() → db_key + derive_kek("secret-1")
/// → VaultDatabase::create() → encrypt_secret(kek, "secret-1", plaintext)
/// → store_secret() → get_secret() → decrypt_secret() → assert plaintext matches
#[test]
fn full_roundtrip() {
    let (keys, _salt) = derive_test_chain();
    let secret_id = "secret-1";
    let plaintext = b"sk-ant-XXXX";

    let kek = kdf::derive_kek(&keys.master_key, secret_id)
        .unwrap_or_else(|e| panic!("derive_kek failed: {:?}", e));

    let tmp = NamedTempFile::new().unwrap_or_else(|e| panic!("tempfile: {:?}", e));
    let db = VaultDatabase::create(tmp.path(), &keys.db_key)
        .unwrap_or_else(|e| panic!("create db: {:?}", e));

    let (ciphertext, nonce) = crypto::encrypt_secret(&kek, secret_id, plaintext)
        .unwrap_or_else(|e| panic!("encrypt: {:?}", e));

    db.store_secret(
        secret_id,
        "my-api-key",
        &ciphertext,
        &nonce,
        "high",
        "",
        "2026-02-08",
        None,
        "static",
    )
    .unwrap_or_else(|e| panic!("store: {:?}", e));

    let (id, enc_blob, enc_nonce, sens, ts, _domains) = db
        .get_secret("my-api-key")
        .unwrap_or_else(|e| panic!("get: {:?}", e));

    assert_eq!(id, secret_id);
    assert_eq!(enc_blob, ciphertext);
    assert_eq!(enc_nonce, nonce);
    assert_eq!(sens, "high");
    assert_eq!(ts, "2026-02-08");

    let decrypted = crypto::decrypt_secret(&kek, secret_id, &enc_blob, &enc_nonce)
        .unwrap_or_else(|e| panic!("decrypt: {:?}", e));

    assert_eq!(decrypted.as_slice(), plaintext);
}

/// T-INT-2: PERSISTENCE ACROSS REOPEN
/// Create DB → store encrypted secret → drop VaultDatabase
/// → VaultDatabase::open() with same db_key → get_secret() → decrypt → assert match
#[test]
fn persistence_across_reopen() {
    let (keys, _salt) = derive_test_chain();
    let secret_id = "persist-secret";
    let plaintext = b"persistent-value-12345";

    let kek = kdf::derive_kek(&keys.master_key, secret_id)
        .unwrap_or_else(|e| panic!("derive_kek: {:?}", e));

    let tmp = NamedTempFile::new().unwrap_or_else(|e| panic!("tempfile: {:?}", e));

    let (ciphertext, nonce) = crypto::encrypt_secret(&kek, secret_id, plaintext)
        .unwrap_or_else(|e| panic!("encrypt: {:?}", e));

    {
        let db = VaultDatabase::create(tmp.path(), &keys.db_key)
            .unwrap_or_else(|e| panic!("create: {:?}", e));
        db.store_secret(
            secret_id,
            "persist-key",
            &ciphertext,
            &nonce,
            "standard",
            "",
            "2026-02-08",
            None,
            "static",
        )
        .unwrap_or_else(|e| panic!("store: {:?}", e));
    }

    let db =
        VaultDatabase::open(tmp.path(), &keys.db_key).unwrap_or_else(|e| panic!("reopen: {:?}", e));

    let (_id, enc_blob, enc_nonce, _sens, _ts, _domains) = db
        .get_secret("persist-key")
        .unwrap_or_else(|e| panic!("get: {:?}", e));

    let decrypted = crypto::decrypt_secret(&kek, secret_id, &enc_blob, &enc_nonce)
        .unwrap_or_else(|e| panic!("decrypt: {:?}", e));

    assert_eq!(decrypted.as_slice(), plaintext);
}

/// T-INT-3: WRONG DB KEY ON REOPEN
/// Create DB → drop → open with WRONG db_key → assert DatabaseKeyInvalid error
#[test]
fn wrong_db_key_on_reopen() {
    let (keys, _salt) = derive_test_chain();
    let tmp = NamedTempFile::new().unwrap_or_else(|e| panic!("tempfile: {:?}", e));

    {
        let _db = VaultDatabase::create(tmp.path(), &keys.db_key)
            .unwrap_or_else(|e| panic!("create: {:?}", e));
    }

    let wrong_key = vec![0xFFu8; 32];
    let result = VaultDatabase::open(tmp.path(), &wrong_key);
    match result {
        Err(VaultError::DatabaseKeyInvalid) => {}
        Err(other) => panic!(
            "Wrong db_key must return DatabaseKeyInvalid, got: {:?}",
            other
        ),
        Ok(_) => panic!("Expected error, got Ok"),
    }
}

/// T-INT-4: CROSS-SECRET ISOLATION
/// Store secret-A with KEK-A, store secret-B with KEK-B
/// Decrypt each with its own KEK → succeeds
/// Cross-decrypt with wrong KEK → FAILS
/// Cross-decrypt with wrong secret_id in AAD → FAILS
#[test]
fn cross_secret_isolation() {
    let (keys, _salt) = derive_test_chain();

    let kek_a =
        kdf::derive_kek(&keys.master_key, "secret-A").unwrap_or_else(|e| panic!("kek_a: {:?}", e));
    let kek_b =
        kdf::derive_kek(&keys.master_key, "secret-B").unwrap_or_else(|e| panic!("kek_b: {:?}", e));

    let tmp = NamedTempFile::new().unwrap_or_else(|e| panic!("tempfile: {:?}", e));
    let db = VaultDatabase::create(tmp.path(), &keys.db_key)
        .unwrap_or_else(|e| panic!("create: {:?}", e));

    let (ct_a, nonce_a) = crypto::encrypt_secret(&kek_a, "secret-A", b"value-A")
        .unwrap_or_else(|e| panic!("encrypt A: {:?}", e));
    db.store_secret(
        "secret-A",
        "key-A",
        &ct_a,
        &nonce_a,
        "high",
        "",
        "2026-02-08",
        None,
        "static",
    )
    .unwrap_or_else(|e| panic!("store A: {:?}", e));

    let (ct_b, nonce_b) = crypto::encrypt_secret(&kek_b, "secret-B", b"value-B")
        .unwrap_or_else(|e| panic!("encrypt B: {:?}", e));
    db.store_secret(
        "secret-B",
        "key-B",
        &ct_b,
        &nonce_b,
        "standard",
        "",
        "2026-02-08",
        None,
        "static",
    )
    .unwrap_or_else(|e| panic!("store B: {:?}", e));

    let (_, blob_a, n_a, _, _, _) = db
        .get_secret("key-A")
        .unwrap_or_else(|e| panic!("get A: {:?}", e));
    let dec_a = crypto::decrypt_secret(&kek_a, "secret-A", &blob_a, &n_a)
        .unwrap_or_else(|e| panic!("decrypt A: {:?}", e));
    assert_eq!(dec_a.as_slice(), b"value-A");

    let (_, blob_b, n_b, _, _, _) = db
        .get_secret("key-B")
        .unwrap_or_else(|e| panic!("get B: {:?}", e));
    let dec_b = crypto::decrypt_secret(&kek_b, "secret-B", &blob_b, &n_b)
        .unwrap_or_else(|e| panic!("decrypt B: {:?}", e));
    assert_eq!(dec_b.as_slice(), b"value-B");

    let result = crypto::decrypt_secret(&kek_b, "secret-A", &blob_a, &n_a);
    assert!(result.is_err(), "Decrypting A with KEK-B must fail");

    let result = crypto::decrypt_secret(&kek_a, "secret-B", &blob_a, &n_a);
    assert!(
        result.is_err(),
        "Decrypting A with wrong AAD must fail — proves binding"
    );
}

/// T-INT-5: TAMPER DETECTION AT REST
/// Store encrypted secret → flip byte in ciphertext
/// → decrypt_secret() → GCM tag failure → Crypto error
#[test]
fn tamper_detection_at_rest() {
    let (keys, _salt) = derive_test_chain();
    let secret_id = "tamper-target";

    let kek =
        kdf::derive_kek(&keys.master_key, secret_id).unwrap_or_else(|e| panic!("kek: {:?}", e));

    let tmp = NamedTempFile::new().unwrap_or_else(|e| panic!("tempfile: {:?}", e));
    let db = VaultDatabase::create(tmp.path(), &keys.db_key)
        .unwrap_or_else(|e| panic!("create: {:?}", e));

    let (ct, nonce) = crypto::encrypt_secret(&kek, secret_id, b"tamper-test-value")
        .unwrap_or_else(|e| panic!("encrypt: {:?}", e));

    db.store_secret(
        secret_id,
        "tamper-key",
        &ct,
        &nonce,
        "high",
        "",
        "2026-02-08",
        None,
        "static",
    )
    .unwrap_or_else(|e| panic!("store: {:?}", e));

    let (_, mut enc_blob, enc_nonce, _, _, _) = db
        .get_secret("tamper-key")
        .unwrap_or_else(|e| panic!("get: {:?}", e));

    enc_blob[0] ^= 0xFF;

    let result = crypto::decrypt_secret(&kek, secret_id, &enc_blob, &enc_nonce);
    assert!(result.is_err(), "Tampered ciphertext must fail GCM auth");
}

/// T-INT-6: METADATA ROUNDTRIP VIA DB
/// Create VaultMeta → store_meta() → get_meta() → assert all fields match
#[test]
fn metadata_roundtrip_via_db() {
    let (keys, salt) = derive_test_chain();

    let tmp = NamedTempFile::new().unwrap_or_else(|e| panic!("tempfile: {:?}", e));
    let db = VaultDatabase::create(tmp.path(), &keys.db_key)
        .unwrap_or_else(|e| panic!("create: {:?}", e));

    let meta = VaultMeta::new_software(&salt, &keys.verifier, 262144, 4, 2);
    db.store_meta(&meta)
        .unwrap_or_else(|e| panic!("store_meta: {:?}", e));

    let loaded = db
        .get_meta()
        .unwrap_or_else(|e| panic!("get_meta: {:?}", e));

    assert_eq!(loaded.mode, "software");
    assert_eq!(loaded.vault_salt, hex::encode(salt));
    assert_eq!(loaded.argon2_m, 262144);
    assert_eq!(loaded.argon2_t, 4);
    assert_eq!(loaded.argon2_p, 2);
    assert!(!loaded.device_key_enrolled);
    assert!(loaded.wrapped_master_key.is_none());
    assert!(loaded.wrap_nonce.is_none());
    assert!(!loaded.biometric_enrolled);
    assert_eq!(loaded.passphrase_verifier, hex::encode(&*keys.verifier));
    assert_eq!(loaded.version, "1.3.0a");
}
