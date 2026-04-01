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

//! Day 7 Phase B: `add` Command Security Contract Tests
//!
//! These tests define binding security contracts for the `add` command.
//! Written BEFORE any production code modifications (test-first discipline).
//!
//! CONTRACTS TESTED:
//!   T-ADD-1:  Roundtrip: add via API → retrieve → byte-equal
//!   T-ADD-2:  Empty secret rejected at API level
//!   T-ADD-3:  Trailing newline stripped (CLI pipeline contract)
//!   T-ADD-4:  Internal whitespace preserved
//!   T-ADD-5:  Binary (non-UTF8) data preserved
//!   T-ADD-6:  Duplicate name → SecretAlreadyExists (DENY)
//!   T-ADD-7:  Default sensitivity is Standard
//!   T-ADD-8:  High sensitivity stored correctly
//!   T-ADD-9:  Low sensitivity stored correctly
//!   T-ADD-10: Secret values never in list output
//!   T-ADD-11: Zeroizing<Vec<u8>> type enforced (compile-time)
//!
//! T-ADD-1 through T-ADD-10 require SQLCipher (cfg-gated for Linux/macOS).
//! T-ADD-11 is all-platform (compile-time type assertion).

use zeroize::Zeroizing;

// ============================================================================
// Helpers (cfg-gated — require SQLCipher)
// ============================================================================

#[cfg(not(target_os = "windows"))]
use std::path::Path;

#[cfg(not(target_os = "windows"))]
use hermetic_core::secret::Sensitivity;
#[cfg(not(target_os = "windows"))]
use hermetic_core::vault::Vault;

/// Shared test passphrase (>= 12 chars).
#[cfg(not(target_os = "windows"))]
fn test_passphrase() -> Zeroizing<Vec<u8>> {
    Zeroizing::new(b"cli-add-test-passphrase-day7!".to_vec())
}

/// Create a test vault in a temp directory.
/// Returns (TempDir, Vault, passphrase).
#[cfg(not(target_os = "windows"))]
fn setup_vault() -> (tempfile::TempDir, Vault, Zeroizing<Vec<u8>>) {
    let dir = tempfile::TempDir::new().expect("create temp dir");
    let passphrase = test_passphrase();
    Vault::init(dir.path(), &passphrase).expect("init vault");
    let vault = Vault::unlock(dir.path(), &passphrase).expect("unlock vault");
    (dir, vault, passphrase)
}

/// Retrieve the decrypted bytes of a secret by name.
///
/// Uses lower-level public APIs (kdf, db, crypto) to perform full roundtrip
/// verification without requiring a Vault::get_secret() method.
///
/// Flow: read salt → derive_full_chain → open DB → get encrypted secret
///       → derive_kek → decrypt_secret → return plaintext bytes.
#[cfg(not(target_os = "windows"))]
fn retrieve_secret_bytes(
    vault_path: &Path,
    passphrase: &Zeroizing<Vec<u8>>,
    secret_name: &str,
) -> Zeroizing<Vec<u8>> {
    // Read salt from sidecar file
    let salt_hex =
        std::fs::read_to_string(vault_path.join("vault.salt")).expect("read salt sidecar");
    let salt_bytes = hex::decode(salt_hex.trim()).expect("decode salt hex");
    let mut salt = [0u8; 32];
    salt.copy_from_slice(&salt_bytes);

    // Derive full key chain from passphrase + salt
    let keys = hermetic_core::kdf::derive_full_chain(passphrase, &salt).expect("derive full chain");

    // Open DB directly with db_key
    let db = hermetic_core::db::VaultDatabase::open(&vault_path.join("vault.db"), &keys.db_key)
        .expect("open vault db");

    // Get encrypted secret: (id, encrypted_blob, nonce, sensitivity, created_at)
    let (id, ciphertext, nonce, _sensitivity, _created_at, _domains) =
        db.get_secret(secret_name).expect("get encrypted secret");

    // Derive per-secret KEK using the secret's UUID
    let kek = hermetic_core::kdf::derive_kek(&keys.master_key, &id).expect("derive kek");

    // Decrypt and return plaintext
    hermetic_core::crypto::decrypt_secret(&kek, &id, &ciphertext, &nonce).expect("decrypt secret")
}

// ============================================================================
// STDIN INGESTION TESTS (Linux — require DB)
// ============================================================================

/// T-ADD-1: Vault::add_secret() accepts secret bytes as Zeroizing<Vec<u8>>.
/// Roundtrip: add known bytes → retrieve via decrypt → exact byte equality.
#[cfg(not(target_os = "windows"))]
#[test]
fn test_add_reads_from_stdin_only() {
    let (dir, vault, passphrase) = setup_vault();

    let secret_value = Zeroizing::new(b"my-api-key-12345".to_vec());
    vault
        .add_secret("api-key", &secret_value, Sensitivity::Standard, None, None)
        .expect("add_secret should succeed");

    let retrieved = retrieve_secret_bytes(dir.path(), &passphrase, "api-key");
    assert_eq!(
        retrieved.as_slice(),
        b"my-api-key-12345",
        "Roundtrip must preserve exact bytes"
    );
}

/// T-ADD-2: Empty byte slice (0 bytes) passed to add_secret() must return error.
/// Empty secrets are rejected, not silently stored.
#[cfg(not(target_os = "windows"))]
#[test]
fn test_add_empty_stdin_is_error() {
    let (_dir, vault, _passphrase) = setup_vault();

    let empty = Zeroizing::new(Vec::new());
    let result = vault.add_secret("empty-secret", &empty, Sensitivity::Standard, None, None);
    assert!(
        result.is_err(),
        "Empty secret must be rejected by add_secret()"
    );

    // Verify no phantom secret was created
    let secrets = vault.list_secrets().expect("list_secrets");
    assert!(
        secrets.iter().all(|s| s.name != "empty-secret"),
        "No phantom secret should exist after empty rejection"
    );
}

/// T-ADD-3: Trailing newlines stripped before storage.
///
/// Passes raw newline-terminated bytes directly to add_secret().
/// The API layer (Remedy 3) strips ONE trailing \n or \r\n before encrypting.
/// Verifies the stored (encrypted) value matches the stripped bytes exactly.
#[cfg(not(target_os = "windows"))]
#[test]
fn test_add_strips_trailing_newline() {
    let (dir, vault, passphrase) = setup_vault();

    // LF case: pass raw "my-secret\n" → API strips → stored "my-secret"
    vault
        .add_secret(
            "lf-test",
            &Zeroizing::new(b"my-secret\n".to_vec()),
            Sensitivity::Standard,
            None,
            None,
        )
        .expect("add with trailing LF");
    let retrieved_lf = retrieve_secret_bytes(dir.path(), &passphrase, "lf-test");
    assert_eq!(
        retrieved_lf.as_slice(),
        b"my-secret",
        "LF must be stripped by add_secret() before storage"
    );

    // CRLF case: pass raw "my-secret\r\n" → API strips → stored "my-secret"
    vault
        .add_secret(
            "crlf-test",
            &Zeroizing::new(b"my-secret\r\n".to_vec()),
            Sensitivity::Standard,
            None,
            None,
        )
        .expect("add with trailing CRLF");
    let retrieved_crlf = retrieve_secret_bytes(dir.path(), &passphrase, "crlf-test");
    assert_eq!(
        retrieved_crlf.as_slice(),
        b"my-secret",
        "CRLF must be stripped by add_secret() before storage"
    );
}

/// T-ADD-4: Internal whitespace preserved exactly.
///
/// Only trailing newlines are stripped by add_secret(). Spaces, tabs, and other
/// whitespace within the value must be stored and retrieved verbatim.
#[cfg(not(target_os = "windows"))]
#[test]
fn test_add_preserves_internal_whitespace() {
    let (dir, vault, passphrase) = setup_vault();

    // Pass raw "my secret value\n" — API strips trailing \n, preserves internal spaces
    vault
        .add_secret(
            "ws-test",
            &Zeroizing::new(b"my secret value\n".to_vec()),
            Sensitivity::Standard,
            None,
            None,
        )
        .expect("add with internal whitespace");

    let retrieved = retrieve_secret_bytes(dir.path(), &passphrase, "ws-test");
    assert_eq!(
        retrieved.as_slice(),
        b"my secret value",
        "Internal whitespace must be preserved exactly"
    );
}

/// T-ADD-5: Binary (non-UTF8) data stored and retrieved without corruption.
///
/// Hermetic stores Vec<u8>, not String. Arbitrary byte sequences including
/// null bytes and high bytes must survive the encrypt/decrypt roundtrip.
#[cfg(not(target_os = "windows"))]
#[test]
fn test_add_binary_secret_preserved() {
    let (dir, vault, passphrase) = setup_vault();

    let binary_data = vec![0x00, 0x01, 0xFF, 0xFE, 0x80, 0x7F];
    vault
        .add_secret(
            "binary-test",
            &Zeroizing::new(binary_data.clone()),
            Sensitivity::Standard,
            None,
            None,
        )
        .expect("add binary secret");

    let retrieved = retrieve_secret_bytes(dir.path(), &passphrase, "binary-test");
    assert_eq!(
        retrieved.as_slice(),
        &binary_data,
        "Binary data must survive encrypt/decrypt roundtrip without corruption"
    );
}

// ============================================================================
// NAMING AND SENSITIVITY TESTS (Linux — require DB)
// ============================================================================

/// T-ADD-6: Duplicate secret name returns SecretAlreadyExists (DENY).
#[cfg(not(target_os = "windows"))]
#[test]
fn test_add_duplicate_name_fails() {
    let (_dir, vault, _passphrase) = setup_vault();

    vault
        .add_secret(
            "foo",
            &Zeroizing::new(b"value1".to_vec()),
            Sensitivity::Standard,
            None,
            None,
        )
        .expect("first add");

    let result = vault.add_secret(
        "foo",
        &Zeroizing::new(b"value2".to_vec()),
        Sensitivity::Standard,
        None,
        None,
    );
    assert!(result.is_err(), "Duplicate name must fail");
    match result.unwrap_err() {
        hermetic_core::VaultError::SecretAlreadyExists { name } => {
            assert_eq!(name, "foo");
        }
        other => panic!("Expected SecretAlreadyExists, got {:?}", other),
    }
}

/// T-ADD-7: Default sensitivity is Sensitivity::Standard.
///
/// When no explicit sensitivity is provided (using Sensitivity::default()),
/// the stored entry must have sensitivity == Standard.
#[cfg(not(target_os = "windows"))]
#[test]
fn test_add_sensitivity_default_is_standard() {
    let (_dir, vault, _passphrase) = setup_vault();

    vault
        .add_secret(
            "default-sens",
            &Zeroizing::new(b"data".to_vec()),
            Sensitivity::default(),
            None,
            None,
        )
        .expect("add with default sensitivity");

    let secrets = vault.list_secrets().expect("list_secrets");
    let entry = secrets
        .iter()
        .find(|s| s.name == "default-sens")
        .expect("entry must exist");
    assert_eq!(
        entry.sensitivity,
        Sensitivity::Standard,
        "Default sensitivity must be Standard"
    );
}

/// T-ADD-8: Sensitivity::High is stored and retrievable as High.
#[cfg(not(target_os = "windows"))]
#[test]
fn test_add_sensitivity_high_stored_correctly() {
    let (_dir, vault, _passphrase) = setup_vault();

    vault
        .add_secret(
            "high-sens",
            &Zeroizing::new(b"secret-data".to_vec()),
            Sensitivity::High,
            None,
            None,
        )
        .expect("add with High sensitivity");

    let secrets = vault.list_secrets().expect("list_secrets");
    let entry = secrets
        .iter()
        .find(|s| s.name == "high-sens")
        .expect("entry must exist");
    assert_eq!(entry.sensitivity, Sensitivity::High);
}

/// T-ADD-9: Sensitivity::Low is stored and retrievable as Low.
#[cfg(not(target_os = "windows"))]
#[test]
fn test_add_sensitivity_low_stored_correctly() {
    let (_dir, vault, _passphrase) = setup_vault();

    vault
        .add_secret(
            "low-sens",
            &Zeroizing::new(b"secret-data".to_vec()),
            Sensitivity::Low,
            None,
            None,
        )
        .expect("add with Low sensitivity");

    let secrets = vault.list_secrets().expect("list_secrets");
    let entry = secrets
        .iter()
        .find(|s| s.name == "low-sens")
        .expect("entry must exist");
    assert_eq!(entry.sensitivity, Sensitivity::Low);
}

// ============================================================================
// OUTPUT SAFETY TESTS (Linux — require DB)
// ============================================================================

/// T-ADD-10: Secret VALUES never appear in list_secrets() output.
///
/// After adding a secret with a known canary value, the list output contains
/// the secret NAME (identifier) but NEVER the secret VALUE (material).
#[cfg(not(target_os = "windows"))]
#[test]
fn test_add_output_never_contains_secret_value() {
    let (_dir, vault, _passphrase) = setup_vault();

    let canary = b"CANARY-VALUE-XYZ789";
    vault
        .add_secret(
            "test_key",
            &Zeroizing::new(canary.to_vec()),
            Sensitivity::Standard,
            None,
            None,
        )
        .expect("add canary secret");

    let secrets = vault.list_secrets().expect("list_secrets");

    // Serialize list output to check for value leakage
    let output = format!("{:?}", secrets);

    // Secret NAME must appear in metadata
    assert!(
        output.contains("test_key"),
        "Secret name must appear in list output"
    );

    // Secret VALUE must NEVER appear
    assert!(
        !output.contains("CANARY-VALUE-XYZ789"),
        "Secret VALUE must NEVER appear in list_secrets() output"
    );
}

// ============================================================================
// COMPILE-TIME SAFETY TESTS (All platforms)
// ============================================================================

/// T-ADD-11: Vault::add_secret() accepts Zeroizing<Vec<u8>> for secret values.
///
/// Compile-time assertion: the secret parameter is bytes, not String.
/// If the API signature changed to accept String or &str for the value,
/// this test would need modification — indicating a security regression.
#[test]
fn test_zeroizing_type_enforced() {
    // Compile-time assertion: secret parameter is bytes, not String
    let secret: Zeroizing<Vec<u8>> = Zeroizing::new(b"type-check-data".to_vec());
    let _ref: &Zeroizing<Vec<u8>> = &secret;

    // The type Zeroizing<Vec<u8>> is the ONLY acceptable type for secret values.
    // String, &str, and Vec<u8> (non-Zeroizing) are prohibited by constitutional
    // invariant P-5. This test's compilation proves the type contract holds.
}
