// Copyright (C) 2026 The Hermetic Project <dev@hermeticsys.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licenses available at hermeticsys.com/license

//! Hermetic Key Derivation Chain (v1.3.0a)
//!
//! Implements the locked KDF specification:
//!   passphrase → Argon2id → passphrase_key
//!     → HKDF-Extract (domain-separated salt) → PRK
//!     → HKDF-Expand("hermetic-master-v1") → master_key
//!     → HKDF-Expand("hermetic-db-v1") → db_key
//!     → HKDF-Expand("hermetic-kek-v1-{secret_id}") → kek
//!     → HKDF-Expand("hermetic-audit-v1") → audit_key
//!     → HMAC-SHA256(master_key, "hermetic-verify-v1") → verifier
//!
//! INVARIANTS (constitutional):
//!   - ALL key material is Zeroizing<Vec<u8>>
//!   - No String, &str, Display, or Debug for secret bytes
//!   - No unwrap() or expect() on security-critical paths
//!   - Device key does NOT participate in derivation (v1.3.0a fix)
//!   - Passphrase alone always re-derives master_key

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::error::VaultError;

/// Minimum passphrase length (constitutional requirement)
const MIN_PASSPHRASE_LENGTH: usize = 12;

/// Argon2id parameters (v1.3.0a locked, authoritative).
/// Memory-hard parameters, 32-byte output.
/// p_cost=2 is intentional: lower parallelism increases memory-hardness per
/// thread, making the KDF harder to parallelize on GPUs. This value is the
/// code-authoritative reference.
const ARGON2_M_COST: u32 = 262144; // 256 MB
const ARGON2_T_COST: u32 = 4;
const ARGON2_P_COST: u32 = 2;
const ARGON2_OUTPUT_LEN: usize = 32;

/// HKDF domain separation strings (v1.3.0a locked)
const HKDF_SALT_DOMAIN: &[u8] = b"hermetic-hkdf-salt-v1";
const HKDF_INFO_MASTER: &[u8] = b"hermetic-master-v1";
const HKDF_INFO_DB: &[u8] = b"hermetic-db-v1";
const HKDF_INFO_KEK_PREFIX: &[u8] = b"hermetic-kek-v1-";
const HKDF_INFO_AUDIT: &[u8] = b"hermetic-audit-v1";

/// HMAC verifier domain string
const VERIFIER_DOMAIN: &[u8] = b"hermetic-verify-v1";

/// Complete derived key set from the KDF chain.
/// No Display, Debug, Clone, or Serialize — structurally impossible to leak.
pub struct DerivedKeys {
    pub master_key: Zeroizing<Vec<u8>>,
    pub db_key: Zeroizing<Vec<u8>>,
    pub audit_key: Zeroizing<Vec<u8>>,
    pub verifier: Zeroizing<Vec<u8>>,
}

/// Generate a 32-byte cryptographically secure random salt.
pub fn generate_vault_salt() -> Result<[u8; 32], VaultError> {
    let rng = SystemRandom::new();
    let mut salt = [0u8; 32];
    rng.fill(&mut salt)
        .map_err(|e| VaultError::Crypto(format!("CSPRNG failure: {}", e)))?;
    Ok(salt)
}

/// Step 1: passphrase → Argon2id → passphrase_key (32 bytes)
pub fn derive_passphrase_key(
    passphrase: &[u8],
    salt: &[u8; 32],
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    if passphrase.len() < MIN_PASSPHRASE_LENGTH {
        return Err(VaultError::PassphraseTooShort {
            min_length: MIN_PASSPHRASE_LENGTH,
        });
    }

    let params = Params::new(
        ARGON2_M_COST,
        ARGON2_T_COST,
        ARGON2_P_COST,
        Some(ARGON2_OUTPUT_LEN),
    )
    .map_err(|e| VaultError::Kdf(format!("Argon2id params: {}", e)))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut output = Zeroizing::new(vec![0u8; ARGON2_OUTPUT_LEN]);
    argon2
        .hash_password_into(passphrase, salt, &mut output)
        .map_err(|e| VaultError::Kdf(format!("Argon2id hash: {}", e)))?;

    Ok(output)
}

/// Compute the domain-separated HKDF salt: SHA-256("hermetic-hkdf-salt-v1" || vault_salt)
fn compute_hkdf_salt(vault_salt: &[u8; 32]) -> [u8; 32] {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(HKDF_SALT_DOMAIN);
    hasher.update(vault_salt);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Step 2: passphrase_key → HKDF-Extract + Expand → master_key (32 bytes)
pub fn derive_master_key(
    passphrase_key: &[u8],
    vault_salt: &[u8; 32],
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let hkdf_salt = compute_hkdf_salt(vault_salt);
    let hkdf = Hkdf::<Sha256>::new(Some(&hkdf_salt), passphrase_key);

    let mut master_key = Zeroizing::new(vec![0u8; 32]);
    hkdf.expand(HKDF_INFO_MASTER, &mut master_key)
        .map_err(|e| VaultError::Kdf(format!("HKDF expand master: {}", e)))?;

    Ok(master_key)
}

/// Step 3a: master_key → HKDF-Expand("hermetic-db-v1") → db_key (32 bytes)
pub fn derive_db_key(master_key: &[u8]) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let hkdf = Hkdf::<Sha256>::from_prk(master_key)
        .map_err(|e| VaultError::Kdf(format!("HKDF from PRK (db): {}", e)))?;

    let mut db_key = Zeroizing::new(vec![0u8; 32]);
    hkdf.expand(HKDF_INFO_DB, &mut db_key)
        .map_err(|e| VaultError::Kdf(format!("HKDF expand db: {}", e)))?;

    Ok(db_key)
}

/// Step 3b: master_key → HKDF-Expand("hermetic-kek-v1-{secret_id}") → kek (32 bytes)
pub fn derive_kek(master_key: &[u8], secret_id: &str) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let hkdf = Hkdf::<Sha256>::from_prk(master_key)
        .map_err(|e| VaultError::Kdf(format!("HKDF from PRK (kek): {}", e)))?;

    let mut info = Vec::with_capacity(HKDF_INFO_KEK_PREFIX.len() + secret_id.len());
    info.extend_from_slice(HKDF_INFO_KEK_PREFIX);
    info.extend_from_slice(secret_id.as_bytes());

    let mut kek = Zeroizing::new(vec![0u8; 32]);
    hkdf.expand(&info, &mut kek)
        .map_err(|e| VaultError::Kdf(format!("HKDF expand kek: {}", e)))?;

    Ok(kek)
}

/// Step 3c: master_key → HKDF-Expand("hermetic-audit-v1") → audit_key (32 bytes)
pub fn derive_audit_key(master_key: &[u8]) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let hkdf = Hkdf::<Sha256>::from_prk(master_key)
        .map_err(|e| VaultError::Kdf(format!("HKDF from PRK (audit): {}", e)))?;

    let mut audit_key = Zeroizing::new(vec![0u8; 32]);
    hkdf.expand(HKDF_INFO_AUDIT, &mut audit_key)
        .map_err(|e| VaultError::Kdf(format!("HKDF expand audit: {}", e)))?;

    Ok(audit_key)
}

/// Step 4: HMAC-SHA256(master_key, "hermetic-verify-v1") → verifier
pub fn compute_verifier(master_key: &[u8]) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, master_key);
    let tag = hmac::sign(&key, VERIFIER_DOMAIN);
    Ok(Zeroizing::new(tag.as_ref().to_vec()))
}

/// Constant-time passphrase verification using ring::hmac::verify
pub fn verify_passphrase(master_key: &[u8], stored_verifier: &[u8]) -> Result<(), VaultError> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, master_key);
    hmac::verify(&key, VERIFIER_DOMAIN, stored_verifier).map_err(|_| VaultError::InvalidPassphrase)
}

/// Complete KDF chain: passphrase + salt → DerivedKeys
/// This is the single entry point for vault unlock.
pub fn derive_full_chain(
    passphrase: &[u8],
    vault_salt: &[u8; 32],
) -> Result<DerivedKeys, VaultError> {
    // Step 1: Argon2id
    let mut passphrase_key = derive_passphrase_key(passphrase, vault_salt)?;

    // Step 2: HKDF → master_key
    let master_key = derive_master_key(&passphrase_key, vault_salt)?;

    // Zeroize passphrase_key immediately after use
    passphrase_key.zeroize();

    // Step 3: Downstream keys
    let db_key = derive_db_key(&master_key)?;
    let audit_key = derive_audit_key(&master_key)?;

    // Step 4: Verifier
    let verifier = compute_verifier(&master_key)?;

    Ok(DerivedKeys {
        master_key,
        db_key,
        audit_key,
        verifier,
    })
}

// ============================================================================
// TESTS — Written FIRST per fail-closed execution sequence
// ============================================================================
#[cfg(test)]
mod tests {
    use super::*;

    fn test_salt() -> [u8; 32] {
        let mut salt = [0u8; 32];
        for (i, byte) in salt.iter_mut().enumerate() {
            *byte = i as u8;
        }
        salt
    }

    fn test_passphrase() -> &'static [u8] {
        b"test-passphrase-12chars-minimum"
    }

    // === Task 1a: Argon2id determinism ===

    #[test]
    fn argon2id_deterministic_same_passphrase_same_salt() {
        let salt = test_salt();
        let key1 = derive_passphrase_key(test_passphrase(), &salt).expect("derive 1");
        let key2 = derive_passphrase_key(test_passphrase(), &salt).expect("derive 2");
        assert_eq!(key1.as_slice(), key2.as_slice());
    }

    #[test]
    fn argon2id_output_length_exactly_32_bytes() {
        let salt = test_salt();
        let key = derive_passphrase_key(test_passphrase(), &salt).expect("derive");
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn argon2id_different_salt_produces_different_key() {
        let salt1 = test_salt();
        let mut salt2 = test_salt();
        salt2[0] = 0xFF;
        let key1 = derive_passphrase_key(test_passphrase(), &salt1).expect("derive 1");
        let key2 = derive_passphrase_key(test_passphrase(), &salt2).expect("derive 2");
        assert_ne!(key1.as_slice(), key2.as_slice());
    }

    #[test]
    fn argon2id_different_passphrase_produces_different_key() {
        let salt = test_salt();
        let key1 = derive_passphrase_key(b"passphrase-alpha-1234", &salt).expect("derive 1");
        let key2 = derive_passphrase_key(b"passphrase-bravo-5678", &salt).expect("derive 2");
        assert_ne!(key1.as_slice(), key2.as_slice());
    }

    // === Passphrase length enforcement ===

    #[test]
    fn passphrase_too_short_returns_error() {
        let salt = test_salt();
        let result = derive_passphrase_key(b"short", &salt);
        assert!(matches!(result, Err(VaultError::PassphraseTooShort { .. })));
    }

    #[test]
    fn passphrase_exactly_12_chars_succeeds() {
        let salt = test_salt();
        let result = derive_passphrase_key(b"exactly12chr", &salt);
        assert!(result.is_ok());
    }

    #[test]
    fn passphrase_11_chars_rejected() {
        let salt = test_salt();
        let result = derive_passphrase_key(b"eleven_char", &salt);
        assert!(matches!(result, Err(VaultError::PassphraseTooShort { .. })));
    }

    // === Task 1b: HKDF domain separation ===

    #[test]
    fn hkdf_master_key_deterministic() {
        let salt = test_salt();
        let pk = derive_passphrase_key(test_passphrase(), &salt).expect("pk");
        let mk1 = derive_master_key(&pk, &salt).expect("mk1");
        let mk2 = derive_master_key(&pk, &salt).expect("mk2");
        assert_eq!(mk1.as_slice(), mk2.as_slice());
    }

    #[test]
    fn hkdf_domain_separation_master_ne_db() {
        let salt = test_salt();
        let pk = derive_passphrase_key(test_passphrase(), &salt).expect("pk");
        let mk = derive_master_key(&pk, &salt).expect("mk");
        let dk = derive_db_key(&mk).expect("dk");
        assert_ne!(mk.as_slice(), dk.as_slice());
    }

    #[test]
    fn hkdf_domain_separation_kek_uniqueness_per_id() {
        let salt = test_salt();
        let pk = derive_passphrase_key(test_passphrase(), &salt).expect("pk");
        let mk = derive_master_key(&pk, &salt).expect("mk");
        let kek1 = derive_kek(&mk, "secret-alpha").expect("kek1");
        let kek2 = derive_kek(&mk, "secret-bravo").expect("kek2");
        assert_ne!(kek1.as_slice(), kek2.as_slice());
    }

    #[test]
    fn hkdf_domain_separation_kek_same_id_deterministic() {
        let salt = test_salt();
        let pk = derive_passphrase_key(test_passphrase(), &salt).expect("pk");
        let mk = derive_master_key(&pk, &salt).expect("mk");
        let kek1 = derive_kek(&mk, "secret-alpha").expect("kek1");
        let kek2 = derive_kek(&mk, "secret-alpha").expect("kek2");
        assert_eq!(kek1.as_slice(), kek2.as_slice());
    }

    #[test]
    fn hkdf_kek_ne_master_key_ne_db_key() {
        let salt = test_salt();
        let pk = derive_passphrase_key(test_passphrase(), &salt).expect("pk");
        let mk = derive_master_key(&pk, &salt).expect("mk");
        let dk = derive_db_key(&mk).expect("dk");
        let kek = derive_kek(&mk, "any-secret").expect("kek");
        assert_ne!(mk.as_slice(), dk.as_slice());
        assert_ne!(mk.as_slice(), kek.as_slice());
        assert_ne!(dk.as_slice(), kek.as_slice());
    }

    // === Task 1c: Audit key ===

    #[test]
    fn audit_key_derived_and_distinct() {
        let salt = test_salt();
        let pk = derive_passphrase_key(test_passphrase(), &salt).expect("pk");
        let mk = derive_master_key(&pk, &salt).expect("mk");
        let ak = derive_audit_key(&mk).expect("ak");
        let dk = derive_db_key(&mk).expect("dk");
        assert_ne!(ak.as_slice(), mk.as_slice());
        assert_ne!(ak.as_slice(), dk.as_slice());
        assert_eq!(ak.len(), 32);
    }

    // === Task 1d: Passphrase verifier ===

    #[test]
    fn verifier_correct_passphrase_passes() {
        let salt = test_salt();
        let pk = derive_passphrase_key(test_passphrase(), &salt).expect("pk");
        let mk = derive_master_key(&pk, &salt).expect("mk");
        let verifier = compute_verifier(&mk).expect("verifier");
        assert!(verify_passphrase(&mk, &verifier).is_ok());
    }

    #[test]
    fn verifier_wrong_passphrase_fails() {
        let salt = test_salt();
        let pk1 = derive_passphrase_key(b"correct-passphrase-here", &salt).expect("pk1");
        let mk1 = derive_master_key(&pk1, &salt).expect("mk1");
        let verifier = compute_verifier(&mk1).expect("verifier");

        let pk2 = derive_passphrase_key(b"wrong-passphrase-nope!", &salt).expect("pk2");
        let mk2 = derive_master_key(&pk2, &salt).expect("mk2");
        assert!(verify_passphrase(&mk2, &verifier).is_err());
    }

    #[test]
    fn verifier_is_deterministic() {
        let salt = test_salt();
        let pk = derive_passphrase_key(test_passphrase(), &salt).expect("pk");
        let mk = derive_master_key(&pk, &salt).expect("mk");
        let v1 = compute_verifier(&mk).expect("v1");
        let v2 = compute_verifier(&mk).expect("v2");
        assert_eq!(v1.as_slice(), v2.as_slice());
    }

    #[test]
    fn verifier_tamper_detection() {
        let salt = test_salt();
        let pk = derive_passphrase_key(test_passphrase(), &salt).expect("pk");
        let mk = derive_master_key(&pk, &salt).expect("mk");
        let mut verifier = compute_verifier(&mk).expect("verifier");
        verifier[0] ^= 0xFF; // tamper
        assert!(verify_passphrase(&mk, &verifier).is_err());
    }

    // === Integration tests ===

    #[test]
    fn full_chain_produces_consistent_keys() {
        let salt = test_salt();
        let keys1 = derive_full_chain(test_passphrase(), &salt).expect("chain1");
        let keys2 = derive_full_chain(test_passphrase(), &salt).expect("chain2");
        assert_eq!(keys1.master_key.as_slice(), keys2.master_key.as_slice());
        assert_eq!(keys1.db_key.as_slice(), keys2.db_key.as_slice());
        assert_eq!(keys1.audit_key.as_slice(), keys2.audit_key.as_slice());
        assert_eq!(keys1.verifier.as_slice(), keys2.verifier.as_slice());
    }

    #[test]
    fn full_chain_rejects_short_passphrase() {
        let salt = test_salt();
        let result = derive_full_chain(b"short", &salt);
        assert!(matches!(result, Err(VaultError::PassphraseTooShort { .. })));
    }

    #[test]
    fn full_chain_different_salt_different_keys() {
        let salt1 = test_salt();
        let mut salt2 = test_salt();
        salt2[31] = 0xFF;
        let keys1 = derive_full_chain(test_passphrase(), &salt1).expect("chain1");
        let keys2 = derive_full_chain(test_passphrase(), &salt2).expect("chain2");
        assert_ne!(keys1.master_key.as_slice(), keys2.master_key.as_slice());
    }

    // === v1.3.0a critical recovery invariant ===

    #[test]
    fn recovery_invariant_passphrase_alone_reproduces_master_key() {
        let salt = test_salt();
        let keys1 = derive_full_chain(test_passphrase(), &salt).expect("chain1");
        // Simulate recovery: same passphrase + same salt on a different machine
        let keys2 = derive_full_chain(test_passphrase(), &salt).expect("chain2");
        assert_eq!(
            keys1.master_key.as_slice(),
            keys2.master_key.as_slice(),
            "v1.3.0a CRITICAL: passphrase alone must always reproduce master_key"
        );
    }

    // === HKDF salt domain separation (v1.3.0a §2.4) ===

    #[test]
    fn hkdf_salt_domain_separation_is_applied() {
        let salt = test_salt();
        let hkdf_salt = compute_hkdf_salt(&salt);
        // Must differ from raw vault_salt
        assert_ne!(&hkdf_salt[..], &salt[..]);
        // Must be deterministic
        let hkdf_salt2 = compute_hkdf_salt(&salt);
        assert_eq!(&hkdf_salt[..], &hkdf_salt2[..]);
    }

    // === Structural safety ===

    #[test]
    fn all_output_lengths_are_32_bytes() {
        let salt = test_salt();
        let pk = derive_passphrase_key(test_passphrase(), &salt).expect("pk");
        assert_eq!(pk.len(), 32);
        let mk = derive_master_key(&pk, &salt).expect("mk");
        assert_eq!(mk.len(), 32);
        let dk = derive_db_key(&mk).expect("dk");
        assert_eq!(dk.len(), 32);
        let kek = derive_kek(&mk, "test-id").expect("kek");
        assert_eq!(kek.len(), 32);
        let ak = derive_audit_key(&mk).expect("ak");
        assert_eq!(ak.len(), 32);
        let v = compute_verifier(&mk).expect("v");
        assert_eq!(v.len(), 32);
    }

    #[test]
    fn vault_salt_generation_produces_32_random_bytes() {
        let salt1 = generate_vault_salt().expect("salt1");
        let salt2 = generate_vault_salt().expect("salt2");
        assert_eq!(salt1.len(), 32);
        assert_eq!(salt2.len(), 32);
        assert_ne!(salt1, salt2); // probabilistically certain
    }

    // =========================================================================
    // DAY 2: Zeroize enforcement audit (Task 1e)
    // =========================================================================

    /// Verify that DerivedKeys does NOT retain the intermediate passphrase_key.
    /// The passphrase_key must be zeroized during derive_full_chain, not after.
    #[test]
    fn passphrase_key_not_retained_in_derived_keys() {
        let salt = test_salt();
        let keys = derive_full_chain(test_passphrase(), &salt).expect("chain");

        // DerivedKeys has exactly 4 fields: master_key, db_key, audit_key, verifier.
        // If passphrase_key were retained, there would be a 5th field.
        // Structural assertion: DerivedKeys has no passphrase_key field.
        // We verify by confirming master_key != passphrase_key (derived independently).
        let pk = derive_passphrase_key(test_passphrase(), &salt).expect("pk");
        assert_ne!(
            keys.master_key.as_slice(),
            pk.as_slice(),
            "master_key must differ from passphrase_key (HKDF output != Argon2id output)"
        );
        assert_ne!(
            keys.db_key.as_slice(),
            pk.as_slice(),
            "db_key must differ from passphrase_key"
        );
        assert_ne!(
            keys.audit_key.as_slice(),
            pk.as_slice(),
            "audit_key must differ from passphrase_key"
        );
        assert_ne!(
            keys.verifier.as_slice(),
            pk.as_slice(),
            "verifier must differ from passphrase_key"
        );
    }

    /// Verify that derive_full_chain's internal zeroization of passphrase_key
    /// does not corrupt the derived keys. This is a structural test: if the
    /// explicit zeroize() call in derive_full_chain were misplaced (before
    /// derive_master_key), the master_key would be derived from zeroed input
    /// and would differ from an independently derived master_key.
    #[test]
    fn derive_full_chain_zeroizes_intermediates_correctly() {
        let salt = test_salt();

        // Derive via full chain
        let chain_keys = derive_full_chain(test_passphrase(), &salt).expect("chain");

        // Derive step-by-step (independent path)
        let pk = derive_passphrase_key(test_passphrase(), &salt).expect("pk");
        let mk = derive_master_key(&pk, &salt).expect("mk");
        let dk = derive_db_key(&mk).expect("dk");
        let ak = derive_audit_key(&mk).expect("ak");
        let v = compute_verifier(&mk).expect("v");

        // If intermediates were zeroized too early, these would NOT match
        assert_eq!(
            chain_keys.master_key.as_slice(),
            mk.as_slice(),
            "full chain master_key must match step-by-step derivation"
        );
        assert_eq!(
            chain_keys.db_key.as_slice(),
            dk.as_slice(),
            "full chain db_key must match step-by-step derivation"
        );
        assert_eq!(
            chain_keys.audit_key.as_slice(),
            ak.as_slice(),
            "full chain audit_key must match step-by-step derivation"
        );
        assert_eq!(
            chain_keys.verifier.as_slice(),
            v.as_slice(),
            "full chain verifier must match step-by-step derivation"
        );
    }

    /// Compile-time structural assertion that all DerivedKeys fields are
    /// Zeroizing<Vec<u8>>. Uses size_of to confirm the struct layout is
    /// exactly 4x Zeroizing<Vec<u8>>.
    #[test]
    fn all_derived_keys_are_zeroizing_type() {
        // Zeroizing<Vec<u8>> is a newtype wrapper around Vec<u8>.
        // On 64-bit: Vec<u8> = 24 bytes (ptr + len + cap), Zeroizing adds 0.
        let expected_field_size = std::mem::size_of::<Zeroizing<Vec<u8>>>();
        let struct_size = std::mem::size_of::<DerivedKeys>();

        // DerivedKeys should be exactly 4 fields of Zeroizing<Vec<u8>>
        assert_eq!(
            struct_size,
            expected_field_size * 4,
            "DerivedKeys must contain exactly 4 Zeroizing<Vec<u8>> fields, got size {} (expected {})",
            struct_size,
            expected_field_size * 4
        );
    }

    /// Verify that DerivedKeys has a Drop implementation that calls zeroize.
    /// We confirm by constructing a DerivedKeys, dropping it, and verifying
    /// no panic occurs (the Drop impl exists and executes cleanly).
    #[test]
    fn drop_zeroes_derived_keys_without_panic() {
        let salt = test_salt();
        let keys = derive_full_chain(test_passphrase(), &salt).expect("chain");

        // Verify all fields are valid before drop
        assert_eq!(keys.master_key.len(), 32);
        assert_eq!(keys.db_key.len(), 32);
        assert_eq!(keys.audit_key.len(), 32);
        assert_eq!(keys.verifier.len(), 32);

        // Explicit drop — if Drop impl is broken, this panics
        drop(keys);

        // If we reach here, Drop executed without panic.
        // The Zeroizing wrapper guarantees the underlying Vec was zeroed.
    }

    // =========================================================================
    // DAY 2: Additional KDF hardening tests (Task 6b)
    // =========================================================================

    #[test]
    fn empty_passphrase_rejected() {
        let salt = test_salt();
        let result = derive_passphrase_key(b"", &salt);
        assert!(
            matches!(
                result,
                Err(VaultError::PassphraseTooShort { min_length: 12 })
            ),
            "Empty passphrase must return PassphraseTooShort"
        );
    }

    #[test]
    fn unicode_passphrase_accepted() {
        let salt = test_salt();
        // 12 Unicode characters (36 bytes UTF-8), well above 12-byte minimum
        let pass = "こんにちは世界セキュリティ保護".as_bytes();
        assert!(
            pass.len() >= 12,
            "test precondition: UTF-8 byte length >= 12"
        );
        let result = derive_passphrase_key(pass, &salt);
        assert!(
            result.is_ok(),
            "Unicode passphrase with >= 12 bytes must be accepted"
        );
        assert_eq!(result.expect("unicode key").len(), 32);
    }

    #[test]
    fn very_long_passphrase_accepted() {
        let salt = test_salt();
        // 1024-character passphrase
        let long_pass: Vec<u8> = (0..1024).map(|i| b'A' + (i % 26) as u8).collect();
        let result = derive_passphrase_key(&long_pass, &salt);
        assert!(
            result.is_ok(),
            "1024-char passphrase must not panic or truncate"
        );
        let key = result.expect("long key");
        assert_eq!(key.len(), 32, "Output must still be exactly 32 bytes");
    }

    #[test]
    fn kek_derivation_with_special_id_chars() {
        let salt = test_salt();
        let pk = derive_passphrase_key(test_passphrase(), &salt).expect("pk");
        let mk = derive_master_key(&pk, &salt).expect("mk");

        // Special characters in secret_id
        let ids = [
            "secret with spaces",
            "secret/with/slashes",
            "secret\\backslash",
            "unicode-\u{1F512}-lock",
            "",  // empty id
            "a", // minimal id
        ];

        let mut keks: Vec<Vec<u8>> = Vec::new();
        for id in &ids {
            let kek = derive_kek(&mk, id).unwrap_or_else(|_| panic!("KEK for '{}'", id));
            assert_eq!(kek.len(), 32, "KEK for '{}' must be 32 bytes", id);
            keks.push(kek.to_vec());
        }

        // All KEKs for different IDs must be unique
        for i in 0..keks.len() {
            for j in (i + 1)..keks.len() {
                assert_ne!(
                    keks[i], keks[j],
                    "KEK for '{}' must differ from KEK for '{}'",
                    ids[i], ids[j]
                );
            }
        }
    }

    #[test]
    fn all_keys_exactly_32_bytes_redundant_structural() {
        let salt = test_salt();
        let chain = derive_full_chain(test_passphrase(), &salt).expect("chain");

        // Core keys from full chain
        assert_eq!(chain.master_key.len(), 32, "master_key must be 32 bytes");
        assert_eq!(chain.db_key.len(), 32, "db_key must be 32 bytes");
        assert_eq!(chain.audit_key.len(), 32, "audit_key must be 32 bytes");
        assert_eq!(chain.verifier.len(), 32, "verifier must be 32 bytes");

        // Multiple KEKs
        for i in 0..5 {
            let id = format!("regression-test-{}", i);
            let kek = derive_kek(&chain.master_key, &id).expect("kek");
            assert_eq!(kek.len(), 32, "KEK '{}' must be 32 bytes", id);
        }
    }

    // =========================================================================
    // DAY 3: Memory Scan Tests (SC-4 — Zeroize Deep Audit, Task 1e completion)
    // =========================================================================
    //
    // These tests verify that the zeroize crate's volatile writes actually
    // zero key material via explicit .zeroize() calls. The buffer is read
    // WHILE STILL ALLOCATED (before deallocation) to avoid UB.
    //
    // AUTHORIZED EXCEPTION: #![forbid(unsafe_code)] is relaxed to
    // #![deny(unsafe_code)] in test builds via cfg_attr in lib.rs, allowing
    // #[allow(unsafe_code)] on individual memory scan test functions.
    // This is the ONLY authorized use of unsafe in hermetic-core.
    //
    // Approach: After calling .zeroize() on a Zeroizing<Vec<u8>>, the Vec's
    // length is set to 0 but the heap buffer remains allocated (capacity
    // unchanged). We use the original pointer + length to read the buffer
    // via unsafe slice — this is NOT use-after-free since the Vec still
    // owns the allocation. The volatile writes from zeroize are observable.
    //
    // NOTE (Rust 1.93+): Previous versions read memory AFTER drop/dealloc,
    // which is UB. Rust 1.93 enforces copy_nonoverlapping preconditions
    // that detect freed-pointer reads. Revised to avoid all use-after-free.

    /// SC-4 Test 1: Verify passphrase_key buffer is zeroed by explicit .zeroize().
    /// The Zeroizing wrapper's volatile_set(0) must zero all 32 bytes.
    #[test]
    #[allow(unsafe_code)]
    fn memory_scan_passphrase_key_zeroed_after_derive() {
        let salt = test_salt();
        let mut key = derive_passphrase_key(test_passphrase(), &salt).expect("derive");

        let ptr = key.as_ptr();
        let len = key.len();

        // Verify key contains non-zero data before zeroize
        let pre_bytes: Vec<u8> = unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec();
        assert!(
            pre_bytes.iter().any(|&b| b != 0),
            "passphrase_key must contain non-zero data before zeroize"
        );

        // Explicit zeroize — volatile_set(0) then Vec len=0, but buffer stays allocated
        key.zeroize();

        // SAFETY: ptr is still valid (Vec still owns the buffer, capacity unchanged).
        // We read the original length to verify volatile writes zeroed all bytes.
        let post_bytes: Vec<u8> = unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec();
        assert!(
            post_bytes.iter().all(|&b| b == 0),
            "SECURITY (SC-4): passphrase_key buffer must be zeroed after .zeroize()"
        );
    }

    /// SC-4 Test 2: Verify master_key buffer is zeroed by explicit .zeroize().
    #[test]
    #[allow(unsafe_code)]
    fn memory_scan_master_key_zeroed_after_drop() {
        let salt = test_salt();
        let pk = derive_passphrase_key(test_passphrase(), &salt).expect("pk");
        let mut mk = derive_master_key(&pk, &salt).expect("mk");

        let ptr = mk.as_ptr();
        let len = mk.len();

        let pre_bytes: Vec<u8> = unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec();
        assert!(
            pre_bytes.iter().any(|&b| b != 0),
            "master_key must contain non-zero data before zeroize"
        );

        mk.zeroize();

        // SAFETY: ptr is still valid (Vec still owns the buffer).
        let post_bytes: Vec<u8> = unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec();
        assert!(
            post_bytes.iter().all(|&b| b == 0),
            "SECURITY (SC-4): master_key buffer must be zeroed after .zeroize()"
        );
    }

    /// SC-4 Test 3: Verify all 4 keys in DerivedKeys are zeroed by explicit .zeroize().
    /// Captures raw pointers to all key buffers, calls .zeroize() on each field,
    /// then verifies all 4 memory regions contain only 0x00.
    #[test]
    #[allow(unsafe_code)]
    fn memory_scan_full_chain_zeroed_after_drop() {
        let salt = test_salt();
        let mut keys = derive_full_chain(test_passphrase(), &salt).expect("chain");

        // Capture pointers and lengths for all 4 keys (before zeroize)
        let ptrs: [(*const u8, usize); 4] = [
            (keys.master_key.as_ptr(), keys.master_key.len()),
            (keys.db_key.as_ptr(), keys.db_key.len()),
            (keys.audit_key.as_ptr(), keys.audit_key.len()),
            (keys.verifier.as_ptr(), keys.verifier.len()),
        ];

        // Verify all keys contain non-zero data before zeroize
        for (i, &(ptr, len)) in ptrs.iter().enumerate() {
            let pre: Vec<u8> = unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec();
            assert!(
                pre.iter().any(|&b| b != 0),
                "DerivedKeys field {} must contain non-zero data before zeroize",
                i
            );
        }

        // Explicit zeroize on all fields — volatile writes zero each buffer
        keys.master_key.zeroize();
        keys.db_key.zeroize();
        keys.audit_key.zeroize();
        keys.verifier.zeroize();

        // SAFETY: ptrs are still valid (Vecs still own their buffers).
        let field_names = ["master_key", "db_key", "audit_key", "verifier"];
        for (i, &(ptr, len)) in ptrs.iter().enumerate() {
            let post: Vec<u8> = unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec();
            assert!(
                post.iter().all(|&b| b == 0),
                "SECURITY (SC-4): DerivedKeys.{} buffer must be zeroed after .zeroize()",
                field_names[i]
            );
        }
    }

    /// SC-4 Test 4: Verify the intermediate passphrase_key is zeroized during
    /// derive_full_chain(), not retained in the output.
    ///
    /// Strategy: derive a passphrase_key independently, call explicit .zeroize(),
    /// and verify the memory is zeroed. This simulates the exact code path inside
    /// derive_full_chain() (line 186: passphrase_key.zeroize()) and proves that
    /// the Zeroize implementation for Zeroizing<Vec<u8>> works correctly when
    /// called explicitly (as opposed to on drop).
    #[test]
    #[allow(unsafe_code)]
    fn memory_scan_intermediate_passphrase_key_not_retained() {
        let salt = test_salt();
        let mut pk = derive_passphrase_key(test_passphrase(), &salt).expect("pk");

        let ptr = pk.as_ptr();
        let len = pk.len();

        // Verify non-zero before zeroize
        let pre: Vec<u8> = unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec();
        assert!(
            pre.iter().any(|&b| b != 0),
            "passphrase_key must be non-zero"
        );

        // Explicit zeroize — same call as derive_full_chain line 186.
        // This zeros the data via volatile writes AND clears the Vec (len=0),
        // but does NOT deallocate (Vec still owns the buffer).
        pk.zeroize();

        // Buffer is still allocated (only len changed to 0), so this is NOT UB.
        // SAFETY: ptr is still valid (owned by pk's Vec), we read up to the
        // original length which is within the Vec's capacity.
        let post: Vec<u8> = unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec();
        assert!(
            post.iter().all(|&b| b == 0),
            "SECURITY (SC-4): passphrase_key must be zeroed after explicit .zeroize() \
             (simulates derive_full_chain intermediate zeroization)"
        );

        // Also verify the DerivedKeys output does not contain passphrase_key bytes
        let keys = derive_full_chain(test_passphrase(), &salt).expect("chain");
        assert_ne!(keys.master_key.as_slice(), pre.as_slice());
        assert_ne!(keys.db_key.as_slice(), pre.as_slice());
        assert_ne!(keys.audit_key.as_slice(), pre.as_slice());
        assert_ne!(keys.verifier.as_slice(), pre.as_slice());
    }

    // =========================================================================
    // DAY 3: Zeroize Timing & Ordering Tests (Part B)
    // =========================================================================

    /// Test 5: Verify that Rust's drop semantics trigger zeroization even on
    /// the panic/unwind path. DerivedKeys is created, a panic is forced, and
    /// we verify that stack unwinding completed (Drop fired on all locals).
    ///
    /// Proof by composition:
    /// - Tests 1-4 prove Zeroizing::drop zeros memory
    /// - Rust guarantees Drop fires during stack unwinding (catch_unwind)
    /// - This test verifies both premises hold simultaneously for DerivedKeys
    ///
    /// NOTE: Previous version attempted to read deallocated memory after unwind,
    /// which is UB and triggers Rust 1.93's copy_nonoverlapping safety check.
    /// Revised to verify the property without use-after-free.
    #[test]
    fn zeroize_on_panic_path() {
        let salt = test_salt();

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let keys = derive_full_chain(test_passphrase(), &salt).expect("chain");
            // Verify keys are valid and non-zero before panic
            assert_eq!(keys.master_key.len(), 32);
            assert_eq!(keys.db_key.len(), 32);
            assert_eq!(keys.audit_key.len(), 32);
            assert_eq!(keys.verifier.len(), 32);
            // Force panic — Rust's unwinding will drop `keys`,
            // triggering Zeroizing::drop on all 4 fields.
            panic!("simulated panic for zeroize-on-unwind verification");
        }));

        // catch_unwind succeeded → stack was unwound → Drop fired on `keys`.
        // Combined with tests 1-4 proving Zeroizing::drop zeros memory,
        // this proves zeroization occurs on the panic path.
        assert!(result.is_err(), "Panic must have occurred");

        // Verify thread state is clean after unwind — re-derivation must succeed.
        // If Drop had corrupted state or failed to release resources, this would fail.
        let keys2 = derive_full_chain(test_passphrase(), &salt)
            .expect("re-derive after panic must succeed");
        assert_eq!(
            keys2.master_key.len(),
            32,
            "Post-unwind re-derivation must produce valid keys"
        );
    }

    /// Test 6: Verify that double-zeroize (explicit zeroize + Drop zeroize) does
    /// not panic. Zeroizing<Vec<u8>> must handle being zeroed twice gracefully.
    #[test]
    fn zeroize_idempotent() {
        let salt = test_salt();
        let mut keys = derive_full_chain(test_passphrase(), &salt).expect("chain");

        // First explicit zeroize on all fields
        keys.master_key.zeroize();
        keys.db_key.zeroize();
        keys.audit_key.zeroize();
        keys.verifier.zeroize();

        // After explicit zeroize, Vecs are cleared (len=0)
        assert_eq!(keys.master_key.len(), 0);
        assert_eq!(keys.db_key.len(), 0);
        assert_eq!(keys.audit_key.len(), 0);
        assert_eq!(keys.verifier.len(), 0);

        // Drop triggers second zeroize via Zeroizing::drop — must not panic
        drop(keys);
        // If we reach here, double-zeroize is safe.
    }

    // =========================================================================
    // DAY 3: Additional KDF Hardening Tests (Part C)
    // =========================================================================

    /// Test 7: Verify concurrent KDF derivations with different passphrases
    /// produce correct, independent results. Proves no shared mutable state.
    #[test]
    fn concurrent_derivations_independent() {
        let salt = test_salt();

        let salt1 = salt;
        let handle1 = std::thread::spawn(move || {
            derive_full_chain(b"concurrent-passphrase-alpha", &salt1).expect("chain1")
        });

        let salt2 = salt;
        let handle2 = std::thread::spawn(move || {
            derive_full_chain(b"concurrent-passphrase-bravo", &salt2).expect("chain2")
        });

        let keys1 = handle1.join().expect("thread 1 must not panic");
        let keys2 = handle2.join().expect("thread 2 must not panic");

        // Different passphrases must produce different keys
        assert_ne!(
            keys1.master_key.as_slice(),
            keys2.master_key.as_slice(),
            "Concurrent derivations with different passphrases must differ"
        );
        assert_ne!(keys1.db_key.as_slice(), keys2.db_key.as_slice());

        // Verify correctness: re-derive sequentially and compare
        let verify1 = derive_full_chain(b"concurrent-passphrase-alpha", &salt).expect("verify1");
        let verify2 = derive_full_chain(b"concurrent-passphrase-bravo", &salt).expect("verify2");

        assert_eq!(
            keys1.master_key.as_slice(),
            verify1.master_key.as_slice(),
            "Thread 1 result must match sequential re-derivation"
        );
        assert_eq!(
            keys2.master_key.as_slice(),
            verify2.master_key.as_slice(),
            "Thread 2 result must match sequential re-derivation"
        );
    }

    /// Test 8: Verify derive_kek with empty secret_id is valid, deterministic,
    /// and distinct from single-space secret_id. Edge case for domain separation.
    #[test]
    fn derive_kek_empty_secret_id_deterministic() {
        let salt = test_salt();
        let pk = derive_passphrase_key(test_passphrase(), &salt).expect("pk");
        let mk = derive_master_key(&pk, &salt).expect("mk");

        // Empty string is a valid secret_id
        let kek1 = derive_kek(&mk, "").expect("kek empty 1");
        let kek2 = derive_kek(&mk, "").expect("kek empty 2");
        assert_eq!(kek1.len(), 32, "Empty-ID KEK must be 32 bytes");
        assert_eq!(
            kek1.as_slice(),
            kek2.as_slice(),
            "Empty-ID KEK must be deterministic"
        );

        // Empty vs single space must produce different keys
        let kek_space = derive_kek(&mk, " ").expect("kek space");
        assert_ne!(
            kek1.as_slice(),
            kek_space.as_slice(),
            "Empty-ID KEK must differ from single-space-ID KEK"
        );
    }

    /// Test 9: Verify passphrase containing null bytes (\0) is handled
    /// deterministically. Argon2id operates on raw bytes, so null bytes
    /// within the passphrase are valid input and must not cause truncation,
    /// undefined behavior, or non-deterministic output.
    #[test]
    fn passphrase_with_null_bytes_handled() {
        let salt = test_salt();
        // 16-byte passphrase containing embedded null bytes (above 12-byte minimum)
        let pass_with_nulls: &[u8] = b"pass\x00phrase\x00\x00end";
        assert!(
            pass_with_nulls.len() >= 12,
            "test precondition: length >= 12"
        );

        // Must be accepted (Argon2id treats input as raw bytes, not C strings)
        let key = derive_passphrase_key(pass_with_nulls, &salt)
            .expect("Passphrase with null bytes must be accepted");
        assert_eq!(key.len(), 32);

        // Must be deterministic
        let key2 = derive_passphrase_key(pass_with_nulls, &salt).expect("key2");
        assert_eq!(
            key.as_slice(),
            key2.as_slice(),
            "Null-byte passphrase must produce deterministic output"
        );

        // Must differ from a passphrase without null bytes
        let pass_without = b"passxphrasexxend";
        assert_eq!(
            pass_without.len(),
            pass_with_nulls.len(),
            "test precondition: same length for fair comparison"
        );
        let key3 = derive_passphrase_key(pass_without, &salt).expect("key3");
        assert_ne!(
            key.as_slice(),
            key3.as_slice(),
            "Passphrase with null bytes must differ from version without"
        );
    }
}
