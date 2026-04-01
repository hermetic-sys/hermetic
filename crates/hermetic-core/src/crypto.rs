// Copyright (C) 2026 The Hermetic Project <dev@hermeticsys.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licenses available at hermeticsys.com/license

//! Hermetic Per-Secret AES-256-GCM Encryption (v1.3.0a)
//!
//! Each secret is encrypted with a unique KEK:
//!   ciphertext = AES-256-GCM(kek(secret_id), plaintext, nonce, aad)
//!   aad = "hermetic-secret-v1-{secret_id}"
//!
//! The AAD (Additional Authenticated Data) binds each ciphertext to its
//! secret_id, preventing cross-secret ciphertext transplantation.
//!
//! INVARIANTS:
//!   - Nonce is 96-bit random from CSPRNG (never reused)
//!   - KEK is Zeroizing<Vec<u8>> (zeroized after use)
//!   - Plaintext is Zeroizing<Vec<u8>> (zeroized after encryption)
//!   - No secret material in error messages or logs

use ring::aead::{self, Aad, BoundKey, Nonce, NonceSequence, AES_256_GCM, NONCE_LEN};
use ring::rand::{SecureRandom, SystemRandom};
use zeroize::Zeroizing;

use crate::error::VaultError;

/// AAD prefix for per-secret encryption domain separation
const SECRET_AAD_PREFIX: &[u8] = b"hermetic-secret-v1-";

/// Builds the AAD for a given secret_id: "hermetic-secret-v1-{secret_id}"
fn build_aad(secret_id: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(SECRET_AAD_PREFIX.len() + secret_id.len());
    aad.extend_from_slice(SECRET_AAD_PREFIX);
    aad.extend_from_slice(secret_id.as_bytes());
    aad
}

/// Single-use nonce sequence for AES-256-GCM.
/// ring requires a NonceSequence trait implementation.
/// This provides exactly one nonce and then errors on subsequent calls.
struct OneNonceSequence(Option<Nonce>);

impl OneNonceSequence {
    fn new(nonce_bytes: [u8; NONCE_LEN]) -> Self {
        OneNonceSequence(Some(Nonce::assume_unique_for_key(nonce_bytes)))
    }
}

impl NonceSequence for OneNonceSequence {
    fn advance(&mut self) -> Result<Nonce, ring::error::Unspecified> {
        self.0.take().ok_or(ring::error::Unspecified)
    }
}

/// Generate a random 96-bit nonce using CSPRNG.
fn generate_nonce() -> Result<[u8; NONCE_LEN], VaultError> {
    let rng = SystemRandom::new();
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill(&mut nonce_bytes)
        .map_err(|e| VaultError::Crypto(format!("CSPRNG nonce generation failed: {}", e)))?;
    Ok(nonce_bytes)
}

/// Encrypt a secret value with AES-256-GCM.
///
/// Returns (ciphertext_with_tag, nonce).
/// The ciphertext includes the 16-byte GCM authentication tag appended.
///
/// # Arguments
/// * `kek` - 32-byte Key Encryption Key (derived from master_key via HKDF)
/// * `secret_id` - Used for AAD domain separation
/// * `plaintext` - Secret value to encrypt
pub fn encrypt_secret(
    kek: &[u8],
    secret_id: &str,
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), VaultError> {
    let nonce_bytes = generate_nonce()?;
    let aad_bytes = build_aad(secret_id);

    let unbound_key = aead::UnboundKey::new(&AES_256_GCM, kek)
        .map_err(|e| VaultError::Crypto(format!("AES-256-GCM key creation failed: {}", e)))?;

    let nonce_seq = OneNonceSequence::new(nonce_bytes);
    let mut sealing_key = aead::SealingKey::new(unbound_key, nonce_seq);

    let mut in_out = plaintext.to_vec();
    sealing_key
        .seal_in_place_append_tag(Aad::from(aad_bytes.as_slice()), &mut in_out)
        .map_err(|e| VaultError::Crypto(format!("AES-256-GCM seal failed: {}", e)))?;

    Ok((in_out, nonce_bytes.to_vec()))
}

/// Decrypt a secret value with AES-256-GCM.
///
/// Returns the plaintext as Zeroizing<Vec<u8>>.
///
/// # Arguments
/// * `kek` - 32-byte Key Encryption Key (must match encryption KEK)
/// * `secret_id` - Must match the secret_id used during encryption (AAD)
/// * `ciphertext` - Ciphertext including 16-byte GCM tag
/// * `nonce` - Nonce used during encryption (validated to be exactly 12 bytes per H-1)
pub fn decrypt_secret(
    kek: &[u8],
    secret_id: &str,
    ciphertext: &[u8],
    nonce: &[u8],
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    // H-1: Validate nonce length BEFORE passing to ring
    if nonce.len() != NONCE_LEN {
        return Err(VaultError::InvalidNonce {
            actual: nonce.len(),
        });
    }

    let aad_bytes = build_aad(secret_id);

    let mut nonce_array = [0u8; NONCE_LEN];
    nonce_array.copy_from_slice(nonce);

    let unbound_key = aead::UnboundKey::new(&AES_256_GCM, kek)
        .map_err(|e| VaultError::Crypto(format!("AES-256-GCM key creation failed: {}", e)))?;

    let nonce_seq = OneNonceSequence::new(nonce_array);
    let mut opening_key = aead::OpeningKey::new(unbound_key, nonce_seq);

    let mut in_out = ciphertext.to_vec();
    let plaintext = opening_key
        .open_in_place(Aad::from(aad_bytes.as_slice()), &mut in_out)
        .map_err(|_| {
            VaultError::Crypto("AES-256-GCM decryption failed: authentication error".into())
        })?;

    Ok(Zeroizing::new(plaintext.to_vec()))
}

// ============================================================================
// TESTS
// ============================================================================
#[cfg(test)]
mod tests {
    use super::*;

    /// Static 32-byte test KEK — avoids Argon2id overhead in unit tests.
    fn test_kek() -> Vec<u8> {
        vec![0x42u8; 32]
    }

    /// A second, different KEK for wrong-key tests.
    fn wrong_kek() -> Vec<u8> {
        vec![0x99u8; 32]
    }

    /// T2b-1: Encrypt → decrypt roundtrip → plaintext matches exactly.
    #[test]
    fn encrypt_decrypt_roundtrip() {
        let kek = test_kek();
        let secret_id = "test-secret-1";
        let plaintext = b"sk-ant-XXXX-secret-api-key-value";

        let (ciphertext, nonce) = encrypt_secret(&kek, secret_id, plaintext)
            .unwrap_or_else(|e| panic!("encrypt failed: {:?}", e));
        let decrypted = decrypt_secret(&kek, secret_id, &ciphertext, &nonce)
            .unwrap_or_else(|e| panic!("decrypt failed: {:?}", e));

        assert_eq!(decrypted.as_slice(), plaintext);
    }

    /// T2b-2: Encrypt same plaintext twice → ciphertexts differ (proves unique nonce).
    #[test]
    fn unique_nonce_per_encrypt() {
        let kek = test_kek();
        let secret_id = "nonce-test";
        let plaintext = b"same-plaintext-twice";

        let (ct1, nonce1) = encrypt_secret(&kek, secret_id, plaintext)
            .unwrap_or_else(|e| panic!("encrypt 1 failed: {:?}", e));
        let (ct2, nonce2) = encrypt_secret(&kek, secret_id, plaintext)
            .unwrap_or_else(|e| panic!("encrypt 2 failed: {:?}", e));

        assert_ne!(nonce1, nonce2, "each encryption must use a unique nonce");
        assert_ne!(ct1, ct2, "ciphertexts must differ due to unique nonces");
    }

    /// T2b-3: Tamper ciphertext (flip byte 0) → decrypt returns Crypto error.
    #[test]
    fn tampered_ciphertext_fails() {
        let kek = test_kek();
        let secret_id = "tamper-test";
        let plaintext = b"tamper-detection-test";

        let (mut ciphertext, nonce) = encrypt_secret(&kek, secret_id, plaintext)
            .unwrap_or_else(|e| panic!("encrypt failed: {:?}", e));

        ciphertext[0] ^= 0xFF;

        let result = decrypt_secret(&kek, secret_id, &ciphertext, &nonce);
        assert!(result.is_err(), "tampered ciphertext should fail GCM auth");
    }

    /// T2b-4: Wrong KEK (32 random bytes) → decrypt returns Crypto error.
    #[test]
    fn wrong_kek_fails() {
        let kek = test_kek();
        let secret_id = "wrong-kek-test";
        let plaintext = b"wrong-kek-detection";

        let (ciphertext, nonce) = encrypt_secret(&kek, secret_id, plaintext)
            .unwrap_or_else(|e| panic!("encrypt failed: {:?}", e));

        let result = decrypt_secret(&wrong_kek(), secret_id, &ciphertext, &nonce);
        assert!(result.is_err(), "wrong KEK should fail GCM auth");
    }

    /// T2b-5: Wrong secret_id in decrypt AAD → Crypto error (proves AAD binding).
    #[test]
    fn wrong_aad_fails() {
        let kek = test_kek();
        let secret_id = "correct-id";
        let plaintext = b"aad-binding-test";

        let (ciphertext, nonce) = encrypt_secret(&kek, secret_id, plaintext)
            .unwrap_or_else(|e| panic!("encrypt failed: {:?}", e));

        let result = decrypt_secret(&kek, "wrong-id", &ciphertext, &nonce);
        assert!(
            result.is_err(),
            "wrong AAD should fail — prevents cross-secret transplantation"
        );
    }

    /// T2b-6: Nonce is exactly 12 bytes.
    #[test]
    fn nonce_is_12_bytes() {
        let kek = test_kek();
        let (_, nonce) = encrypt_secret(&kek, "nonce-len-test", b"data")
            .unwrap_or_else(|e| panic!("encrypt failed: {:?}", e));
        assert_eq!(nonce.len(), 12);
    }

    /// T2b-7: Ciphertext length == plaintext length + 16.
    #[test]
    fn ciphertext_length_includes_tag() {
        let kek = test_kek();
        let plaintext = b"length-verification-test";
        let (ciphertext, _) = encrypt_secret(&kek, "len-test", plaintext)
            .unwrap_or_else(|e| panic!("encrypt failed: {:?}", e));
        assert_eq!(ciphertext.len(), plaintext.len() + 16);
    }

    /// T2b-8: Empty plaintext (0 bytes) → encrypt/decrypt roundtrip succeeds.
    #[test]
    fn empty_plaintext_roundtrip() {
        let kek = test_kek();
        let secret_id = "empty-test";
        let plaintext = b"";

        let (ciphertext, nonce) = encrypt_secret(&kek, secret_id, plaintext)
            .unwrap_or_else(|e| panic!("encrypt failed: {:?}", e));
        assert_eq!(ciphertext.len(), 16); // just the GCM tag

        let decrypted = decrypt_secret(&kek, secret_id, &ciphertext, &nonce)
            .unwrap_or_else(|e| panic!("decrypt failed: {:?}", e));
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    /// T2b-9: Large plaintext (64 KB) → encrypt/decrypt roundtrip succeeds.
    #[test]
    fn large_plaintext_roundtrip() {
        let kek = test_kek();
        let secret_id = "large-test";
        let plaintext = vec![0xABu8; 65536]; // 64 KB

        let (ciphertext, nonce) = encrypt_secret(&kek, secret_id, &plaintext)
            .unwrap_or_else(|e| panic!("encrypt failed: {:?}", e));
        let decrypted = decrypt_secret(&kek, secret_id, &ciphertext, &nonce)
            .unwrap_or_else(|e| panic!("decrypt failed: {:?}", e));

        assert_eq!(decrypted.as_slice(), plaintext.as_slice());
    }

    /// T2b-10: Return type of decrypt_secret is Zeroizing<Vec<u8>> (compile-time type assertion).
    #[test]
    fn decrypt_returns_zeroizing() {
        let kek = test_kek();
        let (ciphertext, nonce) = encrypt_secret(&kek, "type-test", b"zeroize-check")
            .unwrap_or_else(|e| panic!("encrypt failed: {:?}", e));
        let decrypted = decrypt_secret(&kek, "type-test", &ciphertext, &nonce)
            .unwrap_or_else(|e| panic!("decrypt failed: {:?}", e));

        // Compile-time type assertion
        let _: &Zeroizing<Vec<u8>> = &decrypted;
        assert_eq!(decrypted.as_slice(), b"zeroize-check");
    }

    /// T2b-11: decrypt_secret with nonce.len() != 12 → error BEFORE ring is called [H-1].
    #[test]
    fn invalid_nonce_length_rejected() {
        let kek = test_kek();
        let (ciphertext, _) = encrypt_secret(&kek, "nonce-h1", b"test")
            .unwrap_or_else(|e| panic!("encrypt failed: {:?}", e));

        // Too short
        let result = decrypt_secret(&kek, "nonce-h1", &ciphertext, &[0u8; 8]);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            VaultError::InvalidNonce { actual: 8 }
        ));

        // Too long
        let result = decrypt_secret(&kek, "nonce-h1", &ciphertext, &[0u8; 16]);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            VaultError::InvalidNonce { actual: 16 }
        ));

        // Empty
        let result = decrypt_secret(&kek, "nonce-h1", &ciphertext, &[]);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            VaultError::InvalidNonce { actual: 0 }
        ));
    }
}
