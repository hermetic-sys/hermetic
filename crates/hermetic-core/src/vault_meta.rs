// Copyright (C) 2026 The Hermetic Project <dev@hermeticsys.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licenses available at hermeticsys.com/license

//! Hermetic Vault Metadata Schema (v1.3.0a)
//!
//! Stored as JSON in the `meta` table (exactly one row).
//! Contains vault configuration and non-secret cryptographic parameters.
//!
//! INVARIANTS:
//!   - master_key and device_key are NEVER stored here (memory/keychain only)
//!   - vault_salt is NOT secret (prevents rainbow tables)
//!   - passphrase_verifier is a one-way HMAC (cannot recover master_key)
//!   - No secret material in this struct

use serde::{Deserialize, Serialize};

use crate::error::VaultError;

/// Vault metadata stored in the `meta` table.
/// Serialized as JSON. Holds NO secret material.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultMeta {
    /// Vault mode: "software" or "hardware"
    pub mode: String,

    /// 32-byte random salt for Argon2id (hex-encoded)
    pub vault_salt: String,

    /// Argon2id memory parameter in KB
    pub argon2_m: u32,

    /// Argon2id iteration count
    pub argon2_t: u32,

    /// Argon2id parallelism
    pub argon2_p: u32,

    /// Whether a device key is enrolled in the OS keychain
    pub device_key_enrolled: bool,

    /// AES-256-GCM encrypted master_key (hex if present, None for Phase 1)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wrapped_master_key: Option<String>,

    /// GCM nonce for the wrapping operation (hex if present, None for Phase 1)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wrap_nonce: Option<String>,

    /// Whether biometric gate is active on the OS keychain entry
    pub biometric_enrolled: bool,

    /// HMAC-SHA256(master_key, "hermetic-verify-v1") for passphrase verification (hex-encoded)
    pub passphrase_verifier: String,

    /// Architecture specification version
    pub version: String,

    /// HMAC of the last pruned audit entry (chain anchor for verification after pruning).
    /// None if no pruning has occurred.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_chain_anchor: Option<String>,

    /// Secret name tagged as the reveal key (HM-EXEC-REVEAL-001).
    /// At most one secret at a time. None = no reveal key configured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reveal_key_name: Option<String>,

    /// Binary version that last opened this vault.
    /// Updated on every unlock so it always reflects the most recent binary.
    /// Defaults to "unknown" for pre-V1.0.0 vaults (serde backward-compat).
    #[serde(default = "default_binary_version")]
    pub binary_version: String,
}

fn default_binary_version() -> String {
    "unknown".to_string()
}

impl VaultMeta {
    /// Create metadata for a new software-mode vault.
    pub fn new_software(
        vault_salt: &[u8; 32],
        verifier: &[u8],
        argon2_m: u32,
        argon2_t: u32,
        argon2_p: u32,
    ) -> Self {
        VaultMeta {
            mode: "software".to_string(),
            vault_salt: hex::encode(vault_salt),
            argon2_m,
            argon2_t,
            argon2_p,
            device_key_enrolled: false,
            wrapped_master_key: None,
            wrap_nonce: None,
            biometric_enrolled: false,
            passphrase_verifier: hex::encode(verifier),
            version: "1.3.0a".to_string(),
            audit_chain_anchor: None,
            reveal_key_name: None,
            binary_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    /// Serialize to JSON string for database storage.
    pub fn to_json(&self) -> Result<String, VaultError> {
        serde_json::to_string(self).map_err(VaultError::from)
    }

    /// Deserialize from JSON string. Malformed JSON → CorruptedMeta → SEAL.
    pub fn from_json(json: &str) -> Result<Self, VaultError> {
        serde_json::from_str(json).map_err(VaultError::from)
    }

    /// Decode vault_salt from hex to 32-byte array.
    pub fn vault_salt_bytes(&self) -> Result<[u8; 32], VaultError> {
        let bytes = hex::decode(&self.vault_salt).map_err(|_| VaultError::CorruptedMeta)?;
        if bytes.len() != 32 {
            return Err(VaultError::CorruptedMeta);
        }
        let mut salt = [0u8; 32];
        salt.copy_from_slice(&bytes);
        Ok(salt)
    }

    /// Decode passphrase_verifier from hex to bytes.
    pub fn passphrase_verifier_bytes(&self) -> Result<Vec<u8>, VaultError> {
        hex::decode(&self.passphrase_verifier).map_err(|_| VaultError::CorruptedMeta)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::FailClosedAction;

    /// T2c-1: Serialize → deserialize roundtrip — all fields match.
    #[test]
    fn serialize_deserialize_roundtrip() {
        let salt = [0xABu8; 32];
        let verifier = [0xCDu8; 32];
        let meta = VaultMeta::new_software(&salt, &verifier, 262144, 4, 2);
        let json = meta
            .to_json()
            .unwrap_or_else(|e| panic!("serialize failed: {:?}", e));
        let restored =
            VaultMeta::from_json(&json).unwrap_or_else(|e| panic!("deserialize failed: {:?}", e));

        assert_eq!(restored.mode, "software");
        assert_eq!(restored.vault_salt, hex::encode(salt));
        assert_eq!(restored.argon2_m, 262144);
        assert_eq!(restored.argon2_t, 4);
        assert_eq!(restored.argon2_p, 2);
        assert!(!restored.device_key_enrolled);
        assert!(restored.wrapped_master_key.is_none());
        assert!(restored.wrap_nonce.is_none());
        assert!(!restored.biometric_enrolled);
        assert_eq!(restored.passphrase_verifier, hex::encode(verifier));
        assert_eq!(restored.version, "1.3.0a");
        assert!(restored.reveal_key_name.is_none());
    }

    /// T2c-2: version field == "1.3.0a".
    #[test]
    fn version_field_correct() {
        let meta = VaultMeta::new_software(&[0u8; 32], &[0u8; 32], 262144, 4, 2);
        assert_eq!(meta.version, "1.3.0a");
        // Also verify it appears in JSON
        let json = meta
            .to_json()
            .unwrap_or_else(|e| panic!("serialize failed: {:?}", e));
        assert!(json.contains("\"version\":\"1.3.0a\""));
    }

    /// T2c-3: device_key_enrolled defaults to false, wrapped_master_key defaults to None.
    #[test]
    fn device_key_defaults() {
        let meta = VaultMeta::new_software(&[0u8; 32], &[0u8; 32], 262144, 4, 2);
        assert!(!meta.device_key_enrolled);
        assert!(meta.wrapped_master_key.is_none());
        assert!(meta.wrap_nonce.is_none());
        assert!(!meta.biometric_enrolled);
        // Verify optional fields absent from JSON (skip_serializing_if)
        let json = meta
            .to_json()
            .unwrap_or_else(|e| panic!("serialize failed: {:?}", e));
        assert!(!json.contains("wrapped_master_key"));
        assert!(!json.contains("wrap_nonce"));
    }

    /// T2c-4: Malformed JSON → serde_json::Error → VaultError → FailClosedAction (verify mapping).
    #[test]
    fn malformed_json_maps_to_seal() {
        let result = VaultMeta::from_json("this is not json");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.fail_closed_action(), FailClosedAction::Seal);
    }

    /// HM-EXEC-REVEAL-001: reveal_key_name roundtrip + skip_serializing_if.
    #[test]
    fn reveal_key_name_roundtrip() {
        let mut meta = VaultMeta::new_software(&[0u8; 32], &[0u8; 32], 262144, 4, 2);
        // Default: None → not in JSON
        let json = meta.to_json().unwrap();
        assert!(!json.contains("reveal_key_name"));
        // Set a value → appears in JSON
        meta.reveal_key_name = Some("my-api-key".to_string());
        let json = meta.to_json().unwrap();
        assert!(json.contains("\"reveal_key_name\":\"my-api-key\""));
        // Roundtrip
        let restored = VaultMeta::from_json(&json).unwrap();
        assert_eq!(restored.reveal_key_name.as_deref(), Some("my-api-key"));
    }

    /// HM-EXEC-REVEAL-001: Backward compat — old JSON without reveal_key_name deserializes fine.
    #[test]
    fn reveal_key_name_backward_compat() {
        // Simulate a V4 JSON without reveal_key_name
        let old_json = r#"{"mode":"software","vault_salt":"00","argon2_m":262144,"argon2_t":4,"argon2_p":2,"device_key_enrolled":false,"biometric_enrolled":false,"passphrase_verifier":"ff","version":"1.3.0a"}"#;
        let meta = VaultMeta::from_json(old_json).unwrap();
        assert!(meta.reveal_key_name.is_none());
    }

    // ── Mutation gap tests (vault_salt_bytes + passphrase_verifier_bytes) ──

    /// Mutation gap: vault_salt_bytes returns exactly 32 bytes matching the input salt.
    #[test]
    fn vault_salt_bytes_roundtrip() {
        let salt = [0xABu8; 32];
        let meta = VaultMeta::new_software(&salt, &[0u8; 32], 262144, 4, 2);
        let decoded = meta.vault_salt_bytes().unwrap();
        assert_eq!(decoded.len(), 32);
        assert_eq!(decoded, salt);
    }

    /// Mutation gap: vault_salt_bytes rejects non-zero-length but wrong-length hex.
    #[test]
    fn vault_salt_bytes_wrong_length_errors() {
        let mut meta = VaultMeta::new_software(&[0u8; 32], &[0u8; 32], 262144, 4, 2);
        // Set salt to 16 bytes (32 hex chars → 16 bytes... no, 32 hex = 16 bytes)
        // Actually hex::encode([0u8;32]) = 64 hex chars = 32 bytes. So set to shorter:
        meta.vault_salt = hex::encode([0xFFu8; 16]); // 16 bytes, not 32
        let result = meta.vault_salt_bytes();
        assert!(result.is_err());
    }

    /// Mutation gap: vault_salt_bytes rejects invalid hex.
    #[test]
    fn vault_salt_bytes_invalid_hex_errors() {
        let mut meta = VaultMeta::new_software(&[0u8; 32], &[0u8; 32], 262144, 4, 2);
        meta.vault_salt = "not-valid-hex!".to_string();
        let result = meta.vault_salt_bytes();
        assert!(result.is_err());
    }

    /// Mutation gap: vault_salt_bytes does not return all zeros for a non-zero salt.
    #[test]
    fn vault_salt_bytes_not_all_zeros() {
        let salt = [0x42u8; 32];
        let meta = VaultMeta::new_software(&salt, &[0u8; 32], 262144, 4, 2);
        let decoded = meta.vault_salt_bytes().unwrap();
        assert_ne!(decoded, [0u8; 32]);
    }

    /// Mutation gap: passphrase_verifier_bytes returns the correct verifier.
    #[test]
    fn passphrase_verifier_bytes_roundtrip() {
        let verifier = [
            0xDE, 0xAD, 0xBE, 0xEF, 0x42, 0x42, 0x42, 0x42, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            0x07, 0x08, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0xA1, 0xB2, 0xC3, 0xD4,
            0xE5, 0xF6, 0x00, 0xFF,
        ];
        let meta = VaultMeta::new_software(&[0u8; 32], &verifier, 262144, 4, 2);
        let decoded = meta.passphrase_verifier_bytes().unwrap();
        assert_eq!(decoded.len(), 32);
        assert_eq!(decoded.as_slice(), &verifier);
    }

    /// Mutation gap: passphrase_verifier_bytes is non-empty for a non-empty verifier.
    #[test]
    fn passphrase_verifier_bytes_non_empty() {
        let meta = VaultMeta::new_software(&[0u8; 32], &[0xCDu8; 32], 262144, 4, 2);
        let decoded = meta.passphrase_verifier_bytes().unwrap();
        assert!(!decoded.is_empty());
    }

    /// Mutation gap: passphrase_verifier_bytes rejects invalid hex.
    #[test]
    fn passphrase_verifier_bytes_invalid_hex_errors() {
        let mut meta = VaultMeta::new_software(&[0u8; 32], &[0u8; 32], 262144, 4, 2);
        meta.passphrase_verifier = "ZZZZ-not-hex".to_string();
        let result = meta.passphrase_verifier_bytes();
        assert!(result.is_err());
    }
}
