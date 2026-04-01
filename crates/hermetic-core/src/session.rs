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

//! Hermetic Session Persistence 
//!
//! Saves an encrypted passphrase to disk for daemon restart recovery.
//! Session key is derived at runtime — NO key material stored in session file.
//!
//! Derivation:
//!   session_key = HKDF(ikm=install_secret, salt=machine_id+boot_id+hostname+uid,
//!                      info="hermetic-session-v1")
//!
//! Session file contains ONLY: {ciphertext, nonce, created_at, max_age}
//!
//! INVARIANTS:
//!   - install_secret never stored in session file
//!   - session_key never stored anywhere
//!   - boot_id change (reboot) → different session_key → decrypt fails
//!   - max_age enforced (7 days)
//!   - Passphrase is Zeroizing (M-1: encrypt passphrase, not keys)

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::crypto;
use crate::error::VaultError;

const SESSION_FILE: &str = "session.dat";
const MAX_AGE_SECS: u64 = 7 * 24 * 3600; // 7 days
const HKDF_INFO: &[u8] = b"hermetic-session-v1";

/// Session data stored on disk — NO key material.
#[derive(serde::Serialize, serde::Deserialize)]
struct SessionData {
    nonce_hex: String,
    ciphertext_hex: String,
    created_at: u64,
    max_age: u64,
}

/// Manages encrypted passphrase persistence for daemon restart recovery.
pub struct SessionManager {
    session_dir: PathBuf,
}

impl SessionManager {
    pub fn new(session_dir: &Path) -> Self {
        Self {
            session_dir: session_dir.to_path_buf(),
        }
    }

    /// Derive session_key from install_secret + system context.
    /// salt = machine_id + boot_id + hostname + uid
    fn derive_session_key(install_secret: &[u8]) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        let machine_id = read_machine_id();
        let boot_id = read_boot_id();
        let hostname = get_hostname();
        let uid = get_uid();

        let mut salt = Vec::new();
        salt.extend_from_slice(machine_id.as_bytes());
        salt.extend_from_slice(boot_id.as_bytes());
        salt.extend_from_slice(hostname.as_bytes());
        salt.extend_from_slice(&uid.to_le_bytes());

        let hk = Hkdf::<Sha256>::new(Some(&salt), install_secret);
        let mut okm = Zeroizing::new(vec![0u8; 32]);
        hk.expand(HKDF_INFO, &mut okm)
            .map_err(|_| VaultError::Crypto("HKDF session key expand failed".into()))?;
        Ok(okm)
    }

    /// Save passphrase encrypted with session_key derived from install_secret.
    pub fn save(&self, passphrase: &[u8], install_secret: &[u8]) -> Result<(), VaultError> {
        let session_key = Self::derive_session_key(install_secret)?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| VaultError::Crypto(format!("system time error: {e}")))?
            .as_secs();

        // M1-12: Include created_at and max_age in AAD so attacker cannot
        // modify expiry metadata without breaking GCM authentication.
        let aad = format!("hermetic-session-v1:{}:{}", now, MAX_AGE_SECS);
        let (ciphertext, nonce) = crypto::encrypt_secret(&session_key, &aad, passphrase)?;

        let data = SessionData {
            nonce_hex: hex::encode(&nonce),
            ciphertext_hex: hex::encode(&ciphertext),
            created_at: now,
            max_age: MAX_AGE_SECS,
        };

        let json = serde_json::to_string(&data)
            .map_err(|e| VaultError::Serialization(format!("session serialize: {e}")))?;

        let path = self.session_dir.join(SESSION_FILE);
        // Write atomically: write to temp, rename
        let tmp_path = path.with_extension("tmp");
        {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp_path)
                .map_err(|e| VaultError::Serialization(format!("session write: {e}")))?;
            f.write_all(json.as_bytes())
                .map_err(|e| VaultError::Serialization(format!("session write: {e}")))?;
            f.sync_all()
                .map_err(|e| VaultError::Serialization(format!("session sync: {e}")))?;
        }
        std::fs::rename(&tmp_path, &path)
            .map_err(|e| VaultError::Serialization(format!("session rename: {e}")))?;

        Ok(())
    }

    /// Load passphrase from session file. Returns None if missing, expired, or invalid.
    pub fn load(&self, install_secret: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>, VaultError> {
        let path = self.session_dir.join(SESSION_FILE);
        let json = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(_) => return Ok(None), // No session file
        };

        let data: SessionData = match serde_json::from_str(&json) {
            Ok(d) => d,
            Err(_) => return Ok(None), // Corrupt — treat as absent
        };

        // Check max_age
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| VaultError::Crypto(format!("system time error: {e}")))?
            .as_secs();
        if now > data.created_at + data.max_age {
            // Expired — destroy and return None
            let _ = self.destroy();
            return Ok(None);
        }

        // Derive session_key (boot_id/machine_id/hostname/uid re-read at runtime)
        let session_key = Self::derive_session_key(install_secret)?;

        let ciphertext = hex::decode(&data.ciphertext_hex)
            .map_err(|_| VaultError::Crypto("session ciphertext decode failed".into()))?;
        let nonce = hex::decode(&data.nonce_hex)
            .map_err(|_| VaultError::Crypto("session nonce decode failed".into()))?;

        // M1-12: Reconstruct AAD from deserialized metadata — must match save().
        // If attacker modified max_age/created_at, AAD mismatch → GCM auth fails.
        let aad = format!("hermetic-session-v1:{}:{}", data.created_at, data.max_age);

        // Decrypt — if boot_id changed, key differs → GCM auth fails
        match crypto::decrypt_secret(&session_key, &aad, &ciphertext, &nonce) {
            Ok(passphrase) => Ok(Some(passphrase)),
            Err(_) => {
                // Wrong key (different boot/machine/user) or tampered — silent fail
                let _ = self.destroy();
                Ok(None)
            }
        }
    }

    /// Destroy session file (overwrite with zeros, then delete).
    pub fn destroy(&self) -> Result<(), VaultError> {
        let path = self.session_dir.join(SESSION_FILE);
        if !path.exists() {
            return Ok(());
        }
        // M1-06: Check for symlink before zero-fill to prevent symlink attack
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(_) => {
                let _ = std::fs::remove_file(&path);
                return Ok(());
            }
        };
        if metadata.file_type().is_symlink() {
            // Symlink detected — remove the link itself, never follow
            let _ = std::fs::remove_file(&path);
            return Ok(());
        }
        // Regular file — safe to zero-fill then delete
        let len = metadata.len() as usize;
        if len > 0 {
            if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(&path) {
                let _ = f.write_all(&vec![0u8; len]);
                let _ = f.sync_all();
            }
        }
        let _ = std::fs::remove_file(&path);
        Ok(())
    }
}

/// Read boot_id from /proc/sys/kernel/random/boot_id (Linux).
fn read_boot_id() -> String {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .unwrap_or_default()
        .trim()
        .to_string()
}

/// Read machine_id from /etc/machine-id (Linux).
fn read_machine_id() -> String {
    std::fs::read_to_string("/etc/machine-id")
        .unwrap_or_default()
        .trim()
        .to_string()
}

/// Get hostname from /proc/sys/kernel/hostname (safe, no libc).
fn get_hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .unwrap_or_default()
        .trim()
        .to_string()
}

/// Get current UID by parsing /proc/self/status (safe, no libc).
fn get_uid() -> u32 {
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("Uid:") {
                // Format: "Uid:\treal\teffective\tsaved\tfs"
                if let Some(uid_str) = rest.split_whitespace().next() {
                    return uid_str.parse().unwrap_or(0);
                }
            }
        }
    }
    0
}

use std::os::unix::fs::OpenOptionsExt;

// ============================================================================
// TESTS
// ============================================================================
#[cfg(test)]
mod tests {
    use super::*;

    fn test_install_secret() -> Vec<u8> {
        vec![0x42u8; 32]
    }

    fn other_install_secret() -> Vec<u8> {
        vec![0x99u8; 32]
    }

    /// T-S1: save + load roundtrip recovers passphrase.
    #[test]
    fn save_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = SessionManager::new(dir.path());
        let secret = test_install_secret();
        let passphrase = b"my-secure-passphrase-12chars";

        mgr.save(passphrase, &secret).unwrap();
        let loaded = mgr.load(&secret).unwrap();
        assert_eq!(loaded.as_ref().map(|p| p.as_slice()), Some(passphrase.as_slice()));
    }

    /// T-S2: load with wrong install_secret → None (GCM auth fails).
    #[test]
    fn wrong_install_secret_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = SessionManager::new(dir.path());

        mgr.save(b"my-secure-passphrase-12chars", &test_install_secret())
            .unwrap();
        let loaded = mgr.load(&other_install_secret()).unwrap();
        assert!(loaded.is_none());
    }

    /// T-S3: load after max_age exceeded → None.
    #[test]
    fn expired_session_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = SessionManager::new(dir.path());
        let secret = test_install_secret();

        mgr.save(b"my-secure-passphrase-12chars", &secret).unwrap();

        // Backdate created_at
        let path = dir.path().join(SESSION_FILE);
        let json = std::fs::read_to_string(&path).unwrap();
        let mut data: SessionData = serde_json::from_str(&json).unwrap();
        data.created_at = 0; // epoch — definitely expired
        std::fs::write(&path, serde_json::to_string(&data).unwrap()).unwrap();

        let loaded = mgr.load(&secret).unwrap();
        assert!(loaded.is_none());
    }

    /// T-S4: destroy removes file.
    #[test]
    fn destroy_removes_file() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = SessionManager::new(dir.path());

        mgr.save(b"my-secure-passphrase-12chars", &test_install_secret())
            .unwrap();
        assert!(dir.path().join(SESSION_FILE).exists());

        mgr.destroy().unwrap();
        assert!(!dir.path().join(SESSION_FILE).exists());
    }

    /// T-S5: load with tampered ciphertext → None (GCM auth error).
    #[test]
    fn tampered_ciphertext_fails() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = SessionManager::new(dir.path());
        let secret = test_install_secret();

        mgr.save(b"my-secure-passphrase-12chars", &secret).unwrap();

        // Flip a byte in ciphertext
        let path = dir.path().join(SESSION_FILE);
        let json = std::fs::read_to_string(&path).unwrap();
        let mut data: SessionData = serde_json::from_str(&json).unwrap();
        let mut ct_bytes = hex::decode(&data.ciphertext_hex).unwrap();
        ct_bytes[0] ^= 0xFF;
        data.ciphertext_hex = hex::encode(&ct_bytes);
        std::fs::write(&path, serde_json::to_string(&data).unwrap()).unwrap();

        let loaded = mgr.load(&secret).unwrap();
        assert!(loaded.is_none());
    }
}
