// Copyright (C) 2026 The Hermetic Project <dev@hermeticsys.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licenses available at hermeticsys.com/license

//! Hermetic HMAC-Chained Audit Log (v1.3.0a)
//!
//! Tamper-evident audit trail using HMAC-SHA256 chain:
//!   genesis: hmac_0 = HMAC-SHA256(audit_key, "hermetic-audit-genesis")
//!   chain:   hmac_N = HMAC-SHA256(audit_key, hmac_{N-1} || json(entry_N))
//!
//! Pure crypto functions (compute_genesis_hmac, compute_chain_hmac, AuditEntry)
//! are available on ALL platforms.
//! DB-backed AuditLog struct is cfg-gated per CP-001.
//!
//! INVARIANTS:
//!   - audit_key is Zeroizing<Vec<u8>> (INV-SEC)
//!   - No secret VALUES in any audit entry field
//!   - AuditFailure → FailClosedAction::Seal (INV-FAIL)

use ring::hmac;
use serde::{Deserialize, Serialize};

/// Domain string for genesis HMAC computation.
const GENESIS_DOMAIN: &[u8] = b"hermetic-audit-genesis";

/// Audit log entry — contains NO secret values.
/// Secret names (identifiers) are permitted; secret values are NEVER stored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: String,
    pub action: String,
    pub secret_name: Option<String>,
    pub agent: Option<String>,
    pub details: Option<String>,
}

/// Compute the genesis HMAC for an empty audit chain.
/// genesis = HMAC-SHA256(audit_key, "hermetic-audit-genesis")
pub fn compute_genesis_hmac(audit_key: &[u8]) -> Vec<u8> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, audit_key);
    let tag = hmac::sign(&key, GENESIS_DOMAIN);
    tag.as_ref().to_vec()
}

/// Compute the chain HMAC for an audit entry.
/// hmac_N = HMAC-SHA256(audit_key, prev_hmac || json(entry))
pub fn compute_chain_hmac(audit_key: &[u8], prev_hmac: &[u8], entry: &AuditEntry) -> Vec<u8> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, audit_key);
    let entry_json = serde_json::to_string(entry).unwrap_or_default();
    let mut data = Vec::with_capacity(prev_hmac.len() + entry_json.len());
    data.extend_from_slice(prev_hmac);
    data.extend_from_slice(entry_json.as_bytes());
    let tag = hmac::sign(&key, &data);
    tag.as_ref().to_vec()
}

// ============================================================================
// DB-backed AuditLog — cfg-gated per CP-001
// ============================================================================

#[cfg(not(target_os = "windows"))]
use crate::error::VaultError;
#[cfg(not(target_os = "windows"))]
use std::path::Path;
#[cfg(not(target_os = "windows"))]
use zeroize::Zeroizing;

/// H-2: Constant-width hex encoding for key material.
/// Duplicated from db.rs (private there, can't import).
#[cfg(not(target_os = "windows"))]
fn constant_width_hex(bytes: &[u8]) -> Zeroizing<String> {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut hex = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        hex.push(HEX_CHARS[(b >> 4) as usize] as char);
        hex.push(HEX_CHARS[(b & 0x0f) as usize] as char);
    }
    Zeroizing::new(hex)
}

/// DB-backed audit log with HMAC chain verification.
/// Opens its own SQLCipher connection to the vault database.
#[cfg(not(target_os = "windows"))]
pub struct AuditLog {
    conn: rusqlite::Connection,
    audit_key: Zeroizing<Vec<u8>>,
}

#[cfg(not(target_os = "windows"))]
impl AuditLog {
    /// Open a connection to the audit log in the vault database.
    pub fn open(
        db_path: &Path,
        db_key: &[u8],
        audit_key: Zeroizing<Vec<u8>>,
    ) -> Result<Self, VaultError> {
        let conn = rusqlite::Connection::open(db_path)
            .map_err(|e| VaultError::AuditFailure(format!("open audit DB: {}", e)))?;

        let hex_key = constant_width_hex(db_key);
        let pragma = Zeroizing::new(format!("PRAGMA key = \"x'{}'\";", &*hex_key));
        conn.execute_batch(&pragma)
            .map_err(|e| VaultError::AuditFailure(format!("audit DB key: {}", e)))?;

        conn.execute_batch("PRAGMA cipher_page_size = 4096;")
            .map_err(|e| VaultError::AuditFailure(format!("cipher_page_size: {}", e)))?;
        conn.execute_batch("PRAGMA kdf_iter = 256000;")
            .map_err(|e| VaultError::AuditFailure(format!("kdf_iter: {}", e)))?;

        Ok(AuditLog { conn, audit_key })
    }

    /// Write an audit entry, chaining its HMAC from the previous entry.
    pub fn write_entry(&self, entry: &AuditEntry) -> Result<(), VaultError> {
        let prev_hmac = self
            .get_last_hmac()?
            .unwrap_or_else(|| compute_genesis_hmac(&self.audit_key));

        let hmac = compute_chain_hmac(&self.audit_key, &prev_hmac, entry);
        let hmac_hex = hex::encode(&hmac);

        self.conn
            .execute(
                "INSERT INTO audit_log (timestamp, action, secret_name, agent, details, hmac)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![
                    entry.timestamp,
                    entry.action,
                    entry.secret_name,
                    entry.agent,
                    entry.details,
                    hmac_hex,
                ],
            )
            .map_err(|e| VaultError::AuditFailure(format!("write audit entry: {}", e)))?;

        Ok(())
    }

    /// Read all audit entries in order, with their stored HMACs.
    pub fn read_entries(&self) -> Result<Vec<(Vec<u8>, AuditEntry)>, VaultError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT hmac, timestamp, action, secret_name, agent, details
                 FROM audit_log ORDER BY id ASC",
            )
            .map_err(|e| VaultError::AuditFailure(format!("prepare read: {}", e)))?;

        let rows = stmt
            .query_map([], |row| {
                let hmac_hex: String = row.get(0)?;
                Ok((
                    hmac_hex,
                    AuditEntry {
                        timestamp: row.get(1)?,
                        action: row.get(2)?,
                        secret_name: row.get(3)?,
                        agent: row.get(4)?,
                        details: row.get(5)?,
                    },
                ))
            })
            .map_err(|e| VaultError::AuditFailure(format!("query entries: {}", e)))?;

        let mut result = Vec::new();
        for row in rows {
            let (hmac_hex, entry) =
                row.map_err(|e| VaultError::AuditFailure(format!("read row: {}", e)))?;
            let hmac = hex::decode(&hmac_hex)
                .map_err(|_| VaultError::AuditFailure("corrupt HMAC hex".into()))?;
            result.push((hmac, entry));
        }

        Ok(result)
    }

    /// Verify the HMAC chain integrity of the entire audit log.
    /// Replays the chain from genesis and compares each stored HMAC.
    pub fn verify(&self) -> Result<(), VaultError> {
        self.verify_with_anchor(None)
    }

    /// Verify the HMAC chain from an optional anchor point.
    /// If `anchor_hex` is Some, starts verification from that HMAC instead of genesis.
    /// Used after audit log pruning to verify the remaining chain.
    pub fn verify_with_anchor(&self, anchor_hex: Option<&str>) -> Result<(), VaultError> {
        let entries = self.read_entries()?;

        let mut prev_hmac = match anchor_hex {
            Some(hex_str) => hex::decode(hex_str)
                .map_err(|_| VaultError::AuditFailure("corrupt chain anchor hex".into()))?,
            None => compute_genesis_hmac(&self.audit_key),
        };

        for (stored_hmac, entry) in &entries {
            let computed = compute_chain_hmac(&self.audit_key, &prev_hmac, entry);
            if computed != *stored_hmac {
                return Err(VaultError::AuditFailure(
                    "HMAC chain verification failed".into(),
                ));
            }
            prev_hmac = stored_hmac.clone();
        }

        Ok(())
    }

    /// Delete audit entries with timestamps before the cutoff.
    /// Returns (deleted_count, anchor_hmac_hex) where anchor is the HMAC of
    /// the last deleted entry (for chain verification after pruning).
    pub fn delete_entries_before(
        &self,
        cutoff_timestamp: &str,
    ) -> Result<(u64, Option<String>), VaultError> {
        // Get the HMAC of the last entry that will be deleted (chain anchor)
        let anchor: Option<String> = self
            .conn
            .query_row(
                "SELECT hmac FROM audit_log WHERE timestamp < ?1 ORDER BY id DESC LIMIT 1",
                rusqlite::params![cutoff_timestamp],
                |row| row.get(0),
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => {
                    // Map to a special value to indicate no rows to delete
                    VaultError::AuditFailure("__no_rows__".into())
                }
                other => VaultError::AuditFailure(format!("query anchor: {}", other)),
            })
            .ok();

        // Delete entries
        let count = self
            .conn
            .execute(
                "DELETE FROM audit_log WHERE timestamp < ?1",
                rusqlite::params![cutoff_timestamp],
            )
            .map_err(|e| VaultError::AuditFailure(format!("delete audit entries: {}", e)))?
            as u64;

        Ok((count, anchor))
    }

    /// Get the last HMAC in the chain, or None if the log is empty.
    fn get_last_hmac(&self) -> Result<Option<Vec<u8>>, VaultError> {
        let mut stmt = self
            .conn
            .prepare("SELECT hmac FROM audit_log ORDER BY id DESC LIMIT 1")
            .map_err(|e| VaultError::AuditFailure(format!("prepare last hmac: {}", e)))?;

        let mut rows = stmt
            .query([])
            .map_err(|e| VaultError::AuditFailure(format!("query last hmac: {}", e)))?;

        if let Some(row) = rows
            .next()
            .map_err(|e| VaultError::AuditFailure(format!("next row: {}", e)))?
        {
            let hmac_hex: String = row
                .get(0)
                .map_err(|e| VaultError::AuditFailure(format!("get hmac: {}", e)))?;
            let bytes = hex::decode(&hmac_hex)
                .map_err(|_| VaultError::AuditFailure("corrupt HMAC hex".into()))?;
            Ok(Some(bytes))
        } else {
            Ok(None)
        }
    }
}
