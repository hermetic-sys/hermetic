// Copyright (C) 2026 The Hermetic Project <dev@hermeticsys.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licenses available at hermeticsys.com/license

//! Hermetic SQLCipher Encrypted Database (v1.3.0a)
//!
//! Double encryption:
//!   Layer 1: SQLCipher (database-level) keyed by db_key
//!   Layer 2: AES-256-GCM (per-secret) keyed by individual KEKs
//!
//! INVARIANTS:
//!   - Secret plaintext NEVER appears in SQL queries or error messages
//!   - Wrong db_key → DatabaseKeyInvalid → SEAL [H-3]
//!   - Corrupt schema → DatabaseCorrupted → SEAL [H-3]
//!   - Invalid nonce length → InvalidNonce → SEAL [H-1]
//!   - db_key hex uses constant-width formatting [H-2]
//!   - All database errors map to VaultError → SEAL

use std::path::Path;

use rusqlite::{params, Connection};
use zeroize::Zeroizing;

use crate::error::VaultError;
use crate::vault_meta::VaultMeta;

/// H-2: Constant-width hex encoding for key material.
/// Pre-allocates a fixed 64-char buffer (for 32-byte keys), iterates bytes
/// with a lookup table, writes exactly two chars per byte.
/// The result is wrapped in Zeroizing<String> so it is zeroed on drop.
pub fn constant_width_hex(bytes: &[u8]) -> Zeroizing<String> {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut hex = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        hex.push(HEX_CHARS[(b >> 4) as usize] as char);
        hex.push(HEX_CHARS[(b & 0x0f) as usize] as char);
    }
    Zeroizing::new(hex)
}

/// Parse a JSON-encoded allowed_domains column value.
/// NULL → None, "[]" → Some(vec![]), '["a.com"]' → Some(vec!["a.com"]).
fn parse_allowed_domains(raw: Option<&str>) -> Result<Option<Vec<String>>, VaultError> {
    match raw {
        None => Ok(None),
        Some(json) => serde_json::from_str(json)
            .map(Some)
            .map_err(|e| VaultError::Database(format!("allowed_domains JSON: {}", e))),
    }
}

/// SQLCipher-encrypted database wrapper.
/// Wraps a rusqlite::Connection with PRAGMA-based encryption.
pub struct VaultDatabase {
    conn: Connection,
}

impl VaultDatabase {
    /// Create a new SQLCipher-encrypted database at `path`.
    /// Creates all 3 tables (meta, secrets, audit_log).
    pub fn create(path: &Path, db_key: &[u8]) -> Result<VaultDatabase, VaultError> {
        let conn = Connection::open(path)
            .map_err(|e| VaultError::Database(format!("Failed to create database: {}", e)))?;

        // H-2: constant-width hex for db_key
        let hex_key = constant_width_hex(db_key);
        let pragma = Zeroizing::new(format!("PRAGMA key = \"x'{}'\";", &*hex_key));
        conn.execute_batch(&pragma)
            .map_err(|e| VaultError::Database(format!("SQLCipher key: {}", e)))?;

        conn.execute_batch("PRAGMA cipher_page_size = 4096;")
            .map_err(|e| VaultError::Database(format!("cipher_page_size: {}", e)))?;
        conn.execute_batch("PRAGMA kdf_iter = 256000;")
            .map_err(|e| VaultError::Database(format!("kdf_iter: {}", e)))?;

        // Create schema
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS meta (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                data TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS secrets (
                id TEXT PRIMARY KEY,
                name TEXT UNIQUE NOT NULL,
                encrypted_blob BLOB NOT NULL,
                nonce BLOB NOT NULL,
                sensitivity TEXT DEFAULT 'standard' CHECK(sensitivity IN ('high','standard','low')),
                tags TEXT DEFAULT '',
                allowed_domains TEXT DEFAULT NULL,
                created_at TEXT NOT NULL,
                rotated_at TEXT,
                secret_type TEXT DEFAULT 'static'
            );
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                action TEXT NOT NULL,
                secret_name TEXT,
                agent TEXT,
                details TEXT,
                hmac TEXT NOT NULL
            );",
        )
        .map_err(|e| VaultError::Database(format!("Schema creation failed: {}", e)))?;

        Ok(VaultDatabase { conn })
    }

    /// Open an existing SQLCipher-encrypted database.
    /// Validates the key by querying sqlite_master.
    pub fn open(path: &Path, db_key: &[u8]) -> Result<VaultDatabase, VaultError> {
        let conn = Connection::open(path)
            .map_err(|e| VaultError::Database(format!("Failed to open database: {}", e)))?;

        // H-2: constant-width hex for db_key
        let hex_key = constant_width_hex(db_key);
        let pragma = Zeroizing::new(format!("PRAGMA key = \"x'{}'\";", &*hex_key));
        conn.execute_batch(&pragma)
            .map_err(|e| VaultError::Database(format!("SQLCipher key: {}", e)))?;

        conn.execute_batch("PRAGMA cipher_page_size = 4096;")
            .map_err(|e| VaultError::Database(format!("cipher_page_size: {}", e)))?;
        conn.execute_batch("PRAGMA kdf_iter = 256000;")
            .map_err(|e| VaultError::Database(format!("kdf_iter: {}", e)))?;

        // H-3: Validate key — if wrong, SQLCipher returns "not a database" error
        conn.execute_batch("SELECT count(*) FROM sqlite_master;")
            .map_err(|_| VaultError::DatabaseKeyInvalid)?;

        // H-3: Validate schema exists
        let table_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('meta', 'secrets', 'audit_log')",
            [],
            |row| row.get(0),
        ).map_err(|_| VaultError::DatabaseCorrupted)?;

        if table_count < 3 {
            return Err(VaultError::DatabaseCorrupted);
        }

        // V2 schema migration: add tags column if absent (idempotent)
        let has_tags: bool = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('secrets') WHERE name = 'tags'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map(|c| c > 0)
            .unwrap_or(false);

        if !has_tags {
            conn.execute_batch("ALTER TABLE secrets ADD COLUMN tags TEXT DEFAULT '';")
                .map_err(|e| VaultError::Database(format!("V2 migration (tags): {}", e)))?;
        }

        // V3 schema migration: add allowed_domains column if absent (idempotent)
        let has_allowed_domains: bool = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('secrets') WHERE name = 'allowed_domains'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map(|c| c > 0)
            .unwrap_or(false);

        if !has_allowed_domains {
            conn.execute_batch("ALTER TABLE secrets ADD COLUMN allowed_domains TEXT DEFAULT NULL;")
                .map_err(|e| {
                    VaultError::Database(format!("V3 migration (allowed_domains): {}", e))
                })?;
        }

        // V4 schema migration: add secret_type column if absent (idempotent)
        // Stores "static" or "oauth2" — read at list-time without decryption.
        let has_secret_type: bool = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('secrets') WHERE name = 'secret_type'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map(|c| c > 0)
            .unwrap_or(false);

        if !has_secret_type {
            conn.execute_batch("ALTER TABLE secrets ADD COLUMN secret_type TEXT DEFAULT 'static';")
                .map_err(|e| VaultError::Database(format!("V4 migration (secret_type): {}", e)))?;
        }

        Ok(VaultDatabase { conn })
    }

    /// Store an encrypted secret.
    /// H-1: Validates nonce.len() == 12 before storing.
    #[allow(clippy::too_many_arguments)]
    pub fn store_secret(
        &self,
        id: &str,
        name: &str,
        encrypted_blob: &[u8],
        nonce: &[u8],
        sensitivity: &str,
        tags: &str,
        created_at: &str,
        allowed_domains: Option<&str>,
        secret_type: &str,
    ) -> Result<(), VaultError> {
        // H-1: nonce length validation
        if nonce.len() != 12 {
            return Err(VaultError::InvalidNonce {
                actual: nonce.len(),
            });
        }

        // Check for duplicate name
        let exists: bool = self
            .conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM secrets WHERE name = ?1)",
                params![name],
                |row| row.get(0),
            )
            .map_err(|e| VaultError::Database(format!("existence check: {}", e)))?;

        if exists {
            return Err(VaultError::SecretAlreadyExists {
                name: name.to_string(),
            });
        }

        self.conn
            .execute(
                "INSERT INTO secrets (id, name, encrypted_blob, nonce, sensitivity, tags, allowed_domains, created_at, secret_type)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![id, name, encrypted_blob, nonce, sensitivity, tags, allowed_domains, created_at, secret_type],
            )
            .map_err(|e| VaultError::Database(format!("insert secret: {}", e)))?;

        Ok(())
    }

    /// Retrieve an encrypted secret by name.
    /// Returns: (id, encrypted_blob, nonce, sensitivity, created_at, allowed_domains)
    /// H-1: Validates nonce length on retrieval.
    #[allow(clippy::type_complexity)]
    pub fn get_secret(
        &self,
        name: &str,
    ) -> Result<
        (
            String,
            Vec<u8>,
            Vec<u8>,
            String,
            String,
            Option<Vec<String>>,
        ),
        VaultError,
    > {
        let row_result = self
            .conn
            .query_row(
                "SELECT id, encrypted_blob, nonce, sensitivity, created_at, allowed_domains
             FROM secrets WHERE name = ?1",
                params![name],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, Option<String>>(5)?,
                    ))
                },
            )
            .map_err(|_| VaultError::SecretNotFound {
                name: name.to_string(),
            })?;

        // H-1: nonce length validation at read time
        if row_result.2.len() != 12 {
            return Err(VaultError::DatabaseCorrupted);
        }

        let domains = parse_allowed_domains(row_result.5.as_deref())?;
        Ok((
            row_result.0,
            row_result.1,
            row_result.2,
            row_result.3,
            row_result.4,
            domains,
        ))
    }

    /// Delete a secret by name.
    pub fn delete_secret(&self, name: &str) -> Result<(), VaultError> {
        let rows = self
            .conn
            .execute("DELETE FROM secrets WHERE name = ?1", params![name])
            .map_err(|e| VaultError::Database(format!("delete secret: {}", e)))?;

        if rows == 0 {
            return Err(VaultError::SecretNotFound {
                name: name.to_string(),
            });
        }

        Ok(())
    }

    /// Update an existing secret's encrypted blob and nonce in-place.
    ///
    /// Preserves UUID, name, sensitivity, tags, and domain bindings.
    /// Updates rotated_at timestamp. Used for OAuth2 refresh token rotation.
    ///
    /// H-1: Validates nonce.len() == 12 before storing.
    pub fn update_secret_blob(
        &self,
        name: &str,
        encrypted_blob: &[u8],
        nonce: &[u8],
        rotated_at: &str,
    ) -> Result<(), VaultError> {
        if nonce.len() != 12 {
            return Err(VaultError::InvalidNonce {
                actual: nonce.len(),
            });
        }
        let rows = self
            .conn
            .execute(
                "UPDATE secrets SET encrypted_blob = ?1, nonce = ?2, rotated_at = ?3 WHERE name = ?4",
                params![encrypted_blob, nonce, rotated_at, name],
            )
            .map_err(|e| VaultError::Database(format!("update secret blob: {}", e)))?;

        if rows == 0 {
            return Err(VaultError::SecretNotFound {
                name: name.to_string(),
            });
        }

        Ok(())
    }

    /// List all secrets (metadata only — NEVER returns encrypted_blob or nonce).
    /// Returns: Vec<(name, sensitivity, created_at, tags, allowed_domains, secret_type)>
    #[allow(clippy::type_complexity)]
    pub fn list_secrets(
        &self,
    ) -> Result<Vec<(String, String, String, String, Option<Vec<String>>, String)>, VaultError>
    {
        let mut stmt = self
            .conn
            .prepare("SELECT name, sensitivity, created_at, COALESCE(tags, ''), allowed_domains, COALESCE(secret_type, 'static') FROM secrets ORDER BY name")
            .map_err(|e| VaultError::Database(format!("prepare list: {}", e)))?;

        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })
            .map_err(|e| VaultError::Database(format!("list secrets: {}", e)))?;

        let mut result = Vec::new();
        for row in rows {
            let (name, sens, created, tags, domains_json, secret_type) =
                row.map_err(|e| VaultError::Database(format!("row read: {}", e)))?;
            let domains = parse_allowed_domains(domains_json.as_deref())?;
            result.push((name, sens, created, tags, domains, secret_type));
        }
        Ok(result)
    }

    /// Get tags for a specific secret by name (without decrypting).
    pub fn get_secret_tags(&self, name: &str) -> Result<String, VaultError> {
        self.conn
            .query_row(
                "SELECT COALESCE(tags, '') FROM secrets WHERE name = ?1",
                params![name],
                |row| row.get::<_, String>(0),
            )
            .map_err(|_| VaultError::SecretNotFound {
                name: name.to_string(),
            })
    }

    /// Store vault metadata (exactly one row).
    pub fn store_meta(&self, meta: &VaultMeta) -> Result<(), VaultError> {
        let json = meta.to_json()?;
        self.conn
            .execute(
                "INSERT OR REPLACE INTO meta (id, data) VALUES (1, ?1)",
                params![json],
            )
            .map_err(|e| VaultError::Database(format!("store meta: {}", e)))?;
        Ok(())
    }

    /// Load vault metadata. Returns CorruptedMeta if missing or invalid → SEAL.
    pub fn get_meta(&self) -> Result<VaultMeta, VaultError> {
        let json: String = self
            .conn
            .query_row("SELECT data FROM meta WHERE id = 1", [], |row| row.get(0))
            .map_err(|_| VaultError::CorruptedMeta)?;

        VaultMeta::from_json(&json)
    }

    /// Raw secret count via SQL COUNT(*) — no decryption, no parsing.
    /// Used for migration integrity verification.
    pub fn secret_count_raw(&self) -> Result<usize, VaultError> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM secrets", [], |row| row.get(0))
            .map_err(|e| VaultError::Database(format!("count secrets: {}", e)))?;
        Ok(count as usize)
    }

    /// Get a reference to the underlying connection (for testing).
    #[cfg(test)]
    fn conn(&self) -> &Connection {
        &self.conn
    }
}

// ============================================================================
// TESTS
// ============================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    /// Static 32-byte test key — avoids Argon2id overhead in unit tests.
    fn test_db_key() -> Vec<u8> {
        vec![0x42u8; 32]
    }

    fn wrong_db_key() -> Vec<u8> {
        vec![0x99u8; 32]
    }

    /// Create a temp DB for testing.
    fn test_db() -> (VaultDatabase, NamedTempFile) {
        let tmp = NamedTempFile::new().unwrap_or_else(|e| panic!("tempfile: {:?}", e));
        let db = VaultDatabase::create(tmp.path(), &test_db_key())
            .unwrap_or_else(|e| panic!("create db: {:?}", e));
        (db, tmp)
    }

    /// T2a-1: Create DB → hexdump first bytes → SQLCipher header present, no plaintext.
    #[test]
    fn db_file_is_encrypted() {
        let (db, tmp) = test_db();
        // Store some data to ensure file has content
        db.store_secret(
            "id1",
            "test_key",
            b"encrypted-data",
            &[0u8; 12],
            "standard",
            "",
            "2026-01-01",
            None,
            "static",
        )
        .unwrap_or_else(|e| panic!("store: {:?}", e));
        drop(db);

        // Read first 64 bytes of DB file
        let data = std::fs::read(tmp.path()).unwrap_or_else(|e| panic!("read file: {:?}", e));
        assert!(data.len() > 64, "DB file should have content");

        // SQLCipher file should NOT start with "SQLite format 3\0" (that's unencrypted SQLite)
        let sqlite_header = b"SQLite format 3\0";
        assert_ne!(
            &data[..sqlite_header.len()],
            sqlite_header,
            "DB file should be encrypted — must NOT have plain SQLite header"
        );
    }

    /// T2a-2: Create DB → open with correct key → schema tables exist.
    #[test]
    fn create_and_reopen_with_correct_key() {
        let (_, tmp) = test_db();
        let db = VaultDatabase::open(tmp.path(), &test_db_key())
            .unwrap_or_else(|e| panic!("reopen: {:?}", e));

        let count: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
                [],
                |row| row.get(0),
            )
            .unwrap_or_else(|e| panic!("count: {:?}", e));
        assert_eq!(count, 3, "Expected 3 tables: meta, secrets, audit_log");
    }

    /// T2a-3: Create DB → open with WRONG key → DatabaseKeyInvalid [H-3].
    #[test]
    fn wrong_key_returns_database_key_invalid() {
        let (_, tmp) = test_db();
        let result = VaultDatabase::open(tmp.path(), &wrong_db_key());
        match result {
            Err(VaultError::DatabaseKeyInvalid) => {}
            Err(other) => panic!("Wrong db_key must return DatabaseKeyInvalid, not generic Database error, got: {:?}", other),
            Ok(_) => panic!("Expected error, got Ok"),
        }
    }

    /// T2a-4: Create DB → store data → close → reopen → data persists.
    #[test]
    fn data_persists_across_reopen() {
        let tmp = NamedTempFile::new().unwrap_or_else(|e| panic!("tempfile: {:?}", e));
        {
            let db = VaultDatabase::create(tmp.path(), &test_db_key())
                .unwrap_or_else(|e| panic!("create: {:?}", e));
            db.store_secret(
                "id1",
                "persisted_key",
                b"blob",
                &[0xAAu8; 12],
                "high",
                "",
                "2026-02-08",
                None,
                "static",
            )
            .unwrap_or_else(|e| panic!("store: {:?}", e));
        } // db dropped — connection closed

        let db = VaultDatabase::open(tmp.path(), &test_db_key())
            .unwrap_or_else(|e| panic!("reopen: {:?}", e));
        let (id, blob, nonce, sens, ts, domains) = db
            .get_secret("persisted_key")
            .unwrap_or_else(|e| panic!("get: {:?}", e));
        assert_eq!(id, "id1");
        assert_eq!(blob, b"blob");
        assert_eq!(nonce, vec![0xAAu8; 12]);
        assert_eq!(sens, "high");
        assert_eq!(ts, "2026-02-08");
        assert!(
            domains.is_none(),
            "Legacy secret must have None allowed_domains"
        );
    }

    /// T2a-5: Schema validation — meta CHECK(id=1), secrets has all columns.
    #[test]
    fn schema_constraints() {
        let (db, _tmp) = test_db();

        // meta table: CHECK(id=1) — inserting id=2 should fail
        let result = db
            .conn()
            .execute("INSERT INTO meta (id, data) VALUES (2, 'test')", []);
        assert!(result.is_err(), "meta CHECK(id=1) must reject id=2");

        // secrets table: sensitivity CHECK constraint
        let result = db.conn().execute(
            "INSERT INTO secrets (id, name, encrypted_blob, nonce, sensitivity, created_at)
             VALUES ('x', 'x', X'00', X'000000000000000000000000', 'invalid', '2026-01-01')",
            [],
        );
        assert!(result.is_err(), "sensitivity CHECK must reject 'invalid'");
    }

    /// T2a-6: store_secret with nonce.len() != 12 → error [H-1].
    #[test]
    fn store_invalid_nonce_length_rejected() {
        let (db, _tmp) = test_db();

        // 8-byte nonce (too short)
        let result = db.store_secret(
            "id",
            "name",
            b"blob",
            &[0u8; 8],
            "standard",
            "",
            "2026-01-01",
            None,
            "static",
        );
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            VaultError::InvalidNonce { actual: 8 }
        ));

        // 16-byte nonce (too long)
        let result = db.store_secret(
            "id",
            "name",
            b"blob",
            &[0u8; 16],
            "standard",
            "",
            "2026-01-01",
            None,
            "static",
        );
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            VaultError::InvalidNonce { actual: 16 }
        ));
    }

    /// T2a-7: Manually corrupt nonce in DB → get_secret returns DatabaseCorrupted [H-1, H-3].
    #[test]
    fn corrupted_nonce_in_db_returns_corrupted() {
        let (db, _tmp) = test_db();

        // Store valid secret
        db.store_secret(
            "id1",
            "corrupted_nonce",
            b"blob",
            &[0u8; 12],
            "standard",
            "",
            "2026-01-01",
            None,
            "static",
        )
        .unwrap_or_else(|e| panic!("store: {:?}", e));

        // Manually corrupt nonce to 8 bytes via raw SQL
        db.conn()
            .execute(
                "UPDATE secrets SET nonce = X'0000000000000000' WHERE name = 'corrupted_nonce'",
                [],
            )
            .unwrap_or_else(|e| panic!("corrupt nonce: {:?}", e));

        // get_secret should detect invalid nonce length
        let result = db.get_secret("corrupted_nonce");
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), VaultError::DatabaseCorrupted),
            "Corrupted nonce in DB must return DatabaseCorrupted"
        );
    }
}
