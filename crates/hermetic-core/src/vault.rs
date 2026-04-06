// Copyright (C) 2026 The Hermetic Project <dev@hermeticsys.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licenses available at hermeticsys.com/license

//! Hermetic Vault Struct & State Machine (v1.3.0a)
//!
//! Core vault lifecycle: init → unlock → (add/remove/list/status) → seal
//!
//! INVARIANTS:
//!   - All key material is Zeroizing<Vec<u8>> — zeroized on Drop
//!   - VaultDatabase field is cfg-gated (not available on Windows)
//!   - Drop guard zeroes master_key and db_key unconditionally
//!   - No secret material in error messages, logs, or Debug output
//!
//! IMPLEMENTATION NOTE: Salt stored in sidecar file (vault.salt) because
//! it is required before database can be opened. This is a necessary
//! deviation from VaultMeta-only storage model. Salt is NOT secret
//! (it prevents rainbow tables). VaultMeta continues to store the salt
//! redundantly for integrity verification after DB is opened.

use std::path::{Path, PathBuf};

#[cfg(not(target_os = "windows"))]
use std::collections::HashMap;
#[cfg(not(target_os = "windows"))]
use std::sync::{LazyLock, Mutex};
#[cfg(not(target_os = "windows"))]
use std::time::Instant;

use zeroize::{Zeroize, Zeroizing};

#[cfg(not(target_os = "windows"))]
use crate::db::VaultDatabase;
use crate::error::VaultError;
#[cfg(not(target_os = "windows"))]
use crate::kdf;
#[cfg(not(target_os = "windows"))]
use crate::rate_limit::RateLimiter;
use crate::secret::{SecretEntry, Sensitivity};
use crate::vault_meta::VaultMeta;

// ── Migration Infrastructure (V1.0) ────────────────────────────────────────

/// Result of the migration check during vault open.
#[derive(Debug)]
pub enum MigrationResult {
    /// No migration needed — binary version matches vault version.
    NoMigration,
    /// Migration ran and integrity verified.
    Ok {
        from_version: String,
        secrets_verified: usize,
    },
}

/// Pre-migration check: open a raw SQLCipher connection to read secret count
/// and check if migration columns are missing. Does NOT run migrations.
/// The connection is dropped before returning so VaultDatabase::open() can
/// acquire the file exclusively.
#[cfg(not(target_os = "windows"))]
fn pre_migration_secret_count(db_path: &Path, db_key: &[u8]) -> Result<usize, VaultError> {
    // VaultDatabase::open() runs migrations, but we need the count BEFORE that.
    // Open a raw connection with just the PRAGMA key, count secrets, then close.
    let conn = rusqlite::Connection::open(db_path)
        .map_err(|e| VaultError::Database(format!("pre-migration open: {}", e)))?;
    let hex_key = crate::db::constant_width_hex(db_key);
    let pragma = Zeroizing::new(format!("PRAGMA key = \"x'{}'\";", &*hex_key));
    conn.execute_batch(&pragma)
        .map_err(|e| VaultError::Database(format!("pre-migration key: {}", e)))?;
    conn.execute_batch("PRAGMA cipher_page_size = 4096;")
        .map_err(|e| VaultError::Database(format!("pre-migration cipher_page_size: {}", e)))?;
    conn.execute_batch("PRAGMA kdf_iter = 256000;")
        .map_err(|e| VaultError::Database(format!("pre-migration kdf_iter: {}", e)))?;
    conn.execute_batch("SELECT count(*) FROM sqlite_master;")
        .map_err(|_| VaultError::DatabaseKeyInvalid)?;
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM secrets", [], |row| row.get(0))
        .map_err(|e| VaultError::Database(format!("pre-migration count: {}", e)))?;
    drop(conn); // Release file lock before VaultDatabase::open()
    Ok(count as usize)
}

/// Create a timestamped backup of vault.db before migration.
/// Filename includes version, Unix timestamp, and PID to prevent collisions.
#[cfg(not(target_os = "windows"))]
fn backup_vault(db_path: &Path, from_version: &str) -> Result<PathBuf, VaultError> {
    // Defensive: flush WAL if present (current mode is DELETE, but future-proofs)
    if let Ok(conn) = rusqlite::Connection::open(db_path) {
        let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
    }
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let safe_version = from_version.replace('.', "_");
    let backup_path = db_path.with_extension(format!(
        "db.v{}.{}.{}.bak",
        safe_version,
        ts,
        std::process::id()
    ));
    let temp_path = db_path.with_extension("db.backup.tmp");
    std::fs::copy(db_path, &temp_path)
        .map_err(|e| VaultError::IoError(format!("backup copy: {}", e)))?;
    let f = std::fs::File::open(&temp_path)
        .map_err(|e| VaultError::IoError(format!("backup fsync open: {}", e)))?;
    f.sync_all()
        .map_err(|e| VaultError::IoError(format!("backup fsync: {}", e)))?;
    drop(f);
    std::fs::rename(&temp_path, &backup_path)
        .map_err(|e| VaultError::IoError(format!("backup rename: {}", e)))?;
    // fsync parent directory for rename durability
    if let Some(parent) = backup_path.parent() {
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(backup_path)
}

/// Post-migration integrity check. Two independent count paths must agree.
/// On mismatch: atomic restore from backup.
#[cfg(not(target_os = "windows"))]
fn verify_migration_integrity(
    vault: &Vault,
    pre_count: usize,
    backup_path: &Path,
    db_path: &Path,
) -> Result<(), VaultError> {
    let post_count_raw = vault.secret_count_raw()?;
    let post_count_dec = vault.list_secrets()?.len();

    if post_count_raw != pre_count || post_count_dec != pre_count {
        // Atomic restore from backup
        let temp = db_path.with_extension("db.restoring");
        std::fs::copy(backup_path, &temp)
            .map_err(|e| VaultError::MigrationRestoreFailed(format!("copy backup: {}", e)))?;
        let f = std::fs::File::open(&temp)
            .map_err(|e| VaultError::MigrationRestoreFailed(format!("fsync open: {}", e)))?;
        f.sync_all()
            .map_err(|e| VaultError::MigrationRestoreFailed(format!("fsync: {}", e)))?;
        drop(f);
        std::fs::rename(&temp, db_path)
            .map_err(|e| VaultError::MigrationRestoreFailed(format!("rename: {}", e)))?;
        if let Some(parent) = db_path.parent() {
            if let Ok(dir) = std::fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
        return Err(VaultError::MigrationIntegrityFail {
            expected: pre_count,
            got_raw: post_count_raw,
            got_dec: post_count_dec,
        });
    }
    Ok(())
}

// ── Secret Type Discrimination (v1.1) ──────────────────────────────────────
// Always compiled in BOTH editions. Community uses SecretType for upgrade
// funnel UX: `hermetic list` shows "OAuth2" type + "Unavailable (Pro)" health.

/// Secret content type, determined post-decryption.
///
/// Static secrets are raw byte strings (API keys, tokens, passwords).
/// OAuth2 secrets are JSON-serialized composites containing client credentials
/// and a refresh token. The encrypted blob format is identical — the difference
/// is purely in the interpretation of the decrypted bytes.
#[derive(Clone, Debug)]
pub enum SecretType {
    /// Raw secret value (API key, token, password). Used for Bearer/ApiKey injection.
    Static(Zeroizing<Vec<u8>>),
    /// OAuth2 composite: client_id + client_secret + refresh_token + endpoint.
    OAuth2(OAuth2Secret),
    /// AWS SigV4: access_key_id + secret_access_key + region + optional service binding.
    AwsSigV4(AwsSigV4Secret),
}

/// OAuth2 composite secret fields. Data struct only — no refresh logic.
///
/// Fields are plain Strings (not Zeroizing) because serde::Deserialize cannot
/// derive for Zeroizing wrappers. The CALLER holds the decrypted bytes in a
/// Zeroizing<Vec<u8>> — this parsed struct is ephemeral, created and dropped
/// within the same scope.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct OAuth2Secret {
    /// Must be "oauth2". Used for type detection in from_decrypted().
    #[serde(rename = "type")]
    pub secret_type: String,
    pub client_id: String,
    pub client_secret: String,
    pub refresh_token: String,
    /// OAuth2 token endpoint URL (must be HTTPS).
    pub token_endpoint: String,
    /// OAuth2 scopes (space-separated when sent to provider).
    #[serde(default)]
    pub scopes: Vec<String>,
}

/// AWS SigV4 composite secret fields. Data struct only — signing engine is Pro.
///
/// access_key_id is NOT Zeroizing — it appears in plaintext in the Authorization
/// header and is visible in CloudTrail. Same treatment as OAuth2's client_id.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct AwsSigV4Secret {
    #[serde(rename = "type")]
    pub secret_type: String, // must be "aws_sigv4"
    /// AWS access key ID (public identifier).
    pub access_key_id: String,
    /// AWS secret access key (sensitive — Zeroizing at call site).
    pub secret_access_key: String,
    /// STS session token (optional, sensitive).
    #[serde(default)]
    pub session_token: Option<String>,
    /// AWS region (e.g. "us-east-1").
    pub region: String,
    /// Optional service binding (SG-3). None = infer from URL.
    #[serde(default)]
    pub service: Option<String>,
}

impl SecretType {
    /// Post-decryption type detection. Always compiled in both editions.
    ///
    /// Tries to parse `bytes` as JSON with `"type": "oauth2"`. If the parse
    /// succeeds and all required fields are present, returns `OAuth2`.
    /// Otherwise returns `Static` with the raw bytes.
    ///
    /// M-6: If JSON parse fails on a blob that was INTENDED to be OAuth2,
    /// this returns Static (wrong type but safe). The daemon issues a handle
    /// with the raw blob, transport injects it as Bearer, the API call fails,
    /// IC-1 denied() propagates. No type information leaks.
    pub fn from_decrypted(bytes: &[u8]) -> Self {
        // Fast path: most secrets are not JSON
        if bytes.first() != Some(&b'{') {
            return SecretType::Static(Zeroizing::new(bytes.to_vec()));
        }
        // Try JSON parse with "type" marker
        if let Ok(val) = serde_json::from_slice::<serde_json::Value>(bytes) {
            match val.get("type").and_then(|t| t.as_str()) {
                Some("oauth2") => {
                    if let Ok(composite) = serde_json::from_slice::<OAuth2Secret>(bytes) {
                        return SecretType::OAuth2(composite);
                    }
                }
                Some("aws_sigv4") => {
                    if let Ok(aws) = serde_json::from_slice::<AwsSigV4Secret>(bytes) {
                        return SecretType::AwsSigV4(aws);
                    }
                }
                _ => {}
            }
        }
        // Legacy flat string or unrecognized JSON (M-6: safe fallback)
        SecretType::Static(Zeroizing::new(bytes.to_vec()))
    }

    /// Returns true if this is an OAuth2 composite secret.
    pub fn is_oauth2(&self) -> bool {
        matches!(self, SecretType::OAuth2(_))
    }

    /// Returns true if this is an AWS SigV4 composite secret.
    pub fn is_aws_sigv4(&self) -> bool {
        matches!(self, SecretType::AwsSigV4(_))
    }
}

/// Process-global rate limiters, keyed by vault path.
#[cfg(not(target_os = "windows"))]
static RATE_LIMITERS: LazyLock<Mutex<HashMap<PathBuf, RateLimiter>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Trait for types convertible to Sensitivity in vault operations.
/// Allows add_secret to accept both `Sensitivity` and `&str`.
pub trait IntoSensitivity {
    fn into_sensitivity(self) -> Result<Sensitivity, VaultError>;
}

impl IntoSensitivity for Sensitivity {
    fn into_sensitivity(self) -> Result<Sensitivity, VaultError> {
        Ok(self)
    }
}

impl IntoSensitivity for &str {
    fn into_sensitivity(self) -> Result<Sensitivity, VaultError> {
        Sensitivity::parse(self)
    }
}

/// Vault operational state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultState {
    Sealed,
    Unsealed,
}

/// Status information for display — contains NO secret material.
#[derive(Debug, Clone)]
pub struct VaultStatus {
    pub mode: String,
    pub state: VaultState,
    pub secret_count: usize,
    pub passphrase_enrolled: bool,
    pub device_key_enrolled: bool,
    pub biometric_enrolled: bool,
}

/// The Hermetic vault. Holds derived key material and database connection.
///
/// No Display, no Clone — structurally prevents accidental leakage.
/// Drop guard zeroes all key material unconditionally.
pub struct Vault {
    master_key: Zeroizing<Vec<u8>>,
    db_key: Zeroizing<Vec<u8>>,
    #[cfg(not(target_os = "windows"))]
    audit_key: Zeroizing<Vec<u8>>,
    #[cfg_attr(target_os = "windows", allow(dead_code))]
    vault_path: PathBuf,
    #[cfg_attr(target_os = "windows", allow(dead_code))]
    meta: VaultMeta,
    #[cfg(not(target_os = "windows"))]
    db: VaultDatabase,
}

impl Drop for Vault {
    fn drop(&mut self) {
        self.master_key.zeroize();
        self.db_key.zeroize();
        #[cfg(not(target_os = "windows"))]
        self.audit_key.zeroize();
    }
}

impl Vault {
    /// Create a new vault at `path`.
    ///
    /// Generates salt, derives full key chain via Argon2id + HKDF,
    /// creates SQLCipher database, stores metadata and verifier.
    /// Mode defaults to "software" (Phase 1 scope).
    ///
    /// Re-init on existing vault → AlreadyInitialized (DENY).
    /// Passphrase < 12 chars → PassphraseTooShort (DENY).
    #[cfg(not(target_os = "windows"))]
    pub fn init(path: &Path, passphrase: &Zeroizing<Vec<u8>>) -> Result<(), VaultError> {
        let db_path = path.join("vault.db");
        if db_path.exists() {
            return Err(VaultError::AlreadyInitialized);
        }

        if !path.exists() {
            std::fs::create_dir_all(path)?;
        }

        let salt = kdf::generate_vault_salt()?;
        let keys = kdf::derive_full_chain(passphrase, &salt)?;

        let db = VaultDatabase::create(&db_path, &keys.db_key)?;

        let meta = VaultMeta::new_software(&salt, &keys.verifier, 262144, 4, 2);
        db.store_meta(&meta)?;

        // Write salt sidecar (salt is NOT secret — prevents rainbow tables)
        write_salt_sidecar(path, &salt)?;

        // M4-02: Explicit 0600 on vault.db and vault.salt (don't rely on umask)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&db_path, std::fs::Permissions::from_mode(0o600));
            let salt_path = path.join("vault.salt");
            let _ = std::fs::set_permissions(&salt_path, std::fs::Permissions::from_mode(0o600));
        }

        Ok(())
    }

    /// Windows stub — init is not available without SQLCipher.
    #[cfg(target_os = "windows")]
    pub fn init(_path: &Path, _passphrase: &Zeroizing<Vec<u8>>) -> Result<(), VaultError> {
        Err(VaultError::Database(
            "SQLCipher not available on Windows (platform-gated)".into(),
        ))
    }

    /// Unlock an existing vault by verifying passphrase against stored HMAC verifier.
    ///
    /// Reads salt from sidecar, derives keys, opens DB, verifies passphrase.
    /// Returns a live Vault with Unsealed state.
    ///
    /// Wrong passphrase → InvalidPassphrase or DatabaseKeyInvalid (DENY/SEAL).
    /// Missing vault → NotInitialized (DENY).
    #[cfg(not(target_os = "windows"))]
    pub fn unlock(path: &Path, passphrase: &Zeroizing<Vec<u8>>) -> Result<Vault, VaultError> {
        let canonical = path.to_path_buf();

        // Passphrase-context Mutex poison: LOCKOUT_DURATION_SECS (900s) is intentional.
        // Operation-context paths use OPERATION_WINDOW_SECS (60s) instead.
        // Check rate limiter BEFORE attempting unlock
        {
            let limiters = RATE_LIMITERS.lock().map_err(|_| VaultError::Denied {
                reason: "internal state error".into(),
            })?;
            if let Some(limiter) = limiters.get(&canonical) {
                limiter.check_allowed()?;
            }
        }

        // Try the actual unlock
        let result = Self::unlock_inner(path, passphrase);

        // Update rate limiter based on result
        match &result {
            Ok(_) => {
                let mut limiters = RATE_LIMITERS.lock().map_err(|_| VaultError::Denied {
                    reason: "internal state error".into(),
                })?;
                let limiter = limiters.entry(canonical).or_insert_with(RateLimiter::new);
                limiter.record_success();
            }
            Err(VaultError::InvalidPassphrase) | Err(VaultError::DatabaseKeyInvalid) => {
                let mut limiters = RATE_LIMITERS.lock().map_err(|_| VaultError::Denied {
                    reason: "internal state error".into(),
                })?;
                let limiter = limiters.entry(canonical).or_insert_with(RateLimiter::new);
                limiter.record_failure();
            }
            _ => {} // Other errors don't count as passphrase failures
        }

        result
    }

    /// Inner unlock logic — separated for rate limiter integration.
    #[cfg(not(target_os = "windows"))]
    fn unlock_inner(path: &Path, passphrase: &Zeroizing<Vec<u8>>) -> Result<Vault, VaultError> {
        let db_path = path.join("vault.db");
        if !db_path.exists() {
            return Err(VaultError::NotInitialized);
        }

        // Read salt from sidecar file
        let salt_path = path.join("vault.salt");
        if !salt_path.exists() {
            return Err(VaultError::CorruptedMeta);
        }

        let salt_hex = std::fs::read_to_string(&salt_path)?;
        let salt_bytes = hex::decode(salt_hex.trim()).map_err(|_| VaultError::CorruptedMeta)?;
        if salt_bytes.len() != 32 {
            return Err(VaultError::CorruptedMeta);
        }
        let mut salt = [0u8; 32];
        salt.copy_from_slice(&salt_bytes);

        // Derive full key chain from passphrase + salt
        let keys = kdf::derive_full_chain(passphrase, &salt)?;

        // Pre-migration: capture secret count BEFORE VaultDatabase::open() runs migrations.
        // Uses a raw SQLCipher connection that is dropped before the real open.
        let pre_count = pre_migration_secret_count(&db_path, &keys.db_key)?;

        // Open encrypted database with derived db_key (migrations run here)
        let db = VaultDatabase::open(&db_path, &keys.db_key)?;

        // Load metadata and verify passphrase via HMAC verifier
        let mut meta = db.get_meta()?;
        let stored_verifier = meta.passphrase_verifier_bytes()?;
        kdf::verify_passphrase(&keys.master_key, &stored_verifier)?;

        // Update binary_version on every unlock; backup + verify if version changed
        let current_version = env!("CARGO_PKG_VERSION").to_string();
        let prev_version = meta.binary_version.clone();
        if prev_version != current_version {
            // Version delta — back up before any meta write
            let backup_path = backup_vault(&db_path, &prev_version)?;
            meta.binary_version = current_version;
            db.store_meta(&meta)?;
            // Verify migration integrity (pre-count vs post-count)
            let vault_ref = Vault {
                master_key: keys.master_key.clone(),
                db_key: keys.db_key.clone(),
                audit_key: keys.audit_key.clone(),
                vault_path: path.to_path_buf(),
                meta: meta.clone(),
                db: VaultDatabase::open(&db_path, &keys.db_key)?,
            };
            verify_migration_integrity(&vault_ref, pre_count, &backup_path, &db_path)?;
            drop(vault_ref);
            // Re-open after verification (vault_ref consumed the connection)
            let db = VaultDatabase::open(&db_path, &keys.db_key)?;
            let meta = db.get_meta()?;
            return Ok(Vault {
                master_key: keys.master_key,
                db_key: keys.db_key,
                audit_key: keys.audit_key,
                vault_path: path.to_path_buf(),
                meta,
                db,
            });
        } else {
            // No version delta — no migration needed
        };

        Ok(Vault {
            master_key: keys.master_key,
            db_key: keys.db_key,
            audit_key: keys.audit_key,
            vault_path: path.to_path_buf(),
            meta,
            db,
        })
    }

    /// Windows stub — unlock is not available without SQLCipher.
    #[cfg(target_os = "windows")]
    pub fn unlock(_path: &Path, _passphrase: &Zeroizing<Vec<u8>>) -> Result<Vault, VaultError> {
        Err(VaultError::Database(
            "SQLCipher not available on Windows (platform-gated)".into(),
        ))
    }

    /// Raw secret count — no decryption, exercises SQL path only.
    #[cfg(not(target_os = "windows"))]
    pub fn secret_count_raw(&self) -> Result<usize, VaultError> {
        self.db.secret_count_raw()
    }

    /// Seal the vault — consumes self, triggering Drop guard.
    /// master_key and db_key are zeroized via Drop.
    pub fn seal(self) {
        drop(self);
    }

    /// Seal the vault with audit trail and session cleanup.
    /// Order: audit → session destroy → key zeroization.
    /// Errors in audit/session are non-fatal (seal MUST proceed).
    #[cfg(not(target_os = "windows"))]
    pub fn seal_with_audit(self) {
        if let Err(e) = self.write_audit_entry("vault_sealed", None) {
            eprintln!("  ! Audit write failed during seal: {e}");
        }
        let session_mgr = crate::session::SessionManager::new(&self.vault_path);
        if let Err(e) = session_mgr.destroy() {
            eprintln!("  ! Session cleanup failed during seal: {e}");
        }
        drop(self);
    }

    /// Add a secret to the vault.
    ///
    /// Strips ONE trailing newline (\n or \r\n) from the value before storage.
    /// Rejects empty values (after stripping) with EmptySecret (DENY).
    /// Derives a unique KEK for this secret via HKDF, encrypts the value
    /// with AES-256-GCM, stores ciphertext + nonce in the database.
    ///
    /// Empty value → EmptySecret (DENY).
    /// Duplicate name → SecretAlreadyExists (DENY).
    #[cfg(not(target_os = "windows"))]
    pub fn add_secret(
        &self,
        name: &str,
        value: &Zeroizing<Vec<u8>>,
        sensitivity: impl IntoSensitivity,
        tags: Option<&str>,
        allowed_domains: Option<Vec<String>>,
    ) -> Result<(), VaultError> {
        // Operation-context rate limit check BEFORE proceeding
        {
            let limiters = RATE_LIMITERS.lock().map_err(|_| VaultError::RateLimited {
                retry_after_secs: RateLimiter::OPERATION_WINDOW_SECS,
            })?;
            if let Some(limiter) = limiters.get(&self.vault_path) {
                limiter.check_operation_allowed()?;
            }
        }

        let sensitivity = sensitivity.into_sensitivity()?;

        // Strip ONE trailing newline (defense-in-depth: enforced at API layer
        // so every caller — CLI, SDK, daemon — gets consistent behavior)
        let mut cleaned = Zeroizing::new(value.to_vec());
        if cleaned.last() == Some(&b'\n') {
            cleaned.pop();
        }
        if cleaned.last() == Some(&b'\r') {
            cleaned.pop();
        }

        // Reject empty secrets BEFORE any DB or audit operation
        if cleaned.is_empty() {
            return Err(VaultError::EmptySecret);
        }

        // Detect secret type from plaintext BEFORE encryption (stored as metadata).
        // No decryption needed at list-time — type is in the row.
        let secret_type_str = if SecretType::from_decrypted(&cleaned).is_oauth2() {
            "oauth2"
        } else {
            "static"
        };

        let secret_id = uuid::Uuid::new_v4().to_string();
        let kek = kdf::derive_kek(&self.master_key, &secret_id)?;
        let (ciphertext, nonce) = crate::crypto::encrypt_secret(&kek, &secret_id, &cleaned)?;
        let created_at = current_timestamp();

        let normalized = normalize_domains(allowed_domains);
        let domains_json = normalized
            .as_ref()
            .map(|d| serde_json::to_string(d).expect("Vec<String> always serializes"));

        self.db.store_secret(
            &secret_id,
            name,
            &ciphertext,
            &nonce,
            sensitivity.as_str(),
            tags.unwrap_or(""),
            &created_at,
            domains_json.as_deref(),
            secret_type_str,
        )?;

        // Audit entry — failure to audit is fail-closed (SEAL)
        self.write_audit_entry("add_secret", Some(name))?;

        // Record successful operation for rate limiting
        {
            let mut limiters = RATE_LIMITERS.lock().map_err(|_| VaultError::RateLimited {
                retry_after_secs: RateLimiter::OPERATION_WINDOW_SECS,
            })?;
            let limiter = limiters
                .entry(self.vault_path.clone())
                .or_insert_with(RateLimiter::new);
            limiter.record_operation_at(Instant::now());
        }

        Ok(())
    }

    /// Windows stub.
    #[cfg(target_os = "windows")]
    pub fn add_secret(
        &self,
        _name: &str,
        _value: &Zeroizing<Vec<u8>>,
        _sensitivity: impl IntoSensitivity,
        _tags: Option<&str>,
        _allowed_domains: Option<Vec<String>>,
    ) -> Result<(), VaultError> {
        Err(VaultError::Database(
            "SQLCipher not available on Windows (platform-gated)".into(),
        ))
    }

    /// Remove a secret by name.
    ///
    /// Not found → SecretNotFound (DENY).
    #[cfg(not(target_os = "windows"))]
    pub fn remove_secret(&self, name: &str) -> Result<(), VaultError> {
        // R-14: Refuse to remove a reveal-tagged secret directly.
        // Clear the tag first: hermetic reveal --clear (passphrase-gated).
        if self.get_reveal_key_name() == Some(name) {
            return Err(VaultError::Denied {
                reason: "secret is tagged as reveal key; clear first: hermetic reveal --clear"
                    .into(),
            });
        }

        // Operation-context rate limit check BEFORE proceeding
        {
            let limiters = RATE_LIMITERS.lock().map_err(|_| VaultError::RateLimited {
                retry_after_secs: RateLimiter::OPERATION_WINDOW_SECS,
            })?;
            if let Some(limiter) = limiters.get(&self.vault_path) {
                limiter.check_operation_allowed()?;
            }
        }

        self.db.delete_secret(name)?;
        self.write_audit_entry("remove_secret", Some(name))?;

        // Record successful operation for rate limiting
        {
            let mut limiters = RATE_LIMITERS.lock().map_err(|_| VaultError::RateLimited {
                retry_after_secs: RateLimiter::OPERATION_WINDOW_SECS,
            })?;
            let limiter = limiters
                .entry(self.vault_path.clone())
                .or_insert_with(RateLimiter::new);
            limiter.record_operation_at(Instant::now());
        }

        Ok(())
    }

    /// Windows stub.
    #[cfg(target_os = "windows")]
    pub fn remove_secret(&self, _name: &str) -> Result<(), VaultError> {
        Err(VaultError::Database(
            "SQLCipher not available on Windows (platform-gated)".into(),
        ))
    }

    /// Retrieve and decrypt a secret's raw bytes.
    ///
    /// Uses existing internal decrypt chain: db lookup → KEK derivation → decrypt.
    /// Returns Zeroizing<Vec<u8>> — caller MUST handle zeroization.
    ///
    /// SCOPE-EXCEPTION-1: Added in Stage 2.7.4c for handle redemption path.
    #[cfg(not(target_os = "windows"))]
    pub fn get_secret_bytes(&self, name: &str) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        let (id, ciphertext, nonce, _sensitivity, _created_at, _domains) =
            self.db.get_secret(name)?;
        let kek = kdf::derive_kek(&self.master_key, &id)?;
        crate::crypto::decrypt_secret(&kek, &id, &ciphertext, &nonce)
    }

    /// Windows stub.
    #[cfg(target_os = "windows")]
    pub fn get_secret_bytes(&self, _name: &str) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        Err(VaultError::Database(
            "SQLCipher not available on Windows (platform-gated)".into(),
        ))
    }

    /// Update a secret's encrypted value in-place, preserving its UUID and metadata.
    ///
    /// Used for OAuth2 refresh token rotation: the provider issues a new
    /// refresh_token alongside the access token, and we must persist it.
    ///
    /// Operation: look up UUID → derive KEK (same as original) → re-encrypt
    /// new value → UPDATE row. The UUID is preserved, so the KEK derivation
    /// path is identical. The fingerprint (SHA-256 of decrypted bytes) will
    /// change, correctly invalidating all existing handles (HC-10).
    ///
    /// Rate-limited. Audit-logged as "rotate_secret".
    #[cfg(not(target_os = "windows"))]
    pub fn update_secret_value(
        &self,
        name: &str,
        new_value: &Zeroizing<Vec<u8>>,
    ) -> Result<(), VaultError> {
        // Operation-context rate limit check
        {
            let limiters = RATE_LIMITERS.lock().map_err(|_| VaultError::RateLimited {
                retry_after_secs: RateLimiter::OPERATION_WINDOW_SECS,
            })?;
            if let Some(limiter) = limiters.get(&self.vault_path) {
                limiter.check_operation_allowed()?;
            }
        }

        if new_value.is_empty() {
            return Err(VaultError::EmptySecret);
        }

        // Get existing secret's UUID for KEK derivation (preserves identity)
        let (id, _, _, _, _, _) = self.db.get_secret(name)?;
        let kek = kdf::derive_kek(&self.master_key, &id)?;
        let (ciphertext, nonce) = crate::crypto::encrypt_secret(&kek, &id, new_value)?;
        let rotated_at = current_timestamp();

        self.db
            .update_secret_blob(name, &ciphertext, &nonce, &rotated_at)?;

        // Audit entry — failure to audit is fail-closed (SEAL)
        self.write_audit_entry("rotate_secret", Some(name))?;

        // Record successful operation for rate limiting
        {
            let mut limiters = RATE_LIMITERS.lock().map_err(|_| VaultError::RateLimited {
                retry_after_secs: RateLimiter::OPERATION_WINDOW_SECS,
            })?;
            let limiter = limiters
                .entry(self.vault_path.clone())
                .or_insert_with(RateLimiter::new);
            limiter.record_operation_at(Instant::now());
        }

        Ok(())
    }

    /// Windows stub.
    #[cfg(target_os = "windows")]
    pub fn update_secret_value(
        &self,
        _name: &str,
        _new_value: &Zeroizing<Vec<u8>>,
    ) -> Result<(), VaultError> {
        Err(VaultError::Database(
            "SQLCipher not available on Windows (platform-gated)".into(),
        ))
    }

    /// List all secrets — returns metadata ONLY (name, sensitivity, dates).
    /// NEVER returns secret values, ciphertext, or key material.
    #[cfg(not(target_os = "windows"))]
    pub fn list_secrets(&self) -> Result<Vec<SecretEntry>, VaultError> {
        let rows = self.db.list_secrets()?;
        let mut entries = Vec::with_capacity(rows.len());
        for (name, sensitivity_str, created_at, tags, allowed_domains, secret_type) in rows {
            let sensitivity = Sensitivity::parse(&sensitivity_str)?;
            entries.push(SecretEntry {
                id: String::new(),
                name,
                sensitivity,
                created_at,
                rotated_at: None,
                tags,
                allowed_domains,
                secret_type,
            });
        }
        Ok(entries)
    }

    /// Get tags for a specific secret by name (without decrypting).
    #[cfg(not(target_os = "windows"))]
    pub fn get_secret_tags(&self, name: &str) -> Result<String, VaultError> {
        self.db.get_secret_tags(name)
    }

    /// Windows stub.
    #[cfg(target_os = "windows")]
    pub fn get_secret_tags(&self, _name: &str) -> Result<String, VaultError> {
        Err(VaultError::Database(
            "SQLCipher not available on Windows (platform-gated)".into(),
        ))
    }

    /// Windows stub.
    #[cfg(target_os = "windows")]
    pub fn list_secrets(&self) -> Result<Vec<SecretEntry>, VaultError> {
        Err(VaultError::Database(
            "SQLCipher not available on Windows (platform-gated)".into(),
        ))
    }

    /// Get vault status — NO secret material, only operational metadata.
    #[cfg(not(target_os = "windows"))]
    pub fn status(&self) -> VaultStatus {
        let count = self.db.list_secrets().map(|s| s.len()).unwrap_or(0);
        VaultStatus {
            mode: self.meta.mode.clone(),
            state: VaultState::Unsealed,
            secret_count: count,
            passphrase_enrolled: !self.meta.passphrase_verifier.is_empty(),
            device_key_enrolled: self.meta.device_key_enrolled,
            biometric_enrolled: self.meta.biometric_enrolled,
        }
    }

    /// Windows stub — Vault can never be constructed on Windows,
    /// so this method is unreachable in practice.
    #[cfg(target_os = "windows")]
    pub fn status(&self) -> VaultStatus {
        VaultStatus {
            mode: String::new(),
            state: VaultState::Sealed,
            secret_count: 0,
            passphrase_enrolled: false,
            device_key_enrolled: false,
            biometric_enrolled: false,
        }
    }

    /// Get the audit chain anchor (set after CL-2 pruning).
    /// Returns None if no pruning has occurred.
    pub fn audit_chain_anchor(&self) -> Option<&str> {
        self.meta.audit_chain_anchor.as_deref()
    }

    /// HM-EXEC-REVEAL-001: Get the reveal key name from vault metadata.
    pub fn get_reveal_key_name(&self) -> Option<&str> {
        self.meta.reveal_key_name.as_deref()
    }

    /// HM-EXEC-REVEAL-001: Set or clear the reveal key name in vault metadata.
    /// Persists to database AND updates in-memory meta immediately.
    #[cfg(not(target_os = "windows"))]
    pub fn set_reveal_key_name(&mut self, name: Option<&str>) -> Result<(), VaultError> {
        let mut db_meta = self.db.get_meta()?;
        db_meta.reveal_key_name = name.map(|s| s.to_string());
        self.db.store_meta(&db_meta)?;
        self.meta.reveal_key_name = name.map(|s| s.to_string());
        Ok(())
    }

    /// HM-EXEC-REVEAL-001: Verify passphrase inline (Argon2id re-derivation).
    /// Used for passphrase-gated reveal operations (set/clear/remove-tagged).
    #[cfg(not(target_os = "windows"))]
    pub fn verify_passphrase(&self, passphrase: &[u8]) -> Result<(), VaultError> {
        let salt = self.meta.vault_salt_bytes()?;
        let keys = kdf::derive_full_chain(passphrase, &salt)?;
        let stored_verifier = self.meta.passphrase_verifier_bytes()?;
        kdf::verify_passphrase(&keys.master_key, &stored_verifier)
    }

    /// Get an AuditLog handle for reading/verifying the audit chain.
    /// Opens a separate DB connection (audit_key is Zeroizing).
    #[cfg(not(target_os = "windows"))]
    pub fn audit_log(&self) -> Result<crate::audit::AuditLog, VaultError> {
        crate::audit::AuditLog::open(
            &self.vault_path.join("vault.db"),
            &self.db_key,
            Zeroizing::new(self.audit_key.to_vec()),
        )
    }

    /// HM-EXEC-REVEAL-001 R-15: Public audit entry writer for daemon dispatch.
    /// Fail-closed: AuditFailure → SEAL. Must be called BEFORE returning secret value.
    #[cfg(not(target_os = "windows"))]
    pub fn write_audit_entry_public(
        &self,
        action: &str,
        secret_name: Option<&str>,
    ) -> Result<(), VaultError> {
        self.write_audit_entry(action, secret_name)
    }

    /// Write an audit entry for a vault operation.
    /// Failure to write is fail-closed (returns AuditFailure → SEAL).
    #[cfg(not(target_os = "windows"))]
    fn write_audit_entry(&self, action: &str, secret_name: Option<&str>) -> Result<(), VaultError> {
        let audit_log = self.audit_log()?;
        let entry = crate::audit::AuditEntry {
            timestamp: current_timestamp(),
            action: action.to_string(),
            secret_name: secret_name.map(|s| s.to_string()),
            agent: None,
            details: None,
        };
        audit_log.write_entry(&entry)
    }

    /// CL-2: Prune audit log entries older than `retention_days`.
    /// Updates the chain anchor in VaultMeta so verification works after pruning.
    /// Returns the number of deleted entries.
    #[cfg(not(target_os = "windows"))]
    pub fn prune_audit_log(&self, retention_days: u32) -> Result<u64, VaultError> {
        let cutoff = compute_cutoff_timestamp(retention_days);
        let audit = self.audit_log()?;
        let (count, anchor) = audit.delete_entries_before(&cutoff)?;
        if count > 0 {
            if let Some(ref anchor_hex) = anchor {
                let mut meta = self.db.get_meta()?;
                meta.audit_chain_anchor = Some(anchor_hex.clone());
                self.db.store_meta(&meta)?;
            }
        }
        Ok(count)
    }
}

/// Compute an ISO 8601 cutoff timestamp by subtracting `days` from now.
#[cfg(not(target_os = "windows"))]
fn compute_cutoff_timestamp(days: u32) -> String {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let cutoff_secs = duration.as_secs().saturating_sub(days as u64 * 86400);

    // Convert epoch seconds to ISO 8601
    let days_total = cutoff_secs / 86400;
    let time_of_day = cutoff_secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    let mut y = 1970i64;
    let mut remaining_days = days_total as i64;
    loop {
        let days_in_year = if is_leap_year(y) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        y += 1;
    }

    let leap = is_leap_year(y);
    let month_days: [i64; 12] = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 0u32;
    for (i, &md) in month_days.iter().enumerate() {
        if remaining_days < md {
            month = i as u32 + 1;
            break;
        }
        remaining_days -= md;
    }
    if month == 0 {
        month = 12;
    }
    let day = remaining_days + 1;

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y, month, day, hours, minutes, seconds
    )
}

/// Normalize domain list for MCP-7 domain binding persistence.
/// Lowercases, strips scheme/port/trailing dots, removes empties.
pub fn normalize_domains(domains: Option<Vec<String>>) -> Option<Vec<String>> {
    domains.map(|ds| {
        ds.into_iter()
            .map(|d| {
                d.trim()
                    .to_ascii_lowercase()
                    .trim_start_matches("http://")
                    .trim_start_matches("https://")
                    .trim_end_matches('.')
                    .split(':')
                    .next()
                    .unwrap_or("")
                    .trim_end_matches('.')
                    .to_string()
            })
            .filter(|d| !d.is_empty())
            .collect()
    })
}

/// Write the vault salt to a sidecar file alongside vault.db.
///
/// IMPLEMENTATION NOTE: The salt is needed to derive db_key (via HKDF),
/// but db_key is needed to open the SQLCipher database where VaultMeta
/// (containing the salt) is stored. This sidecar resolves the
/// chicken-and-egg problem. The salt is NOT secret.
#[cfg(not(target_os = "windows"))]
fn write_salt_sidecar(path: &Path, salt: &[u8; 32]) -> Result<(), VaultError> {
    let salt_path = path.join("vault.salt");
    std::fs::write(&salt_path, hex::encode(salt))?;
    Ok(())
}

/// Generate an ISO 8601 UTC timestamp string.
#[cfg(not(target_os = "windows"))]
fn current_timestamp() -> String {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    let mut y = 1970i64;
    let mut remaining_days = days as i64;
    loop {
        let days_in_year = if is_leap_year(y) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        y += 1;
    }

    let leap = is_leap_year(y);
    let month_days: [i64; 12] = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut m = 0usize;
    for (i, &md) in month_days.iter().enumerate() {
        if remaining_days < md {
            m = i;
            break;
        }
        remaining_days -= md;
    }

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y,
        m + 1,
        remaining_days + 1,
        hours,
        minutes,
        seconds
    )
}

#[cfg(not(target_os = "windows"))]
fn is_leap_year(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}
