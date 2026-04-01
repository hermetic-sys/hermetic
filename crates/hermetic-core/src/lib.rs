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

// Production builds: forbid(unsafe_code) — absolute prohibition, cannot be overridden.
// Test builds: deny(unsafe_code) — errors by default, but Day 3 memory scan tests
// may use #[allow(unsafe_code)] to inspect raw memory for zeroization verification.
// This is the ONE authorized exception per the Day 3 constitutional amendment.
#![cfg_attr(not(test), forbid(unsafe_code))]

//! Hermetic Core Library
//!
//! Provides the cryptographic foundation for Hermetic:
//!   - kdf: Key derivation chain (Argon2id + HKDF) [Day 1 — CERTIFIED]
//!   - error: Fail-closed typed errors [Day 0 — CERTIFIED]
//!   - crypto: AES-256-GCM per-secret encryption [Day 4]
//!   - vault_meta: Vault metadata schema [Day 4]
//!   - secret: Secret model with sensitivity tagging [Day 4]
//!   - db: SQLCipher encrypted database [Day 4, Linux/macOS only]

pub mod error;
pub mod kdf;

// Day 4: AES-256-GCM + metadata + secret model (all platforms)
pub mod crypto;
pub mod secret;
pub mod vault_meta;

// Day 4: SQLCipher encrypted database (Linux/macOS only — requires OpenSSL)
#[cfg(not(target_os = "windows"))]
pub mod db;

// Day 5: Vault struct + state machine
pub mod vault;

// Day 6: Rate limiter (pure Rust, all platforms)
pub mod rate_limit;

// Day 6: HMAC-chained audit log
// Pure crypto (AuditEntry, compute_*) on all platforms.
// DB-backed AuditLog cfg-gated per CP-001.
pub mod audit;

// Shared terminal UI — color, HC-11 sanitization, structured output (all platforms)
pub mod ui;

// Session persistence — encrypted passphrase for daemon restart recovery
#[cfg(not(target_os = "windows"))]
pub mod session;

// Re-export VaultError at crate root
pub use error::VaultError;
pub use zeroize::Zeroizing;

// v1.1: Secret type discrimination (always compiled, both editions)
pub use vault::{AwsSigV4Secret, OAuth2Secret, SecretType};
