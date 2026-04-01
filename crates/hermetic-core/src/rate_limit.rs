// Copyright (C) 2026 The Hermetic Project <dev@hermeticsys.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licenses available at hermeticsys.com/license

//! Hermetic Rate Limiter (v1.3.0a)
//!
//! Pure Rust state tracking for brute-force protection.
//! No database dependency, no filesystem, no secrets.
//!
//! INVARIANTS:
//!   - 5 consecutive failures → 15-minute lockout
//!   - Correct passphrase resets counter
//!   - Injectable time source for testability (no thread::sleep)
//!   - RateLimited → FailClosedAction::Deny
//!   - Operation rate limiting: MAX_OPERATIONS_PER_MINUTE within OPERATION_WINDOW_SECS
//!   - Mutex poisoning → fail-closed (DENY with LOCKOUT_DURATION_SECS)
//!   - Counter overflow → saturating_add, deny at u64::MAX

use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::error::VaultError;

/// Maximum consecutive failed passphrase attempts before lockout.
const MAX_ATTEMPTS: u32 = 5;

/// Lockout duration in seconds (15 minutes).
const LOCKOUT_DURATION_SECS: u64 = 900;

/// Maximum operations (add/remove) per minute before rate limiting.
const MAX_OPERATIONS_PER_MINUTE: u64 = 60;

/// Operation rate limit window in seconds.
const OPERATION_WINDOW_SECS: u64 = 60;

/// Tracks consecutive failed passphrase attempts, lockout state,
/// and operation rate limiting. Pure state — no DB, no filesystem, no secrets.
pub struct RateLimiter {
    // Passphrase rate limiting fields
    failure_count: u32,
    lockout_start: Option<Instant>,
    // Operation rate limiting fields
    operation_count: u64,
    operation_window_start: Option<Instant>,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimiter {
    pub const MAX_ATTEMPTS: u32 = MAX_ATTEMPTS;
    pub const LOCKOUT_DURATION_SECS: u64 = LOCKOUT_DURATION_SECS;
    pub const MAX_OPERATIONS_PER_MINUTE: u64 = MAX_OPERATIONS_PER_MINUTE;
    pub const OPERATION_WINDOW_SECS: u64 = OPERATION_WINDOW_SECS;

    pub fn new() -> Self {
        RateLimiter {
            failure_count: 0,
            lockout_start: None,
            operation_count: 0,
            operation_window_start: None,
        }
    }

    // ---- Passphrase rate limiting (existing, unchanged) ----

    /// Check if an unlock attempt is allowed at the current time.
    pub fn check_allowed(&self) -> Result<(), VaultError> {
        self.check_allowed_at(Instant::now())
    }

    /// Check if an unlock attempt is allowed at a specific time.
    /// Injectable time source for deterministic testing.
    pub fn check_allowed_at(&self, now: Instant) -> Result<(), VaultError> {
        if let Some(start) = self.lockout_start {
            let elapsed = now.duration_since(start);
            if elapsed < Duration::from_secs(LOCKOUT_DURATION_SECS) {
                let remaining = LOCKOUT_DURATION_SECS - elapsed.as_secs();
                return Err(VaultError::RateLimited {
                    retry_after_secs: remaining,
                });
            }
        }
        Ok(())
    }

    /// Record a failed passphrase attempt at the current time.
    /// Returns true if the maximum attempt count has been reached.
    pub fn record_failure(&mut self) -> bool {
        self.record_failure_at(Instant::now())
    }

    /// Record a failed passphrase attempt at a specific time.
    /// Returns true if the maximum attempt count has been reached.
    pub fn record_failure_at(&mut self, now: Instant) -> bool {
        self.failure_count += 1;
        if self.failure_count >= MAX_ATTEMPTS {
            self.lockout_start = Some(now);
            return true;
        }
        false
    }

    /// Record a successful passphrase verification.
    /// Resets the failure counter and clears any lockout.
    pub fn record_success(&mut self) {
        self.failure_count = 0;
        self.lockout_start = None;
    }

    // ---- Operation rate limiting (Day 8) ----

    /// Check if an operation is allowed at the current time.
    pub fn check_operation_allowed(&self) -> Result<(), VaultError> {
        self.check_operation_allowed_at(Instant::now())
    }

    /// Check if an operation is allowed at a specific time.
    /// Injectable time source for deterministic testing.
    ///
    /// Returns Ok(()) if: no operations recorded, window expired, or count within limit.
    /// Returns RateLimited if count exceeds MAX_OPERATIONS_PER_MINUTE within active window.
    /// retry_after_secs is a function of elapsed time only — never of operation count.
    pub fn check_operation_allowed_at(&self, now: Instant) -> Result<(), VaultError> {
        if let Some(start) = self.operation_window_start {
            let elapsed = now.duration_since(start);
            if elapsed >= Duration::from_secs(OPERATION_WINDOW_SECS) {
                // Window expired — allow
                return Ok(());
            }
            if self.operation_count > MAX_OPERATIONS_PER_MINUTE {
                let remaining = OPERATION_WINDOW_SECS - elapsed.as_secs();
                return Err(VaultError::RateLimited {
                    retry_after_secs: remaining,
                });
            }
        }
        Ok(())
    }

    /// Record a vault operation (add/remove) at a specific time.
    /// Injectable time source for deterministic testing.
    ///
    /// If the window has expired, resets the counter and starts a new window.
    /// Uses saturating_add to prevent overflow — counter caps at u64::MAX.
    pub fn record_operation_at(&mut self, now: Instant) {
        match self.operation_window_start {
            Some(start) => {
                let elapsed = now.duration_since(start);
                if elapsed >= Duration::from_secs(OPERATION_WINDOW_SECS) {
                    // Window expired — reset and start new window
                    self.operation_window_start = Some(now);
                    self.operation_count = 0;
                }
            }
            None => {
                // First operation — start window
                self.operation_window_start = Some(now);
            }
        }
        self.operation_count = self.operation_count.saturating_add(1);
    }

    /// Set internal operation counter (for overflow testing).
    pub fn set_operation_count(&mut self, count: u64) {
        self.operation_count = count;
    }

    // ---- Mutex-safe wrappers (Day 8) ----

    /// Check if a passphrase attempt is allowed, handling Mutex poisoning fail-closed.
    /// Poisoned Mutex → RateLimited with LOCKOUT_DURATION_SECS (conservative maximum).
    pub fn check_allowed_mutex(lock: &Mutex<Self>) -> Result<(), VaultError> {
        let guard = lock.lock().map_err(|_| VaultError::RateLimited {
            retry_after_secs: LOCKOUT_DURATION_SECS,
        })?;
        guard.check_allowed()
    }

    /// Record a passphrase failure via Mutex, handling poisoning fail-closed.
    /// Poisoned Mutex → RateLimited with LOCKOUT_DURATION_SECS (conservative maximum).
    pub fn record_failure_mutex(lock: &Mutex<Self>) -> Result<bool, VaultError> {
        let mut guard = lock.lock().map_err(|_| VaultError::RateLimited {
            retry_after_secs: LOCKOUT_DURATION_SECS,
        })?;
        Ok(guard.record_failure())
    }
}
