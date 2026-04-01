// Copyright (C) 2026 The Hermetic Project <dev@hermeticsys.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licenses available at hermeticsys.com/license

//! Hermetic Day 6 — Rate Limiter Unit Tests
//!
//! Written BEFORE rate_limit.rs exists (test-first discipline).
//! The rate limiter is pure Rust state tracking — NO database, NO cfg-gating.
//! All tests run on ALL platforms.
//!
//! Assumed API surface:
//!   RateLimiter::new() -> Self
//!   RateLimiter::check_allowed() -> Result<(), VaultError>
//!   RateLimiter::check_allowed_at(now: Instant) -> Result<(), VaultError>
//!   RateLimiter::record_failure() -> bool  (true if max reached)
//!   RateLimiter::record_failure_at(now: Instant) -> bool
//!   RateLimiter::record_success()
//!   RateLimiter::MAX_ATTEMPTS = 5
//!   RateLimiter::LOCKOUT_DURATION_SECS = 900

use std::time::{Duration, Instant};

use hermetic_core::error::{FailClosedAction, VaultError};
use hermetic_core::rate_limit::RateLimiter;

// ============================================================================
// T-RL-1: Fresh limiter allows unlock attempt
// ============================================================================
#[test]
fn test_allows_first_attempt() {
    let limiter = RateLimiter::new();
    assert!(
        limiter.check_allowed().is_ok(),
        "Fresh limiter must allow the first attempt"
    );
}

// ============================================================================
// T-RL-2: 4 consecutive failures still allow 5th attempt
// ============================================================================
#[test]
fn test_allows_up_to_max_attempts() {
    let now = Instant::now();
    let mut limiter = RateLimiter::new();

    // 4 failures — should NOT trigger lockout
    for i in 0..4 {
        let reached_max = limiter.record_failure_at(now);
        assert!(
            !reached_max,
            "Failure {} must not reach max (max is 5)",
            i + 1
        );
    }

    // 5th attempt should still be allowed (lockout triggers AFTER 5th failure)
    assert!(
        limiter.check_allowed_at(now).is_ok(),
        "5th attempt must be allowed (lockout triggers after 5th failure, not before)"
    );
}

// ============================================================================
// T-RL-3: 5 consecutive failures → RateLimited on next attempt
// ============================================================================
#[test]
fn test_lockout_after_max_failures() {
    let now = Instant::now();
    let mut limiter = RateLimiter::new();

    // Record 5 consecutive failures
    for i in 0..4 {
        let reached = limiter.record_failure_at(now);
        assert!(!reached, "Failure {} should not trigger max", i + 1);
    }
    let reached = limiter.record_failure_at(now);
    assert!(reached, "5th failure must signal max reached");

    // Next check must return RateLimited
    let result = limiter.check_allowed_at(now);
    assert!(result.is_err(), "Must be locked out after 5 failures");
    assert!(
        matches!(result.unwrap_err(), VaultError::RateLimited { .. }),
        "Must return RateLimited error"
    );
}

// ============================================================================
// T-RL-4: Success resets counter
// ============================================================================
#[test]
fn test_success_resets_counter() {
    let now = Instant::now();
    let mut limiter = RateLimiter::new();

    // 3 failures
    for _ in 0..3 {
        limiter.record_failure_at(now);
    }

    // 1 success resets counter
    limiter.record_success();

    // 4 more failures — should NOT trigger lockout (counter was reset)
    for i in 0..4 {
        let reached = limiter.record_failure_at(now);
        assert!(
            !reached,
            "Failure {} after reset must not trigger max",
            i + 1
        );
    }

    // Still allowed
    assert!(
        limiter.check_allowed_at(now).is_ok(),
        "Must be allowed after reset + 4 failures (below max)"
    );
}

// ============================================================================
// T-RL-5: Lockout expires after 15 minutes
// Uses injectable time source (check_allowed_at), NOT thread::sleep.
// ============================================================================
#[test]
fn test_lockout_expires() {
    let now = Instant::now();
    let mut limiter = RateLimiter::new();

    // Trigger lockout
    for _ in 0..5 {
        limiter.record_failure_at(now);
    }

    // Still locked at now + 14 minutes
    let before_expiry = now + Duration::from_secs(899);
    assert!(
        limiter.check_allowed_at(before_expiry).is_err(),
        "Must still be locked out before 15 minutes"
    );

    // Allowed at now + 15 minutes + 1 second
    let after_expiry = now + Duration::from_secs(901);
    assert!(
        limiter.check_allowed_at(after_expiry).is_ok(),
        "Must be allowed after lockout expires (15 minutes)"
    );
}

// ============================================================================
// T-RL-6: Lockout returns correct retry_after_secs value
// ============================================================================
#[test]
fn test_lockout_duration_is_correct() {
    let now = Instant::now();
    let mut limiter = RateLimiter::new();

    // Trigger lockout at `now`
    for _ in 0..5 {
        limiter.record_failure_at(now);
    }

    // Check at now + 5 minutes (300 seconds into lockout)
    let check_time = now + Duration::from_secs(300);
    match limiter.check_allowed_at(check_time) {
        Err(VaultError::RateLimited { retry_after_secs }) => {
            // Lockout started at `now`, duration is 900s.
            // At now+300, remaining = 900-300 = 600 seconds.
            assert_eq!(
                retry_after_secs, 600,
                "retry_after_secs must reflect remaining lockout time"
            );
        }
        other => panic!(
            "Expected RateLimited with retry_after_secs, got: {:?}",
            other
        ),
    }
}

// ============================================================================
// T-RL-7: RateLimited maps to FailClosedAction::Deny
// ============================================================================
#[test]
fn test_fail_closed_action_mapping() {
    let err = VaultError::RateLimited {
        retry_after_secs: 900,
    };
    assert_eq!(
        err.fail_closed_action(),
        FailClosedAction::Deny,
        "RateLimited must map to Deny (vault seal is vault's responsibility)"
    );
}
