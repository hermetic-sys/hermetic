// Copyright (C) 2026 The Hermetic Project <dev@hermeticsys.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licenses available at hermeticsys.com/license

//! Hermetic Day 8 — Rate Limiter Hardening Tests
//!
//! Written BEFORE production implementation (test-first discipline, P-D5-1).
//! 12 tests covering mutex safety, operation rate limits, per-vault isolation,
//! counter overflow, lockout precision, and information leakage prevention.
//!
//! Test IDs: T-RLH-1 through T-RLH-12

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use hermetic_core::error::{FailClosedAction, VaultError};
use hermetic_core::rate_limit::RateLimiter;

// ============================================================================
// T-RLH-1: Mutex poisoning → fail-closed (DENY)
// Simulate a poisoned Mutex. Verify that subsequent check returns
// VaultError::RateLimited, NOT Ok(()). Fail CLOSED, never open.
// ============================================================================
#[test]
fn t_rlh_01_mutex_poisoning_denies_access() {
    let mutex = Arc::new(Mutex::new(RateLimiter::new()));
    let mutex_clone = Arc::clone(&mutex);

    // Poison the mutex by panicking inside a lock scope in a separate thread
    let handle = thread::spawn(move || {
        let _guard = mutex_clone.lock().unwrap();
        panic!("intentional panic to poison mutex");
    });
    let _ = handle.join(); // join the panicked thread

    // Mutex is now poisoned — verify
    assert!(mutex.lock().is_err(), "Mutex must be poisoned");

    // check_allowed_mutex must fail closed → RateLimited, NOT Ok(())
    let result = RateLimiter::check_allowed_mutex(&mutex);
    assert!(result.is_err(), "Poisoned mutex must fail closed");
    match result.unwrap_err() {
        VaultError::RateLimited { .. } => {} // correct: fail-closed → Deny
        other => panic!("Expected RateLimited, got: {:?}", other),
    }
}

// ============================================================================
// T-RLH-2: Operation rate limit triggers
// Call record_operation() more than MAX_OPERATIONS_PER_MINUTE times within
// OPERATION_WINDOW_SECS. Verify check_operation_allowed() returns RateLimited.
// ============================================================================
#[test]
fn t_rlh_02_operation_rate_limit_triggers() {
    let now = Instant::now();
    let mut limiter = RateLimiter::new();

    // Exceed MAX_OPERATIONS_PER_MINUTE within the window
    for _ in 0..=RateLimiter::MAX_OPERATIONS_PER_MINUTE {
        limiter.record_operation_at(now);
    }

    // Next check must return RateLimited
    let result = limiter.check_operation_allowed_at(now);
    assert!(
        result.is_err(),
        "Must be rate-limited after exceeding operation limit"
    );
    match result.unwrap_err() {
        VaultError::RateLimited { retry_after_secs } => {
            assert!(retry_after_secs > 0, "retry_after_secs must be > 0");
        }
        other => panic!("Expected RateLimited, got: {:?}", other),
    }
}

// ============================================================================
// T-RLH-3: Operation rate limit resets after window
// Exceed the operation limit. Advance injectable time by
// OPERATION_WINDOW_SECS + 1. Verify check_operation_allowed() → Ok(()).
// ============================================================================
#[test]
fn t_rlh_03_operation_rate_limit_resets_after_window() {
    let now = Instant::now();
    let mut limiter = RateLimiter::new();

    // Exceed operation limit
    for _ in 0..=RateLimiter::MAX_OPERATIONS_PER_MINUTE {
        limiter.record_operation_at(now);
    }

    // Verify locked
    assert!(
        limiter.check_operation_allowed_at(now).is_err(),
        "Must be rate-limited"
    );

    // Advance past the window
    let after_window = now + Duration::from_secs(RateLimiter::OPERATION_WINDOW_SECS + 1);
    assert!(
        limiter.check_operation_allowed_at(after_window).is_ok(),
        "Must be allowed after operation window resets"
    );
}

// ============================================================================
// T-RLH-4: Operation limit independent per vault
// Rate-limit vault_path_A to the max. Verify vault_path_B is unaffected.
// ============================================================================
#[test]
fn t_rlh_04_operation_limit_independent_per_vault() {
    let now = Instant::now();
    let mut limiter_a = RateLimiter::new();
    let limiter_b = RateLimiter::new();

    // Rate-limit vault A to the max
    for _ in 0..=RateLimiter::MAX_OPERATIONS_PER_MINUTE {
        limiter_a.record_operation_at(now);
    }

    // Vault A is rate-limited
    assert!(
        limiter_a.check_operation_allowed_at(now).is_err(),
        "Vault A must be rate-limited"
    );

    // Vault B must be unaffected
    assert!(
        limiter_b.check_operation_allowed_at(now).is_ok(),
        "Vault B must NOT be affected by vault A's rate limit"
    );
}

// ============================================================================
// T-RLH-5: Passphrase and operation limits are independent
// Trigger passphrase lockout → operations still allowed.
// Trigger operation limit → passphrase attempts still work (if not locked out).
// list() and status() are NEVER blocked by either limiter.
// ============================================================================
#[test]
fn t_rlh_05_passphrase_and_operation_limits_independent() {
    let now = Instant::now();
    let mut limiter = RateLimiter::new();

    // Part 1: Trigger passphrase lockout (5 failures)
    for _ in 0..5 {
        limiter.record_failure_at(now);
    }
    assert!(
        limiter.check_allowed_at(now).is_err(),
        "Passphrase must be locked out after 5 failures"
    );

    // Operations must still be allowed (independent)
    assert!(
        limiter.check_operation_allowed_at(now).is_ok(),
        "Operation rate limit must be independent of passphrase lockout"
    );

    // Part 2: Reset passphrase, trigger operation limit
    limiter.record_success(); // resets passphrase counter
    for _ in 0..=RateLimiter::MAX_OPERATIONS_PER_MINUTE {
        limiter.record_operation_at(now);
    }
    assert!(
        limiter.check_operation_allowed_at(now).is_err(),
        "Operations must be rate-limited"
    );

    // Passphrase attempts must still work (was reset)
    assert!(
        limiter.check_allowed_at(now).is_ok(),
        "Passphrase must be allowed when operation limit is hit (independent)"
    );

    // Part 3: list() and status() are NEVER blocked by either limiter.
    // These operations are exempt at the vault layer, not within RateLimiter.
    // Trigger both limiters simultaneously to verify no cross-contamination.
    for _ in 0..5 {
        limiter.record_failure_at(now);
    }
    // Both passphrase and operation limiters are now triggered.
    // The exemption for list/status is enforced at vault.rs integration level,
    // verified in integration tests. This unit test confirms limiter independence.
}

// ============================================================================
// T-RLH-6: Counter overflow safety
// Set the internal operation counter to near u64::MAX.
// Call record_operation(). Verify no panic, no wraparound to 0.
// Counter should saturate at u64::MAX and deny.
// ============================================================================
#[test]
fn t_rlh_06_counter_overflow_safety() {
    let now = Instant::now();
    let mut limiter = RateLimiter::new();

    // Set counter to near u64::MAX
    limiter.set_operation_count(u64::MAX - 1);

    // Record operation — must NOT panic, must NOT wraparound to 0
    limiter.record_operation_at(now);

    // Counter should saturate at u64::MAX and deny further operations
    let result = limiter.check_operation_allowed_at(now);
    assert!(
        result.is_err(),
        "Saturated counter must deny (fail-closed, no wraparound)"
    );
}

// ============================================================================
// T-RLH-7: Lockout expiry precision (exact boundary)
// Trigger passphrase lockout. At LOCKOUT_DURATION_SECS - 1: still locked.
// At exactly LOCKOUT_DURATION_SECS: unlocked.
// ============================================================================
#[test]
fn t_rlh_07_lockout_expiry_precision() {
    let now = Instant::now();
    let mut limiter = RateLimiter::new();

    // Trigger passphrase lockout
    for _ in 0..5 {
        limiter.record_failure_at(now);
    }

    // At LOCKOUT_DURATION_SECS - 1: still locked
    let just_before = now + Duration::from_secs(RateLimiter::LOCKOUT_DURATION_SECS - 1);
    assert!(
        limiter.check_allowed_at(just_before).is_err(),
        "Must still be locked 1 second before expiry"
    );

    // At exactly LOCKOUT_DURATION_SECS: unlocked
    let exactly_at = now + Duration::from_secs(RateLimiter::LOCKOUT_DURATION_SECS);
    assert!(
        limiter.check_allowed_at(exactly_at).is_ok(),
        "Must be unlocked at exactly LOCKOUT_DURATION_SECS"
    );
}

// ============================================================================
// T-RLH-8: retry_after reveals no information about attempt count
// Trigger rate limiting at different attempt/operation counts.
// Verify retry_after_secs is a function of elapsed time against the window,
// NEVER a function of attempt/operation count.
// ============================================================================
#[test]
fn t_rlh_08_retry_after_no_information_leakage() {
    let now = Instant::now();

    // Scenario 1: Passphrase lockout — retry_after depends on elapsed time only
    let mut limiter1 = RateLimiter::new();
    for _ in 0..5 {
        limiter1.record_failure_at(now);
    }

    let mut limiter2 = RateLimiter::new();
    for _ in 0..5 {
        limiter2.record_failure_at(now);
    }
    // Extra excess attempts on limiter2
    for _ in 0..100 {
        limiter2.record_failure_at(now);
    }

    // Check both at the same elapsed time
    let check_time = now + Duration::from_secs(300);
    let retry1 = match limiter1.check_allowed_at(check_time) {
        Err(VaultError::RateLimited { retry_after_secs }) => retry_after_secs,
        other => panic!("Expected RateLimited for limiter1, got: {:?}", other),
    };
    let retry2 = match limiter2.check_allowed_at(check_time) {
        Err(VaultError::RateLimited { retry_after_secs }) => retry_after_secs,
        other => panic!("Expected RateLimited for limiter2, got: {:?}", other),
    };

    assert_eq!(
        retry1, retry2,
        "retry_after_secs must be identical regardless of excess attempt count"
    );

    // Scenario 2: Operation rate limit — retry_after depends on window elapsed only
    let mut limiter3 = RateLimiter::new();
    for _ in 0..=RateLimiter::MAX_OPERATIONS_PER_MINUTE {
        limiter3.record_operation_at(now);
    }

    let mut limiter4 = RateLimiter::new();
    for i in 0..(RateLimiter::MAX_OPERATIONS_PER_MINUTE + 100) {
        limiter4.record_operation_at(now);
        let _ = i; // suppress unused warning
    }

    let op_check = now + Duration::from_secs(10);
    let op_retry1 = match limiter3.check_operation_allowed_at(op_check) {
        Err(VaultError::RateLimited { retry_after_secs }) => retry_after_secs,
        other => panic!("Expected RateLimited for limiter3, got: {:?}", other),
    };
    let op_retry2 = match limiter4.check_operation_allowed_at(op_check) {
        Err(VaultError::RateLimited { retry_after_secs }) => retry_after_secs,
        other => panic!("Expected RateLimited for limiter4, got: {:?}", other),
    };

    assert_eq!(
        op_retry1, op_retry2,
        "Operation retry_after_secs must depend only on window elapsed time"
    );
}

// ============================================================================
// T-RLH-9: Concurrent access safety
// Spawn 2+ threads. All call check_allowed() and record_failure() concurrently
// on the same vault path. Verify: no panic, no data race, deterministic lockout.
// ============================================================================
#[test]
fn t_rlh_09_concurrent_access_safety() {
    let mutex = Arc::new(Mutex::new(RateLimiter::new()));
    let mut handles = vec![];

    // Spawn multiple threads that concurrently access the rate limiter
    for _ in 0..4 {
        let mutex_clone = Arc::clone(&mutex);
        let handle = thread::spawn(move || {
            for _ in 0..10 {
                // Each thread attempts check + record_failure via mutex wrapper
                let _ = RateLimiter::check_allowed_mutex(&mutex_clone);
                let _ = RateLimiter::record_failure_mutex(&mutex_clone);
            }
        });
        handles.push(handle);
    }

    // All threads must complete without panic or data race
    for handle in handles {
        handle.join().expect("Thread must not panic");
    }

    // After enough failures, limiter must be locked out
    let guard = mutex.lock().unwrap();
    assert!(
        guard.check_allowed().is_err(),
        "Must be locked out after concurrent failures exceed threshold"
    );
}

// ============================================================================
// T-RLH-10: Fresh limiter allows first attempt
// Create a brand new rate limiter. Verify check_allowed() returns Ok(())
// on the very first call. Zero-attempt lockout must be impossible.
// ============================================================================
#[test]
fn t_rlh_10_fresh_limiter_allows_first_attempt() {
    let limiter = RateLimiter::new();

    // Passphrase: first attempt allowed
    assert!(
        limiter.check_allowed().is_ok(),
        "Fresh limiter must allow first passphrase attempt"
    );

    // Operations: first operation allowed
    assert!(
        limiter.check_operation_allowed().is_ok(),
        "Fresh limiter must allow first operation"
    );
}

// ============================================================================
// T-RLH-11: Operation limit returns correct error type
// Trigger operation rate limit. Verify the returned error is exactly
// VaultError::RateLimited { retry_after_secs: N } where N > 0.
// ============================================================================
#[test]
fn t_rlh_11_operation_limit_returns_rate_limited_error() {
    let now = Instant::now();
    let mut limiter = RateLimiter::new();

    // Trigger operation rate limit
    for _ in 0..=RateLimiter::MAX_OPERATIONS_PER_MINUTE {
        limiter.record_operation_at(now);
    }

    let result = limiter.check_operation_allowed_at(now);
    assert!(result.is_err(), "Must be rate-limited");

    match result.unwrap_err() {
        VaultError::RateLimited { retry_after_secs } => {
            assert!(retry_after_secs > 0, "retry_after_secs must be positive");
        }
        other => panic!(
            "Expected VaultError::RateLimited {{ retry_after_secs: N }}, got: {:?}",
            other
        ),
    }
}

// ============================================================================
// T-RLH-12: All rate limit errors map to FailClosedAction::Deny
// For every rate-limit error path (passphrase RateLimited, operation
// RateLimited, Mutex poison RateLimited), verify Deny via the existing
// exhaustive mapping function.
// ============================================================================
#[test]
fn t_rlh_12_all_rate_limit_errors_map_to_deny() {
    // Passphrase RateLimited → Deny
    let passphrase_err = VaultError::RateLimited {
        retry_after_secs: 900,
    };
    assert_eq!(
        passphrase_err.fail_closed_action(),
        FailClosedAction::Deny,
        "Passphrase RateLimited must map to Deny"
    );

    // Operation RateLimited → Deny (same error type, different context)
    let operation_err = VaultError::RateLimited {
        retry_after_secs: 60,
    };
    assert_eq!(
        operation_err.fail_closed_action(),
        FailClosedAction::Deny,
        "Operation RateLimited must map to Deny"
    );

    // Mutex poison RateLimited → Deny (same error type from fail-closed handler)
    let poison_err = VaultError::RateLimited {
        retry_after_secs: 0,
    };
    assert_eq!(
        poison_err.fail_closed_action(),
        FailClosedAction::Deny,
        "Mutex poison RateLimited must map to Deny"
    );
}
