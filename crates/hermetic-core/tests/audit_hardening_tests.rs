// Copyright (C) 2026 The Hermetic Project <dev@hermeticsys.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licenses available at hermeticsys.com/license

//! Hermetic Day 9 — Audit Chain Hardening Tests
//!
//! Written BEFORE any changes (test-first discipline, P-D5-1).
//! 10 tests covering HMAC chain tamper detection, determinism,
//! genesis verification, chain length boundaries, and fail-closed mapping.
//!
//! Test IDs: T-AH-1 through T-AH-10
//!
//! PLATFORM CONSTRAINT: ALL tests are all-platform. NO cfg-gating.
//! Uses ONLY the three public all-platform API items from audit.rs:
//!   - compute_genesis_hmac(audit_key: &[u8]) -> Vec<u8>
//!   - compute_chain_hmac(audit_key: &[u8], prev_hmac: &[u8], entry: &AuditEntry) -> Vec<u8>
//!   - AuditEntry { timestamp, action, secret_name, agent, details }
//!
//! Does NOT use the DB-backed audit log type (Linux-only, cfg-gated).

use hermetic_core::audit::{compute_chain_hmac, compute_genesis_hmac, AuditEntry};
use hermetic_core::error::{FailClosedAction, VaultError};

/// Helper: create a test audit entry with all fields populated.
fn make_entry(action: &str, secret_name: Option<&str>) -> AuditEntry {
    AuditEntry {
        timestamp: "2026-02-19T00:00:00Z".to_string(),
        action: action.to_string(),
        secret_name: secret_name.map(|s| s.to_string()),
        agent: Some("test-harness".to_string()),
        details: Some("hardening-test".to_string()),
    }
}

/// Helper: build a chain of N entries and return (entries, hmacs).
/// hmacs[0] = genesis, hmacs[i+1] = chain HMAC for entries[i].
fn build_chain(key: &[u8], entries: &[AuditEntry]) -> Vec<Vec<u8>> {
    let mut hmacs = Vec::with_capacity(entries.len() + 1);
    let genesis = compute_genesis_hmac(key);
    hmacs.push(genesis);
    for entry in entries {
        let prev = hmacs.last().unwrap();
        let hmac = compute_chain_hmac(key, prev, entry);
        hmacs.push(hmac);
    }
    hmacs
}

// ============================================================================
// T-AH-1: Truncation detection
// Build a valid chain of N entries. Remove the last entry. The truncated
// chain's final HMAC differs from the full chain's final HMAC, proving
// truncation is detectable if the expected chain state is known.
// ============================================================================
#[test]
fn t_ah_01_truncation_detection() {
    let key = [0x01u8; 32];
    let entries: Vec<AuditEntry> = (0..4)
        .map(|i| make_entry(&format!("op_{}", i), Some(&format!("secret_{}", i))))
        .collect();

    // Build full chain of 4 entries
    let full_hmacs = build_chain(&key, &entries);
    assert_eq!(full_hmacs.len(), 5); // genesis + 4 chain HMACs

    // Build truncated chain of 3 entries (remove last)
    let truncated_hmacs = build_chain(&key, &entries[..3]);
    assert_eq!(truncated_hmacs.len(), 4); // genesis + 3 chain HMACs

    // First 4 HMACs match (genesis + entries 0..2)
    for i in 0..4 {
        assert_eq!(
            full_hmacs[i], truncated_hmacs[i],
            "HMAC at position {} must match between full and truncated chain",
            i
        );
    }

    // Full chain has a 5th HMAC that the truncated chain does not
    // The truncated chain's last HMAC (position 3) != full chain's last (position 4)
    assert_ne!(
        truncated_hmacs.last().unwrap(),
        full_hmacs.last().unwrap(),
        "Truncated chain must have different final HMAC — truncation detected"
    );
}

// ============================================================================
// T-AH-2: Reorder detection
// Build a valid chain of 3+ entries. Swap two consecutive entries.
// Recompute chain from genesis. HMACs must diverge from swap point forward.
// ============================================================================
#[test]
fn t_ah_02_reorder_detection() {
    let key = [0x02u8; 32];
    let entries = vec![
        make_entry("add_secret", Some("key_a")),
        make_entry("remove_secret", Some("key_b")),
        make_entry("add_secret", Some("key_c")),
    ];

    // Build original chain
    let original_hmacs = build_chain(&key, &entries);

    // Swap entries[1] and entries[2]
    let reordered = vec![entries[0].clone(), entries[2].clone(), entries[1].clone()];
    let reordered_hmacs = build_chain(&key, &reordered);

    // Genesis and first chain HMAC must match (entry[0] is the same)
    assert_eq!(original_hmacs[0], reordered_hmacs[0], "Genesis must match");
    assert_eq!(
        original_hmacs[1], reordered_hmacs[1],
        "First entry HMAC must match (same entry)"
    );

    // From swap point forward, HMACs must diverge
    assert_ne!(
        original_hmacs[2], reordered_hmacs[2],
        "Swapped entry at position 2 must produce different HMAC"
    );
    assert_ne!(
        original_hmacs[3], reordered_hmacs[3],
        "Entry at position 3 must diverge after reorder"
    );
}

// ============================================================================
// T-AH-3: Genesis corruption
// Flip one byte in genesis. Use corrupted genesis as prev_hmac for the first
// chain entry. Entire chain diverges. Also verify AuditFailure → Seal.
// ============================================================================
#[test]
fn t_ah_03_genesis_corruption() {
    let key = [0x03u8; 32];
    let entry = make_entry("add_secret", Some("test_key"));

    // Compute correct genesis
    let genesis = compute_genesis_hmac(&key);

    // Corrupt genesis: flip first byte
    let mut corrupted_genesis = genesis.clone();
    corrupted_genesis[0] ^= 0xFF;
    assert_ne!(genesis, corrupted_genesis, "Corruption must alter genesis");

    // Chain from correct genesis
    let correct_hmac = compute_chain_hmac(&key, &genesis, &entry);

    // Chain from corrupted genesis
    let corrupted_hmac = compute_chain_hmac(&key, &corrupted_genesis, &entry);

    // Entire chain diverges from a corrupted genesis
    assert_ne!(
        correct_hmac, corrupted_hmac,
        "Corrupted genesis must cause entire chain to diverge"
    );

    // Verify AuditFailure → Seal
    let err = VaultError::AuditFailure("genesis corruption detected".into());
    assert_eq!(
        err.fail_closed_action(),
        FailClosedAction::Seal,
        "AuditFailure must map to Seal"
    );
}

// ============================================================================
// T-AH-4: Mid-chain corruption
// Build a chain of 5+ entries. Modify entry #3's action field. Recompute
// chain from genesis. HMACs diverge from entry #3 forward. Entries before
// #3 remain valid.
// ============================================================================
#[test]
fn t_ah_04_mid_chain_corruption() {
    let key = [0x04u8; 32];
    let entries: Vec<AuditEntry> = (0..5)
        .map(|i| make_entry(&format!("operation_{}", i), Some(&format!("secret_{}", i))))
        .collect();

    // Build original chain
    let original_hmacs = build_chain(&key, &entries);

    // Corrupt entry #3: change the action field
    let mut corrupted_entries = entries.clone();
    corrupted_entries[3] = make_entry("CORRUPTED_ACTION", Some("secret_3"));

    // Rebuild chain with corrupted entry
    let corrupted_hmacs = build_chain(&key, &corrupted_entries);

    // Entries 0–2 and their HMACs must be identical (before corruption point)
    for i in 0..4 {
        // genesis + entries 0, 1, 2 → hmacs[0..4]
        assert_eq!(
            original_hmacs[i], corrupted_hmacs[i],
            "HMAC at position {} must match (before corruption point)",
            i
        );
    }

    // Entry #3 onward: HMACs must diverge
    assert_ne!(
        original_hmacs[4], corrupted_hmacs[4],
        "Corrupted entry #3 must produce different HMAC"
    );
    assert_ne!(
        original_hmacs[5], corrupted_hmacs[5],
        "Entry #4 must diverge after mid-chain corruption"
    );
}

// ============================================================================
// T-AH-5: Empty chain verification
// Call compute_genesis_hmac with a valid key. Verify it returns a non-empty
// Vec<u8> and does not panic. An empty chain with only genesis is valid.
// ============================================================================
#[test]
fn t_ah_05_empty_chain_verification() {
    let key = [0x05u8; 32];

    // Genesis computation must not panic
    let genesis = compute_genesis_hmac(&key);

    // Must be non-empty (32 bytes for HMAC-SHA256)
    assert!(!genesis.is_empty(), "Genesis HMAC must be non-empty");
    assert_eq!(genesis.len(), 32, "Genesis HMAC must be 32 bytes (SHA-256)");

    // Must not be all zeros (actual cryptographic output)
    assert_ne!(genesis, vec![0u8; 32], "Genesis must not be trivial zeros");

    // Empty chain = only genesis. build_chain with zero entries succeeds
    let hmacs = build_chain(&key, &[]);
    assert_eq!(hmacs.len(), 1, "Empty chain has only genesis");
    assert_eq!(
        hmacs[0], genesis,
        "build_chain genesis must match direct call"
    );
}

// ============================================================================
// T-AH-6: Deterministic replay
// Given identical audit_key and identical AuditEntry sequence, compute the
// chain twice. All genesis and chain HMACs must be byte-identical.
// ============================================================================
#[test]
fn t_ah_06_deterministic_replay() {
    let key = [0x06u8; 32];
    let entries: Vec<AuditEntry> = (0..5)
        .map(|i| make_entry(&format!("action_{}", i), Some(&format!("name_{}", i))))
        .collect();

    // Build chain twice
    let chain_a = build_chain(&key, &entries);
    let chain_b = build_chain(&key, &entries);

    // Every HMAC must be byte-identical
    assert_eq!(
        chain_a.len(),
        chain_b.len(),
        "Both chains must have same length"
    );
    for i in 0..chain_a.len() {
        assert_eq!(
            chain_a[i], chain_b[i],
            "HMAC at position {} must be byte-identical across replays",
            i
        );
    }
}

// ============================================================================
// T-AH-7: Genesis known-answer test (self-verifying)
// Compute HMAC-SHA256 independently using ring::hmac with a known key and
// the literal domain string "hermetic-audit-genesis". Compare against
// compute_genesis_hmac(). Both must match byte-for-byte.
// ============================================================================
#[test]
fn t_ah_07_genesis_known_answer() {
    let key = [0x01u8; 32];

    // Independent computation using ring::hmac directly
    let hmac_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &key);
    let independent_tag = ring::hmac::sign(&hmac_key, b"hermetic-audit-genesis");
    let independent_result = independent_tag.as_ref().to_vec();

    // Compute via public API
    let api_result = compute_genesis_hmac(&key);

    // Must match byte-for-byte
    assert_eq!(
        independent_result, api_result,
        "Independent ring::hmac computation must match compute_genesis_hmac"
    );

    // Both must be 32 bytes (HMAC-SHA256)
    assert_eq!(independent_result.len(), 32);
    assert_eq!(api_result.len(), 32);
}

// ============================================================================
// T-AH-8: Chain length boundary
// Build and verify chains of length 1, 2, and 100 entries. All must complete
// without panic. Each chain must be internally consistent.
// ============================================================================
#[test]
fn t_ah_08_chain_length_boundary() {
    let key = [0x08u8; 32];

    for chain_len in [1, 2, 100] {
        let entries: Vec<AuditEntry> = (0..chain_len)
            .map(|i| make_entry(&format!("op_{}", i), None))
            .collect();

        let hmacs = build_chain(&key, &entries);

        // Must have genesis + N chain HMACs
        assert_eq!(
            hmacs.len(),
            chain_len + 1,
            "Chain of {} entries must produce {} HMACs",
            chain_len,
            chain_len + 1
        );

        // Every HMAC must be 32 bytes
        for (i, hmac) in hmacs.iter().enumerate() {
            assert_eq!(
                hmac.len(),
                32,
                "HMAC at position {} in chain of {} must be 32 bytes",
                i,
                chain_len
            );
        }

        // Each HMAC depends on the previous (no two adjacent are equal)
        for i in 1..hmacs.len() {
            assert_ne!(
                hmacs[i],
                hmacs[i - 1],
                "Adjacent HMACs at positions {}/{} must differ in chain of {}",
                i - 1,
                i,
                chain_len
            );
        }
    }
}

// ============================================================================
// T-AH-9: Entry field completeness
// Construct an AuditEntry with all 5 fields. Verify all fields are accessible.
// Verify no field contains hex-encoded key material or secret values.
// ============================================================================
#[test]
fn t_ah_09_entry_field_completeness() {
    let entry = AuditEntry {
        timestamp: "2026-02-19T12:00:00Z".to_string(),
        action: "add_secret".to_string(),
        secret_name: Some("my_api_key".to_string()),
        agent: Some("cli-v1".to_string()),
        details: Some("sensitivity=high".to_string()),
    };

    // All 5 fields accessible
    assert_eq!(entry.timestamp, "2026-02-19T12:00:00Z");
    assert_eq!(entry.action, "add_secret");
    assert_eq!(entry.secret_name.as_deref(), Some("my_api_key"));
    assert_eq!(entry.agent.as_deref(), Some("cli-v1"));
    assert_eq!(entry.details.as_deref(), Some("sensitivity=high"));

    // No field contains hex-encoded key material or secret values
    let all_fields = format!(
        "{} {} {:?} {:?} {:?}",
        entry.timestamp, entry.action, entry.secret_name, entry.agent, entry.details
    );

    // Must not contain raw key bytes or long hex strings (>= 64 hex chars = 32 bytes)
    let has_long_hex = all_fields
        .as_bytes()
        .windows(64)
        .any(|w| w.iter().all(|b| b.is_ascii_hexdigit()));
    assert!(
        !has_long_hex,
        "Audit entry fields must not contain hex-encoded key material"
    );

    // Secret names (identifiers) ARE allowed — verify the name is present
    assert!(
        all_fields.contains("my_api_key"),
        "Secret name (identifier) must be present"
    );
}

// ============================================================================
// T-AH-10: AuditFailure → Seal mapping
// Construct a VaultError::AuditFailure. Call .fail_closed_action().
// Assert result equals FailClosedAction::Seal.
// ============================================================================
#[test]
fn t_ah_10_audit_failure_seal_mapping() {
    let err = VaultError::AuditFailure("chain verification failed".into());
    assert_eq!(
        err.fail_closed_action(),
        FailClosedAction::Seal,
        "AuditFailure must map to FailClosedAction::Seal"
    );

    // Verify with different message content — mapping is invariant of message
    let err2 = VaultError::AuditFailure("write failed".into());
    assert_eq!(
        err2.fail_closed_action(),
        FailClosedAction::Seal,
        "AuditFailure mapping must be invariant of error message content"
    );
}
