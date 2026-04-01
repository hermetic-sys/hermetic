// Copyright (C) 2026 The Hermetic Project <dev@hermeticsys.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tests for SecretType discrimination (v1.1).
//! Ensures from_decrypted() correctly classifies secret content
//! as Static or OAuth2, and handles edge cases safely (M-6).

use hermetic_core::vault::SecretType;

#[test]
fn test_secret_type_static_plain_string() {
    let bytes = b"sk-abc123def456";
    let st = SecretType::from_decrypted(bytes);
    assert!(matches!(st, SecretType::Static(_)));
    assert!(!st.is_oauth2());
}

#[test]
fn test_secret_type_static_non_oauth_json() {
    // JSON but not type:oauth2 — must be Static
    let bytes = br#"{"key": "value", "type": "bearer"}"#;
    let st = SecretType::from_decrypted(bytes);
    assert!(matches!(st, SecretType::Static(_)));
    assert!(!st.is_oauth2());
}

#[test]
fn test_secret_type_oauth2_valid() {
    let bytes = br#"{"type":"oauth2","client_id":"cid","client_secret":"cs","refresh_token":"rt","token_endpoint":"https://oauth.example.com/token","scopes":["read"]}"#;
    let st = SecretType::from_decrypted(bytes);
    assert!(st.is_oauth2());
    if let SecretType::OAuth2(o) = st {
        assert_eq!(o.client_id, "cid");
        assert_eq!(o.client_secret, "cs");
        assert_eq!(o.refresh_token, "rt");
        assert_eq!(o.token_endpoint, "https://oauth.example.com/token");
        assert_eq!(o.scopes, vec!["read"]);
        assert_eq!(o.secret_type, "oauth2");
    } else {
        panic!("Expected OAuth2 variant");
    }
}

#[test]
fn test_secret_type_malformed_oauth_json() {
    // Has type:oauth2 but missing required fields — M-6 safe fallback to Static
    let bytes = br#"{"type":"oauth2","client_id":"cid"}"#;
    let st = SecretType::from_decrypted(bytes);
    assert!(matches!(st, SecretType::Static(_)));
    assert!(!st.is_oauth2());
}

#[test]
fn test_secret_type_empty_bytes() {
    let st = SecretType::from_decrypted(b"");
    assert!(matches!(st, SecretType::Static(_)));
    assert!(!st.is_oauth2());
}

#[test]
fn test_secret_type_binary_garbage() {
    let st = SecretType::from_decrypted(&[0xFF, 0xFE, 0x00, 0x01]);
    assert!(matches!(st, SecretType::Static(_)));
    assert!(!st.is_oauth2());
}

// ── AWS SigV4 tests ──

#[test]
fn test_secret_type_aws_sigv4_valid() {
    let bytes = br#"{"type":"aws_sigv4","access_key_id":"AKIAIOSFODNN7EXAMPLE","secret_access_key":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY","region":"us-east-1"}"#;
    let st = SecretType::from_decrypted(bytes);
    assert!(st.is_aws_sigv4());
    if let SecretType::AwsSigV4(aws) = st {
        assert_eq!(aws.access_key_id, "AKIAIOSFODNN7EXAMPLE");
        assert_eq!(aws.region, "us-east-1");
        assert!(aws.service.is_none());
        assert!(aws.session_token.is_none());
    } else {
        panic!("Expected AwsSigV4 variant");
    }
}

#[test]
fn test_secret_type_aws_sigv4_malformed() {
    // Has type:aws_sigv4 but missing secret_access_key → M-6 safe fallback
    let bytes = br#"{"type":"aws_sigv4","access_key_id":"AKIAIOSFODNN7EXAMPLE"}"#;
    let st = SecretType::from_decrypted(bytes);
    assert!(matches!(st, SecretType::Static(_)));
}

#[test]
fn test_secret_type_aws_sigv4_missing_region() {
    let bytes = br#"{"type":"aws_sigv4","access_key_id":"AKIA","secret_access_key":"secret"}"#;
    let st = SecretType::from_decrypted(bytes);
    assert!(matches!(st, SecretType::Static(_)));
}
