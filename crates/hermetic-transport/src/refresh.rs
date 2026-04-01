// Copyright (C) 2026 The Hermetic Project <dev@hermeticsys.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licenses available at hermeticsys.com/license

//! OAuth2 token refresh — wraps the existing SSRF-validated transport pipeline.
//!
//! CRITICAL: This module does NOT build its own reqwest::Client. The refresh
//! call goes through `executor::execute()` which enforces:
//!   - HC-1: HTTPS-only
//!   - HC-2: DNS-resolve → IP-validate → connect-by-IP (SSRF defense)
//!   - HC-6: Redirect re-validation per hop
//!   - HC-7: Forbidden header filtering
//!   - HC-9: Timeouts
//!
//! The token_endpoint URL receives the same treatment as any agent-requested URL.

use std::sync::Arc;

use zeroize::Zeroizing;

use crate::executor::{self, TransportRequest};
use crate::ssrf::{DnsResolver, SystemDnsResolver};

/// Result of a successful OAuth2 token refresh.
#[derive(Debug)]
pub struct RefreshResult {
    /// The new access token (Zeroizing — zeroized on drop).
    pub access_token: Zeroizing<String>,
    /// Seconds until the access token expires (default 3600 if not provided).
    pub expires_in: u64,
    /// New refresh token, if the provider rotated it.
    pub new_refresh_token: Option<String>,
}

/// Execute an OAuth2 token refresh synchronously.
///
/// Creates a one-shot tokio runtime for the HTTP call. The token_endpoint
/// URL goes through the full SSRF validation pipeline (HC-1/2/6/7/9).
///
/// # Arguments
/// - `token_endpoint`: HTTPS URL for the OAuth2 token endpoint
/// - `client_id`: OAuth2 client ID
/// - `client_secret`: OAuth2 client secret
/// - `refresh_token`: Current refresh token
/// - `scopes`: OAuth2 scopes (space-joined when sent)
///
/// # Errors
/// Returns a String error description. Caller maps to IC-1 denied().
pub fn execute_refresh(
    token_endpoint: &str,
    client_id: &str,
    client_secret: &str,
    refresh_token: &str,
    scopes: &[String],
) -> Result<RefreshResult, String> {
    // Build URL-encoded form body
    let mut parts = vec![
        format!(
            "grant_type=refresh_token&client_id={}&client_secret={}&refresh_token={}",
            urlencoded(client_id),
            urlencoded(client_secret),
            urlencoded(refresh_token),
        ),
    ];
    let scope_str = scopes.join(" ");
    if !scope_str.is_empty() {
        parts.push(format!("&scope={}", urlencoded(&scope_str)));
    }
    let body = parts.join("");

    // Build a TransportRequest — NO credential injection (creds are in the body).
    // The token_endpoint URL goes through the full SSRF pipeline.
    let request = TransportRequest {
        url: token_endpoint.to_string(),
        method: "POST".to_string(),
        headers: vec![
            (
                "Content-Type".to_string(),
                "application/x-www-form-urlencoded".to_string(),
            ),
            (
                "Accept".to_string(),
                "application/json".to_string(),
            ),
        ],
        body: Some(body.into_bytes()),
        credential: None,
        extra_headers: vec![],
    };

    let resolver: Arc<dyn DnsResolver> = Arc::new(SystemDnsResolver);

    // One-shot tokio runtime — created and destroyed within this call.
    // This is called from daemon dispatch (sync context). SM-4: no persistent
    // async runtime, no background tasks, no spawn.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime: {e}"))?;

    let response = rt
        .block_on(executor::execute(request, resolver))
        .map_err(|e| format!("transport: {e}"))?;

    if response.status < 200 || response.status >= 300 {
        return Err(format!("HTTP {}", response.status));
    }

    // Parse JSON response
    let json: serde_json::Value = serde_json::from_slice(&response.body)
        .map_err(|e| format!("json parse: {e}"))?;

    let access_token = json["access_token"]
        .as_str()
        .ok_or_else(|| {
            // Include provider error for diagnostics (no secrets in this message)
            let err = json.get("error").and_then(|e| e.as_str()).unwrap_or("unknown");
            let desc = json.get("error_description").and_then(|e| e.as_str()).unwrap_or("");
            format!("missing access_token: error={err}, description={desc}")
        })?;

    Ok(RefreshResult {
        access_token: Zeroizing::new(access_token.to_string()),
        expires_in: json["expires_in"].as_u64().unwrap_or(3600),
        new_refresh_token: json["refresh_token"].as_str().map(String::from),
    })
}

/// Minimal URL encoding for form body values.
pub fn urlencoded(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(b as char);
            }
            _ => {
                result.push_str(&format!("%{:02X}", b));
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_refresh_rejects_http() {
        let result = execute_refresh(
            "http://insecure.example.com/token",
            "client_id",
            "client_secret",
            "refresh_token",
            &[],
        );
        // Should fail because executor enforces HTTPS-only (HC-1)
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("Https") || err.contains("https") || err.contains("scheme"),
            "Error should mention HTTPS requirement, got: {err}"
        );
    }

    #[test]
    fn test_urlencoded_special_chars() {
        assert_eq!(urlencoded("hello world"), "hello%20world");
        assert_eq!(urlencoded("key=value&foo"), "key%3Dvalue%26foo");
        assert_eq!(urlencoded("simple"), "simple");
    }
}
