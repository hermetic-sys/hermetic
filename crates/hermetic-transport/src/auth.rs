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

//! Credential injection — HC-3 BINDING.
//!
//! This module builds Authorization/X-API-Key headers from raw secret bytes
//! and injects them into reqwest RequestBuilders.
//!
//! HC-3 BINDING: inject_credential() MUST call .zeroize() on the secret
//! buffer AFTER header construction, BEFORE returning — on BOTH success and
//! error paths. Do NOT rely solely on Drop.
//!
//! MCP-1 BINDING: Secret bytes MUST NOT appear in any error variant,
//! Display output, or Debug output.

use base64::{engine::general_purpose::STANDARD, Engine};
use zeroize::Zeroize;

use crate::error::TransportError;

/// Authentication scheme for outbound HTTP requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthScheme {
    /// `Authorization: Bearer <token>`
    Bearer,
    /// `X-API-Key: <key>`
    XApiKey,
    /// `Authorization: Basic <base64(user:pass)>`
    ///
    /// Secret bytes must be UTF-8 encoded `user:pass`.
    Basic,
    /// Custom header injection: `<name>: <secret>`
    ///
    /// SG-1 Extension (HM-CONST-AMEND-005). Used by APIs that accept credentials
    /// in non-standard headers (e.g., `X-Goog-Api-Key`, `Api-Token`).
    /// The header name must be a valid RFC 7230 token and must not be on the
    /// HC-7 forbidden header list. Validation is performed at the daemon SG-1 gate.
    Header { name: String },
}

impl AuthScheme {
    /// Parse an auth scheme from its wire representation.
    ///
    /// Wire format:
    /// - `"bearer"` → Bearer
    /// - `"x-api-key"` → XApiKey
    /// - `"basic"` → Basic
    /// - `"header:<name>"` → Header { name }
    ///
    /// SG-1: Unknown scheme values are rejected.
    /// SG-1 Extension: Header names preserve original case; daemon validates RFC 7230 + HC-7.
    pub fn parse(s: &str) -> Result<Self, TransportError> {
        let lower = s.to_ascii_lowercase();
        match lower.as_str() {
            "bearer" => Ok(AuthScheme::Bearer),
            "x-api-key" => Ok(AuthScheme::XApiKey),
            "basic" => Ok(AuthScheme::Basic),
            _ if lower.starts_with("header:") => {
                let name = &s[7..]; // preserve original case for header name
                if name.is_empty() {
                    return Err(TransportError::InvalidCredential);
                }
                // SG-1 Extension: Header name validation (RFC 7230 + HC-7)
                // is performed at the daemon SG-1 gate. Transport layer accepts
                // any non-empty header name for flexibility.
                Ok(AuthScheme::Header {
                    name: name.to_string(),
                })
            }
            _ => Err(TransportError::InvalidCredential),
        }
    }

    /// Wire representation of this auth scheme.
    ///
    /// Round-trip: `AuthScheme::parse(scheme.as_wire_str())` recovers the original.
    pub fn as_wire_str(&self) -> String {
        match self {
            AuthScheme::Bearer => "bearer".to_string(),
            AuthScheme::XApiKey => "x-api-key".to_string(),
            AuthScheme::Basic => "basic".to_string(),
            AuthScheme::Header { name } => format!("header:{name}"),
        }
    }
}

/// Build the (header_name, header_value) pair for the given scheme.
///
/// Takes `secret` as `&[u8]` — the caller retains ownership and lifecycle.
/// This function does NOT zeroize; the caller is responsible.
///
/// Returns `Err(TransportError::InvalidCredential)` if the secret is not
/// valid UTF-8 (Bearer/XApiKey) or if base64 encoding fails.
///
/// MCP-1: No secret bytes in any error message.
pub fn build_auth_header(
    secret: &[u8],
    scheme: &AuthScheme,
) -> Result<(String, String), TransportError> {
    match scheme {
        AuthScheme::Bearer => {
            let token =
                std::str::from_utf8(secret).map_err(|_| TransportError::InvalidCredential)?;
            Ok(("Authorization".to_string(), format!("Bearer {token}")))
        }
        AuthScheme::XApiKey => {
            let key = std::str::from_utf8(secret).map_err(|_| TransportError::InvalidCredential)?;
            Ok(("X-API-Key".to_string(), key.to_string()))
        }
        AuthScheme::Basic => {
            // Secret bytes are "user:pass" UTF-8. base64-encode the raw bytes.
            // We do NOT require valid UTF-8 for the Basic payload — RFC 7617
            // allows arbitrary octets. We base64-encode directly from bytes.
            let encoded = STANDARD.encode(secret);
            Ok(("Authorization".to_string(), format!("Basic {encoded}")))
        }
        AuthScheme::Header { ref name } => {
            // SG-1 Extension: Custom header injection.
            // Secret injected as the value of a custom-named header.
            // Agent headers applied BEFORE credential injection (executor.rs Phase 4 vs 5),
            // so credential injection overwrites any duplicate. Defense-in-depth: harmless.
            let value =
                std::str::from_utf8(secret).map_err(|_| TransportError::InvalidCredential)?;
            Ok((name.clone(), value.to_string()))
        }
    }
}

/// Inject credential into a request builder and explicitly zeroize the secret.
///
/// HC-3 BINDING: `.zeroize()` is called on the secret buffer AFTER header
/// construction, BEFORE the `?` operator on the result. This guarantees
/// zeroization on BOTH the success path and the error path.
///
/// Pattern:
/// ```text
/// let result = build_auth_header(&secret, scheme);  // borrows
/// secret.zeroize();                                  // ALWAYS runs
/// let (name, value) = result?;                       // ? AFTER zeroize
/// ```
///
/// If `.zeroize()` were placed after `?`, the error path would skip
/// zeroization. The pattern above ensures this cannot happen.
///
/// The secret is consumed (moved into this function). The caller cannot
/// access secret bytes after this call returns.
///
/// MCP-1: No secret bytes in any error message.
pub fn inject_credential(
    mut secret: zeroize::Zeroizing<Vec<u8>>,
    builder: reqwest::RequestBuilder,
    scheme: &AuthScheme,
) -> Result<reqwest::RequestBuilder, TransportError> {
    let result = build_auth_header(&secret, scheme);

    // HC-3: ALWAYS zeroize — runs on BOTH success and error paths.
    // MUST be before the ? operator. Do not reorder.
    secret.zeroize();

    let (header_name, header_value) = result?;
    Ok(builder.header(header_name, header_value))
}

// -----------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use zeroize::Zeroizing;

    use super::{build_auth_header, inject_credential, AuthScheme};
    use crate::error::TransportError;

    // --- build_auth_header ---

    #[test]
    fn bearer_produces_correct_header() {
        let secret = b"tok_abc123";
        let (name, value) = build_auth_header(secret, &AuthScheme::Bearer).unwrap();
        assert_eq!(name, "Authorization");
        assert_eq!(value, "Bearer tok_abc123");
    }

    #[test]
    fn x_api_key_produces_correct_header() {
        let secret = b"key_xyz789";
        let (name, value) = build_auth_header(secret, &AuthScheme::XApiKey).unwrap();
        assert_eq!(name, "X-API-Key");
        assert_eq!(value, "key_xyz789");
    }

    #[test]
    fn basic_produces_base64_header() {
        // "user:pass" → base64 → "dXNlcjpwYXNz"
        let secret = b"user:pass";
        let (name, value) = build_auth_header(secret, &AuthScheme::Basic).unwrap();
        assert_eq!(name, "Authorization");
        assert_eq!(value, "Basic dXNlcjpwYXNz");
    }

    #[test]
    fn bearer_non_utf8_returns_invalid_credential() {
        let secret = &[0xFF, 0xFE, 0x00]; // invalid UTF-8
        let result = build_auth_header(secret, &AuthScheme::Bearer);
        assert!(
            matches!(result, Err(TransportError::InvalidCredential)),
            "Non-UTF8 bearer token must return InvalidCredential"
        );
    }

    #[test]
    fn x_api_key_non_utf8_returns_invalid_credential() {
        let secret = &[0xFF, 0xFE]; // invalid UTF-8
        let result = build_auth_header(secret, &AuthScheme::XApiKey);
        assert!(matches!(result, Err(TransportError::InvalidCredential)));
    }

    #[test]
    fn basic_accepts_non_utf8_bytes() {
        // Basic auth base64-encodes raw bytes — no UTF-8 requirement
        let secret = &[0xFF, 0xFE, 0x00];
        let result = build_auth_header(secret, &AuthScheme::Basic);
        assert!(result.is_ok(), "Basic auth must accept non-UTF8 bytes");
        let (name, value) = result.unwrap();
        assert_eq!(name, "Authorization");
        assert!(value.starts_with("Basic "));
    }

    #[test]
    fn error_message_contains_no_secret_bytes() {
        // MCP-1: error Display must not contain secret material
        let bad = &[0xFF_u8; 8];
        let err = build_auth_header(bad, &AuthScheme::Bearer).unwrap_err();
        let display = format!("{err}");
        // The display must not contain the raw bytes as a string literal
        assert!(
            !display.contains('\u{FFFF}'),
            "Error display must not contain secret bytes"
        );
        assert_eq!(display, "invalid credential format");
    }

    // --- inject_credential (HC-3 zeroization) ---

    #[test]
    fn inject_credential_zeroizes_on_success() {
        let secret_bytes = b"tok_success_test_12345".to_vec();
        let secret = Zeroizing::new(secret_bytes.clone());
        // We verify the contract by ensuring inject_credential returns Ok
        // and that the call does not panic. Direct memory verification of
        // zeroization is not possible without unsafe in production tests.
        // Structural: secret is consumed — cannot be accessed after call.
        let client = reqwest::Client::new();
        let builder = client.get("https://example.com");
        let result = inject_credential(secret, builder, &AuthScheme::Bearer);
        assert!(
            result.is_ok(),
            "inject_credential must succeed with valid secret"
        );
    }

    #[test]
    fn inject_credential_zeroizes_on_error_path() {
        // Non-UTF8 bytes trigger the error path in build_auth_header.
        // HC-3: zeroize must run even when build_auth_header returns Err.
        let secret = Zeroizing::new(vec![0xFF_u8, 0xFE_u8]);
        let client = reqwest::Client::new();
        let builder = client.get("https://example.com");
        let result = inject_credential(secret, builder, &AuthScheme::Bearer);
        // Error path: zeroize must have run (secret is consumed, can't check
        // bytes directly without unsafe — structural guarantee via code review)
        assert!(
            matches!(result, Err(TransportError::InvalidCredential)),
            "Error path must return InvalidCredential and must have zeroized"
        );
    }

    #[test]
    fn inject_credential_bearer_header_set() {
        let secret = Zeroizing::new(b"test-token-abc".to_vec());
        let client = reqwest::Client::new();
        let builder = client.get("https://example.com");
        let result = inject_credential(secret, builder, &AuthScheme::Bearer);
        assert!(result.is_ok());
        // RequestBuilder does not expose headers for inspection in unit tests;
        // the header injection is verified structurally via build_auth_header tests.
    }

    #[test]
    fn auth_scheme_eq() {
        assert_eq!(AuthScheme::Bearer, AuthScheme::Bearer);
        assert_ne!(AuthScheme::Bearer, AuthScheme::XApiKey);
        assert_ne!(AuthScheme::XApiKey, AuthScheme::Basic);
    }

    // --- AuthScheme::parse (SG-1, SG-2) ---

    #[test]
    fn parse_bearer() {
        assert_eq!(AuthScheme::parse("bearer").unwrap(), AuthScheme::Bearer);
        assert_eq!(AuthScheme::parse("Bearer").unwrap(), AuthScheme::Bearer);
        assert_eq!(AuthScheme::parse("BEARER").unwrap(), AuthScheme::Bearer);
    }

    #[test]
    fn parse_x_api_key() {
        assert_eq!(AuthScheme::parse("x-api-key").unwrap(), AuthScheme::XApiKey);
        assert_eq!(AuthScheme::parse("X-API-KEY").unwrap(), AuthScheme::XApiKey);
    }

    #[test]
    fn parse_basic() {
        assert_eq!(AuthScheme::parse("basic").unwrap(), AuthScheme::Basic);
        assert_eq!(AuthScheme::parse("Basic").unwrap(), AuthScheme::Basic);
    }

    #[test]
    fn parse_query_scheme_rejected() {
        // F-01: Query auth scheme removed — secrets must not appear in URLs.
        assert!(AuthScheme::parse("query:api_key").is_err());
        assert!(AuthScheme::parse("query:").is_err());
        assert!(AuthScheme::parse("Query:ApiKey").is_err());
    }

    #[test]
    fn parse_unknown_scheme_rejected() {
        // SG-1: Unknown schemes must be rejected
        assert!(AuthScheme::parse("oauth2").is_err());
        assert!(AuthScheme::parse("digest").is_err());
        assert!(AuthScheme::parse("").is_err());
    }

    // --- as_wire_str round-trip ---

    #[test]
    fn wire_str_roundtrip() {
        for scheme in &[
            AuthScheme::Bearer,
            AuthScheme::XApiKey,
            AuthScheme::Basic,
            AuthScheme::Header {
                name: "X-Goog-Api-Key".to_string(),
            },
        ] {
            let wire = scheme.as_wire_str();
            let parsed = AuthScheme::parse(&wire).unwrap();
            assert_eq!(&parsed, scheme, "round-trip failed for {wire}");
        }
    }

    // --- SG-1 Extension: Header scheme ---

    #[test]
    fn parse_header_valid() {
        let scheme = AuthScheme::parse("header:X-Goog-Api-Key").unwrap();
        assert_eq!(
            scheme,
            AuthScheme::Header {
                name: "X-Goog-Api-Key".to_string()
            }
        );
    }

    #[test]
    fn parse_header_preserves_case() {
        let scheme = AuthScheme::parse("Header:Api-Token").unwrap();
        assert_eq!(
            scheme,
            AuthScheme::Header {
                name: "Api-Token".to_string()
            }
        );
    }

    #[test]
    fn parse_header_empty_name_rejected() {
        assert!(AuthScheme::parse("header:").is_err());
    }

    #[test]
    fn header_build_auth_produces_correct_header() {
        let secret = b"secret-key-123";
        let scheme = AuthScheme::Header {
            name: "X-Goog-Api-Key".to_string(),
        };
        let (name, value) = build_auth_header(secret, &scheme).unwrap();
        assert_eq!(name, "X-Goog-Api-Key");
        assert_eq!(value, "secret-key-123");
    }

    #[test]
    fn header_non_utf8_rejected() {
        let secret = &[0xFF, 0xFE];
        let scheme = AuthScheme::Header {
            name: "X-Api-Key".to_string(),
        };
        let result = build_auth_header(secret, &scheme);
        assert!(matches!(result, Err(TransportError::InvalidCredential)));
    }

    #[test]
    fn inject_credential_header_succeeds() {
        let secret = Zeroizing::new(b"custom-api-token".to_vec());
        let client = reqwest::Client::new();
        let builder = client.get("https://example.com/api");
        let scheme = AuthScheme::Header {
            name: "X-Custom-Auth".to_string(),
        };
        let result = inject_credential(secret, builder, &scheme);
        assert!(result.is_ok(), "header injection must succeed");
    }
}
