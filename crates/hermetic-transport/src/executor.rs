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

//! HTTP executor — HC-2 (SSRF connect-by-IP) + HC-3 (credential zeroization).
//!
//! HC-2 BINDING: DNS resolve → validate ALL IPs → connect-by-IP via
//! `ClientBuilder::resolve()`. The URL hostname is NEVER mutated; reqwest
//! derives TLS SNI and the Host header directly from the URL. Redirects are
//! NOT followed automatically; each hop is re-validated before following.
//!
//! HC-3 BINDING: Credential zeroization MUST occur AFTER header construction
//! and BEFORE the first `.await`. Zeroize regardless of whether credential
//! injection succeeds or fails.
//!
//! MCP-1 BINDING: No secret bytes in any error path or log.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use reqwest::header::HeaderMap;
use url::Url;
use zeroize::Zeroizing;

use crate::{
    auth::{inject_credential, AuthScheme},
    error::TransportError,
    ssrf::{validate_resolved_ips, DnsResolver},
};

/// Maximum response body size accepted (1 MiB).
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;

/// Maximum number of redirect hops followed.
pub const MAX_REDIRECTS: u32 = 3;

/// TCP connect timeout.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Total request timeout (headers + body).
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

// -----------------------------------------------------------------------
// Request / Response types
// -----------------------------------------------------------------------

/// Outbound HTTP request descriptor.
///
/// NOT `Clone` — credential bytes must not be silently duplicated.
pub struct TransportRequest {
    /// Fully-qualified HTTPS URL. The scheme MUST be `https`.
    pub url: String,
    /// HTTP method (GET, POST, PUT, PATCH, DELETE, HEAD).
    pub method: String,
    /// Request headers (name, value) pairs. Subject to HC-7 forbidden header filtering.
    pub headers: Vec<(String, String)>,
    /// Optional request body.
    pub body: Option<Vec<u8>>,
    /// Optional credential to inject. Consumed and zeroized inside `execute()`.
    pub credential: Option<(Zeroizing<Vec<u8>>, AuthScheme)>,
    /// Extra headers injected AFTER HC-7 filtering. Used for SigV4 pre-signed headers
    /// (Authorization, x-amz-date, x-amz-content-sha256, x-amz-security-token).
    /// HC-7 exception: daemon-controlled headers, not agent-supplied.
    pub extra_headers: Vec<(String, String)>,
}

/// Response from a completed HTTP request.
#[derive(Debug)]
pub struct TransportResponse {
    /// HTTP status code.
    pub status: u16,
    /// Filtered response headers.
    pub headers: Vec<(String, String)>,
    /// Response body bytes (capped at `MAX_RESPONSE_BYTES`).
    pub body: Vec<u8>,
}

// -----------------------------------------------------------------------
// Header filtering
// -----------------------------------------------------------------------

/// Response headers permitted to pass through.
///
/// Strips hop-by-hop headers (Connection, Transfer-Encoding, etc.) and
/// internal headers that could confuse callers.
const ALLOWED_RESPONSE_HEADERS: &[&str] = &[
    "content-type",
    "content-length",
    "content-encoding",
    "cache-control",
    "etag",
    "last-modified",
    "retry-after",
    "x-request-id",
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
];

/// Filter response headers to the allow-list only.
pub fn filter_response_headers(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            let name_lower = name.as_str().to_ascii_lowercase();
            if ALLOWED_RESPONSE_HEADERS.contains(&name_lower.as_str()) {
                let v = value.to_str().ok()?.to_string();
                Some((name.as_str().to_string(), v))
            } else {
                None
            }
        })
        .collect()
}

/// Request headers that MUST NOT be set by MCP callers.
///
/// HC-7 BINDING: Agent-supplied headers are filtered before injection.
/// - `host`: Prevents CDN/reverse-proxy tenant-routing attacks.
/// - `authorization`: Credential injection is exclusive to HC-3 inject_credential().
/// - `connection` / `transfer-encoding`: Prevents request smuggling.
/// - `x-forwarded-*` / `x-real-ip`: Prevents origin identity spoofing at LBs.
/// - `proxy-authorization` / `proxy-connection`: Prevents proxy credential injection.
const FORBIDDEN_REQUEST_HEADERS: &[&str] = &[
    "host",
    "authorization",
    "connection",
    "transfer-encoding",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-real-ip",
    "proxy-authorization",
    "proxy-connection",
    "content-length",
    "te",
];

/// Returns true if the header name is forbidden for MCP callers.
fn is_forbidden_request_header(name: &str) -> bool {
    FORBIDDEN_REQUEST_HEADERS.contains(&name.to_ascii_lowercase().as_str())
}

/// Default User-Agent value injected when the agent does not supply one.
/// Static string only — no system information leakage.
const DEFAULT_USER_AGENT: &str = "Hermetic/1.0";

/// Returns true if the header list contains a User-Agent header (case-insensitive).
fn has_user_agent_header(headers: &[(String, String)]) -> bool {
    headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("user-agent"))
}

/// Determine HTTP method for redirect hop per RFC 7231.
///
/// - 301, 302: POST → GET; other methods preserved.
/// - 303: ALWAYS GET regardless of original method.
/// - 307, 308: method preserved (body preserved separately by caller).
/// - Unknown: defaults to GET.
fn redirect_method(status_code: u16, current: &reqwest::Method) -> reqwest::Method {
    match status_code {
        301 | 302 => {
            if *current == reqwest::Method::POST {
                reqwest::Method::GET
            } else {
                current.clone()
            }
        }
        303 => reqwest::Method::GET,
        307 | 308 => current.clone(),
        _ => reqwest::Method::GET,
    }
}

/// Check that response body does not exceed MAX_RESPONSE_BYTES.
fn check_body_size(len: usize) -> Result<(), TransportError> {
    if len > MAX_RESPONSE_BYTES {
        return Err(TransportError::ResponseTooLarge);
    }
    Ok(())
}

/// Reject redirect URLs with embedded credentials or non-HTTPS scheme.
fn validate_redirect_url(url: &Url) -> Result<(), TransportError> {
    if url.username() != "" || url.password().is_some() {
        return Err(TransportError::InvalidUrl(
            "embedded credentials in redirect".into(),
        ));
    }
    if url.scheme() != "https" {
        return Err(TransportError::RedirectSchemeDowngrade);
    }
    Ok(())
}

// -----------------------------------------------------------------------
// Core executor
// -----------------------------------------------------------------------

/// Execute an outbound HTTPS request with HC-2 SSRF protection.
///
/// # HC-2 execution phases
///
/// 1. Parse URL, enforce HTTPS scheme.
/// 2. DNS-resolve the target host; validate ALL resolved IPs; pick first public IP.
/// 3. Build reqwest client with `redirect::Policy::none()` and `.resolve()` to
///    pin the validated IP without mutating the URL hostname (TLS SNI intact).
/// 4. Inject credential (HC-3: zeroize BEFORE first `.await`).
/// 5. Send initial request.
/// 6. On 3xx: validate redirect target via DNS; re-validate IP; enforce HTTPS;
///    apply method conversion rules; build NEW client with per-hop `.resolve()`;
///    follow up to `MAX_REDIRECTS` hops.
/// 7. Cap response body at `MAX_RESPONSE_BYTES`; filter headers.
pub async fn execute(
    request: TransportRequest,
    resolver: Arc<dyn DnsResolver>,
) -> Result<TransportResponse, TransportError> {
    // ------------------------------------------------------------------
    // Phase 1: Parse URL + enforce HTTPS
    // ------------------------------------------------------------------
    let url = Url::parse(&request.url).map_err(|e| TransportError::InvalidUrl(e.to_string()))?;

    if url.scheme() != "https" {
        return Err(TransportError::SchemeNotHttps);
    }

    // HC-7-URL: Reject embedded credentials in initial URL.
    // Same check as redirect path (line ~279). Prevents credential confusion
    // where agent-supplied user:pass@ in URL could override or conflict with
    // HC-3 inject_credential().
    if url.username() != "" || url.password().is_some() {
        return Err(TransportError::InvalidUrl(
            "embedded credentials in URL".into(),
        ));
    }

    let original_host = url
        .host_str()
        .ok_or_else(|| TransportError::InvalidUrl("missing host".to_string()))?
        .to_string();
    let port = url.port_or_known_default().unwrap_or(443);

    // ------------------------------------------------------------------
    // Phase 2: DNS resolve + SSRF IP validation (HC-2)
    // ------------------------------------------------------------------
    let resolved_ip = {
        let host = original_host.clone();
        let r = Arc::clone(&resolver);
        tokio::task::spawn_blocking(move || r.resolve(&host, port))
            .await
            .map_err(|e| TransportError::DnsResolutionFailed(e.to_string()))??
    };
    let connect_ip = validate_resolved_ips(&resolved_ip)?;

    // HC-2-RESOLVE-1: Normalize hostname for .resolve() key matching.
    // Prevents trailing-dot or case mismatch causing reqwest DNS fallback
    // HC-2: ensure .resolve() key matches to prevent DNS re-resolution.
    let resolve_key = original_host.trim_end_matches('.').to_lowercase();

    // ------------------------------------------------------------------
    // Phase 3: Build client — .resolve() pins IP without mutating URL.
    // URL hostname is preserved for TLS SNI + Host header derivation.
    // ------------------------------------------------------------------
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .cookie_store(false)
        .resolve(&resolve_key, SocketAddr::new(connect_ip, port))
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .build()
        .map_err(|e| TransportError::HttpError(e.to_string()))?;

    // ------------------------------------------------------------------
    // Phase 4: Build initial request builder
    // ------------------------------------------------------------------
    let method = reqwest::Method::from_bytes(request.method.to_ascii_uppercase().as_bytes())
        .map_err(|_| TransportError::InvalidUrl(format!("invalid method: {}", request.method)))?;

    // Clone body before consuming it — needed to re-attach on 307/308 redirects.
    let original_body = request.body.clone();

    let mut builder = client.request(method.clone(), url.as_str());

    // HC-12 B-5: Default User-Agent injection — BEFORE HC-7 forbidden header
    // stripping. If the agent does not supply a User-Agent header, inject
    // "Hermetic/1.0". User-Agent is NOT on the HC-7 forbidden list.
    if !has_user_agent_header(&request.headers) {
        builder = builder.header("user-agent", DEFAULT_USER_AGENT);
    }

    // Caller-supplied headers — HC-7: strip forbidden headers.
    for (name, value) in &request.headers {
        if is_forbidden_request_header(name) {
            // Silently drop. Do NOT log the value (MCP-1).
            continue;
        }
        builder = builder.header(name.as_str(), value.as_str());
    }

    // HC-7 exception: daemon-provided headers (SigV4 Authorization, x-amz-date).
    for (name, value) in &request.extra_headers {
        builder = builder.header(name.as_str(), value.as_str());
    }

    // Body.
    if let Some(body) = request.body {
        builder = builder.body(body);
    }

    // ------------------------------------------------------------------
    // Phase 5: Credential injection — HC-3 BINDING
    // Zeroize BEFORE first `.await`. inject_credential consumes the secret.
    // ------------------------------------------------------------------
    if let Some((secret, scheme)) = request.credential {
        builder = inject_credential(secret, builder, &scheme)
            .map_err(|e| TransportError::InjectionFailed(e.to_string()))?;
    }

    // ------------------------------------------------------------------
    // Phase 6: Send initial request (first .await — credential already zeroized)
    // ------------------------------------------------------------------
    let mut response = builder
        .send()
        .await
        .map_err(|e| TransportError::HttpError(e.to_string()))?;

    // ------------------------------------------------------------------
    // Phase 7: Redirect loop — HC-2 re-validation on every hop
    // ------------------------------------------------------------------
    let mut redirect_count: u32 = 0;
    let mut current_method = method;
    // Tracks the logical URL of the last request for relative redirect resolution.
    // URL is never mutated, so current_url is always hostname-bearing.
    let mut current_url = url;

    while response.status().is_redirection() {
        if redirect_count >= MAX_REDIRECTS {
            return Err(TransportError::TooManyRedirects);
        }
        redirect_count += 1;

        let status_code = response.status().as_u16();

        let location = response
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                TransportError::HttpError("redirect missing Location header".to_string())
            })?
            .to_string();

        // Parse redirect URL — use join() so relative Location values are
        // resolved against the current logical URL.
        let redirect_url = current_url
            .join(&location)
            .map_err(|e| TransportError::InvalidUrl(e.to_string()))?;

        // Reject embedded credentials + enforce HTTPS on redirect target.
        validate_redirect_url(&redirect_url)?;

        let redirect_host = redirect_url
            .host_str()
            .ok_or_else(|| TransportError::InvalidUrl("redirect missing host".to_string()))?
            .to_string();
        let redirect_port = redirect_url.port_or_known_default().unwrap_or(443);

        // HC-2: Re-validate DNS for redirect target.
        let redirect_ips = {
            let host = redirect_host.clone();
            let r = Arc::clone(&resolver);
            tokio::task::spawn_blocking(move || r.resolve(&host, redirect_port))
                .await
                .map_err(|e| TransportError::DnsResolutionFailed(e.to_string()))??
        };
        let redirect_ip = validate_resolved_ips(&redirect_ips)
            .map_err(|_| TransportError::RedirectSsrfBlocked(redirect_ips[0].to_string()))?;

        // Normalize redirect hostname for .resolve() key matching.
        let redirect_resolve_key = redirect_host.trim_end_matches('.').to_lowercase();

        // Build NEW client per hop with .resolve() for the redirect target.
        // URL is never mutated — hostname stays intact for TLS SNI.
        let redirect_client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .cookie_store(false)
            .resolve(
                &redirect_resolve_key,
                SocketAddr::new(redirect_ip, redirect_port),
            )
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|e| TransportError::HttpError(e.to_string()))?;

        // Redirect method conversion (RFC 7231).
        // Credentials are NEVER resent on redirect.
        let next_method = redirect_method(status_code, &current_method);

        let mut redirect_builder =
            redirect_client.request(next_method.clone(), redirect_url.as_str());

        // Re-attach original body on 307/308 (method + body preserved).
        // 301/302/303 strip the body (no attachment here).
        if matches!(status_code, 307 | 308) {
            if let Some(ref b) = original_body {
                redirect_builder = redirect_builder.body(b.clone());
            }
        }

        response = redirect_builder
            .send()
            .await
            .map_err(|e| TransportError::HttpError(e.to_string()))?;

        // URL is never mutated, so redirect_url is already hostname-bearing.
        current_url = redirect_url;
        current_method = next_method;
    }

    // ------------------------------------------------------------------
    // Phase 8: Response — body cap + header filtering
    // ------------------------------------------------------------------
    let status = response.status().as_u16();
    let filtered_headers = filter_response_headers(response.headers());

    // Stream body with 1 MiB cap.
    let body_bytes = response
        .bytes()
        .await
        .map_err(|e| TransportError::HttpError(e.to_string()))?;

    check_body_size(body_bytes.len())?;

    Ok(TransportResponse {
        status,
        headers: filtered_headers,
        body: body_bytes.to_vec(),
    })
}

// -----------------------------------------------------------------------
// Tests (unit — no network)
// -----------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::sync::Arc;

    use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

    use super::{
        execute, filter_response_headers, TransportRequest, MAX_REDIRECTS, MAX_RESPONSE_BYTES,
    };
    use crate::error::TransportError;
    use crate::ssrf::DnsResolver;

    /// Mock DNS resolver for unit tests — returns configurable IPs.
    struct MockDnsResolver {
        ips: Vec<IpAddr>,
    }

    impl DnsResolver for MockDnsResolver {
        fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<IpAddr>, TransportError> {
            if self.ips.is_empty() {
                return Err(TransportError::DnsResolutionFailed(
                    "mock: no addresses".into(),
                ));
            }
            Ok(self.ips.clone())
        }
    }

    fn public_resolver() -> Arc<dyn DnsResolver> {
        Arc::new(MockDnsResolver {
            ips: vec!["93.184.216.34".parse().unwrap()],
        })
    }

    fn private_resolver() -> Arc<dyn DnsResolver> {
        Arc::new(MockDnsResolver {
            ips: vec!["10.0.0.1".parse().unwrap()],
        })
    }

    fn empty_resolver() -> Arc<dyn DnsResolver> {
        Arc::new(MockDnsResolver { ips: vec![] })
    }

    #[test]
    fn constants_correct() {
        assert_eq!(MAX_RESPONSE_BYTES, 1_048_576);
        assert_eq!(MAX_REDIRECTS, 3);
    }

    #[test]
    fn filter_allows_content_type() {
        let mut map = HeaderMap::new();
        map.insert(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("application/json"),
        );
        let filtered = filter_response_headers(&map);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].0, "content-type");
        assert_eq!(filtered[0].1, "application/json");
    }

    #[test]
    fn filter_strips_set_cookie() {
        let mut map = HeaderMap::new();
        map.insert(
            HeaderName::from_static("set-cookie"),
            HeaderValue::from_static("session=abc"),
        );
        let filtered = filter_response_headers(&map);
        assert!(filtered.is_empty(), "set-cookie must be stripped");
    }

    #[test]
    fn filter_strips_transfer_encoding() {
        let mut map = HeaderMap::new();
        map.insert(
            HeaderName::from_static("transfer-encoding"),
            HeaderValue::from_static("chunked"),
        );
        let filtered = filter_response_headers(&map);
        assert!(filtered.is_empty(), "transfer-encoding must be stripped");
    }

    #[test]
    fn filter_allows_ratelimit_headers() {
        let mut map = HeaderMap::new();
        map.insert(
            HeaderName::from_static("x-ratelimit-limit"),
            HeaderValue::from_static("100"),
        );
        map.insert(
            HeaderName::from_static("x-ratelimit-remaining"),
            HeaderValue::from_static("99"),
        );
        let filtered = filter_response_headers(&map);
        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn default_user_agent_injected_when_absent() {
        use super::{has_user_agent_header, DEFAULT_USER_AGENT};

        let headers: Vec<(String, String)> = vec![
            ("Content-Type".into(), "application/json".into()),
            ("Accept".into(), "text/html".into()),
        ];
        assert!(!has_user_agent_header(&headers), "no User-Agent in headers");
        assert_eq!(DEFAULT_USER_AGENT, "Hermetic/1.0");
    }

    #[test]
    fn agent_user_agent_preserved() {
        use super::has_user_agent_header;

        let headers: Vec<(String, String)> = vec![
            ("User-Agent".into(), "MyAgent/2.0".into()),
            ("Accept".into(), "text/html".into()),
        ];
        assert!(
            has_user_agent_header(&headers),
            "agent-supplied User-Agent must be detected"
        );
    }

    #[test]
    fn user_agent_detection_case_insensitive() {
        use super::has_user_agent_header;

        assert!(has_user_agent_header(&[("user-agent".into(), "x".into())]));
        assert!(has_user_agent_header(&[("User-Agent".into(), "x".into())]));
        assert!(has_user_agent_header(&[("USER-AGENT".into(), "x".into())]));
        assert!(!has_user_agent_header(&[(
            "Content-Type".into(),
            "x".into()
        )]));
    }

    #[test]
    fn forbidden_headers_stripped_with_user_agent_present() {
        use super::{has_user_agent_header, is_forbidden_request_header};

        let headers: Vec<(String, String)> = vec![
            ("User-Agent".into(), "MyAgent/2.0".into()),
            ("Host".into(), "evil.com".into()),
            ("Authorization".into(), "Bearer secret".into()),
            ("Content-Type".into(), "application/json".into()),
        ];

        // User-Agent is present
        assert!(has_user_agent_header(&headers));
        // HC-7 still strips forbidden headers
        assert!(is_forbidden_request_header("Host"));
        assert!(is_forbidden_request_header("Authorization"));
        // User-Agent is NOT forbidden
        assert!(!is_forbidden_request_header("User-Agent"));

        // Simulate the header filtering loop
        let allowed: Vec<_> = headers
            .iter()
            .filter(|(name, _)| !is_forbidden_request_header(name))
            .collect();

        // User-Agent and Content-Type pass through; Host and Authorization stripped
        assert_eq!(allowed.len(), 2);
        assert_eq!(allowed[0].0, "User-Agent");
        assert_eq!(allowed[0].1, "MyAgent/2.0");
        assert_eq!(allowed[1].0, "Content-Type");
    }

    #[test]
    fn forbidden_request_headers_blocked() {
        use super::is_forbidden_request_header;
        // All must be blocked (case-insensitive)
        assert!(is_forbidden_request_header("Host"));
        assert!(is_forbidden_request_header("host"));
        assert!(is_forbidden_request_header("HOST"));
        assert!(is_forbidden_request_header("Authorization"));
        assert!(is_forbidden_request_header("Connection"));
        assert!(is_forbidden_request_header("Transfer-Encoding"));
        assert!(is_forbidden_request_header("X-Forwarded-For"));
        assert!(is_forbidden_request_header("X-Forwarded-Host"));
        assert!(is_forbidden_request_header("X-Forwarded-Proto"));
        assert!(is_forbidden_request_header("X-Real-Ip"));
        assert!(is_forbidden_request_header("Proxy-Authorization"));
        assert!(is_forbidden_request_header("Proxy-Connection"));
        // These must be allowed
        assert!(!is_forbidden_request_header("Content-Type"));
        assert!(!is_forbidden_request_header("Accept"));
        assert!(!is_forbidden_request_header("User-Agent"));
        assert!(!is_forbidden_request_header("X-Api-Key"));
    }

    // ---------------------------------------------------------------
    // filter_response_headers — additional edge cases
    // ---------------------------------------------------------------

    #[test]
    fn filter_empty_header_map() {
        let map = HeaderMap::new();
        let filtered = filter_response_headers(&map);
        assert!(filtered.is_empty());
    }

    #[test]
    fn filter_all_allowed_headers_pass() {
        let mut map = HeaderMap::new();
        map.insert(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("text/html"),
        );
        map.insert(
            HeaderName::from_static("content-length"),
            HeaderValue::from_static("42"),
        );
        map.insert(
            HeaderName::from_static("content-encoding"),
            HeaderValue::from_static("gzip"),
        );
        map.insert(
            HeaderName::from_static("cache-control"),
            HeaderValue::from_static("no-cache"),
        );
        map.insert(
            HeaderName::from_static("etag"),
            HeaderValue::from_static("\"abc\""),
        );
        map.insert(
            HeaderName::from_static("last-modified"),
            HeaderValue::from_static("Thu, 01 Jan 2026 00:00:00 GMT"),
        );
        map.insert(
            HeaderName::from_static("retry-after"),
            HeaderValue::from_static("120"),
        );
        map.insert(
            HeaderName::from_static("x-request-id"),
            HeaderValue::from_static("req-123"),
        );
        map.insert(
            HeaderName::from_static("x-ratelimit-limit"),
            HeaderValue::from_static("100"),
        );
        map.insert(
            HeaderName::from_static("x-ratelimit-remaining"),
            HeaderValue::from_static("99"),
        );
        map.insert(
            HeaderName::from_static("x-ratelimit-reset"),
            HeaderValue::from_static("1700000000"),
        );
        let filtered = filter_response_headers(&map);
        assert_eq!(filtered.len(), 11, "all 11 allowed headers must pass");
    }

    #[test]
    fn filter_mixed_allowed_and_disallowed() {
        let mut map = HeaderMap::new();
        map.insert(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("application/json"),
        );
        map.insert(
            HeaderName::from_static("server"),
            HeaderValue::from_static("nginx"),
        );
        map.insert(
            HeaderName::from_static("x-powered-by"),
            HeaderValue::from_static("express"),
        );
        map.insert(
            HeaderName::from_static("etag"),
            HeaderValue::from_static("\"v1\""),
        );
        let filtered = filter_response_headers(&map);
        assert_eq!(filtered.len(), 2);
        let names: Vec<&str> = filtered.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"content-type"));
        assert!(names.contains(&"etag"));
    }

    // ---------------------------------------------------------------
    // execute() — early-exit validation paths (no HTTP needed)
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn execute_rejects_http_scheme() {
        let request = TransportRequest {
            url: "http://example.com/api".to_string(),
            method: "GET".to_string(),
            headers: vec![],
            body: None,
            credential: None,
            extra_headers: vec![],
        };
        let result = execute(request, public_resolver()).await;
        assert!(
            matches!(result, Err(TransportError::SchemeNotHttps)),
            "http:// must be rejected"
        );
    }

    #[tokio::test]
    async fn execute_rejects_ftp_scheme() {
        let request = TransportRequest {
            url: "ftp://example.com/file".to_string(),
            method: "GET".to_string(),
            headers: vec![],
            body: None,
            credential: None,
            extra_headers: vec![],
        };
        let result = execute(request, public_resolver()).await;
        assert!(
            matches!(result, Err(TransportError::SchemeNotHttps)),
            "ftp:// must be rejected as non-HTTPS"
        );
    }

    #[tokio::test]
    async fn execute_rejects_invalid_url() {
        let request = TransportRequest {
            url: "not a url at all".to_string(),
            method: "GET".to_string(),
            headers: vec![],
            body: None,
            credential: None,
            extra_headers: vec![],
        };
        let result = execute(request, public_resolver()).await;
        assert!(matches!(result, Err(TransportError::InvalidUrl(_))));
    }

    #[tokio::test]
    async fn execute_rejects_embedded_userinfo() {
        let request = TransportRequest {
            url: "https://user:pass@example.com/api".to_string(),
            method: "GET".to_string(),
            headers: vec![],
            body: None,
            credential: None,
            extra_headers: vec![],
        };
        let result = execute(request, public_resolver()).await;
        assert!(
            matches!(result, Err(TransportError::InvalidUrl(ref msg)) if msg.contains("embedded credentials")),
            "URL with user:pass@ must be rejected"
        );
    }

    #[tokio::test]
    async fn execute_rejects_embedded_username_only() {
        let request = TransportRequest {
            url: "https://user@example.com/api".to_string(),
            method: "GET".to_string(),
            headers: vec![],
            body: None,
            credential: None,
            extra_headers: vec![],
        };
        let result = execute(request, public_resolver()).await;
        assert!(
            matches!(result, Err(TransportError::InvalidUrl(_))),
            "URL with user@ must be rejected"
        );
    }

    #[tokio::test]
    async fn execute_rejects_private_dns() {
        let request = TransportRequest {
            url: "https://example.com/api".to_string(),
            method: "GET".to_string(),
            headers: vec![],
            body: None,
            credential: None,
            extra_headers: vec![],
        };
        let result = execute(request, private_resolver()).await;
        assert!(
            matches!(result, Err(TransportError::SsrfBlocked(_))),
            "DNS resolving to private IP must be blocked"
        );
    }

    #[tokio::test]
    async fn execute_rejects_empty_dns() {
        let request = TransportRequest {
            url: "https://example.com/api".to_string(),
            method: "GET".to_string(),
            headers: vec![],
            body: None,
            credential: None,
            extra_headers: vec![],
        };
        let result = execute(request, empty_resolver()).await;
        assert!(
            matches!(result, Err(TransportError::DnsResolutionFailed(_))),
            "empty DNS result must fail"
        );
    }

    #[tokio::test]
    async fn execute_rejects_invalid_method() {
        let request = TransportRequest {
            url: "https://example.com/api".to_string(),
            method: "NOT A METHOD !@#".to_string(),
            headers: vec![],
            body: None,
            credential: None,
            extra_headers: vec![],
        };
        let result = execute(request, public_resolver()).await;
        assert!(
            matches!(result, Err(TransportError::InvalidUrl(_))),
            "invalid HTTP method must be rejected"
        );
    }

    // ---------------------------------------------------------------
    // has_user_agent_header — additional edge cases
    // ---------------------------------------------------------------

    #[test]
    fn user_agent_empty_headers_returns_false() {
        use super::has_user_agent_header;
        let headers: Vec<(String, String)> = vec![];
        assert!(!has_user_agent_header(&headers));
    }

    #[test]
    fn user_agent_empty_value_still_detected() {
        use super::has_user_agent_header;
        // Empty User-Agent value still means the header exists
        assert!(has_user_agent_header(&[("User-Agent".into(), "".into())]));
    }

    #[test]
    fn default_user_agent_value_is_hermetic() {
        use super::DEFAULT_USER_AGENT;
        assert_eq!(DEFAULT_USER_AGENT, "Hermetic/1.0");
        assert!(!DEFAULT_USER_AGENT.is_empty());
    }

    // ---------------------------------------------------------------
    // redirect_method — RFC 7231 method conversion
    // ---------------------------------------------------------------

    #[test]
    fn redirect_301_post_becomes_get() {
        let m = super::redirect_method(301, &reqwest::Method::POST);
        assert_eq!(m, reqwest::Method::GET);
    }

    #[test]
    fn redirect_301_get_stays_get() {
        let m = super::redirect_method(301, &reqwest::Method::GET);
        assert_eq!(m, reqwest::Method::GET);
    }

    #[test]
    fn redirect_301_put_stays_put() {
        let m = super::redirect_method(301, &reqwest::Method::PUT);
        assert_eq!(m, reqwest::Method::PUT);
    }

    #[test]
    fn redirect_302_post_becomes_get() {
        let m = super::redirect_method(302, &reqwest::Method::POST);
        assert_eq!(m, reqwest::Method::GET);
    }

    #[test]
    fn redirect_302_delete_stays_delete() {
        let m = super::redirect_method(302, &reqwest::Method::DELETE);
        assert_eq!(m, reqwest::Method::DELETE);
    }

    #[test]
    fn redirect_303_always_get() {
        assert_eq!(
            super::redirect_method(303, &reqwest::Method::POST),
            reqwest::Method::GET
        );
        assert_eq!(
            super::redirect_method(303, &reqwest::Method::PUT),
            reqwest::Method::GET
        );
        assert_eq!(
            super::redirect_method(303, &reqwest::Method::DELETE),
            reqwest::Method::GET
        );
        assert_eq!(
            super::redirect_method(303, &reqwest::Method::GET),
            reqwest::Method::GET
        );
    }

    #[test]
    fn redirect_307_preserves_method() {
        assert_eq!(
            super::redirect_method(307, &reqwest::Method::POST),
            reqwest::Method::POST
        );
        assert_eq!(
            super::redirect_method(307, &reqwest::Method::PUT),
            reqwest::Method::PUT
        );
        assert_eq!(
            super::redirect_method(307, &reqwest::Method::GET),
            reqwest::Method::GET
        );
    }

    #[test]
    fn redirect_308_preserves_method() {
        assert_eq!(
            super::redirect_method(308, &reqwest::Method::POST),
            reqwest::Method::POST
        );
        assert_eq!(
            super::redirect_method(308, &reqwest::Method::DELETE),
            reqwest::Method::DELETE
        );
    }

    #[test]
    fn redirect_unknown_status_defaults_to_get() {
        assert_eq!(
            super::redirect_method(399, &reqwest::Method::POST),
            reqwest::Method::GET
        );
    }

    // ---------------------------------------------------------------
    // check_body_size — response body cap
    // ---------------------------------------------------------------

    #[test]
    fn body_size_zero_ok() {
        assert!(super::check_body_size(0).is_ok());
    }

    #[test]
    fn body_size_at_limit_ok() {
        assert!(super::check_body_size(MAX_RESPONSE_BYTES).is_ok());
    }

    #[test]
    fn body_size_one_over_limit_rejected() {
        let result = super::check_body_size(MAX_RESPONSE_BYTES + 1);
        assert!(matches!(result, Err(TransportError::ResponseTooLarge)));
    }

    #[test]
    fn body_size_way_over_limit_rejected() {
        let result = super::check_body_size(MAX_RESPONSE_BYTES * 2);
        assert!(matches!(result, Err(TransportError::ResponseTooLarge)));
    }

    // ---------------------------------------------------------------
    // validate_redirect_url — credential + scheme checks
    // ---------------------------------------------------------------

    #[test]
    fn redirect_url_https_no_creds_ok() {
        let url = url::Url::parse("https://example.com/path").unwrap();
        assert!(super::validate_redirect_url(&url).is_ok());
    }

    #[test]
    fn redirect_url_with_userinfo_rejected() {
        let url = url::Url::parse("https://user:pass@example.com/").unwrap();
        let result = super::validate_redirect_url(&url);
        assert!(
            matches!(result, Err(TransportError::InvalidUrl(ref msg)) if msg.contains("embedded credentials"))
        );
    }

    #[test]
    fn redirect_url_with_username_only_rejected() {
        let url = url::Url::parse("https://user@example.com/").unwrap();
        let result = super::validate_redirect_url(&url);
        assert!(matches!(result, Err(TransportError::InvalidUrl(_))));
    }

    #[test]
    fn redirect_url_http_scheme_rejected() {
        let url = url::Url::parse("http://example.com/path").unwrap();
        let result = super::validate_redirect_url(&url);
        assert!(matches!(
            result,
            Err(TransportError::RedirectSchemeDowngrade)
        ));
    }

    #[test]
    fn redirect_url_ftp_scheme_rejected() {
        let url = url::Url::parse("ftp://example.com/file").unwrap();
        let result = super::validate_redirect_url(&url);
        assert!(matches!(
            result,
            Err(TransportError::RedirectSchemeDowngrade)
        ));
    }

    #[test]
    fn redirect_url_http_with_creds_rejected_as_creds() {
        // Credentials check fires before scheme check
        let url = url::Url::parse("http://user:pass@example.com/").unwrap();
        let result = super::validate_redirect_url(&url);
        assert!(matches!(result, Err(TransportError::InvalidUrl(_))));
    }
}
