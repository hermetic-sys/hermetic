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

//! Transport error types.
//!
//! MCP-1 BINDING: No secret material in any variant, Display output,
//! or Debug output. Diagnostic strings contain URLs, error descriptions,
//! or policy violation names only.

use std::fmt;

/// Errors from the transport layer.
#[derive(Debug)]
pub enum TransportError {
    /// URL parsing or structural error
    InvalidUrl(String),
    /// Scheme is not HTTPS (http, ftp, ws, etc. rejected)
    SchemeNotHttps,
    /// SSRF: private/reserved IP detected in DNS resolution (carries blocked IP string)
    SsrfBlocked(String),
    /// DNS resolution failure
    DnsResolutionFailed(String),
    /// Too many redirects (max 3)
    TooManyRedirects,
    /// Redirect target has private IP (HC-2: re-validation; carries blocked IP string)
    RedirectSsrfBlocked(String),
    /// Redirect downgrades from HTTPS to HTTP
    RedirectSchemeDowngrade,
    /// Response body exceeds 1MB cap
    ResponseTooLarge,
    /// HTTP client error (reqwest)
    HttpError(String),
    /// Invalid auth scheme or credential format (non-UTF8, etc.)
    InvalidCredential,
    /// Credential injection failure
    InjectionFailed(String),
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUrl(msg) => write!(f, "invalid URL: {msg}"),
            Self::SchemeNotHttps => write!(f, "scheme must be https"),
            Self::SsrfBlocked(ip) => write!(f, "SSRF: blocked IP {ip}"),
            Self::DnsResolutionFailed(msg) => write!(f, "DNS resolution failed: {msg}"),
            Self::TooManyRedirects => write!(f, "too many redirects (max 3)"),
            Self::RedirectSsrfBlocked(ip) => write!(f, "redirect target blocked IP {ip}"),
            Self::RedirectSchemeDowngrade => write!(f, "redirect downgrades HTTPS to HTTP"),
            Self::ResponseTooLarge => write!(f, "response exceeds 1MB cap"),
            Self::HttpError(msg) => write!(f, "HTTP error: {msg}"),
            Self::InvalidCredential => write!(f, "invalid credential format"),
            Self::InjectionFailed(msg) => write!(f, "credential injection failed: {msg}"),
        }
    }
}

impl std::error::Error for TransportError {}
