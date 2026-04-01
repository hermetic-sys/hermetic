// Copyright (C) 2026 The Hermetic Project <dev@hermeticsys.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licenses available at hermeticsys.com/license

//! Hermetic Transport — HTTP executor with credential injection and SSRF protection.
//!
//! This crate handles outbound HTTP requests with injected credentials.
//! It does NOT manage secret lifecycle — it accepts `Zeroizing<Vec<u8>>`
//! from callers, injects into requests, and zeroizes its copy.
//!
//! Consumers: hermetic-mcp (Phase 2.7), hermetic-sdk (future).

#![forbid(unsafe_code)]
#![deny(clippy::all)]

pub mod auth;
pub mod error;
pub mod executor;
#[cfg(feature = "oauth-refresh")]
pub mod refresh;
pub mod ssrf;
