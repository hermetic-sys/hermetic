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

//! Opaque credential handle — SECURITY-CRITICAL.
//!
//! SecretHandle wraps secret bytes in Rust and exposes ZERO Python-visible
//! paths to read them. Every Python introspection escape hatch (__str__,
//! __repr__, __reduce__, __copy__, __getstate__, etc.) is overridden to
//! return opaque values or raise errors.
//!
//! REUSE SEMANTICS: The handle is reusable until explicitly destroyed via
//! .destroy() or garbage-collected. Each call to authenticated_request /
//! hmac_sign / hmac_verify clones the secret inside Rust (both copies
//! Zeroizing, clone consumed by operation, original stays for reuse).
//!
//! PYSDK-A4: No __del__ — Rust Drop handles cleanup via PyO3.

use std::sync::{Arc, Mutex};

use pyo3::exceptions::{PyRuntimeError, PyTypeError};
use pyo3::prelude::*;
use ring::hmac;
use zeroize::Zeroizing;

use crate::types;

/// Return type for clone_secret: (secret_bytes, auth_scheme, runtime).
pub type ClonedSecret = (
    Zeroizing<Vec<u8>>,
    Option<String>,
    Arc<tokio::runtime::Runtime>,
);

/// Opaque credential handle. Secret bytes NEVER leak to Python.
#[pyclass]
pub struct SecretHandle {
    inner: Mutex<Option<Zeroizing<Vec<u8>>>>,
    auth_scheme: Option<String>,
    display_id: String,
    destroyed: Mutex<bool>,
    runtime: Arc<tokio::runtime::Runtime>,
}

impl SecretHandle {
    /// Create a new handle (Rust-side only, not exposed to Python).
    pub fn new(
        secret: Zeroizing<Vec<u8>>,
        auth_scheme: Option<String>,
        display_id: String,
        runtime: Arc<tokio::runtime::Runtime>,
    ) -> Self {
        Self {
            inner: Mutex::new(Some(secret)),
            auth_scheme,
            display_id,
            destroyed: Mutex::new(false),
            runtime,
        }
    }

    /// Clone the inner secret for use in an operation. NON-CONSUMING.
    /// The original stays in the Mutex for reuse. The clone is wrapped
    /// in Zeroizing and consumed by the caller.
    /// Returns None if destroyed.
    fn clone_secret(&self) -> Option<ClonedSecret> {
        let guard = self.inner.lock().ok()?;
        let secret = guard.as_ref()?;
        let cloned = Zeroizing::new(secret.to_vec());
        Some((cloned, self.auth_scheme.clone(), Arc::clone(&self.runtime)))
    }
}

#[pymethods]
impl SecretHandle {
    // --- Business methods ---

    /// Execute an authenticated HTTP request using the secret as credential.
    /// The handle remains valid for reuse after this call.
    ///
    /// Args:
    ///     url: Target HTTPS URL.
    ///     method: HTTP method (GET, POST, etc.).
    ///     headers: Optional list of (name, value) header tuples.
    ///     body: Optional request body bytes.
    ///
    /// Returns: HttpResponse with status, headers, body.
    #[pyo3(signature = (url, method, headers=None, body=None))]
    fn authenticated_request(
        &self,
        url: String,
        method: String,
        headers: Option<Vec<(String, String)>>,
        body: Option<Vec<u8>>,
    ) -> PyResult<types::HttpResponse> {
        // Clone secret (non-consuming — handle stays valid)
        let (secret, scheme_str, runtime) = self
            .clone_secret()
            .ok_or_else(|| types::HandleError::new_err("handle destroyed"))?;

        // Parse auth scheme (PYSDK-A5)
        let auth_scheme =
            hermetic_transport::auth::AuthScheme::parse(scheme_str.as_deref().unwrap_or("bearer"))
                .map_err(|e| types::TransportError::new_err(format!("invalid auth scheme: {e}")))?;

        // Build TransportRequest — clone is consumed here, original stays in Mutex
        let request = hermetic_transport::executor::TransportRequest {
            url,
            method: method.to_uppercase(),
            headers: headers.unwrap_or_default(),
            body,
            credential: Some((secret, auth_scheme)),
            extra_headers: vec![],
        };

        // Execute with SSRF protection
        let resolver = Arc::new(hermetic_transport::ssrf::SystemDnsResolver);
        let response = runtime
            .block_on(hermetic_transport::executor::execute(request, resolver))
            .map_err(|e| types::TransportError::new_err(format!("{e}")))?;

        Ok(types::HttpResponse {
            status: response.status,
            headers: response.headers,
            body: response.body,
        })
    }

    /// Compute HMAC-SHA256 signature using the secret as key.
    /// The handle remains valid for reuse after this call.
    ///
    /// Args:
    ///     data: Bytes to sign.
    ///
    /// Returns: HMAC-SHA256 signature as bytes.
    fn hmac_sign(&self, data: Vec<u8>) -> PyResult<Vec<u8>> {
        let (secret, _scheme, _runtime) = self
            .clone_secret()
            .ok_or_else(|| types::HandleError::new_err("handle destroyed"))?;

        let key = hmac::Key::new(hmac::HMAC_SHA256, &secret);
        let tag = hmac::sign(&key, &data);
        Ok(tag.as_ref().to_vec())
    }

    /// Verify an HMAC-SHA256 signature using the secret as key.
    /// The handle remains valid for reuse after this call.
    /// Uses ring's constant-time HMAC verification.
    ///
    /// Args:
    ///     data: Original data that was signed.
    ///     signature: HMAC signature to verify.
    ///
    /// Returns: True if signature is valid, False otherwise.
    fn hmac_verify(&self, data: Vec<u8>, signature: Vec<u8>) -> PyResult<bool> {
        let (secret, _scheme, _runtime) = self
            .clone_secret()
            .ok_or_else(|| types::HandleError::new_err("handle destroyed"))?;

        let key = hmac::Key::new(hmac::HMAC_SHA256, &secret);
        Ok(hmac::verify(&key, &data, &signature).is_ok())
    }

    // --- Lifecycle ---

    /// Destroy the handle, zeroizing the inner secret.
    /// Safe to call multiple times. After destroy(), all operations fail.
    fn destroy(&self) -> PyResult<()> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| PyRuntimeError::new_err("lock poisoned"))?;
        *guard = None; // Zeroizing<Vec<u8>> Drop → zeroizes
        let mut d = self
            .destroyed
            .lock()
            .map_err(|_| PyRuntimeError::new_err("lock poisoned"))?;
        *d = true;
        Ok(())
    }

    // --- Escape hatch blocking ---

    fn __str__(&self) -> String {
        "[SecretHandle: OPAQUE]".to_string()
    }

    fn __repr__(&self) -> String {
        format!("SecretHandle(opaque, id={})", self.display_id)
    }

    fn __format__(&self, _spec: &str) -> String {
        "[SecretHandle: OPAQUE]".to_string()
    }

    fn __reduce__(&self) -> PyResult<()> {
        Err(PyTypeError::new_err("SecretHandle cannot be pickled"))
    }

    fn __copy__(&self) -> PyResult<()> {
        Err(PyTypeError::new_err("SecretHandle cannot be copied"))
    }

    fn __deepcopy__(&self, _memo: &Bound<'_, PyAny>) -> PyResult<()> {
        Err(PyTypeError::new_err("SecretHandle cannot be copied"))
    }

    fn __getstate__(&self) -> PyResult<()> {
        Err(PyTypeError::new_err("SecretHandle cannot be serialized"))
    }

    fn __bool__(&self) -> bool {
        let d = self.destroyed.lock().unwrap_or_else(|e| e.into_inner());
        !*d
    }

    fn __sizeof__(&self) -> usize {
        std::mem::size_of::<Self>()
    }

    fn __dir__<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, pyo3::types::PyList>> {
        let names = vec![
            "authenticated_request",
            "hmac_sign",
            "hmac_verify",
            "destroy",
        ];
        pyo3::types::PyList::new(py, names)
    }
}

/// Test helper — creates a SecretHandle with dummy bytes.
/// Only available when the `test-helpers` feature is enabled.
/// NOT included in release wheels.
#[cfg(feature = "test-helpers")]
#[pyfunction]
pub fn _test_make_handle() -> SecretHandle {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to create test runtime");
    SecretHandle::new(
        Zeroizing::new(b"test-secret-1234".to_vec()),
        Some("bearer".to_string()),
        "abcd1234".to_string(),
        Arc::new(runtime),
    )
}

// NOTE: Rust unit tests for SecretHandle cannot run via `cargo test` because
// #[pyclass] types require Python symbols at link time. The destroy/zeroize
// and double-destroy behaviors are tested via Python in test_escape_hatches.py
// (test_bool_lifecycle, test_destroy_safe) and test_errors.py
// (test_use_after_destroy, test_hmac_after_destroy, test_verify_after_destroy).
