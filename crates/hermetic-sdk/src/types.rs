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

//! Python-visible type wrappers for the Hermetic SDK.
//!
//! Exception hierarchy:
//!   HermeticError (base) → ConnectionError, HandleError, TransportError
//!
//! All are proper Python exceptions (create_exception!), not pyclasses.

use pyo3::create_exception;
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;

// ---------------------------------------------------------------------------
// Exception hierarchy
// ---------------------------------------------------------------------------

create_exception!(hermetic, HermeticError, PyRuntimeError);
create_exception!(hermetic, ConnectionError, HermeticError);
create_exception!(hermetic, HandleError, HermeticError);
create_exception!(hermetic, TransportError, HermeticError);

/// Register all exception types in the Python module.
pub fn register_exceptions(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("HermeticError", m.py().get_type::<HermeticError>())?;
    m.add("ConnectionError", m.py().get_type::<ConnectionError>())?;
    m.add("HandleError", m.py().get_type::<HandleError>())?;
    m.add("TransportError", m.py().get_type::<TransportError>())?;
    Ok(())
}

// ---------------------------------------------------------------------------
// AuthScheme
// ---------------------------------------------------------------------------

/// Python-visible auth scheme wrapper.
/// Validates against transport's AuthScheme::parse on construction.
#[pyclass]
#[derive(Clone)]
pub struct AuthScheme {
    #[pyo3(get)]
    pub scheme: String,
}

#[pymethods]
impl AuthScheme {
    #[new]
    fn new(scheme: String) -> PyResult<Self> {
        hermetic_transport::auth::AuthScheme::parse(&scheme)
            .map_err(|_| PyRuntimeError::new_err(format!("invalid auth scheme: {scheme}")))?;
        Ok(Self { scheme })
    }

    #[staticmethod]
    fn bearer() -> Self {
        Self {
            scheme: "bearer".to_string(),
        }
    }

    #[staticmethod]
    fn x_api_key() -> Self {
        Self {
            scheme: "x-api-key".to_string(),
        }
    }

    #[staticmethod]
    fn basic() -> Self {
        Self {
            scheme: "basic".to_string(),
        }
    }

    #[staticmethod]
    fn header(name: String) -> PyResult<Self> {
        Self::new(format!("header:{name}"))
    }

    fn __str__(&self) -> String {
        self.scheme.clone()
    }

    fn __repr__(&self) -> String {
        format!("AuthScheme('{}')", self.scheme)
    }
}

// ---------------------------------------------------------------------------
// HttpResponse
// ---------------------------------------------------------------------------

/// Python-visible HTTP response returned by authenticated_request.
#[pyclass]
pub struct HttpResponse {
    #[pyo3(get)]
    pub status: u16,
    #[pyo3(get)]
    pub headers: Vec<(String, String)>,
    #[pyo3(get)]
    pub body: Vec<u8>,
}

#[pymethods]
impl HttpResponse {
    fn __repr__(&self) -> String {
        format!("HttpResponse(status={})", self.status)
    }
}

// ---------------------------------------------------------------------------
// HermeticConfig (pub(crate) — internal plumbing, not Python-exported)
// ---------------------------------------------------------------------------

// Consumed by client.rs (Chunk G).
#[allow(dead_code)]
#[derive(Clone)]
pub(crate) struct HermeticConfig {
    pub socket_path: String,
    pub env_name: String,
}

#[allow(dead_code)]
impl HermeticConfig {
    pub fn new(socket_path: Option<String>, env_name: Option<String>) -> Self {
        let env = env_name.unwrap_or_else(|| "default".to_string());
        let path = socket_path.unwrap_or_else(|| {
            let runtime_dir =
                std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".to_string());
            format!("{}/hermetic/{}/daemon.sock", runtime_dir, env)
        });
        Self {
            socket_path: path,
            env_name: env,
        }
    }
}
