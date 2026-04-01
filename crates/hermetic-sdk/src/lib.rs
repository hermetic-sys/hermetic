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

// DD-4: PyO3 generates unsafe FFI glue; forbid(unsafe_code) is incompatible.
// All hand-written code in this crate remains safe.
#![deny(unsafe_code)]
#![deny(clippy::all)]

use pyo3::prelude::*;

mod client;
mod handle;
mod protocol;
mod types;
mod wire;

/// Hermetic Python SDK — zero-knowledge credential broker for AI agents.
#[pymodule]
fn hermetic(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", "1.0.0")?;
    // Exception hierarchy: HermeticError → ConnectionError, HandleError, TransportError
    types::register_exceptions(m)?;
    // Types
    m.add_class::<types::AuthScheme>()?;
    m.add_class::<types::HttpResponse>()?;
    m.add_class::<handle::SecretHandle>()?;
    m.add_class::<client::HermeticClient>()?;
    // Test helpers (only in dev builds with test-helpers feature)
    #[cfg(feature = "test-helpers")]
    m.add_function(wrap_pyfunction!(handle::_test_make_handle, m)?)?;
    Ok(())
}
