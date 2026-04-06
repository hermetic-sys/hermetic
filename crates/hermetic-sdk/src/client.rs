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

//! HermeticClient — Python-visible client for daemon communication.
//!
//! Connects to daemon via UDS, implements get_secret + list_secrets.
//! get_secret returns an opaque SecretHandle.

use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use pyo3::prelude::*;
use zeroize::Zeroizing;

use crate::handle::SecretHandle;
use crate::protocol::{DaemonRequest, DaemonResponse, ResponseData};
use crate::types;
use crate::wire;

/// Python-visible client for Hermetic daemon communication.
///
/// Holds a persistent UDS connection (Mutex-protected) and a tokio Runtime
/// for bridging async transport operations.
#[pyclass]
pub struct HermeticClient {
    stream: Mutex<UnixStream>,
    socket_path: String,
    runtime: Arc<tokio::runtime::Runtime>,
}

impl HermeticClient {
    /// Send a DaemonRequest and read a DaemonResponse.
    fn send_request(&self, request: &DaemonRequest) -> Result<DaemonResponse, String> {
        let payload =
            serde_json::to_vec(request).map_err(|e| format!("failed to serialize request: {e}"))?;

        let mut stream = self
            .stream
            .lock()
            .map_err(|_| "stream lock poisoned".to_string())?;

        // First attempt
        match Self::send_and_read(&mut stream, &payload) {
            Ok(resp) => return Ok(resp),
            Err(e) if Self::is_dead_connection(&e) => {}
            Err(e) => return Err(e),
        }

        // Reconnect and retry once
        let new_stream =
            UnixStream::connect(&self.socket_path).map_err(|e| format!("reconnect failed: {e}"))?;
        new_stream
            .set_read_timeout(Some(wire::UDS_TIMEOUT))
            .map_err(|e| format!("set read timeout: {e}"))?;
        new_stream
            .set_write_timeout(Some(wire::UDS_TIMEOUT))
            .map_err(|e| format!("set write timeout: {e}"))?;
        *stream = new_stream;

        Self::send_and_read(&mut stream, &payload)
    }

    fn send_and_read(stream: &mut UnixStream, payload: &[u8]) -> Result<DaemonResponse, String> {
        wire::write_frame(stream, payload).map_err(|e| format!("write failed: {e}"))?;
        let response_bytes = wire::read_frame(stream).map_err(|e| format!("read failed: {e}"))?;
        serde_json::from_slice(&response_bytes).map_err(|e| format!("invalid response: {e}"))
    }

    fn is_dead_connection(err: &str) -> bool {
        err.contains("Broken pipe")
            || err.contains("Connection reset")
            || err.contains("UnexpectedEof")
            || err.contains("unexpected eof")
            || err.contains("broken pipe")
            || err.contains("connection reset")
            || err.contains("NotConnected")
            || err.contains("not connected")
    }

    fn check_response(resp: &DaemonResponse) -> Result<(), String> {
        if resp.success {
            Ok(())
        } else {
            Err(resp
                .error
                .clone()
                .unwrap_or_else(|| "daemon rejected request".to_string()))
        }
    }

    /// Extract domain from URL for handle binding (PYSDK-A2).
    fn extract_domain(url_str: &str) -> Option<String> {
        url::Url::parse(url_str).ok().and_then(|parsed| {
            parsed
                .host_str()
                .map(|h| h.to_ascii_lowercase().trim_end_matches('.').to_string())
        })
    }
}

#[pymethods]
impl HermeticClient {
    /// Connect to the Hermetic daemon.
    ///
    /// Args:
    ///     socket_path: Path to the daemon's Unix domain socket.
    ///                  If None, uses XDG_RUNTIME_DIR/hermetic/default/daemon.sock.
    #[new]
    #[pyo3(signature = (socket_path=None))]
    fn new(socket_path: Option<String>) -> PyResult<Self> {
        let config = crate::types::HermeticConfig::new(socket_path, None);

        let stream = UnixStream::connect(&config.socket_path).map_err(|e| {
            types::ConnectionError::new_err(format!(
                "failed to connect to daemon at {}: {e}",
                config.socket_path
            ))
        })?;
        stream
            .set_read_timeout(Some(wire::UDS_TIMEOUT))
            .map_err(|e| types::ConnectionError::new_err(format!("set read timeout: {e}")))?;
        stream
            .set_write_timeout(Some(wire::UDS_TIMEOUT))
            .map_err(|e| types::ConnectionError::new_err(format!("set write timeout: {e}")))?;

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| {
                types::ConnectionError::new_err(format!("failed to create runtime: {e}"))
            })?;

        Ok(Self {
            stream: Mutex::new(stream),
            socket_path: config.socket_path,
            runtime: Arc::new(runtime),
        })
    }

    /// Get an opaque SecretHandle for use with authenticated_request/hmac_sign.
    ///
    /// 5-step flow:
    /// A: request_handle → handle_id
    /// B: redeem_handle → base64 secret + auth_scheme
    /// C: Construct SecretHandle
    ///
    /// Args:
    ///     secret_name: Name of the stored secret.
    ///     url: Target URL (for domain binding).
    ///     method: HTTP method.
    ///     auth_scheme: Auth scheme string (default: "bearer").
    ///     required_tags: Comma-separated required tags.
    #[pyo3(signature = (secret_name, url=None, method=None, auth_scheme=None, required_tags=None))]
    fn get_secret(
        &self,
        secret_name: String,
        url: Option<String>,
        method: Option<String>,
        auth_scheme: Option<String>,
        required_tags: Option<String>,
    ) -> PyResult<SecretHandle> {
        // Step A: request_handle
        let domain = url.as_deref().and_then(Self::extract_domain);

        let req = DaemonRequest {
            action: "request_handle".to_string(),
            secret_name: Some(secret_name),
            operation: Some("authenticated_request".to_string()),
            domain,
            url,
            method,
            required_tags,
            auth_scheme: auth_scheme.clone(),
            ..Default::default()
        };

        let resp = self
            .send_request(&req)
            .map_err(types::ConnectionError::new_err)?;
        Self::check_response(&resp).map_err(types::HandleError::new_err)?;

        let handle_id = match resp.data {
            Some(ResponseData::Handle { handle_id }) => handle_id,
            _ => {
                return Err(types::HandleError::new_err(
                    "unexpected response for request_handle",
                ))
            }
        };

        // Step B: redeem_handle
        let redeem_req = DaemonRequest {
            action: "redeem_handle".to_string(),
            handle_id: Some(handle_id.clone()),
            ..Default::default()
        };

        let redeem_resp = self
            .send_request(&redeem_req)
            .map_err(types::ConnectionError::new_err)?;
        Self::check_response(&redeem_resp).map_err(types::HandleError::new_err)?;

        let (secret_b64, redeemed_scheme) = match redeem_resp.data {
            Some(ResponseData::Secret { value, auth_scheme }) => (value, auth_scheme),
            _ => {
                return Err(types::HandleError::new_err(
                    "unexpected response for redeem_handle",
                ))
            }
        };

        let secret_bytes = STANDARD
            .decode(&secret_b64)
            .map_err(|_| types::HandleError::new_err("invalid base64 in secret response"))?;

        // Step C: Construct SecretHandle
        // PYSDK-A5: auth_scheme priority — redeemed > requested > default
        let final_scheme = redeemed_scheme.or(auth_scheme);
        let display_id = if handle_id.len() >= 8 {
            handle_id[..8].to_string()
        } else {
            handle_id.clone()
        };

        Ok(SecretHandle::new(
            Zeroizing::new(secret_bytes),
            final_scheme,
            display_id,
            Arc::clone(&self.runtime),
        ))
    }

    /// List stored secret names.
    ///
    /// Returns a list of (name, sensitivity) tuples.
    /// MCP-1: No secret values returned.
    #[pyo3(signature = (tag_filter=None))]
    fn list_secrets(&self, tag_filter: Option<String>) -> PyResult<Vec<(String, String)>> {
        let req = DaemonRequest {
            action: "list".to_string(),
            tags: tag_filter,
            ..Default::default()
        };

        let resp = self
            .send_request(&req)
            .map_err(types::ConnectionError::new_err)?;
        Self::check_response(&resp).map_err(types::HandleError::new_err)?;

        match resp.data {
            Some(ResponseData::List(names)) => Ok(names
                .into_iter()
                .map(|n| (n, "standard".to_string()))
                .collect()),
            Some(ResponseData::ListMeta(entries)) => Ok(entries
                .into_iter()
                .map(|e| (e.name, "standard".to_string()))
                .collect()),
            _ => Err(types::HandleError::new_err(
                "unexpected response data for list",
            )),
        }
    }

    fn __repr__(&self) -> String {
        format!("HermeticClient(socket='{}')", self.socket_path)
    }
}
