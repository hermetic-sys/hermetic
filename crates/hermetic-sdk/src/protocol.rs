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

//! SDK-local daemon protocol types — wire-compatible with daemon's protocol.rs.
//!
//! DD-6: These are local mirrors, NOT imported from hermetic-daemon.
//! The daemon uses `#[serde(deny_unknown_fields)]` on SocketRequest,
//! so DaemonRequest MUST use `skip_serializing_if` on all Option fields
//! to avoid sending unexpected fields.

// protocol module is consumed by client.rs (Chunk G); allow dead_code until then.
#![allow(dead_code)]

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Request
// ---------------------------------------------------------------------------

/// Request sent to daemon over UDS.
/// Wire-compatible with daemon's SocketRequest (14 fields, deny_unknown_fields).
#[derive(Debug, Default, Serialize)]
pub struct DaemonRequest {
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sensitivity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_domains: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_tags: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_scheme: Option<String>,
}

// ---------------------------------------------------------------------------
// Response
// ---------------------------------------------------------------------------

/// Response from daemon over UDS.
#[derive(Debug, Deserialize)]
pub struct DaemonResponse {
    pub success: bool,
    pub error: Option<String>,
    #[serde(default)]
    pub data: Option<ResponseData>,
}

/// Response data variants — tagged enum matching daemon's ResponseData.
/// `{"kind":"Handle","value":{"handle_id":"..."}}`
#[derive(Debug, Deserialize)]
#[serde(tag = "kind", content = "value")]
#[allow(dead_code)] // List/ListMeta consumed in client.rs (Chunk G)
pub enum ResponseData {
    List(Vec<String>),
    ListMeta(Vec<ListEntry>),
    #[allow(dead_code)]
    Status(StatusInfo),
    Handle {
        handle_id: String,
    },
    Secret {
        value: String,
        #[serde(default)]
        auth_scheme: Option<String>,
    },
}

/// Enriched list entry with tag metadata.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct ListEntry {
    pub name: String,
    #[allow(dead_code)]
    pub tags: String,
}

/// Status info from daemon.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct StatusInfo {
    pub mode: String,
    pub sealed: bool,
    pub secret_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_request_handle() {
        let req = DaemonRequest {
            action: "request_handle".to_string(),
            secret_name: Some("api-key".to_string()),
            operation: Some("authenticated_request".to_string()),
            domain: Some("api.example.com".to_string()),
            url: Some("https://api.example.com/v1".to_string()),
            method: Some("GET".to_string()),
            auth_scheme: Some("bearer".to_string()),
            ..Default::default()
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["action"], "request_handle");
        assert_eq!(json["secret_name"], "api-key");
        assert_eq!(json["operation"], "authenticated_request");
        assert_eq!(json["domain"], "api.example.com");
        assert_eq!(json["auth_scheme"], "bearer");
        assert_eq!(json.as_object().unwrap().len(), 7);
    }

    #[test]
    fn test_serialize_redeem_handle() {
        let req = DaemonRequest {
            action: "redeem_handle".to_string(),
            handle_id: Some("abcd1234".to_string()),
            ..Default::default()
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["action"], "redeem_handle");
        assert_eq!(json["handle_id"], "abcd1234");
        assert_eq!(json.as_object().unwrap().len(), 2);
    }

    #[test]
    fn test_skip_none_fields() {
        let req = DaemonRequest {
            action: "list".to_string(),
            ..Default::default()
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json.as_object().unwrap().len(), 1);
        assert!(json.get("name").is_none());
        assert!(json.get("value").is_none());
        assert!(json.get("handle_id").is_none());
    }

    #[test]
    fn test_deserialize_handle_response() {
        let json = r#"{"success":true,"error":null,"data":{"kind":"Handle","value":{"handle_id":"abcd1234"}}}"#;
        let resp: DaemonResponse = serde_json::from_str(json).unwrap();
        assert!(resp.success);
        match resp.data {
            Some(ResponseData::Handle { handle_id }) => {
                assert_eq!(handle_id, "abcd1234");
            }
            other => panic!("expected Handle, got {other:?}"),
        }
    }

    #[test]
    fn test_deserialize_secret_response() {
        let json = r#"{"success":true,"error":null,"data":{"kind":"Secret","value":{"value":"dGVzdA==","auth_scheme":"bearer"}}}"#;
        let resp: DaemonResponse = serde_json::from_str(json).unwrap();
        assert!(resp.success);
        match resp.data {
            Some(ResponseData::Secret { value, auth_scheme }) => {
                assert_eq!(value, "dGVzdA==");
                assert_eq!(auth_scheme.as_deref(), Some("bearer"));
            }
            other => panic!("expected Secret, got {other:?}"),
        }
    }

    #[test]
    fn test_deserialize_error_response() {
        let json = r#"{"success":false,"error":"RequestDenied"}"#;
        let resp: DaemonResponse = serde_json::from_str(json).unwrap();
        assert!(!resp.success);
        assert_eq!(resp.error.as_deref(), Some("RequestDenied"));
        assert!(resp.data.is_none());
    }
}
