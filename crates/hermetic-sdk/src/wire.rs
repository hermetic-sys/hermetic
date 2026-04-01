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

//! Wire protocol framing for daemon UDS communication.
//!
//! Wire format: `[4-byte big-endian u32 length prefix][JSON payload bytes]`
//! Length prefix encodes payload size only (not including the 4 prefix bytes).
//!
//! Key differences from MCP wire.rs:
//! - MAX_FRAME_SIZE = 65,536 (daemon's limit, not MCP's 1 MiB)
//! - UDS_TIMEOUT = 30 seconds (SDK client needs more patience than MCP's 5s)
//!
//! Daemon authority: crates/hermetic-daemon/src/wire.rs
//! - 4-byte BE u32 length prefix
//! - MAX_PAYLOAD_SIZE: 65,536 bytes

// wire module is consumed by client.rs (Chunk G); allow dead_code until then.
#![allow(dead_code)]

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

/// Maximum frame size — matches daemon's MAX_PAYLOAD_SIZE (65,536 bytes).
pub const MAX_FRAME_SIZE: usize = 65_536;

/// UDS socket timeout for SDK client operations.
pub const UDS_TIMEOUT: Duration = Duration::from_secs(30);

/// Write a length-prefixed frame: [4-byte BE u32 length][payload].
pub fn write_frame(stream: &mut UnixStream, payload: &[u8]) -> io::Result<()> {
    if payload.len() > MAX_FRAME_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "payload size {} exceeds maximum {MAX_FRAME_SIZE}",
                payload.len()
            ),
        ));
    }
    let len = payload.len() as u32;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(payload)?;
    stream.flush()
}

/// Read a length-prefixed frame: [4-byte BE u32 length][payload].
pub fn read_frame(stream: &mut UnixStream) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;

    if len > MAX_FRAME_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame size {len} exceeds maximum {MAX_FRAME_SIZE}"),
        ));
    }

    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload)?;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn test_write_read_roundtrip() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        let payload = br#"{"action":"seal"}"#;

        write_frame(&mut a, payload).unwrap();
        let decoded = read_frame(&mut b).unwrap();
        assert_eq!(decoded, payload);
    }

    #[cfg(unix)]
    #[test]
    fn test_oversized_frame_rejected() {
        let (mut a, _b) = UnixStream::pair().unwrap();
        let payload = vec![0u8; MAX_FRAME_SIZE + 1];

        let result = write_frame(&mut a, &payload);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[cfg(unix)]
    #[test]
    fn test_zero_length_frame() {
        let (mut a, mut b) = UnixStream::pair().unwrap();

        write_frame(&mut a, b"").unwrap();
        let decoded = read_frame(&mut b).unwrap();
        assert!(decoded.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn test_malformed_length() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        b.set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();

        // Write only 3 bytes of the 4-byte length prefix
        a.write_all(&[0u8; 3]).unwrap();
        a.flush().unwrap();
        drop(a); // EOF after 3 bytes

        let result = read_frame(&mut b);
        assert!(result.is_err());
    }
}
