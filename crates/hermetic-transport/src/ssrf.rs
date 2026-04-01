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

//! SSRF protection — IP range validation and DNS resolution abstraction.
//!
//! HC-2 BINDING: DNS resolution → validate ALL resolved IPs → connect-by-IP.
//! If ANY resolved IP is private or reserved, the entire resolution set is
//! rejected. This closes the TOCTOU/round-robin attack vector where a DNS
//! server could return a public IP on the first query and a private IP on
//! subsequent queries.
//!
//! IPv4-mapped IPv6 addresses (::ffff:x.x.x.x) are unwrapped to IPv4 and
//! re-validated against all IPv4 private ranges.
//! HC-2: IPv4-mapped unwrap is mandatory — ensures all embedded IPv4
//! addresses are subject to the same private-range checks.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};

use crate::error::TransportError;

// -----------------------------------------------------------------------
// IPv4 private/reserved range checks
// -----------------------------------------------------------------------

/// Return true if the IPv4 address is private, loopback, or otherwise
/// non-routable. Comprehensive coverage required for HC-2 compliance.
fn is_private_ipv4(ip: &Ipv4Addr) -> bool {
    let o = ip.octets();

    // 10.0.0.0/8 — RFC 1918 private
    if o[0] == 10 {
        return true;
    }
    // 172.16.0.0/12 — RFC 1918 private (172.16.x.x through 172.31.x.x)
    if o[0] == 172 && o[1] >= 16 && o[1] <= 31 {
        return true;
    }
    // 192.168.0.0/16 — RFC 1918 private
    if o[0] == 192 && o[1] == 168 {
        return true;
    }
    // 127.0.0.0/8 — RFC 1122 loopback
    if o[0] == 127 {
        return true;
    }
    // 169.254.0.0/16 — RFC 3927 link-local (APIPA)
    if o[0] == 169 && o[1] == 254 {
        return true;
    }
    // 0.0.0.0/8 — RFC 1122 "this network, this host"
    if o[0] == 0 {
        return true;
    }
    // 100.64.0.0/10 — RFC 6598 shared address space (100.64.x.x through 100.127.x.x)
    // /10: top 10 bits fixed → second octet range [64, 127]
    if o[0] == 100 && o[1] >= 64 && o[1] <= 127 {
        return true;
    }
    // 192.0.0.0/24 — RFC 6890 IETF protocol assignments
    if o[0] == 192 && o[1] == 0 && o[2] == 0 {
        return true;
    }
    // 192.0.2.0/24 — RFC 5737 TEST-NET-1 (documentation only)
    if o[0] == 192 && o[1] == 0 && o[2] == 2 {
        return true;
    }
    // 198.51.100.0/24 — RFC 5737 TEST-NET-2 (documentation only)
    if o[0] == 198 && o[1] == 51 && o[2] == 100 {
        return true;
    }
    // 203.0.113.0/24 — RFC 5737 TEST-NET-3 (documentation only)
    if o[0] == 203 && o[1] == 0 && o[2] == 113 {
        return true;
    }
    // 198.18.0.0/15 — RFC 2544 benchmarking (198.18.x.x through 198.19.x.x)
    // /15: second octet is 18 (00010010) or 19 (00010011)
    if o[0] == 198 && (o[1] == 18 || o[1] == 19) {
        return true;
    }
    // 224.0.0.0/4 — RFC 1112 multicast (224.x.x.x through 239.x.x.x)
    // Multicast addresses are not valid HTTP server destinations.
    if o[0] >= 224 && o[0] <= 239 {
        return true;
    }
    // 240.0.0.0/4 — RFC 1112 future use / reserved (240.x.x.x through 255.x.x.x)
    // Includes 255.255.255.255 (broadcast). /4: first nibble = 0b1111.
    if o[0] >= 240 {
        return true;
    }

    false
}

// -----------------------------------------------------------------------
// IPv6 private/reserved range checks
// -----------------------------------------------------------------------

/// Return true if the IPv6 address is private, loopback, or otherwise
/// non-routable. IPv4-mapped addresses are unwrapped and re-validated.
fn is_private_ipv6(ip: &Ipv6Addr) -> bool {
    // ::1 — RFC 4291 loopback
    if ip == &Ipv6Addr::LOCALHOST {
        return true;
    }
    // :: — RFC 4291 unspecified address
    if ip == &Ipv6Addr::UNSPECIFIED {
        return true;
    }

    let bytes = ip.octets();

    // fc00::/7 — RFC 4193 unique local (fc00:: through fdff::)
    // Top 7 bits of first byte: 1111110x → mask with 0xFE → 0xFC
    if bytes[0] & 0xFE == 0xFC {
        return true;
    }
    // fe80::/10 — RFC 4291 link-local (fe80:: through febf::)
    // First byte: 0xFE; second byte top 2 bits: 10xxxxxx → mask with 0xC0 → 0x80
    if bytes[0] == 0xFE && bytes[1] & 0xC0 == 0x80 {
        return true;
    }

    // ff00::/8 — RFC 4291 multicast (all IPv6 multicast addresses)
    if bytes[0] == 0xFF {
        return true;
    }

    // ::ffff:x.x.x.x — RFC 4291 IPv4-mapped addresses
    // CRITICAL: unwrap to IPv4 and re-validate against all IPv4 private ranges.
    // HC-2: Unwrap to IPv4 and apply private-range validation uniformly.
    // to_ipv4() also handles deprecated IPv4-compatible (::x.x.x.x) addresses.
    if let Some(ipv4) = ip.to_ipv4() {
        return is_private_ipv4(&ipv4);
    }

    // 2002::/16 — RFC 3056 6to4 tunnel addresses.
    // IPv4 address is embedded in bytes 2–5 (e.g. 2002:7f00:0001:: wraps 127.0.0.1).
    // HC-2: to_ipv4() does not extract 6to4 embeddings — explicit check required.
    if bytes[0] == 0x20 && bytes[1] == 0x02 {
        let embedded = Ipv4Addr::new(bytes[2], bytes[3], bytes[4], bytes[5]);
        return is_private_ipv4(&embedded);
    }

    // 64:ff9b::/96 — RFC 6052 NAT64 well-known prefix.
    // IPv4 address is embedded in the last 4 bytes (bytes 12–15).
    // HC-2: to_ipv4() does not extract NAT64 embeddings — explicit check required.
    if bytes[0..12]
        == [
            0x00, 0x64, 0xff, 0x9b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]
    {
        let embedded = Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]);
        return is_private_ipv4(&embedded);
    }

    false
}

// -----------------------------------------------------------------------
// Public API
// -----------------------------------------------------------------------

/// Return true if the IP address is private, loopback, link-local, or
/// otherwise reserved. Safe to contact if and only if this returns false.
pub fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_ipv4(v4),
        IpAddr::V6(v6) => is_private_ipv6(v6),
    }
}

/// HC-2 Step 3: Validate all resolved IPs against private/reserved ranges.
///
/// BINDING: If ANY resolved IP is private → reject ALL. Return the first
/// public IP on success.
///
/// Rationale: DNS may return multiple A/AAAA records. A single private IP
/// in the set could be used in a TOCTOU or round-robin attack where the
/// attacker's DNS alternates between public and private responses.
pub fn validate_resolved_ips(ips: &[IpAddr]) -> Result<IpAddr, TransportError> {
    if ips.is_empty() {
        return Err(TransportError::DnsResolutionFailed(
            "no addresses resolved".to_string(),
        ));
    }
    for ip in ips {
        if is_private_ip(ip) {
            return Err(TransportError::SsrfBlocked(ip.to_string()));
        }
    }
    Ok(ips[0])
}

// -----------------------------------------------------------------------
// DNS resolver abstraction
// -----------------------------------------------------------------------

/// DNS resolution abstraction for testability.
///
/// HC-2: Production code uses [`SystemDnsResolver`]. Tests use a
/// `MockDnsResolver` that returns configurable IP sequences, enabling
/// T-TR-15 (DNS rebinding: first call public, second call private).
///
/// `Send + Sync` is required for `Arc<dyn DnsResolver>` sharing across
/// async task boundaries.
pub trait DnsResolver: Send + Sync {
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<IpAddr>, TransportError>;
}

/// Production DNS resolver using [`std::net::ToSocketAddrs`] (synchronous,
/// blocking). Stateless — no DNS cache, no connection pooling.
///
/// When called from an async context in `executor.rs`, the caller MUST
/// wrap this in `tokio::task::spawn_blocking()` to avoid blocking the
/// async executor thread.
pub struct SystemDnsResolver;

impl DnsResolver for SystemDnsResolver {
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<IpAddr>, TransportError> {
        let host_port = format!("{host}:{port}");
        let addrs = host_port
            .to_socket_addrs()
            .map_err(|e| TransportError::DnsResolutionFailed(e.to_string()))?;
        let ips: Vec<IpAddr> = addrs.map(|a| a.ip()).collect();
        if ips.is_empty() {
            return Err(TransportError::DnsResolutionFailed(
                "no addresses returned by resolver".to_string(),
            ));
        }
        Ok(ips)
    }
}

// -----------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::{is_private_ip, validate_resolved_ips};
    use crate::error::TransportError;

    // --- IPv4 private range coverage ---

    #[test]
    fn ipv4_rfc1918_10() {
        // inside
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(10, 255, 255, 255))));
        // boundary below
        assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(9, 255, 255, 255))));
        // boundary above
        assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(11, 0, 0, 0))));
    }

    #[test]
    fn ipv4_rfc1918_172() {
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(172, 31, 255, 255))));
        // boundary: 172.15.x.x is public
        assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(172, 15, 0, 1))));
        // boundary: 172.32.x.x is public
        assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(172, 32, 0, 1))));
    }

    #[test]
    fn ipv4_rfc1918_192_168() {
        // inside
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1))));
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(
            192, 168, 255, 255
        ))));
        // boundary below (192.167.x.x — different second octet)
        assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(
            192, 167, 255, 255
        ))));
        // boundary above (192.169.x.x)
        assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(192, 169, 0, 0))));
        // && → || kill: first octet matches, second doesn't (191.168.x.x)
        assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(191, 168, 0, 1))));
    }

    #[test]
    fn ipv4_loopback() {
        // inside
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(
            127, 255, 255, 255
        ))));
        // boundary below
        assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(
            126, 255, 255, 255
        ))));
        // boundary above
        assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0))));
    }

    #[test]
    fn ipv4_link_local() {
        // inside
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(169, 254, 0, 1))));
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(
            169, 254, 255, 255
        ))));
        // boundary below (169.253.x.x)
        assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(
            169, 253, 255, 255
        ))));
        // boundary above (169.255.x.x)
        assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(169, 255, 0, 0))));
        // && → || kill: first octet matches, second doesn't (168.254.x.x)
        assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(168, 254, 0, 1))));
    }

    #[test]
    fn ipv4_current_network() {
        // inside
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))));
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(0, 255, 255, 255))));
        // boundary above
        assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(1, 0, 0, 0))));
    }

    #[test]
    fn ipv4_shared_address_space() {
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))));
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(
            100, 127, 255, 255
        ))));
        // boundary: 100.63.x.x is public
        assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(100, 63, 0, 1))));
        // boundary: 100.128.x.x is public
        assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(100, 128, 0, 1))));
    }

    #[test]
    fn ipv4_documentation_ranges() {
        // TEST-NET-1 (192.0.2.0/24)
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));
        assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(192, 0, 3, 0))));
        // TEST-NET-2 (198.51.100.0/24)
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))));
        assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(198, 51, 101, 0))));
        // TEST-NET-3 (203.0.113.0/24)
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))));
        assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(203, 0, 114, 0))));
    }

    #[test]
    fn ipv4_benchmarking() {
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1))));
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(198, 19, 255, 255))));
        // boundary: 198.17.x.x is public
        assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(198, 17, 0, 1))));
        // boundary: 198.20.x.x is public
        assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(198, 20, 0, 1))));
    }

    #[test]
    fn ipv4_future_use_and_broadcast() {
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(240, 0, 0, 1))));
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(
            255, 255, 255, 255
        ))));
    }

    #[test]
    fn ipv4_public_not_blocked() {
        // Well-known public IPs must not be blocked
        assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))));
    }

    // --- IPv6 private range coverage ---

    #[test]
    fn ipv6_loopback() {
        assert!(is_private_ip(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn ipv6_unspecified() {
        assert!(is_private_ip(&IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
    }

    #[test]
    fn ipv6_unique_local() {
        // fc00::/7 — covers fc00:: through fdff::
        let fc: IpAddr = "fc00::1".parse().unwrap();
        let fd: IpAddr = "fd12:3456:789a:1::1".parse().unwrap();
        assert!(is_private_ip(&fc));
        assert!(is_private_ip(&fd));
        // boundary below (fb00:: — outside /7)
        let fb: IpAddr = "fb00::1".parse().unwrap();
        assert!(!is_private_ip(&fb));
        // boundary above (fe00:: — outside /7, not caught by link-local)
        let fe00: IpAddr = "fe00::1".parse().unwrap();
        assert!(!is_private_ip(&fe00));
    }

    #[test]
    fn ipv6_link_local() {
        // inside fe80::/10
        let fe80: IpAddr = "fe80::1".parse().unwrap();
        assert!(is_private_ip(&fe80));
        let febf: IpAddr = "febf::1".parse().unwrap();
        assert!(is_private_ip(&febf));
        // boundary below (fe40:: — outside /10, && → || kill)
        let fe40: IpAddr = "fe40::1".parse().unwrap();
        assert!(!is_private_ip(&fe40));
        // boundary above (fec0:: — outside /10)
        let fec0: IpAddr = "fec0::1".parse().unwrap();
        assert!(!is_private_ip(&fec0));
    }

    #[test]
    fn ipv6_mapped_ipv4_loopback_blocked() {
        // ::ffff:127.0.0.1 — CRITICAL: must be blocked despite being IPv6 form
        let mapped: Ipv6Addr = "::ffff:127.0.0.1".parse().unwrap();
        assert!(
            is_private_ip(&IpAddr::V6(mapped)),
            "::ffff:127.0.0.1 must be blocked (IPv4-mapped loopback bypass)"
        );
    }

    #[test]
    fn ipv6_mapped_ipv4_private_blocked() {
        // ::ffff:10.0.0.1 and ::ffff:192.168.1.1 must be blocked
        let mapped_10: Ipv6Addr = "::ffff:10.0.0.1".parse().unwrap();
        let mapped_192: Ipv6Addr = "::ffff:192.168.1.1".parse().unwrap();
        assert!(is_private_ip(&IpAddr::V6(mapped_10)));
        assert!(is_private_ip(&IpAddr::V6(mapped_192)));
    }

    #[test]
    fn ipv6_mapped_ipv4_public_allowed() {
        // ::ffff:8.8.8.8 — public IPv4 in mapped form MUST be allowed
        let mapped_public: Ipv6Addr = "::ffff:8.8.8.8".parse().unwrap();
        assert!(
            !is_private_ip(&IpAddr::V6(mapped_public)),
            "::ffff:8.8.8.8 must be treated as public"
        );
    }

    #[test]
    fn ipv6_public_not_blocked() {
        // 2001:4860:4860::8888 (Google DNS)
        let public: IpAddr = "2001:4860:4860::8888".parse().unwrap();
        assert!(!is_private_ip(&public));
    }

    #[test]
    fn ipv4_multicast_blocked() {
        // 224.0.0.0/4 — multicast range must be blocked
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1))));
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(
            239, 255, 255, 255
        ))));
        // boundary: 223.x.x.x is public
        assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(
            223, 255, 255, 255
        ))));
    }

    #[test]
    fn ipv6_6to4_embeds_private_ipv4_blocked() {
        // 2002::/16 — 6to4: 2002:7f00:0001:: wraps 127.0.0.1 (loopback bypass)
        let loopback_6to4: IpAddr = "2002:7f00:0001::".parse().unwrap();
        assert!(
            is_private_ip(&loopback_6to4),
            "2002:7f00:1:: (6to4 wrapping 127.0.0.1) must be blocked"
        );
        // 2002:c0a8:0101:: wraps 192.168.1.1 (RFC 1918 bypass)
        let rfc1918_6to4: IpAddr = "2002:c0a8:0101::".parse().unwrap();
        assert!(
            is_private_ip(&rfc1918_6to4),
            "2002:c0a8:101:: (6to4 wrapping 192.168.1.1) must be blocked"
        );
        // 6to4 with public embedded IPv4 → allowed
        let public_6to4: IpAddr = "2002:0808:0808::".parse().unwrap();
        assert!(
            !is_private_ip(&public_6to4),
            "2002:0808:0808:: (6to4 wrapping 8.8.8.8) must be allowed"
        );
        // && → || kill: bytes[0]==0x20 matches but bytes[1]!=0x02.
        // Use address where embedded IPv4 (bytes[2..5]) is private, so the
        // || mutation would incorrectly enter the block AND return true.
        // 2001:7f00:0001:: → bytes[0]=0x20, bytes[1]=0x01, embedded=127.0.0.1
        let not_6to4_private_embed: IpAddr = "2001:7f00:0001::".parse().unwrap();
        assert!(
            !is_private_ip(&not_6to4_private_embed),
            "2001:7f00:1:: is NOT 6to4; must not be blocked despite embedded 127.0.0.1"
        );
    }

    #[test]
    fn ipv6_multicast_blocked() {
        let ff02: IpAddr = "ff02::1".parse().unwrap();
        assert!(
            is_private_ip(&ff02),
            "ff02::1 (IPv6 multicast) must be blocked"
        );
        let ff0e: IpAddr = "ff0e::1".parse().unwrap();
        assert!(
            is_private_ip(&ff0e),
            "ff0e::1 (global multicast) must be blocked"
        );
    }

    #[test]
    fn ipv4_ietf_protocol_assignments_blocked() {
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(192, 0, 0, 1))));
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(192, 0, 0, 255))));
        // boundary: 192.0.1.x is public
        assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(192, 0, 1, 1))));
    }

    #[test]
    fn ipv6_nat64_embeds_private_ipv4_blocked() {
        // 64:ff9b::/96 — NAT64: last 4 bytes are IPv4
        // 64:ff9b::7f00:1 wraps 127.0.0.1 (loopback bypass)
        let loopback_nat64: IpAddr = "64:ff9b::7f00:1".parse().unwrap();
        assert!(
            is_private_ip(&loopback_nat64),
            "64:ff9b::7f00:1 (NAT64 wrapping 127.0.0.1) must be blocked"
        );
        // 64:ff9b::c0a8:101 wraps 192.168.1.1
        let rfc1918_nat64: IpAddr = "64:ff9b::c0a8:101".parse().unwrap();
        assert!(
            is_private_ip(&rfc1918_nat64),
            "64:ff9b::c0a8:101 (NAT64 wrapping 192.168.1.1) must be blocked"
        );
    }

    // --- validate_resolved_ips ---

    #[test]
    fn validate_rejects_any_private_ip() {
        let ips = vec![
            "93.184.216.34".parse::<IpAddr>().unwrap(), // public
            "10.0.0.1".parse::<IpAddr>().unwrap(),      // private — poisons the set
        ];
        let result = validate_resolved_ips(&ips);
        assert!(
            matches!(result, Err(TransportError::SsrfBlocked(_))),
            "Any private IP must poison the entire resolution set"
        );
    }

    #[test]
    fn validate_returns_first_public_ip() {
        let ips = vec![
            "93.184.216.34".parse::<IpAddr>().unwrap(),
            "1.1.1.1".parse::<IpAddr>().unwrap(),
        ];
        let result = validate_resolved_ips(&ips).unwrap();
        assert_eq!(result, "93.184.216.34".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn validate_empty_slice_errors() {
        let result = validate_resolved_ips(&[]);
        assert!(matches!(
            result,
            Err(TransportError::DnsResolutionFailed(_))
        ));
    }

    #[test]
    fn validate_single_public_ip_succeeds() {
        let ips = vec!["8.8.8.8".parse::<IpAddr>().unwrap()];
        let result = validate_resolved_ips(&ips).unwrap();
        assert_eq!(result, "8.8.8.8".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn validate_single_private_ip_denied() {
        let ips = vec!["10.0.0.1".parse::<IpAddr>().unwrap()];
        let result = validate_resolved_ips(&ips);
        assert!(matches!(result, Err(TransportError::SsrfBlocked(_))));
    }

    #[test]
    fn validate_all_private_denied() {
        let ips = vec![
            "10.0.0.1".parse::<IpAddr>().unwrap(),
            "192.168.1.1".parse::<IpAddr>().unwrap(),
        ];
        let result = validate_resolved_ips(&ips);
        assert!(matches!(result, Err(TransportError::SsrfBlocked(_))));
    }

    #[test]
    fn ipv4_future_use_boundary() {
        // 239.255.255.255 is multicast (blocked)
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(
            239, 255, 255, 255
        ))));
        // 240.0.0.0 is future-use (blocked)
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(240, 0, 0, 0))));
        // 255.255.255.255 is broadcast (blocked)
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(
            255, 255, 255, 255
        ))));
    }

    #[test]
    fn ipv6_multicast_boundary() {
        // ff00::1 (first multicast) — blocked
        let ff00: IpAddr = "ff00::1".parse().unwrap();
        assert!(is_private_ip(&ff00));
        // feff::1 — outside multicast, outside link-local & ULA → public
        // bytes[0]=0xFE, not 0xFF. Check: 0xFE & 0xFE = 0xFE ≠ 0xFC (not ULA),
        // bytes[1]=0xFF, 0xFF & 0xC0 = 0xC0 ≠ 0x80 (not link-local)
        let feff: IpAddr = "feff::1".parse().unwrap();
        assert!(!is_private_ip(&feff));
    }
}
