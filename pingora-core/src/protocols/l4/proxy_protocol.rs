// Copyright 2025 Cloudflare, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Proxy Protocol (V1 & V2) parser
//!
//! This module implements parsing for the PROXY protocol as defined in:
//! <https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt>
//!
//! The PROXY protocol is used by load balancers and proxies to pass client
//! connection information to backend servers.
//!
//! This implementation uses the `proxy-header` crate for parsing.

use super::socket::SocketAddr;
use bytes::Bytes;
use pingora_error::{Error, ErrorType, Result};
use proxy_header::{ParseConfig, ProxyHeader, Tlv as ProxyHeaderTlv};
use tokio::io::AsyncRead;

/// Version of the PROXY protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyProtocolVersion {
    V1,
    V2,
}

/// Type-Length-Value (TLV) entry from PROXY protocol V2
#[derive(Debug, Clone)]
pub struct Tlv {
    pub typ: u8,
    pub value: Bytes,
}

/// Well-known TLV types
pub mod tlv_types {
    pub const ALPN: u8 = 0x01;
    pub const AUTHORITY: u8 = 0x02;
    pub const CRC32C: u8 = 0x03;
    pub const NOOP: u8 = 0x04;
    pub const UNIQUE_ID: u8 = 0x05;
    pub const SSL: u8 = 0x20;
    pub const SSL_VERSION: u8 = 0x21;
    pub const SSL_CN: u8 = 0x22;
    pub const SSL_CIPHER: u8 = 0x23;
    pub const SSL_SIG_ALG: u8 = 0x24;
    pub const SSL_KEY_ALG: u8 = 0x25;
    pub const NETNS: u8 = 0x30;
}

/// Parsed PROXY protocol header information
#[derive(Debug, Clone)]
pub struct ProxyProtocolHeader {
    /// Version of the PROXY protocol used
    pub version: ProxyProtocolVersion,
    /// Whether this is a LOCAL command (health check) or PROXY command
    pub is_local: bool,
    /// Source address (client)
    pub source_addr: Option<SocketAddr>,
    /// Destination address (proxy's receiving address)
    pub dest_addr: Option<SocketAddr>,
    /// TLV entries (only for V2)
    pub tlvs: Vec<Tlv>,
    /// Raw header bytes (useful for forwarding)
    pub raw_header: Bytes,
}

impl ProxyProtocolHeader {
    /// Get the original client IP address
    pub fn client_addr(&self) -> Option<&SocketAddr> {
        self.source_addr.as_ref()
    }

    /// Get a TLV by type
    pub fn get_tlv(&self, typ: u8) -> Option<&Tlv> {
        self.tlvs.iter().find(|t| t.typ == typ)
    }

    /// Get the ALPN TLV value if present
    pub fn alpn(&self) -> Option<&[u8]> {
        self.get_tlv(tlv_types::ALPN).map(|t| t.value.as_ref())
    }

    /// Get the authority (SNI) TLV value if present
    pub fn authority(&self) -> Option<&str> {
        self.get_tlv(tlv_types::AUTHORITY)
            .and_then(|t| std::str::from_utf8(&t.value).ok())
    }

    /// Get the unique ID TLV value if present
    pub fn unique_id(&self) -> Option<&[u8]> {
        self.get_tlv(tlv_types::UNIQUE_ID).map(|t| t.value.as_ref())
    }
}

/// Convert a `proxy_header::ProxyHeader` to our `ProxyProtocolHeader`
///
/// The version is inferred from the raw header bytes since the proxy-header crate
/// doesn't expose a version method.
fn convert_header(header: &ProxyHeader<'_>, raw_header: Bytes) -> ProxyProtocolHeader {
    // Infer version from raw header: V2 starts with the 12-byte signature,
    // V1 starts with "PROXY "
    let version = if raw_header.starts_with(b"PROXY ") {
        ProxyProtocolVersion::V1
    } else {
        ProxyProtocolVersion::V2
    };

    let is_local = header.proxied_address().is_none();

    let (source_addr, dest_addr) = match header.proxied_address() {
        Some(addr) => (
            Some(SocketAddr::Inet(addr.source)),
            Some(SocketAddr::Inet(addr.destination)),
        ),
        None => (None, None),
    };

    // Convert TLVs
    let mut tlvs = Vec::new();
    for tlv_result in header.tlvs() {
        if let Ok(tlv) = tlv_result {
            let (typ, value) = match tlv {
                ProxyHeaderTlv::Alpn(v) => (tlv_types::ALPN, Bytes::copy_from_slice(&v)),
                ProxyHeaderTlv::Authority(v) => (tlv_types::AUTHORITY, Bytes::copy_from_slice(v.as_bytes())),
                ProxyHeaderTlv::Crc32c(_) => (tlv_types::CRC32C, Bytes::new()), // CRC is validated, not stored
                ProxyHeaderTlv::Noop(_) => continue, // Skip NOOP
                ProxyHeaderTlv::UniqueId(v) => (tlv_types::UNIQUE_ID, Bytes::copy_from_slice(&v)),
                ProxyHeaderTlv::Ssl(ssl_info) => {
                    // Store SSL TLV - we could expand this to store sub-TLVs
                    let _ = ssl_info; // For now, just acknowledge we have SSL info
                    (tlv_types::SSL, Bytes::new())
                }
                ProxyHeaderTlv::Netns(v) => (tlv_types::NETNS, Bytes::copy_from_slice(v.as_bytes())),
                ProxyHeaderTlv::SslVersion(v) => (tlv_types::SSL_VERSION, Bytes::copy_from_slice(v.as_bytes())),
                ProxyHeaderTlv::SslCn(v) => (tlv_types::SSL_CN, Bytes::copy_from_slice(v.as_bytes())),
                ProxyHeaderTlv::SslCipher(v) => (tlv_types::SSL_CIPHER, Bytes::copy_from_slice(v.as_bytes())),
                ProxyHeaderTlv::SslSigAlg(v) => (tlv_types::SSL_SIG_ALG, Bytes::copy_from_slice(v.as_bytes())),
                ProxyHeaderTlv::SslKeyAlg(v) => (tlv_types::SSL_KEY_ALG, Bytes::copy_from_slice(v.as_bytes())),
                ProxyHeaderTlv::Custom(typ, v) => (typ, Bytes::copy_from_slice(&v)),
                _ => continue, // Skip unknown TLV types
            };
            tlvs.push(Tlv { typ, value });
        }
    }

    ProxyProtocolHeader {
        version,
        is_local,
        source_addr,
        dest_addr,
        tlvs,
        raw_header,
    }
}

/// Read and parse a PROXY protocol header from a stream
///
/// This function reads from the stream and parses the PROXY protocol header.
/// It returns the parsed header and any remaining bytes that were read but
/// not part of the header.
///
/// Returns `Ok((Some(header), remaining))` if a valid header was parsed,
/// `Ok((None, peeked_data))` if no PROXY protocol header was detected,
/// `Err` if parsing failed.
pub async fn read_proxy_protocol<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<(Option<ProxyProtocolHeader>, Vec<u8>)> {
    use tokio::io::AsyncReadExt;

    // Read enough bytes to detect and parse the header
    // V1 max is 108 bytes, V2 can be larger but we read incrementally
    let mut buf = Vec::with_capacity(256);
    let mut tmp = [0u8; 256];

    loop {
        let n = stream
            .read(&mut tmp)
            .await
            .map_err(|e| Error::explain(ErrorType::ReadError, format!("Failed to read PROXY protocol header: {}", e)))?;

        if n == 0 {
            if buf.is_empty() {
                return Ok((None, Vec::new()));
            }
            return Err(Error::explain(
                ErrorType::AcceptError,
                "Connection closed while reading PROXY protocol header",
            ));
        }

        buf.extend_from_slice(&tmp[..n]);

        match parse_proxy_protocol(&buf)? {
            Some((header, len)) => {
                let remaining = buf[len..].to_vec();
                return Ok((Some(header), remaining));
            }
            None => {
                // Need more data, but check if this looks like a non-PROXY protocol connection
                if buf.len() >= 8 {
                    // Check if it starts with PROXY v1 or v2 signature
                    let is_v1 = buf.starts_with(b"PROXY ");
                    let is_v2 = buf.len() >= 12 && buf[..12] == [0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A];

                    if !is_v1 && !is_v2 {
                        // Not a PROXY protocol header
                        return Ok((None, buf));
                    }
                }

                // Prevent reading too much data
                if buf.len() > 1024 {
                    return Err(Error::explain(
                        ErrorType::AcceptError,
                        "PROXY protocol header too large",
                    ));
                }
                // Continue reading
            }
        }
    }
}

/// Read and parse a PROXY protocol header from a buffer
///
/// This is a synchronous version that parses from an existing buffer.
/// Returns the parsed header and the number of bytes consumed.
pub fn parse_proxy_protocol(buf: &[u8]) -> Result<Option<(ProxyProtocolHeader, usize)>> {
    let config = ParseConfig::default();

    match ProxyHeader::parse(buf, config) {
        Ok((header, len)) => {
            let raw_header = Bytes::copy_from_slice(&buf[..len]);
            let converted = convert_header(&header, raw_header);
            Ok(Some((converted, len)))
        }
        Err(proxy_header::Error::BufferTooShort) => Ok(None),
        Err(e) => Err(Error::explain(
            ErrorType::AcceptError,
            format!("Failed to parse PROXY protocol: {}", e),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_v1_tcp4() {
        let header = b"PROXY TCP4 192.168.1.1 192.168.1.2 12345 80\r\n";

        let (result, len) = parse_proxy_protocol(header).unwrap().unwrap();

        assert_eq!(result.version, ProxyProtocolVersion::V1);
        assert!(!result.is_local);
        assert_eq!(
            result.source_addr,
            Some(SocketAddr::Inet("192.168.1.1:12345".parse().unwrap()))
        );
        assert_eq!(
            result.dest_addr,
            Some(SocketAddr::Inet("192.168.1.2:80".parse().unwrap()))
        );
        assert_eq!(len, header.len());
    }

    #[test]
    fn test_parse_v1_tcp6() {
        let header = b"PROXY TCP6 2001:db8::1 2001:db8::2 12345 80\r\n";

        let (result, len) = parse_proxy_protocol(header).unwrap().unwrap();

        assert_eq!(result.version, ProxyProtocolVersion::V1);
        assert!(!result.is_local);
        assert_eq!(
            result.source_addr,
            Some(SocketAddr::Inet("[2001:db8::1]:12345".parse().unwrap()))
        );
        assert_eq!(
            result.dest_addr,
            Some(SocketAddr::Inet("[2001:db8::2]:80".parse().unwrap()))
        );
        assert_eq!(len, header.len());
    }

    #[test]
    fn test_parse_v1_unknown() {
        let header = b"PROXY UNKNOWN\r\n";

        let (result, len) = parse_proxy_protocol(header).unwrap().unwrap();

        assert_eq!(result.version, ProxyProtocolVersion::V1);
        assert!(result.is_local);
        assert!(result.source_addr.is_none());
        assert_eq!(len, header.len());
    }

    #[test]
    fn test_parse_v2_tcp4() {
        // V2 header for TCP4 192.168.1.1:12345 -> 192.168.1.2:80
        let mut header = Vec::new();
        // V2 signature
        header.extend_from_slice(&[0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A]);
        header.push(0x21); // version 2, PROXY command
        header.push(0x11); // AF_INET, STREAM
        header.extend_from_slice(&12u16.to_be_bytes()); // address length
        header.extend_from_slice(&[192, 168, 1, 1]); // src IP
        header.extend_from_slice(&[192, 168, 1, 2]); // dst IP
        header.extend_from_slice(&12345u16.to_be_bytes()); // src port
        header.extend_from_slice(&80u16.to_be_bytes()); // dst port

        let (result, len) = parse_proxy_protocol(&header).unwrap().unwrap();

        assert_eq!(result.version, ProxyProtocolVersion::V2);
        assert!(!result.is_local);
        assert_eq!(
            result.source_addr,
            Some(SocketAddr::Inet("192.168.1.1:12345".parse().unwrap()))
        );
        assert_eq!(
            result.dest_addr,
            Some(SocketAddr::Inet("192.168.1.2:80".parse().unwrap()))
        );
        assert_eq!(len, header.len());
    }

    #[test]
    fn test_parse_v2_tcp6() {
        use std::net::Ipv6Addr;

        // V2 header for TCP6 [2001:db8::1]:12345 -> [2001:db8::2]:80
        let mut header = Vec::new();
        // V2 signature
        header.extend_from_slice(&[0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A]);
        header.push(0x21); // version 2, PROXY command
        header.push(0x21); // AF_INET6, STREAM
        header.extend_from_slice(&36u16.to_be_bytes()); // address length (16+16+2+2)

        let src_ip: Ipv6Addr = "2001:db8::1".parse().unwrap();
        header.extend_from_slice(&src_ip.octets());
        let dst_ip: Ipv6Addr = "2001:db8::2".parse().unwrap();
        header.extend_from_slice(&dst_ip.octets());
        header.extend_from_slice(&12345u16.to_be_bytes()); // src port
        header.extend_from_slice(&80u16.to_be_bytes()); // dst port

        let (result, len) = parse_proxy_protocol(&header).unwrap().unwrap();

        assert_eq!(result.version, ProxyProtocolVersion::V2);
        assert!(!result.is_local);
        assert_eq!(
            result.source_addr,
            Some(SocketAddr::Inet("[2001:db8::1]:12345".parse().unwrap()))
        );
        assert_eq!(
            result.dest_addr,
            Some(SocketAddr::Inet("[2001:db8::2]:80".parse().unwrap()))
        );
        assert_eq!(len, header.len());
    }

    #[test]
    fn test_parse_v2_local() {
        // V2 header for LOCAL command
        let mut header = Vec::new();
        // V2 signature
        header.extend_from_slice(&[0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A]);
        header.push(0x20); // version 2, LOCAL command
        header.push(0x00); // UNSPEC
        header.extend_from_slice(&0u16.to_be_bytes()); // address length

        let (result, len) = parse_proxy_protocol(&header).unwrap().unwrap();

        assert_eq!(result.version, ProxyProtocolVersion::V2);
        assert!(result.is_local);
        assert!(result.source_addr.is_none());
        assert_eq!(len, header.len());
    }

    #[test]
    fn test_parse_v2_with_tlv() {
        // V2 header with TLVs
        let mut header = Vec::new();
        // V2 signature
        header.extend_from_slice(&[0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A]);
        header.push(0x21); // version 2, PROXY command
        header.push(0x11); // AF_INET, STREAM

        // TLVs: authority "example.com" and a custom TLV (type 0xE0)
        let authority = b"example.com";
        let custom_value = b"custom-data";
        let tlv1_len = 3 + authority.len(); // type(1) + len(2) + value
        let tlv2_len = 3 + custom_value.len();
        let addr_len = 12 + tlv1_len + tlv2_len;

        header.extend_from_slice(&(addr_len as u16).to_be_bytes());
        header.extend_from_slice(&[192, 168, 1, 1]); // src IP
        header.extend_from_slice(&[192, 168, 1, 2]); // dst IP
        header.extend_from_slice(&12345u16.to_be_bytes()); // src port
        header.extend_from_slice(&80u16.to_be_bytes()); // dst port

        // TLV 1: authority
        header.push(tlv_types::AUTHORITY);
        header.extend_from_slice(&(authority.len() as u16).to_be_bytes());
        header.extend_from_slice(authority);

        // TLV 2: custom (0xE0 is in the reserved range for custom use)
        header.push(0xE0);
        header.extend_from_slice(&(custom_value.len() as u16).to_be_bytes());
        header.extend_from_slice(custom_value);

        let (result, _) = parse_proxy_protocol(&header).unwrap().unwrap();

        assert_eq!(result.authority(), Some("example.com"));
        assert_eq!(result.tlvs.len(), 2);

        let custom_tlv = result.get_tlv(0xE0).unwrap();
        assert_eq!(custom_tlv.value.as_ref(), b"custom-data");
    }

    #[test]
    fn test_no_proxy_protocol() {
        let data = b"GET / HTTP/1.1\r\n";

        // This should return an error since it's not a valid PROXY protocol header
        let result = parse_proxy_protocol(data);
        assert!(result.is_err() || result.unwrap().is_none());
    }

    #[test]
    fn test_incomplete_buffer() {
        // Incomplete V1 header
        let data = b"PROXY TCP4 192.168";

        let result = parse_proxy_protocol(data).unwrap();
        assert!(result.is_none()); // BufferTooShort
    }
}
