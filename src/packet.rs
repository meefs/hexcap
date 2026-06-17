use std::collections::HashSet;
use std::fmt;
use std::time::SystemTime;

use serde::Serialize;

use crate::expert::ExpertItem;

/// Link-layer type determining how to parse packet headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LinkType {
    /// Standard Ethernet (14-byte header) — `DLT_EN10MB` (1).
    #[default]
    Ethernet,
    /// BSD loopback (4-byte AF family header) — `DLT_NULL` (0).
    Null,
    /// Raw IP (no link-layer header) — `DLT_RAW` (12 on macOS, 228 on Linux).
    RawIp,
}

impl LinkType {
    /// Create from a pcap/DLT link-type value.
    #[must_use]
    pub fn from_dlt(dlt: u32) -> Self {
        match dlt {
            0 => Self::Null,
            12 | 14 | 101 | 228 => Self::RawIp,
            _ => Self::Ethernet, // fallback (includes DLT_EN10MB=1)
        }
    }

    /// Return the DLT number for pcap export.
    #[must_use]
    pub fn to_dlt(self) -> u32 {
        match self {
            Self::Ethernet => 1,
            Self::Null => 0,
            Self::RawIp => 101,
        }
    }

    /// Return the link-layer header length in bytes.
    #[must_use]
    pub fn header_len(self) -> usize {
        match self {
            Self::Ethernet => 14,
            Self::Null => 4,
            Self::RawIp => 0,
        }
    }
}

/// A bidirectional flow key — normalizes direction so A<>B == B<>A.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct FlowKey(pub String, pub String);

impl FlowKey {
    /// Create a normalized flow key from source and destination addresses.
    #[must_use]
    pub fn new(src: &str, dst: &str) -> Self {
        if src <= dst {
            Self(src.to_string(), dst.to_string())
        } else {
            Self(dst.to_string(), src.to_string())
        }
    }
}

impl fmt::Display for FlowKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}", self.0, self.1)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Arp,
    Dns,
    Other(u8),
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp => write!(f, "TCP"),
            Self::Udp => write!(f, "UDP"),
            Self::Icmp => write!(f, "ICMP"),
            Self::Arp => write!(f, "ARP"),
            Self::Dns => write!(f, "DNS"),
            Self::Other(n) => write!(f, "0x{n:02X}"),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CapturedPacket {
    pub id: u64,
    #[serde(serialize_with = "serialize_system_time")]
    pub timestamp: SystemTime,
    pub protocol: Protocol,
    pub src: String,
    pub dst: String,
    pub length: usize,
    #[serde(serialize_with = "serialize_bytes_as_hex")]
    pub data: Vec<u8>,
    pub decoded: Vec<DecodedField>,
    /// Raw TCP flags byte (SYN=0x02, RST=0x04, FIN=0x01, etc.). Zero for non-TCP.
    pub tcp_flags: u8,
    /// Expert information items (TCP analysis, anomaly detection, etc.).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub expert: Vec<ExpertItem>,
}

/// A decoded header field for display in the detail view.
#[derive(Debug, Clone, Serialize)]
pub struct DecodedField {
    pub label: String,
    pub value: String,
}

impl CapturedPacket {
    /// Check if either the source or destination port matches one of the given ports.
    pub fn matches_ports(&self, ports: &HashSet<u16>) -> bool {
        if ports.is_empty() {
            return true;
        }
        extract_port_from_addr(&self.src).is_some_and(|p| ports.contains(&p))
            || extract_port_from_addr(&self.dst).is_some_and(|p| ports.contains(&p))
    }
}

/// Extract port from address string. Handles `ip:port` and `[ipv6]:port`.
pub fn extract_port_from_addr(addr: &str) -> Option<u16> {
    if let Some(rest) = addr.strip_prefix('[') {
        // [ipv6]:port
        let after_bracket = rest.split(']').nth(1)?;
        after_bracket.strip_prefix(':')?.parse().ok()
    } else {
        addr.rsplit(':').next()?.parse().ok()
    }
}

/// Minimal packet parser — extracts Ethernet → IP → protocol / addresses.
#[allow(dead_code)]
pub fn parse_packet(id: u64, data: &[u8]) -> CapturedPacket {
    parse_packet_with_link(id, data, LinkType::Ethernet)
}

#[allow(clippy::too_many_lines)]
pub fn parse_packet_with_link(id: u64, data: &[u8], link_type: LinkType) -> CapturedPacket {
    let timestamp = SystemTime::now();
    let length = data.len();
    let hdr_len = link_type.header_len();

    if data.len() < hdr_len + 1 {
        return CapturedPacket {
            id,
            timestamp,
            protocol: Protocol::Other(0),
            src: "??".into(),
            dst: "??".into(),
            length,
            data: data.to_vec(),
            decoded: vec![],
            tcp_flags: 0,
            expert: vec![],
        };
    }

    // Determine IP version / ethertype based on link layer.
    match link_type {
        LinkType::Null => {
            // BSD loopback: 4-byte AF family in host byte order.
            let af = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
            match af {
                2 => parse_ipv4_at(id, timestamp, data, length, hdr_len), // AF_INET
                30 | 10 | 24 => parse_ipv6_at(id, timestamp, data, length, hdr_len), // AF_INET6
                _ => CapturedPacket {
                    id,
                    timestamp,
                    #[allow(clippy::cast_possible_truncation)]
                    protocol: Protocol::Other(af as u8),
                    src: "??".into(),
                    dst: "??".into(),
                    length,
                    data: data.to_vec(),
                    decoded: vec![field("AF", format!("{af}"))],
                    tcp_flags: 0,
                    expert: vec![],
                },
            }
        }
        LinkType::RawIp => {
            // No link header; first byte determines IP version.
            let version = data[0] >> 4;
            match version {
                4 => parse_ipv4_at(id, timestamp, data, length, 0),
                6 => parse_ipv6_at(id, timestamp, data, length, 0),
                _ => CapturedPacket {
                    id,
                    timestamp,
                    protocol: Protocol::Other(version),
                    src: "??".into(),
                    dst: "??".into(),
                    length,
                    data: data.to_vec(),
                    decoded: vec![],
                    tcp_flags: 0,
                    expert: vec![],
                },
            }
        }
        LinkType::Ethernet => {
            if data.len() < 14 {
                return CapturedPacket {
                    id,
                    timestamp,
                    protocol: Protocol::Other(0),
                    src: "??".into(),
                    dst: "??".into(),
                    length,
                    data: data.to_vec(),
                    decoded: vec![],
                    tcp_flags: 0,
                    expert: vec![],
                };
            }

            let ethertype = u16::from_be_bytes([data[12], data[13]]);

            match ethertype {
                0x0806 => {
                    let decoded = decode_arp(data);
                    CapturedPacket {
                        id,
                        timestamp,
                        protocol: Protocol::Arp,
                        src: format_mac(&data[6..12]),
                        dst: format_mac(&data[0..6]),
                        length,
                        data: data.to_vec(),
                        decoded,
                        tcp_flags: 0,
                        expert: vec![],
                    }
                }
                0x0800 => parse_ipv4_at(id, timestamp, data, length, 14),
                0x86DD => parse_ipv6_at(id, timestamp, data, length, 14),
                _ => CapturedPacket {
                    id,
                    timestamp,
                    #[allow(clippy::cast_possible_truncation)]
                    protocol: Protocol::Other((ethertype >> 8) as u8),
                    src: format_mac(&data[6..12]),
                    dst: format_mac(&data[0..6]),
                    length,
                    data: data.to_vec(),
                    decoded: vec![field("EtherType", format!("0x{ethertype:04X}"))],
                    tcp_flags: 0,
                    expert: vec![],
                },
            }
        }
    }
}

fn parse_ipv4_at(
    id: u64,
    timestamp: SystemTime,
    data: &[u8],
    length: usize,
    ip_offset: usize,
) -> CapturedPacket {
    if data.len() < ip_offset + 20 {
        return CapturedPacket {
            id,
            timestamp,
            protocol: Protocol::Other(0),
            src: "??".into(),
            dst: "??".into(),
            length,
            data: data.to_vec(),
            decoded: vec![],
            tcp_flags: 0,
            expert: vec![],
        };
    }

    let ip = &data[ip_offset..];
    let proto_byte = ip[9];
    let src_ip = format!("{}.{}.{}.{}", ip[12], ip[13], ip[14], ip[15]);
    let dst_ip = format!("{}.{}.{}.{}", ip[16], ip[17], ip[18], ip[19]);
    let ttl = ip[8];
    let total_len = u16::from_be_bytes([ip[2], ip[3]]);
    let ip_id = u16::from_be_bytes([ip[4], ip[5]]);
    let flags_frag = u16::from_be_bytes([ip[6], ip[7]]);
    let ihl = ((ip[0] & 0x0F) as usize) * 4;

    let mut decoded = vec![
        field("Version", "IPv4".into()),
        field("TTL", ttl.to_string()),
        field("Total Length", total_len.to_string()),
        field("ID", format!("0x{ip_id:04X}")),
        field("Flags", format_ip_flags(flags_frag)),
    ];

    let (protocol, src, dst, tcp_flags) = match proto_byte {
        1 => {
            decoded.extend(decode_icmp(ip, ihl));
            (Protocol::Icmp, src_ip, dst_ip, 0u8)
        }
        6 => {
            let (sp, dp) = parse_ports(ip, ihl);
            decoded.extend(decode_tcp(ip, ihl));
            let is_dns = sp == 53 || dp == 53;
            let flags = if ip.len() > ihl + 13 { ip[ihl + 13] } else { 0 };
            (
                if is_dns { Protocol::Dns } else { Protocol::Tcp },
                format!("{src_ip}:{sp}"),
                format!("{dst_ip}:{dp}"),
                flags,
            )
        }
        17 => {
            let (sp, dp) = parse_ports(ip, ihl);
            decoded.extend(decode_udp(ip, ihl));
            let is_dns = sp == 53 || dp == 53;
            (
                if is_dns { Protocol::Dns } else { Protocol::Udp },
                format!("{src_ip}:{sp}"),
                format!("{dst_ip}:{dp}"),
                0u8,
            )
        }
        other => {
            decoded.push(field("IP Protocol", format!("0x{other:02X}")));
            (Protocol::Other(other), src_ip, dst_ip, 0u8)
        }
    };

    CapturedPacket {
        id,
        timestamp,
        protocol,
        src,
        dst,
        length,
        data: data.to_vec(),
        decoded,
        tcp_flags,
        expert: vec![],
    }
}

fn parse_ports(ip: &[u8], ihl: usize) -> (u16, u16) {
    if ip.len() < ihl + 4 {
        return (0, 0);
    }
    let sp = u16::from_be_bytes([ip[ihl], ip[ihl + 1]]);
    let dp = u16::from_be_bytes([ip[ihl + 2], ip[ihl + 3]]);
    (sp, dp)
}

fn parse_ipv6_at(
    id: u64,
    timestamp: SystemTime,
    data: &[u8],
    length: usize,
    ip_offset: usize,
) -> CapturedPacket {
    if data.len() < ip_offset + 40 {
        return CapturedPacket {
            id,
            timestamp,
            protocol: Protocol::Other(0),
            src: "??".into(),
            dst: "??".into(),
            length,
            data: data.to_vec(),
            decoded: vec![],
            tcp_flags: 0,
            expert: vec![],
        };
    }

    let ip6 = &data[ip_offset..];
    let next_header = ip6[6];
    let hop_limit = ip6[7];
    let payload_len = u16::from_be_bytes([ip6[4], ip6[5]]);
    let src_ip = format_ipv6(&ip6[8..24]);
    let dst_ip = format_ipv6(&ip6[24..40]);

    let transport_offset = 40;

    let mut decoded = vec![
        field("Version", "IPv6".into()),
        field("Hop Limit", hop_limit.to_string()),
        field("Payload Length", payload_len.to_string()),
    ];

    let (protocol, src, dst, tcp_flags) = match next_header {
        58 => {
            decoded.extend(decode_icmp(ip6, transport_offset));
            (Protocol::Icmp, src_ip, dst_ip, 0u8)
        }
        6 => {
            let (sp, dp) = parse_ports(ip6, transport_offset);
            decoded.extend(decode_tcp(ip6, transport_offset));
            let is_dns = sp == 53 || dp == 53;
            let flags = if ip6.len() > transport_offset + 13 {
                ip6[transport_offset + 13]
            } else {
                0
            };
            (
                if is_dns { Protocol::Dns } else { Protocol::Tcp },
                format!("[{src_ip}]:{sp}"),
                format!("[{dst_ip}]:{dp}"),
                flags,
            )
        }
        17 => {
            let (sp, dp) = parse_ports(ip6, transport_offset);
            decoded.extend(decode_udp(ip6, transport_offset));
            let is_dns = sp == 53 || dp == 53;
            (
                if is_dns { Protocol::Dns } else { Protocol::Udp },
                format!("[{src_ip}]:{sp}"),
                format!("[{dst_ip}]:{dp}"),
                0u8,
            )
        }
        other => {
            decoded.push(field("Next Header", format!("0x{other:02X}")));
            (Protocol::Other(other), src_ip, dst_ip, 0u8)
        }
    };

    CapturedPacket {
        id,
        timestamp,
        protocol,
        src,
        dst,
        length,
        data: data.to_vec(),
        decoded,
        tcp_flags,
        expert: vec![],
    }
}

fn format_ipv6(bytes: &[u8]) -> String {
    let groups: Vec<String> = (0..8)
        .map(|i| {
            let hi = bytes[i * 2];
            let lo = bytes[i * 2 + 1];
            format!("{:x}", u16::from_be_bytes([hi, lo]))
        })
        .collect();
    // Simple compression: join with colons (no :: shortening for clarity).
    groups.join(":")
}

fn field(label: &str, value: String) -> DecodedField {
    DecodedField {
        label: label.into(),
        value,
    }
}

fn format_ip_flags(flags_frag: u16) -> String {
    let df = flags_frag & 0x4000 != 0;
    let mf = flags_frag & 0x2000 != 0;
    let offset = flags_frag & 0x1FFF;
    let mut parts = Vec::new();
    if df {
        parts.push("DF");
    }
    if mf {
        parts.push("MF");
    }
    if offset > 0 {
        return format!("{} off={offset}", parts.join(","));
    }
    if parts.is_empty() {
        "none".into()
    } else {
        parts.join(",")
    }
}

fn decode_tcp(ip: &[u8], offset: usize) -> Vec<DecodedField> {
    if ip.len() < offset + 20 {
        return vec![];
    }
    let t = &ip[offset..];
    let seq = u32::from_be_bytes([t[4], t[5], t[6], t[7]]);
    let ack = u32::from_be_bytes([t[8], t[9], t[10], t[11]]);
    let flags_byte = t[13];
    let window = u16::from_be_bytes([t[14], t[15]]);
    let data_offset = ((t[12] >> 4) as usize) * 4;

    let mut flags = Vec::new();
    if flags_byte & 0x01 != 0 {
        flags.push("FIN");
    }
    if flags_byte & 0x02 != 0 {
        flags.push("SYN");
    }
    if flags_byte & 0x04 != 0 {
        flags.push("RST");
    }
    if flags_byte & 0x08 != 0 {
        flags.push("PSH");
    }
    if flags_byte & 0x10 != 0 {
        flags.push("ACK");
    }
    if flags_byte & 0x20 != 0 {
        flags.push("URG");
    }

    let mut fields = vec![
        field("Seq", seq.to_string()),
        field("Ack", ack.to_string()),
        field("Flags", flags.join(",")),
        field("Window", window.to_string()),
    ];

    // Try to decode TLS handshake from TCP payload.
    let payload_start = offset + data_offset;
    if payload_start < ip.len() {
        fields.extend(decode_tls_record(&ip[payload_start..]));
    }

    fields
}

fn decode_udp(ip: &[u8], offset: usize) -> Vec<DecodedField> {
    if ip.len() < offset + 8 {
        return vec![];
    }
    let t = &ip[offset..];
    let udp_len = u16::from_be_bytes([t[4], t[5]]);
    let checksum = u16::from_be_bytes([t[6], t[7]]);
    vec![
        field("UDP Length", udp_len.to_string()),
        field("Checksum", format!("0x{checksum:04X}")),
    ]
}

fn decode_icmp(ip: &[u8], offset: usize) -> Vec<DecodedField> {
    if ip.len() < offset + 4 {
        return vec![];
    }
    let t = &ip[offset..];
    let icmp_type = t[0];
    let icmp_code = t[1];
    let type_name = match icmp_type {
        0 => "Echo Reply",
        3 => "Destination Unreachable",
        8 => "Echo Request",
        11 => "Time Exceeded",
        128 => "Echo Request (v6)",
        129 => "Echo Reply (v6)",
        _ => "Other",
    };
    vec![
        field("Type", format!("{icmp_type} ({type_name})")),
        field("Code", icmp_code.to_string()),
    ]
}

fn decode_arp(data: &[u8]) -> Vec<DecodedField> {
    if data.len() < 42 {
        return vec![field("ARP", "truncated".into())];
    }
    let arp = &data[14..];
    let op = u16::from_be_bytes([arp[6], arp[7]]);
    let op_name = match op {
        1 => "Request",
        2 => "Reply",
        _ => "Other",
    };
    let sender_ip = format!("{}.{}.{}.{}", arp[14], arp[15], arp[16], arp[17]);
    let target_ip = format!("{}.{}.{}.{}", arp[24], arp[25], arp[26], arp[27]);
    let sender_mac = format_mac(&arp[8..14]);
    vec![
        field("Operation", format!("{op} ({op_name})")),
        field("Sender MAC", sender_mac),
        field("Sender IP", sender_ip),
        field("Target IP", target_ip),
    ]
}

fn format_mac(bytes: &[u8]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
    )
}

// -- TLS handshake decode --------------------------------------------------

/// Try to decode a TLS record header and handshake message.
fn decode_tls_record(data: &[u8]) -> Vec<DecodedField> {
    // TLS record: content_type(1) + version(2) + length(2) = 5 bytes minimum
    if data.len() < 5 {
        return vec![];
    }
    let content_type = data[0];
    let version = u16::from_be_bytes([data[1], data[2]]);

    // Only decode Handshake (22) and ChangeCipherSpec (20) content types.
    let type_name = match content_type {
        20 => "ChangeCipherSpec",
        21 => "Alert",
        22 => "Handshake",
        23 => "ApplicationData",
        _ => return vec![],
    };

    let version_str = match version {
        0x0301 => "TLS 1.0",
        0x0302 => "TLS 1.1",
        0x0303 => "TLS 1.2",
        0x0304 => "TLS 1.3",
        _ => "Unknown",
    };

    let mut fields = vec![
        field("TLS", type_name.into()),
        field("TLS Version", format!("{version_str} (0x{version:04X})")),
    ];

    // Decode handshake messages.
    if content_type == 22 && data.len() > 5 {
        fields.extend(decode_tls_handshake(&data[5..]));
    }

    fields
}

/// Decode the TLS handshake message type and extract SNI from `ClientHello`.
fn decode_tls_handshake(data: &[u8]) -> Vec<DecodedField> {
    if data.is_empty() {
        return vec![];
    }

    let hs_type = data[0];
    let hs_name = match hs_type {
        0 => "HelloRequest",
        1 => "ClientHello",
        2 => "ServerHello",
        4 => "NewSessionTicket",
        11 => "Certificate",
        12 => "ServerKeyExchange",
        13 => "CertificateRequest",
        14 => "ServerHelloDone",
        15 => "CertificateVerify",
        16 => "ClientKeyExchange",
        20 => "Finished",
        _ => "Unknown",
    };

    let mut fields = vec![field("Handshake", hs_name.into())];

    // Extract SNI from ClientHello.
    if hs_type == 1
        && let Some(sni) = extract_sni(data)
    {
        fields.push(field("SNI", sni));
    }

    // Extract TLS version from ClientHello/ServerHello.
    if (hs_type == 1 || hs_type == 2) && data.len() >= 6 {
        let hs_version = u16::from_be_bytes([data[4], data[5]]);
        let ver_str = match hs_version {
            0x0301 => "TLS 1.0",
            0x0302 => "TLS 1.1",
            0x0303 => "TLS 1.2/1.3",
            _ => "Unknown",
        };
        fields.push(field(
            "Handshake Version",
            format!("{ver_str} (0x{hs_version:04X})"),
        ));
    }

    fields
}

/// Extract Server Name Indication (SNI) from a TLS `ClientHello` message.
fn extract_sni(data: &[u8]) -> Option<String> {
    // ClientHello layout:
    //   [0]: handshake type (1)
    //   [1..4]: length (3 bytes)
    //   [4..6]: client version
    //   [6..38]: random (32 bytes)
    //   [38]: session_id length
    if data.len() < 39 {
        return None;
    }

    let mut pos = 38;
    // Skip session ID.
    let session_id_len = *data.get(pos)? as usize;
    pos += 1 + session_id_len;

    // Skip cipher suites.
    if pos + 2 > data.len() {
        return None;
    }
    let cipher_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2 + cipher_len;

    // Skip compression methods.
    if pos >= data.len() {
        return None;
    }
    let comp_len = *data.get(pos)? as usize;
    pos += 1 + comp_len;

    // Extensions total length.
    if pos + 2 > data.len() {
        return None;
    }
    let ext_total = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos + ext_total;

    // Iterate extensions looking for SNI (type 0x0000).
    while pos + 4 <= data.len().min(ext_end) {
        let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;

        if ext_type == 0 && ext_len >= 5 && pos + ext_len <= data.len() {
            // SNI extension: list_length(2) + type(1) + name_length(2) + name
            let name_len = u16::from_be_bytes([data[pos + 3], data[pos + 4]]) as usize;
            if pos + 5 + name_len <= data.len() {
                return String::from_utf8(data[pos + 5..pos + 5 + name_len].to_vec()).ok();
            }
        }

        pos += ext_len;
    }

    None
}

// -- Serde helpers -----------------------------------------------------------

/// Serialize `SystemTime` as ISO 8601 UTC string.
fn serialize_system_time<S: serde::Serializer>(
    ts: &SystemTime,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let dur = ts
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    let millis = dur.subsec_millis();
    // Format as seconds.millis (compact epoch representation).
    serializer.serialize_str(&format!("{secs}.{millis:03}"))
}

/// Serialize `Option<SystemTime>` as epoch string or null.
/// Serde's `serialize_with` requires `&Option<T>` signature for optional fields.
#[allow(clippy::ref_option)]
pub fn serialize_opt_timestamp<S: serde::Serializer>(
    ts: &Option<SystemTime>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match ts {
        Some(t) => serialize_system_time(t, serializer),
        None => serializer.serialize_none(),
    }
}

/// Serialize `Vec<u8>` as a hex string (e.g. "00 11 22 ff").
fn serialize_bytes_as_hex<S: serde::Serializer>(
    data: &[u8],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let hex: Vec<String> = data.iter().map(|b| format!("{b:02x}")).collect();
    serializer.serialize_str(&hex.join(" "))
}

// ---------------------------------------------------------------------------
// Shared helpers (used by both TUI and headless paths)
// ---------------------------------------------------------------------------

/// Extract the TCP sequence number and payload from a raw Ethernet frame.
/// Returns `(seq, payload_slice)` or `None` if not a TCP packet with parseable headers.
pub fn extract_tcp_seq_payload(data: &[u8]) -> Option<(u32, &[u8])> {
    if data.len() < 14 {
        return None;
    }
    let ethertype = u16::from_be_bytes([data[12], data[13]]);
    let ip = &data[14..];
    let ip_hdr_len = match ethertype {
        0x0800 => {
            if ip.is_empty() {
                return None;
            }
            ((ip[0] & 0x0F) as usize) * 4
        }
        0x86DD => 40,
        _ => return None,
    };
    if ip.len() < ip_hdr_len + 20 {
        return None;
    }
    let tcp = &ip[ip_hdr_len..];
    let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
    let tcp_hdr_len = ((tcp[12] >> 4) as usize) * 4;
    if tcp.len() <= tcp_hdr_len {
        return Some((seq, &[]));
    }
    Some((seq, &tcp[tcp_hdr_len..]))
}

/// Extract TCP payload from a raw Ethernet frame.
///
/// Skips Ethernet header (14 bytes), IP header (variable), and TCP header (variable).
pub fn extract_tcp_payload(data: &[u8]) -> Option<&[u8]> {
    if data.len() < 14 {
        return None;
    }
    let ethertype = u16::from_be_bytes([data[12], data[13]]);
    let ip = &data[14..];
    let ip_hdr_len = match ethertype {
        0x0800 => {
            // IPv4
            if ip.is_empty() {
                return None;
            }
            ((ip[0] & 0x0F) as usize) * 4
        }
        0x86DD => 40, // IPv6 fixed header
        _ => return None,
    };
    if ip.len() < ip_hdr_len + 20 {
        return None;
    }
    let tcp = &ip[ip_hdr_len..];
    let tcp_hdr_len = ((tcp[12] >> 4) as usize) * 4;
    if tcp.len() <= tcp_hdr_len {
        return None; // No payload
    }
    Some(&tcp[tcp_hdr_len..])
}

/// Evaluate a display filter expression against a packet.
///
/// Supports:
/// - Protocol: `tcp`, `udp`, `icmp`, `dns`, `arp`
/// - Port:    `port:443`
/// - IP:      `ip:10.0.0.1`
/// - Flags:   `syn`, `rst`, `fin`, `ack`, `psh`
/// - Length:  `len>100`, `len<1500`, `len>=64`, `len<=1500`, `len==100`
/// - Expert:  `expert`, `expert.warn`, `expert.error`, `expert.note`, `expert.chat`
/// - Negation: prefix any token with `!` (e.g. `!arp`, `!port:22`)
/// - OR:      `tcp || udp`  or  `tcp or udp`
/// - AND:     `tcp port:443` (implicit) or `tcp && port:443` or `tcp and port:443`
///
/// Operator precedence: `||` binds looser than `&&` / implicit AND.
pub fn matches_display_filter(pkt: &CapturedPacket, filter: &str) -> bool {
    // Split into OR groups first, then AND within each group.
    let or_groups = split_or(filter);
    or_groups.iter().any(|group| {
        let and_tokens = split_and(group);
        and_tokens.iter().all(|token| eval_token(pkt, token.trim()))
    })
}

/// Split a filter string on `||` or `or` (case-insensitive).
fn split_or(filter: &str) -> Vec<String> {
    // Replace ` or ` (word-bounded) with `||`, then split on `||`.
    let normalized = filter.replace(" or ", " || ").replace(" OR ", " || ");
    normalized
        .split("||")
        .map(|s| s.trim().to_string())
        .collect()
}

/// Split an AND group on `&&` or `and`; otherwise whitespace-separated tokens.
fn split_and(group: &str) -> Vec<String> {
    let normalized = group.replace(" and ", " && ").replace(" AND ", " && ");
    if normalized.contains("&&") {
        normalized
            .split("&&")
            .map(|s| s.trim().to_string())
            .collect()
    } else {
        // Implicit AND: whitespace-separated tokens.
        normalized.split_whitespace().map(String::from).collect()
    }
}

/// Evaluate a single filter token (possibly negated) against a packet.
fn eval_token(pkt: &CapturedPacket, token: &str) -> bool {
    if token.is_empty() {
        return true;
    }
    let (negated, tok) = if let Some(rest) = token.strip_prefix('!') {
        (true, rest)
    } else {
        (false, token)
    };
    let matched = eval_atom(pkt, tok);
    if negated { !matched } else { matched }
}

/// Evaluate a single non-negated atom.
fn eval_atom(pkt: &CapturedPacket, tok: &str) -> bool {
    match tok.to_ascii_lowercase().as_str() {
        "tcp" => pkt.protocol == Protocol::Tcp,
        "udp" => pkt.protocol == Protocol::Udp,
        "icmp" => pkt.protocol == Protocol::Icmp,
        "dns" => pkt.protocol == Protocol::Dns,
        "arp" => pkt.protocol == Protocol::Arp,
        "syn" => pkt.tcp_flags & 0x02 != 0,
        "rst" => pkt.tcp_flags & 0x04 != 0,
        "fin" => pkt.tcp_flags & 0x01 != 0,
        "ack" => pkt.tcp_flags & 0x10 != 0,
        "psh" => pkt.tcp_flags & 0x08 != 0,
        "expert" => !pkt.expert.is_empty(),
        "expert.chat" => pkt
            .expert
            .iter()
            .any(|e| e.severity == crate::expert::Severity::Chat),
        "expert.note" => pkt
            .expert
            .iter()
            .any(|e| e.severity == crate::expert::Severity::Note),
        "expert.warn" => pkt
            .expert
            .iter()
            .any(|e| e.severity == crate::expert::Severity::Warn),
        "expert.error" => pkt
            .expert
            .iter()
            .any(|e| e.severity == crate::expert::Severity::Error),
        other => eval_comparison(pkt, other),
    }
}

/// Evaluate comparison expressions like `len>100`, `port:443`, `ip:10.0.0`.
fn eval_comparison(pkt: &CapturedPacket, tok: &str) -> bool {
    // port:N
    if let Some(port_str) = tok.strip_prefix("port:") {
        return if let Ok(port) = port_str.parse::<u16>() {
            let src_port = extract_port_from_addr(&pkt.src);
            let dst_port = extract_port_from_addr(&pkt.dst);
            src_port == Some(port) || dst_port == Some(port)
        } else {
            false
        };
    }
    // ip:ADDR
    if let Some(ip_str) = tok.strip_prefix("ip:") {
        return pkt.src.starts_with(ip_str) || pkt.dst.starts_with(ip_str);
    }
    // len comparisons: len>N, len<N, len>=N, len<=N, len==N, len=N
    if let Some(rest) = tok.strip_prefix("len") {
        return eval_len_cmp(pkt.length, rest);
    }
    // Unknown token — no match.
    false
}

/// Evaluate a length comparison like `>100`, `<=1500`, `==64`.
fn eval_len_cmp(length: usize, expr: &str) -> bool {
    let (op, val_str) = if let Some(v) = expr.strip_prefix(">=") {
        (">=", v)
    } else if let Some(v) = expr.strip_prefix("<=") {
        ("<=", v)
    } else if let Some(v) = expr.strip_prefix("==") {
        ("==", v)
    } else if let Some(v) = expr.strip_prefix("!=") {
        ("!=", v)
    } else if let Some(v) = expr.strip_prefix('>') {
        (">", v)
    } else if let Some(v) = expr.strip_prefix('<') {
        ("<", v)
    } else if let Some(v) = expr.strip_prefix('=') {
        ("=", v)
    } else {
        return false;
    };

    let Ok(n) = val_str.parse::<usize>() else {
        return false;
    };
    match op {
        ">=" => length >= n,
        "<=" => length <= n,
        "==" | "=" => length == n,
        "!=" => length != n,
        ">" => length > n,
        "<" => length < n,
        _ => false,
    }
}
