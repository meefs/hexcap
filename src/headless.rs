//! Headless (non-TUI) output for agent and pipeline consumption.
//!
//! Each public function corresponds to a CLI subcommand and writes JSON to
//! stdout.  Live capture outputs one JSON object per line (JSONL); file-based
//! commands output a single JSON value.

use std::cmp::Reverse;
use std::collections::HashMap;
use std::io::{self, Write};
use std::path::Path;

use anyhow::{Result, bail};
use serde::Serialize;

use crate::app::FlowInfo;
use crate::capture;
use crate::dns;
use crate::export;
use crate::geoip;
use crate::packet::{
    self, CapturedPacket, FlowKey, Protocol, extract_tcp_payload, matches_display_filter,
};

/// Optional enrichment for headless output (`GeoIP` + DNS).
pub struct Enrichment {
    pub geo_db: Option<geoip::GeoDb>,
    pub dns: bool,
    dns_cache: HashMap<std::net::IpAddr, String>,
    geo_cache: HashMap<std::net::IpAddr, String>,
}

impl Enrichment {
    pub fn new(geoip_path: Option<&str>, dns_enabled: bool) -> Self {
        let geo_db = geoip_path.and_then(|p| geoip::GeoDb::open(std::path::Path::new(p)).ok());
        Self {
            geo_db,
            dns: dns_enabled,
            dns_cache: HashMap::new(),
            geo_cache: HashMap::new(),
        }
    }

    /// Enrich an address string with DNS hostname and/or `GeoIP` country code.
    pub fn enrich(&mut self, addr: &str) -> String {
        let mut result = addr.to_string();
        if self.dns
            && let Some(ip) = parse_ip(addr)
        {
            let hostname = self
                .dns_cache
                .entry(ip)
                .or_insert_with(|| dns::resolve_blocking(ip).unwrap_or_default());
            if !hostname.is_empty() {
                result = format!("{result} ({hostname})");
            }
        }
        if let Some(ref db) = self.geo_db
            && let Some(ip) = parse_ip(addr)
        {
            let code = self
                .geo_cache
                .entry(ip)
                .or_insert_with(|| db.country(ip).unwrap_or_default());
            if !code.is_empty() {
                result = format!("{result} [{code}]");
            }
        }
        result
    }

    /// Enrich a packet's src and dst fields in place.
    pub fn enrich_packet(&mut self, pkt: &mut CapturedPacket) {
        if self.geo_db.is_some() || self.dns {
            pkt.src = self.enrich(&pkt.src);
            pkt.dst = self.enrich(&pkt.dst);
        }
    }

    pub fn is_active(&self) -> bool {
        self.geo_db.is_some() || self.dns
    }
}

/// Extract IP from "ip:port" or "[ipv6]:port" format.
fn parse_ip(addr: &str) -> Option<std::net::IpAddr> {
    let ip_str = if let Some(rest) = addr.strip_prefix('[') {
        rest.split(']').next()?
    } else if let Some(idx) = addr.rfind(':') {
        let after = &addr[idx + 1..];
        if after.chars().all(|c| c.is_ascii_digit()) {
            &addr[..idx]
        } else {
            addr
        }
    } else {
        addr
    };
    ip_str.parse().ok()
}

/// Write a serializable value as JSON (compact or pretty) followed by a newline.
fn write_json<T: Serialize>(value: &T, compact: bool) -> Result<()> {
    let stdout = io::stdout();
    let mut out = stdout.lock();
    if compact {
        serde_json::to_writer(&mut out, value)?;
    } else {
        serde_json::to_writer_pretty(&mut out, value)?;
    }
    out.write_all(b"\n")?;
    out.flush()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Subcommand: read
// ---------------------------------------------------------------------------

/// Read a pcap file, decode packets, optionally filter, and output as JSON array.
pub fn cmd_read(
    file: &str,
    filter: Option<&str>,
    limit: usize,
    enrich: &mut Enrichment,
) -> Result<()> {
    let (link_type, raw) = export::read_pcap(Path::new(file))?;
    let stdout = io::stdout();
    let mut out = stdout.lock();

    out.write_all(b"[")?;
    let mut first = true;
    let mut count = 0usize;

    for (i, (timestamp, data)) in raw.into_iter().enumerate() {
        let mut pkt = packet::parse_packet_with_link((i + 1) as u64, &data, link_type);
        pkt.timestamp = timestamp;

        if let Some(f) = filter
            && !matches_display_filter(&pkt, f)
        {
            continue;
        }

        if !first {
            out.write_all(b",")?;
        }
        first = false;

        enrich.enrich_packet(&mut pkt);
        serde_json::to_writer(&mut out, &pkt)?;

        count += 1;
        if limit > 0 && count >= limit {
            break;
        }
    }

    out.write_all(b"]\n")?;
    out.flush()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Subcommand: capture
// ---------------------------------------------------------------------------

/// Capture packets headless, outputting one JSON object per line (JSONL).
pub fn cmd_capture(
    interface: Option<&str>,
    bpf_filter: Option<&str>,
    count: usize,
    display_filter: Option<&str>,
    enrich: &mut Enrichment,
) -> Result<()> {
    let iface = if let Some(i) = interface {
        i.to_string()
    } else {
        let ifaces = capture::list_interfaces()?;
        ifaces
            .first()
            .map(|i| i.name.clone())
            .ok_or_else(|| anyhow::anyhow!("no capture interface found"))?
    };

    let device = pcap::Device::from(iface.as_str());
    let mut cap = pcap::Capture::from_device(device)?
        .promisc(true)
        .timeout(100)
        .open()?;

    let link_type = packet::LinkType::from_dlt(cap.get_datalink().0.cast_unsigned());

    if let Some(f) = bpf_filter {
        cap.filter(f, true)?;
    }

    let stdout = io::stdout();
    let mut out = stdout.lock();
    let mut id = 1u64;
    let mut emitted = 0usize;

    loop {
        match cap.next_packet() {
            Ok(pkt_data) => {
                let mut pkt = packet::parse_packet_with_link(id, pkt_data.data, link_type);
                id += 1;

                if let Some(f) = display_filter
                    && !matches_display_filter(&pkt, f)
                {
                    continue;
                }

                enrich.enrich_packet(&mut pkt);
                serde_json::to_writer(&mut out, &pkt)?;
                out.write_all(b"\n")?;
                out.flush()?;
                emitted += 1;

                if count > 0 && emitted >= count {
                    break;
                }
            }
            Err(pcap::Error::TimeoutExpired) => {}
            Err(e) => bail!("capture error: {e}"),
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Subcommand: flows
// ---------------------------------------------------------------------------

/// Extract flows from a pcap file and output as JSON array.
pub fn cmd_flows(file: &str, compact: bool, enrich: &mut Enrichment) -> Result<()> {
    let (link_type, raw) = export::read_pcap(Path::new(file))?;
    let mut flows: HashMap<FlowKey, FlowInfo> = HashMap::new();

    for (i, (timestamp, data)) in raw.into_iter().enumerate() {
        let mut pkt = packet::parse_packet_with_link((i + 1) as u64, &data, link_type);
        pkt.timestamp = timestamp;

        let key = FlowKey::new(&pkt.src, &pkt.dst);
        let entry = flows.entry(key.clone()).or_insert_with(|| FlowInfo {
            key,
            protocol: pkt.protocol,
            src: pkt.src.clone(),
            dst: pkt.dst.clone(),
            packet_count: 0,
            total_bytes: 0,
            packets_a_to_b: 0,
            bytes_a_to_b: 0,
            packets_b_to_a: 0,
            bytes_b_to_a: 0,
            first_seen: Some(pkt.timestamp),
            last_seen: None,
        });
        entry.packet_count += 1;
        entry.total_bytes += pkt.length as u64;
        entry.last_seen = Some(pkt.timestamp);

        // Track directional counters: src in FlowInfo is the first-seen endpoint.
        if pkt.src == entry.src {
            entry.packets_a_to_b += 1;
            entry.bytes_a_to_b += pkt.length as u64;
        } else {
            entry.packets_b_to_a += 1;
            entry.bytes_b_to_a += pkt.length as u64;
        }
    }

    let mut flow_list: Vec<FlowInfo> = flows.into_values().collect();
    flow_list.sort_by_key(|f| Reverse(f.total_bytes));

    if enrich.is_active() {
        for f in &mut flow_list {
            f.src = enrich.enrich(&f.src);
            f.dst = enrich.enrich(&f.dst);
        }
    }

    write_json(&flow_list, compact)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Subcommand: stats
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct StatsOutput {
    total_packets: usize,
    total_bytes: u64,
    protocols: HashMap<String, u64>,
    top_talkers: Vec<TalkerEntry>,
    top_conversations: Vec<ConversationEntry>,
}

#[derive(Serialize)]
struct TalkerEntry {
    address: String,
    packets: u64,
}

#[derive(Serialize)]
struct ConversationEntry {
    src: String,
    dst: String,
    packets: u64,
    bytes: u64,
}

/// Compute capture statistics from a pcap file and output as JSON.
pub fn cmd_stats(file: &str, compact: bool, enrich: &mut Enrichment) -> Result<()> {
    let (link_type, raw) = export::read_pcap(Path::new(file))?;
    let total_packets = raw.len();
    let mut protocols: HashMap<String, u64> = HashMap::new();
    let mut talkers: HashMap<String, u64> = HashMap::new();
    let mut conversations: HashMap<String, (String, String, u64, u64)> = HashMap::new();
    let mut total_bytes: u64 = 0;

    for (i, (timestamp, data)) in raw.into_iter().enumerate() {
        let mut pkt = packet::parse_packet_with_link((i + 1) as u64, &data, link_type);
        pkt.timestamp = timestamp;

        *protocols.entry(format!("{}", pkt.protocol)).or_insert(0) += 1;
        total_bytes += pkt.length as u64;

        // Extract IP (strip port).
        let src_ip = pkt.src.rsplit_once(':').map_or(&*pkt.src, |(ip, _)| ip);
        let dst_ip = pkt.dst.rsplit_once(':').map_or(&*pkt.dst, |(ip, _)| ip);
        *talkers.entry(src_ip.to_string()).or_insert(0) += 1;
        *talkers.entry(dst_ip.to_string()).or_insert(0) += 1;

        let conv_key = FlowKey::new(&pkt.src, &pkt.dst);
        let conv = conversations
            .entry(format!("{conv_key}"))
            .or_insert_with(|| (pkt.src.clone(), pkt.dst.clone(), 0, 0));
        conv.2 += 1;
        conv.3 += pkt.length as u64;
    }

    let mut top_talkers: Vec<TalkerEntry> = talkers
        .into_iter()
        .map(|(address, packets)| TalkerEntry { address, packets })
        .collect();
    top_talkers.sort_by_key(|t| Reverse(t.packets));
    top_talkers.truncate(10);

    let mut top_conversations: Vec<ConversationEntry> = conversations
        .into_values()
        .map(|(src, dst, packets, bytes)| ConversationEntry {
            src,
            dst,
            packets,
            bytes,
        })
        .collect();
    top_conversations.sort_by_key(|c| Reverse(c.bytes));
    top_conversations.truncate(10);

    if enrich.is_active() {
        for t in &mut top_talkers {
            t.address = enrich.enrich(&t.address);
        }
        for c in &mut top_conversations {
            c.src = enrich.enrich(&c.src);
            c.dst = enrich.enrich(&c.dst);
        }
    }

    let output = StatsOutput {
        total_packets,
        total_bytes,
        protocols,
        top_talkers,
        top_conversations,
    };

    write_json(&output, compact)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Subcommand: stream
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct StreamOutput {
    flow: String,
    packets: usize,
    payload_bytes: usize,
    payload_hex: String,
    payload_ascii: String,
}

/// Follow a TCP stream from a pcap file and output as JSON.
pub fn cmd_stream(
    file: &str,
    flow_str: Option<&str>,
    compact: bool,
    enrich: &mut Enrichment,
) -> Result<()> {
    let (link_type, raw) = export::read_pcap(Path::new(file))?;
    let mut packets: Vec<CapturedPacket> = Vec::new();

    for (i, (timestamp, data)) in raw.into_iter().enumerate() {
        let mut pkt = packet::parse_packet_with_link((i + 1) as u64, &data, link_type);
        pkt.timestamp = timestamp;
        packets.push(pkt);
    }

    // Determine the flow to follow.
    let target_flow = if let Some(f) = flow_str {
        // Parse "src-dst" format.
        let parts: Vec<&str> = f.split('-').collect();
        if parts.len() != 2 {
            bail!("flow format should be 'src:port-dst:port' (e.g. '10.0.0.1:443-10.0.0.2:52100')");
        }
        FlowKey::new(parts[0], parts[1])
    } else {
        // Find the flow with the most TCP packets.
        let mut flow_counts: HashMap<FlowKey, u64> = HashMap::new();
        for pkt in &packets {
            if pkt.protocol == Protocol::Tcp {
                *flow_counts
                    .entry(FlowKey::new(&pkt.src, &pkt.dst))
                    .or_insert(0) += 1;
            }
        }
        flow_counts
            .into_iter()
            .max_by_key(|(_, count)| *count)
            .map(|(key, _)| key)
            .ok_or_else(|| anyhow::anyhow!("no TCP flows found"))?
    };

    // Collect TCP payload for the target flow.
    let mut payload = Vec::new();
    let mut stream_pkt_count = 0usize;

    for pkt in &packets {
        if pkt.protocol == Protocol::Tcp {
            let pkt_flow = FlowKey::new(&pkt.src, &pkt.dst);
            if pkt_flow == target_flow
                && let Some(tcp_payload) = extract_tcp_payload(&pkt.data)
                && !tcp_payload.is_empty()
            {
                payload.extend_from_slice(tcp_payload);
                stream_pkt_count += 1;
            }
        }
    }

    let hex_str: Vec<String> = payload.iter().map(|b| format!("{b:02x}")).collect();
    let ascii_str: String = payload
        .iter()
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                b as char
            } else {
                '.'
            }
        })
        .collect();

    let raw_flow = format!("{target_flow}");
    let flow_display = if enrich.is_active() {
        let parts: Vec<&str> = raw_flow.split('-').collect();
        if parts.len() == 2 {
            format!("{}-{}", enrich.enrich(parts[0]), enrich.enrich(parts[1]))
        } else {
            raw_flow
        }
    } else {
        raw_flow
    };

    let output = StreamOutput {
        flow: flow_display,
        packets: stream_pkt_count,
        payload_bytes: payload.len(),
        payload_hex: hex_str.join(" "),
        payload_ascii: ascii_str,
    };

    write_json(&output, compact)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Subcommand: decode
// ---------------------------------------------------------------------------

/// Decode a single packet from a pcap file and output as pretty JSON.
pub fn cmd_decode(file: &str, id: u64, compact: bool, enrich: &mut Enrichment) -> Result<()> {
    let (link_type, raw) = export::read_pcap(Path::new(file))?;
    #[allow(clippy::cast_possible_truncation)]
    let idx = id as usize;
    if id == 0 || idx > raw.len() {
        bail!("packet ID {id} out of range (1..{})", raw.len());
    }
    let (timestamp, data) = &raw[idx - 1];
    let mut pkt = packet::parse_packet_with_link(id, data, link_type);
    pkt.timestamp = *timestamp;

    enrich.enrich_packet(&mut pkt);
    write_json(&pkt, compact)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Subcommand: interfaces
// ---------------------------------------------------------------------------

/// List available capture interfaces as JSON.
pub fn cmd_interfaces(compact: bool) -> Result<()> {
    let ifaces = capture::list_interfaces()?;
    let entries: Vec<InterfaceEntry> = ifaces
        .into_iter()
        .map(|i| InterfaceEntry {
            name: i.name,
            description: i.description,
            addresses: i.addresses,
        })
        .collect();
    write_json(&entries, compact)
}

#[derive(Serialize)]
struct InterfaceEntry {
    name: String,
    description: String,
    addresses: Vec<String>,
}

// ---------------------------------------------------------------------------
// --json flag on root CLI
// ---------------------------------------------------------------------------

/// Dump a pcap file as a JSON array (for `--read --json`).
pub fn cmd_json_read(file: &str, enrich: &mut Enrichment) -> Result<()> {
    cmd_read(file, None, 0, enrich)
}

/// Live capture with JSON output (for `--json` without `--read`).
pub fn cmd_json_live(
    interface: Option<&str>,
    bpf_filter: Option<&str>,
    count: usize,
    enrich: &mut Enrichment,
) -> Result<()> {
    cmd_capture(interface, bpf_filter, count, None, enrich)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    fn sample_packet() -> CapturedPacket {
        CapturedPacket {
            id: 1,
            timestamp: SystemTime::UNIX_EPOCH,
            protocol: Protocol::Tcp,
            src: "10.0.0.1:443".into(),
            dst: "10.0.0.2:52100".into(),
            length: 100,
            data: vec![0x00, 0xff, 0x42],
            decoded: vec![packet::DecodedField {
                label: "Src Port".into(),
                value: "443".into(),
            }],
            tcp_flags: 0x02, // SYN
            expert: vec![],
        }
    }

    #[test]
    fn packet_serializes_to_json() {
        let pkt = sample_packet();
        let json = serde_json::to_string(&pkt).unwrap();
        assert!(json.contains("\"protocol\":\"Tcp\""));
        assert!(json.contains("\"src\":\"10.0.0.1:443\""));
        assert!(json.contains("\"data\":\"00 ff 42\""));
        assert!(json.contains("\"tcp_flags\":2"));
    }

    #[test]
    fn display_filter_protocol() {
        let pkt = sample_packet();
        assert!(matches_display_filter(&pkt, "tcp"));
        assert!(!matches_display_filter(&pkt, "udp"));
        assert!(matches_display_filter(&pkt, "!udp"));
        assert!(!matches_display_filter(&pkt, "!tcp"));
    }

    #[test]
    fn display_filter_port() {
        let pkt = sample_packet();
        assert!(matches_display_filter(&pkt, "port:443"));
        assert!(matches_display_filter(&pkt, "port:52100"));
        assert!(!matches_display_filter(&pkt, "port:80"));
    }

    #[test]
    fn display_filter_ip() {
        let pkt = sample_packet();
        assert!(matches_display_filter(&pkt, "ip:10.0.0.1"));
        assert!(matches_display_filter(&pkt, "ip:10.0.0"));
        assert!(!matches_display_filter(&pkt, "ip:192.168"));
    }

    #[test]
    fn display_filter_flags() {
        let pkt = sample_packet();
        assert!(matches_display_filter(&pkt, "syn"));
        assert!(!matches_display_filter(&pkt, "rst"));
        assert!(!matches_display_filter(&pkt, "fin"));
    }

    #[test]
    fn display_filter_combined() {
        let pkt = sample_packet();
        assert!(matches_display_filter(&pkt, "tcp port:443 syn"));
        assert!(!matches_display_filter(&pkt, "tcp port:80"));
        assert!(matches_display_filter(&pkt, "!udp !rst"));
    }

    #[test]
    fn display_filter_or() {
        let pkt = sample_packet();
        assert!(matches_display_filter(&pkt, "tcp || udp"));
        assert!(matches_display_filter(&pkt, "udp || tcp"));
        assert!(!matches_display_filter(&pkt, "udp || icmp"));
        assert!(matches_display_filter(&pkt, "udp or tcp"));
    }

    #[test]
    fn display_filter_and_explicit() {
        let pkt = sample_packet();
        assert!(matches_display_filter(&pkt, "tcp && syn"));
        assert!(!matches_display_filter(&pkt, "tcp && rst"));
        assert!(matches_display_filter(&pkt, "tcp and port:443"));
    }

    #[test]
    fn display_filter_len_comparison() {
        let pkt = sample_packet(); // length = 100
        assert!(matches_display_filter(&pkt, "len>50"));
        assert!(!matches_display_filter(&pkt, "len>200"));
        assert!(matches_display_filter(&pkt, "len>=100"));
        assert!(matches_display_filter(&pkt, "len==100"));
        assert!(!matches_display_filter(&pkt, "len<100"));
        assert!(matches_display_filter(&pkt, "len<=100"));
        assert!(matches_display_filter(&pkt, "len!=50"));
    }

    #[test]
    fn display_filter_or_and_combined() {
        let pkt = sample_packet();
        // tcp && syn is true; udp && rst is false — OR should pass.
        assert!(matches_display_filter(&pkt, "udp || tcp syn"));
        assert!(matches_display_filter(&pkt, "tcp port:443 || icmp"));
        assert!(!matches_display_filter(&pkt, "udp || icmp"));
    }

    #[test]
    fn display_filter_ack_psh() {
        let pkt = sample_packet(); // tcp_flags = 0x02 (SYN only)
        assert!(!matches_display_filter(&pkt, "ack"));
        assert!(!matches_display_filter(&pkt, "psh"));
    }

    #[test]
    fn flow_key_display() {
        let key = FlowKey::new("10.0.0.1:443", "10.0.0.2:52100");
        assert_eq!(format!("{key}"), "10.0.0.1:443-10.0.0.2:52100");
    }
}
