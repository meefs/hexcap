mod agent;
mod app;
mod capture;
mod clipboard;
mod config;
mod dns;
mod event_loop;
mod expert;
mod export;
mod geoip;
mod headless;
mod hex;
mod keys;
mod packet;
mod process;
mod tcp_analysis;
mod theme;
mod traceroute;
mod ui;

use std::io;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use clap::Parser;
use crossterm::event::{DisableMouseCapture, EnableMouseCapture};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::prelude::*;

use app::App;
use capture::CaptureHandle;

/// hexcap — TUI packet capture with libpcap + hexyl-style hex dump
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// Network interface to capture on (e.g. en0, eth0)
    #[arg(short, long)]
    interface: Option<String>,

    /// BPF filter expression (e.g. "tcp port 80")
    #[arg(short, long)]
    filter: Option<String>,

    /// Maximum number of packets to keep in the ring buffer
    #[arg(long, default_value_t = 10_000)]
    max_packets: usize,

    /// Filter packets by process name or PID
    #[arg(short, long)]
    process: Option<String>,

    /// Write captured packets to a pcap file on exit or when pressing 'w'
    #[arg(short, long)]
    write: Option<String>,

    /// Read packets from a pcap file instead of live capture
    #[arg(short, long)]
    read: Option<String>,

    /// Path to `GeoLite2-City.mmdb` or `GeoLite2-Country.mmdb` for `GeoIP` lookups
    #[arg(long)]
    geoip: Option<String>,

    /// Output JSON instead of TUI (JSONL for live capture, JSON array for --read)
    #[arg(long)]
    json: bool,

    /// Use compact JSON output (no pretty-printing) in headless/subcommand mode
    #[arg(long)]
    compact: bool,

    /// Enable reverse DNS resolution in headless/subcommand mode
    #[arg(long)]
    dns: bool,

    /// Pipe captured packets as JSONL to a child process (e.g. "uv run agent.py")
    #[arg(long)]
    pipe: Option<String>,

    /// Create a Unix domain socket to stream JSONL packets to external agents
    #[arg(long)]
    socket: Option<String>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(clap::Subcommand)]
enum Command {
    /// Read and decode a pcap file to JSON
    Read {
        /// Path to the pcap file
        file: String,
        /// Display filter expression (e.g. "tcp port:443 !arp")
        #[arg(short, long)]
        filter: Option<String>,
        /// Maximum number of packets to output (0 = all)
        #[arg(short = 'n', long, default_value_t = 0)]
        limit: usize,
    },
    /// Capture packets headless and output as JSONL
    Capture {
        /// Network interface (comma-separated for multiple)
        #[arg(short, long)]
        interface: Option<String>,
        /// BPF filter expression
        #[arg(short, long)]
        filter: Option<String>,
        /// Number of packets to capture (0 = unlimited)
        #[arg(short = 'c', long, default_value_t = 100)]
        count: usize,
        /// Display filter expression
        #[arg(short, long)]
        display_filter: Option<String>,
    },
    /// Extract connection flows from a pcap file
    Flows {
        /// Path to the pcap file
        file: String,
    },
    /// Show capture statistics from a pcap file
    Stats {
        /// Path to the pcap file
        file: String,
    },
    /// Follow a TCP stream from a pcap file
    Stream {
        /// Path to the pcap file
        file: String,
        /// Flow to follow (e.g. "10.0.0.1:443-10.0.0.2:52100")
        #[arg(long)]
        flow: Option<String>,
    },
    /// Decode a single packet from a pcap file
    Decode {
        /// Path to the pcap file
        file: String,
        /// Packet ID (1-based)
        #[arg(long)]
        id: u64,
    },
    /// List available capture interfaces as JSON
    Interfaces,
}

#[allow(clippy::too_many_lines)]
fn main() -> Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(io::stderr)
        .init();

    // ── Subcommand dispatch (headless, JSON output) ────────────────────
    if let Some(cmd) = cli.command {
        let compact = cli.compact;
        let mut enrich = headless::Enrichment::new(cli.geoip.as_deref(), cli.dns);
        return match cmd {
            Command::Read {
                file,
                filter,
                limit,
            } => headless::cmd_read(&file, filter.as_deref(), limit, &mut enrich),
            Command::Capture {
                interface,
                filter,
                count,
                display_filter,
            } => headless::cmd_capture(
                interface.as_deref(),
                filter.as_deref(),
                count,
                display_filter.as_deref(),
                &mut enrich,
            ),
            Command::Flows { file } => headless::cmd_flows(&file, compact, &mut enrich),
            Command::Stats { file } => headless::cmd_stats(&file, compact, &mut enrich),
            Command::Stream { file, flow } => {
                headless::cmd_stream(&file, flow.as_deref(), compact, &mut enrich)
            }
            Command::Decode { file, id } => headless::cmd_decode(&file, id, compact, &mut enrich),
            Command::Interfaces => headless::cmd_interfaces(compact),
        };
    }

    // ── --json flag on root CLI ────────────────────────────────────────
    if cli.json {
        let mut enrich = headless::Enrichment::new(cli.geoip.as_deref(), cli.dns);
        return if let Some(ref path) = cli.read {
            headless::cmd_json_read(path, &mut enrich)
        } else {
            headless::cmd_json_live(
                cli.interface.as_deref(),
                cli.filter.as_deref(),
                cli.max_packets,
                &mut enrich,
            )
        };
    }

    // ── TUI mode (default) ────────────────────────────────────────────

    // Resolve --process flag to a port-based filter.
    let process_filter = if let Some(ref query) = cli.process {
        let info = process::resolve_process(query)?;
        tracing::info!(
            pid = info.pid,
            name = %info.name,
            ports = ?info.ports,
            "filtering by process"
        );
        Some(app::ProcessFilter {
            name: info.name,
            pid: info.pid,
            ports: info.ports,
        })
    } else {
        None
    };

    let app = Arc::new(Mutex::new(App::new(
        cli.max_packets,
        process_filter,
        cli.write.map(std::path::PathBuf::from),
    )));

    // ── Agent pipe / socket setup ──────────────────────────────────────
    let agent_output = app.lock().expect("app mutex poisoned").agent_output.clone();
    let agent_commands = app
        .lock()
        .expect("app mutex poisoned")
        .agent_commands
        .clone();
    let agent_queries = agent::new_queries();
    let stamped_commands = agent::new_stamped_commands();

    let mut agent_pipe = if let Some(ref cmd) = cli.pipe {
        match agent::AgentPipe::spawn(cmd, agent_output.clone(), &agent_commands) {
            Ok(pipe) => {
                if let Ok(mut a) = app.lock() {
                    a.show_agent_pane = true;
                    a.agent_name = Some(cmd.clone());
                    a.set_status(format!("Agent pipe: {cmd}"));
                }
                Some(pipe)
            }
            Err(e) => {
                tracing::warn!("Failed to spawn agent pipe: {e}");
                None
            }
        }
    } else {
        None
    };

    let mut socket_server = if let Some(ref path) = cli.socket {
        match agent::SocketServer::bind(
            path,
            &agent_commands,
            &agent_queries,
            &stamped_commands,
            cli.max_packets,
        ) {
            Ok(srv) => {
                if let Ok(mut a) = app.lock() {
                    a.set_status(format!("Agent socket: {path}"));
                    a.socket_path = Some(path.clone());
                }
                Some(srv)
            }
            Err(e) => {
                tracing::warn!("Failed to bind agent socket: {e}");
                None
            }
        }
    } else {
        None
    };

    // Load GeoIP database if provided, or auto-detect common filenames.
    let geoip_path = cli.geoip.clone().or_else(|| {
        let candidates = [
            "country.mmdb",
            "GeoLite2-Country.mmdb",
            "GeoLite2-City.mmdb",
        ];
        candidates
            .iter()
            .find(|p| std::path::Path::new(p).exists())
            .map(std::string::ToString::to_string)
    });
    let geoip_db = if let Some(ref path) = geoip_path {
        match geoip::GeoDb::open(std::path::Path::new(path)) {
            Ok(db) => {
                if let Ok(mut a) = app.lock() {
                    a.geoip_enabled = true;
                    a.set_status("GeoIP database loaded".into());
                }
                Some(Arc::new(db))
            }
            Err(e) => {
                tracing::warn!("Failed to load GeoIP database: {e}");
                None
            }
        }
    } else {
        None
    };

    // Either read from pcap file or start live capture.
    // Mutex poisoning policy: if any thread panics while holding the App
    // mutex, recovery is not possible — the TUI state is inconsistent.
    // All `.expect("app mutex poisoned")` calls intentionally propagate the panic.
    let (mut capture, capture_group) = if let Some(ref path) = cli.read {
        let (link_type, raw_packets) = export::read_pcap(std::path::Path::new(path))?;
        let mut a = app.lock().expect("app mutex poisoned");
        for (i, (timestamp, data)) in raw_packets.into_iter().enumerate() {
            let mut pkt = packet::parse_packet_with_link((i + 1) as u64, &data, link_type);
            pkt.timestamp = timestamp;
            a.push_packet(pkt);
        }
        a.paused = true; // No live capture, start paused.
        a.interface_name.clone_from(path);
        // Load bookmarks sidecar if present.
        let pcap_path = std::path::Path::new(path);
        let bm_path = export::bookmark_path(pcap_path);
        if bm_path.exists() {
            match export::load_bookmarks(&bm_path) {
                Ok(bm) => {
                    let count = bm.len();
                    a.bookmarks = bm;
                    if count > 0 {
                        a.set_status(format!("Loaded {count} bookmarks"));
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to load bookmarks: {e}");
                }
            }
        }
        // Load annotations sidecar if present.
        let ann_path = export::annotation_path(pcap_path);
        if ann_path.exists() {
            match export::load_annotations(&ann_path) {
                Ok(ann) => {
                    let count = ann.len();
                    a.annotations = ann;
                    if count > 0 {
                        let prev = a.status_message.as_ref().map(|(m, _)| m.clone());
                        let msg = if let Some(prev_msg) = prev {
                            format!("{prev_msg}, {count} annotations")
                        } else {
                            format!("Loaded {count} annotations")
                        };
                        a.set_status(msg);
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to load annotations: {e}");
                }
            }
        }
        drop(a);
        (None, None)
    } else if let Some(ref iface) = cli.interface {
        if iface.contains(',') {
            // Multi-interface capture.
            let names: Vec<String> = iface.split(',').map(|s| s.trim().to_string()).collect();
            let counter = Arc::new(std::sync::atomic::AtomicU64::new(0));
            let group = capture::CaptureGroup::start(
                &names,
                cli.filter.as_deref(),
                Arc::clone(&app),
                counter,
            )?;
            (None, Some(group))
        } else {
            let h = CaptureHandle::start(
                Some(iface.as_str()),
                cli.filter.as_deref(),
                Arc::clone(&app),
            )?;
            (Some(h), None)
        }
    } else {
        let h = CaptureHandle::start(None, cli.filter.as_deref(), Arc::clone(&app))?;
        (Some(h), None)
    };

    let bpf_filter = cli.filter.clone();

    enable_raw_mode()?;
    execute!(io::stdout(), EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)?;

    let result = event_loop::run_loop(
        &mut terminal,
        &app,
        &mut capture,
        bpf_filter.as_deref(),
        geoip_db.as_ref(),
        &mut agent_pipe,
        &mut socket_server,
        &agent_output,
        &agent_commands,
        &agent_queries,
        &stamped_commands,
    );

    disable_raw_mode()?;
    execute!(io::stdout(), LeaveAlternateScreen, DisableMouseCapture)?;
    drop(capture);
    drop(capture_group);

    result
}
