use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::path::PathBuf;
use std::time::Instant;

use crate::config;
use crate::expert::Severity;
use crate::packet::{
    CapturedPacket, FlowKey, Protocol, extract_tcp_seq_payload, matches_display_filter,
};
use crate::process::ProcessInfo;
use crate::tcp_analysis::TcpAnalyser;
use crate::theme::{self, Theme};

/// How timestamps are displayed in the packet list.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TimeFormat {
    /// Absolute wall-clock time (HH:MM:SS.mmm).
    #[default]
    Absolute,
    /// Seconds since first packet in the capture.
    Relative,
    /// Seconds since the previous displayed packet.
    Delta,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    List,
    Detail,
    Flows,
    Stream,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum InputMode {
    #[default]
    Normal,
    Search,
    /// Go-to-packet-by-number input.
    GoToPacket,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ProtoFilter {
    #[default]
    All,
    Tcp,
    Udp,
    Icmp,
    Dns,
    Arp,
}

impl ProtoFilter {
    pub fn next(self) -> Self {
        match self {
            Self::All => Self::Tcp,
            Self::Tcp => Self::Udp,
            Self::Udp => Self::Icmp,
            Self::Icmp => Self::Dns,
            Self::Dns => Self::Arp,
            Self::Arp => Self::All,
        }
    }

    pub fn matches(self, proto: Protocol) -> bool {
        match self {
            Self::All => true,
            Self::Tcp => proto == Protocol::Tcp,
            Self::Udp => proto == Protocol::Udp,
            Self::Icmp => proto == Protocol::Icmp,
            Self::Dns => proto == Protocol::Dns,
            Self::Arp => proto == Protocol::Arp,
        }
    }
}

impl fmt::Display for ProtoFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::All => write!(f, "All"),
            Self::Tcp => write!(f, "TCP"),
            Self::Udp => write!(f, "UDP"),
            Self::Icmp => write!(f, "ICMP"),
            Self::Dns => write!(f, "DNS"),
            Self::Arp => write!(f, "ARP"),
        }
    }
}

#[allow(clippy::struct_excessive_bools)]
pub struct App {
    pub packets: VecDeque<CapturedPacket>,
    pub max_packets: usize,
    pub selected: usize,
    pub view: View,
    pub paused: bool,
    pub hex_scroll: u16,
    pub theme_index: usize,
    pub themes: Vec<Theme>,

    // -- Filtering --
    pub input_mode: InputMode,
    pub search_query: String,
    pub proto_filter: ProtoFilter,
    /// Display filter expression (e.g., "tcp port:443 !dns").
    pub display_filter: String,
    /// Whether the display filter input bar is active.
    pub display_filter_editing: bool,
    /// Buffer for editing the display filter.
    pub display_filter_buf: String,
    pub follow: bool,
    /// Follow mode scroll interval: 1 = every packet, 5 = every 5th, etc.
    pub follow_interval: u64,
    /// Counter for follow interval throttling.
    pub follow_counter: u64,

    // -- Stats --
    pub total_bytes: u64,
    /// Bytes received in the current 1-second window.
    pub current_window_bytes: u64,
    /// Bandwidth history (bytes per second), most recent last. Fixed length.
    pub bandwidth_history: VecDeque<u64>,
    /// When the current 1-second window started.
    pub window_start: Instant,

    // -- Process filter --
    pub process_filter: Option<ProcessFilter>,
    pub process_picker: Option<ProcessPicker>,

    // -- Export --
    pub export_path: Option<PathBuf>,

    // -- Status message (auto-clears after a few seconds) --
    pub status_message: Option<(String, Instant)>,

    // -- Flow tracking --
    pub flows: Vec<FlowInfo>,
    pub flow_map: HashMap<FlowKey, usize>,
    pub flow_selected: usize,
    pub flow_filter: Option<FlowKey>,

    // -- Interface --
    pub interface_name: String,
    pub interface_picker: Option<InterfacePicker>,
    /// Set to Some(name) when user picks a new interface; main loop consumes it.
    pub pending_interface: Option<String>,

    // -- Bookmarks --
    /// Set of bookmarked packet IDs.
    pub bookmarks: HashSet<u64>,

    // -- Annotations --
    /// User notes per packet ID.
    pub annotations: HashMap<u64, String>,
    /// When set, we're editing an annotation for this packet ID.
    pub annotating: Option<u64>,
    /// Text buffer for annotation input.
    pub annotation_buf: String,

    // -- Capture timing --
    /// When capture started (or packets were loaded).
    pub capture_start: Instant,
    /// Rolling packet count for packets-per-second calculation.
    pub pps_counter: u64,
    /// Last computed packets-per-second value.
    pub pps: u64,

    // -- DNS resolution cache --
    pub dns_cache: HashMap<std::net::IpAddr, String>,
    pub dns_enabled: bool,

    // -- GeoIP cache --
    pub geoip_cache: HashMap<std::net::IpAddr, String>,
    pub geoip_enabled: bool,

    // -- TCP stream follow --
    /// Reassembled TCP stream payload for the current flow.
    pub stream_data: Vec<u8>,
    pub stream_scroll: u16,

    // -- Column widths --
    /// Index of the column currently being resized (0-6).
    pub resize_column: usize,
    /// Extra width adjustments per column.
    pub column_widths: [i16; 7],

    // -- Help overlay --
    pub show_help: bool,

    // -- Stats summary overlay --
    pub show_stats_summary: bool,

    // -- Packet diff --
    /// First packet ID marked for diff comparison.
    pub diff_mark: Option<u64>,
    /// When set, show diff overlay comparing these two packet indices.
    pub diff_pair: Option<(usize, usize)>,

    // -- TCP analysis --
    pub tcp_analyser: TcpAnalyser,

    // -- Expert info overlay --
    pub show_expert: bool,

    // -- Protocol hierarchy overlay --
    pub show_proto_hierarchy: bool,

    // -- Flow graph overlay --
    pub show_flow_graph: bool,
    /// Selected packet index within the flow graph overlay.
    pub flow_graph_selected: usize,

    // -- Traceroute --
    pub traceroute_state: Option<crate::traceroute::TracerouteState>,
    pub traceroute_input: String,
    pub traceroute_input_active: bool,
    pub pending_traceroute_spawn: Option<String>,

    // -- Time display --
    pub time_format: TimeFormat,
    /// Packet ID set as time reference (t=0 point).
    pub time_reference: Option<u64>,

    // -- Agent pane --
    pub show_agent_pane: bool,
    pub agent_output: crate::agent::AgentOutput,
    /// Scroll offset within the agent pane.
    pub agent_scroll: usize,
    /// Main/agent pane split ratio (percentage for main pane, 20..80).
    pub agent_pane_ratio: u16,
    /// Whether the user is currently dragging the agent pane border.
    pub agent_pane_dragging: bool,
    /// Agent picker overlay.
    pub agent_picker: Option<AgentPicker>,
    /// The command that was used to spawn the current agent (for display).
    pub agent_name: Option<String>,
    /// Tmux pane ID of the agent split (for send-keys chat delivery).
    pub agent_tmux_pane: Option<String>,
    /// Pending commands from agent → TUI.
    pub agent_commands: crate::agent::AgentCommands,
    /// Set to `Some(preset_index)` when user picks an agent; main loop consumes it.
    pub pending_agent_spawn: Option<usize>,
    /// Socket path (when active) for display in status/footer.
    pub socket_path: Option<String>,
    /// Chat messages displayed in the agent pane.
    pub chat_messages: Vec<ChatMessage>,
    /// Input buffer for the chat input bar.
    pub chat_input: String,
    /// Whether the chat input bar is focused (keypresses go to input).
    pub chat_input_active: bool,
    /// Pending outbound chat message; main loop consumes and sends via socket.
    pub pending_chat_send: Option<String>,

    // -- Go to packet --
    pub goto_buf: String,
}

/// A single message in the agent chat pane.
#[derive(Debug, Clone)]
pub struct ChatMessage {
    /// Who sent the message: "you", agent name, or "system".
    pub sender: String,
    /// Message text (may be multi-line).
    pub text: String,
}

/// Aggregated info for a single bidirectional flow.
#[derive(Debug, Clone, serde::Serialize)]
pub struct FlowInfo {
    pub key: FlowKey,
    pub protocol: Protocol,
    pub src: String,
    pub dst: String,
    pub packet_count: u64,
    pub total_bytes: u64,
    /// Packets from src → dst.
    pub packets_a_to_b: u64,
    /// Bytes from src → dst.
    pub bytes_a_to_b: u64,
    /// Packets from dst → src.
    pub packets_b_to_a: u64,
    /// Bytes from dst → src.
    pub bytes_b_to_a: u64,
    /// Timestamp of the first packet in this flow (epoch secs).
    #[serde(serialize_with = "crate::packet::serialize_opt_timestamp")]
    pub first_seen: Option<std::time::SystemTime>,
    /// Timestamp of the last packet in this flow (epoch secs).
    #[serde(serialize_with = "crate::packet::serialize_opt_timestamp")]
    pub last_seen: Option<std::time::SystemTime>,
}

/// Active process filter state.
#[derive(Debug, Clone)]
pub struct ProcessFilter {
    pub name: String,
    pub pid: u32,
    pub ports: HashSet<u16>,
}

/// Interactive process picker overlay.
#[derive(Debug, Clone)]
pub struct ProcessPicker {
    pub processes: Vec<ProcessInfo>,
    pub filtered: Vec<usize>,
    pub selected: usize,
    pub query: String,
}

/// Interactive interface picker overlay.
#[derive(Debug, Clone)]
pub struct InterfacePicker {
    pub interfaces: Vec<crate::capture::InterfaceInfo>,
    pub selected: usize,
}

/// Interactive agent picker overlay.
#[derive(Debug, Clone)]
pub struct AgentPicker {
    pub selected: usize,
}

impl App {
    pub fn new(
        max_packets: usize,
        process_filter: Option<ProcessFilter>,
        export_path: Option<PathBuf>,
    ) -> Self {
        // Load persisted theme preference first, then fall back to Ghostty detection.
        let prefs = config::load_preferences();
        let theme_index = if prefs.theme != theme::THEMES[0].name || config::has_preferences_file()
        {
            theme::theme_index_by_name(&prefs.theme)
        } else {
            theme::detect_initial_theme()
        };

        // Build mutable theme list; patch Default themes with actual terminal bg.
        let mut themes: Vec<Theme> = theme::THEMES.to_vec();
        if let Some((r, g, b)) = theme::query_terminal_bg() {
            theme::patch_default_themes(&mut themes, r, g, b);
        }

        Self {
            packets: VecDeque::new(),
            max_packets,
            selected: 0,
            view: View::List,
            paused: false,
            hex_scroll: 0,
            theme_index,
            themes,
            input_mode: InputMode::Normal,
            search_query: String::new(),
            proto_filter: ProtoFilter::All,
            display_filter: String::new(),
            display_filter_editing: false,
            display_filter_buf: String::new(),
            follow: true,
            follow_interval: 1,
            follow_counter: 0,
            total_bytes: 0,
            current_window_bytes: 0,
            bandwidth_history: VecDeque::new(),
            window_start: Instant::now(),
            process_filter,
            process_picker: None,
            export_path,
            status_message: None,
            flows: Vec::new(),
            flow_map: HashMap::new(),
            flow_selected: 0,
            flow_filter: None,
            interface_name: String::new(),
            interface_picker: None,
            pending_interface: None,
            bookmarks: HashSet::new(),
            annotations: HashMap::new(),
            annotating: None,
            annotation_buf: String::new(),
            capture_start: Instant::now(),
            pps_counter: 0,
            pps: 0,
            dns_cache: HashMap::new(),
            dns_enabled: false,
            geoip_cache: HashMap::new(),
            geoip_enabled: false,
            stream_data: Vec::new(),
            stream_scroll: 0,
            resize_column: 0,
            column_widths: [0; 7],
            show_help: false,
            show_stats_summary: false,
            diff_mark: None,
            diff_pair: None,
            tcp_analyser: TcpAnalyser::new(),
            show_expert: false,
            show_proto_hierarchy: false,
            show_flow_graph: false,
            flow_graph_selected: 0,
            traceroute_state: None,
            traceroute_input: String::new(),
            traceroute_input_active: false,
            pending_traceroute_spawn: None,
            time_format: TimeFormat::Absolute,
            time_reference: None,
            show_agent_pane: false,
            agent_output: crate::agent::new_output(),
            agent_scroll: 0,
            agent_pane_ratio: 75,
            agent_pane_dragging: false,
            agent_picker: None,
            agent_name: None,
            agent_tmux_pane: None,
            agent_commands: crate::agent::new_commands(),
            pending_agent_spawn: None,
            socket_path: None,
            chat_messages: Vec::new(),
            chat_input: String::new(),
            chat_input_active: false,
            pending_chat_send: None,
            goto_buf: String::new(),
        }
    }

    // -- Theme ---------------------------------------------------------------

    #[must_use]
    pub fn theme(&self) -> &Theme {
        &self.themes[self.theme_index]
    }

    pub fn next_theme(&mut self) {
        self.theme_index = (self.theme_index + 1) % self.themes.len();
        self.persist_preferences();
    }

    /// Cycle time display format: Absolute → Relative → Delta → Absolute.
    pub fn cycle_time_format(&mut self) {
        self.time_format = match self.time_format {
            TimeFormat::Absolute => {
                self.set_status("Time: relative (since first packet)".into());
                TimeFormat::Relative
            }
            TimeFormat::Relative => {
                self.set_status("Time: delta (since previous packet)".into());
                TimeFormat::Delta
            }
            TimeFormat::Delta => {
                self.set_status("Time: absolute".into());
                TimeFormat::Absolute
            }
        };
    }

    /// Toggle time reference on current packet.
    pub fn toggle_time_reference(&mut self) {
        if let Some(pkt) = self.selected_packet() {
            let id = pkt.id;
            if self.time_reference == Some(id) {
                self.time_reference = None;
                self.set_status("Time reference cleared".into());
            } else {
                self.time_reference = Some(id);
                self.set_status(format!("Time reference set to #{id}"));
            }
        }
    }

    fn persist_preferences(&self) {
        let prefs = config::Preferences {
            theme: self.theme().name.to_string(),
        };
        let _ = config::save_preferences(&prefs);
    }

    // -- Filtering -----------------------------------------------------------

    /// Get the filtered view indices into `self.packets`.
    pub fn filtered_indices(&self) -> Vec<usize> {
        self.packets
            .iter()
            .enumerate()
            .filter(|(_, p)| self.matches_filters(p))
            .map(|(i, _)| i)
            .collect()
    }

    fn matches_filters(&self, pkt: &CapturedPacket) -> bool {
        // Process port filter.
        if let Some(ref pf) = self.process_filter
            && !pf.ports.is_empty()
            && !pkt.matches_ports(&pf.ports)
        {
            return false;
        }
        if !self.proto_filter.matches(pkt.protocol) {
            return false;
        }
        if !self.search_query.is_empty() {
            let q = self.search_query.to_ascii_lowercase();
            // First try matching against metadata (protocol, addresses, length).
            let haystack = format!("{} {} {} {}", pkt.protocol, pkt.src, pkt.dst, pkt.length)
                .to_ascii_lowercase();
            if !haystack.contains(&q) {
                // Fall back to payload search: try ASCII substring in raw bytes,
                // then hex pattern (e.g. "ff d8" or "ffd8").
                if !payload_contains_ascii(&pkt.data, &q) && !payload_contains_hex(&pkt.data, &q) {
                    return false;
                }
            }
        }
        // Flow filter.
        if let Some(ref fk) = self.flow_filter {
            let pkt_flow = FlowKey::new(&pkt.src, &pkt.dst);
            if &pkt_flow != fk {
                return false;
            }
        }
        // Display filter.
        if !self.display_filter.is_empty() && !matches_display_filter(pkt, &self.display_filter) {
            return false;
        }
        true
    }

    pub fn next_proto_filter(&mut self) {
        self.proto_filter = self.proto_filter.next();
        self.clamp_selected();
    }

    pub fn start_search(&mut self) {
        self.input_mode = InputMode::Search;
    }

    pub fn cancel_search(&mut self) {
        self.input_mode = InputMode::Normal;
        self.search_query.clear();
    }

    pub fn confirm_search(&mut self) {
        self.input_mode = InputMode::Normal;
        self.clamp_selected();
    }

    // -- Go to packet --------------------------------------------------------

    pub fn start_goto(&mut self) {
        self.input_mode = InputMode::GoToPacket;
        self.goto_buf.clear();
    }

    pub fn goto_push(&mut self, ch: char) {
        if ch.is_ascii_digit() {
            self.goto_buf.push(ch);
        }
    }

    pub fn goto_pop(&mut self) {
        self.goto_buf.pop();
    }

    pub fn confirm_goto(&mut self) {
        self.input_mode = InputMode::Normal;
        if let Ok(target_id) = self.goto_buf.parse::<u64>() {
            let filtered = self.filtered_indices();
            // Find the packet with this ID in the filtered view.
            if let Some(&idx) = filtered
                .iter()
                .find(|&&i| self.packets.get(i).is_some_and(|p| p.id == target_id))
            {
                self.selected = idx;
                self.follow = false;
            } else {
                self.set_status(format!("Packet #{target_id} not found"));
            }
        }
        self.goto_buf.clear();
    }

    pub fn cancel_goto(&mut self) {
        self.input_mode = InputMode::Normal;
        self.goto_buf.clear();
    }

    // -- Traceroute Controls --------------------------------------------------

    pub fn start_traceroute_input(&mut self, default_target: Option<String>) {
        self.traceroute_input_active = true;
        self.traceroute_input = default_target.unwrap_or_default();
    }

    pub fn cancel_traceroute_input(&mut self) {
        self.traceroute_input_active = false;
        self.traceroute_input.clear();
    }

    pub fn confirm_traceroute_input(&mut self) {
        self.traceroute_input_active = false;
        let target = self.traceroute_input.trim().to_string();
        self.traceroute_input.clear();
        if !target.is_empty() {
            self.traceroute_state = Some(crate::traceroute::TracerouteState::new(target.clone()));
            self.pending_traceroute_spawn = Some(target);
        }
    }

    pub fn close_traceroute(&mut self) {
        self.traceroute_state = None;
    }

    pub fn search_push(&mut self, ch: char) {
        self.search_query.push(ch);
        self.clamp_selected();
    }

    pub fn search_pop(&mut self) {
        self.search_query.pop();
        self.clamp_selected();
    }

    fn clamp_selected(&mut self) {
        let filtered = self.filtered_indices();
        if filtered.is_empty() {
            self.selected = 0;
        } else if !filtered.contains(&self.selected) {
            self.selected = *filtered.last().unwrap_or(&0);
        }
    }

    // -- Follow mode ---------------------------------------------------------

    /// Cycle follow speed: off → 1x → 5x → 10x → 25x → off.
    pub fn cycle_follow_speed(&mut self) {
        if self.follow {
            self.follow_interval = match self.follow_interval {
                1 => 5,
                5 => 10,
                10 => 25,
                _ => {
                    self.follow = false;
                    self.set_status("Follow: off".into());
                    return;
                }
            };
        } else {
            self.follow = true;
            self.follow_interval = 1;
        }
        self.follow_counter = 0;
        let label = if self.follow_interval == 1 {
            "Follow: every packet".into()
        } else {
            format!("Follow: every {}th packet", self.follow_interval)
        };
        self.set_status(label);
    }

    // -- Bandwidth tracking ---------------------------------------------------

    /// Maximum number of 1-second samples to keep for the sparkline.
    const BANDWIDTH_HISTORY_LEN: usize = 30;

    /// Call periodically (~every tick) to rotate bandwidth windows and compute PPS.
    pub fn tick_bandwidth(&mut self) {
        if self.window_start.elapsed().as_secs() >= 1 {
            self.bandwidth_history.push_back(self.current_window_bytes);
            while self.bandwidth_history.len() > Self::BANDWIDTH_HISTORY_LEN {
                self.bandwidth_history.pop_front();
            }
            self.current_window_bytes = 0;
            self.pps = self.pps_counter;
            self.pps_counter = 0;
            self.window_start = Instant::now();
        }
    }

    // -- Packets -------------------------------------------------------------

    pub fn push_packet(&mut self, mut pkt: CapturedPacket) {
        if self.paused {
            return;
        }
        self.total_bytes += pkt.length as u64;
        self.current_window_bytes += pkt.length as u64;
        self.pps_counter += 1;

        // Run TCP sequence analysis.
        let expert_items = self.tcp_analyser.analyse(&pkt);
        pkt.expert = expert_items;

        // Update flow tracking.
        let flow = FlowKey::new(&pkt.src, &pkt.dst);
        let flow_idx = if let Some(&idx) = self.flow_map.get(&flow) {
            idx
        } else {
            let idx = self.flows.len();
            self.flows.push(FlowInfo {
                key: flow.clone(),
                protocol: pkt.protocol,
                src: pkt.src.clone(),
                dst: pkt.dst.clone(),
                packet_count: 0,
                total_bytes: 0,
                packets_a_to_b: 0,
                bytes_a_to_b: 0,
                packets_b_to_a: 0,
                bytes_b_to_a: 0,
                first_seen: None,
                last_seen: None,
            });
            self.flow_map.insert(flow.clone(), idx);
            idx
        };
        let fi = &mut self.flows[flow_idx];
        fi.packet_count += 1;
        fi.total_bytes += pkt.length as u64;
        fi.last_seen = Some(pkt.timestamp);
        if fi.first_seen.is_none() {
            fi.first_seen = Some(pkt.timestamp);
        }
        // Determine direction: does the packet's src match the flow's stored src?
        // The flow key is normalized (sorted), so flow.0 == fi.src side.
        let is_a_to_b = pkt.src == fi.src || (pkt.src != fi.dst && pkt.src <= pkt.dst);
        if is_a_to_b {
            fi.packets_a_to_b += 1;
            fi.bytes_a_to_b += pkt.length as u64;
        } else {
            fi.packets_b_to_a += 1;
            fi.bytes_b_to_a += pkt.length as u64;
        }

        self.packets.push_back(pkt);
        while self.packets.len() > self.max_packets {
            self.packets.pop_front();
            if self.selected > 0 {
                self.selected -= 1;
            }
        }
        if self.follow {
            self.follow_counter += 1;
            if self.follow_counter >= self.follow_interval {
                self.follow_counter = 0;
                let filtered = self.filtered_indices();
                if let Some(&last) = filtered.last() {
                    self.selected = last;
                }
            }
        }
    }

    // -- Agent pane scrolling ------------------------------------------------

    /// Returns the total scrollable line count for the agent pane, accounting
    /// for which mode is active (chat messages vs pipe output).
    pub fn agent_pane_line_count(&self) -> usize {
        if !self.chat_messages.is_empty() || self.chat_input_active {
            // Count rendered lines from chat messages (one line per text line,
            // plus a header "sender: " prefix line per message).
            self.chat_messages
                .iter()
                .map(|m| m.text.lines().count().max(1))
                .sum()
        } else {
            self.agent_output.lock().map_or(0, |o| o.len())
        }
    }

    /// Scroll the agent pane toward the top (older content).
    pub fn agent_scroll_up(&mut self) {
        let total = self.agent_pane_line_count();
        if self.agent_scroll < total {
            self.agent_scroll += 1;
        }
    }

    /// Scroll the agent pane toward the bottom (newer content).
    pub fn agent_scroll_down(&mut self) {
        self.agent_scroll = self.agent_scroll.saturating_sub(1);
    }

    // -- Navigation ----------------------------------------------------------

    pub fn next(&mut self) {
        self.follow = false;
        let filtered = self.filtered_indices();
        if let Some(pos) = filtered.iter().position(|&i| i == self.selected) {
            if pos + 1 < filtered.len() {
                self.selected = filtered[pos + 1];
            }
        } else if let Some(&first) = filtered.first() {
            self.selected = first;
        }
    }

    pub fn previous(&mut self) {
        self.follow = false;
        let filtered = self.filtered_indices();
        if let Some(pos) = filtered.iter().position(|&i| i == self.selected) {
            if pos > 0 {
                self.selected = filtered[pos - 1];
            }
        } else if let Some(&first) = filtered.first() {
            self.selected = first;
        }
    }

    pub fn first(&mut self) {
        self.follow = false;
        let filtered = self.filtered_indices();
        if let Some(&f) = filtered.first() {
            self.selected = f;
        }
    }

    pub fn last(&mut self) {
        self.follow = false;
        let filtered = self.filtered_indices();
        if let Some(&l) = filtered.last() {
            self.selected = l;
        }
    }

    const PAGE_SIZE: usize = 20;

    pub fn page_down(&mut self) {
        self.follow = false;
        let filtered = self.filtered_indices();
        if let Some(pos) = filtered.iter().position(|&i| i == self.selected) {
            let target = (pos + Self::PAGE_SIZE).min(filtered.len().saturating_sub(1));
            self.selected = filtered[target];
        }
    }

    pub fn page_up(&mut self) {
        self.follow = false;
        let filtered = self.filtered_indices();
        if let Some(pos) = filtered.iter().position(|&i| i == self.selected) {
            let target = pos.saturating_sub(Self::PAGE_SIZE);
            self.selected = filtered[target];
        }
    }

    pub fn open_detail(&mut self) {
        if self.selected_packet().is_some() {
            self.view = View::Detail;
            self.hex_scroll = 0;
            self.paused = true;
        }
    }

    pub fn close_detail(&mut self) {
        self.view = View::List;
    }

    pub fn toggle_pause(&mut self) {
        self.paused = !self.paused;
    }

    pub fn clear(&mut self) {
        self.packets.clear();
        self.selected = 0;
        self.total_bytes = 0;
        self.flows.clear();
        self.flow_map.clear();
        self.flow_selected = 0;
        self.flow_filter = None;
        self.tcp_analyser = TcpAnalyser::new();
    }

    // -- Flow view -----------------------------------------------------------

    pub fn open_flows(&mut self) {
        self.view = View::Flows;
        self.flow_selected = 0;
    }

    /// Return indices into `self.packets` for the currently selected flow.
    pub fn flow_graph_packet_indices(&self) -> Vec<usize> {
        let Some(flow) = self.flows.get(self.flow_selected) else {
            return vec![];
        };
        let flow_key = &flow.key;
        self.packets
            .iter()
            .enumerate()
            .filter(|(_, p)| crate::packet::FlowKey::new(&p.src, &p.dst) == *flow_key)
            .map(|(i, _)| i)
            .collect()
    }

    pub fn close_flows(&mut self) {
        self.view = View::List;
    }

    pub fn flow_next(&mut self) {
        if !self.flows.is_empty() && self.flow_selected + 1 < self.flows.len() {
            self.flow_selected += 1;
        }
    }

    pub fn flow_prev(&mut self) {
        if self.flow_selected > 0 {
            self.flow_selected -= 1;
        }
    }

    /// Apply a flow filter and return to the packet list.
    pub fn flow_select(&mut self) {
        if let Some(flow) = self.flows.get(self.flow_selected) {
            self.flow_filter = Some(flow.key.clone());
            self.view = View::List;
            self.clamp_selected();
        }
    }

    pub fn clear_flow_filter(&mut self) {
        self.flow_filter = None;
        self.clamp_selected();
    }

    // -- TCP stream follow ---------------------------------------------------

    /// Open the TCP stream view for the currently selected packet's flow.
    #[allow(clippy::cast_possible_truncation)] // TCP segment lengths bounded by MTU
    pub fn open_stream(&mut self) {
        let Some(pkt) = self.selected_packet() else {
            return;
        };
        if pkt.protocol != Protocol::Tcp {
            self.set_status("Follow stream only works for TCP packets".into());
            return;
        }
        let flow = FlowKey::new(&pkt.src, &pkt.dst);

        // Reassemble: collect TCP segments with sequence numbers, sort by seq,
        // and deduplicate overlapping bytes for proper stream reconstruction.
        let mut segments: Vec<(u32, Vec<u8>)> = Vec::new();
        for p in &self.packets {
            if p.protocol != Protocol::Tcp {
                continue;
            }
            let pkt_flow = FlowKey::new(&p.src, &p.dst);
            if pkt_flow != flow {
                continue;
            }
            if let Some((seq, tcp_payload)) = extract_tcp_seq_payload(&p.data)
                && !tcp_payload.is_empty()
            {
                segments.push((seq, tcp_payload.to_vec()));
            }
        }

        // Sort segments by sequence number.
        segments.sort_by_key(|(seq, _)| *seq);

        // Merge segments, skipping overlaps and retransmissions.
        let mut payload = Vec::new();
        let mut next_seq: Option<u32> = None;
        for (seq, data) in &segments {
            match next_seq {
                None => {
                    // First segment — accept fully.
                    payload.extend_from_slice(data);
                    next_seq = Some(seq.wrapping_add(data.len() as u32));
                }
                Some(expected) => {
                    // Check if this segment starts at or after expected.
                    let diff = seq.wrapping_sub(expected);
                    if diff == 0 {
                        // Exactly in order.
                        payload.extend_from_slice(data);
                        next_seq = Some(seq.wrapping_add(data.len() as u32));
                    } else if diff < 0x8000_0000 {
                        // Gap (missing data) — accept with gap.
                        payload.extend_from_slice(data);
                        next_seq = Some(seq.wrapping_add(data.len() as u32));
                    } else {
                        // Overlap or retransmission (seq < expected).
                        let overlap = expected.wrapping_sub(*seq) as usize;
                        if overlap < data.len() {
                            // Partial new data after the overlap.
                            payload.extend_from_slice(&data[overlap..]);
                            next_seq = Some(seq.wrapping_add(data.len() as u32));
                        }
                        // Else: fully retransmitted segment — skip.
                    }
                }
            }
        }

        self.stream_data = payload;
        self.stream_scroll = 0;
        self.view = View::Stream;
    }

    pub fn close_stream(&mut self) {
        self.view = View::Detail;
    }

    pub fn stream_scroll_down(&mut self) {
        self.stream_scroll = self.stream_scroll.saturating_add(1);
    }

    pub fn stream_scroll_up(&mut self) {
        self.stream_scroll = self.stream_scroll.saturating_sub(1);
    }

    // -- Column resizing -----------------------------------------------------

    pub fn next_resize_column(&mut self) {
        self.resize_column = (self.resize_column + 1) % 7;
    }

    pub fn widen_column(&mut self) {
        self.column_widths[self.resize_column] =
            self.column_widths[self.resize_column].saturating_add(2);
    }

    pub fn narrow_column(&mut self) {
        self.column_widths[self.resize_column] =
            self.column_widths[self.resize_column].saturating_sub(2);
    }

    // -- Interface picker ----------------------------------------------------

    pub fn open_interface_picker(&mut self, interfaces: Vec<crate::capture::InterfaceInfo>) {
        self.interface_picker = Some(InterfacePicker {
            interfaces,
            selected: 0,
        });
    }

    pub fn close_interface_picker(&mut self) {
        self.interface_picker = None;
    }

    pub fn iface_picker_next(&mut self) {
        if let Some(ref mut picker) = self.interface_picker
            && picker.selected + 1 < picker.interfaces.len()
        {
            picker.selected += 1;
        }
    }

    pub fn iface_picker_prev(&mut self) {
        if let Some(ref mut picker) = self.interface_picker
            && picker.selected > 0
        {
            picker.selected -= 1;
        }
    }

    pub fn iface_picker_select(&mut self) {
        let name = {
            let Some(picker) = &self.interface_picker else {
                return;
            };
            let Some(iface) = picker.interfaces.get(picker.selected) else {
                return;
            };
            iface.name.clone()
        };
        self.pending_interface = Some(name);
        self.interface_picker = None;
    }

    // -- Agent picker --------------------------------------------------------

    pub fn open_agent_picker(&mut self) {
        self.agent_picker = Some(AgentPicker { selected: 0 });
    }

    pub fn close_agent_picker(&mut self) {
        self.agent_picker = None;
    }

    pub fn agent_picker_next(&mut self) {
        if let Some(picker) = &mut self.agent_picker
            && picker.selected + 1 < crate::agent::AGENT_PRESETS.len()
        {
            picker.selected += 1;
        }
    }

    pub fn agent_picker_prev(&mut self) {
        if let Some(picker) = &mut self.agent_picker
            && picker.selected > 0
        {
            picker.selected -= 1;
        }
    }

    /// Select the current agent preset. Sets `pending_agent_spawn` for the main loop.
    pub fn agent_picker_select(&mut self) {
        let Some(idx) = self.agent_picker.as_ref().map(|p| p.selected) else {
            return;
        };
        self.agent_picker = None;
        self.pending_agent_spawn = Some(idx);
    }

    // -- Bookmarks -----------------------------------------------------------

    /// Toggle bookmark on the currently selected packet.
    pub fn toggle_bookmark(&mut self) {
        if let Some(pkt) = self.selected_packet() {
            let id = pkt.id;
            if !self.bookmarks.remove(&id) {
                self.bookmarks.insert(id);
            }
        }
    }

    /// Jump to the next bookmarked packet (forward from current selection).
    pub fn jump_next_bookmark(&mut self) {
        let filtered = self.filtered_indices();
        if let Some(cur_pos) = filtered.iter().position(|&i| i == self.selected) {
            // Search forward from current position.
            for &idx in &filtered[cur_pos + 1..] {
                if let Some(pkt) = self.packets.get(idx)
                    && self.bookmarks.contains(&pkt.id)
                {
                    self.selected = idx;
                    self.follow = false;
                    return;
                }
            }
            // Wrap around from the start.
            for &idx in &filtered[..cur_pos] {
                if let Some(pkt) = self.packets.get(idx)
                    && self.bookmarks.contains(&pkt.id)
                {
                    self.selected = idx;
                    self.follow = false;
                    return;
                }
            }
        }
    }

    /// Jump to the previous bookmarked packet.
    pub fn jump_prev_bookmark(&mut self) {
        let filtered = self.filtered_indices();
        if let Some(cur_pos) = filtered.iter().position(|&i| i == self.selected) {
            // Search backward.
            for &idx in filtered[..cur_pos].iter().rev() {
                if let Some(pkt) = self.packets.get(idx)
                    && self.bookmarks.contains(&pkt.id)
                {
                    self.selected = idx;
                    self.follow = false;
                    return;
                }
            }
            // Wrap around from the end.
            for &idx in filtered[cur_pos + 1..].iter().rev() {
                if let Some(pkt) = self.packets.get(idx)
                    && self.bookmarks.contains(&pkt.id)
                {
                    self.selected = idx;
                    self.follow = false;
                    return;
                }
            }
        }
    }

    /// Mark current packet for diff, or open diff if a mark already exists.
    pub fn mark_or_diff(&mut self) {
        let Some(pkt) = self.selected_packet() else {
            return;
        };
        let current_id = pkt.id;
        let current_idx = self.selected;

        if let Some(mark_id) = self.diff_mark {
            if mark_id == current_id {
                self.diff_mark = None;
                self.set_status("Diff mark cleared".into());
                return;
            }
            if let Some(mark_idx) = self.packets.iter().position(|p| p.id == mark_id) {
                self.diff_pair = Some((mark_idx, current_idx));
                self.diff_mark = None;
            } else {
                self.set_status("Marked packet no longer in buffer".into());
                self.diff_mark = None;
            }
        } else {
            self.diff_mark = Some(current_id);
            self.set_status(format!(
                "Marked #{current_id} for diff — select another and press x"
            ));
        }
    }

    pub fn scroll_down(&mut self) {
        self.hex_scroll = self.hex_scroll.saturating_add(1);
    }

    // -- Annotations ---------------------------------------------------------

    /// Start editing an annotation for the selected packet.
    pub fn start_annotate(&mut self) {
        if let Some(pkt) = self.selected_packet() {
            let id = pkt.id;
            self.annotation_buf = self.annotations.get(&id).cloned().unwrap_or_default();
            self.annotating = Some(id);
        }
    }

    /// Confirm the annotation input.
    pub fn confirm_annotate(&mut self) {
        if let Some(id) = self.annotating.take() {
            let text = self.annotation_buf.trim().to_string();
            if text.is_empty() {
                self.annotations.remove(&id);
                self.set_status(format!("Annotation removed from #{id}"));
            } else {
                self.annotations.insert(id, text);
                self.set_status(format!("Annotated #{id}"));
            }
            self.annotation_buf.clear();
        }
    }

    /// Cancel annotation input.
    pub fn cancel_annotate(&mut self) {
        self.annotating = None;
        self.annotation_buf.clear();
    }

    /// Push a char into annotation buffer.
    pub fn annotate_push(&mut self, ch: char) {
        self.annotation_buf.push(ch);
    }

    /// Pop a char from annotation buffer.
    pub fn annotate_pop(&mut self) {
        self.annotation_buf.pop();
    }

    // -- Display filter --------------------------------------------------------

    pub fn start_display_filter(&mut self) {
        self.display_filter_editing = true;
        self.display_filter_buf = self.display_filter.clone();
    }

    pub fn confirm_display_filter(&mut self) {
        self.display_filter = self.display_filter_buf.clone();
        self.display_filter_editing = false;
        self.clamp_selected();
    }

    pub fn cancel_display_filter(&mut self) {
        self.display_filter_editing = false;
        self.display_filter_buf.clear();
    }

    pub fn display_filter_push(&mut self, ch: char) {
        self.display_filter_buf.push(ch);
    }

    pub fn display_filter_pop(&mut self) {
        self.display_filter_buf.pop();
    }

    pub fn scroll_up(&mut self) {
        self.hex_scroll = self.hex_scroll.saturating_sub(1);
    }

    /// Get the highest severity expert item for a packet, if any.
    pub fn max_severity(pkt: &CapturedPacket) -> Option<Severity> {
        pkt.expert.iter().map(|e| e.severity).max()
    }

    pub fn selected_packet(&self) -> Option<&CapturedPacket> {
        self.packets.get(self.selected)
    }

    // -- Process picker ------------------------------------------------------

    pub fn open_process_picker(&mut self, processes: Vec<ProcessInfo>) {
        let filtered: Vec<usize> = (0..processes.len()).collect();
        self.process_picker = Some(ProcessPicker {
            processes,
            filtered,
            selected: 0,
            query: String::new(),
        });
    }

    pub fn close_process_picker(&mut self) {
        self.process_picker = None;
    }

    pub fn picker_select(&mut self) {
        let info = {
            let Some(picker) = &self.process_picker else {
                return;
            };
            let Some(&idx) = picker.filtered.get(picker.selected) else {
                return;
            };
            picker.processes[idx].clone()
        };
        self.process_filter = Some(ProcessFilter {
            name: info.name,
            pid: info.pid,
            ports: info.ports,
        });
        self.process_picker = None;
        self.clamp_selected();
    }

    pub fn clear_process_filter(&mut self) {
        self.process_filter = None;
        self.clamp_selected();
    }

    pub fn picker_next(&mut self) {
        if let Some(ref mut picker) = self.process_picker
            && picker.selected + 1 < picker.filtered.len()
        {
            picker.selected += 1;
        }
    }

    pub fn picker_prev(&mut self) {
        if let Some(ref mut picker) = self.process_picker
            && picker.selected > 0
        {
            picker.selected -= 1;
        }
    }

    pub fn picker_push(&mut self, ch: char) {
        if let Some(ref mut picker) = self.process_picker {
            picker.query.push(ch);
            Self::refilter_picker(picker);
        }
    }

    pub fn picker_pop(&mut self) {
        if let Some(ref mut picker) = self.process_picker {
            picker.query.pop();
            Self::refilter_picker(picker);
        }
    }

    fn refilter_picker(picker: &mut ProcessPicker) {
        let q = picker.query.to_ascii_lowercase();
        picker.filtered = picker
            .processes
            .iter()
            .enumerate()
            .filter(|(_, p)| {
                q.is_empty()
                    || p.name.to_ascii_lowercase().contains(&q)
                    || p.pid.to_string().contains(&q)
            })
            .map(|(i, _)| i)
            .collect();
        if picker.selected >= picker.filtered.len() {
            picker.selected = picker.filtered.len().saturating_sub(1);
        }
    }

    /// Refresh process ports for the active filter (call periodically).
    pub fn refresh_process_ports(&mut self) {
        if let Some(ref mut pf) = self.process_filter
            && let Ok(info) = crate::process::resolve_process(&pf.name)
        {
            pf.ports = info.ports;
            pf.pid = info.pid;
        }
    }

    // -- Stats ---------------------------------------------------------------

    /// Set a temporary status message (displayed for ~3 seconds).
    pub fn set_status(&mut self, msg: String) {
        self.status_message = Some((msg, Instant::now()));
    }

    /// Clear expired status messages (older than 3 seconds).
    pub fn tick_status(&mut self) {
        if let Some((_, at)) = &self.status_message
            && at.elapsed().as_secs() >= 3
        {
            self.status_message = None;
        }
    }

    /// Export visible (filtered) packets to a pcap file.
    /// If `--write` was given, uses that path. Otherwise auto-generates a timestamped name.
    /// Returns a status message describing the result.
    pub fn export_packets(&self) -> String {
        let path = if let Some(ref p) = self.export_path {
            p.clone()
        } else {
            // Auto-generate filename: hexcap_YYYYMMDD_HHMMSS.pcap
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            // Simple timestamp without chrono: use seconds since epoch.
            PathBuf::from(format!("hexcap_{now}.pcap"))
        };
        let filtered = self.filtered_indices();
        let packets: Vec<&CapturedPacket> = filtered
            .iter()
            .filter_map(|&i| self.packets.get(i))
            .collect();
        match crate::export::write_pcap(path.as_path(), &packets) {
            Ok(n) => {
                // Save bookmarks sidecar if any bookmarks exist.
                let bm_path = crate::export::bookmark_path(&path);
                if let Err(e) = crate::export::save_bookmarks(&bm_path, &self.bookmarks) {
                    return format!("Exported {n} packets but bookmark save failed: {e}");
                }
                // Save annotations sidecar.
                let ann_path = crate::export::annotation_path(&path);
                if let Err(e) = crate::export::save_annotations(&ann_path, &self.annotations) {
                    return format!("Exported {n} packets but annotation save failed: {e}");
                }
                let mut extras = Vec::new();
                if !self.bookmarks.is_empty() {
                    extras.push(format!("{} bookmarks", self.bookmarks.len()));
                }
                if !self.annotations.is_empty() {
                    extras.push(format!("{} annotations", self.annotations.len()));
                }
                let note = if extras.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", extras.join(", "))
                };
                format!("Exported {n} packets{note} to {}", path.display())
            }
            Err(e) => format!("Export failed: {e}"),
        }
    }

    pub fn proto_counts(&self) -> ProtoCounts {
        let mut counts = ProtoCounts::default();
        for p in &self.packets {
            match p.protocol {
                Protocol::Tcp => counts.tcp += 1,
                Protocol::Udp => counts.udp += 1,
                Protocol::Icmp => counts.icmp += 1,
                Protocol::Dns => counts.dns += 1,
                Protocol::Arp => counts.arp += 1,
                Protocol::Other(_) => counts.other += 1,
            }
        }
        counts
    }
}

#[derive(Debug, Default)]
pub struct ProtoCounts {
    pub tcp: usize,
    pub udp: usize,
    pub icmp: usize,
    pub dns: usize,
    pub arp: usize,
    pub other: usize,
}

/// Check if packet data contains the query as an ASCII substring (case-insensitive).
fn payload_contains_ascii(data: &[u8], query: &str) -> bool {
    let query_bytes = query.as_bytes();
    if query_bytes.is_empty() || query_bytes.len() > data.len() {
        return false;
    }
    data.windows(query_bytes.len()).any(|window| {
        window
            .iter()
            .zip(query_bytes.iter())
            .all(|(a, b)| a.to_ascii_lowercase() == *b)
    })
}

/// Check if the query looks like a hex pattern and search for it in the data.
///
/// Accepts patterns like "ff d8 ff" or "ffd8ff" (spaces optional).
fn payload_contains_hex(data: &[u8], query: &str) -> bool {
    let hex_chars: String = query.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if hex_chars.len() < 2 || !hex_chars.len().is_multiple_of(2) {
        return false;
    }
    // All chars must be valid hex.
    if !hex_chars.chars().all(|c| c.is_ascii_hexdigit()) {
        return false;
    }
    let pattern: Vec<u8> = (0..hex_chars.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&hex_chars[i..i + 2], 16).ok())
        .collect();
    if pattern.len() != hex_chars.len() / 2 || pattern.is_empty() {
        return false;
    }
    data.windows(pattern.len())
        .any(|window| window == pattern.as_slice())
}
