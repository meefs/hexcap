use std::collections::HashMap;
use std::time::UNIX_EPOCH;

use ratatui::prelude::*;
use ratatui::text::Span;
use ratatui::widgets::{Block, Borders, Cell, Row, Table, TableState};

use crate::app::{App, TimeFormat};
use crate::dns;
use crate::expert;
use crate::geoip;
use crate::packet::{CapturedPacket, FlowKey, Protocol};
use crate::theme::Theme;

use super::helpers::{highlight_style, stripe_style};

/// TCP flag constants.
const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;

/// Semantic row color based on protocol and TCP flags (Wireshark-style).
/// Returns `None` for normal coloring (use flow/stripe defaults).
fn semantic_color(p: &CapturedPacket) -> Option<Color> {
    if p.tcp_flags & TCP_RST != 0 {
        return Some(Color::Rgb(255, 80, 80)); // red — connection reset
    }
    if p.tcp_flags & TCP_SYN != 0 && p.tcp_flags & 0x10 == 0 {
        return Some(Color::Rgb(100, 220, 100)); // green — new connection (SYN only)
    }
    if p.tcp_flags & TCP_FIN != 0 {
        return Some(Color::Rgb(200, 160, 80)); // amber — connection closing
    }
    match p.protocol {
        Protocol::Icmp => Some(Color::Rgb(180, 180, 255)), // light blue
        Protocol::Arp => Some(Color::Rgb(200, 200, 140)),  // khaki
        Protocol::Dns => Some(Color::Rgb(140, 220, 200)),  // teal
        _ => None,
    }
}

/// Base column widths for the packet table.
const BASE_WIDTHS: [u16; 7] = [7, 12, 8, 18, 18, 6, 3];

/// Build column constraints with user adjustments applied.
fn table_widths(adjustments: &[i16; 7]) -> [Constraint; 7] {
    let adjusted = |i: usize| -> u16 {
        #[allow(clippy::cast_possible_wrap)]
        let base = BASE_WIDTHS[i] as i16;
        #[allow(clippy::cast_sign_loss)]
        let w = (base + adjustments[i]).max(4) as u16;
        w
    };
    [
        Constraint::Length(adjusted(0)),
        Constraint::Length(adjusted(1)),
        Constraint::Length(adjusted(2)),
        Constraint::Min(adjusted(3)),
        Constraint::Min(adjusted(4)),
        Constraint::Length(adjusted(5)),
        Constraint::Length(adjusted(6)),
    ]
}

/// Build the table header row.
fn table_header(theme: &Theme) -> Row<'static> {
    Row::new(vec![
        Cell::from("#"),
        Cell::from("Time"),
        Cell::from("Proto"),
        Cell::from("Source"),
        Cell::from("Destination"),
        Cell::from("Len"),
        Cell::from("Exp"),
    ])
    .style(
        Style::default()
            .fg(theme.accent)
            .add_modifier(Modifier::BOLD),
    )
}

/// Protocol tag color.
fn proto_color(proto: Protocol, theme: &Theme) -> Color {
    match proto {
        Protocol::Tcp => theme.accent,
        Protocol::Udp => theme.tag,
        Protocol::Icmp => theme.highlight_fg,
        Protocol::Arp | Protocol::Other(_) => theme.muted,
        Protocol::Dns => theme.hex_ascii,
    }
}

/// Render the packet list table.
pub fn draw_packet_table(frame: &mut Frame, app: &App, theme: &Theme, area: Rect) {
    let header = table_header(theme);

    let mut flow_map: HashMap<FlowKey, usize> = HashMap::new();
    let mut next_color: usize = 0;

    // Precompute first-packet timestamp and time reference timestamp.
    let first_ts = app.packets.front().map(|p| p.timestamp);
    let ref_ts = app
        .time_reference
        .and_then(|id| app.packets.iter().find(|p| p.id == id).map(|p| p.timestamp));
    let mut prev_ts: Option<std::time::SystemTime> = None;

    let rows: Vec<Row> = app
        .packets
        .iter()
        .enumerate()
        .map(|(idx, p)| {
            let proto_col = proto_color(p.protocol, theme);

            // Assign a flow color.
            let flow = FlowKey::new(&p.src, &p.dst);
            let flow_idx = *flow_map.entry(flow).or_insert_with(|| {
                let i = next_color;
                next_color = (next_color + 1) % theme.flow_colors.len();
                i
            });
            let flow_col = theme.flow_colors[flow_idx];

            let has_bookmark = app.bookmarks.contains(&p.id);
            let has_annotation = app.annotations.contains_key(&p.id);
            let is_time_ref = app.time_reference == Some(p.id);
            let id_label = match (has_bookmark, has_annotation, is_time_ref) {
                (_, _, true) => format!("*{}", p.id),
                (true, true, false) => format!("★✎{}", p.id),
                (true, false, false) => format!("★{}", p.id),
                (false, true, false) => format!("✎{}", p.id),
                (false, false, false) => format!("{}", p.id),
            };

            let time_str = format_time(p, app.time_format, first_ts, ref_ts, prev_ts);
            prev_ts = Some(p.timestamp);

            let mut src_display = if app.dns_enabled {
                dns::resolve_display(&p.src, &app.dns_cache)
            } else {
                p.src.clone()
            };
            let mut dst_display = if app.dns_enabled {
                dns::resolve_display(&p.dst, &app.dns_cache)
            } else {
                p.dst.clone()
            };
            if app.geoip_enabled {
                src_display = geoip::geo_display(&src_display, &app.geoip_cache);
                dst_display = geoip::geo_display(&dst_display, &app.geoip_cache);
            }

            // Expert severity indicator.
            let expert_cell = if let Some(sev) = App::max_severity(p) {
                Cell::from(expert::severity_symbol(sev).to_string())
                    .style(Style::default().fg(expert::severity_color(sev)))
            } else {
                Cell::from("")
            };

            Row::new(vec![
                Cell::from(id_label),
                Cell::from(time_str),
                Cell::from(p.protocol.to_string()).style(Style::default().fg(proto_col)),
                Cell::from(src_display).style(Style::default().fg(flow_col)),
                Cell::from(dst_display).style(Style::default().fg(flow_col)),
                Cell::from(format!("{}", p.length)),
                expert_cell,
            ])
            .style(if let Some(sem) = semantic_color(p) {
                stripe_style(idx, theme).fg(sem)
            } else {
                stripe_style(idx, theme)
            })
        })
        .collect();

    let pause_label = if app.paused { " ⏸" } else { "" };
    let title = format!(" Packets: {}{pause_label} ", app.packets.len());

    let title_style = Style::default()
        .fg(theme.accent)
        .add_modifier(Modifier::BOLD);

    let widths = table_widths(&app.column_widths);
    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme.border))
                .title(title)
                .title_style(title_style),
        )
        .row_highlight_style(highlight_style(theme));

    let mut state = TableState::default().with_selected(Some(app.selected));
    frame.render_stateful_widget(table, area, &mut state);
}

/// Render the search input bar.
pub fn draw_search_bar(frame: &mut Frame, app: &App, theme: &Theme, area: Rect) {
    let text = Line::from(vec![
        Span::styled(
            " / ",
            Style::default()
                .fg(theme.key_fg)
                .bg(theme.key_bg)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(" {}", app.search_query),
            Style::default().fg(theme.fg),
        ),
        Span::styled("▌", Style::default().fg(theme.accent)),
    ]);
    let paragraph =
        ratatui::widgets::Paragraph::new(text).style(Style::default().bg(theme.panel_bg));
    frame.render_widget(paragraph, area);
}

/// Render the annotation input bar.
pub fn draw_annotation_bar(frame: &mut Frame, app: &App, theme: &Theme, area: Rect) {
    let id = app.annotating.unwrap_or(0);
    let text = Line::from(vec![
        Span::styled(
            format!(" ✎ #{id} "),
            Style::default()
                .fg(theme.key_fg)
                .bg(theme.key_bg)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(" {}", app.annotation_buf),
            Style::default().fg(theme.fg),
        ),
        Span::styled("▌", Style::default().fg(theme.accent)),
    ]);
    let paragraph =
        ratatui::widgets::Paragraph::new(text).style(Style::default().bg(theme.panel_bg));
    frame.render_widget(paragraph, area);
}

/// Render the go-to-packet input bar.
pub fn draw_goto_bar(frame: &mut Frame, app: &App, theme: &Theme, area: Rect) {
    let text = Line::from(vec![
        Span::styled(
            " : ",
            Style::default()
                .fg(theme.key_fg)
                .bg(theme.key_bg)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(" Go to #{}", app.goto_buf),
            Style::default().fg(theme.fg),
        ),
        Span::styled("▌", Style::default().fg(theme.accent)),
    ]);
    let paragraph =
        ratatui::widgets::Paragraph::new(text).style(Style::default().bg(theme.panel_bg));
    frame.render_widget(paragraph, area);
}

/// Render the display filter input bar.
pub fn draw_display_filter_bar(frame: &mut Frame, app: &App, theme: &Theme, area: Rect) {
    let active = !app.display_filter.is_empty();
    let label = if active { " \\ filter: " } else { " \\ " };
    let text = Line::from(vec![
        Span::styled(
            label,
            Style::default()
                .fg(theme.key_fg)
                .bg(theme.key_bg)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(" {}", app.display_filter_buf),
            Style::default().fg(theme.fg),
        ),
        Span::styled("▌", Style::default().fg(theme.accent)),
    ]);
    let paragraph =
        ratatui::widgets::Paragraph::new(text).style(Style::default().bg(theme.panel_bg));
    frame.render_widget(paragraph, area);
}

/// Render the traceroute input bar.
pub fn draw_traceroute_bar(frame: &mut Frame, app: &App, theme: &Theme, area: Rect) {
    let text = Line::from(vec![
        Span::styled(
            " Traceroute Target: ",
            Style::default()
                .fg(theme.key_fg)
                .bg(theme.key_bg)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(" {}", app.traceroute_input),
            Style::default().fg(theme.fg),
        ),
        Span::styled("▌", Style::default().fg(theme.accent)),
    ]);
    let paragraph =
        ratatui::widgets::Paragraph::new(text).style(Style::default().bg(theme.panel_bg));
    frame.render_widget(paragraph, area);
}

fn format_time(
    p: &CapturedPacket,
    fmt: TimeFormat,
    first_ts: Option<std::time::SystemTime>,
    ref_ts: Option<std::time::SystemTime>,
    prev_ts: Option<std::time::SystemTime>,
) -> String {
    match fmt {
        TimeFormat::Absolute => {
            let secs = p
                .timestamp
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs_f64();
            let s = secs % 86400.0;
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let h = (s / 3600.0) as u32;
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let m = ((s % 3600.0) / 60.0) as u32;
            let sec = s % 60.0;
            format!("{h:02}:{m:02}:{sec:06.3}")
        }
        TimeFormat::Relative => {
            // If there's a time reference, use that; otherwise use first packet.
            let base = ref_ts.or(first_ts).unwrap_or(p.timestamp);
            let delta = p
                .timestamp
                .duration_since(base)
                .unwrap_or_default()
                .as_secs_f64();
            format!("{delta:>10.6}")
        }
        TimeFormat::Delta => {
            let base = prev_ts.unwrap_or(p.timestamp);
            let delta = p
                .timestamp
                .duration_since(base)
                .unwrap_or_default()
                .as_secs_f64();
            format!("{delta:>10.6}")
        }
    }
}
