mod agent_pane;
mod detail;
mod diff;
mod expert_overlay;
mod flow_graph;
mod flows;
mod footer;
mod header;
mod help;
pub mod helpers;
mod list;
mod picker;
mod proto_hierarchy;
mod stats;
mod stats_summary;
mod traceroute;

use ratatui::prelude::*;
use ratatui::widgets::{Block, Clear};

use crate::app::{App, InputMode, View};

use helpers::render_size_guard;

/// Render the entire TUI into the given frame.
pub fn render(frame: &mut Frame, app: &App) {
    let theme = app.theme();

    if render_size_guard(frame, theme) {
        return;
    }

    let area = frame.area();

    // Paint background.
    frame.render_widget(Clear, area);
    frame.render_widget(
        Block::default().style(Style::default().bg(theme.bg).fg(theme.fg)),
        area,
    );

    // Split for agent pane if visible.
    let (main_area, agent_area) = if app.show_agent_pane {
        let split = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Percentage(app.agent_pane_ratio),
                Constraint::Percentage(100 - app.agent_pane_ratio),
            ])
            .split(area);
        (split[0], Some(split[1]))
    } else {
        (area, None)
    };

    match app.view {
        View::List => draw_list_layout(frame, app, main_area),
        View::Detail => draw_detail_layout(frame, app, main_area),
        View::Flows => draw_flows_layout(frame, app, main_area),
        View::Stream => draw_stream_layout(frame, app, main_area),
    }

    // Render agent pane if visible.
    if let Some(agent_area) = agent_area {
        agent_pane::draw_agent_pane(frame, app, theme, agent_area);
    }

    // Overlay: process picker popup.
    if app.process_picker.is_some() {
        picker::draw_process_picker(frame, app, theme);
    }

    // Overlay: interface picker popup.
    if app.interface_picker.is_some() {
        picker::draw_interface_picker(frame, app, theme);
    }

    // Overlay: agent picker popup.
    if app.agent_picker.is_some() {
        picker::draw_agent_picker(frame, app, theme);
    }

    // Overlay: help popup.
    if app.show_help {
        help::draw_help(frame, theme);
    }

    // Overlay: stats summary popup.
    if app.show_stats_summary {
        stats_summary::draw_stats_summary(frame, app, theme);
    }

    // Overlay: traceroute results.
    if app.traceroute_state.is_some() {
        traceroute::draw_traceroute(frame, app, theme);
    }

    // Overlay: packet diff.
    if app.diff_pair.is_some() {
        diff::draw_diff(frame, app, theme);
    }

    // Overlay: expert info.
    if app.show_expert {
        expert_overlay::draw_expert(frame, app, theme);
    }

    // Overlay: protocol hierarchy.
    if app.show_proto_hierarchy {
        proto_hierarchy::draw_proto_hierarchy(frame, app, theme);
    }

    // Overlay: flow graph / sequence diagram.
    if app.show_flow_graph {
        flow_graph::draw_flow_graph(frame, app, theme);
    }
}

/// List layout: header | stats | table | search bar? | footer.
fn draw_list_layout(frame: &mut Frame, app: &App, area: Rect) {
    let theme = app.theme();

    let input_bar_height = u16::from(
        app.input_mode == InputMode::Search
            || app.input_mode == InputMode::GoToPacket
            || app.annotating.is_some()
            || app.display_filter_editing
            || app.traceroute_input_active,
    );

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),                // header
            Constraint::Length(1),                // stats row
            Constraint::Min(5),                   // packet table (flexible)
            Constraint::Length(input_bar_height), // input bar (conditional)
            Constraint::Length(1),                // footer
        ])
        .split(area);

    header::draw_header(frame, app, theme, chunks[0]);
    stats::draw_stats_row(frame, app, theme, chunks[1]);
    list::draw_packet_table(frame, app, theme, chunks[2]);
    match app.input_mode {
        InputMode::Search => list::draw_search_bar(frame, app, theme, chunks[3]),
        InputMode::GoToPacket => list::draw_goto_bar(frame, app, theme, chunks[3]),
        InputMode::Normal if app.annotating.is_some() => {
            list::draw_annotation_bar(frame, app, theme, chunks[3]);
        }
        InputMode::Normal if app.display_filter_editing => {
            list::draw_display_filter_bar(frame, app, theme, chunks[3]);
        }
        InputMode::Normal if app.traceroute_input_active => {
            list::draw_traceroute_bar(frame, app, theme, chunks[3]);
        }
        InputMode::Normal => {}
    }
    footer::draw_footer(frame, app, theme, chunks[4]);
}

/// Detail layout: header | packet info | decoded fields | hex dump | footer.
fn draw_detail_layout(frame: &mut Frame, app: &App, area: Rect) {
    let theme = app.theme();

    // Calculate decoded fields height dynamically (includes expert items).
    let decoded_count = app.selected_packet().map_or(0, |pkt| {
        let base = pkt.decoded.len().max(1);
        let expert_lines = if pkt.expert.is_empty() {
            0
        } else {
            pkt.expert.len() + 1
        };
        base + expert_lines
    });
    let decoded_height = u16::try_from(decoded_count)
        .unwrap_or(u16::MAX)
        .saturating_add(2);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),              // header
            Constraint::Length(3),              // packet info
            Constraint::Length(decoded_height), // decoded protocol fields
            Constraint::Min(5),                 // hex dump (flexible)
            Constraint::Length(1),              // footer
        ])
        .split(area);

    header::draw_header(frame, app, theme, chunks[0]);
    detail::draw_packet_info(frame, app, theme, chunks[1]);
    detail::draw_decoded_fields(frame, app, theme, chunks[2]);
    detail::draw_hex_dump(frame, app, theme, chunks[3]);
    footer::draw_footer(frame, app, theme, chunks[4]);
}

/// Flows layout: header | flows table | footer.
fn draw_flows_layout(frame: &mut Frame, app: &App, area: Rect) {
    let theme = app.theme();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // header
            Constraint::Min(5),    // flows table
            Constraint::Length(1), // footer
        ])
        .split(area);

    header::draw_header(frame, app, theme, chunks[0]);
    flows::draw_flows_table(frame, app, theme, chunks[1]);
    footer::draw_footer(frame, app, theme, chunks[2]);
}

/// Stream layout: header | stream content | footer.
fn draw_stream_layout(frame: &mut Frame, app: &App, area: Rect) {
    let theme = app.theme();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // header
            Constraint::Min(5),    // stream content
            Constraint::Length(1), // footer
        ])
        .split(area);

    header::draw_header(frame, app, theme, chunks[0]);
    detail::draw_stream_content(frame, app, theme, chunks[1]);
    footer::draw_footer(frame, app, theme, chunks[2]);
}
