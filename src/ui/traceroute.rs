use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table};

use crate::app::App;
use crate::theme::Theme;

/// Render a centered traceroute results overlay.
pub fn draw_traceroute(frame: &mut Frame, app: &App, theme: &Theme) {
    let area = frame.area();
    let Some(state) = &app.traceroute_state else {
        return;
    };

    // Center a large popup area — 80% width, 70% height
    let popup_w = (area.width * 80 / 100)
        .max(60)
        .min(area.width.saturating_sub(4));
    let popup_h = (area.height * 70 / 100)
        .max(16)
        .min(area.height.saturating_sub(2));
    let x = area.x + (area.width.saturating_sub(popup_w)) / 2;
    let y = area.y + (area.height.saturating_sub(popup_h)) / 2;
    let popup = Rect::new(x, y, popup_w, popup_h);

    frame.render_widget(Clear, popup);

    let bold = Style::default()
        .fg(theme.accent)
        .add_modifier(Modifier::BOLD);
    let normal = Style::default().fg(theme.fg);
    let muted = Style::default().fg(theme.muted);

    // Header status text
    let status_text = if state.running {
        Span::styled(" Running...", Style::default().fg(theme.accent))
    } else if let Some(ref err) = state.error {
        Span::styled(format!(" Error: {err}"), Style::default().fg(Color::Red))
    } else {
        Span::styled(" Finished", Style::default().fg(theme.accent))
    };

    let title = Line::from(vec![
        Span::styled(format!(" Traceroute to {} ", state.target), bold),
        status_text,
    ]);

    // Create table rows for hops
    let mut rows = Vec::new();
    for h in &state.hops {
        let rtt_str = h.rtt.map_or("*".to_string(), |r| format!("{r:.2} ms"));

        let host_display = match &h.hostname {
            Some(host) => format!("{} ({})", host, h.ip),
            None => h.ip.clone(),
        };

        let geo_str = h.geoip.as_ref().map_or(String::new(), |g| format!("[{g}]"));

        rows.push(
            Row::new(vec![
                Cell::from(format!(" {}", h.hop)),
                Cell::from(host_display),
                Cell::from(geo_str),
                Cell::from(rtt_str),
            ])
            .style(normal),
        );
    }

    let widths = [
        Constraint::Length(5),  // Hop
        Constraint::Min(32),    // Hostname/IP
        Constraint::Length(8),  // GeoIP
        Constraint::Length(12), // RTT
    ];

    let header = Row::new(vec![
        Cell::from(" Hop").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from(" Hostname / IP").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from(" GeoIP").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from(" RTT").style(Style::default().add_modifier(Modifier::BOLD)),
    ])
    .style(Style::default().fg(theme.accent))
    .bottom_margin(1);

    let table = Table::new(rows, widths).header(header).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme.accent))
            .title(title)
            .style(Style::default().bg(theme.panel_bg)),
    );

    frame.render_widget(table, popup);

    // Footer hints inside the overlay
    let hint_text = Line::from(vec![
        Span::styled(
            " Esc/q ",
            Style::default()
                .fg(theme.key_fg)
                .bg(theme.key_bg)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" Close  ", muted),
        Span::styled(
            " y ",
            Style::default()
                .fg(theme.key_fg)
                .bg(theme.key_bg)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" Copy to Clipboard", muted),
    ]);

    let hint_area = Rect::new(popup.x + 2, popup.y + popup.height - 2, popup.width - 4, 1);
    frame.render_widget(
        Paragraph::new(hint_text).style(Style::default().bg(theme.panel_bg)),
        hint_area,
    );
}
