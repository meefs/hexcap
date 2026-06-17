use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use crate::app::App;
use crate::theme::Theme;

/// Height of the chat input bar (border + input line).
const INPUT_BAR_HEIGHT: u16 = 1;

/// Render the agent pane at the bottom of the screen.
///
/// When chat messages exist (split-mode agents), renders a chat view with
/// an inline input bar. Otherwise falls back to the legacy markdown output
/// view (for `--pipe` agents).
pub fn draw_agent_pane(frame: &mut Frame, app: &App, theme: &Theme, area: Rect) {
    if !app.chat_messages.is_empty() || app.chat_input_active {
        draw_chat_pane(frame, app, theme, area);
    } else {
        draw_output_pane(frame, app, theme, area);
    }
}

/// Chat-style pane: messages list + inline input bar at the bottom.
fn draw_chat_pane(frame: &mut Frame, app: &App, theme: &Theme, area: Rect) {
    let agent_label = app.agent_name.as_deref().unwrap_or("Agent");
    let msg_count = app.chat_messages.len();
    let title = format!(" {agent_label} ({msg_count} messages) ");

    // Split area: messages on top, input bar at bottom.
    let input_height = if app.chat_input_active {
        INPUT_BAR_HEIGHT
    } else {
        0
    };
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(3),               // chat messages
            Constraint::Length(input_height), // input bar
        ])
        .split(area);

    // -- Chat messages --
    let mut lines: Vec<Line<'_>> = Vec::new();
    for msg in &app.chat_messages {
        let (prefix_style, text_style) = match msg.sender.as_str() {
            "you" => (
                Style::default()
                    .fg(theme.accent)
                    .add_modifier(Modifier::BOLD),
                Style::default().fg(theme.fg),
            ),
            "system" => (
                Style::default()
                    .fg(theme.muted)
                    .add_modifier(Modifier::ITALIC),
                Style::default()
                    .fg(theme.muted)
                    .add_modifier(Modifier::ITALIC),
            ),
            _ => (
                Style::default().fg(theme.tag).add_modifier(Modifier::BOLD),
                Style::default().fg(theme.fg),
            ),
        };
        // First line with sender prefix.
        let mut first = true;
        for text_line in msg.text.lines() {
            if first {
                lines.push(Line::from(vec![
                    Span::styled(format!("{}: ", msg.sender), prefix_style),
                    Span::styled(text_line.to_string(), text_style),
                ]));
                first = false;
            } else {
                // Continuation lines indented.
                let indent = " ".repeat(msg.sender.len() + 2);
                lines.push(Line::from(vec![
                    Span::raw(indent),
                    Span::styled(text_line.to_string(), text_style),
                ]));
            }
        }
        if first {
            // Empty message body — still show the sender.
            lines.push(Line::from(Span::styled(
                format!("{}: ", msg.sender),
                prefix_style,
            )));
        }
    }

    let line_count = lines.len();
    let visible = chunks[0].height.saturating_sub(2) as usize; // minus border chrome
    let scroll_offset = if app.agent_scroll == 0 {
        line_count.saturating_sub(visible)
    } else {
        line_count
            .saturating_sub(visible)
            .saturating_sub(app.agent_scroll)
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.accent))
        .title(title)
        .title_style(
            Style::default()
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD),
        )
        .style(Style::default().bg(theme.panel_bg));

    let paragraph = Paragraph::new(Text::from(lines))
        .block(block)
        .wrap(Wrap { trim: false })
        .scroll((
            #[allow(clippy::cast_possible_truncation)]
            {
                scroll_offset as u16
            },
            0,
        ));
    frame.render_widget(paragraph, chunks[0]);

    // -- Input bar --
    if app.chat_input_active {
        let input_text = format!("> {}", app.chat_input);
        let input_style = Style::default().fg(theme.accent);
        let input = Paragraph::new(Span::styled(input_text, input_style))
            .style(Style::default().bg(theme.panel_bg));
        frame.render_widget(input, chunks[1]);

        // Place cursor at the end of input.
        #[allow(clippy::cast_possible_truncation)]
        let cursor_x = chunks[1].x + 2 + app.chat_input.len() as u16;
        frame.set_cursor_position((cursor_x, chunks[1].y));
    }
}

/// Legacy output pane for `--pipe` agents: markdown-rendered output.
fn draw_output_pane(frame: &mut Frame, app: &App, theme: &Theme, area: Rect) {
    let output = app
        .agent_output
        .lock()
        .expect("agent output mutex poisoned");
    let total = output.len();

    // Join all output lines into a single markdown document.
    let md_source: String = output.iter().fold(String::new(), |mut acc, line| {
        acc.push_str(line);
        acc.push('\n');
        acc
    });
    drop(output);

    // Parse markdown into ratatui Text.
    let text = tui_markdown::from_str(&md_source);
    let line_count = text.lines.len();

    // Visible lines (area height minus border chrome).
    let visible = area.height.saturating_sub(2) as usize;

    // Compute scroll offset (from the bottom).
    let scroll_offset = if app.agent_scroll == 0 {
        line_count.saturating_sub(visible) // auto-scroll to bottom
    } else {
        line_count
            .saturating_sub(visible)
            .saturating_sub(app.agent_scroll)
    };

    let agent_label = app.agent_name.as_deref().unwrap_or("Agent");
    let title = format!(" {agent_label} ({total} lines) ");
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.accent))
        .title(title)
        .title_style(
            Style::default()
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD),
        )
        .style(Style::default().bg(theme.panel_bg));

    let paragraph = Paragraph::new(text)
        .block(block)
        .wrap(Wrap { trim: false })
        .scroll((
            #[allow(clippy::cast_possible_truncation)]
            {
                scroll_offset as u16
            },
            0,
        ));

    frame.render_widget(paragraph, area);
}
