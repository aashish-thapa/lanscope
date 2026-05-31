//! Ratatui terminal UI.
//!
//! The capture pipeline runs on the async runtime and publishes into a shared
//! [`Dashboard`]; this module renders that snapshot and handles input on a
//! blocking thread (crossterm's `poll`/`read` are blocking). Pressing `q`/`Esc`
//! signals the pipeline to shut down.

use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::prelude::*;
use ratatui::widgets::{
    Block, Borders, Cell, List, ListItem, Paragraph, Row, Table, TableState, Wrap,
};
use tokio::sync::watch;

use crate::alert::{Alert, Severity};
use crate::error::{Error, Result};
use crate::netfmt;
use crate::registry::Device;

/// Maximum alerts retained for the live feed.
const MAX_ALERTS: usize = 200;

/// Snapshot of pipeline state shared with the renderer.
pub struct Dashboard {
    pub backend: String,
    pub mode: String,
    pub devices: Vec<Device>,
    pub alerts: VecDeque<Alert>,
}

impl Dashboard {
    pub fn new(backend: impl Into<String>, mode: impl Into<String>) -> Self {
        Self {
            backend: backend.into(),
            mode: mode.into(),
            devices: Vec::new(),
            alerts: VecDeque::new(),
        }
    }

    /// Replace the device list (sorted most-recently-seen first).
    pub fn set_devices(&mut self, mut devices: Vec<Device>) {
        devices.sort_by_key(|d| std::cmp::Reverse(d.last_seen));
        self.devices = devices;
    }

    /// Push a new alert, evicting the oldest beyond the cap.
    pub fn push_alert(&mut self, alert: Alert) {
        self.alerts.push_front(alert);
        self.alerts.truncate(MAX_ALERTS);
    }
}

/// Renderer-local state (selection/scroll) — kept out of the shared snapshot.
#[derive(Default)]
struct UiState {
    table: TableState,
}

impl UiState {
    fn move_selection(&mut self, delta: isize, len: usize) {
        if len == 0 {
            self.table.select(None);
            return;
        }
        let cur = self.table.selected().unwrap_or(0) as isize;
        let next = (cur + delta).rem_euclid(len as isize) as usize;
        self.table.select(Some(next));
    }
}

/// Run the TUI render/input loop until the user quits or `shutdown` fires.
/// Blocking; intended to run via `spawn_blocking`.
pub fn run_blocking(dashboard: Arc<Mutex<Dashboard>>, shutdown: watch::Sender<bool>) -> Result<()> {
    let mut terminal = setup_terminal()?;
    let mut ui = UiState::default();
    ui.table.select(Some(0));

    let result = (|| -> Result<()> {
        loop {
            {
                let dash = dashboard.lock().unwrap();
                terminal
                    .draw(|f| render(f, &dash, &mut ui))
                    .map_err(Error::Io)?;
            }

            if shutdown.is_closed() || *shutdown.borrow() {
                break;
            }
            if event::poll(Duration::from_millis(250)).map_err(Error::Io)? {
                if let Event::Key(key) = event::read().map_err(Error::Io)? {
                    if key.kind != KeyEventKind::Press {
                        continue;
                    }
                    let len = dashboard.lock().unwrap().devices.len();
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => break,
                        KeyCode::Down | KeyCode::Char('j') => ui.move_selection(1, len),
                        KeyCode::Up | KeyCode::Char('k') => ui.move_selection(-1, len),
                        _ => {}
                    }
                }
            }
        }
        Ok(())
    })();

    restore_terminal(&mut terminal)?;
    let _ = shutdown.send(true);
    result
}

type Tui = Terminal<CrosstermBackend<io::Stdout>>;

fn setup_terminal() -> Result<Tui> {
    enable_raw_mode().map_err(Error::Io)?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).map_err(Error::Io)?;
    Terminal::new(CrosstermBackend::new(stdout)).map_err(Error::Io)
}

fn restore_terminal(terminal: &mut Tui) -> Result<()> {
    disable_raw_mode().map_err(Error::Io)?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen).map_err(Error::Io)?;
    terminal.show_cursor().map_err(Error::Io)?;
    Ok(())
}

fn render(f: &mut Frame, dash: &Dashboard, ui: &mut UiState) {
    let chunks = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .split(f.area());

    render_header(f, chunks[0], dash);

    let body = Layout::horizontal([Constraint::Percentage(58), Constraint::Percentage(42)])
        .split(chunks[1]);
    render_devices(f, body[0], dash, ui);

    let right =
        Layout::vertical([Constraint::Percentage(50), Constraint::Percentage(50)]).split(body[1]);
    render_detail(f, right[0], dash, ui);
    render_alerts(f, right[1], dash);

    render_footer(f, chunks[2]);
}

fn render_header(f: &mut Frame, area: Rect, dash: &Dashboard) {
    let warns = dash
        .alerts
        .iter()
        .filter(|a| a.severity != Severity::Info)
        .count();
    let line = Line::from(vec![
        Span::styled(
            " lanscope ",
            Style::new().fg(Color::Black).bg(Color::Cyan).bold(),
        ),
        Span::raw("  backend: "),
        Span::styled(&dash.backend, Style::new().fg(Color::Green)),
        Span::raw("  mode: "),
        Span::styled(&dash.mode, Style::new().fg(Color::Yellow)),
        Span::raw(format!("  devices: {}", dash.devices.len())),
        Span::styled(
            format!("  alerts: {} ({} warn+)", dash.alerts.len(), warns),
            Style::new().fg(if warns > 0 { Color::Red } else { Color::Gray }),
        ),
    ]);
    f.render_widget(
        Paragraph::new(line).block(Block::default().borders(Borders::ALL)),
        area,
    );
}

fn render_devices(f: &mut Frame, area: Rect, dash: &Dashboard, ui: &mut UiState) {
    let rows = dash.devices.iter().map(|d| {
        Row::new(vec![
            Cell::from(d.mac.clone()),
            Cell::from(d.device_type.clone().unwrap_or_else(|| "—".into())),
            Cell::from(
                d.hostname
                    .clone()
                    .or_else(|| d.vendor.clone())
                    .unwrap_or_else(|| "—".into()),
            ),
            Cell::from(d.ips.last().cloned().unwrap_or_else(|| "—".into())),
        ])
    });
    let widths = [
        Constraint::Length(18),
        Constraint::Length(20),
        Constraint::Min(14),
        Constraint::Length(16),
    ];
    let table = Table::new(rows, widths)
        .header(
            Row::new(["MAC", "TYPE", "NAME / VENDOR", "IP"])
                .style(Style::new().bold().fg(Color::Cyan)),
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" Devices ({}) ", dash.devices.len())),
        )
        .row_highlight_style(Style::new().bg(Color::DarkGray).bold())
        .highlight_symbol("▶ ");
    f.render_stateful_widget(table, area, &mut ui.table);
}

fn render_detail(f: &mut Frame, area: Rect, dash: &Dashboard, ui: &mut UiState) {
    let block = Block::default().borders(Borders::ALL).title(" Detail ");
    let Some(dev) = ui.table.selected().and_then(|i| dash.devices.get(i)) else {
        f.render_widget(Paragraph::new("No device selected.").block(block), area);
        return;
    };

    let mut lines = vec![
        kv("MAC", &dev.mac),
        kv("Type", dev.device_type.as_deref().unwrap_or("—")),
        kv("Vendor", dev.vendor.as_deref().unwrap_or("—")),
        kv("Hostname", dev.hostname.as_deref().unwrap_or("—")),
        kv(
            "IPs",
            &if dev.ips.is_empty() {
                "—".to_string()
            } else {
                dev.ips.join(", ")
            },
        ),
        kv("DHCP fp", dev.dhcp_fingerprint.as_deref().unwrap_or("—")),
        kv(
            "Traffic",
            &format!("{} pkts / {} bytes", dev.packets, dev.bytes),
        ),
        kv("First seen", &netfmt::fmt_ts(dev.first_seen)),
        kv("Last seen", &netfmt::fmt_ts(dev.last_seen)),
    ];
    if !dev.services.is_empty() {
        lines.push(Line::from(Span::styled(
            "Services:",
            Style::new().fg(Color::Cyan),
        )));
        for s in dev.services.iter().take(6) {
            lines.push(Line::from(format!("  • {s}")));
        }
    }
    f.render_widget(
        Paragraph::new(lines).block(block).wrap(Wrap { trim: true }),
        area,
    );
}

fn render_alerts(f: &mut Frame, area: Rect, dash: &Dashboard) {
    let items: Vec<ListItem> = dash
        .alerts
        .iter()
        .map(|a| {
            let color = match a.severity {
                Severity::Info => Color::Gray,
                Severity::Warning => Color::Yellow,
                Severity::Critical => Color::Red,
            };
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("{} ", netfmt::fmt_ts(a.ts)),
                    Style::new().fg(Color::DarkGray),
                ),
                Span::styled(
                    format!("[{}] ", a.severity.as_str()),
                    Style::new().fg(color).bold(),
                ),
                Span::raw(a.message.clone()),
            ]))
        })
        .collect();
    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" Alerts ({}) ", dash.alerts.len())),
    );
    f.render_widget(list, area);
}

fn render_footer(f: &mut Frame, area: Rect) {
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(" ↑/↓ ", Style::new().fg(Color::Cyan)),
            Span::raw("select  "),
            Span::styled("q ", Style::new().fg(Color::Cyan)),
            Span::raw("quit"),
        ]))
        .style(Style::new().bg(Color::Black)),
        area,
    );
}

fn kv<'a>(key: &'a str, value: &str) -> Line<'a> {
    Line::from(vec![
        Span::styled(format!("{key:<11}"), Style::new().fg(Color::Cyan)),
        Span::raw(value.to_string()),
    ])
}
