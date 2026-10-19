//! `smt-tui` — High-frame-rate `ratatui` Operator & Reverse-Engineering Console
//! for Moxa NPort Serial Device Servers (`NPort 5610-8-DT`, `5450`, `5250A`, `5110`, etc.).
//!
//! Includes on-demand stream logging (`[l]`), instant rolling-buffer dump to disk (`[w]`),
//! and live operator log annotations (`[n]`).

use std::io;
use std::time::Duration;

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use nport5610_core::{
    adjacent_port_pair, discover_nports_udp, parse_payload_input, DiscoveredNPort,
    NPortController, NPortModelProfile,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table};
use ratatui::{Frame, Terminal};

#[derive(PartialEq, Eq)]
enum PromptKind {
    None,
    LiveTerminal,
    InjectFrame,
    AnnotateLog,
    ChangeHostIp,
    FilterSearch,
}

struct AppUiState {
    selected_port: u8,
    prompt_kind: PromptKind,
    terminal_view: bool,
    input_buffer: String,
    demo_model_idx: usize,
}

impl AppUiState {
    fn new() -> Self {
        Self {
            selected_port: 1,
            prompt_kind: PromptKind::None,
            terminal_view: true,
            input_buffer: String::new(),
            demo_model_idx: 0,
        }
    }
}

const DEMO_MODEL_IDS: [u16; 4] = [0x5610, 0x5450, 0x5250, 0x5110];

fn render_ui(frame: &mut Frame, ctrl: &NPortController, ui: &AppUiState) {
    let st = ctrl.state.lock().unwrap();
    let port_count = st.ports.len();
    let table_height = (port_count as u16 + 4).clamp(5, 14);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),            // Top hardware & model auto-detection banner
            Constraint::Length(table_height), // Dynamic NPort Port Matrix (adapts to 1/2/4/8/16 ports)
            Constraint::Length(5),            // Command, Stream Pause/Stop & Filter Keybinding Bar
            Constraint::Min(8),               // PuTTY Live Terminal Viewer OR Packet Inspector
            Constraint::Length(5),            // Event Log / Modal Prompt / PuTTY Typing Status
        ])
        .split(frame.area());

    // 1. Top Hardware & Model Auto-Detection Banner
    let rec_badge = match &st.text_log_path {
        Some(p) => Span::styled(
            format!(" ● LOGGING: {} ", p.display()),
            Style::default()
                .fg(Color::White)
                .bg(Color::Red)
                .add_modifier(Modifier::BOLD),
        ),
        None => Span::styled(" ○ LOG: OFF ([l] Live / [w] Dump) ", Style::default().fg(Color::Gray)),
    };

    let pause_badge = if st.stream_paused {
        Span::styled(
            format!(" ⏸ PAUSED ({} skipped) ", st.paused_skipped_frames),
            Style::default()
                .fg(Color::Black)
                .bg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(" ▶ LIVE ", Style::default().fg(Color::Green))
    };

    let banner_line = Line::from(vec![
        Span::styled(
            format!(
                " {} ({}-Port {}) ",
                st.profile.model_name, st.profile.port_count, st.profile.interfaces
            ),
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" "),
        Span::styled(
            format!("Host: {} ", st.host),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(
                "| {} | Via: {} | Mode: {} ",
                st.profile.connector, st.discovery_method, st.mode_banner
            ),
            Style::default().fg(Color::White),
        ),
        pause_badge,
        rec_badge,
    ]);

    let banner_block = Paragraph::new(banner_line).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Moxa NPort Adaptive Connection & Control Console "),
    );
    frame.render_widget(banner_block, chunks[0]);

    // 2. Dynamic Multi-Port Status Matrix
    let header_cells = [
        "PORT",
        "DATA",
        "ASPP",
        "ROLE",
        "UART / IFACE / FLOW",
        "OUT (DTR/RTS)",
        "IN (CTS/DSR/DCD)",
        "RX (Frames/Bytes)",
        "TX (Frames/Bytes)",
    ]
    .into_iter()
    .map(|h| {
        Cell::from(h).style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
    });

    let header = Row::new(header_cells).height(1);

    let rows = st.ports.iter().map(|ps| {
        let is_sel = ps.port_num == ui.selected_port;
        let marker = if is_sel { "▶ " } else { "  " };
        let style = if is_sel {
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else if ps.connected {
            Style::default().fg(Color::Green)
        } else {
            Style::default().fg(Color::White)
        };

        let port_label = if ps.alias.is_empty() {
            format!("{marker}P{}", ps.port_num)
        } else {
            format!("{marker}P{} {}", ps.port_num, ps.alias)
        };
        let role_label = if ps.role == "IDLE" {
            format!("IDLE ({})", ps.op_mode)
        } else {
            ps.role.clone()
        };

        Row::new(vec![
            Cell::from(port_label),
            Cell::from(format!(":{}", ps.data_tcp_port())),
            Cell::from(format!(":{}", ps.aspp_tcp_port())),
            Cell::from(role_label),
            Cell::from(format!(
                "{:>6} {} {} {}",
                ps.baud,
                ps.framing.as_str(),
                ps.interface.as_str(),
                ps.flow_control.as_str()
            )),
            Cell::from(format!(
                "DTR:{} RTS:{}",
                u8::from(ps.dtr),
                u8::from(ps.rts)
            )),
            Cell::from(format!(
                "CTS:{} DSR:{} DCD:{}",
                u8::from(ps.modem.cts),
                u8::from(ps.modem.dsr),
                u8::from(ps.modem.dcd)
            )),
            Cell::from(format!("{:>4} / {:>6} B", ps.rx_frames, ps.rx_bytes)),
            Cell::from(format!("{:>4} / {:>6} B", ps.tx_frames, ps.tx_bytes)),
        ])
        .style(style)
    });

    let widths = [
        Constraint::Length(12),
        Constraint::Length(6),
        Constraint::Length(6),
        Constraint::Length(16),
        Constraint::Length(27),
        Constraint::Length(13),
        Constraint::Length(17),
        Constraint::Length(16),
        Constraint::Length(16),
    ];

    let ports_table = Table::new(rows, widths).header(header).block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(
                " Serial Channels (1..{}) — Auto-Adapted to {} ",
                st.profile.port_count, st.profile.model_name
            )),
    );
    frame.render_widget(ports_table, chunks[1]);

    // 3. Keybinding, PuTTY Terminal, Pause/Stop Stream & Filter Control Bar
    let (pa, pb) = adjacent_port_pair(ui.selected_port, st.profile.port_count);
    let view_mode_label = if ui.terminal_view || ui.prompt_kind == PromptKind::LiveTerminal {
        "PuTTY Terminal"
    } else {
        "Packet Inspector"
    };
    let controls_text = vec![
        Line::from(vec![
            Span::styled(
                "[Enter]",
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(" PuTTY Live Type (P{})  ", ui.selected_port)),
            Span::styled(
                "[Tab]",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(" View({view_mode_label})  ")),
            Span::styled(
                "[1-8/↑↓]",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(" Select P{}  ", ui.selected_port)),
            Span::styled(
                "[c]",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" Connect  "),
            Span::styled(
                "[b/f/j/e]",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" Baud/Frame/Flow/Iface  "),
            Span::styled(
                "[d/r]",
                Style::default()
                    .fg(Color::Magenta)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" DTR/RTS  "),
            Span::styled(
                "[i]",
                Style::default()
                    .fg(Color::Magenta)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" Inject Hex/ASCII"),
        ]),
        Line::from(vec![
            Span::styled(
                "[Space]",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" Pause  "),
            Span::styled(
                "[s]",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            Span::raw(" Stop All  "),
            Span::styled(
                "[/]",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" Search Filter  "),
            Span::styled(
                "[o]",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(" Dir({})  ", st.filter.direction.as_str())),
            Span::styled(
                "[h]",
                Style::default()
                    .fg(Color::Magenta)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(
                " ChangedOnly({})  ",
                if st.filter.only_changed { "ON" } else { "OFF" }
            )),
            Span::styled(
                "[y]",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(
                " PortFilter({})  ",
                st.filter
                    .port_filter
                    .map(|p| format!("P{p}"))
                    .unwrap_or_else(|| String::from("ALL"))
            )),
            Span::styled(
                "[z]",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" Reset Filters"),
        ]),
        Line::from(vec![
            Span::styled(
                "[l]",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            Span::raw(" Live Log  "),
            Span::styled(
                "[w]",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" Dump Log  "),
            Span::styled(
                "[n]",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" Note  "),
            Span::styled(
                "[g]",
                Style::default()
                    .fg(Color::Magenta)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" Clear Screen/Buf  "),
            Span::styled(
                "[t/v]",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(" Tap/MITM(P{pa}⟷P{pb})  ")),
            Span::styled(
                "[a]",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" Set IP  "),
            Span::styled(
                "[p]",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" Probe  "),
            Span::styled(
                "[q]",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" Quit"),
        ]),
    ];
    let controls_block = Paragraph::new(controls_text).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" PuTTY Live Terminal, Stream Pause/Stop, Multi-Option Filtering & Logging Controls "),
    );
    frame.render_widget(controls_block, chunks[2]);

    // 4. PuTTY Live Text TX/RX Terminal Viewer OR Framed Packet Inspector
    if ui.terminal_view || ui.prompt_kind == PromptKind::LiveTerminal {
        render_terminal_viewer(frame, chunks[3], &st, ui);
    } else {
        render_frame_inspector(frame, chunks[3], &st);
    }

    // 5. Event Log or Modal Input Bar
    match ui.prompt_kind {
        PromptKind::LiveTerminal => {
            let echo_lbl = if st.terminal_local_echo { "ON" } else { "OFF" };
            let crlf_lbl = if st.terminal_crlf { "CR+LF (\\r\\n)" } else { "CR (\\r)" };
            let prompt = Paragraph::new(vec![
                Line::from(vec![
                    Span::styled(
                        format!(" 🟢 LIVE PUTTY TERMINAL TX/RX ACTIVE ON PORT {} ", ui.selected_port),
                        Style::default()
                            .fg(Color::Black)
                            .bg(Color::Green)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::raw("  Every keystroke transmits live over RS-232!"),
                ]),
                Line::from(vec![
                    Span::styled("[F1]", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                    Span::raw(format!(" Local Echo: {echo_lbl}   ")),
                    Span::styled("[F2]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                    Span::raw(format!(" Enter Sends: {crlf_lbl}   ")),
                    Span::styled("[F3]", Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)),
                    Span::raw(" Clear Terminal   "),
                    Span::styled("[Esc]", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
                    Span::raw(" Exit Live Typing Mode (Return to Hotkeys)"),
                ]),
            ])
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Green))
                    .title(" PuTTY Interactive Serial Terminal Mode (Type directly — Esc to exit) "),
            );
            frame.render_widget(prompt, chunks[4]);
        }
        PromptKind::InjectFrame => {
            let prompt = Paragraph::new(format!(
                "Inject on Port {} (ASCII e.g. \\x0201POLL\\x03 or Hex e.g. hex:02 30 31 03): {}█",
                ui.selected_port, ui.input_buffer
            ))
            .style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Transmit / Inject Serial Frame (Enter = Send, Esc = Cancel) "),
            );
            frame.render_widget(prompt, chunks[4]);
        }
        PromptKind::AnnotateLog => {
            let prompt = Paragraph::new(format!(
                "Log Note / Test Action Label (written to active .log & event history): {}█",
                ui.input_buffer
            ))
            .style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Add Timestamped Operator Annotation to Log (Enter = Record Note, Esc = Cancel) "),
            );
            frame.render_widget(prompt, chunks[4]);
        }
        PromptKind::ChangeHostIp => {
            let prompt = Paragraph::new(format!(
                "New Moxa NPort IP Address (e.g. 192.168.127.254, 10.0.0.50, or 'demo'): {}█",
                ui.input_buffer
            ))
            .style(
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            )
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Connect to New Moxa IP Address & Auto-Detect Model (Enter = Connect, Esc = Cancel) "),
            );
            frame.render_widget(prompt, chunks[4]);
        }
        PromptKind::FilterSearch => {
            let prompt = Paragraph::new(format!(
                "Filter Stream by Hex / ASCII / Source (leave empty to clear search filter): {}█",
                ui.input_buffer
            ))
            .style(
                Style::default()
                    .fg(Color::Magenta)
                    .add_modifier(Modifier::BOLD),
            )
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Set Stream Search Filter (Enter = Apply, Esc = Cancel) "),
            );
            frame.render_widget(prompt, chunks[4]);
        }
        PromptKind::None => {
            let logs: Vec<Line> = st
                .status_log
                .iter()
                .rev()
                .take(3)
                .rev()
                .map(|entry| {
                    let style = if entry.contains("ERROR") || entry.contains("WARNING") {
                        Style::default().fg(Color::Red)
                    } else if entry.contains("OPERATOR NOTE") || entry.contains("Dumped") || entry.contains("Live stream logging ON") {
                        Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)
                    } else if entry.contains("NOTE:") || entry.contains("PAUSED") {
                        Style::default().fg(Color::Yellow)
                    } else {
                        Style::default().fg(Color::Gray)
                    };
                    Line::from(Span::styled(entry.clone(), style))
                })
                .collect();
            let log_block = Paragraph::new(logs).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" System, Discovery & On-Demand Logging Event Log "),
            );
            frame.render_widget(log_block, chunks[4]);
        }
    }
}

fn render_terminal_viewer(
    frame: &mut Frame,
    area: Rect,
    st: &nport5610_core::SharedEngineState,
    ui: &AppUiState,
) {
    let is_live_typing = ui.prompt_kind == PromptKind::LiveTerminal;
    let max_rows = area.height.saturating_sub(2) as usize;

    let Some(ps) = st.ports.get((ui.selected_port - 1) as usize) else {
        return;
    };

    let alias_str = if ps.alias.is_empty() {
        String::new()
    } else {
        format!(" ({})", ps.alias)
    };
    let conn_str = if ps.connected { "ONLINE" } else { "DISCONNECTED" };
    let echo_str = if st.terminal_local_echo { "ON" } else { "OFF" };
    let crlf_str = if st.terminal_crlf { "CR+LF" } else { "CR" };

    let mut raw_lines: Vec<String> = if ps.terminal_text.is_empty() {
        vec![String::new()]
    } else {
        ps.terminal_text.split('\n').map(String::from).collect()
    };

    if is_live_typing {
        if let Some(last) = raw_lines.last_mut() {
            last.push('█');
        }
    }

    let mut lines: Vec<Line> = Vec::new();
    if ps.terminal_text.is_empty() && !is_live_typing {
        lines.push(Line::from(Span::styled(
            format!(
                "PuTTY Live Serial Terminal ready on Port {}{} (:{}, {} {} {}).",
                ps.port_num,
                alias_str,
                ps.data_tcp_port(),
                ps.baud,
                ps.framing.as_str(),
                ps.flow_control.as_str()
            ),
            Style::default().fg(Color::Cyan),
        )));
        lines.push(Line::from(Span::styled(
            "Press [Enter] to start live PuTTY character-by-character typing (TX/RX), or [Tab] to switch to Packet Inspector.",
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        )));
    } else {
        let start = raw_lines.len().saturating_sub(max_rows.max(1));
        for l in &raw_lines[start..] {
            lines.push(Line::from(Span::styled(
                l.clone(),
                Style::default().fg(Color::Green),
            )));
        }
    }

    let border_col = if is_live_typing {
        Color::Green
    } else {
        Color::Cyan
    };
    let mode_hint = if is_live_typing {
        "🟢 LIVE TYPING ACTIVE (Esc=Exit, F1=Echo, F2=CR+LF, F3=Clear)"
    } else {
        "Press [Enter] to Type Live | [Tab] Packet Inspector"
    };
    let title = format!(
        " 🖥 PuTTY Live Terminal — P{}{} [{}] (:{} @ {} {} {}) | Echo:{} Enter:{} | RX:{}B TX:{}B | {} ",
        ps.port_num,
        alias_str,
        conn_str,
        ps.data_tcp_port(),
        ps.baud,
        ps.framing.as_str(),
        ps.flow_control.as_str(),
        echo_str,
        crlf_str,
        ps.rx_bytes,
        ps.tx_bytes,
        mode_hint
    );

    let block = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border_col))
            .title(title),
    );
    frame.render_widget(block, area);
}

fn render_frame_inspector(
    frame: &mut Frame,
    area: Rect,
    st: &nport5610_core::SharedEngineState,
) {
    let max_rows = area.height.saturating_sub(3) as usize;
    let matching = st.filtered_frames();
    let total = st.frames.len();
    let visible: Vec<_> = matching.iter().rev().take(max_rows).rev().collect();

    let mut lines = Vec::with_capacity(visible.len() + 1);
    lines.push(Line::from(vec![Span::styled(
        "SEQ    TIMESTAMP     +DELTA(ms)  SOURCE          LEN   HEX PAYLOAD (Changed Bytes Highlighted)         ASCII              CHECKSUMS (XOR / LRC / CRC16)",
        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
    )]));

    for fr in visible {
        let base_color = if fr.direction.contains("CTRL→DEV") || fr.direction.starts_with("P1") {
            Color::Cyan
        } else if fr.direction.contains("DEV→CTRL") || fr.direction.starts_with("P2") {
            Color::Yellow
        } else if fr.direction.contains("TX") {
            Color::Magenta
        } else {
            Color::Green
        };

        let mut spans = vec![Span::styled(
            format!(
                "#{:<5} {}  +{:>8.2}  {:<14}  {:>3}B  ",
                fr.seq,
                fr.timestamp.format("%H:%M:%S%.3f"),
                fr.delta_ms,
                fr.direction,
                fr.payload.len()
            ),
            Style::default().fg(base_color),
        )];

        let max_hex_bytes = 15usize;
        for (idx, &b) in fr.payload.iter().take(max_hex_bytes).enumerate() {
            let is_changed = fr.changed_indices.contains(&idx);
            let byte_style = if is_changed {
                Style::default()
                    .fg(Color::White)
                    .bg(Color::Magenta)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(base_color)
            };
            spans.push(Span::styled(format!("{b:02X}"), byte_style));
            spans.push(Span::raw(" "));
        }
        if fr.payload.len() < max_hex_bytes {
            let pad = (max_hex_bytes - fr.payload.len()) * 3;
            spans.push(Span::raw(" ".repeat(pad)));
        } else if fr.payload.len() > max_hex_bytes {
            spans.push(Span::styled("..", Style::default().fg(Color::DarkGray)));
        } else {
            spans.push(Span::raw("  "));
        }

        let ascii_preview: String = fr.ascii_string().chars().take(16).collect();
        spans.push(Span::styled(
            format!("  {:<16}   ", ascii_preview),
            Style::default().fg(Color::White),
        ));
        spans.push(Span::styled(
            format!(
                "XOR:{:02X} LRC:{:02X} CRC16:{:04X}",
                fr.checksums.xor8, fr.checksums.lrc, fr.checksums.crc16_modbus
            ),
            Style::default().fg(Color::Gray),
        ));

        lines.push(Line::from(spans));
    }

    let title = format!(
        " Packet Inspector — Showing {}/{} frames | Filter: {} ",
        matching.len(),
        total,
        st.filter.summary()
    );
    let block = Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(title));
    frame.render_widget(block, area);
}

fn print_snapshot(ctrl: &NPortController) {
    let st = ctrl.state.lock().unwrap();
    println!(
        "=== MOXA {} ({}-Port {}) | Host: {} | Detected via: {} ===",
        st.profile.model_name,
        st.profile.port_count,
        st.profile.interfaces,
        st.host,
        st.discovery_method
    );
    println!(
        "PORT         DATA    ASPP   ROLE              UART / IFACE / FLOW         OUT(DTR/RTS)  IN(CTS/DSR/DCD)   RX(F/B)      TX(F/B)"
    );
    println!("{}", "-".repeat(128));
    for ps in &st.ports {
        let port_lbl = if ps.alias.is_empty() {
            format!("P{}", ps.port_num)
        } else {
            format!("P{} {}", ps.port_num, ps.alias)
        };
        let role_lbl = if ps.role == "IDLE" {
            format!("IDLE ({})", ps.op_mode)
        } else {
            ps.role.clone()
        };
        println!(
            "{:<11}  :{:<5} :{:<4}  {:<16}  {:>6} {} {:<9} {:<7} DTR:{} RTS:{}   CTS:{} DSR:{} DCD:{}    {:>3}/{:>5}B   {:>3}/{:>5}B",
            port_lbl,
            ps.data_tcp_port(),
            ps.aspp_tcp_port(),
            role_lbl,
            ps.baud,
            ps.framing.as_str(),
            ps.interface.as_str(),
            ps.flow_control.as_str(),
            u8::from(ps.dtr),
            u8::from(ps.rts),
            u8::from(ps.modem.cts),
            u8::from(ps.modem.dsr),
            u8::from(ps.modem.dcd),
            ps.rx_frames,
            ps.rx_bytes,
            ps.tx_frames,
            ps.tx_bytes
        );
    }
    println!("{}", "-".repeat(128));
    for fr in st.frames.iter().rev().take(6).rev() {
        println!(
            "#{:<3} [{} +{:>6.2}ms] {:<14} ({:>2}B) | {:<42} | {:<16} | XOR:{:02X} LRC:{:02X} CRC16:{:04X} | Diff:{:?}",
            fr.seq,
            fr.timestamp.format("%H:%M:%S%.3f"),
            fr.delta_ms,
            fr.direction,
            fr.payload.len(),
            fr.hex_string(),
            fr.ascii_string(),
            fr.checksums.xor8,
            fr.checksums.lrc,
            fr.checksums.crc16_modbus,
            fr.changed_indices
        );
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut host = String::from("192.168.1.249");
    let mut demo = false;
    let mut snapshot = false;
    let mut start_log: Option<String> = None;
    let mut gap_ms = 8.0f64;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--demo" => demo = true,
            "--snapshot" => snapshot = true,
            "--log" => {
                start_log = Some(String::from("session"));
            }
            "--gap-ms" => {
                if let Some(v) = args.next() {
                    gap_ms = v.parse().unwrap_or(8.0);
                }
            }
            "-h" | "--help" => {
                println!(
                    "Usage: smt-tui [NPORT_IP] [--demo] [--log] [--snapshot] [--gap-ms MS]"
                );
                return Ok(());
            }
            other if !other.starts_with('-') => {
                host = other.to_string();
            }
            _ => {}
        }
    }

    let ctrl = NPortController::new(host, gap_ms, demo);
    if !demo {
        ctrl.probe_all_ports().await;
    }
    if let Some(lbl) = start_log {
        ctrl.state.lock().unwrap().toggle_jsonl(Some(&lbl));
    }

    if snapshot {
        if demo {
            tokio::time::sleep(Duration::from_millis(2100)).await;
        }
        let dumped = ctrl.state.lock().unwrap().dump_buffer_on_demand(Some("snapshot"));
        print_snapshot(&ctrl);
        if let Some(path) = dumped {
            println!("Saved on-demand stream log dump to: {}", path.display());
        }
        return Ok(());
    }

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut ui = AppUiState::new();
    let res = run_event_loop(&mut terminal, &ctrl, &mut ui).await;

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    res
}

async fn run_event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    ctrl: &NPortController,
    ui: &mut AppUiState,
) -> Result<()> {
    loop {
        terminal.draw(|f| render_ui(f, ctrl, ui))?;

        if !event::poll(Duration::from_millis(50))? {
            continue;
        }
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }

        if ui.prompt_kind == PromptKind::LiveTerminal {
            match key.code {
                KeyCode::Esc => {
                    ui.prompt_kind = PromptKind::None;
                }
                KeyCode::F(1) => {
                    let mut st = ctrl.state.lock().unwrap();
                    st.terminal_local_echo = !st.terminal_local_echo;
                    let on_off = if st.terminal_local_echo { "ON" } else { "OFF" };
                    st.log_event(format!("PuTTY Terminal Local Echo -> {on_off}"));
                }
                KeyCode::F(2) => {
                    let mut st = ctrl.state.lock().unwrap();
                    st.terminal_crlf = !st.terminal_crlf;
                    let mode = if st.terminal_crlf {
                        "CR+LF (\\r\\n)"
                    } else {
                        "CR (\\r)"
                    };
                    st.log_event(format!("PuTTY Terminal Enter line ending -> {mode}"));
                }
                KeyCode::F(3) => {
                    let mut st = ctrl.state.lock().unwrap();
                    if let Some(ps) = st.ports.get_mut((ui.selected_port - 1) as usize) {
                        ps.clear_terminal();
                    }
                    st.log_event(format!("Cleared Port {} terminal screen", ui.selected_port));
                }
                KeyCode::Enter => {
                    let crlf = { ctrl.state.lock().unwrap().terminal_crlf };
                    let bytes = if crlf {
                        b"\r\n".to_vec()
                    } else {
                        b"\r".to_vec()
                    };
                    ctrl.send_terminal_bytes(ui.selected_port, bytes).await;
                }
                KeyCode::Backspace => {
                    ctrl.send_terminal_bytes(ui.selected_port, vec![0x08]).await;
                }
                KeyCode::Tab => {
                    ctrl.send_terminal_bytes(ui.selected_port, vec![b'\t']).await;
                }
                KeyCode::Char(c) => {
                    let mut buf = [0u8; 4];
                    let bytes = c.encode_utf8(&mut buf).as_bytes().to_vec();
                    ctrl.send_terminal_bytes(ui.selected_port, bytes).await;
                }
                _ => {}
            }
            continue;
        }

        if ui.prompt_kind != PromptKind::None {
            match key.code {
                KeyCode::Esc => {
                    ui.prompt_kind = PromptKind::None;
                    ui.input_buffer.clear();
                }
                KeyCode::Enter => {
                    let raw = ui.input_buffer.trim().to_string();
                    let mode = std::mem::replace(&mut ui.prompt_kind, PromptKind::None);
                    ui.input_buffer.clear();
                    match mode {
                        PromptKind::FilterSearch => {
                            let mut st = ctrl.state.lock().unwrap();
                            st.filter.search_query = raw.clone();
                            let summary = st.filter.summary();
                            st.log_event(format!("Updated stream filter -> {summary}"));
                        }
                        PromptKind::InjectFrame if !raw.is_empty() => {
                            match parse_payload_input(&raw) {
                                Ok(bytes) => ctrl.inject_payload(ui.selected_port, bytes).await,
                                Err(e) => ctrl
                                    .state
                                    .lock()
                                    .unwrap()
                                    .log_event(format!("ERROR parsing payload: {e}")),
                            }
                        }
                        PromptKind::AnnotateLog if !raw.is_empty() => {
                            ctrl.state.lock().unwrap().annotate_log(&raw);
                        }
                        PromptKind::ChangeHostIp if !raw.is_empty() => {
                            ctrl.switch_target_host(&raw).await;
                            let new_max = ctrl.state.lock().unwrap().profile.port_count;
                            if ui.selected_port > new_max {
                                ui.selected_port = new_max;
                            }
                        }
                        _ => {}
                    }
                }
                KeyCode::Backspace => {
                    ui.input_buffer.pop();
                }
                KeyCode::Char(c) => {
                    ui.input_buffer.push(c);
                }
                _ => {}
            }
            continue;
        }

        let max_ports = { ctrl.state.lock().unwrap().profile.port_count };
        match key.code {
            KeyCode::Char('q') | KeyCode::Char('Q') => break,
            KeyCode::Tab => {
                ui.terminal_view = !ui.terminal_view;
            }
            KeyCode::Enter => {
                ui.terminal_view = true;
                ui.prompt_kind = PromptKind::LiveTerminal;
                let is_conn = {
                    let st = ctrl.state.lock().unwrap();
                    st.ports
                        .get((ui.selected_port - 1) as usize)
                        .map(|p| p.connected)
                        .unwrap_or(false)
                };
                if !is_conn {
                    ctrl.connect_port(ui.selected_port, "TERMINAL").await;
                }
            }
            KeyCode::Char(' ') => {
                ctrl.state.lock().unwrap().toggle_pause();
            }
            KeyCode::Char('s') | KeyCode::Char('S') => {
                ctrl.stop_all_streams();
            }
            KeyCode::Char('/') => {
                ui.prompt_kind = PromptKind::FilterSearch;
                ui.input_buffer = ctrl.state.lock().unwrap().filter.search_query.clone();
            }
            KeyCode::Char('o') | KeyCode::Char('O') => {
                let mut st = ctrl.state.lock().unwrap();
                st.filter.direction = st.filter.direction.next();
                let dir_str = st.filter.direction.as_str();
                st.log_event(format!("Direction filter set to: {dir_str}"));
            }
            KeyCode::Char('h') | KeyCode::Char('H') => {
                let mut st = ctrl.state.lock().unwrap();
                st.filter.only_changed = !st.filter.only_changed;
                let state_str = if st.filter.only_changed {
                    "ON (Hiding static heartbeats)"
                } else {
                    "OFF (Showing all frames)"
                };
                st.log_event(format!("Changed-Bytes-Only filter: {state_str}"));
            }
            KeyCode::Char('y') | KeyCode::Char('Y') => {
                let mut st = ctrl.state.lock().unwrap();
                if st.filter.port_filter == Some(ui.selected_port) {
                    st.filter.port_filter = None;
                    st.log_event("Port filter set to: ALL ports");
                } else {
                    st.filter.port_filter = Some(ui.selected_port);
                    st.log_event(format!("Port filter locked to: Port {}", ui.selected_port));
                }
            }
            KeyCode::Char('z') | KeyCode::Char('Z') => {
                let mut st = ctrl.state.lock().unwrap();
                st.filter.reset();
                st.log_event("Reset all stream filters (showing all frames)");
            }
            KeyCode::Char(c @ '1'..='8') => {
                let p = (c as u8) - b'0';
                if p <= max_ports {
                    ui.selected_port = p;
                }
            }
            KeyCode::Up => {
                ui.selected_port = if ui.selected_port <= 1 {
                    max_ports
                } else {
                    ui.selected_port - 1
                };
            }
            KeyCode::Down => {
                ui.selected_port = if ui.selected_port >= max_ports {
                    1
                } else {
                    ui.selected_port + 1
                };
            }
            KeyCode::Char('c') | KeyCode::Char('C') => {
                let is_conn = {
                    let st = ctrl.state.lock().unwrap();
                    st.ports
                        .get((ui.selected_port - 1) as usize)
                        .map(|p| p.connected)
                        .unwrap_or(false)
                };
                if is_conn {
                    ctrl.disconnect_port(ui.selected_port);
                } else {
                    ctrl.connect_port(ui.selected_port, "TERMINAL").await;
                }
            }
            KeyCode::Char('b') | KeyCode::Char('B') => {
                ctrl.cycle_baud(ui.selected_port).await;
            }
            KeyCode::Char('f') | KeyCode::Char('F') => {
                ctrl.cycle_framing(ui.selected_port).await;
            }
            KeyCode::Char('j') | KeyCode::Char('J') => {
                ctrl.cycle_flow_control(ui.selected_port).await;
            }
            KeyCode::Char('e') | KeyCode::Char('E') => {
                ctrl.cycle_interface(ui.selected_port).await;
            }
            KeyCode::Char('d') | KeyCode::Char('D') => {
                ctrl.toggle_dtr(ui.selected_port).await;
            }
            KeyCode::Char('r') | KeyCode::Char('R') => {
                ctrl.toggle_rts(ui.selected_port).await;
            }
            KeyCode::Char('x') | KeyCode::Char('X') => {
                ctrl.flush_fifo(ui.selected_port).await;
            }
            KeyCode::Char('k') | KeyCode::Char('K') => {
                ctrl.send_break(ui.selected_port).await;
            }
            KeyCode::Char('t') | KeyCode::Char('T') => {
                let (pa, pb) = adjacent_port_pair(ui.selected_port, max_ports);
                ctrl.start_passive_tap(pa, pb).await;
            }
            KeyCode::Char('v') | KeyCode::Char('V') => {
                let (pa, pb) = adjacent_port_pair(ui.selected_port, max_ports);
                ctrl.start_mitm_bridge(pa, pb).await;
            }
            KeyCode::Char('a') | KeyCode::Char('A') => {
                ui.prompt_kind = PromptKind::ChangeHostIp;
                ui.input_buffer = ctrl.state.lock().unwrap().host.clone();
            }
            KeyCode::Char('p') | KeyCode::Char('P') => {
                ctrl.probe_all_ports().await;
            }
            KeyCode::Char('u') | KeyCode::Char('U') => {
                ctrl.state
                    .lock()
                    .unwrap()
                    .log_event("Broadcasting Moxa UDP 4800 discovery query...");
                if let Ok(units) = discover_nports_udp(Duration::from_millis(900)).await {
                    let mut st = ctrl.state.lock().unwrap();
                    if units.is_empty() {
                        st.log_event(
                            "UDP 4800 scan finished: no remote NPort units responded on LAN",
                        );
                    } else {
                        for u in units {
                            st.log_event(format!(
                                "Discovered {} ({} ports) at {} [MAC {}]",
                                u.profile.model_name,
                                u.profile.port_count,
                                u.ip_address,
                                u.mac_address
                            ));
                        }
                    }
                }
            }
            KeyCode::Char('m') | KeyCode::Char('M') => {
                ui.demo_model_idx = (ui.demo_model_idx + 1) % DEMO_MODEL_IDS.len();
                let next_id = DEMO_MODEL_IDS[ui.demo_model_idx];
                let profile = NPortModelProfile::from_model_id(next_id);
                let new_max = profile.port_count;
                let mut st = ctrl.state.lock().unwrap();
                let host = st.host.clone();
                st.apply_detected_profile(DiscoveredNPort {
                    ip_address: host,
                    mac_address: String::from("00:90:E8:56:10:08"),
                    profile,
                    discovery_method: String::from("Simulated UDP 4800 Model Switch"),
                });
                if ui.selected_port > new_max {
                    ui.selected_port = new_max;
                }
            }
            KeyCode::Char('l') | KeyCode::Char('L') => {
                ctrl.state.lock().unwrap().toggle_jsonl(None);
            }
            KeyCode::Char('w') | KeyCode::Char('W') => {
                ctrl.state.lock().unwrap().dump_buffer_on_demand(None);
            }
            KeyCode::Char('n') | KeyCode::Char('N') => {
                ui.prompt_kind = PromptKind::AnnotateLog;
                ui.input_buffer.clear();
            }
            KeyCode::Char('g') | KeyCode::Char('G') => {
                let mut st = ctrl.state.lock().unwrap();
                if let Some(ps) = st.ports.get_mut((ui.selected_port - 1) as usize) {
                    ps.clear_terminal();
                }
                st.frames.clear();
                st.log_event(format!(
                    "Cleared Port {} terminal screen and frame inspector buffer",
                    ui.selected_port
                ));
            }
            KeyCode::Char('i') | KeyCode::Char('I') => {
                ui.prompt_kind = PromptKind::InjectFrame;
                ui.input_buffer.clear();
            }
            _ => {}
        }
    }
    Ok(())
}
