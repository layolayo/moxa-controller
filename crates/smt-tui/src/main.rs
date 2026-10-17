//! `smt-tui` — High-frame-rate `ratatui` Operator & Reverse-Engineering Console
//! for Moxa NPort Serial Device Servers (`NPort 5610-8-DT`, `5450`, `5250A`, `5110`, etc.).
//!
//! Designed to run alongside the main SMT Wayland desktop control software or over SSH.

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

struct AppUiState {
    selected_port: u8,
    input_mode: bool,
    input_buffer: String,
    demo_model_idx: usize,
}

impl AppUiState {
    fn new() -> Self {
        Self {
            selected_port: 1,
            input_mode: false,
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
            Constraint::Length(4),            // Command & Keybinding Bar
            Constraint::Min(8),               // Live Byte-Diff & Checksum Frame Inspector
            Constraint::Length(5),            // Event Log / Frame Injection Prompt
        ])
        .split(frame.area());

    // 1. Top Hardware & Model Auto-Detection Banner
    let rec_badge = match &st.jsonl_path {
        Some(p) => Span::styled(
            format!(" ● REC: {} ", p.display()),
            Style::default().fg(Color::White).bg(Color::Red).add_modifier(Modifier::BOLD),
        ),
        None => Span::styled(
            " ○ REC: OFF ",
            Style::default().fg(Color::Gray),
        ),
    };

    let banner_line = Line::from(vec![
        Span::styled(
            format!(" {} ({}-Port {}) ", st.profile.model_name, st.profile.port_count, st.profile.interfaces),
            Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD),
        ),
        Span::raw(" "),
        Span::styled(
            format!("Host: {} ", st.host),
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("| Connector: {} | Detected via: {} | Mode: {} ", st.profile.connector, st.discovery_method, st.mode_banner),
            Style::default().fg(Color::White),
        ),
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
        "UART",
        "OUT (DTR/RTS)",
        "IN (CTS/DSR/DCD)",
        "RX (Frames/Bytes)",
        "TX (Frames/Bytes)",
    ]
    .into_iter()
    .map(|h| Cell::from(h).style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)));

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

        Row::new(vec![
            Cell::from(format!("{marker}P{}", ps.port_num)),
            Cell::from(format!(":{}", ps.data_tcp_port())),
            Cell::from(format!(":{}", ps.aspp_tcp_port())),
            Cell::from(ps.role.clone()),
            Cell::from(format!("{:>6} {}", ps.baud, ps.framing.as_str())),
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
        Constraint::Length(7),
        Constraint::Length(7),
        Constraint::Length(7),
        Constraint::Length(18),
        Constraint::Length(12),
        Constraint::Length(15),
        Constraint::Length(18),
        Constraint::Length(18),
        Constraint::Length(18),
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

    // 3. Keybinding & Protocol Control Bar
    let (pa, pb) = adjacent_port_pair(ui.selected_port, st.profile.port_count);
    let controls_text = vec![
        Line::from(vec![
            Span::styled("[1-8/↑↓]", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw(format!(" Select P{}  ", ui.selected_port)),
            Span::styled("[c]", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
            Span::raw(" Connect/Disc  "),
            Span::styled("[b]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::raw(" Baud  "),
            Span::styled("[f]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::raw(" Framing  "),
            Span::styled("[d]", Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)),
            Span::raw(" DTR  "),
            Span::styled("[r]", Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)),
            Span::raw(" RTS  "),
            Span::styled("[x]", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw(" Flush FIFO  "),
            Span::styled("[k]", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
            Span::raw(" Send BREAK"),
        ]),
        Line::from(vec![
            Span::styled("[t]", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw(format!(" Passive Tap (P{pa}+P{pb})  ")),
            Span::styled("[v]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::raw(format!(" Active MITM (P{pa}⟷P{pb})  ")),
            Span::styled("[i]", Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)),
            Span::raw(" Inject TX  "),
            Span::styled("[p]", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
            Span::raw(" Auto-Detect Model  "),
            Span::styled("[u]", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
            Span::raw(" UDP 4800 Scan  "),
            Span::styled("[m]", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw(" Cycle Demo Model  "),
            Span::styled("[l]", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
            Span::raw(" JSONL Rec  "),
            Span::styled("[q]", Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
            Span::raw(" Quit"),
        ]),
    ];
    let controls_block = Paragraph::new(controls_text)
        .block(Block::default().borders(Borders::ALL).title(" Hardware & Protocol Controls "));
    frame.render_widget(controls_block, chunks[2]);

    // 4. Live Framed Packet Inspector with Byte-Diff Highlighting & CRC-16/MODBUS
    render_frame_inspector(frame, chunks[3], &st);

    // 5. Event Log or Modal Injection Input Bar
    if ui.input_mode {
        let prompt = Paragraph::new(format!(
            "Inject on Port {} (ASCII e.g. \\x0201POLL\\x03 or Hex e.g. hex:02 30 31 03): {}█",
            ui.selected_port, ui.input_buffer
        ))
        .style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Transmit / Inject Serial Frame (Enter = Send, Esc = Cancel) "),
        );
        frame.render_widget(prompt, chunks[4]);
    } else {
        let logs: Vec<Line> = st
            .status_log
            .iter()
            .rev()
            .take(3)
            .rev()
            .map(|entry| {
                let style = if entry.contains("ERROR") || entry.contains("WARNING") {
                    Style::default().fg(Color::Red)
                } else if entry.contains("NOTE:") {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default().fg(Color::Gray)
                };
                Line::from(Span::styled(entry.clone(), style))
            })
            .collect();
        let log_block = Paragraph::new(logs)
            .block(Block::default().borders(Borders::ALL).title(" System & Discovery Event Log "));
        frame.render_widget(log_block, chunks[4]);
    }
}

fn render_frame_inspector(
    frame: &mut Frame,
    area: Rect,
    st: &nport5610_core::SharedEngineState,
) {
    let max_rows = area.height.saturating_sub(3) as usize;
    let visible: Vec<_> = st.frames.iter().rev().take(max_rows).rev().collect();

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

        // Render up to 15 hex bytes with byte-diff highlighting
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

    let block = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Live Framed Serial Packet Inspector (Magenta Byte = Changed Since Previous Frame) "),
    );
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
        "PORT  DATA    ASPP   ROLE              UART        OUT(DTR/RTS)  IN(CTS/DSR/DCD)   RX(F/B)      TX(F/B)"
    );
    println!("{}", "-".repeat(106));
    for ps in &st.ports {
        println!(
            "P{:<2}  :{:<5} :{:<4}  {:<16}  {:>6} {}  DTR:{} RTS:{}   CTS:{} DSR:{} DCD:{}    {:>3}/{:>5}B   {:>3}/{:>5}B",
            ps.port_num,
            ps.data_tcp_port(),
            ps.aspp_tcp_port(),
            ps.role,
            ps.baud,
            ps.framing.as_str(),
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
    println!("{}", "-".repeat(106));
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
    let mut host = String::from("192.168.127.254");
    let mut demo = false;
    let mut snapshot = false;
    let mut gap_ms = 8.0f64;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--demo" => demo = true,
            "--snapshot" => snapshot = true,
            "--gap-ms" => {
                if let Some(v) = args.next() {
                    gap_ms = v.parse().unwrap_or(8.0);
                }
            }
            "-h" | "--help" => {
                println!("Usage: smt-tui [NPORT_IP] [--demo] [--snapshot] [--gap-ms MS]");
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

    if snapshot {
        if demo {
            tokio::time::sleep(Duration::from_millis(2100)).await;
        }
        print_snapshot(&ctrl);
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

        if ui.input_mode {
            match key.code {
                KeyCode::Esc => {
                    ui.input_mode = false;
                    ui.input_buffer.clear();
                }
                KeyCode::Enter => {
                    let raw = ui.input_buffer.trim().to_string();
                    ui.input_mode = false;
                    ui.input_buffer.clear();
                    if !raw.is_empty() {
                        match parse_payload_input(&raw) {
                            Ok(bytes) => ctrl.inject_payload(ui.selected_port, bytes).await,
                            Err(e) => ctrl
                                .state
                                .lock()
                                .unwrap()
                                .log_event(format!("ERROR parsing payload: {e}")),
                        }
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
                    ctrl.connect_port(ui.selected_port, "STREAM").await;
                }
            }
            KeyCode::Char('b') | KeyCode::Char('B') => {
                ctrl.cycle_baud(ui.selected_port).await;
            }
            KeyCode::Char('f') | KeyCode::Char('F') => {
                ctrl.cycle_framing(ui.selected_port).await;
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
                        st.log_event("UDP 4800 scan finished: no remote NPort units responded on LAN");
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
                // Cycle simulated Moxa NPort hardware model to demonstrate dynamic UI adaptation
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
            KeyCode::Char('g') | KeyCode::Char('G') => {
                let mut st = ctrl.state.lock().unwrap();
                st.frames.clear();
                st.log_event("Cleared frame inspector display buffer");
            }
            KeyCode::Char('i') | KeyCode::Char('I') => {
                ui.input_mode = true;
                ui.input_buffer.clear();
            }
            _ => {}
        }
    }
    Ok(())
}
