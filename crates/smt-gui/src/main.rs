//! `smt-gui` — Native Wayland/X11 Desktop GUI for Moxa NPort Connection,
//! Configuration, On-Demand Logging, and RS-232 Protocol Reverse-Engineering.

use std::time::Duration;

use eframe::egui::{self, Color32, FontId, RichText, ScrollArea, Stroke};
use nport5610_core::{
    adjacent_port_pair, discover_nports_udp, format_paste_bytes, parse_payload_input,
    DirectionFilter, DiscoveredNPort, FrameFilter, NPortController, NPortModelProfile, SerialFrame,
};

const DEMO_MODEL_IDS: [u16; 4] = [0x5610, 0x5450, 0x5250, 0x5110];

#[derive(Clone, Copy, PartialEq, Eq)]
enum CentreViewMode {
    PuttyTerminal,
    SplitTerminalAndPackets,
    PacketInspector,
}

struct SmtGuiApp {
    rt: tokio::runtime::Runtime,
    ctrl: NPortController,
    ip_input: String,
    selected_port: u8,
    view_mode: CentreViewMode,
    terminal_live_keystrokes: bool,
    terminal_line_input: String,
    tx_payload_input: String,
    log_note_input: String,
    min_len_input: String,
    max_len_input: String,
    selected_frame_seq: Option<u64>,
    discovered_units: Vec<DiscoveredNPort>,
    demo_model_idx: usize,
    auto_scroll: bool,
}

impl SmtGuiApp {
    fn new(cc: &eframe::CreationContext<'_>, initial_host: String, demo: bool) -> Self {
        cc.egui_ctx.set_visuals(egui::Visuals::dark());

        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Failed to initialise Tokio runtime");

        let ctrl = rt.block_on(async {
            let c = NPortController::new(initial_host.clone(), 8.0, demo);
            if !demo {
                c.probe_all_ports().await;
            }
            c
        });

        Self {
            rt,
            ctrl,
            ip_input: initial_host,
            selected_port: 1,
            view_mode: CentreViewMode::SplitTerminalAndPackets,
            terminal_live_keystrokes: true,
            terminal_line_input: String::new(),
            tx_payload_input: String::from("\\x0201POLL:99\\x03"),
            log_note_input: String::new(),
            min_len_input: String::new(),
            max_len_input: String::new(),
            selected_frame_seq: None,
            discovered_units: Vec::new(),
            demo_model_idx: 0,
            auto_scroll: true,
        }
    }
}

fn led_badge(ui: &mut egui::Ui, label: &str, active: bool, on_colour: Color32) {
    let (bg, fg) = if active {
        (on_colour, Color32::BLACK)
    } else {
        (Color32::from_rgb(45, 50, 58), Color32::from_rgb(150, 155, 165))
    };
    egui::Frame::none()
        .fill(bg)
        .rounding(3.0)
        .inner_margin(egui::Margin::symmetric(5.0, 2.0))
        .show(ui, |ui| {
            ui.label(RichText::new(label).color(fg).monospace().size(11.5).strong());
        });
}

impl eframe::App for SmtGuiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Repaint at ~20 Hz so live serial traffic updates smoothly
        ctx.request_repaint_after(Duration::from_millis(50));

        // Record whether any TextEdit widget owned keyboard focus at the start of this frame
        // so that pressing Enter inside a single-line TextEdit (which surrenders focus during ui.add)
        // is never double-handled by the PuTTY live keystroke listener at the end of the frame.
        let kb_claimed_before = ctx.wants_keyboard_input();
        let mut text_edit_submitted = false;

        let (
            _host,
            profile,
            discovery_method,
            mode_banner,
            stream_paused,
            paused_skipped,
            terminal_local_echo,
            terminal_crlf,
            filter_snapshot,
            active_log_path,
            ports,
            total_frames,
            filtered_frames,
            status_log,
        ) = {
            let st = self.ctrl.state.lock().unwrap();
            (
                st.host.clone(),
                st.profile.clone(),
                st.discovery_method.clone(),
                st.mode_banner.clone(),
                st.stream_paused,
                st.paused_skipped_frames,
                st.terminal_local_echo,
                st.terminal_crlf,
                st.filter.clone(),
                st.text_log_path.clone(),
                st.ports.clone(),
                st.frames.len(),
                st.filtered_frames(),
                st.status_log.iter().cloned().collect::<Vec<_>>(),
            )
        };

        if self.selected_port > profile.port_count {
            self.selected_port = profile.port_count.max(1);
        }

        // -------------------------------------------------------------------
        // 1. Top Panel: Moxa IP Connection, Model Auto-Detection & Logging
        // -------------------------------------------------------------------
        egui::TopBottomPanel::top("top_connection_bar").show(ctx, |ui| {
            ui.add_space(4.0);
            ui.horizontal_wrapped(|ui| {
                egui::Frame::none()
                    .fill(Color32::from_rgb(0, 180, 216))
                    .rounding(4.0)
                    .inner_margin(egui::Margin::symmetric(8.0, 4.0))
                    .show(ui, |ui| {
                        ui.label(
                            RichText::new(format!(
                                "{} ({}-Port {})",
                                profile.model_name, profile.port_count, profile.interfaces
                            ))
                            .color(Color32::BLACK)
                            .strong(),
                        );
                    });

                ui.label(
                    RichText::new(format!("Connector: {} | Via: {}", profile.connector, discovery_method))
                        .color(Color32::LIGHT_GRAY),
                );

                ui.separator();

                ui.label(RichText::new("Moxa IP:").strong());
                let ip_resp = ui.add(
                    egui::TextEdit::singleline(&mut self.ip_input)
                        .desired_width(135.0)
                        .font(FontId::monospace(13.0)),
                );
                let ip_enter = ip_resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                if ui.button("🔌 Connect & Auto-Detect").clicked() || ip_enter {
                    if ip_enter {
                        text_edit_submitted = true;
                    }
                    let new_ip = self.ip_input.trim().to_string();
                    let ctrl = self.ctrl.clone();
                    self.rt.spawn(async move {
                        ctrl.switch_target_host(new_ip).await;
                    });
                }

                if ui.button("📡 UDP 4800 LAN Scan").clicked() {
                    let ctrl = self.ctrl.clone();
                    if let Ok(found) = self
                        .rt
                        .block_on(discover_nports_udp(Duration::from_millis(750)))
                    {
                        let mut st = ctrl.state.lock().unwrap();
                        if found.is_empty() {
                            st.log_event("UDP 4800 scan finished: no remote NPort units responded on LAN");
                        } else {
                            for u in &found {
                                st.log_event(format!(
                                    "Discovered {} at {} [{}]",
                                    u.profile.model_name, u.ip_address, u.mac_address
                                ));
                            }
                        }
                        self.discovered_units = found;
                    }
                }

                if ui.button("🔄 Cycle Demo Model").clicked() {
                    self.demo_model_idx = (self.demo_model_idx + 1) % DEMO_MODEL_IDS.len();
                    let next_id = DEMO_MODEL_IDS[self.demo_model_idx];
                    let new_prof = NPortModelProfile::from_model_id(next_id);
                    let mut st = self.ctrl.state.lock().unwrap();
                    let cur_host = st.host.clone();
                    st.apply_detected_profile(DiscoveredNPort {
                        ip_address: cur_host,
                        mac_address: String::from("00:90:E8:56:10:08"),
                        profile: new_prof,
                        discovery_method: String::from("Simulated Model Switch"),
                    });
                }

                ui.separator();

                // Stream Pause / Resume & Stop All Streams Controls
                let pause_btn_text = if stream_paused {
                    RichText::new(format!("▶ Resume Stream ({paused_skipped} skipped)"))
                        .color(Color32::BLACK)
                        .strong()
                } else {
                    RichText::new("⏸ Pause Stream").color(Color32::WHITE)
                };
                let pause_btn = egui::Button::new(pause_btn_text).fill(if stream_paused {
                    Color32::from_rgb(245, 175, 40)
                } else {
                    Color32::from_rgb(55, 65, 81)
                });
                if ui.add(pause_btn).clicked() {
                    self.ctrl.state.lock().unwrap().toggle_pause();
                }

                if ui
                    .add(
                        egui::Button::new(
                            RichText::new("⏹ Stop All Streams").color(Color32::from_rgb(255, 140, 140)),
                        )
                        .fill(Color32::from_rgb(65, 35, 40)),
                    )
                    .clicked()
                {
                    self.ctrl.stop_all_streams();
                }

                ui.separator();

                // On-Demand Stream Logging & Buffer Dump Buttons
                let is_logging = active_log_path.is_some();
                let log_btn_text = if let Some(ref p) = active_log_path {
                    RichText::new(format!("● REC: {}", p.display()))
                        .color(Color32::WHITE)
                        .strong()
                } else {
                    RichText::new("⏺ Start Live Log").color(Color32::WHITE)
                };
                let log_btn = egui::Button::new(log_btn_text).fill(if is_logging {
                    Color32::from_rgb(200, 40, 40)
                } else {
                    Color32::from_rgb(55, 65, 81)
                });
                if ui.add(log_btn).clicked() {
                    self.ctrl.state.lock().unwrap().toggle_jsonl(None);
                }

                if ui
                    .button(
                        RichText::new("⬇ Dump Buffer to Log Now")
                            .color(Color32::from_rgb(120, 240, 160)),
                    )
                    .clicked()
                {
                    self.ctrl.state.lock().unwrap().dump_buffer_on_demand(None);
                }

                if ui.button("🗑 Clear Buffer").clicked() {
                    let mut st = self.ctrl.state.lock().unwrap();
                    st.frames.clear();
                    self.selected_frame_seq = None;
                    st.log_event("Cleared packet inspector display buffer");
                }
            });

            if !self.discovered_units.is_empty() {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Discovered on LAN:").color(Color32::YELLOW));
                    for u in self.discovered_units.clone() {
                        if ui
                            .small_button(format!(
                                "{} ({}) [{}]",
                                u.ip_address, u.profile.model_name, u.mac_address
                            ))
                            .clicked()
                        {
                            self.ip_input = u.ip_address.clone();
                            let ctrl = self.ctrl.clone();
                            self.rt.spawn(async move {
                                ctrl.switch_target_host(u.ip_address).await;
                            });
                        }
                    }
                });
            }
            ui.add_space(4.0);
        });

        // -------------------------------------------------------------------
        // 2. Bottom Panel: Event Log & Selected Frame Byte/Bit Dissector
        // -------------------------------------------------------------------
        egui::TopBottomPanel::bottom("bottom_status_and_dissector")
            .resizable(true)
            .min_height(130.0)
            .show(ctx, |ui| {
                ui.add_space(4.0);
                // Transmit / Inject & Log Note Bar
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(format!("TX Inject (P{}):", self.selected_port))
                            .color(Color32::from_rgb(230, 140, 255))
                            .strong(),
                    );
                    let tx_edit = ui.add(
                        egui::TextEdit::singleline(&mut self.tx_payload_input)
                            .desired_width(260.0)
                            .font(FontId::monospace(13.0))
                            .hint_text("ASCII e.g. \\x0201POLL\\x03 or hex:02 30 31 03"),
                    );
                    let tx_enter =
                        tx_edit.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                    if ui.button("🚀 Send Frame").clicked() || tx_enter {
                        if tx_enter {
                            text_edit_submitted = true;
                        }
                        match parse_payload_input(&self.tx_payload_input) {
                            Ok(bytes) => {
                                let ctrl = self.ctrl.clone();
                                let p = self.selected_port;
                                self.rt.spawn(async move {
                                    ctrl.inject_payload(p, bytes).await;
                                });
                            }
                            Err(e) => {
                                self.ctrl
                                    .state
                                    .lock()
                                    .unwrap()
                                    .log_event(format!("ERROR parsing TX payload: {e}"));
                            }
                        }
                    }

                    ui.separator();

                    ui.label(RichText::new("Operator Log Note:").color(Color32::YELLOW));
                    let note_edit = ui.add(
                        egui::TextEdit::singleline(&mut self.log_note_input)
                            .desired_width(220.0)
                            .hint_text("e.g. toggled relay 1 / set speed 50"),
                    );
                    let note_enter =
                        note_edit.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                    if ui.button("📝 Add Note to Log").clicked() || note_enter {
                        if note_enter {
                            text_edit_submitted = true;
                        }
                        let note = self.log_note_input.trim().to_string();
                        if !note.is_empty() {
                            self.ctrl.state.lock().unwrap().annotate_log(&note);
                            self.log_note_input.clear();
                        }
                    }
                });

                ui.separator();

                ui.columns(2, |cols| {
                    // Left column: Selected Frame Byte/Bit Dissector
                    cols[0].label(
                        RichText::new("🔍 Selected Frame Byte & Bit Dissector (Click any packet row above)")
                            .color(Color32::from_rgb(0, 210, 255))
                            .strong(),
                    );
                    let inspected: Option<&SerialFrame> = self
                        .selected_frame_seq
                        .and_then(|seq| filtered_frames.iter().find(|f| f.seq == seq))
                        .or_else(|| filtered_frames.last());

                    if let Some(fr) = inspected {
                        cols[0].label(
                            RichText::new(format!(
                                "Frame #{} | {} | {} bytes | XOR: 0x{:02X} | LRC: 0x{:02X} | CRC-16/MODBUS: 0x{:04X}",
                                fr.seq,
                                fr.direction,
                                fr.payload.len(),
                                fr.checksums.xor8,
                                fr.checksums.lrc,
                                fr.checksums.crc16_modbus
                            ))
                            .monospace()
                            .size(12.0),
                        );
                        ScrollArea::horizontal()
                            .id_salt("byte_dissector_scroll")
                            .show(&mut cols[0], |ui| {
                                ui.horizontal(|ui| {
                                    for (idx, &b) in fr.payload.iter().enumerate() {
                                        let changed = fr.changed_indices.contains(&idx);
                                        let border_col = if changed {
                                            Color32::from_rgb(235, 80, 255)
                                        } else {
                                            Color32::from_rgb(65, 75, 90)
                                        };
                                        let ch = if (32..=126).contains(&b) {
                                            b as char
                                        } else {
                                            '.'
                                        };
                                        egui::Frame::none()
                                            .fill(if changed {
                                                Color32::from_rgb(70, 20, 80)
                                            } else {
                                                Color32::from_rgb(28, 32, 38)
                                            })
                                            .stroke(Stroke::new(1.0_f32, border_col))
                                            .rounding(3.0)
                                            .inner_margin(egui::Margin::symmetric(5.0, 3.0))
                                            .show(ui, |ui| {
                                                ui.vertical(|ui| {
                                                    ui.label(
                                                        RichText::new(format!("[{idx:02}]"))
                                                            .color(Color32::GRAY)
                                                            .monospace()
                                                            .size(10.0),
                                                    );
                                                    ui.label(
                                                        RichText::new(format!("0x{b:02X}"))
                                                            .color(Color32::WHITE)
                                                            .monospace()
                                                            .strong()
                                                            .size(12.0),
                                                    );
                                                    ui.label(
                                                        RichText::new(format!("{b:3} '{ch}'"))
                                                            .color(Color32::LIGHT_GRAY)
                                                            .monospace()
                                                            .size(10.5),
                                                    );
                                                });
                                            });
                                    }
                                });
                            });
                    } else {
                        cols[0].label(RichText::new("No matching frames to inspect.").color(Color32::GRAY));
                    }

                    // Right column: Event & Discovery History
                    cols[1].label(
                        RichText::new("📋 System, Discovery & Logging Event History")
                            .color(Color32::from_rgb(0, 210, 255))
                            .strong(),
                    );
                    ScrollArea::vertical()
                        .id_salt("event_log_scroll")
                        .max_height(85.0)
                        .stick_to_bottom(true)
                        .show(&mut cols[1], |ui| {
                            for entry in status_log.iter().rev().take(12).rev() {
                                let col = if entry.contains("ERROR") || entry.contains("WARNING") {
                                    Color32::LIGHT_RED
                                } else if entry.contains("OPERATOR NOTE")
                                    || entry.contains("Dumped")
                                    || entry.contains("Live stream logging ON")
                                {
                                    Color32::LIGHT_GREEN
                                } else {
                                    Color32::LIGHT_GRAY
                                };
                                ui.label(RichText::new(entry).color(col).monospace().size(11.5));
                            }
                        });
                });
            });

        // -------------------------------------------------------------------
        // 3. Central Panel: Adaptive Port Matrix + Live Serial Frame Inspector
        // -------------------------------------------------------------------
        egui::CentralPanel::default().show(ctx, |ui| {
            // 3A. Selected Port Hardware & Mode Control Toolbar
            let (pa, pb) = adjacent_port_pair(self.selected_port, profile.port_count);
            let sel_data_port = ports
                .get((self.selected_port - 1) as usize)
                .map(|p| p.data_tcp_port())
                .unwrap_or(949 + u16::from(self.selected_port));
            egui::Frame::none()
                .fill(Color32::from_rgb(30, 35, 44))
                .rounding(5.0)
                .inner_margin(egui::Margin::symmetric(8.0, 6.0))
                .show(ui, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(
                            RichText::new(format!(
                                "Selected: Port {} (Data :{} / ASPP :{}) | Mode: {}",
                                self.selected_port,
                                sel_data_port,
                                965 + u16::from(self.selected_port),
                                mode_banner
                            ))
                            .color(Color32::from_rgb(0, 220, 255))
                            .strong(),
                        );

                        ui.separator();

                        let is_conn = ports
                            .get((self.selected_port - 1) as usize)
                            .map(|p| p.connected)
                            .unwrap_or(false);

                        if ui
                            .button(if is_conn {
                                "⏹ Disconnect Port"
                            } else {
                                "▶ Connect Stream"
                            })
                            .clicked()
                        {
                            let ctrl = self.ctrl.clone();
                            let p = self.selected_port;
                            if is_conn {
                                ctrl.disconnect_port(p);
                            } else {
                                self.rt.spawn(async move {
                                    ctrl.connect_port(p, "STREAM").await;
                                });
                            }
                        }

                        if ui.button("⚡ Cycle Baud Rate").clicked() {
                            let ctrl = self.ctrl.clone();
                            let p = self.selected_port;
                            self.rt.spawn(async move {
                                ctrl.cycle_baud(p).await;
                            });
                        }

                        if ui.button("📐 Cycle Framing").clicked() {
                            let ctrl = self.ctrl.clone();
                            let p = self.selected_port;
                            self.rt.spawn(async move {
                                ctrl.cycle_framing(p).await;
                            });
                        }

                        if ui.button("🌊 Cycle Flow").clicked() {
                            let ctrl = self.ctrl.clone();
                            let p = self.selected_port;
                            self.rt.spawn(async move {
                                ctrl.cycle_flow_control(p).await;
                            });
                        }

                        if ui.button("🔌 Cycle Interface").clicked() {
                            let ctrl = self.ctrl.clone();
                            let p = self.selected_port;
                            self.rt.spawn(async move {
                                ctrl.cycle_interface(p).await;
                            });
                        }

                        if ui.button("Toggle DTR (Pin 4)").clicked() {
                            let ctrl = self.ctrl.clone();
                            let p = self.selected_port;
                            self.rt.spawn(async move {
                                ctrl.toggle_dtr(p).await;
                            });
                        }

                        if ui.button("Toggle RTS (Pin 7)").clicked() {
                            let ctrl = self.ctrl.clone();
                            let p = self.selected_port;
                            self.rt.spawn(async move {
                                ctrl.toggle_rts(p).await;
                            });
                        }

                        if ui.button("🧹 Flush FIFO").clicked() {
                            let ctrl = self.ctrl.clone();
                            let p = self.selected_port;
                            self.rt.spawn(async move {
                                ctrl.flush_fifo(p).await;
                            });
                        }

                        if ui.button("⚡ Send BREAK").clicked() {
                            let ctrl = self.ctrl.clone();
                            let p = self.selected_port;
                            self.rt.spawn(async move {
                                ctrl.send_break(p).await;
                            });
                        }

                        ui.separator();

                        if ui
                            .button(
                                RichText::new(format!("🎧 Passive Tap (P{pa} + P{pb})"))
                                    .color(Color32::from_rgb(0, 230, 255)),
                            )
                            .clicked()
                        {
                            let ctrl = self.ctrl.clone();
                            self.rt.spawn(async move {
                                ctrl.start_passive_tap(pa, pb).await;
                            });
                        }

                        if ui
                            .button(
                                RichText::new(format!("🔀 Active MITM (P{pa} ⟷ P{pb})"))
                                    .color(Color32::YELLOW),
                            )
                            .clicked()
                        {
                            let ctrl = self.ctrl.clone();
                            self.rt.spawn(async move {
                                ctrl.start_mitm_bridge(pa, pb).await;
                            });
                        }
                    });
                });

            ui.add_space(6.0);

            // 3B. Adaptive Multi-Port Hardware Status Grid (1..=port_count)
            egui::Grid::new("nport_ports_grid")
                .striped(true)
                .spacing([12.0, 4.0])
                .show(ui, |ui| {
                    for hdr in [
                        "Select",
                        "Data / ASPP",
                        "Active Role",
                        "UART / Iface / Flow",
                        "Outputs (Pin 4 / 7)",
                        "Inputs (Pin 8 / 6 / 1)",
                        "RX (Frames / Bytes)",
                        "TX (Frames / Bytes)",
                    ] {
                        ui.label(
                            RichText::new(hdr)
                                .color(Color32::from_rgb(0, 210, 255))
                                .strong(),
                        );
                    }
                    ui.end_row();

                    for ps in &ports {
                        let is_sel = ps.port_num == self.selected_port;
                        let name_suffix = if ps.alias.is_empty() {
                            String::new()
                        } else {
                            format!(" ({})", ps.alias)
                        };
                        let btn_label = if is_sel {
                            format!("▶ Port {}{}", ps.port_num, name_suffix)
                        } else {
                            format!("  Port {}{}", ps.port_num, name_suffix)
                        };
                        let btn = egui::Button::new(
                            RichText::new(btn_label)
                                .monospace()
                                .strong()
                                .color(if is_sel {
                                    Color32::BLACK
                                } else {
                                    Color32::WHITE
                                }),
                        )
                        .fill(if is_sel {
                            Color32::from_rgb(0, 200, 240)
                        } else {
                            Color32::from_rgb(45, 52, 64)
                        });
                        if ui.add(btn).clicked() {
                            self.selected_port = ps.port_num;
                        }

                        ui.label(
                            RichText::new(format!(":{} / :{}", ps.data_tcp_port(), ps.aspp_tcp_port()))
                                .monospace(),
                        );

                        let role_col = if ps.connected {
                            Color32::LIGHT_GREEN
                        } else {
                            Color32::GRAY
                        };
                        let role_lbl = if ps.role == "IDLE" {
                            format!("IDLE ({})", ps.op_mode)
                        } else {
                            ps.role.clone()
                        };
                        ui.label(RichText::new(role_lbl).color(role_col).monospace().strong());

                        ui.label(
                            RichText::new(format!(
                                "{} {} | {} | {}",
                                ps.baud,
                                ps.framing.as_str(),
                                ps.interface.as_str(),
                                ps.flow_control.as_str()
                            ))
                            .monospace(),
                        );

                        ui.horizontal(|ui| {
                            led_badge(ui, "DTR", ps.dtr, Color32::from_rgb(220, 120, 255));
                            led_badge(ui, "RTS", ps.rts, Color32::from_rgb(220, 120, 255));
                        });

                        ui.horizontal(|ui| {
                            led_badge(ui, "CTS", ps.modem.cts, Color32::from_rgb(80, 230, 130));
                            led_badge(ui, "DSR", ps.modem.dsr, Color32::from_rgb(80, 230, 130));
                            led_badge(ui, "DCD", ps.modem.dcd, Color32::from_rgb(255, 190, 60));
                        });

                        ui.label(
                            RichText::new(format!("{:>4} / {:>6} B", ps.rx_frames, ps.rx_bytes))
                                .monospace(),
                        );
                        ui.label(
                            RichText::new(format!("{:>4} / {:>6} B", ps.tx_frames, ps.tx_bytes))
                                .monospace(),
                        );
                        ui.end_row();
                    }
                });

            ui.separator();

            // 3C. View Mode Switcher + Stream Filter & Terminal Options Toolbar
            egui::Frame::none()
                .fill(Color32::from_rgb(26, 31, 40))
                .rounding(4.0)
                .inner_margin(egui::Margin::symmetric(8.0, 5.0))
                .show(ui, |ui| {
                    let mut new_filter: FrameFilter = filter_snapshot.clone();
                    let mut changed = false;

                    ui.horizontal_wrapped(|ui| {
                        ui.label(
                            RichText::new("🖥 View:")
                                .color(Color32::from_rgb(0, 220, 255))
                                .strong(),
                        );
                        if ui
                            .selectable_label(
                                self.view_mode == CentreViewMode::PuttyTerminal,
                                "🖥 PuTTY Live Terminal",
                            )
                            .clicked()
                        {
                            self.view_mode = CentreViewMode::PuttyTerminal;
                        }
                        if ui
                            .selectable_label(
                                self.view_mode == CentreViewMode::SplitTerminalAndPackets,
                                "🗔 Split (PuTTY + Packets)",
                            )
                            .clicked()
                        {
                            self.view_mode = CentreViewMode::SplitTerminalAndPackets;
                        }
                        if ui
                            .selectable_label(
                                self.view_mode == CentreViewMode::PacketInspector,
                                "📡 Packet Inspector",
                            )
                            .clicked()
                        {
                            self.view_mode = CentreViewMode::PacketInspector;
                        }

                        ui.separator();

                        ui.label(
                            RichText::new("🔎 Filter:")
                                .color(Color32::from_rgb(0, 220, 255))
                                .strong(),
                        );

                        // Hex / ASCII / Source text search
                        let search_resp = ui.add(
                            egui::TextEdit::singleline(&mut new_filter.search_query)
                                .desired_width(130.0)
                                .font(FontId::monospace(12.0))
                                .hint_text("Hex/ASCII e.g. POLL"),
                        );
                        if search_resp.changed() {
                            changed = true;
                        }

                        ui.separator();

                        // Port Filter: All or P1..PN
                        ui.label(RichText::new("Port:").color(Color32::LIGHT_GRAY));
                        if ui
                            .selectable_label(new_filter.port_filter.is_none(), "All")
                            .clicked()
                        {
                            new_filter.port_filter = None;
                            changed = true;
                        }
                        for p in 1..=profile.port_count {
                            if ui
                                .selectable_label(
                                    new_filter.port_filter == Some(p),
                                    format!("P{p}"),
                                )
                                .clicked()
                            {
                                new_filter.port_filter = Some(p);
                                changed = true;
                            }
                        }

                        ui.separator();

                        // Direction Filter
                        ui.label(RichText::new("Direction:").color(Color32::LIGHT_GRAY));
                        for dir_opt in DirectionFilter::ALL {
                            if ui
                                .selectable_label(
                                    new_filter.direction == dir_opt,
                                    dir_opt.as_str(),
                                )
                                .clicked()
                            {
                                new_filter.direction = dir_opt;
                                changed = true;
                            }
                        }

                        ui.separator();

                        // Changed Bytes Only toggle (hide static heartbeats)
                        if ui
                            .checkbox(
                                &mut new_filter.only_changed,
                                RichText::new("⚡ Changed Only")
                                    .color(Color32::from_rgb(235, 130, 255)),
                            )
                            .changed()
                        {
                            changed = true;
                        }

                        ui.separator();

                        // Min / Max payload byte length
                        ui.label(RichText::new("Len(B):").color(Color32::LIGHT_GRAY));
                        let min_resp = ui.add(
                            egui::TextEdit::singleline(&mut self.min_len_input)
                                .desired_width(34.0)
                                .hint_text("Min"),
                        );
                        ui.label("..");
                        let max_resp = ui.add(
                            egui::TextEdit::singleline(&mut self.max_len_input)
                                .desired_width(34.0)
                                .hint_text("Max"),
                        );
                        if min_resp.changed() || max_resp.changed() {
                            new_filter.min_len = self.min_len_input.trim().parse::<usize>().ok();
                            new_filter.max_len = self.max_len_input.trim().parse::<usize>().ok();
                            changed = true;
                        }

                        if new_filter.is_active() && ui.button("✖ Reset Filters").clicked() {
                            new_filter.reset();
                            self.min_len_input.clear();
                            self.max_len_input.clear();
                            changed = true;
                        }
                    });

                    if changed {
                        self.ctrl.state.lock().unwrap().filter = new_filter;
                    }
                });

            ui.add_space(4.0);

            match self.view_mode {
                CentreViewMode::PuttyTerminal => {
                    self.render_putty_terminal_pane(
                        ui,
                        ctx,
                        &ports,
                        terminal_local_echo,
                        terminal_crlf,
                        &mut text_edit_submitted,
                    );
                }
                CentreViewMode::PacketInspector => {
                    self.render_packet_inspector_pane(
                        ui,
                        stream_paused,
                        paused_skipped,
                        &filter_snapshot,
                        total_frames,
                        &filtered_frames,
                    );
                }
                CentreViewMode::SplitTerminalAndPackets => {
                    ui.columns(2, |cols| {
                        self.render_putty_terminal_pane(
                            &mut cols[0],
                            ctx,
                            &ports,
                            terminal_local_echo,
                            terminal_crlf,
                            &mut text_edit_submitted,
                        );
                        self.render_packet_inspector_pane(
                            &mut cols[1],
                            stream_paused,
                            paused_skipped,
                            &filter_snapshot,
                            total_frames,
                            &filtered_frames,
                        );
                    });
                }
            }

            // Capture live character-by-character keystrokes (PuTTY style) when terminal mode is active
            // and no TextEdit widget owned or surrendered keyboard focus during this frame.
            if self.view_mode != CentreViewMode::PacketInspector
                && self.terminal_live_keystrokes
                && !kb_claimed_before
                && !ctx.wants_keyboard_input()
                && !text_edit_submitted
            {
                let mut outgoing = Vec::new();
                let events = ctx.input(|i| i.events.clone());
                for ev in events {
                    match ev {
                        egui::Event::Text(text) => {
                            if !text.is_empty() {
                                outgoing.extend_from_slice(text.as_bytes());
                            }
                        }
                        egui::Event::Paste(text) => {
                            if !text.is_empty() {
                                outgoing.extend_from_slice(&format_paste_bytes(&text, terminal_crlf));
                            }
                        }
                        egui::Event::Copy => {
                            // In PuTTY live terminal focus, Ctrl+C transmits ETX (0x03) to the remote device
                            outgoing.push(0x03);
                        }
                        egui::Event::Key {
                            key,
                            pressed: true,
                            modifiers,
                            ..
                        } if modifiers.ctrl || modifiers.command => match key {
                            egui::Key::A => outgoing.push(0x01),
                            egui::Key::C => outgoing.push(0x03),
                            egui::Key::D => outgoing.push(0x04),
                            egui::Key::E => outgoing.push(0x05),
                            egui::Key::K => outgoing.push(0x0B),
                            egui::Key::L => outgoing.push(0x0C),
                            egui::Key::U => outgoing.push(0x15),
                            egui::Key::W => outgoing.push(0x17),
                            egui::Key::Z => outgoing.push(0x1A),
                            _ => {}
                        },
                        egui::Event::Key {
                            key: egui::Key::Enter,
                            pressed: true,
                            ..
                        } => {
                            if terminal_crlf {
                                outgoing.extend_from_slice(b"\r\n");
                            } else {
                                outgoing.push(b'\r');
                            }
                        }
                        egui::Event::Key {
                            key: egui::Key::Backspace,
                            pressed: true,
                            ..
                        } => {
                            outgoing.push(0x08);
                        }
                        egui::Event::Key {
                            key: egui::Key::Delete,
                            pressed: true,
                            ..
                        } => {
                            outgoing.extend_from_slice(b"\x1b[3~");
                        }
                        egui::Event::Key {
                            key: egui::Key::Tab,
                            pressed: true,
                            ..
                        } => {
                            outgoing.push(b'\t');
                        }
                        egui::Event::Key {
                            key: egui::Key::Escape,
                            pressed: true,
                            ..
                        } => {
                            outgoing.push(0x1B);
                        }
                        egui::Event::Key {
                            key: egui::Key::ArrowUp,
                            pressed: true,
                            ..
                        } => {
                            outgoing.extend_from_slice(b"\x1b[A");
                        }
                        egui::Event::Key {
                            key: egui::Key::ArrowDown,
                            pressed: true,
                            ..
                        } => {
                            outgoing.extend_from_slice(b"\x1b[B");
                        }
                        egui::Event::Key {
                            key: egui::Key::ArrowRight,
                            pressed: true,
                            ..
                        } => {
                            outgoing.extend_from_slice(b"\x1b[C");
                        }
                        egui::Event::Key {
                            key: egui::Key::ArrowLeft,
                            pressed: true,
                            ..
                        } => {
                            outgoing.extend_from_slice(b"\x1b[D");
                        }
                        egui::Event::Key {
                            key: egui::Key::Home,
                            pressed: true,
                            ..
                        } => {
                            outgoing.extend_from_slice(b"\x1b[H");
                        }
                        egui::Event::Key {
                            key: egui::Key::End,
                            pressed: true,
                            ..
                        } => {
                            outgoing.extend_from_slice(b"\x1b[F");
                        }
                        _ => {}
                    }
                }
                if !outgoing.is_empty() {
                    let ctrl = self.ctrl.clone();
                    let p = self.selected_port;
                    self.rt.spawn(async move {
                        ctrl.send_terminal_bytes(p, outgoing).await;
                    });
                }
            }
        });
    }
}

impl SmtGuiApp {
    fn render_putty_terminal_pane(
        &mut self,
        ui: &mut egui::Ui,
        ctx: &egui::Context,
        ports: &[nport5610_core::PortState],
        terminal_local_echo: bool,
        terminal_crlf: bool,
        text_edit_submitted: &mut bool,
    ) {
        let sel_ps = ports.get((self.selected_port - 1) as usize);
        let is_conn = sel_ps.map(|p| p.connected).unwrap_or(false);
        let baud = sel_ps.map(|p| p.baud).unwrap_or(9600);
        let framing = sel_ps.map(|p| p.framing.as_str()).unwrap_or("8N1");
        let flow = sel_ps.map(|p| p.flow_control.as_str()).unwrap_or("NONE");
        let data_port = sel_ps
            .map(|p| p.data_tcp_port())
            .unwrap_or(949 + u16::from(self.selected_port));
        let term_text = sel_ps.map(|p| p.terminal_text.as_str()).unwrap_or("");
        let live_focus = self.terminal_live_keystrokes && !ctx.wants_keyboard_input();

        ui.horizontal_wrapped(|ui| {
            ui.label(
                RichText::new(format!(
                    "🖥 PuTTY Terminal — P{} (:{} @ {} {} {})",
                    self.selected_port, data_port, baud, framing, flow
                ))
                .color(Color32::from_rgb(80, 240, 140))
                .strong(),
            );

            ui.checkbox(
                &mut self.terminal_live_keystrokes,
                RichText::new("⌨ Live Keystroke TX")
                    .color(if live_focus {
                        Color32::LIGHT_GREEN
                    } else {
                        Color32::LIGHT_GRAY
                    }),
            );

            let mut echo = terminal_local_echo;
            if ui.checkbox(&mut echo, "Local Echo").changed() {
                self.ctrl.state.lock().unwrap().terminal_local_echo = echo;
            }

            let mut crlf = terminal_crlf;
            if ui.checkbox(&mut crlf, "CR+LF (\\r\\n)").changed() {
                self.ctrl.state.lock().unwrap().terminal_crlf = crlf;
            }

            if ui.small_button("🧹 Clear").clicked() {
                let mut st = self.ctrl.state.lock().unwrap();
                if let Some(ps) = st.ports.get_mut((self.selected_port - 1) as usize) {
                    ps.clear_terminal();
                }
            }

            if ui.small_button("📋 Copy").clicked() {
                ui.output_mut(|o| o.copied_text = term_text.to_string());
            }
        });

        // Line command bar for sending complete lines or commands
        ui.horizontal(|ui| {
            ui.label(
                RichText::new("Line TX:")
                    .color(Color32::from_rgb(0, 210, 255))
                    .monospace(),
            );
            let line_resp = ui.add(
                egui::TextEdit::singleline(&mut self.terminal_line_input)
                    .desired_width(220.0)
                    .font(FontId::monospace(12.5))
                    .hint_text("Type command line & press Enter (or click screen below for live keystrokes)"),
            );
            let enter_on_line =
                line_resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            let send_clicked = ui.button("⏎ Send Line").clicked() || enter_on_line;
            if send_clicked {
                if enter_on_line {
                    *text_edit_submitted = true;
                    line_resp.request_focus();
                }
                let mut bytes = self.terminal_line_input.as_bytes().to_vec();
                if terminal_crlf {
                    bytes.extend_from_slice(b"\r\n");
                } else {
                    bytes.push(b'\r');
                }
                self.terminal_line_input.clear();
                let ctrl = self.ctrl.clone();
                let p = self.selected_port;
                self.rt.spawn(async move {
                    ctrl.send_terminal_bytes(p, bytes).await;
                });
            }
            if !live_focus && ui.small_button("🟢 Focus Live Keyboard").clicked() {
                if let Some(focused_id) = ctx.memory(|m| m.focused()) {
                    ctx.memory_mut(|m| m.surrender_focus(focused_id));
                }
                self.terminal_live_keystrokes = true;
            }
        });

        let border_col = if live_focus {
            Color32::from_rgb(60, 230, 120)
        } else {
            Color32::from_rgb(60, 75, 95)
        };

        let term_frame = egui::Frame::none()
            .fill(Color32::from_rgb(10, 14, 18))
            .stroke(Stroke::new(if live_focus { 1.5_f32 } else { 1.0_f32 }, border_col))
            .rounding(4.0)
            .inner_margin(egui::Margin::symmetric(8.0, 6.0))
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.set_min_height(ui.available_height().max(120.0));
                ScrollArea::vertical()
                    .id_salt("putty_terminal_scroll")
                    .stick_to_bottom(true)
                    .show(ui, |ui| {
                        ui.set_min_width(ui.available_width());
                        if term_text.is_empty() {
                            let status_msg = if is_conn {
                                format!(
                                    "Connected to Port {} (:{} @ {} {} {}).\nClick inside this terminal and type — every keystroke is transmitted live (like PuTTY).",
                                    self.selected_port, data_port, baud, framing, flow
                                )
                            } else {
                                format!(
                                    "Port {} (:{} @ {} {} {}) ready.\nClick inside this terminal and type to auto-connect & transmit live (like PuTTY).",
                                    self.selected_port, data_port, baud, framing, flow
                                )
                            };
                            ui.label(
                                RichText::new(if live_focus {
                                    format!("{status_msg}\n█")
                                } else {
                                    status_msg
                                })
                                .color(Color32::from_rgb(110, 210, 140))
                                .monospace()
                                .size(13.0),
                            );
                        } else {
                            let display_str = if live_focus {
                                format!("{term_text}█")
                            } else {
                                term_text.to_string()
                            };
                            ui.label(
                                RichText::new(display_str)
                                    .color(Color32::from_rgb(90, 245, 130))
                                    .monospace()
                                    .size(13.0),
                            );
                        }
                    });
            });

        if term_frame.response.interact(egui::Sense::click()).clicked() {
            if let Some(focused_id) = ctx.memory(|m| m.focused()) {
                ctx.memory_mut(|m| m.surrender_focus(focused_id));
            }
            self.terminal_live_keystrokes = true;
        }
    }

    fn render_packet_inspector_pane(
        &mut self,
        ui: &mut egui::Ui,
        stream_paused: bool,
        paused_skipped: u64,
        filter_snapshot: &FrameFilter,
        total_frames: usize,
        filtered_frames: &[SerialFrame],
    ) {
        ui.horizontal(|ui| {
            let status_badge = if stream_paused {
                format!(
                    "⏸ PAUSED ({paused_skipped} skipped) — {}/{} frames",
                    filtered_frames.len(),
                    total_frames
                )
            } else {
                format!(
                    "📡 Packet Stream — {}/{} frames ({})",
                    filtered_frames.len(),
                    total_frames,
                    filter_snapshot.summary()
                )
            };
            ui.label(
                RichText::new(status_badge)
                    .color(if stream_paused {
                        Color32::from_rgb(255, 190, 60)
                    } else {
                        Color32::from_rgb(0, 210, 255)
                    })
                    .strong(),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.checkbox(&mut self.auto_scroll, "Auto-scroll");
            });
        });

        ScrollArea::vertical()
            .id_salt("packet_inspector_scroll")
            .stick_to_bottom(self.auto_scroll)
            .show(ui, |ui| {
                for fr in filtered_frames {
                    let is_selected_frame = self.selected_frame_seq == Some(fr.seq);
                    let dir_col = if fr.direction.contains("CTRL→DEV")
                        || fr.direction.starts_with("P1")
                    {
                        Color32::from_rgb(80, 220, 255)
                    } else if fr.direction.contains("DEV→CTRL")
                        || fr.direction.starts_with("P2")
                    {
                        Color32::from_rgb(255, 210, 90)
                    } else if fr.direction.contains("TX") {
                        Color32::from_rgb(235, 130, 255)
                    } else {
                        Color32::LIGHT_GREEN
                    };

                    let row_bg = if is_selected_frame {
                        Color32::from_rgb(45, 55, 75)
                    } else {
                        Color32::TRANSPARENT
                    };

                    let resp = egui::Frame::none()
                        .fill(row_bg)
                        .inner_margin(egui::Margin::symmetric(4.0, 2.0))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(
                                    RichText::new(format!(
                                        "#{:<4} {} +{:>7.2}ms {:<14} ({:>2}B) |",
                                        fr.seq,
                                        fr.timestamp.format("%H:%M:%S%.3f"),
                                        fr.delta_ms,
                                        fr.direction,
                                        fr.payload.len()
                                    ))
                                    .color(dir_col)
                                    .monospace()
                                    .size(12.0),
                                );

                                // Render hex bytes with Magenta highlight on changed bytes
                                for (idx, &b) in fr.payload.iter().take(16).enumerate() {
                                    let changed = fr.changed_indices.contains(&idx);
                                    if changed {
                                        egui::Frame::none()
                                            .fill(Color32::from_rgb(175, 35, 195))
                                            .rounding(2.0)
                                            .inner_margin(egui::Margin::symmetric(2.0, 0.0))
                                            .show(ui, |ui| {
                                                ui.label(
                                                    RichText::new(format!("{b:02X}"))
                                                        .color(Color32::WHITE)
                                                        .monospace()
                                                        .strong()
                                                        .size(12.0),
                                                );
                                            });
                                    } else {
                                        ui.label(
                                            RichText::new(format!("{b:02X}"))
                                                .color(dir_col)
                                                .monospace()
                                                .size(12.0),
                                        );
                                    }
                                }

                                ui.label(
                                    RichText::new(format!(
                                        "| {:<18} | XOR:{:02X} LRC:{:02X} CRC16:{:04X}",
                                        fr.ascii_string(),
                                        fr.checksums.xor8,
                                        fr.checksums.lrc,
                                        fr.checksums.crc16_modbus
                                    ))
                                    .color(Color32::LIGHT_GRAY)
                                    .monospace()
                                    .size(12.0),
                                );
                            });
                        })
                        .response;

                    if resp.interact(egui::Sense::click()).clicked() {
                        self.selected_frame_seq = Some(fr.seq);
                        self.auto_scroll = false;
                    }
                }
            });
    }
}

fn main() -> eframe::Result<()> {
    let mut host = String::from("192.168.1.249");
    let mut demo = false;

    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--demo" => demo = true,
            "-h" | "--help" => {
                println!("Usage: smt-gui [NPORT_IP] [--demo]");
                return Ok(());
            }
            other if !other.starts_with('-') => host = other.to_string(),
            _ => {}
        }
    }

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("SMT Control System — Moxa NPort Adaptive GUI Console")
            .with_inner_size([1340.0, 820.0])
            .with_min_inner_size([960.0, 600.0]),
        ..Default::default()
    };

    eframe::run_native(
        "SMT Control System — Moxa NPort Adaptive GUI Console",
        native_options,
        Box::new(move |cc| Ok(Box::new(SmtGuiApp::new(cc, host, demo)))),
    )
}
