//! `smt-daemon` — 24/7 Moxa NPort Background Service & Local IPC Bridge
//!
//! Designed to run on the dedicated Linux box (under `systemd` or alongside the
//! Wayland desktop SMT control software):
//!   1. Automatically polls and identifies the Moxa NPort hardware model (`5610-8-DT`, `5450`, etc.).
//!   2. Supervises persistent TCP Data (`4001..`) and ASPP (`966..`) channels.
//!   3. Exposes a local JSON IPC socket (`127.0.0.1:7450`) so the Wayland SMT control GUI
//!      or external tools can read live hardware telemetry and inject serial commands.

use std::time::Duration;

use anyhow::Result;
use nport5610_core::{parse_payload_input, NPortController};
use serde::Serialize;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

#[derive(Serialize)]
struct DaemonStatusSnapshot {
    host: String,
    model_name: String,
    port_count: u8,
    interfaces: String,
    connector: String,
    discovery_method: String,
    mode_banner: String,
    ports: Vec<nport5610_core::PortState>,
    recent_frames: Vec<nport5610_core::SerialFrame>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut host = String::from("192.168.127.254");
    let mut ipc_addr = String::from("127.0.0.1:7450");
    let mut demo = false;
    let mut once = false;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--demo" => demo = true,
            "--once" => once = true,
            "--ipc" => {
                if let Some(v) = args.next() {
                    ipc_addr = v;
                }
            }
            "-h" | "--help" => {
                println!("Usage: smt-daemon [NPORT_IP] [--ipc 127.0.0.1:7450] [--demo] [--once]");
                return Ok(());
            }
            other if !other.starts_with('-') => host = other.to_string(),
            _ => {}
        }
    }

    let ctrl = NPortController::new(&host, 8.0, demo);
    ctrl.probe_all_ports().await;

    {
        let st = ctrl.state.lock().unwrap();
        println!(
            "[smt-daemon] Active Target: {} | Detected Model: {} ({}-Port {}, {}) via {}",
            st.host,
            st.profile.model_name,
            st.profile.port_count,
            st.profile.interfaces,
            st.profile.connector,
            st.discovery_method
        );
    }

    if once {
        return Ok(());
    }

    let listener = TcpListener::bind(&ipc_addr).await?;
    println!("[smt-daemon] Local Wayland GUI / IPC JSON server listening on {ipc_addr}");

    let ctrl_ipc = ctrl.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let ctrl_conn = ctrl_ipc.clone();
            tokio::spawn(async move {
                let (reader, mut writer) = stream.into_split();
                let mut lines = BufReader::new(reader).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    let cmd = line.trim();
                    if cmd.eq_ignore_ascii_case("STATUS") || cmd.is_empty() {
                        let json_reply = {
                            let st = ctrl_conn.state.lock().unwrap();
                            let snap = DaemonStatusSnapshot {
                                host: st.host.clone(),
                                model_name: st.profile.model_name.clone(),
                                port_count: st.profile.port_count,
                                interfaces: st.profile.interfaces.clone(),
                                connector: st.profile.connector.clone(),
                                discovery_method: st.discovery_method.clone(),
                                mode_banner: st.mode_banner.clone(),
                                ports: st.ports.clone(),
                                recent_frames: st.frames.iter().rev().take(20).rev().cloned().collect(),
                            };
                            serde_json::to_string(&snap).unwrap_or_default()
                        };
                        let _ = writer.write_all(format!("{json_reply}\n").as_bytes()).await;
                    } else if let Some(rest) = cmd.strip_prefix("SEND ") {
                        // Format: SEND <port_num> <payload>
                        let mut parts = rest.splitn(2, ' ');
                        if let (Some(p_str), Some(payload_str)) = (parts.next(), parts.next()) {
                            if let (Ok(p), Ok(bytes)) =
                                (p_str.parse::<u8>(), parse_payload_input(payload_str))
                            {
                                ctrl_conn.inject_payload(p, bytes).await;
                                let _ = writer.write_all(b"{\"ok\":true}\n").await;
                                continue;
                            }
                        }
                        let _ = writer
                            .write_all(b"{\"ok\":false,\"error\":\"Invalid SEND syntax\"}\n")
                            .await;
                    }
                }
            });
        }
    });

    // Periodic hardware health and model/modem polling loop
    let ctrl_poll = ctrl.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(15)).await;
            ctrl_poll.probe_all_ports().await;
        }
    });

    tokio::signal::ctrl_c().await?;
    println!("\n[smt-daemon] Shutting down cleanly.");
    Ok(())
}
