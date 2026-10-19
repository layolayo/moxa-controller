//! `moxa-daemon` — 24/7 Moxa NPort Background Service & Local IPC Bridge
//!
//! Designed to run on the dedicated Linux box (under `systemd` or alongside the
//! Wayland desktop Moxa controller suite):
//!   1. Automatically polls and identifies the Moxa NPort hardware model (`5610-8-DT`, `5450`, etc.).
//!   2. Supervises persistent TCP Data (`4001..`) and ASPP (`966..`) channels.
//!   3. Exposes a local IPC socket (`127.0.0.1:7450`) supporting:
//!      - `STATUS`            -> JSON snapshot of model, ports, and recent frames
//!      - `HOST <ip>`         -> Switch target Moxa IP address at runtime and auto-detect model
//!      - `LOG [label]`       -> Toggle live stream logging to `logs/*.log` + `.jsonl`
//!      - `DUMP [label]`      -> Immediately dump buffered frames to `logs/*.log` + `.jsonl` on demand
//!      - `NOTE <text>`       -> Write a timestamped operator note into the log
//!      - `STREAM`            -> Stream every serial frame live to the client on demand
//!      - `SEND <port> <raw>` -> Transmit ASCII or `hex:...` frame out of a port

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
    active_log_file: Option<String>,
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
                println!("Usage: moxa-daemon [NPORT_IP] [--ipc 127.0.0.1:7450] [--demo] [--once]");
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
            "[moxa-daemon] Active Target: {} | Detected Model: {} ({}-Port {}, {}) via {}",
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
    println!("[moxa-daemon] Local Wayland GUI / IPC server listening on {ipc_addr}");

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
                                active_log_file: st
                                    .text_log_path
                                    .as_ref()
                                    .map(|p| p.display().to_string()),
                                ports: st.ports.clone(),
                                recent_frames: st
                                    .frames
                                    .iter()
                                    .rev()
                                    .take(20)
                                    .rev()
                                    .cloned()
                                    .collect(),
                            };
                            serde_json::to_string(&snap).unwrap_or_default()
                        };
                        let _ = writer.write_all(format!("{json_reply}\n").as_bytes()).await;
                    } else if let Some(new_ip) = cmd.strip_prefix("HOST ") {
                        ctrl_conn.switch_target_host(new_ip).await;
                        let reply = {
                            let st = ctrl_conn.state.lock().unwrap();
                            serde_json::json!({
                                "ok": true,
                                "host": st.host,
                                "model": st.profile.model_name,
                                "ports": st.profile.port_count
                            })
                            .to_string()
                        };
                        let _ = writer.write_all(format!("{reply}\n").as_bytes()).await;
                    } else if cmd.eq_ignore_ascii_case("DUMP") || cmd.starts_with("DUMP ") {
                        let lbl = cmd.strip_prefix("DUMP").map(str::trim).filter(|s| !s.is_empty());
                        let path = ctrl_conn.state.lock().unwrap().dump_buffer_on_demand(lbl);
                        let reply = serde_json::json!({
                            "ok": path.is_some(),
                            "dump_file": path.map(|p| p.display().to_string())
                        })
                        .to_string();
                        let _ = writer.write_all(format!("{reply}\n").as_bytes()).await;
                    } else if cmd.eq_ignore_ascii_case("LOG") || cmd.starts_with("LOG ") {
                        let lbl = cmd.strip_prefix("LOG").map(str::trim).filter(|s| !s.is_empty());
                        let path = ctrl_conn.state.lock().unwrap().toggle_jsonl(lbl);
                        let reply = serde_json::json!({
                            "logging_active": path.is_some(),
                            "log_file": path.map(|p| p.display().to_string())
                        })
                        .to_string();
                        let _ = writer.write_all(format!("{reply}\n").as_bytes()).await;
                    } else if let Some(note) = cmd.strip_prefix("NOTE ") {
                        ctrl_conn.state.lock().unwrap().annotate_log(note);
                        let _ = writer.write_all(b"{\"ok\":true}\n").await;
                    } else if cmd.eq_ignore_ascii_case("STREAM") {
                        let mut rx = {
                            let st = ctrl_conn.state.lock().unwrap();
                            st.frame_tx.subscribe()
                        };
                        let _ = writer
                            .write_all(b"# Streaming live Moxa serial frames (Ctrl+C to stop)...\n")
                            .await;
                        while let Ok(fr) = rx.recv().await {
                            let line = format!("{}\n", fr.format_log_line());
                            if writer.write_all(line.as_bytes()).await.is_err() {
                                break;
                            }
                        }
                        break;
                    } else if let Some(rest) = cmd.strip_prefix("SEND ") {
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

    let ctrl_poll = ctrl.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(15)).await;
            ctrl_poll.probe_all_ports().await;
        }
    });

    tokio::signal::ctrl_c().await?;
    println!("\n[moxa-daemon] Shutting down cleanly.");
    Ok(())
}
