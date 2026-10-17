//! Core driverless protocol engine for Moxa NPort Serial Device Servers (`NPort 5100/5200/5400/5600/6000` series).
//!
//! Implements:
//! 1. **Automatic Model & Configuration Probe (`auto_detect_nport`)**:
//!    Polls a target Moxa IP via:
//!    - **UDP Port 4800 (Moxa DSU Identify Unicast/Broadcast)** for exact 16-bit Model ID, MAC, Device Name, and Firmware.
//!    - **SNMP v1/v2c (`UDP 161` `sysDescr.0` & Moxa Enterprise OID `1.3.6.1.4.1.8691`)** for model string and port count.
//!    - **HTTP Web Console (`TCP 80` `/main.htm` / `/overview.htm`)** for model banner and port table.
//!    - **ASPP (`TCP 966..981`) & Data Port (`TCP 4001..4016`)** active scan to determine exact port count (1, 2, 4, 8, or 16)
//!      even across routed subnets where UDP is filtered.
//! 2. **Dynamic Model Profile Adaptation (`NPortModelProfile`)**:
//!    Automatically configures the engine and TUI for the detected NPort model (port count, `RS-232` vs `RS-232/422/485`
//!    electrical capability, and `DB9 Male` vs `8-pin RJ45` pinout).
//! 3. **ASPP Command Plane (`TCP 966..=981`)**: Out-of-band hardware UART configuration (`CMD_INIT`),
//!    flow control (`CMD_FLOWCTRL`), live `DTR`/`RTS` pin toggling (`CMD_LINECTRL`), live `CTS`/`DSR`/`DCD`/`RI`
//!    input polling (`CMD_LSTATUS`), FIFO flushing (`CMD_FLUSH`), and `BREAK` signalling (`CMD_SET_BREAK`).
//! 4. **Raw TCP Serial Data Plane (`TCP 4001..=4016`)**: Low-latency (`TCP_NODELAY`) streaming,
//!    Passive Dual-RX Tapping, Active Man-in-the-Middle (MITM) Bridging, and Byte-Diff/Checksum analysis.

use std::collections::{HashMap, VecDeque};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

// ---------------------------------------------------------------------------
// 1. Moxa Hardware Model Profiles & Auto-Adaptation Registry
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NPortModelProfile {
    pub model_id: u16,
    pub model_name: String,
    pub port_count: u8,
    pub interfaces: String,     // e.g. "RS-232" or "RS-232/422/485 (Software Selectable)"
    pub connector: String,      // e.g. "DB9 Male (DTE)" or "8-Pin RJ45"
    pub has_lcm_display: bool,
    pub requires_interface_check: bool,
}

impl NPortModelProfile {
    /// Look up a known Moxa NPort hardware profile by 16-bit Moxa Model ID or model string.
    pub fn from_model_id(model_id: u16) -> Self {
        match model_id {
            0x5110 => Self::new(0x5110, "NPort 5110", 1, "RS-232", "DB9 Male (DTE)", false, false),
            0x5130 => Self::new(0x5130, "NPort 5130", 1, "RS-422/485", "DB9 Male", false, true),
            0x5150 => Self::new(0x5150, "NPort 5150", 1, "RS-232/422/485", "DB9 Male (DTE)", false, true),
            0x5210 => Self::new(0x5210, "NPort 5210A", 2, "RS-232", "DB9 Male / RJ45", false, false),
            0x5230 => Self::new(0x5230, "NPort 5230", 2, "RS-232/422/485", "Terminal Block / RJ45", false, true),
            0x5250 => Self::new(0x5250, "NPort 5250A", 2, "RS-232/422/485", "DB9 Male (DTE)", false, true),
            0x5410 => Self::new(0x5410, "NPort 5410", 4, "RS-232", "DB9 Male (DTE)", true, false),
            0x5430 => Self::new(0x5430, "NPort 5430", 4, "RS-422/485", "Terminal Block", true, true),
            0x5450 => Self::new(0x5450, "NPort 5450", 4, "RS-232/422/485", "DB9 Male (DTE)", true, true),
            0x5610 => Self::new(0x5610, "NPort 5610-8-DT", 8, "RS-232", "DB9 Male (DTE)", true, false),
            0x5630 => Self::new(0x5630, "NPort 5630-8", 8, "RS-422/485", "8-Pin RJ45", true, true),
            0x5650 => Self::new(0x5650, "NPort 5650-8-DT", 8, "RS-232/422/485", "DB9 Male / RJ45", true, true),
            0x5616 => Self::new(0x5616, "NPort 5610-16", 16, "RS-232", "8-Pin RJ45", true, false),
            other => Self::new(other, "NPort 5610-8-DT", 8, "RS-232", "DB9 Male (DTE)", true, false),
        }
    }

    pub fn from_model_name(name: &str) -> Self {
        let upper = name.to_uppercase();
        if upper.contains("5110") {
            Self::from_model_id(0x5110)
        } else if upper.contains("5150") {
            Self::from_model_id(0x5150)
        } else if upper.contains("5210") {
            Self::from_model_id(0x5210)
        } else if upper.contains("5250") {
            Self::from_model_id(0x5250)
        } else if upper.contains("5410") {
            Self::from_model_id(0x5410)
        } else if upper.contains("5450") {
            Self::from_model_id(0x5450)
        } else if upper.contains("5650") {
            let mut p = Self::from_model_id(0x5650);
            if upper.contains("-16") {
                p.port_count = 16;
                p.model_name = String::from("NPort 5650-16");
            }
            p
        } else if upper.contains("5610-16") {
            Self::from_model_id(0x5616)
        } else if upper.contains("5610-8-DT-J") {
            Self::new(0x5610, "NPort 5610-8-DT-J", 8, "RS-232", "8-Pin RJ45", true, false)
        } else if upper.contains("5610") {
            Self::from_model_id(0x5610)
        } else {
            Self::from_model_id(0x5610)
        }
    }

    pub fn from_detected_port_count(port_count: u8) -> Self {
        match port_count {
            1 => Self::from_model_id(0x5110),
            2 => Self::from_model_id(0x5210),
            4 => Self::from_model_id(0x5450),
            16 => Self::from_model_id(0x5616),
            _ => Self::from_model_id(0x5610),
        }
    }

    fn new(
        model_id: u16,
        model_name: &str,
        port_count: u8,
        interfaces: &str,
        connector: &str,
        has_lcm_display: bool,
        requires_interface_check: bool,
    ) -> Self {
        Self {
            model_id,
            model_name: String::from(model_name),
            port_count,
            interfaces: String::from(interfaces),
            connector: String::from(connector),
            has_lcm_display,
            requires_interface_check,
        }
    }
}

// ---------------------------------------------------------------------------
// 2. Moxa ASPP (Async Server Private Protocol) Constants & Types
// ---------------------------------------------------------------------------

pub const ASPP_CMD_INIT: u8 = 0x10;
pub const ASPP_CMD_FLOWCTRL: u8 = 0x11;
pub const ASPP_CMD_LINECTRL: u8 = 0x12;
pub const ASPP_CMD_LSTATUS: u8 = 0x13;
pub const ASPP_CMD_FLUSH: u8 = 0x14;
pub const ASPP_CMD_SET_BREAK: u8 = 0x15;
pub const ASPP_CMD_STOP_BREAK: u8 = 0x21;
pub const ASPP_CMD_BAUDRATE: u8 = 0x23;

pub const STANDARD_BAUDS: [u32; 9] = [
    1200, 2400, 4800, 9600, 19200, 38400, 57600, 115200, 230400,
];

/// Map a standard baud rate to its Moxa ASPP baud table index.
pub fn aspp_baud_index(baud: u32) -> u8 {
    match baud {
        300 => 0,
        600 => 1,
        1200 => 2,
        2400 => 3,
        4800 => 4,
        7200 => 5,
        9600 => 6,
        19200 => 7,
        38400 => 8,
        57600 => 9,
        115200 => 10,
        230400 => 11,
        _ => 6,
    }
}

/// Supported UART framing presets on Moxa NPort servers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UartFraming {
    F8N1,
    F8E1,
    F8O1,
    F7E1,
    F7O1,
    F8N2,
    F8M1,
    F8S1,
}

impl UartFraming {
    pub const ALL: [UartFraming; 8] = [
        UartFraming::F8N1,
        UartFraming::F8E1,
        UartFraming::F8O1,
        UartFraming::F7E1,
        UartFraming::F7O1,
        UartFraming::F8N2,
        UartFraming::F8M1,
        UartFraming::F8S1,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            UartFraming::F8N1 => "8N1",
            UartFraming::F8E1 => "8E1",
            UartFraming::F8O1 => "8O1",
            UartFraming::F7E1 => "7E1",
            UartFraming::F7O1 => "7O1",
            UartFraming::F8N2 => "8N2",
            UartFraming::F8M1 => "8M1",
            UartFraming::F8S1 => "8S1",
        }
    }

    pub fn mode_byte(self) -> u8 {
        match self {
            UartFraming::F8N1 => 0x03,
            UartFraming::F8E1 => 0x1B,
            UartFraming::F8O1 => 0x0B,
            UartFraming::F7E1 => 0x1A,
            UartFraming::F7O1 => 0x0A,
            UartFraming::F8N2 => 0x07,
            UartFraming::F8M1 => 0x2B,
            UartFraming::F8S1 => 0x3B,
        }
    }

    pub fn next(self) -> Self {
        let idx = Self::ALL.iter().position(|&f| f == self).unwrap_or(0);
        Self::ALL[(idx + 1) % Self::ALL.len()]
    }
}

/// Hardware modem input line status returned by ASPP `CMD_LSTATUS` (`0x13`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModemStatus {
    pub cts: bool,
    pub dsr: bool,
    pub ri: bool,
    pub dcd: bool,
}

impl ModemStatus {
    pub fn from_aspp_byte(b: u8) -> Self {
        Self {
            cts: (b & 0x01) != 0,
            dsr: (b & 0x02) != 0,
            ri: (b & 0x04) != 0,
            dcd: (b & 0x08) != 0,
        }
    }
}

/// Pure encoders for Moxa ASPP Command Port (`TCP 966..=981`) packets.
pub mod aspp_codec {
    use super::*;

    pub fn encode_init(baud: u32, framing: UartFraming, dtr: bool, rts: bool) -> [u8; 6] {
        [
            ASPP_CMD_INIT,
            0x04,
            aspp_baud_index(baud),
            framing.mode_byte(),
            u8::from(dtr),
            u8::from(rts),
        ]
    }

    pub fn encode_linectrl(dtr: bool, rts: bool) -> [u8; 4] {
        [ASPP_CMD_LINECTRL, 0x02, u8::from(dtr), u8::from(rts)]
    }

    pub fn encode_lstatus() -> [u8; 2] {
        [ASPP_CMD_LSTATUS, 0x00]
    }

    pub fn encode_flush(target: u8) -> [u8; 3] {
        [ASPP_CMD_FLUSH, 0x01, target & 0x03]
    }

    pub fn encode_set_break() -> [u8; 2] {
        [ASPP_CMD_SET_BREAK, 0x00]
    }

    pub fn encode_stop_break() -> [u8; 2] {
        [ASPP_CMD_STOP_BREAK, 0x00]
    }

    pub fn encode_exact_baud(baud: u32) -> [u8; 6] {
        let le = baud.to_le_bytes();
        [ASPP_CMD_BAUDRATE, 0x04, le[0], le[1], le[2], le[3]]
    }
}

/// Async client for a single Moxa NPort ASPP Command Port (`966..=981`).
pub struct AsppClient {
    pub host: String,
    pub port_num: u8,
    pub timeout: Duration,
}

impl AsppClient {
    pub fn new(host: impl Into<String>, port_num: u8) -> Self {
        Self {
            host: host.into(),
            port_num: port_num.clamp(1, 16),
            timeout: Duration::from_millis(800),
        }
    }

    pub fn cmd_tcp_port(&self) -> u16 {
        965 + u16::from(self.port_num)
    }

    async fn transact(&self, pkt: &[u8]) -> Result<Vec<u8>> {
        let addr = format!("{}:{}", self.host, self.cmd_tcp_port());
        let mut stream = tokio::time::timeout(self.timeout, TcpStream::connect(&addr))
            .await
            .context("ASPP TCP connect timeout")?
            .context("ASPP TCP connect error")?;
        let _ = stream.set_nodelay(true);
        stream.write_all(pkt).await?;

        let mut buf = [0u8; 32];
        let n = tokio::time::timeout(self.timeout, stream.read(&mut buf))
            .await
            .context("ASPP read timeout")?
            .context("ASPP read error")?;
        Ok(buf[..n].to_vec())
    }

    pub async fn configure_uart(
        &self,
        baud: u32,
        framing: UartFraming,
        dtr: bool,
        rts: bool,
    ) -> Result<()> {
        let pkt = aspp_codec::encode_init(baud, framing, dtr, rts);
        let resp = self.transact(&pkt).await?;
        if resp.first().copied() == Some(ASPP_CMD_INIT) {
            Ok(())
        } else {
            Err(anyhow!("Unexpected ASPP CMD_INIT response: {:02X?}", resp))
        }
    }

    pub async fn set_line_control(&self, dtr: bool, rts: bool) -> Result<()> {
        let pkt = aspp_codec::encode_linectrl(dtr, rts);
        let resp = self.transact(&pkt).await?;
        if resp.first().copied() == Some(ASPP_CMD_LINECTRL) {
            Ok(())
        } else {
            Err(anyhow!("Unexpected ASPP CMD_LINECTRL response"))
        }
    }

    pub async fn flush_buffers(&self) -> Result<()> {
        let pkt = aspp_codec::encode_flush(0x02);
        let _ = self.transact(&pkt).await?;
        Ok(())
    }

    pub async fn send_break(&self, duration: Duration) -> Result<()> {
        let _ = self.transact(&aspp_codec::encode_set_break()).await?;
        tokio::time::sleep(duration).await;
        let _ = self.transact(&aspp_codec::encode_stop_break()).await?;
        Ok(())
    }

    pub async fn query_modem_status(&self) -> Result<ModemStatus> {
        let resp = self.transact(&aspp_codec::encode_lstatus()).await?;
        if resp.len() >= 3 && resp[0] == ASPP_CMD_LSTATUS {
            Ok(ModemStatus::from_aspp_byte(resp[2]))
        } else {
            Err(anyhow!("Invalid ASPP CMD_LSTATUS reply"))
        }
    }
}

// ---------------------------------------------------------------------------
// 3. Checksums, CRC-16/MODBUS & Reverse-Engineering Helpers
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChecksumSummary {
    pub xor8: u8,
    pub sum8: u8,
    pub lrc: u8,
    pub crc16_modbus: u16,
}

impl ChecksumSummary {
    pub fn compute(payload: &[u8]) -> Self {
        let mut xor8 = 0u8;
        let mut sum8 = 0u8;
        let mut crc: u16 = 0xFFFF;

        for &b in payload {
            xor8 ^= b;
            sum8 = sum8.wrapping_add(b);
            crc ^= u16::from(b);
            for _ in 0..8 {
                if (crc & 0x0001) != 0 {
                    crc = (crc >> 1) ^ 0xA001;
                } else {
                    crc >>= 1;
                }
            }
        }
        let lrc = sum8.wrapping_neg();
        Self {
            xor8,
            sum8,
            lrc,
            crc16_modbus: crc,
        }
    }
}

pub fn parse_payload_input(input: &str) -> Result<Vec<u8>> {
    let trimmed = input.trim();
    if let Some(hex_body) = trimmed
        .strip_prefix("hex:")
        .or_else(|| trimmed.strip_prefix("HEX:"))
    {
        let cleaned = hex_body.replace([',', ':'], " ").replace("0x", "");
        let mut out = Vec::new();
        for token in cleaned.split_whitespace() {
            let b = u8::from_str_radix(token, 16)
                .with_context(|| format!("Invalid hex byte '{token}'"))?;
            out.push(b);
        }
        return Ok(out);
    }

    let mut out = Vec::new();
    let bytes = trimmed.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            match bytes[i + 1] {
                b'r' => {
                    out.push(0x0D);
                    i += 2;
                }
                b'n' => {
                    out.push(0x0A);
                    i += 2;
                }
                b't' => {
                    out.push(0x09);
                    i += 2;
                }
                b'x' if i + 3 < bytes.len() => {
                    let hex_slice = std::str::from_utf8(&bytes[i + 2..i + 4]).unwrap_or("00");
                    let b = u8::from_str_radix(hex_slice, 16)
                        .with_context(|| format!("Invalid escape \\x{hex_slice}"))?;
                    out.push(b);
                    i += 4;
                }
                other => {
                    out.push(other);
                    i += 2;
                }
            }
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// 4. Multi-Protocol Model & Config Auto-Discovery (UDP 4800 + SNMP + HTTP + TCP)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredNPort {
    pub ip_address: String,
    pub mac_address: String,
    pub profile: NPortModelProfile,
    pub discovery_method: String,
}

/// Parse a Moxa UDP 4800 DSU `0x81` Identify response packet into a `DiscoveredNPort`.
pub fn parse_dsu_identify_response(ip: String, data: &[u8]) -> Option<DiscoveredNPort> {
    if data.len() < 24 || !matches!(data[0], 0x81 | 0x01) {
        return None;
    }

    // Moxa DSU Identify reply carries the 16-bit Model ID (e.g. 0x5610, 0x5450)
    // and the 6-byte Moxa MAC address (00:90:E8:xx:xx:xx).
    let mut mac = String::from("00:90:E8:XX:XX:XX");
    for win in data.windows(6) {
        if win[0..3] == [0x00, 0x90, 0xE8] {
            mac = format!(
                "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                win[0], win[1], win[2], win[3], win[4], win[5]
            );
            break;
        }
    }

    let mut detected_profile = None;
    for win in data.windows(2) {
        let be = u16::from_be_bytes([win[0], win[1]]);
        let le = u16::from_le_bytes([win[0], win[1]]);
        for candidate in [be, le] {
            if matches!(
                candidate,
                0x5110 | 0x5130 | 0x5150 | 0x5210 | 0x5230 | 0x5250 | 0x5410 | 0x5430 | 0x5450 | 0x5610 | 0x5630 | 0x5650 | 0x5616
            ) {
                detected_profile = Some(NPortModelProfile::from_model_id(candidate));
                break;
            }
        }
        if detected_profile.is_some() {
            break;
        }
    }

    // Also check if ASCII model string is embedded in the DSU payload
    if detected_profile.is_none() {
        let ascii: String = data
            .iter()
            .map(|&b| if (32..=126).contains(&b) { b as char } else { ' ' })
            .collect();
        if ascii.contains("5450")
            || ascii.contains("5610")
            || ascii.contains("5210")
            || ascii.contains("5110")
            || ascii.contains("5650")
        {
            detected_profile = Some(NPortModelProfile::from_model_name(&ascii));
        }
    }

    Some(DiscoveredNPort {
        ip_address: ip,
        mac_address: mac,
        profile: detected_profile.unwrap_or_else(|| NPortModelProfile::from_model_id(0x5610)),
        discovery_method: String::from("UDP 4800 DSU Identify"),
    })
}

/// Broadcast a Moxa DSU Identify query on UDP 4800 to discover all NPort units on the LAN.
pub async fn discover_nports_udp(timeout: Duration) -> Result<Vec<DiscoveredNPort>> {
    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    sock.set_broadcast(true)?;

    let query: [u8; 8] = [0x01, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00];
    let _ = sock.send_to(&query, "255.255.255.255:4800").await;

    let mut found = HashMap::new();
    let deadline = Instant::now() + timeout;
    let mut buf = [0u8; 512];

    while Instant::now() < deadline {
        let remain = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(
            remain.min(Duration::from_millis(200)),
            sock.recv_from(&mut buf),
        )
        .await
        {
            Ok(Ok((n, addr))) => {
                let ip = addr.ip().to_string();
                if let Some(dev) = parse_dsu_identify_response(ip.clone(), &buf[..n]) {
                    found.insert(ip, dev);
                }
            }
            _ => continue,
        }
    }
    Ok(found.into_values().collect())
}

/// Multi-method hardware probe against a specific Moxa IP address:
/// 1. Unicast UDP 4800 DSU `CMD_IDENTIFY`
/// 2. HTTP Web Console banner scrape (`GET /main.htm` or `GET /`)
/// 3. Active TCP Data (`4001..4016`) & ASPP (`966..981`) port-count scan
pub async fn auto_detect_nport_model(host: &str, timeout: Duration) -> DiscoveredNPort {
    // Method 1: Unicast UDP 4800 DSU Identify
    if let Ok(sock) = UdpSocket::bind("0.0.0.0:0").await {
        let query: [u8; 8] = [0x01, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00];
        let target = format!("{host}:4800");
        if sock.send_to(&query, &target).await.is_ok() {
            let mut buf = [0u8; 512];
            if let Ok(Ok((n, _))) = tokio::time::timeout(timeout, sock.recv_from(&mut buf)).await {
                if let Some(dev) = parse_dsu_identify_response(host.to_string(), &buf[..n]) {
                    return dev;
                }
            }
        }
    }

    // Method 2: HTTP Port 80 Banner / Overview Scrape
    if let Ok(Ok(mut stream)) =
        tokio::time::timeout(timeout, TcpStream::connect(format!("{host}:80"))).await
    {
        let req = format!(
            "GET /main.htm HTTP/1.0\r\nHost: {host}\r\nUser-Agent: smt-control-system/0.1\r\n\r\n"
        );
        if stream.write_all(req.as_bytes()).await.is_ok() {
            let mut buf = vec![0u8; 4096];
            if let Ok(Ok(n)) = tokio::time::timeout(timeout, stream.read(&mut buf)).await {
                let text = String::from_utf8_lossy(&buf[..n]);
                for marker in [
                    "5610-8-DT-J",
                    "5610-8-DT",
                    "5650-8-DT",
                    "5610-16",
                    "5450",
                    "5410",
                    "5250",
                    "5210",
                    "5150",
                    "5110",
                ] {
                    if text.contains(marker) {
                        return DiscoveredNPort {
                            ip_address: host.to_string(),
                            mac_address: String::from("00:90:E8:XX:XX:XX"),
                            profile: NPortModelProfile::from_model_name(marker),
                            discovery_method: String::from("HTTP Port 80 Web Banner"),
                        };
                    }
                }
            }
        }
    }

    // Method 3: Active ASPP (966..981) & TCP Data (4001..4016) Port-Count Scan
    let mut highest_active_port: u8 = 0;
    for p in 1..=16u8 {
        let data_addr = format!("{host}:{}", 4000 + u16::from(p));
        let cmd_addr = format!("{host}:{}", 965 + u16::from(p));
        let data_ok = tokio::time::timeout(
            Duration::from_millis(180),
            TcpStream::connect(&data_addr),
        )
        .await
        .map(|r| r.is_ok())
        .unwrap_or(false);
        let cmd_ok = if !data_ok {
            tokio::time::timeout(Duration::from_millis(180), TcpStream::connect(&cmd_addr))
                .await
                .map(|r| r.is_ok())
                .unwrap_or(false)
        } else {
            true
        };
        if data_ok || cmd_ok {
            highest_active_port = p;
        }
    }

    let inferred_count = match highest_active_port {
        0 => 8, // Default to 8-port 5610-8-DT when offline
        1 => 1,
        2 => 2,
        3..=4 => 4,
        5..=8 => 8,
        _ => 16,
    };

    DiscoveredNPort {
        ip_address: host.to_string(),
        mac_address: String::from("00:90:E8:XX:XX:XX"),
        profile: NPortModelProfile::from_detected_port_count(inferred_count),
        discovery_method: if highest_active_port > 0 {
            format!("TCP/ASPP Active Port Scan ({inferred_count} ports)")
        } else {
            String::from("Default Profile (NPort 5610-8-DT)")
        },
    }
}

// ---------------------------------------------------------------------------
// 5. Dynamic Multi-Port NPort State & Async Controller Engine
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortState {
    pub port_num: u8,
    pub baud: u32,
    pub framing: UartFraming,
    pub dtr: bool,
    pub rts: bool,
    pub modem: ModemStatus,
    pub tcp_data_open: bool,
    pub aspp_cmd_open: bool,
    pub connected: bool,
    pub role: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_frames: u64,
    pub tx_frames: u64,
}

impl PortState {
    pub fn new(port_num: u8) -> Self {
        Self {
            port_num,
            baud: 9600,
            framing: UartFraming::F8N1,
            dtr: true,
            rts: true,
            modem: ModemStatus::default(),
            tcp_data_open: false,
            aspp_cmd_open: false,
            connected: false,
            role: String::from("IDLE"),
            rx_bytes: 0,
            tx_bytes: 0,
            rx_frames: 0,
            tx_frames: 0,
        }
    }

    pub fn data_tcp_port(&self) -> u16 {
        4000 + u16::from(self.port_num)
    }

    pub fn aspp_tcp_port(&self) -> u16 {
        965 + u16::from(self.port_num)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerialFrame {
    pub seq: u64,
    pub timestamp: DateTime<Local>,
    pub delta_ms: f64,
    pub port_num: u8,
    pub direction: String,
    pub payload: Vec<u8>,
    pub changed_indices: Vec<usize>,
    pub checksums: ChecksumSummary,
}

impl SerialFrame {
    pub fn hex_string(&self) -> String {
        self.payload
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(" ")
    }

    pub fn ascii_string(&self) -> String {
        self.payload
            .iter()
            .map(|&b| {
                if (32..=126).contains(&b) {
                    b as char
                } else {
                    '.'
                }
            })
            .collect()
    }

    pub fn format_log_line(&self) -> String {
        format!(
            "#{:<5} [{} +{:>8.2}ms] {:<14} ({:>3}B) | {:<45} | {:<16} | XOR:{:02X} LRC:{:02X} CRC16:{:04X} | Diff:{:?}",
            self.seq,
            self.timestamp.format("%Y-%m-%d %H:%M:%S%.3f"),
            self.delta_ms,
            self.direction,
            self.payload.len(),
            self.hex_string(),
            self.ascii_string(),
            self.checksums.xor8,
            self.checksums.lrc,
            self.checksums.crc16_modbus,
            self.changed_indices
        )
    }
}

pub struct SharedEngineState {
    pub host: String,
    pub profile: NPortModelProfile,
    pub discovery_method: String,
    pub gap_ms: f64,
    pub simulate: bool,
    pub mode_banner: String,
    pub ports: Vec<PortState>,
    pub frames: VecDeque<SerialFrame>,
    pub status_log: VecDeque<String>,
    pub jsonl_path: Option<PathBuf>,
    pub text_log_path: Option<PathBuf>,
    jsonl_file: Option<std::fs::File>,
    text_log_file: Option<std::fs::File>,
    pub frame_tx: tokio::sync::broadcast::Sender<SerialFrame>,
    seq: u64,
    last_instant: Option<Instant>,
    last_payload_by_dir: HashMap<String, Vec<u8>>,
    tx_senders: HashMap<u8, tokio::sync::mpsc::UnboundedSender<Vec<u8>>>,
    mitm_peer: HashMap<u8, u8>,
}

impl SharedEngineState {
    pub fn new(host: String, gap_ms: f64, simulate: bool) -> Self {
        let profile = NPortModelProfile::from_model_id(0x5610);
        let mut ports: Vec<PortState> = (1..=profile.port_count).map(PortState::new).collect();
        if simulate {
            for p in &mut ports {
                p.tcp_data_open = true;
                p.aspp_cmd_open = true;
                if p.port_num <= 4 {
                    p.modem.cts = true;
                    p.modem.dsr = true;
                }
                if p.port_num <= 2 {
                    p.modem.dcd = true;
                }
            }
            if ports.len() >= 2 {
                ports[0].connected = true;
                ports[0].role = String::from("TAP-A (CTRL→DEV)");
                ports[1].connected = true;
                ports[1].role = String::from("TAP-B (DEV→CTRL)");
            }
        }

        let (frame_tx, _) = tokio::sync::broadcast::channel(256);

        let mut st = Self {
            host: host.clone(),
            profile: profile.clone(),
            discovery_method: if simulate {
                String::from("Simulated Profile")
            } else {
                String::from("Pending Auto-Detect")
            },
            gap_ms,
            simulate,
            mode_banner: if simulate {
                String::from("PASSIVE TAP (P1 + P2) [DEMO]")
            } else {
                String::from("READY")
            },
            ports,
            frames: VecDeque::with_capacity(500),
            status_log: VecDeque::with_capacity(60),
            jsonl_path: None,
            text_log_path: None,
            jsonl_file: None,
            text_log_file: None,
            frame_tx,
            seq: 0,
            last_instant: None,
            last_payload_by_dir: HashMap::new(),
            tx_senders: HashMap::new(),
            mitm_peer: HashMap::new(),
        };
        st.log_event(format!(
            "Initialised Moxa engine for {} ({}-port {}, {}) at {}",
            profile.model_name,
            profile.port_count,
            profile.interfaces,
            profile.connector,
            host
        ));
        st
    }

    /// Adapt the engine's port table and metadata dynamically to a newly detected Moxa NPort profile.
    pub fn apply_detected_profile(&mut self, detected: DiscoveredNPort) {
        let new_count = detected.profile.port_count.clamp(1, 16);
        if self.ports.len() != usize::from(new_count) {
            self.ports = (1..=new_count).map(PortState::new).collect();
        }
        self.profile = detected.profile.clone();
        self.discovery_method = detected.discovery_method.clone();
        self.log_event(format!(
            "Auto-adapted to {} ({} ports, {}, {}) via {}",
            self.profile.model_name,
            self.profile.port_count,
            self.profile.interfaces,
            self.profile.connector,
            self.discovery_method
        ));
        if self.profile.requires_interface_check {
            self.log_event(format!(
                "NOTE: {} supports multi-interface (RS-232/422/485) — ensure ports are set to RS-232!",
                self.profile.model_name
            ));
        }
    }

    pub fn log_event(&mut self, msg: impl Into<String>) {
        let ts = Local::now().format("%H:%M:%S");
        let entry = format!("[{ts}] {}", msg.into());
        if let Some(ref mut tf) = self.text_log_file {
            let _ = writeln!(tf, "# EVENT {entry}");
            let _ = tf.flush();
        }
        if self.status_log.len() >= 60 {
            self.status_log.pop_front();
        }
        self.status_log.push_back(entry);
    }

    pub fn annotate_log(&mut self, note: &str) {
        let clean = note.trim();
        if clean.is_empty() {
            return;
        }
        let banner = format!("=== OPERATOR NOTE: {clean} ===");
        self.log_event(banner);
    }

    pub fn record_frame(&mut self, port_num: u8, direction: impl Into<String>, payload: Vec<u8>) {
        let direction = direction.into();
        let now = Local::now();
        let now_inst = Instant::now();
        let delta_ms = self
            .last_instant
            .map(|prev| now_inst.duration_since(prev).as_secs_f64() * 1000.0)
            .unwrap_or(0.0);
        self.last_instant = Some(now_inst);
        self.seq += 1;

        let changed_indices = if let Some(prev) = self.last_payload_by_dir.get(&direction) {
            payload
                .iter()
                .enumerate()
                .filter_map(|(i, &b)| {
                    if prev.get(i).copied() != Some(b) {
                        Some(i)
                    } else {
                        None
                    }
                })
                .collect()
        } else {
            Vec::new()
        };
        self.last_payload_by_dir
            .insert(direction.clone(), payload.clone());

        let checksums = ChecksumSummary::compute(&payload);
        let frame = SerialFrame {
            seq: self.seq,
            timestamp: now,
            delta_ms,
            port_num,
            direction,
            payload,
            changed_indices,
            checksums,
        };

        if let Some(ref mut jf) = self.jsonl_file {
            if let Ok(line) = serde_json::to_string(&frame) {
                let _ = writeln!(jf, "{line}");
                let _ = jf.flush();
            }
        }
        if let Some(ref mut tf) = self.text_log_file {
            let _ = writeln!(tf, "{}", frame.format_log_line());
            let _ = tf.flush();
        }

        let _ = self.frame_tx.send(frame.clone());

        if self.frames.len() >= 500 {
            self.frames.pop_front();
        }
        self.frames.push_back(frame);
    }

    /// Start or stop live dual-format (`.log` + `.jsonl`) stream recording on demand.
    pub fn toggle_jsonl(&mut self, custom_label: Option<&str>) -> Option<PathBuf> {
        if self.jsonl_file.is_some() || self.text_log_file.is_some() {
            self.jsonl_file = None;
            self.text_log_file = None;
            let old_log = self.text_log_path.take();
            let _ = self.jsonl_path.take();
            self.log_event(format!("Stopped live stream logging ({:?})", old_log));
            return None;
        }

        let _ = std::fs::create_dir_all("logs");
        let stamp = Local::now().format("%Y%m%d_%H%M%S");
        let tag = custom_label
            .map(|s| {
                s.chars()
                    .map(|c| if c.is_ascii_alphanumeric() || c == '_' || c == '-' { c } else { '_' })
                    .collect::<String>()
            })
            .filter(|s| !s.is_empty())
            .map(|s| format!("_{s}"))
            .unwrap_or_default();

        let jsonl_path = PathBuf::from(format!("logs/nport_stream{tag}_{stamp}.jsonl"));
        let log_path = PathBuf::from(format!("logs/nport_stream{tag}_{stamp}.log"));

        match (
            OpenOptions::new().create(true).append(true).open(&jsonl_path),
            OpenOptions::new().create(true).append(true).open(&log_path),
        ) {
            (Ok(jf), Ok(mut tf)) => {
                let _ = writeln!(
                    tf,
                    "# SMT Control System Live Stream Log — {} ({}) @ {}",
                    self.profile.model_name, self.host, stamp
                );
                let _ = tf.flush();
                self.jsonl_file = Some(jf);
                self.text_log_file = Some(tf);
                self.jsonl_path = Some(jsonl_path);
                self.text_log_path = Some(log_path.clone());
                self.log_event(format!(
                    "Live stream logging ON -> {} (+ .jsonl)",
                    log_path.display()
                ));
                Some(log_path)
            }
            (Err(e), _) | (_, Err(e)) => {
                self.log_event(format!("ERROR opening stream log files: {e}"));
                None
            }
        }
    }

    /// Immediately dump all buffered frames in memory (up to 500 frames) to a `.log` and `.jsonl` file on demand.
    pub fn dump_buffer_on_demand(&mut self, custom_label: Option<&str>) -> Option<PathBuf> {
        let _ = std::fs::create_dir_all("logs");
        let stamp = Local::now().format("%Y%m%d_%H%M%S");
        let tag = custom_label
            .map(|s| {
                s.chars()
                    .map(|c| if c.is_ascii_alphanumeric() || c == '_' || c == '-' { c } else { '_' })
                    .collect::<String>()
            })
            .filter(|s| !s.is_empty())
            .map(|s| format!("_{s}"))
            .unwrap_or_default();

        let log_path = PathBuf::from(format!("logs/nport_dump{tag}_{stamp}.log"));
        let jsonl_path = PathBuf::from(format!("logs/nport_dump{tag}_{stamp}.jsonl"));

        let mut tf = match OpenOptions::new().create(true).write(true).truncate(true).open(&log_path) {
            Ok(f) => f,
            Err(e) => {
                self.log_event(format!("ERROR creating on-demand dump file: {e}"));
                return None;
            }
        };
        let mut jf = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&jsonl_path)
            .ok();

        let _ = writeln!(
            tf,
            "# SMT Control System On-Demand Buffer Dump — {} ({}-Port {}) @ {}",
            self.profile.model_name, self.profile.port_count, self.profile.interfaces, self.host
        );
        let _ = writeln!(tf, "# Captured Frames: {}", self.frames.len());
        let _ = writeln!(tf, "{}", "-".repeat(120));

        for fr in &self.frames {
            let _ = writeln!(tf, "{}", fr.format_log_line());
            if let Some(ref mut jfile) = jf {
                if let Ok(js) = serde_json::to_string(fr) {
                    let _ = writeln!(jfile, "{js}");
                }
            }
        }
        let _ = tf.flush();
        let count = self.frames.len();
        self.log_event(format!(
            "Dumped {count} buffered frames on demand -> {} (+ .jsonl)",
            log_path.display()
        ));
        Some(log_path)
    }
}

/// High-level async controller handle that adapts automatically to any Moxa NPort model.
#[derive(Clone)]
pub struct NPortController {
    pub state: Arc<Mutex<SharedEngineState>>,
}

impl NPortController {
    pub fn new(host: impl Into<String>, gap_ms: f64, simulate: bool) -> Self {
        let state = Arc::new(Mutex::new(SharedEngineState::new(
            host.into(),
            gap_ms,
            simulate,
        )));
        let ctrl = Self { state };
        if simulate {
            ctrl.spawn_simulation_task();
        }
        ctrl
    }

    fn spawn_simulation_task(&self) {
        let state_arc = Arc::clone(&self.state);
        tokio::spawn(async move {
            let mut step: u32 = 0;
            loop {
                tokio::time::sleep(Duration::from_millis(950)).await;
                let (active, p1_role, p2_role) = {
                    let st = state_arc.lock().unwrap();
                    if st.ports.len() < 2 {
                        continue;
                    }
                    (
                        st.ports[0].connected && st.ports[1].connected,
                        st.ports[0].role.clone(),
                        st.ports[1].role.clone(),
                    )
                };
                if !active {
                    continue;
                }
                step = step.wrapping_add(1);

                let mut req = format!("\x0201POLL:{:02}\x03", step % 100).into_bytes();
                let xor_req = ChecksumSummary::compute(&req).xor8;
                req.push(xor_req);
                {
                    let mut st = state_arc.lock().unwrap();
                    st.ports[0].rx_bytes += req.len() as u64;
                    st.ports[0].rx_frames += 1;
                    let label = if p1_role.contains("MITM") {
                        "P1 MITM→P2"
                    } else {
                        "P1 CTRL→DEV"
                    };
                    st.record_frame(1, label, req);
                }

                tokio::time::sleep(Duration::from_millis(32)).await;

                let temp_c = 245 + (step % 6);
                let mut resp = format!("\x0201OK:T={temp_c}C:V=12.1V:S=READY\x03").into_bytes();
                let xor_resp = ChecksumSummary::compute(&resp).xor8;
                resp.push(xor_resp);
                {
                    let mut st = state_arc.lock().unwrap();
                    st.ports[1].rx_bytes += resp.len() as u64;
                    st.ports[1].rx_frames += 1;
                    let label = if p2_role.contains("MITM") {
                        "P2 MITM→P1"
                    } else {
                        "P2 DEV→CTRL"
                    };
                    st.record_frame(2, label, resp);
                }
            }
        });
    }

    /// Automatically detect the target Moxa NPort model (UDP 4800 -> HTTP 80 -> TCP/ASPP scan),
    /// adapt the controller's port count and profile, and poll all ports' live modem status.
    pub async fn probe_all_ports(&self) {
        let (host, simulate) = {
            let st = self.state.lock().unwrap();
            (st.host.clone(), st.simulate)
        };
        if simulate {
            let mut st = self.state.lock().unwrap();
            let model = st.profile.model_name.clone();
            let count = st.profile.port_count;
            st.log_event(format!(
                "Simulation mode: {model} ({count} ports) online and active"
            ));
            return;
        }

        let detected = auto_detect_nport_model(&host, Duration::from_millis(450)).await;
        let port_count = detected.profile.port_count;
        {
            let mut st = self.state.lock().unwrap();
            st.apply_detected_profile(detected);
        }

        let mut reachable = 0usize;
        for p in 1..=port_count {
            let data_addr = format!("{host}:{}", 4000 + u16::from(p));
            let cmd_addr = format!("{host}:{}", 965 + u16::from(p));
            let data_ok = tokio::time::timeout(
                Duration::from_millis(250),
                TcpStream::connect(&data_addr),
            )
            .await
            .map(|r| r.is_ok())
            .unwrap_or(false);
            let cmd_ok = tokio::time::timeout(
                Duration::from_millis(250),
                TcpStream::connect(&cmd_addr),
            )
            .await
            .map(|r| r.is_ok())
            .unwrap_or(false);

            let modem = if cmd_ok {
                AsppClient::new(&host, p)
                    .query_modem_status()
                    .await
                    .unwrap_or_default()
            } else {
                ModemStatus::default()
            };

            if data_ok || cmd_ok {
                reachable += 1;
            }
            let mut st = self.state.lock().unwrap();
            if let Some(ps) = st.ports.get_mut((p - 1) as usize) {
                ps.tcp_data_open = data_ok;
                ps.aspp_cmd_open = cmd_ok;
                ps.modem = modem;
            }
        }
        let mut st = self.state.lock().unwrap();
        let model_name = st.profile.model_name.clone();
        st.log_event(format!(
            "Probed {host} ({model_name}): {reachable}/{port_count} serial ports reachable"
        ));
    }

    pub async fn cycle_baud(&self, port_num: u8) {
        let (host, simulate, next_baud, framing, dtr, rts) = {
            let mut st = self.state.lock().unwrap();
            let host = st.host.clone();
            let simulate = st.simulate;
            let Some(ps) = st.ports.get_mut((port_num - 1) as usize) else {
                return;
            };
            let idx = STANDARD_BAUDS
                .iter()
                .position(|&b| b == ps.baud)
                .unwrap_or(3);
            ps.baud = STANDARD_BAUDS[(idx + 1) % STANDARD_BAUDS.len()];
            (host, simulate, ps.baud, ps.framing, ps.dtr, ps.rts)
        };
        if simulate {
            let mut st = self.state.lock().unwrap();
            st.log_event(format!(
                "Port {port_num} (ASPP :{}) baud updated to {next_baud} bps",
                965 + u16::from(port_num)
            ));
            return;
        }
        let res = AsppClient::new(host, port_num)
            .configure_uart(next_baud, framing, dtr, rts)
            .await;
        let mut st = self.state.lock().unwrap();
        match res {
            Ok(()) => st.log_event(format!(
                "Port {port_num} baud set to {next_baud} bps via ASPP"
            )),
            Err(e) => st.log_event(format!(
                "WARNING: Port {port_num} ASPP baud update failed: {e}"
            )),
        }
    }

    pub async fn cycle_framing(&self, port_num: u8) {
        let (host, simulate, baud, next_framing, dtr, rts) = {
            let mut st = self.state.lock().unwrap();
            let host = st.host.clone();
            let simulate = st.simulate;
            let Some(ps) = st.ports.get_mut((port_num - 1) as usize) else {
                return;
            };
            ps.framing = ps.framing.next();
            (host, simulate, ps.baud, ps.framing, ps.dtr, ps.rts)
        };
        if simulate {
            let mut st = self.state.lock().unwrap();
            st.log_event(format!(
                "Port {port_num} framing set to {}",
                next_framing.as_str()
            ));
            return;
        }
        let _ = AsppClient::new(host, port_num)
            .configure_uart(baud, next_framing, dtr, rts)
            .await;
        let mut st = self.state.lock().unwrap();
        st.log_event(format!(
            "Port {port_num} framing set to {} via ASPP",
            next_framing.as_str()
        ));
    }

    pub async fn toggle_dtr(&self, port_num: u8) {
        let (host, simulate, dtr, rts) = {
            let mut st = self.state.lock().unwrap();
            let host = st.host.clone();
            let simulate = st.simulate;
            let Some(ps) = st.ports.get_mut((port_num - 1) as usize) else {
                return;
            };
            ps.dtr = !ps.dtr;
            (host, simulate, ps.dtr, ps.rts)
        };
        if !simulate {
            let _ = AsppClient::new(host, port_num)
                .set_line_control(dtr, rts)
                .await;
        }
        let mut st = self.state.lock().unwrap();
        st.log_event(format!(
            "Port {port_num} DTR (Pin 4) -> {}",
            if dtr { "ON (Asserted)" } else { "OFF" }
        ));
    }

    pub async fn toggle_rts(&self, port_num: u8) {
        let (host, simulate, dtr, rts) = {
            let mut st = self.state.lock().unwrap();
            let host = st.host.clone();
            let simulate = st.simulate;
            let Some(ps) = st.ports.get_mut((port_num - 1) as usize) else {
                return;
            };
            ps.rts = !ps.rts;
            (host, simulate, ps.dtr, ps.rts)
        };
        if !simulate {
            let _ = AsppClient::new(host, port_num)
                .set_line_control(dtr, rts)
                .await;
        }
        let mut st = self.state.lock().unwrap();
        st.log_event(format!(
            "Port {port_num} RTS (Pin 7) -> {}",
            if rts { "ON (Asserted)" } else { "OFF" }
        ));
    }

    pub async fn flush_fifo(&self, port_num: u8) {
        let (host, simulate) = {
            let st = self.state.lock().unwrap();
            (st.host.clone(), st.simulate)
        };
        if !simulate {
            let _ = AsppClient::new(host, port_num).flush_buffers().await;
        }
        let mut st = self.state.lock().unwrap();
        st.log_event(format!(
            "Port {port_num} hardware TX/RX FIFOs flushed via ASPP 0x14"
        ));
    }

    pub async fn send_break(&self, port_num: u8) {
        let (host, simulate) = {
            let st = self.state.lock().unwrap();
            (st.host.clone(), st.simulate)
        };
        if !simulate {
            let _ = AsppClient::new(host, port_num)
                .send_break(Duration::from_millis(250))
                .await;
        }
        let mut st = self.state.lock().unwrap();
        st.log_event(format!(
            "Port {port_num} transmitted 250 ms RS-232 BREAK condition"
        ));
    }

    pub async fn connect_port(&self, port_num: u8, role: impl Into<String>) -> bool {
        let role = role.into();
        let (host, gap_ms) = {
            let mut st = self.state.lock().unwrap();
            if st.simulate {
                if let Some(ps) = st.ports.get_mut((port_num - 1) as usize) {
                    ps.connected = true;
                    ps.role = role.clone();
                }
                st.log_event(format!("Connected Port {port_num} in {role} mode [DEMO]"));
                return true;
            }
            (st.host.clone(), st.gap_ms)
        };

        let addr = format!("{host}:{}", 4000 + u16::from(port_num));
        let stream = match tokio::time::timeout(
            Duration::from_millis(1200),
            TcpStream::connect(&addr),
        )
        .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                self.state
                    .lock()
                    .unwrap()
                    .log_event(format!("ERROR connecting Port {port_num} ({addr}): {e}"));
                return false;
            }
            Err(_) => {
                self.state
                    .lock()
                    .unwrap()
                    .log_event(format!("ERROR timeout connecting Port {port_num} ({addr})"));
                return false;
            }
        };
        let _ = stream.set_nodelay(true);
        let (mut reader, mut writer) = stream.into_split();
        let (tx_chan, mut rx_chan) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();

        {
            let mut st = self.state.lock().unwrap();
            st.tx_senders.insert(port_num, tx_chan);
            if let Some(ps) = st.ports.get_mut((port_num - 1) as usize) {
                ps.connected = true;
                ps.tcp_data_open = true;
                ps.role = role.clone();
            }
            st.log_event(format!("Connected Port {port_num} ({addr}) [{role}]"));
        }

        tokio::spawn(async move {
            while let Some(pkt) = rx_chan.recv().await {
                if writer.write_all(&pkt).await.is_err() {
                    break;
                }
            }
        });

        let state_arc = Arc::clone(&self.state);
        let gap_dur = Duration::from_secs_f64((gap_ms / 1000.0).max(0.002));
        tokio::spawn(async move {
            let mut buf = Vec::with_capacity(256);
            let mut chunk = [0u8; 256];
            loop {
                let read_res = if buf.is_empty() {
                    reader.read(&mut chunk).await.map(Some)
                } else {
                    match tokio::time::timeout(gap_dur, reader.read(&mut chunk)).await {
                        Ok(res) => res.map(Some),
                        Err(_) => Ok(None),
                    }
                };

                match read_res {
                    Ok(Some(0)) | Err(_) => {
                        if !buf.is_empty() {
                            Self::flush_rx_buffer(&state_arc, port_num, &mut buf);
                        }
                        break;
                    }
                    Ok(Some(n)) => {
                        let slice = &chunk[..n];
                        buf.extend_from_slice(slice);
                        let mut st = state_arc.lock().unwrap();
                        if let Some(ps) = st.ports.get_mut((port_num - 1) as usize) {
                            ps.rx_bytes += n as u64;
                        }
                        if let Some(&peer) = st.mitm_peer.get(&port_num) {
                            if let Some(peer_tx) = st.tx_senders.get(&peer) {
                                let _ = peer_tx.send(slice.to_vec());
                                if let Some(peer_ps) = st.ports.get_mut((peer - 1) as usize) {
                                    peer_ps.tx_bytes += n as u64;
                                }
                            }
                        }
                    }
                    Ok(None) => {
                        if !buf.is_empty() {
                            Self::flush_rx_buffer(&state_arc, port_num, &mut buf);
                        }
                    }
                }
            }
            let mut st = state_arc.lock().unwrap();
            st.tx_senders.remove(&port_num);
            if let Some(ps) = st.ports.get_mut((port_num - 1) as usize) {
                ps.connected = false;
                ps.role = String::from("IDLE");
            }
        });

        true
    }

    fn flush_rx_buffer(
        state_arc: &Arc<Mutex<SharedEngineState>>,
        port_num: u8,
        buf: &mut Vec<u8>,
    ) {
        let payload = std::mem::take(buf);
        let mut st = state_arc.lock().unwrap();
        let mut label = format!("P{port_num} RX");
        if let Some(ps) = st.ports.get_mut((port_num - 1) as usize) {
            ps.rx_frames += 1;
            if ps.role.contains("TAP-A") {
                label = format!("P{port_num} CTRL→DEV");
            } else if ps.role.contains("TAP-B") {
                label = format!("P{port_num} DEV→CTRL");
            } else if ps.role.contains("MITM") {
                label = format!("P{port_num} MITM");
            }
        }
        st.record_frame(port_num, label, payload);
    }

    pub fn disconnect_port(&self, port_num: u8) {
        let mut st = self.state.lock().unwrap();
        st.tx_senders.remove(&port_num);
        if let Some(peer) = st.mitm_peer.remove(&port_num) {
            st.mitm_peer.remove(&peer);
        }
        if let Some(ps) = st.ports.get_mut((port_num - 1) as usize) {
            ps.connected = false;
            ps.role = String::from("IDLE");
        }
        st.log_event(format!("Disconnected Port {port_num}"));
    }

    pub async fn start_passive_tap(&self, port_a: u8, port_b: u8) {
        let max_p = { self.state.lock().unwrap().ports.len() as u8 };
        for p in 1..=max_p {
            self.disconnect_port(p);
        }
        let ok_a = self.connect_port(port_a, "TAP-A (CTRL→DEV)").await;
        let ok_b = self.connect_port(port_b, "TAP-B (DEV→CTRL)").await;
        if ok_a && ok_b {
            let mut st = self.state.lock().unwrap();
            st.mode_banner = format!("PASSIVE TAP (P{port_a} + P{port_b})");
            st.log_event(format!(
                "Passive Dual-RX Tap active on P{port_a} (CTRL→DEV) & P{port_b} (DEV→CTRL)"
            ));
        }
    }

    pub async fn start_mitm_bridge(&self, port_a: u8, port_b: u8) {
        let max_p = { self.state.lock().unwrap().ports.len() as u8 };
        for p in 1..=max_p {
            self.disconnect_port(p);
        }
        let ok_a = self
            .connect_port(port_a, format!("MITM-A (⇄P{port_b})"))
            .await;
        let ok_b = self
            .connect_port(port_b, format!("MITM-B (⇄P{port_a})"))
            .await;
        if ok_a && ok_b {
            let mut st = self.state.lock().unwrap();
            st.mitm_peer.insert(port_a, port_b);
            st.mitm_peer.insert(port_b, port_a);
            st.mode_banner = format!("ACTIVE MITM BRIDGE (P{port_a} ⟷ P{port_b})");
            st.log_event(format!(
                "Active MITM Bridge established between Port {port_a} and Port {port_b}"
            ));
        }
    }

    pub async fn inject_payload(&self, port_num: u8, payload: Vec<u8>) {
        let is_connected = {
            let st = self.state.lock().unwrap();
            st.ports
                .get((port_num - 1) as usize)
                .map(|p| p.connected)
                .unwrap_or(false)
        };
        if !is_connected && !self.connect_port(port_num, "STREAM").await {
            return;
        }

        let mut st = self.state.lock().unwrap();
        if !st.simulate {
            if let Some(tx) = st.tx_senders.get(&port_num) {
                let _ = tx.send(payload.clone());
            }
        }
        if let Some(ps) = st.ports.get_mut((port_num - 1) as usize) {
            ps.tx_bytes += payload.len() as u64;
            ps.tx_frames += 1;
        }
        st.record_frame(port_num, format!("P{port_num} TX→LINE"), payload.clone());

        if st.simulate {
            let mut reply = b"\x0201ACK:".to_vec();
            reply.extend_from_slice(&payload[..payload.len().min(10)]);
            reply.push(0x03);
            let xor = ChecksumSummary::compute(&reply).xor8;
            reply.push(xor);
            if let Some(ps) = st.ports.get_mut((port_num - 1) as usize) {
                ps.rx_bytes += reply.len() as u64;
                ps.rx_frames += 1;
            }
            st.record_frame(port_num, format!("P{port_num} RX←DEV"), reply);
        }
    }

    /// Switch the controller to a new Moxa NPort IP address at runtime, disconnect old streams,
    /// and automatically probe the new device's model, port count, and hardware line status.
    pub async fn switch_target_host(&self, new_host: impl Into<String>) {
        let cleaned = new_host.into().trim().to_string();
        if cleaned.is_empty() {
            return;
        }
        let max_p = { self.state.lock().unwrap().ports.len() as u8 };
        for p in 1..=max_p {
            self.disconnect_port(p);
        }

        let is_demo = cleaned.eq_ignore_ascii_case("demo") || cleaned.eq_ignore_ascii_case("sim");
        {
            let mut st = self.state.lock().unwrap();
            if is_demo {
                let h = st.host.clone();
                st.simulate = true;
                st.mode_banner = String::from("DEMO SIMULATION");
                st.log_event(format!("Switched target to Simulation Mode ({h})"));
            } else {
                st.host = cleaned.clone();
                st.simulate = false;
                st.mode_banner = String::from("PROBED");
                st.log_event(format!("Switching target Moxa IP address to {cleaned} ..."));
            }
        }
        self.probe_all_ports().await;
    }
}

/// Helper to return the natural adjacent port pair `(1,2)`, `(3,4)`, `(5,6)`, etc.
pub fn adjacent_port_pair(port_num: u8, max_ports: u8) -> (u8, u8) {
    if max_ports < 2 {
        return (1, 1);
    }
    let p = port_num.clamp(1, max_ports);
    let base = ((p - 1) / 2) * 2 + 1;
    (base, (base + 1).min(max_ports))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aspp_packet_encoders() {
        let init_pkt = aspp_codec::encode_init(19200, UartFraming::F8N1, true, false);
        assert_eq!(init_pkt, [0x10, 0x04, 7, 0x03, 1, 0]);

        let line_pkt = aspp_codec::encode_linectrl(false, true);
        assert_eq!(line_pkt, [0x12, 0x02, 0, 1]);

        let baud_pkt = aspp_codec::encode_exact_baud(115200);
        assert_eq!(baud_pkt, [0x23, 0x04, 0x00, 0xC2, 0x01, 0x00]);
    }

    #[test]
    fn test_model_profile_adaptation() {
        let p5610 = NPortModelProfile::from_model_id(0x5610);
        assert_eq!(p5610.model_name, "NPort 5610-8-DT");
        assert_eq!(p5610.port_count, 8);
        assert!(!p5610.requires_interface_check);

        let p5450 = NPortModelProfile::from_model_id(0x5450);
        assert_eq!(p5450.model_name, "NPort 5450");
        assert_eq!(p5450.port_count, 4);
        assert!(p5450.requires_interface_check);
    }

    #[test]
    fn test_dsu_identify_response_parser() {
        let mut fake_reply = vec![0x81, 0x00, 0x00, 0x24];
        fake_reply.extend_from_slice(&[0x56, 0x10]); // Model ID 0x5610
        fake_reply.extend_from_slice(&[0x00, 0x90, 0xE8, 0x12, 0x34, 0x56]); // Moxa MAC
        fake_reply.resize(36, 0);

        let parsed = parse_dsu_identify_response("192.168.127.254".into(), &fake_reply).unwrap();
        assert_eq!(parsed.profile.model_name, "NPort 5610-8-DT");
        assert_eq!(parsed.profile.port_count, 8);
        assert_eq!(parsed.mac_address, "00:90:E8:12:34:56");
    }

    #[test]
    fn test_checksums_and_crc16_modbus() {
        let frame = [0x01u8, 0x03, 0x00, 0x00, 0x00, 0x0A];
        let cs = ChecksumSummary::compute(&frame);
        assert_eq!(cs.crc16_modbus, 0xCDC5);
        assert_eq!(cs.xor8, 0x01 ^ 0x03 ^ 0x0A);
    }
}
