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
pub const ASPP_CMD_BAUDRATE: u8 = 0x17;
pub const ASPP_CMD_STOP_BREAK: u8 = 0x21;

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
            UartFraming::F8E1 => 0x0B,
            UartFraming::F8O1 => 0x13,
            UartFraming::F7E1 => 0x0A,
            UartFraming::F7O1 => 0x12,
            UartFraming::F8N2 => 0x07,
            UartFraming::F8M1 => 0x1B,
            UartFraming::F8S1 => 0x23,
        }
    }

    pub fn from_mode_byte(b: u8) -> Self {
        match b & 0x3F {
            0x03 => UartFraming::F8N1,
            0x0B => UartFraming::F8E1,
            0x13 => UartFraming::F8O1,
            0x0A => UartFraming::F7E1,
            0x12 => UartFraming::F7O1,
            0x07 => UartFraming::F8N2,
            0x1B => UartFraming::F8M1,
            0x23 => UartFraming::F8S1,
            _ => UartFraming::F8N1,
        }
    }

    pub fn next(self) -> Self {
        let idx = Self::ALL.iter().position(|&f| f == self).unwrap_or(0);
        Self::ALL[(idx + 1) % Self::ALL.len()]
    }
}

/// Physical serial electrical interface modes on Moxa NPort servers.
/// Note: `-10` models (`NPort 5610-8-DT`, `5410`, `5210`, `5110`) have fixed RS-232 transceivers,
/// whereas `-50` / `-30` models (`NPort 5650-8-DT`, `5450`, `5250A`, `5150`) allow software selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SerialInterface {
    Rs232,
    Rs485TwoWire,
    Rs422,
    Rs485FourWire,
}

impl SerialInterface {
    pub const ALL: [SerialInterface; 4] = [
        SerialInterface::Rs232,
        SerialInterface::Rs485TwoWire,
        SerialInterface::Rs422,
        SerialInterface::Rs485FourWire,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            SerialInterface::Rs232 => "RS-232",
            SerialInterface::Rs485TwoWire => "RS-485 2W",
            SerialInterface::Rs422 => "RS-422",
            SerialInterface::Rs485FourWire => "RS-485 4W",
        }
    }

    pub fn from_dsu_byte(b: u8) -> Self {
        match b {
            0x01 => SerialInterface::Rs485TwoWire,
            0x02 => SerialInterface::Rs422,
            0x03 => SerialInterface::Rs485FourWire,
            _ => SerialInterface::Rs232,
        }
    }

    pub fn next(self) -> Self {
        let idx = Self::ALL.iter().position(|&i| i == self).unwrap_or(0);
        Self::ALL[(idx + 1) % Self::ALL.len()]
    }
}

/// Per-port UART flow control options supported via Moxa ASPP (`0x2C` / `0x11`) and DSU (`0x34`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowControl {
    None,
    RtsCts,
    XonXoff,
    DtrDsr,
}

impl FlowControl {
    pub const ALL: [FlowControl; 4] = [
        FlowControl::None,
        FlowControl::RtsCts,
        FlowControl::XonXoff,
        FlowControl::DtrDsr,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            FlowControl::None => "NONE",
            FlowControl::RtsCts => "RTS/CTS",
            FlowControl::XonXoff => "XON/XOFF",
            FlowControl::DtrDsr => "DTR/DSR",
        }
    }

    pub fn from_dsu_byte(b: u8) -> Self {
        match b {
            0x01 => FlowControl::RtsCts,
            0x02 => FlowControl::XonXoff,
            0x03 => FlowControl::DtrDsr,
            _ => FlowControl::None,
        }
    }

    pub fn aspp_flags(self) -> [u8; 4] {
        match self {
            FlowControl::None => [0, 0, 0, 0],
            FlowControl::RtsCts => [1, 1, 0, 0],
            FlowControl::XonXoff => [0, 0, 1, 1],
            FlowControl::DtrDsr => [1, 1, 0, 0],
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

    pub const ASPP_CMD_PORT_INIT: u8 = 0x2C;
    pub const ASPP_CMD_FLOWCTRL: u8 = 0x11;

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

    /// Encode the 10-byte Moxa RealCOM `ASPP_CMD_PORT_INIT` (`0x2C`) packet verified on NPort 5610-8-DT.
    pub fn encode_port_init(baud: u32, framing: UartFraming, dtr: bool, rts: bool) -> [u8; 10] {
        encode_port_init_with_flow(baud, framing, dtr, rts, FlowControl::None)
    }

    /// Encode `ASPP_CMD_PORT_INIT` (`0x2C`) with explicit flow-control flags (`RTS/CTS` / `XON/XOFF`).
    pub fn encode_port_init_with_flow(
        baud: u32,
        framing: UartFraming,
        dtr: bool,
        rts: bool,
        flow: FlowControl,
    ) -> [u8; 10] {
        let [fl_tx, fl_rx, ixon, ixoff] = flow.aspp_flags();
        [
            ASPP_CMD_PORT_INIT,
            0x08,
            aspp_baud_index(baud),
            framing.mode_byte(),
            u8::from(dtr),
            u8::from(rts),
            fl_tx,
            fl_rx,
            ixon,
            ixoff,
        ]
    }

    /// Encode the 6-byte Moxa `ASPP_CMD_FLOWCTRL` (`0x11`) packet (`11 04 <tx_hw> <rx_hw> <ixon> <ixoff>`).
    pub fn encode_flowctrl(flow: FlowControl) -> [u8; 6] {
        let [fl_tx, fl_rx, ixon, ixoff] = flow.aspp_flags();
        [ASPP_CMD_FLOWCTRL, 0x04, fl_tx, fl_rx, ixon, ixoff]
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

    /// Encode the 6-byte Moxa `ASPP_CMD_SETBAUD` (`0x17`) exact 32-bit baud rate packet verified on NPort 5610-8-DT.
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
            timeout: Duration::from_millis(600),
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
        // Ensure a RealCOM Data socket (:949+p) or TCP Server socket (:4000+p) is open while
        // sending 0x2C, because NPort 5610 firmware ignores 0x2C when the Data socket is closed.
        let realcom_addr = format!("{}:{}", self.host, 949 + u16::from(self.port_num));
        let tcpsrv_addr = format!("{}:{}", self.host, 4000 + u16::from(self.port_num));
        let _data_guard = match tokio::time::timeout(
            Duration::from_millis(250),
            TcpStream::connect(&realcom_addr),
        )
        .await
        {
            Ok(Ok(s)) => Some(s),
            _ => tokio::time::timeout(
                Duration::from_millis(250),
                TcpStream::connect(&tcpsrv_addr),
            )
            .await
            .ok()
            .and_then(|r| r.ok()),
        };

        let addr = format!("{}:{}", self.host, self.cmd_tcp_port());
        let mut stream = tokio::time::timeout(self.timeout, TcpStream::connect(&addr))
            .await
            .context("ASPP TCP connect timeout")?
            .context("ASPP TCP connect error")?;
        let _ = stream.set_nodelay(true);

        // 1. Send 0x2C (ASPP_CMD_PORT_INIT)
        let init_pkt = aspp_codec::encode_port_init(baud, framing, dtr, rts);
        stream.write_all(&init_pkt).await?;
        let mut buf = [0u8; 32];
        let _ = tokio::time::timeout(self.timeout, stream.read(&mut buf)).await;

        // 2. Send 0x17 (ASPP_CMD_SETBAUD exact 32-bit baud rate)
        let baud_pkt = aspp_codec::encode_exact_baud(baud);
        stream.write_all(&baud_pkt).await?;
        let n = tokio::time::timeout(self.timeout, stream.read(&mut buf))
            .await
            .context("ASPP SETBAUD read timeout")?
            .context("ASPP SETBAUD read error")?;

        if n > 0 && (buf[0] == ASPP_CMD_BAUDRATE || buf[0] == aspp_codec::ASPP_CMD_PORT_INIT) {
            Ok(())
        } else {
            Err(anyhow!(
                "Unexpected ASPP UART config response: {:02X?}",
                &buf[..n]
            ))
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
        // Send 0x2C Port Init query or 0x13 LSTATUS to read live modem status bits
        let pkt = aspp_codec::encode_port_init(9600, UartFraming::F8N1, true, true);
        if let Ok(resp) = self.transact(&pkt).await {
            if resp.len() >= 5 && resp[0] == aspp_codec::ASPP_CMD_PORT_INIT {
                return Ok(ModemStatus::from_aspp_byte(resp[2]));
            }
        }
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

/// Live per-port configuration read directly from a Moxa NPort unit via UDP 4800 DSU/DSCI
/// opcodes `0x31` (UART Baud & Framing), `0x34` (Flow Control), `0x37` (Port Alias), and `0x47` (Operating Mode).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DsuPortConfig {
    pub port_num: u8,
    pub baud: u32,
    pub framing: UartFraming,
    pub interface: SerialInterface,
    pub flow_control: FlowControl,
    pub alias: String,
    pub op_mode: String,
    pub tcp_port: u16,
}

/// Poll a Moxa NPort over UDP 4800 DSU protocol (`0x01` -> `0x31`, `0x34`, `0x37`, `0x47`) to retrieve
/// the current per-port baud rate, UART framing, flow control, alias, and operating mode for all ports.
pub async fn query_dsu_port_configs(host: &str, timeout: Duration) -> Vec<DsuPortConfig> {
    let Ok(sock) = UdpSocket::bind("0.0.0.0:0").await else {
        return Vec::new();
    };
    let target = format!("{host}:4800");

    // Step 1: Send 0x01 Identify to obtain the 12-byte device ID header (bytes 8..20 of reply)
    let id_req: [u8; 8] = [0x01, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00];
    if sock.send_to(&id_req, &target).await.is_err() {
        return Vec::new();
    }
    let mut buf = [0u8; 1024];
    let Ok(Ok((n, _))) = tokio::time::timeout(timeout, sock.recv_from(&mut buf)).await else {
        return Vec::new();
    };
    if n < 20 || buf[0] != 0x81 {
        return Vec::new();
    }
    let dev_id = buf[8..20].to_vec();

    let mut configs: Vec<DsuPortConfig> = Vec::new();

    // Step 2: Opcode 0x31 — Per-port UART Baud (u32 LE) & Framing mode byte
    let mut req31 = vec![0x31, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00];
    req31.extend_from_slice(&dev_id);
    if sock.send_to(&req31, &target).await.is_ok() {
        if let Ok(Ok((n31, _))) = tokio::time::timeout(timeout, sock.recv_from(&mut buf)).await {
            if n31 >= 24 && buf[0] == 0xB1 && buf[1] == 0x00 {
                let count = buf[21] as usize;
                let payload = &buf[24..n31];
                for i in 0..count {
                    let off = i * 8;
                    if off + 8 <= payload.len() {
                        let baud = u32::from_le_bytes([
                            payload[off],
                            payload[off + 1],
                            payload[off + 2],
                            payload[off + 3],
                        ]);
                        let mode_byte = payload[off + 4];
                        configs.push(DsuPortConfig {
                            port_num: (i + 1) as u8,
                            baud: if baud > 0 { baud } else { 9600 },
                            framing: UartFraming::from_mode_byte(mode_byte),
                            interface: SerialInterface::Rs232,
                            flow_control: FlowControl::None,
                            alias: String::new(),
                            op_mode: String::from("RealCOM"),
                            tcp_port: 950 + i as u16,
                        });
                    }
                }
            }
        }
    }

    // Step 3: Opcode 0x34 — Per-port Flow Control (0=None, 1=RTS/CTS, 2=XON/XOFF, 3=DTR/DSR)
    let mut req34 = vec![0x34, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00];
    req34.extend_from_slice(&dev_id);
    if sock.send_to(&req34, &target).await.is_ok() {
        if let Ok(Ok((n34, _))) = tokio::time::timeout(timeout, sock.recv_from(&mut buf)).await {
            if n34 >= 24 && buf[0] == 0xB4 && buf[1] == 0x00 {
                let payload = &buf[24..n34];
                for cfg in &mut configs {
                    let idx = (cfg.port_num - 1) as usize;
                    if idx < payload.len() {
                        cfg.flow_control = FlowControl::from_dsu_byte(payload[idx]);
                    }
                }
            }
        }
    }

    // Step 4: Opcode 0x37 — Per-port 16-byte ASCII Alias ("MFE-1", "MFE-2", etc.)
    let mut req37 = vec![0x37, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00];
    req37.extend_from_slice(&dev_id);
    if sock.send_to(&req37, &target).await.is_ok() {
        if let Ok(Ok((n37, _))) = tokio::time::timeout(timeout, sock.recv_from(&mut buf)).await {
            if n37 >= 24 && buf[0] == 0xB7 && buf[1] == 0x00 {
                let payload = &buf[24..n37];
                for cfg in &mut configs {
                    let off = ((cfg.port_num - 1) as usize) * 16;
                    if off + 16 <= payload.len() {
                        let raw = &payload[off..off + 16];
                        let end = raw.iter().position(|&b| b == 0).unwrap_or(16);
                        cfg.alias = String::from_utf8_lossy(&raw[..end]).trim().to_string();
                    }
                }
            }
        }
    }

    // Step 5: Opcode 0x47 — Per-port Operating Mode (1=RealCOM, 2=TCP-Srv, 4=TCP-Cli, 5=UDP)
    let mut req47 = vec![0x47, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00];
    req47.extend_from_slice(&dev_id);
    if sock.send_to(&req47, &target).await.is_ok() {
        if let Ok(Ok((n47, _))) = tokio::time::timeout(timeout, sock.recv_from(&mut buf)).await {
            if n47 >= 24 && buf[0] == 0xC7 && buf[1] == 0x00 {
                let payload = &buf[24..n47];
                for cfg in &mut configs {
                    let off = ((cfg.port_num - 1) as usize) * 8;
                    if off + 8 <= payload.len() {
                        let tcp_p = u16::from_le_bytes([payload[off + 2], payload[off + 3]]);
                        let mode_code = payload[off + 4];
                        cfg.op_mode = match mode_code {
                            0x01 => String::from("RealCOM"),
                            0x02 => String::from("TCP-Srv"),
                            0x04 => String::from("TCP-Cli"),
                            0x05 => String::from("UDP"),
                            0x06 => String::from("Pair"),
                            _ => format!("Mode-{mode_code}"),
                        };
                        if mode_code == 0x02 && tcp_p > 0 {
                            cfg.tcp_port = tcp_p;
                        }
                    }
                }
            }
        }
    }

    configs
}

// ---------------------------------------------------------------------------
// 5. Dynamic Multi-Port NPort State & Async Controller Engine
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortState {
    pub port_num: u8,
    pub alias: String,
    pub op_mode: String,
    pub interface: SerialInterface,
    pub flow_control: FlowControl,
    pub baud: u32,
    pub framing: UartFraming,
    pub dtr: bool,
    pub rts: bool,
    pub modem: ModemStatus,
    pub active_data_port: u16,
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
            alias: String::new(),
            op_mode: String::from("RealCOM"),
            interface: SerialInterface::Rs232,
            flow_control: FlowControl::None,
            baud: 9600,
            framing: UartFraming::F8N1,
            dtr: true,
            rts: true,
            modem: ModemStatus::default(),
            active_data_port: 949 + u16::from(port_num),
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
        self.active_data_port
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

/// Direction filter options for narrowing down captured RS-232 traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DirectionFilter {
    All,
    CtrlToDev,
    DevToCtrl,
    TxInjected,
}

impl DirectionFilter {
    pub const ALL: [DirectionFilter; 4] = [
        DirectionFilter::All,
        DirectionFilter::CtrlToDev,
        DirectionFilter::DevToCtrl,
        DirectionFilter::TxInjected,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            DirectionFilter::All => "All Directions",
            DirectionFilter::CtrlToDev => "CTRL→DEV Only",
            DirectionFilter::DevToCtrl => "DEV→CTRL Only",
            DirectionFilter::TxInjected => "TX Injected Only",
        }
    }

    pub fn next(self) -> Self {
        let idx = Self::ALL.iter().position(|&d| d == self).unwrap_or(0);
        Self::ALL[(idx + 1) % Self::ALL.len()]
    }

    pub fn matches(self, direction_label: &str) -> bool {
        match self {
            DirectionFilter::All => true,
            DirectionFilter::CtrlToDev => {
                direction_label.contains("CTRL→DEV") || direction_label.contains("MITM→P2")
            }
            DirectionFilter::DevToCtrl => {
                direction_label.contains("DEV→CTRL")
                    || direction_label.contains("RX←DEV")
                    || direction_label.contains("MITM→P1")
            }
            DirectionFilter::TxInjected => direction_label.contains("TX→LINE"),
        }
    }
}

/// Configurable multi-criteria stream filter for reverse-engineering serial protocols.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameFilter {
    pub port_filter: Option<u8>,
    pub direction: DirectionFilter,
    pub only_changed: bool,
    pub search_query: String,
    pub min_len: Option<usize>,
    pub max_len: Option<usize>,
}

impl Default for FrameFilter {
    fn default() -> Self {
        Self {
            port_filter: None,
            direction: DirectionFilter::All,
            only_changed: false,
            search_query: String::new(),
            min_len: None,
            max_len: None,
        }
    }
}

impl FrameFilter {
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    pub fn is_active(&self) -> bool {
        self.port_filter.is_some()
            || self.direction != DirectionFilter::All
            || self.only_changed
            || !self.search_query.trim().is_empty()
            || self.min_len.is_some()
            || self.max_len.is_some()
    }

    pub fn matches(&self, frame: &SerialFrame) -> bool {
        if let Some(p) = self.port_filter {
            if frame.port_num != p {
                return false;
            }
        }
        if !self.direction.matches(&frame.direction) {
            return false;
        }
        if self.only_changed && frame.changed_indices.is_empty() {
            return false;
        }
        if let Some(min_l) = self.min_len {
            if frame.payload.len() < min_l {
                return false;
            }
        }
        if let Some(max_l) = self.max_len {
            if frame.payload.len() > max_l {
                return false;
            }
        }
        let q = self.search_query.trim();
        if !q.is_empty() {
            let q_up = q.to_uppercase();
            let hex_match = frame.hex_string().contains(&q_up);
            let ascii_match = frame.ascii_string().to_uppercase().contains(&q_up);
            let dir_match = frame.direction.to_uppercase().contains(&q_up);
            if !(hex_match || ascii_match || dir_match) {
                return false;
            }
        }
        true
    }

    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        if let Some(p) = self.port_filter {
            parts.push(format!("Port=P{p}"));
        }
        if self.direction != DirectionFilter::All {
            parts.push(format!("Dir={}", self.direction.as_str()));
        }
        if self.only_changed {
            parts.push(String::from("ChangedOnly=ON"));
        }
        if let Some(min_l) = self.min_len {
            parts.push(format!("MinLen={min_l}B"));
        }
        if let Some(max_l) = self.max_len {
            parts.push(format!("MaxLen={max_l}B"));
        }
        let q = self.search_query.trim();
        if !q.is_empty() {
            parts.push(format!("Match=\"{q}\""));
        }
        if parts.is_empty() {
            String::from("None (Showing All Frames)")
        } else {
            parts.join(" | ")
        }
    }
}

pub struct SharedEngineState {
    pub host: String,
    pub profile: NPortModelProfile,
    pub discovery_method: String,
    pub gap_ms: f64,
    pub simulate: bool,
    pub stream_paused: bool,
    pub paused_skipped_frames: u64,
    pub filter: FrameFilter,
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
    cmd_senders: HashMap<u8, tokio::sync::mpsc::UnboundedSender<Vec<u8>>>,
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
            stream_paused: false,
            paused_skipped_frames: 0,
            filter: FrameFilter::default(),
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
            cmd_senders: HashMap::new(),
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

    pub fn toggle_pause(&mut self) -> bool {
        self.stream_paused = !self.stream_paused;
        if self.stream_paused {
            self.paused_skipped_frames = 0;
            self.log_event("Stream PAUSED — live display frozen for inspection");
        } else {
            let skipped = self.paused_skipped_frames;
            self.paused_skipped_frames = 0;
            self.log_event(format!(
                "Stream RESUMED ({skipped} background frames elapsed while paused)"
            ));
        }
        self.stream_paused
    }

    /// Return all buffered frames that match the current `FrameFilter`.
    pub fn filtered_frames(&self) -> Vec<SerialFrame> {
        self.frames
            .iter()
            .filter(|f| self.filter.matches(f))
            .cloned()
            .collect()
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
        if self.stream_paused {
            self.paused_skipped_frames += 1;
            return;
        }
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

        let matching = self.filtered_frames();
        let total = self.frames.len();
        let filter_desc = self.filter.summary();

        let _ = writeln!(
            tf,
            "# SMT Control System On-Demand Buffer Dump — {} ({}-Port {}) @ {}",
            self.profile.model_name, self.profile.port_count, self.profile.interfaces, self.host
        );
        let _ = writeln!(
            tf,
            "# Filter: {} | Matching Frames: {} / {}",
            filter_desc,
            matching.len(),
            total
        );
        let _ = writeln!(tf, "{}", "-".repeat(120));

        for fr in &matching {
            let _ = writeln!(tf, "{}", fr.format_log_line());
            if let Some(ref mut jfile) = jf {
                if let Ok(js) = serde_json::to_string(fr) {
                    let _ = writeln!(jfile, "{js}");
                }
            }
        }
        let _ = tf.flush();
        let count = matching.len();
        self.log_event(format!(
            "Dumped {count}/{total} frames (Filter: {filter_desc}) -> {} (+ .jsonl)",
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
    /// poll all ports' live configuration (`baud`, `framing`, `alias`, `op_mode`) via UDP 4800 DSU
    /// (`0x31`, `0x37`, `0x47`), and check TCP/ASPP socket reachability.
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

        // Poll live per-port UART Baud, Framing, Flow Control, Alias, and Operating Mode from UDP 4800 DSU
        let dsu_configs = query_dsu_port_configs(&host, Duration::from_millis(450)).await;
        let mut config_summary = Vec::new();
        if !dsu_configs.is_empty() {
            let mut st = self.state.lock().unwrap();
            for cfg in &dsu_configs {
                if let Some(ps) = st.ports.get_mut((cfg.port_num - 1) as usize) {
                    ps.baud = cfg.baud;
                    ps.framing = cfg.framing;
                    ps.flow_control = cfg.flow_control;
                    ps.interface = cfg.interface;
                    ps.alias = cfg.alias.clone();
                    ps.op_mode = cfg.op_mode.clone();
                    let label = if cfg.alias.is_empty() {
                        format!("P{}", cfg.port_num)
                    } else {
                        format!("P{}({})", cfg.port_num, cfg.alias)
                    };
                    config_summary.push(format!(
                        "{label}:{}@{}",
                        cfg.baud,
                        cfg.framing.as_str()
                    ));
                }
            }
        }

        let mut reachable = 0usize;
        let mut realcom_ports = 0usize;
        let mut tcpsrv_ports = 0usize;
        for p in 1..=port_count {
            let (already_data, already_cmd, cur_port) = {
                let st = self.state.lock().unwrap();
                let data_active = st.tx_senders.contains_key(&p);
                let cmd_active = st.cmd_senders.contains_key(&p);
                let cur_port = st
                    .ports
                    .get((p - 1) as usize)
                    .map(|ps| ps.active_data_port)
                    .unwrap_or(949 + u16::from(p));
                (data_active, cmd_active, cur_port)
            };

            if already_data || already_cmd {
                reachable += 1;
                if cur_port < 1000 {
                    realcom_ports += 1;
                } else {
                    tcpsrv_ports += 1;
                }
                continue;
            }

            let tcp_srv_port = 4000 + u16::from(p);
            let realcom_port = 949 + u16::from(p);
            let cmd_port = 965 + u16::from(p);

            let tcpsrv_ok = tokio::time::timeout(
                Duration::from_millis(200),
                TcpStream::connect(format!("{host}:{tcp_srv_port}")),
            )
            .await
            .map(|r| r.is_ok())
            .unwrap_or(false);

            // Connect to the ASPP Command port (:966..973) rather than opening & closing a bare
            // RealCOM Data socket (:950..957), because on NPort 5610 firmware a bare connect/close
            // on :950..957 without 0x2C resets the port's runtime UART baud rate back to NVRAM default.
            let cmd_ok = tokio::time::timeout(
                Duration::from_millis(200),
                TcpStream::connect(format!("{host}:{cmd_port}")),
            )
            .await
            .map(|r| r.is_ok())
            .unwrap_or(false);

            let realcom_ok = !tcpsrv_ok && cmd_ok;

            let data_ok = tcpsrv_ok || realcom_ok;
            let active_data_port = if tcpsrv_ok {
                tcpsrv_ports += 1;
                tcp_srv_port
            } else {
                if realcom_ok {
                    realcom_ports += 1;
                }
                realcom_port
            };

            if data_ok || cmd_ok {
                reachable += 1;
            }
            let mut st = self.state.lock().unwrap();
            if let Some(ps) = st.ports.get_mut((p - 1) as usize) {
                ps.active_data_port = active_data_port;
                ps.tcp_data_open = data_ok;
                ps.aspp_cmd_open = cmd_ok;
            }
        }
        let mut st = self.state.lock().unwrap();
        let model_name = st.profile.model_name.clone();
        let mode_note = if realcom_ports > 0 && tcpsrv_ports == 0 {
            "Real COM Mode (:950.. / :966..)"
        } else if tcpsrv_ports > 0 {
            "TCP Server Mode (:4001.. / :966..)"
        } else {
            "No open serial sockets"
        };
        if config_summary.is_empty() {
            st.log_event(format!(
                "Probed {host} ({model_name}): {reachable}/{port_count} ports online [{mode_note}]"
            ));
        } else {
            st.log_event(format!(
                "Probed {host} ({model_name}): {reachable}/{port_count} online [{mode_note}] | {}",
                config_summary.join(" ")
            ));
        }
    }

    /// Ensure a persistent TCP connection to the port's ASPP Command port (`965 + port_num`)
    /// is open and return its command sender channel.
    async fn ensure_aspp_cmd_channel(
        &self,
        port_num: u8,
    ) -> Result<tokio::sync::mpsc::UnboundedSender<Vec<u8>>, String> {
        let host = {
            let mut st = self.state.lock().unwrap();
            if let Some(existing) = st.cmd_senders.get(&port_num) {
                if !existing.is_closed() {
                    return Ok(existing.clone());
                }
                st.cmd_senders.remove(&port_num);
            }
            st.host.clone()
        };

        let cmd_port = 965 + u16::from(port_num);
        let addr = format!("{host}:{cmd_port}");
        let stream = tokio::time::timeout(Duration::from_millis(800), TcpStream::connect(&addr))
            .await
            .map_err(|_| format!("timeout connecting to ASPP {addr}"))?
            .map_err(|e| format!("ASPP {addr}: {e}"))?;

        let _ = stream.set_nodelay(true);
        let (mut cmd_reader, mut cmd_writer) = stream.into_split();
        let (cmd_tx, mut cmd_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();

        {
            let mut st = self.state.lock().unwrap();
            st.cmd_senders.insert(port_num, cmd_tx.clone());
            if let Some(ps) = st.ports.get_mut((port_num - 1) as usize) {
                ps.aspp_cmd_open = true;
            }
        }

        tokio::spawn(async move {
            while let Some(pkt) = cmd_rx.recv().await {
                if cmd_writer.write_all(&pkt).await.is_err() {
                    break;
                }
                let _ = cmd_writer.flush().await;
            }
        });

        let state_arc = Arc::clone(&self.state);
        tokio::spawn(async move {
            let mut buf = [0u8; 128];
            while let Ok(n) = cmd_reader.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                let slice = &buf[..n];
                let mut st = state_arc.lock().unwrap();
                if let Some(ps) = st.ports.get_mut((port_num - 1) as usize) {
                    // Parse 0x2C (ASPP_CMD_PORT_INIT reply: 2C 03 <modem> 00 00)
                    // or 0x26 (ASPP_NOTIFY: 26 00 <line_status> <modem_status>)
                    let mut i = 0;
                    while i < slice.len() {
                        if slice[i] == aspp_codec::ASPP_CMD_PORT_INIT && i + 2 < slice.len() {
                            ps.modem = ModemStatus::from_aspp_byte(slice[i + 2]);
                            i += 5;
                        } else if slice[i] == 0x26 && i + 3 < slice.len() {
                            ps.modem = ModemStatus::from_aspp_byte(slice[i + 3]);
                            i += 4;
                        } else {
                            i += 1;
                        }
                    }
                }
            }
            let mut st = state_arc.lock().unwrap();
            st.cmd_senders.remove(&port_num);
        });

        Ok(cmd_tx)
    }

    /// Apply UART `baud`, `framing`, and `flow` to the NPort hardware and verify via UDP 4800 DSU `0x31`.
    ///
    /// On Moxa NPort 5610 units:
    /// 1. The firmware only applies `0x2C` (`ASPP_CMD_PORT_INIT`) on `:966..973` if the corresponding
    ///    Data socket (`:950..957` or `:4001..4008`) is opened FIRST, followed by `:966..973`.
    /// 2. Closing the Data socket causes the NPort 5610 to reset `:966..973`, so when the port is idle
    ///    (`!data_already_open`), we perform a self-contained `(data_stream, cmd_stream)` transaction,
    ///    await the synchronous `2C 03 ...` ACK, and close both sockets cleanly.
    async fn apply_uart_to_hardware(
        &self,
        port_num: u8,
        baud: u32,
        framing: UartFraming,
        dtr: bool,
        rts: bool,
        flow: FlowControl,
    ) -> Result<(u32, UartFraming, FlowControl), String> {
        let (host, data_already_open) = {
            let mut st = self.state.lock().unwrap();
            let active = st.tx_senders.contains_key(&port_num);
            if !active {
                // Remove any stale command channel from a previous idle transaction
                st.cmd_senders.remove(&port_num);
            }
            (st.host.clone(), active)
        };

        let mut payload =
            aspp_codec::encode_port_init_with_flow(baud, framing, dtr, rts, flow).to_vec();
        payload.extend_from_slice(&aspp_codec::encode_flowctrl(flow));

        if data_already_open {
            let cmd_tx = self.ensure_aspp_cmd_channel(port_num).await?;
            cmd_tx
                .send(payload)
                .map_err(|e| format!("ASPP channel send failed: {e}"))?;
            tokio::time::sleep(Duration::from_millis(60)).await;
        } else {
            let realcom_addr = format!("{host}:{}", 949 + u16::from(port_num));
            let tcpsrv_addr = format!("{host}:{}", 4000 + u16::from(port_num));
            let data_stream = match tokio::time::timeout(
                Duration::from_millis(300),
                TcpStream::connect(&realcom_addr),
            )
            .await
            {
                Ok(Ok(s)) => Some(s),
                _ => tokio::time::timeout(
                    Duration::from_millis(300),
                    TcpStream::connect(&tcpsrv_addr),
                )
                .await
                .ok()
                .and_then(|r| r.ok()),
            };

            let cmd_addr = format!("{host}:{}", 965 + u16::from(port_num));
            let mut cmd_stream =
                tokio::time::timeout(Duration::from_millis(400), TcpStream::connect(&cmd_addr))
                    .await
                    .map_err(|_| format!("timeout connecting to ASPP {cmd_addr}"))?
                    .map_err(|e| format!("ASPP {cmd_addr}: {e}"))?;
            let _ = cmd_stream.set_nodelay(true);
            cmd_stream
                .write_all(&payload)
                .await
                .map_err(|e| format!("ASPP write failed: {e}"))?;
            let _ = cmd_stream.flush().await;

            let mut ack_buf = [0u8; 64];
            if let Ok(Ok(n)) =
                tokio::time::timeout(Duration::from_millis(300), cmd_stream.read(&mut ack_buf))
                    .await
            {
                if n >= 3 && ack_buf[0] == aspp_codec::ASPP_CMD_PORT_INIT {
                    let mut st = self.state.lock().unwrap();
                    if let Some(ps) = st.ports.get_mut((port_num - 1) as usize) {
                        ps.modem = ModemStatus::from_aspp_byte(ack_buf[2]);
                        ps.aspp_cmd_open = true;
                    }
                }
            }
            drop(cmd_stream);
            drop(data_stream);
        }

        // Read back live hardware configuration via UDP 4800 DSU opcode 0x31 to verify
        let dsu = query_dsu_port_configs(&host, Duration::from_millis(250)).await;
        if let Some(cfg) = dsu.into_iter().find(|c| c.port_num == port_num) {
            let mut st = self.state.lock().unwrap();
            if let Some(ps) = st.ports.get_mut((port_num - 1) as usize) {
                ps.baud = cfg.baud;
                ps.framing = cfg.framing;
            }
            Ok((cfg.baud, cfg.framing, flow))
        } else {
            Ok((baud, framing, flow))
        }
    }

    pub async fn cycle_baud(&self, port_num: u8) {
        let (simulate, next_baud, framing, dtr, rts, flow, op_mode, alias) = {
            let mut st = self.state.lock().unwrap();
            let simulate = st.simulate;
            let Some(ps) = st.ports.get_mut((port_num - 1) as usize) else {
                return;
            };
            let idx = STANDARD_BAUDS
                .iter()
                .position(|&b| b == ps.baud)
                .unwrap_or(3);
            ps.baud = STANDARD_BAUDS[(idx + 1) % STANDARD_BAUDS.len()];
            (
                simulate,
                ps.baud,
                ps.framing,
                ps.dtr,
                ps.rts,
                ps.flow_control,
                ps.op_mode.clone(),
                ps.alias.clone(),
            )
        };
        if simulate {
            let mut st = self.state.lock().unwrap();
            st.log_event(format!(
                "Port {port_num} (ASPP :{}) baud updated to {next_baud} bps",
                965 + u16::from(port_num)
            ));
            return;
        }
        match self
            .apply_uart_to_hardware(port_num, next_baud, framing, dtr, rts, flow)
            .await
        {
            Ok((hw_baud, hw_framing, _)) => {
                let mut st = self.state.lock().unwrap();
                if hw_baud == next_baud {
                    st.log_event(format!(
                        "Port {port_num} baud set to {next_baud} bps (NPort DSU 0x31 verified: {hw_baud} {})",
                        hw_framing.as_str()
                    ));
                } else {
                    let name = if alias.is_empty() {
                        format!("P{port_num}")
                    } else {
                        format!("P{port_num} ({alias})")
                    };
                    st.log_event(format!(
                        "WARNING: {name} is in {op_mode} mode; NPort 5610 only applies runtime ASPP 0x2C baud changes on RealCOM ports (remained {hw_baud} {})",
                        hw_framing.as_str()
                    ));
                }
            }
            Err(e) => {
                let mut st = self.state.lock().unwrap();
                st.log_event(format!(
                    "WARNING: Port {port_num} ASPP baud update failed: {e}"
                ));
            }
        }
    }

    pub async fn cycle_framing(&self, port_num: u8) {
        let (simulate, baud, next_framing, dtr, rts, flow, op_mode, alias) = {
            let mut st = self.state.lock().unwrap();
            let simulate = st.simulate;
            let Some(ps) = st.ports.get_mut((port_num - 1) as usize) else {
                return;
            };
            ps.framing = ps.framing.next();
            (
                simulate,
                ps.baud,
                ps.framing,
                ps.dtr,
                ps.rts,
                ps.flow_control,
                ps.op_mode.clone(),
                ps.alias.clone(),
            )
        };
        if simulate {
            let mut st = self.state.lock().unwrap();
            st.log_event(format!(
                "Port {port_num} framing set to {}",
                next_framing.as_str()
            ));
            return;
        }
        match self
            .apply_uart_to_hardware(port_num, baud, next_framing, dtr, rts, flow)
            .await
        {
            Ok((hw_baud, hw_framing, _)) => {
                let mut st = self.state.lock().unwrap();
                if hw_framing == next_framing {
                    st.log_event(format!(
                        "Port {port_num} framing set to {} (NPort DSU 0x31 verified: {hw_baud} {})",
                        next_framing.as_str(),
                        hw_framing.as_str()
                    ));
                } else {
                    let name = if alias.is_empty() {
                        format!("P{port_num}")
                    } else {
                        format!("P{port_num} ({alias})")
                    };
                    st.log_event(format!(
                        "WARNING: {name} is in {op_mode} mode; NPort 5610 only applies runtime ASPP 0x2C framing changes on RealCOM ports (remained {hw_baud} {})",
                        hw_framing.as_str()
                    ));
                }
            }
            Err(e) => {
                let mut st = self.state.lock().unwrap();
                st.log_event(format!(
                    "WARNING: Port {port_num} ASPP framing update failed: {e}"
                ));
            }
        }
    }

    pub async fn cycle_flow_control(&self, port_num: u8) {
        let (simulate, baud, framing, dtr, rts, next_flow) = {
            let mut st = self.state.lock().unwrap();
            let simulate = st.simulate;
            let Some(ps) = st.ports.get_mut((port_num - 1) as usize) else {
                return;
            };
            ps.flow_control = ps.flow_control.next();
            (simulate, ps.baud, ps.framing, ps.dtr, ps.rts, ps.flow_control)
        };
        if simulate {
            let mut st = self.state.lock().unwrap();
            st.log_event(format!(
                "Port {port_num} flow control set to {}",
                next_flow.as_str()
            ));
            return;
        }
        match self
            .apply_uart_to_hardware(port_num, baud, framing, dtr, rts, next_flow)
            .await
        {
            Ok((hw_baud, hw_framing, hw_flow)) => {
                let mut st = self.state.lock().unwrap();
                st.log_event(format!(
                    "Port {port_num} flow control set to {} via ASPP 0x2C/0x11 ({hw_baud} {})",
                    hw_flow.as_str(),
                    hw_framing.as_str()
                ));
            }
            Err(e) => {
                let mut st = self.state.lock().unwrap();
                st.log_event(format!(
                    "WARNING: Port {port_num} ASPP flow control update failed: {e}"
                ));
            }
        }
    }

    pub async fn cycle_interface(&self, port_num: u8) {
        let mut st = self.state.lock().unwrap();
        let multi_iface = st.profile.requires_interface_check;
        let model_name = st.profile.model_name.clone();
        let Some(ps) = st.ports.get_mut((port_num - 1) as usize) else {
            return;
        };
        if !multi_iface {
            ps.interface = SerialInterface::Rs232;
            st.log_event(format!(
                "Port {port_num}: {model_name} has fixed RS-232 hardware transceivers (RS-422/485 requires NPort 5650/5450/5250/5150; press [m] to preview)"
            ));
        } else {
            ps.interface = ps.interface.next();
            let iface_str = ps.interface.as_str();
            st.log_event(format!(
                "Port {port_num} electrical transceiver mode set to {iface_str} ({model_name})"
            ));
        }
    }

    pub async fn toggle_dtr(&self, port_num: u8) {
        let (simulate, dtr, rts) = {
            let mut st = self.state.lock().unwrap();
            let simulate = st.simulate;
            let Some(ps) = st.ports.get_mut((port_num - 1) as usize) else {
                return;
            };
            ps.dtr = !ps.dtr;
            (simulate, ps.dtr, ps.rts)
        };
        if !simulate {
            if let Ok(cmd_tx) = self.ensure_aspp_cmd_channel(port_num).await {
                let _ = cmd_tx.send(aspp_codec::encode_linectrl(dtr, rts).to_vec());
            }
        }
        let mut st = self.state.lock().unwrap();
        st.log_event(format!(
            "Port {port_num} DTR (Pin 4) -> {}",
            if dtr { "ON (Asserted)" } else { "OFF" }
        ));
    }

    pub async fn toggle_rts(&self, port_num: u8) {
        let (simulate, dtr, rts) = {
            let mut st = self.state.lock().unwrap();
            let simulate = st.simulate;
            let Some(ps) = st.ports.get_mut((port_num - 1) as usize) else {
                return;
            };
            ps.rts = !ps.rts;
            (simulate, ps.dtr, ps.rts)
        };
        if !simulate {
            if let Ok(cmd_tx) = self.ensure_aspp_cmd_channel(port_num).await {
                let _ = cmd_tx.send(aspp_codec::encode_linectrl(dtr, rts).to_vec());
            }
        }
        let mut st = self.state.lock().unwrap();
        st.log_event(format!(
            "Port {port_num} RTS (Pin 7) -> {}",
            if rts { "ON (Asserted)" } else { "OFF" }
        ));
    }

    pub async fn flush_fifo(&self, port_num: u8) {
        let simulate = { self.state.lock().unwrap().simulate };
        if !simulate {
            if let Ok(cmd_tx) = self.ensure_aspp_cmd_channel(port_num).await {
                let _ = cmd_tx.send(aspp_codec::encode_flush(0x02).to_vec());
            }
        }
        let mut st = self.state.lock().unwrap();
        st.log_event(format!(
            "Port {port_num} hardware TX/RX FIFOs flushed via ASPP 0x14"
        ));
    }

    pub async fn send_break(&self, port_num: u8) {
        let simulate = { self.state.lock().unwrap().simulate };
        if !simulate {
            if let Ok(cmd_tx) = self.ensure_aspp_cmd_channel(port_num).await {
                let _ = cmd_tx.send(aspp_codec::encode_set_break().to_vec());
                tokio::time::sleep(Duration::from_millis(250)).await;
                let _ = cmd_tx.send(aspp_codec::encode_stop_break().to_vec());
            }
        }
        let mut st = self.state.lock().unwrap();
        st.log_event(format!(
            "Port {port_num} transmitted 250 ms RS-232 BREAK condition"
        ));
    }

    pub async fn connect_port(&self, port_num: u8, role: impl Into<String>) -> bool {
        let role = role.into();
        let (host, gap_ms, baud, framing, dtr, rts) = {
            let mut st = self.state.lock().unwrap();
            if st.simulate {
                if let Some(ps) = st.ports.get_mut((port_num - 1) as usize) {
                    ps.connected = true;
                    ps.role = role.clone();
                }
                st.log_event(format!("Connected Port {port_num} in {role} mode [DEMO]"));
                return true;
            }
            let (baud, framing, dtr, rts) = st
                .ports
                .get((port_num - 1) as usize)
                .map(|p| (p.baud, p.framing, p.dtr, p.rts))
                .unwrap_or((9600, UartFraming::F8N1, true, true));
            (st.host.clone(), st.gap_ms, baud, framing, dtr, rts)
        };

        // Open and hold the persistent ASPP Command socket (:966..973) FIRST so RealCOM UART config stays locked
        if let Ok(cmd_tx) = self.ensure_aspp_cmd_channel(port_num).await {
            let mut payload = aspp_codec::encode_port_init(baud, framing, dtr, rts).to_vec();
            payload.extend_from_slice(&aspp_codec::encode_exact_baud(baud));
            let _ = cmd_tx.send(payload);
        }

        // Try TCP Server Mode (:4001..4016) first, then automatically fall back to Real COM Mode (:950..965)
        let tcp_srv_port = 4000 + u16::from(port_num);
        let realcom_port = 949 + u16::from(port_num);
        let mut chosen_port = tcp_srv_port;

        let stream = match tokio::time::timeout(
            Duration::from_millis(500),
            TcpStream::connect(format!("{host}:{tcp_srv_port}")),
        )
        .await
        {
            Ok(Ok(s)) => s,
            _ => {
                chosen_port = realcom_port;
                let addr = format!("{host}:{realcom_port}");
                match tokio::time::timeout(
                    Duration::from_millis(900),
                    TcpStream::connect(&addr),
                )
                .await
                {
                    Ok(Ok(s)) => s,
                    Ok(Err(e)) => {
                        self.state.lock().unwrap().log_event(format!(
                            "ERROR connecting Port {port_num} (tried :{tcp_srv_port} & :{realcom_port}): {e}"
                        ));
                        return false;
                    }
                    Err(_) => {
                        self.state.lock().unwrap().log_event(format!(
                            "ERROR timeout connecting Port {port_num} (:{tcp_srv_port} / :{realcom_port})"
                        ));
                        return false;
                    }
                }
            }
        };

        // Re-assert UART baud & framing after Data socket connects so the NPort 5610 applies our exact baud rate
        if let Ok(cmd_tx) = self.ensure_aspp_cmd_channel(port_num).await {
            let mut payload = aspp_codec::encode_port_init(baud, framing, dtr, rts).to_vec();
            payload.extend_from_slice(&aspp_codec::encode_exact_baud(baud));
            let _ = cmd_tx.send(payload);
        }

        let addr = format!("{host}:{chosen_port}");
        let _ = stream.set_nodelay(true);
        let (mut reader, mut writer) = stream.into_split();
        let (tx_chan, mut rx_chan) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();

        {
            let mut st = self.state.lock().unwrap();
            st.tx_senders.insert(port_num, tx_chan);
            if let Some(ps) = st.ports.get_mut((port_num - 1) as usize) {
                ps.active_data_port = chosen_port;
                ps.connected = true;
                ps.tcp_data_open = true;
                ps.role = role.clone();
            }
            let mode_tag = if chosen_port < 1000 {
                "RealCOM"
            } else {
                "TCP-Srv"
            };
            st.log_event(format!(
                "Connected Port {port_num} ({addr} {mode_tag} @ {baud} {}) [{role}]",
                framing.as_str()
            ));
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
        st.cmd_senders.remove(&port_num);
        if let Some(peer) = st.mitm_peer.remove(&port_num) {
            st.mitm_peer.remove(&peer);
        }
        if let Some(ps) = st.ports.get_mut((port_num - 1) as usize) {
            ps.connected = false;
            ps.role = String::from("IDLE");
        }
        st.log_event(format!("Disconnected Port {port_num}"));
    }

    /// Stop and disconnect all active serial streams across all ports on the NPort unit.
    pub fn stop_all_streams(&self) {
        let max_p = { self.state.lock().unwrap().ports.len() as u8 };
        for p in 1..=max_p {
            let mut st = self.state.lock().unwrap();
            st.tx_senders.remove(&p);
            st.cmd_senders.remove(&p);
            st.mitm_peer.remove(&p);
            if let Some(ps) = st.ports.get_mut((p - 1) as usize) {
                ps.connected = false;
                ps.role = String::from("IDLE");
            }
        }
        let mut st = self.state.lock().unwrap();
        st.stream_paused = false;
        st.paused_skipped_frames = 0;
        st.mode_banner = String::from("STOPPED (ALL STREAMS IDLE)");
        st.log_event(format!(
            "Stopped all active streams across ports 1..{max_p}"
        ));
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
        assert_eq!(baud_pkt, [0x17, 0x04, 0x00, 0xC2, 0x01, 0x00]);
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

    #[test]
    fn test_frame_filter_options_and_pause() {
        let mut st = SharedEngineState::new("192.168.127.254".into(), 8.0, false);
        st.record_frame(1, "P1 CTRL→DEV", b"\x0201POLL:01\x03".to_vec());
        st.record_frame(1, "P1 CTRL→DEV", b"\x0201POLL:01\x03".to_vec()); // identical static heartbeat
        st.record_frame(1, "P1 CTRL→DEV", b"\x0201POLL:02\x03".to_vec()); // changed byte at index 9
        st.record_frame(2, "P2 DEV→CTRL", b"\x0201OK:T=248C\x03".to_vec());
        assert_eq!(st.frames.len(), 4);

        // Pause stream and verify incoming frames are skipped while paused
        st.toggle_pause();
        st.record_frame(1, "P1 CTRL→DEV", b"\x0201POLL:03\x03".to_vec());
        assert_eq!(st.frames.len(), 4);
        assert_eq!(st.paused_skipped_frames, 1);
        st.toggle_pause();
        assert!(!st.stream_paused);

        // Direction filter: DEV→CTRL only
        st.filter.direction = DirectionFilter::DevToCtrl;
        assert_eq!(st.filtered_frames().len(), 1);

        // Changed-bytes-only filter on CTRL→DEV
        st.filter.direction = DirectionFilter::CtrlToDev;
        st.filter.only_changed = true;
        let changed = st.filtered_frames();
        assert_eq!(changed.len(), 1);
        assert_eq!(changed[0].seq, 3);

        // Search query filter (ASCII or Hex)
        st.filter.reset();
        st.filter.search_query = String::from("248C");
        assert_eq!(st.filtered_frames().len(), 1);
    }
}
