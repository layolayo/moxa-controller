# Moxa NPort Controller & Serial Console Suite (`moxa-controller`)

This repository contains the standalone **Rust (`tokio` + `eframe`/`egui` + `ratatui`)** Moxa NPort 5000-series controller, live PuTTY-style interactive terminal, passive dual-RX hardware tap, active Man-in-the-Middle (MITM) bridge, and RS-232/422/485 packet dissector suite.

> **Related Repository:** For the SMT Control System & COM-Port / Card-Detail Sniffing concept and RS-232 reverse-engineering documentation, see [`layolayo/smt-control-system`](https://github.com/layolayo/smt-control-system).

---

## Repository Structure

### 1. Rust Production Workspace (`crates/`)
* **[`crates/nport5610-core/`](crates/nport5610-core/)** — Core async Rust library (`tokio`) implementing:
  * **Automatic Moxa Hardware Model & Port-Count Detection (`auto_detect_nport_model`):** Queries the target Moxa IP via **UDP Port 4800 (Moxa DSU `0x01` Identify)**, **HTTP Port 80 Web Banner & Port Table Scraping**, and **Active TCP/ASPP Port-Range Scanning (`950..965`, `4001..4016` & `966..981`)** to automatically identify the model (`NPort 5610-8-DT`, `5650-8-DT`, `5450`, `5410`, `5250A`, `5210A`, `5110`, etc.), port count (`1`, `2`, `4`, `8`, or `16`), electrical interface (`RS-232` vs `RS-232/422/485`), and connector pinout (`DB9 Male` vs `8-Pin RJ45`).
  * **Moxa ASPP Hardware Command Plane (`TCP 966..981`):** Live UART configuration (`1200`–`230400` baud, `8N1`/`8E1`/`8O1`/`7E1`/`8N2`/`8M1`/`8S1`), flow control (`NONE`, `RTS/CTS`, `XON/XOFF`, `DTR/DSR`), electrical interface selection (`RS-232`, `RS-422`, `RS-485 2W`, `RS-485 4W`), physical `DTR`/`RTS` output pin toggling (`0x12`), live `CTS`/`DSR`/`DCD`/`RI` input polling (`0x13`), hardware FIFO flushing (`0x14`), and `BREAK` pulse generation (`0x15`/`0x21`).
  * **Low-Latency Serial Data, PuTTY Terminal & Sniffing Engine (`TCP 950..965` / `4001..4016`):** Interactive PuTTY-style character-by-character terminal buffer, microsecond inter-frame gap packetisation, **Passive Dual-RX Tapping**, **Active Man-in-the-Middle (MITM) Bridging**, **Byte-Diff Tracking** (automatically flags which byte offsets changed between consecutive frames), and real-time `XOR8`, `LRC`, and `CRC-16/MODBUS` calculation.
* **[`crates/moxa-gui/`](crates/moxa-gui/)** — Native Wayland/X11 desktop GUI (`moxa-gui` built with `eframe`/`egui`). Features live IP switching, UDP 4800 LAN discovery badges, collapsible multi-port LED status matrix (`🔼 Hide Port Matrix` / `⤢ Maximise Active Pane`), in-app **`⛶ Fullscreen (F11)`** toggle, **PuTTY Live Terminal** + **Packet Inspector** + **Split View**, **Pause/Resume Stream**, **Stop All Streams**, a multi-option **Stream Filter Toolbar**, one-click Passive Tap & Active MITM controls, on-demand stream/buffer logging, and a click-to-inspect **Byte & Bit Dissector Drawer**.
* **[`crates/moxa-tui/`](crates/moxa-tui/)** — Compiled `ratatui` operator and serial-port terminal console (`moxa-tui`). Ideal for terminal windows or SSH sessions, dynamically adapting its layout to the detected Moxa NPort model.
* **[`crates/moxa-daemon/`](crates/moxa-daemon/)** — 24/7 headless background service (`moxa-daemon`) and local JSON IPC server (`127.0.0.1:7450`), packaged with [`deploy/moxa-daemon.service`](deploy/moxa-daemon.service).

### 2. Documentation & Rapid Prototyping Tools
* **[`docs/01-moxa-linux-architecture.md`](docs/01-moxa-linux-architecture.md)** — Guide to Moxa Ethernet-to-Serial architectures on Linux (Direct TCP Socket Mode, RFC 2217, Moxa `npreal2` Real TTY driver, and `socat` PTY bridges).
* **[`docs/03-nport-configuration-and-wiring.md`](docs/03-nport-configuration-and-wiring.md)** — Moxa NPort 5610-8-DT specification: ASPP byte-level protocol tables, DB9 Male & RJ45 (`-J`) pinouts, 8-port allocation strategy, and Web UI latency tuning (`Force Transmit`, `FIFO`, `Max Connection = 2`).
* **[`tools/`](tools/)** — Lightweight Python scripts (`nport_tui.py`, `serial_tap_logger.py`, `nport_probe.py`) for quick ad-hoc scripting.

---

## Quick-Start: Building & Running Locally

### 1. Build & Run Tests
```bash
cd ~/Projects/moxa-controller

# Run unit tests (ASPP codecs, model auto-detection, CRC-16/MODBUS, stream filters, pause & GUI viewport)
cargo test --workspace

# Build optimised release binaries (moxa-gui, moxa-tui, moxa-daemon)
cargo build --release
```

### 2. Launch the Native Wayland/X11 Desktop GUI (`moxa-gui`)
```bash
# 1. Connect directly to your physical Moxa NPort IP address (defaults to 192.168.1.249):
./target/release/moxa-gui

# 2. Launch in Fullscreen Mode or toggle at any time via F11 / the topbar button:
./target/release/moxa-gui --fullscreen

# 3. Launch in Demo Mode (simulated NPort 5610-8-DT traffic):
./target/release/moxa-gui --demo
```

### 3. Launch the Compiled Terminal UI (`moxa-tui`)
```bash
# 1. Connect directly to your physical Moxa NPort (automatically detects model & port count):
./target/release/moxa-tui 192.168.1.249

# 2. Or launch in interactive Demo / Simulation mode:
./target/release/moxa-tui --demo
```
