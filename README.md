# SMT Control System Modernisation (`smt-control-system`)

This repository contains the **Rust (`tokio` + `ratatui`)** production backend, adaptive Moxa NPort protocol engine, interactive Terminal User Interface (`smt-tui`), 24/7 background service (`smt-daemon`), and reverse-engineering handbook for modernising the legacy RS-232 SMT control system using a **Moxa NPort 5610-8-DT** (or any NPort 5100/5200/5400/5600 series device server).

---

## Repository Structure

### 1. Rust Production Workspace (`crates/`)
* **[`crates/nport5610-core/`](crates/nport5610-core/)** — Core async Rust library (`tokio`) implementing:
  * **Automatic Moxa Hardware Model & Port-Count Detection (`auto_detect_nport_model`):** Queries the target Moxa IP via **UDP Port 4800 (Moxa DSU `0x01` Identify)**, **HTTP Port 80 Web Banner**, and **Active TCP/ASPP Port-Range Scanning (`4001..4016` & `966..981`)** to automatically identify the model (`NPort 5610-8-DT`, `5650-8-DT`, `5450`, `5410`, `5250A`, `5210A`, `5110`, etc.), port count (`1`, `2`, `4`, `8`, or `16`), electrical interface (`RS-232` vs `RS-232/422/485`), and connector pinout (`DB9 Male` vs `8-Pin RJ45`).
  * **Moxa ASPP Hardware Command Plane (`TCP 966..981`):** Live UART configuration (`1200`–`230400` baud, `8N1`/`8E1`/`8O1`/`7E1`/`8N2`/`8M1`/`8S1`), physical `DTR`/`RTS` output pin toggling (`0x12`), live `CTS`/`DSR`/`DCD`/`RI` input polling (`0x13`), hardware FIFO flushing (`0x14`), and `BREAK` pulse generation (`0x15`/`0x21`).
  * **Low-Latency Serial Data & Sniffing Engine (`TCP 4001..4016`):** Microsecond inter-frame gap packetisation, **Passive Dual-RX Tapping**, **Active Man-in-the-Middle (MITM) Bridging**, **Byte-Diff Tracking** (automatically flags which byte offsets changed between consecutive frames), and real-time `XOR8`, `LRC`, and `CRC-16/MODBUS` calculation.
* **[`crates/smt-tui/`](crates/smt-tui/)** — Compiled `ratatui` operator and protocol-sniffing console (`smt-tui`). Designed to run in a terminal window alongside the main Wayland SMT control application (or over SSH), dynamically adapting its UI layout to the detected Moxa NPort model.
* **[`crates/smt-daemon/`](crates/smt-daemon/)** — 24/7 headless background service (`smt-daemon`) and local JSON IPC server (`127.0.0.1:7450`) for the Wayland desktop SMT control GUI, packaged with [`deploy/smt-daemon.service`](deploy/smt-daemon.service).

### 2. Documentation & Rapid Prototyping Tools
* **[`docs/01-moxa-linux-architecture.md`](docs/01-moxa-linux-architecture.md)** — Guide to Moxa Ethernet-to-Serial architectures on Linux (Direct TCP Socket Mode, RFC 2217, Moxa `npreal2` Real TTY driver, and `socat` PTY bridges).
* **[`docs/02-rs232-sniffing-and-protocol-analysis.md`](docs/02-rs232-sniffing-and-protocol-analysis.md)** — Engineering handbook for passive dual-RX hardware tapping, logic analyser baud discovery, active MITM proxying, and CRC reverse-engineering.
* **[`docs/03-nport-configuration-and-wiring.md`](docs/03-nport-configuration-and-wiring.md)** — Moxa NPort 5610-8-DT specification: ASPP byte-level protocol tables, DB9 Male & RJ45 (`-J`) pinouts, 8-port allocation strategy, and Web UI latency tuning (`Force Transmit`, `FIFO`, `Max Connection = 2`).
* **[`tools/`](tools/)** — Lightweight Python scripts (`nport_tui.py`, `serial_tap_logger.py`, `nport_probe.py`) for quick ad-hoc scripting.

---

## Quick-Start: Building & Running the Rust Applications Locally

### 1. Build & Run Tests
```bash
cd ~/Projects/smt-control-system

# Run unit tests (ASPP codecs, model auto-detection, CRC-16/MODBUS, payload parsers)
cargo test --workspace

# Build optimised release binaries (target/release/smt-tui & target/release/smt-daemon)
cargo build --release
```

### 2. Launch the Compiled Rust TUI (`smt-tui`)
```bash
# 1. Launch in interactive Demo / Simulation mode (with synthetic SMT traffic & byte-diff highlighting):
./target/release/smt-tui --demo

# 2. Or connect directly to your physical Moxa NPort (automatically detects model & port count):
./target/release/smt-tui 192.168.127.254
```

#### Interactive `smt-tui` Controls

| Key | Action |
| :--- | :--- |
| **`1`–`8`** or **`↑`/`↓`** | Select active serial port (`P1` through `P8`, adapting automatically to detected port count) |
| **`c`** | Connect / Disconnect raw TCP Data stream (`:4001+`) on the selected port |
| **`b`** / **`f`** | Cycle Baud Rate (`1200`–`230400`) or UART Framing (`8N1`, `8E1`, `8O1`, `7E1`, `8M1`, etc.) via ASPP `0x10` |
| **`d`** / **`r`** | Toggle physical **`DTR`** (Pin 4) or **`RTS`** (Pin 7) output pin (`ON` / `OFF`) via ASPP `0x12` |
| **`x`** / **`k`** | Flush hardware UART TX/RX FIFOs (`0x14`) or transmit a `250 ms` RS-232 `BREAK` pulse (`0x15`/`0x21`) |
| **`t`** | Start **Passive Dual-RX Tap** on the adjacent port pair (`P1+P2`, `P3+P4`, `P5+P6`, `P7+P8`) |
| **`v`** | Start **Active MITM Bridge** on the adjacent port pair (`P1⟷P2`, `P3⟷P4`, `P5⟷P6`, `P7⟷P8`) |
| **`i`** | **Inject / Transmit Frame** (enter ASCII e.g. `\x0201POLL\x03` or Hex e.g. `hex:02 30 31 03`) |
| **`p`** | Poll target IP to **Auto-Detect Moxa Model** and refresh `CTS`/`DSR`/`DCD` hardware input lines |
| **`u`** | Broadcast **Moxa UDP 4800 Discovery** to find all NPort units on the LAN |
| **`m`** | *(In Demo Mode)* Cycle simulated Moxa hardware model (`5610-8-DT` → `5450` → `5250A` → `5110`) to watch the UI adapt |
| **`l`** / **`g`** / **`q`** | Toggle live `.jsonl` packet recording (`l`), clear frame buffer (`g`), or quit (`q`) |

### 3. Run the Background Control Daemon (`smt-daemon`)
```bash
# Start background daemon (auto-detects NPort model and serves Wayland GUI IPC on 127.0.0.1:7450)
./target/release/smt-daemon 192.168.127.254 --ipc 127.0.0.1:7450
```
The Wayland SMT control application (or any local process) can query live JSON telemetry or transmit serial frames via `127.0.0.1:7450` (`STATUS\n` or `SEND 1 hex:02 30 31 03\n`), whilst `smt-tui` runs side-by-side in a terminal window using the NPort's second TCP connection slot (`Max Connection = 2`).
