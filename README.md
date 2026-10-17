# SMT Control System Modernisation (`smt-control-system`)

This repository contains the architectural documentation, reverse-engineering methodology, clean control protocol stack (`nport5610`), and interactive 8-port Terminal User Interface (`nport_tui.py`) for modernising the legacy RS-232 SMT control system using an **8-Port Moxa NPort 5610-8-DT** serial device server.

---

## Repository Structure

* **[`nport5610/`](nport5610/)** — Pure-Python, driverless protocol & control package for the **Moxa NPort 5610-8-DT**:
  * [`nport5610/protocol.py`](nport5610/protocol.py) — Implements Moxa **UDP 4800 Broadcast Discovery**, **ASPP (Async Server Private Protocol) Command Ports (`:966`–`:973`)** for live UART configuration (`1200`–`230400` baud, `8N1`/`8E1`/`7E1`/`8M1`, `DTR`/`RTS` toggling, `CTS`/`DSR`/`DCD` polling, FIFO flushing, and `BREAK` signalling), and **Raw TCP Data Streaming (`:4001`–`:4008`)** with built-in **Passive Dual-RX Tapping** and **Active MITM Bridging**.
* **[`tools/nport_tui.py`](tools/nport_tui.py)** — Full-screen interactive 8-port `curses` TUI to control, monitor, passive-tap, MITM-bridge, auto-baud scan, and inject frames across all 8 RS-232 ports of a Moxa NPort 5610-8-DT.
* **[`tools/serial_tap_logger.py`](tools/serial_tap_logger.py)** — Headless CLI dual-channel RS-232 passive tap and active MITM logger supporting Moxa TCP Server sockets (`tcp://<ip>:4001`) and local `/dev/tty*` ports.
* **[`tools/nport_probe.py`](tools/nport_probe.py)** — Headless CLI port scanner and ASPP (`:966`–`:973`) automatic baud-rate scanner across all 8 ports.
* **[`docs/01-moxa-linux-architecture.md`](docs/01-moxa-linux-architecture.md)** — Guide to interfacing a Linux application with an Ethernet-connected Moxa serial device (Direct TCP/UDP Socket Mode, RFC 2217, Moxa `npreal2` Real TTY driver, and `socat` user-space PTY bridges).
* **[`docs/02-rs232-sniffing-and-protocol-analysis.md`](docs/02-rs232-sniffing-and-protocol-analysis.md)** — Engineering handbook for non-intrusively tapping, capturing, and reverse-engineering bidirectional RS-232 serial traffic between two legacy devices.
* **[`docs/03-nport-configuration-and-wiring.md`](docs/03-nport-configuration-and-wiring.md)** — Dedicated **Moxa NPort 5610-8-DT** specification: ASPP byte-level protocol tables, DB9 Male & RJ45 (`-J`) pinouts, 8-port allocation strategy, Web UI latency tuning (`Force Transmit`, `FIFO`, `Max Connection = 2`), and TUI operator manual.

---

## Quick-Start: Controlling the Moxa NPort 5610-8-DT

### 1. Launch the Interactive 8-Port TUI (`tools/nport_tui.py`)
```bash
# Connect to a live Moxa NPort 5610-8-DT on your network:
./tools/nport_tui.py 192.168.127.254

# Or launch immediately in offline Demo / Simulation mode (with simulated legacy SMT traffic):
./tools/nport_tui.py --demo
```

Inside the TUI:
* **`1`–`8`** / **`↑`/`↓`**: Select any of the 8 RS-232 ports (`P1 :4001` through `P8 :4008`).
* **`t`**: Start **Passive Dual-RX Tap** on the selected port pair (`P1+P2`, `P3+P4`, `P5+P6`, `P7+P8`).
* **`m`**: Start **Active MITM Bridge** on the selected port pair (`P1⟷P2`, `P3⟷P4`, `P5⟷P6`, `P7⟷P8`).
* **`b`** / **`f`**: Cycle Baud Rate (`1200`–`230400`) and Framing (`8N1`, `8E1`, `8O1`, `7E1`, `8M1`, etc.) live over ASPP (`:966`–`:973`).
* **`d`** / **`r`**: Toggle physical **`DTR`** (Pin 4) and **`RTS`** (Pin 7) output lines live over ASPP (`0x12`).
* **`x`** / **`k`**: Flush hardware UART FIFOs (`0x14`) or transmit a `250 ms` RS-232 `BREAK` pulse (`0x15`/`0x21`).
* **`i`**: Inject/transmit an ASCII (`\x0201POLL\x03`) or Hex (`hex:02 30 31 03`) frame out of the selected port.
* **`s`**: Run automatic ASPP **Baud-Rate Scanner** on the selected port.
* **`u`**: Broadcast **UDP Port 4800 Discovery** to find NPort 5610-8-DT units on the LAN.
* **`l`**: Toggle live structured **`.jsonl` packet capture recording**.

---

### 2. Recommended 8-Port Allocation on the NPort 5610-8-DT

All 8 rear-panel DB9 Male ports on the **NPort 5610-8-DT** are pure RS-232 DTE (`Pin 2 = RXD`, `Pin 3 = TXD`, `Pin 5 = GND`, `Pin 4 = DTR`, `Pin 7 = RTS`, `Pin 8 = CTS`, `Pin 6 = DSR`, `Pin 1 = DCD`):

| NPort 5610-8-DT Port | TCP Data | ASPP Cmd | Role | Physical Wiring (DB9 Male) |
| :--- | :--- | :--- | :--- | :--- |
| **Port 1** | `:4001` | `:966` | **Passive Tap 1A (`CTRL → DEV`)** | `Pin 2 (RXD)` tapped onto Link 1 Controller `TXD`; `Pin 5` to shared `GND`; `Pin 3` NC. |
| **Port 2** | `:4002` | `:967` | **Passive Tap 1B (`DEV → CTRL`)** | `Pin 2 (RXD)` tapped onto Link 1 SMT Device `TXD`; `Pin 5` to shared `GND`; `Pin 3` NC. |
| **Port 3** | `:4003` | `:968` | **New Linux Control / MITM Port A** | Full RS-232 cable (`Pins 2, 3, 5, 7, 8`) to Target SMT Device #1. |
| **Port 4** | `:4004` | `:969` | **Device Emulator / MITM Port B** | Full RS-232 cable (with Null-Modem adapter) to Legacy Controller #1. |
| **Port 5** | `:4005` | `:970` | **Passive Tap 2A (`CTRL → DEV`)** | `Pin 2 (RXD)` tapped onto Link 2 Controller `TXD` (for multi-channel SMT machines). |
| **Port 6** | `:4006` | `:971` | **Passive Tap 2B (`DEV → CTRL`)** | `Pin 2 (RXD)` tapped onto Link 2 SMT Device `TXD`. |
| **Port 7** | `:4007` | `:972` | **Production / Auxiliary Port 7** | Additional RS-232 control channel. |
| **Port 8** | `:4008` | `:973` | **Loopback Self-Test / Spare Port 8** | Can bridge `P7 ⟷ P8` for hardware-in-the-loop protocol validation. |

---

### 3. NPort 5610-8-DT Web UI Settings Checklist
Under **Operating Settings** and **Serial Settings** for **Ports 1–8**:
* **Operation Mode:** `TCP Server Mode` (Ports `4001`–`4008`)
* **Allow Driver Control:** `Yes` (enables ASPP Command Ports `966`–`973` for live baud/framing/pin control)
* **Force Transmit:** `1 ms` or `2 ms` (preserves binary packet boundaries over Ethernet)
* **FIFO:** `Disable` (while sniffing at ≤19,200 baud)
* **Flow Control:** `None` (on Passive Tap Ports 1, 2, 5, 6)
* **Max Connection:** `2` with **Ignore Jammed IP:** `Yes` (allows the production service and `nport_tui.py` to attach to the same port simultaneously)
