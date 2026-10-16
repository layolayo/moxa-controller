# SMT Control System Modernisation (`smt-control-system`)

This repository contains the architectural documentation, reverse-engineering methodology, and diagnostic capture tooling for modernising the legacy RS-232 SMT control system into a Linux-based Ethernet-connected architecture using a **4-Port Moxa NPort 5450** serial device server.

---

## Repository Structure

* **[`docs/01-moxa-linux-architecture.md`](docs/01-moxa-linux-architecture.md)** — Comprehensive guide to interfacing a Linux application with an Ethernet-connected Moxa serial device (Direct TCP/UDP Socket Mode, RFC 2217, Moxa `npreal2` Real TTY driver, and `socat` user-space PTY bridges).
* **[`docs/02-rs232-sniffing-and-protocol-analysis.md`](docs/02-rs232-sniffing-and-protocol-analysis.md)** — Engineering handbook for non-intrusively tapping, capturing, and reverse-engineering bidirectional RS-232 serial traffic between two legacy devices.
* **[`docs/03-nport-configuration-and-wiring.md`](docs/03-nport-configuration-and-wiring.md)** — Dedicated **Moxa NPort 5450** playbook: DB9 Male RS-232/422/485 pinout table, mandatory `Interface = RS-232` check, 4-port allocation strategy, passive dual-RX & active MITM topologies, Web UI latency tuning (`Force Transmit`, `FIFO`, `Max Connection = 2`), and out-of-band ASPP Command Port (`966`–`969`) control.
* **[`tools/serial_tap_logger.py`](tools/serial_tap_logger.py)** — Dual-channel RS-232 passive tap and active MITM logger supporting both Moxa TCP Server sockets (`tcp://<ip>:4001`) and local `/dev/tty*` interfaces, with microsecond timestamping, automatic inter-frame silence detection, colourised Hex + ASCII output, and JSONL structured logging.
* **[`tools/nport_probe.py`](tools/nport_probe.py)** — Moxa NPort 5450 network port scanner and automatic baud-rate detector using the NPort's ASPP Command Ports (`966`–`969`) and TCP Data Ports (`4001`–`4004`).

---

## Quick-Start: Moxa NPort 5450 Setup & Capture

### 1. Mandatory NPort 5450 Pre-Flight Check
Each port on the **NPort 5450** supports RS-232, RS-422, and RS-485 on the same DB9 Male connector. Before connecting any serial cables:
1. Open the NPort 5450 Web Console (default `192.168.127.254`) or use the top-panel LCM display.
2. Under **Serial Settings → Port 1–4**, verify **`Interface = RS-232`** on all four ports (in RS-422 mode, DB9 Pin 2 is a driven output; in RS-232 mode, Pin 2 is `RXD` input, Pin 3 is `TXD` output, and Pin 5 is `GND`).
3. Under **Operating Settings → Port 1–4**, set:
   * **Operation Mode:** `TCP Server Mode` (Ports `4001`–`4004`)
   * **Force Transmit:** `1 ms` or `2 ms`
   * **FIFO:** `Disable` (while sniffing at ≤19,200 baud)
   * **Flow Control:** `None` (on Passive Tap Ports 1 & 2)
   * **Max Connection:** `2` (with **Ignore Jammed IP:** `Yes`)

### 2. Recommended 4-Port Allocation on the NPort 5450

| NPort 5450 Port | TCP Data Port | ASPP Cmd Port | Role | Physical Wiring (DB9 Male) |
| :--- | :--- | :--- | :--- | :--- |
| **Port 1** | `:4001` | `:966` | **Passive Tap A (`CTRL → DEV`)** | `Pin 2 (RXD)` tapped onto Legacy Controller `TXD`; `Pin 5` to shared `GND`; `Pin 3 (TXD)` disconnected. |
| **Port 2** | `:4002` | `:967` | **Passive Tap B (`DEV → CTRL`)** | `Pin 2 (RXD)` tapped onto Target SMT Device `TXD`; `Pin 5` to shared `GND`; `Pin 3 (TXD)` disconnected. |
| **Port 3** | `:4003` | `:968` | **New Linux Control / MITM Port A** | Full RS-232 cable (`Pins 2, 3, 5, 7, 8`) ready to plug into the SMT Device during active testing. |
| **Port 4** | `:4004` | `:969` | **Device Emulator / MITM Port B** | Full RS-232 cable (with Null-Modem adapter) ready to plug into the Legacy Controller. |

### 3. Probe the NPort 5450 & Auto-Scan Unknown Baud Rates
```bash
# Check active TCP Server / ASPP ports on the NPort 5450
./tools/nport_probe.py 192.168.127.254

# Dynamically scan standard baud rates (1200..115200) on Port 1 via ASPP Command Port 966
./tools/nport_probe.py 192.168.127.254 --port 1 --scan-baud
```

### 4. Record Bidirectional Traffic (Passive Tap on Ports 1 & 2)
```bash
./tools/serial_tap_logger.py \
  --port-a tcp://192.168.127.254:4001 \
  --port-b tcp://192.168.127.254:4002 \
  --gap-ms 5 \
  -o smt_baseline_capture.jsonl
```

### 5. Run Active Man-in-the-Middle Bridge (Ports 3 & 4)
```bash
./tools/serial_tap_logger.py \
  --mitm \
  --port-a tcp://192.168.127.254:4003 \
  --port-b tcp://192.168.127.254:4004 \
  --gap-ms 5 \
  -o smt_mitm_capture.jsonl
```

---

## Modernisation Roadmap

1. **Phase 1: Electrical & Physical Layer Discovery** — Verify DB9 pinouts, voltage swings (±3 V to ±15 V), hardware handshaking lines (`RTS`/`CTS`, `DTR`/`DSR`), and framing parameters (`nport_probe.py --scan-baud` or logic analyser).
2. **Phase 2: Passive Line Tapping & Traffic Capture** — Tap both directions into NPort 5450 **Port 1 (`RXD`)** and **Port 2 (`RXD`)**, confirm **Orange/Amber `Rx` LEDs** blink on both ports, and capture correlated stimulus-response sessions via [`tools/serial_tap_logger.py`](tools/serial_tap_logger.py).
3. **Phase 3: Protocol Reverse-Engineering** — Analyse frame boundaries, background heartbeat polls, command opcodes, numeric encodings, and checksum/CRC algorithms (`XOR`, `LRC`, or 16-bit CRC via `reveng`).
4. **Phase 4: Active Proxy & Emulation** — Bridge the Legacy Controller and SMT Device through NPort 5450 **Ports 3 & 4** in `--mitm` mode to validate decoded packets and state machines.
5. **Phase 5: Native Linux Control Application** — Replace the legacy controller with the modern Linux control service communicating over Ethernet to the NPort 5450 (`:4001` / `:4003`), keeping `Max Connection = 2` so diagnostic tooling can attach live at any time.
