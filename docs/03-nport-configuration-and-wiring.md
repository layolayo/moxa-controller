# Moxa NPort Configuration, Wiring & Reverse-Engineering Playbook

Since this project uses a **Moxa NPort** serial device server, we can leverage specific NPort hardware and firmware features for **both** phases of the project:
1. **Phase A (Reverse-Engineering):** Using the NPort as an Ethernet-connected **Passive Sniffer** or **Active Man-in-the-Middle (MITM) Bridge** between the legacy controller and the target SMT device.
2. **Phase B (Modernised Production):** Using the same NPort to connect our new Linux control application directly to the target SMT device over TCP/IP.

---

## 1. Moxa NPort RS-232 Pinouts (DB9 Male vs 8-Pin RJ45)

Before wiring a passive tap or inline cable, verify which physical connector your NPort model uses.

### A. NPort DB9 Male Connector (DTE Pinout)
*Used on NPort 5110, 5150, 5210A, 5250A, 5410, 5450, 6150, 6250, 6450.*

| DB9 Pin | RS-232 Signal | Direction (Relative to NPort) | Passive Sniffer Role |
| :--- | :--- | :--- | :--- |
| **Pin 1** | `DCD` | Input ( into NPort ) | Optional tap for handshaking inspection |
| **Pin 2** | **`RXD`** | **Input ( into NPort )** | **Connect to tapped TX line** |
| **Pin 3** | `TXD` | Output ( from NPort ) | **Leave disconnected (NC) in Passive Tap mode** |
| **Pin 4** | `DTR` | Output ( from NPort ) | Leave disconnected in Passive Tap mode |
| **Pin 5** | **`GND`** | **Signal Ground** | **Connect to shared Legacy GND (Pin 5)** |
| **Pin 6** | `DSR` | Input ( into NPort ) | Optional tap for handshaking inspection |
| **Pin 7** | `RTS` | Output ( from NPort ) | Leave disconnected in Passive Tap mode |
| **Pin 8** | `CTS` | Input ( into NPort ) | Optional tap for handshaking inspection |

### B. NPort 8-Pin RJ45 Serial Connector
*Used on NPort 5210 (legacy), 5230, 5610-8/16, and rackmount NPort 6610/6650.*

| RJ45 Pin | RS-232 Signal | Direction (Relative to NPort) | Passive Sniffer Role |
| :--- | :--- | :--- | :--- |
| **Pin 1** | `DSR` (or `DCD` on some 5600 rev) | Input | Optional |
| **Pin 2** | `RTS` | Output | NC in Passive Tap mode |
| **Pin 3** | **`GND`** | **Signal Ground** | **Connect to shared Legacy GND** |
| **Pin 4** | `TXD` | Output | **NC in Passive Tap mode** |
| **Pin 5** | **`RXD`** | **Input ( into NPort )** | **Connect to tapped TX line** |
| **Pin 6** | `DCD` | Input | Optional |
| **Pin 7** | `CTS` | Input | Optional |
| **Pin 8** | `DTR` | Output | NC in Passive Tap mode |

---

## 2. Three Topologies Using Your NPort

### Topology 1: NPort Passive Dual-RX Tap (Zero Latency, Non-Intrusive)
Requires **2 NPort serial ports** (either a 2/4-port NPort such as an NPort 5210A/5410, or two 1-port NPort 5110s, or 1 NPort port + 1 USB-to-RS232 adapter):

```text
Legacy Controller                Passive Y-Tap                Target SMT Device
┌───────────────┐                                             ┌───────────────┐
│      TXD (3) ●┼──────────────┬─────────────────────────────►│ RXD           │
│      RXD (2) ◄┼──────┬───────┼──────────────────────────────┼─● TXD         │
│      GND (5) ●┼──┬───┼───────┼──────────────────────────────┼─● GND         │
└───────────────┘  │   │       │                              └───────────────┘
                   │   │       └──────────────┐
                   │   └──────────────┐       │
                   ▼                  ▼       ▼
             ┌───────────┬──────────────┬──────────────┐
             │  GND (5)  │Port 2 RXD (2)│Port 1 RXD (2)│
             │           │ (DEV → CTRL) │ (CTRL → DEV) │
             └───────────┴──────────────┴──────────────┘
                         Moxa NPort (Ethernet)
                           │              │
                     TCP :4002      TCP :4001
                           ▼              ▼
                   Linux Workstation (serial_tap_logger.py)
```

### Topology 2: NPort Active Man-in-the-Middle Bridge (Packet Injection & Emulation)
Once you know the baud rate and want to test sending custom commands or spoofing responses without unplugging the legacy controller:
1. Plug the **Legacy Controller** into **NPort Port 1** (using a null-modem crossover adapter if both are DTE).
2. Plug the **Target SMT Device** into **NPort Port 2** (straight-through or null-modem depending on whether the SMT device is DCE or DTE).
3. Run [`tools/serial_tap_logger.py`](../tools/serial_tap_logger.py) in `--mitm` mode on Linux:
   ```bash
   ./tools/serial_tap_logger.py \
     --mitm \
     --port-a tcp://192.168.127.254:4001 \
     --port-b tcp://192.168.127.254:4002 \
     --gap-ms 5 \
     -o mitm_session.jsonl
   ```
   Every byte sent by the controller enters NPort Port 1, travels over Ethernet (`:4001`) to your Linux script, is logged and decoded, and is immediately forwarded out of `:4002` (NPort Port 2) to the SMT device.

### Topology 3: Production Architecture (Linux App → NPort → SMT Device)
Once the protocol is reverse-engineered:
1. Retire the Legacy Controller.
2. Leave the **Target SMT Device** plugged into **NPort Port 1**.
3. Point the new Linux control service at `tcp://<nport-ip>:4001`.

---

## 3. Critical NPort Web Configuration Settings for Sniffing & Control

Moxa's factory defaults are tuned for general throughput rather than low-latency control or microsecond-accurate packet sniffing. Adjust these settings in the NPort Web Console (**Operating Settings** and **Serial Settings**):

| NPort Setting | Factory Default | Recommended Value | Why It Matters |
| :--- | :--- | :--- | :--- |
| **Operation Mode** | Real COM Mode | **TCP Server Mode** | Exposes clean raw TCP sockets on ports `4001`, `4002`, etc. without needing Linux kernel modules. |
| **TCP Alive Check Time** | `7 min` | **`1 min`** | Cleans up half-open sockets quickly if the Linux host restarts. |
| **Max Connection** | `1` | **`2` (or `4`)** | **Killer feature:** Allows your main Linux control app *and* `serial_tap_logger.py` to connect to `:4001` at the same time! The NPort duplicates incoming serial data to all connected TCP clients. |
| **Ignore Jammed IP** | `No` | **`Yes`** | Prevents a slow monitoring client from stalling the real-time control client when `Max Connection > 1`. |
| **FIFO** | `Enable` | **`Disable` (during sniffing ≤19200 baud)** | Disabling the 16/64-byte UART FIFO during reverse-engineering forces the NPort to process each byte immediately rather than batching 16 bytes at a time. |
| **Force Transmit** | `0 ms` | **`1 ms` or `2 ms`** | Crucial for binary protocols (like Modbus or custom binary frames). Flushes the Ethernet packet as soon as the serial line goes silent for 1–2 ms. |
| **Flow Control** | `RTS/CTS` | **`None` (for Passive Tap)** | In Passive Tap mode, `CTS` is not driven; if left on `RTS/CTS`, the NPort may hold buffers indefinitely. |

---

## 4. Hidden NPort Feature: Out-of-Band UART & Line Control via Command Port (`966`)

Many developers assume that choosing **TCP Server Mode** (`4001`) means giving up the ability to read `CTS`/`DSR`/`DCD` or toggle `DTR`/`RTS` or change the baud rate from Linux.

In fact, even in **TCP Server Mode**, the Moxa NPort listens on a companion **Command Port** (`TCP 966` for Port 1, `TCP 967` for Port 2, etc.) using Moxa's **ASPP (Async Server Private Protocol)**:
* **Data Port (`4001`):** Pure, unencumbered serial byte stream.
* **Command Port (`966`):** Accepts compact binary control frames to:
  * Dynamically change baud rate, data bits, parity, and stop bits on the fly (useful when auto-scanning unknown baud rates on a legacy device!).
  * Assert or de-assert `DTR` and `RTS` outputs.
  * Poll live hardware line states (`CTS`, `DSR`, `DCD`, `RI`) and UART error counters (Parity Error, Framing Error, Break, Overrun).

This means your Linux application gets the simplicity and container-friendliness of **raw TCP sockets (`4001`)** whilst retaining full hardware control via port `966` whenever needed.
