# RS-232 Serial Sniffing & Protocol Reverse-Engineering Guide

When modernising a legacy RS-232 control system (consisting of a **Legacy Controller** and a **Controlled Device / Actuator / Instrument**), you cannot simply run Wireshark on the wire as you would on an Ethernet switch. RS-232 is a point-to-point, full-duplex electrical link operating at bipolar voltages (±3 V to ±15 V) with two independent data lines:

* **Direction A (Controller → Device):** Controller `TXD` driving Device `RXD`
* **Direction B (Device → Controller):** Device `TXD` driving Controller `RXD`

Because standard UART receivers only listen on a single `RXD` pin, capturing a full-duplex conversation between two external devices requires tapping both transmit lines separately and correlating them with high-resolution timestamps.

Below are the five primary methods for intercepting and analysing RS-232 traffic, ranked from completely non-intrusive passive hardware taps to active Man-in-the-Middle (MITM) software proxies.

---

## Method 1: Passive Dual-RX Hardware Tap ("Y-Sniffer Cable") — *Gold Standard*

A **passive dual-RX tap** sits inline between the two legacy devices without breaking or delaying the electrical path. The legacy controller and the controlled device remain directly wired to each other, whilst two high-impedance `RXD` inputs on your sniffing system silently listen to each direction.

### Why Two Serial Ports Are Required
Each RS-232 port on your capture computer (or Moxa NPort) has only **one** `RXD` pin (Pin 2 on a standard DE-9 DTE connector). Therefore:
* **Sniffer Port A (`RXD`)** taps the **Controller → Device** line.
* **Sniffer Port B (`RXD`)** taps the **Device → Controller** line.
* **Signal Ground (`GND`, Pin 5)** is shared across all four connectors to establish a common voltage reference.
* **Sniffer `TXD` pins (Pin 3)** are left **completely disconnected** so the sniffer can never inject voltage or corrupt the live bus.

### DE-9 (DB-9) Passive Sniffer Wiring Topology

```text
Legacy Controller (DTE)                              Controlled Device (DCE/DTE)
┌──────────────────────┐                            ┌──────────────────────────┐
│  Pin 3 (TXD) ●───────┼───────────┬───────────────►│ Pin 2/3 (RXD)            │
│                      │           │                │                          │
│  Pin 2 (RXD) ◄───────┼───┬───────┼────────────────┼─● Pin 2/3 (TXD)          │
│                      │   │       │                │                          │
│  Pin 5 (GND) ●───────┼───┼───────┼───┬────────────┼─● Pin 5 (GND)            │
│  All other pins ─────┼───┼───────┼───┼────────────┼─► Pass straight through  │
└──────────────────────┘   │       │   │            └──────────────────────────┘
                           │       │   │
                           │       │   ├──────────────────────────┐
                           │       │   │                          │
                           │       ▼   ▼                          ▼
                           │    ┌──────────────┐           ┌──────────────┐
                           │    │ Pin 2   Pin 5│           │ Pin 5   Pin 2│
                           │    │ (RXD)   (GND)│           │ (GND)   (RXD)│
                           │    └──────────────┘           └──────────────┘
                           │     Sniffer Port 1             Sniffer Port 2
                           │   (Captures CTRL→DEV)        (Captures DEV→CTRL)
                           └──────────────────────────────────────▲
```

### Pinout Reference Table (DE-9 Standard)

| Signal | Legacy Side A | Legacy Side B | Sniffer Port 1 (DTE) | Sniffer Port 2 (DTE) | Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Pass-Through (1–9)** | Pins 1–9 | Pins 1–9 | — | — | Preserves full hardware handshaking (RTS/CTS/DTR/DSR) |
| **Direction A Tap** | Pin 3 (TXD) | — | **Pin 2 (RXD)** | — | Captures Controller → Device bytes |
| **Direction B Tap** | — | Pin 2 or 3 (TXD) | — | **Pin 2 (RXD)** | Captures Device → Controller bytes |
| **Common Reference** | Pin 5 (GND) | Pin 5 (GND) | **Pin 5 (GND)** | **Pin 5 (GND)** | Mandatory shared signal ground |
| **Sniffer Transmit** | — | — | Pin 3 (NC) | Pin 3 (NC) | Leave disconnected (Passive Listen Only) |

> [!TIP]
> **Off-the-shelf hardware:** Instead of soldering a custom Y-cable, you can use two **DB9 Male-to-Female Inline Breakout Boards** (with screw terminals and LEDs for every pin) connected back-to-back, or purchase a commercial passive tap such as the **EZ-Tap / Stratus Engineering Versa-Tap** or **Tibbo Ninja**. Inline LED breakout boxes are doubly useful because the LEDs immediately show which pins (2 or 3, plus 4/6/7/8) are actively driven by each device.

---

## Method 2: Networked Passive Tap via a Multi-Port Moxa NPort

If you already have a 2-port, 4-port, or 8-port Moxa device server (such as an **NPort 5210, 5250, 5410, or 5610**), you can use two of its RS-232 ports as a remote Ethernet-connected passive sniffer:

1. Wire **Sniffer Port 1** of the passive Y-tap into **Moxa Port 1** (`RXD` and `GND`).
2. Wire **Sniffer Port 2** of the passive Y-tap into **Moxa Port 2** (`RXD` and `GND`).
3. Configure both Moxa ports identically in the Moxa web UI:
   * **Operating Mode:** TCP Server Mode (`4001` and `4002`)
   * **Baud Rate / Parity / Data Bits / Stop Bits:** Match the legacy bus (e.g. `9600 8N1` or `19200 8E1`)
   * **Flow Control:** `None` (crucial so the Moxa never waits for CTS before forwarding captured bytes)
   * **Force Transmit:** `1 ms` or `2 ms` (so bytes are flushed to Ethernet immediately with minimal buffering jitter)
4. Run [`tools/serial_tap_logger.py`](../tools/serial_tap_logger.py) on your Linux workstation pointed at `<moxa-ip>:4001` and `<moxa-ip>:4002` to record both streams into a unified, microsecond-timestamped timeline.

---

## Method 3: Electrical & Baud Rate Discovery (Logic Analyser / Oscilloscope)

If you have **zero documentation** on the legacy system and do not know the baud rate, parity, voltage levels, or whether hardware handshaking lines are toggled as custom control signals:

1. **Inline RS-232 Breakout Box with Bi-Colour LEDs:**
   * Plug the breakout box inline between Controller and Device.
   * Idle RS-232 `TXD` lines rest at a **negative voltage** (-5 V to -12 V, Space/Mark logic 1).
   * Identifying which pin is negative on each side with the cable unplugged immediately tells you whether each device is wired as **DTE** (transmits on Pin 3) or **DCE** (transmits on Pin 2).
2. **Logic Analyser + `sigrok` / `PulseView` (on Linux):**
   * Connect an RS-232-tolerant logic analyser (or use a MAX3232 level-shifter board to convert ±12 V RS-232 down to 3.3 V CMOS for a cheap 24 MHz Saleae-clone USB logic analyser) across `TXD`, `RXD`, `RTS`, `CTS`, `DTR`, `DSR`, and `GND`.
   * Open **PulseView** (`sudo pacman -S pulseview sigrok-cli` on Arch/Omarchy).
   * Measure the shortest pulse width (`T_bit`) on the wire:
     * `104.16 µs` → **9,600 baud** (`1 ÷ 0.00010416`)
     * `52.08 µs` → **19,200 baud**
     * `26.04 µs` → **38,400 baud**
     * `17.36 µs` → **57,600 baud**
     * `8.68 µs` → **115,200 baud**
   * Add the built-in **UART Protocol Decoder** in PulseView to inspect start bits, data bits (7 vs 8), parity bits (None/Even/Odd), and stop bits visually against the waveform.
   * **Why this matters:** Some 1980s/1990s industrial controllers use **9-bit framing** (Wakeup/Address bit via Mark/Space parity switching) or toggle `RTS`/`DTR` with strict timing before transmitting. A logic analyser reveals this immediately, whereas a standard UART port might silently drop parity errors.

---

## Method 4: Active Software Man-in-the-Middle (MITM Proxy Bridge)

Once you know the baud rate and framing—or when you move from passive observation to **active protocol testing**—you can place your Linux machine (using two USB-to-RS232 adapters or two Moxa NPort ports) directly inline:

```text
[Legacy Controller] ◄──RS232──► [Port A: Linux Proxy : Port B] ◄──RS232──► [Controlled Device]
```

### Option A: Quick Command-Line MITM with `socat`
```bash
socat -x -v /dev/ttyUSB0,b9600,rawer,echo=0 /dev/ttyUSB1,b9600,rawer,echo=0 2> session_capture.log
```
* `-x` prints every forwarded chunk in hexadecimal.
* `-v` prefixes direction markers (`>` and `<`), timestamps, and byte counts.

### Option B: `interceptty` or Custom Python MITM Proxy
Using a custom Python proxy (or [`tools/serial_tap_logger.py --mitm`](../tools/serial_tap_logger.py)) allows you to:
* Log exact request-response pairs.
* **Modify bytes on the fly** (e.g. changing a setpoint or status bit to observe how the controller reacts).
* **Inject synthetic frames** into the device whilst suppressing or spoofing responses back to the legacy controller.

> [!WARNING]
> **Caveat with Active MITM:** Because each byte must be received completely by Port A before being re-transmitted out of Port B, an active proxy introduces at least **1 character time of latency** (e.g. ~1 ms at 9600 baud, plus USB/network jitter) and does not automatically forward hardware handshaking transitions (`RTS`/`CTS`/`DTR`/`DSR`) unless explicitly bridged. Always start with **Method 1 (Passive Tap)** first to capture the true baseline timing!

---

## Method 5: Capturing Moxa Network Traffic via `Wireshark` / `tshark`

When using a Moxa NPort in TCP Server mode (Port `4001` / `4002`) or Real COM mode (Port `950` / `966`), every serial byte traverses your Ethernet interface as TCP payload:

```bash
# Capture raw serial payloads going to/from Moxa ports 4001 and 4002
tshark -i any -f "host 192.168.127.254 and (port 4001 or port 4002)" -T fields -e frame.time_epoch -e tcp.srcport -e tcp.payload
```

---

## Step-by-Step Reverse-Engineering Workflow for the Legacy Control Protocol

Once you have captured bidirectional traffic using [`tools/serial_tap_logger.py`](../tools/serial_tap_logger.py), follow this systematic methodology to decode the protocol:

### 1. Determine Frame Boundaries (Framing Analysis)
Look at the captured bytes and inter-byte arrival times:
* **ASCII / Delimiter-based:** Do frames always end with `0D` (`\r`), `0A` (`\n`), `0D 0A` (`\r\n`), or bracketed between `02` (`STX`) and `03` (`ETX`)?
* **Time-gap (Silence) delimited:** Like Modbus RTU, are packets pure binary separated by >3.5 character times of silence (e.g. >4 ms at 9600 baud)?
* **Fixed Header + Length Byte:** Do packets start with a magic sync byte (e.g. `AA 55`, `FF`, `7E`, `10 02`) followed shortly by a byte whose value equals the remaining payload length?

### 2. Separate Background Polling ("Heartbeat") from Operator Actions
Almost all legacy industrial controllers run a continuous polling loop (e.g. every 50–500 ms asking the device `"Are you alive / What is your status?"`).
1. Record **60 seconds of idle baseline** where nothing is touched.
2. Identify the repeating request/response pair—this is your **Status Poll / Heartbeat** frame.
3. Filter out or mentally baseline that heartbeat so new commands stand out clearly.

### 3. Controlled Stimulus-Response Matrix
Perform **one physical action at a time** on the legacy controller while logging timestamps, and annotate each run:
* **Test 1:** Power on / Initialisation handshake (very important—some devices require a startup init sequence before accepting commands).
* **Test 2:** Toggle a single digital output (e.g. Relay 1 ON, wait 5 s, Relay 1 OFF).
* **Test 3:** Step an analogue or numeric parameter incrementally (e.g. Setpoint = `10`, then `11`, then `12`, then `20`, then `100`).
  * Stepping by `+1` (`10` → `11` → `12`) makes it immediately obvious which bytes represent the value (whether encoded as ASCII digits `"0010"`, big-endian 16-bit integer `00 0A`, little-endian `0A 00`, BCD, or IEEE-754 float) and which trailing bytes change unpredictably (the **checksum/CRC**).

### 4. Cracking the Checksum / CRC
When you change a single byte by `+1`:
* **If the last byte also changes by `+1` (or `-1`):** It is a simple **8-bit Longitudinal Redundancy Check (LRC)**, **2's complement sum** (like Intel HEX / Modbus ASCII), or **XOR checksum** (`byte_0 ^ byte_1 ^ ... ^ byte_n`).
* **If the last 2 bytes jump pseudo-randomly:** It is a **16-bit CRC** (e.g. CRC-16/MODBUS, CRC-16/CCITT, CRC-16/XMODEM).
  * Feed 3 or 4 captured valid frames (in hex) into the Linux tool **`reveng`** (CRC RevEng):
    ```bash
    # Example: automatically discover the exact CRC-16 polynomial, init value, and XOR-out
    reveng -w 16 -s 01030000000ac5cd 01030001000a940d 01030002000a640d
    ```
  * `reveng` will immediately output the exact CRC algorithm parameters so you can reproduce valid packets in your new Linux application.
