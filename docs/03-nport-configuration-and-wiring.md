# Moxa NPort 5610-8-DT Protocol Specification, Wiring & TUI Guide

This project uses the **Moxa NPort 5610-8-DT** — an 8-port RS-232 desktop serial device server with **8 × DB9 Male (DTE) connectors** (or 8 × 8-pin RJ45 connectors on the `-J` variant), **dual 10/100 Mbps Ethernet ports**, an onboard **LCM display with 4 push buttons**, and **8 Tx/Rx status LEDs**.

Because the **5610-8-DT** is a dedicated RS-232 device server (unlike the 5650 multi-interface series), all 8 ports are wired purely for RS-232, giving you **four independent port-pairs** (`P1+P2`, `P3+P4`, `P5+P6`, `P7+P8`) that can simultaneously perform passive sniffing, active Man-in-the-Middle (MITM) bridging, legacy controller emulation, and production control.

---

## 1. Clean Set of Control & Data Protocols (`nport5610` Package)

To control and monitor a Moxa NPort 5610-8-DT completely from Linux without proprietary kernel modules (`npreal2`), our [`nport5610/protocol.py`](../nport5610/protocol.py) library implements four clean, driverless network planes:

### Plane 1: UDP Broadcast Discovery Protocol (`UDP Port 4800`)
* **Purpose:** Locates any Moxa NPort 5610-8-DT on the local Layer-2 broadcast domain (even if the unit is still on its factory subnet `192.168.127.254`).
* **Request Frame (8 bytes → `255.255.255.255:4800`):**
  ```text
  [0x01, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00]
  ```
* **Response Frame (`0x81` Identify Reply):** Contains the unit's Moxa OUI MAC address (`00:90:E8:xx:xx:xx`), Model ID (`0x5610`), IPv4 address, netmask, and device name.

### Plane 2: ASPP (Async Server Private Protocol) Command Plane (`TCP Ports 966–973`)
When an NPort 5610-8-DT port is configured in **TCP Server Mode** (with *Allow Driver Control = Yes*) or **Real COM Mode**, each of the 8 serial ports exposes a dedicated out-of-band **ASPP Command Port**:
* **Port Mapping:** `ASPP Port = 965 + Port_Number` (`Port 1 = :966`, `Port 2 = :967`, ..., `Port 8 = :973`).
* **Binary Command Frame Structure (`nport5610.ASPPClient`):**

| Command Name | Opcode | Payload Length | Byte Format (Hex) | Description |
| :--- | :--- | :--- | :--- | :--- |
| **`CMD_INIT`** | `0x10` | `4 bytes` | `10 04 <baud_idx> <mode_byte> <dtr> <rts>` | Dynamically sets UART baud rate, data bits, stop bits, parity, and initial `DTR`/`RTS` state. |
| **`CMD_FLOWCTRL`** | `0x11` | `4 bytes` | `11 04 <cts> <rts> <xon_xoff> <dtr_dsr>` | Sets hardware (`RTS/CTS`, `DTR/DSR`), software (`XON/XOFF`), or `None` flow control. |
| **`CMD_LINECTRL`** | `0x12` | `2 bytes` | `12 02 <dtr:0|1> <rts:0|1>` | Immediately toggles physical `DTR` (Pin 4) and `RTS` (Pin 7) output pins. |
| **`CMD_LSTATUS`** | `0x13` | `0 bytes` | `13 00` → Reply: `13 01 <status_bits>` | Polls live hardware modem inputs: `Bit 0 = CTS`, `Bit 1 = DSR`, `Bit 2 = RI`, `Bit 3 = DCD`. |
| **`CMD_FLUSH`** | `0x14` | `1 byte` | `14 01 <00=RX | 01=TX | 02=Both>` | Flushes the hardware UART TX/RX FIFOs on the NPort 5610-8-DT. |
| **`CMD_SET_BREAK`** | `0x15` | `0 bytes` | `15 00` | Asserts a continuous RS-232 `BREAK` (Space voltage) on `TXD`. |
| **`CMD_STOP_BREAK`** | `0x21` | `0 bytes` | `21 00` | De-asserts the RS-232 `BREAK` condition and restores idle Mark state. |
| **`CMD_BAUDRATE`** | `0x23` | `4 bytes` | `23 04 <uint32_le_baud>` | Sets an arbitrary exact 32-bit baud rate (e.g. `19200` or custom industrial baud rates). |

* **ASPP `mode_byte` Encoding (`CMD_INIT`):**
  * `0x03` = `8N1` (8 data bits, No parity, 1 stop bit)
  * `0x1B` = `8E1` (8 data bits, Even parity, 1 stop bit)
  * `0x0B` = `8O1` (8 data bits, Odd parity, 1 stop bit)
  * `0x1A` = `7E1` (7 data bits, Even parity, 1 stop bit)
  * `0x0A` = `7O1` (7 data bits, Odd parity, 1 stop bit)
  * `0x07` = `8N2` (8 data bits, No parity, 2 stop bits)
  * `0x2B` = `8M1` (8 data bits, Mark parity — 9-bit address wakeup)
  * `0x3B` = `8S1` (8 data bits, Space parity — 9-bit data frame)

### Plane 3: Raw TCP Serial Data Plane (`TCP Ports 4001–4008`)
* **Port Mapping:** `Data Port = 4000 + Port_Number` (`Port 1 = :4001`, ..., `Port 8 = :4008`).
* Opened with `TCP_NODELAY` so every transmitted frame leaves the Linux network stack immediately without Nagle buffering.
* Supports up to `Max Connection = 2..4` simultaneous TCP clients per serial port so your production controller and the [`nport_tui.py`](../tools/nport_tui.py) monitor can stay connected concurrently.

---

## 2. NPort 5610-8-DT Hardware Pinouts & 8-Port Allocation

### A. Rear-Panel DB9 Male Pinout (`NPort 5610-8-DT`)
*Note: If your unit is the `NPort 5610-8-DT-J` (RJ45 variant), see Table B below.*

| DB9 Male Pin | RS-232 Signal | Direction (Relative to NPort) | Passive Sniffer Role |
| :--- | :--- | :--- | :--- |
| **Pin 1** | `DCD` | Input (into NPort) | High-Z input — can tap auxiliary handshake line |
| **Pin 2** | **`RXD`** | **Input (into NPort)** | **Connect to tapped Legacy `TXD` line** |
| **Pin 3** | `TXD` | Output (from NPort) | **Leave disconnected (NC) on Passive Tap ports** |
| **Pin 4** | `DTR` | Output (from NPort) | Toggled via ASPP `0x12` (`[d]` key in TUI) |
| **Pin 5** | **`GND`** | **Signal Ground** | **Connect to shared Legacy `GND` (Pin 5)** |
| **Pin 6** | `DSR` | Input (into NPort) | Polled via ASPP `0x13` — can tap Legacy `DTR` |
| **Pin 7** | `RTS` | Output (from NPort) | Toggled via ASPP `0x12` (`[r]` key in TUI) |
| **Pin 8** | `CTS` | Input (into NPort) | Polled via ASPP `0x13` — can tap Legacy `RTS` |

### B. 8-Pin RJ45 Pinout (`NPort 5610-8-DT-J` Variant Only)
| RJ45 Pin | `1: DSR` | `2: RTS` | `3: GND` | `4: TXD` | `5: RXD` | `6: DCD` | `7: CTS` | `8: DTR` |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |

### C. Recommended 8-Port Layout on the NPort 5610-8-DT

| NPort Port | TCP Data | ASPP Cmd | Assigned Role | Description |
| :--- | :--- | :--- | :--- | :--- |
| **Port 1** | `:4001` | `:966` | **Passive Tap 1A (`CTRL → DEV`)** | `Pin 2 (RXD)` taps Link 1 Controller `TXD`; `Pin 8 (CTS)` taps Controller `RTS`; `Pin 5` to `GND` |
| **Port 2** | `:4002` | `:967` | **Passive Tap 1B (`DEV → CTRL`)** | `Pin 2 (RXD)` taps Link 1 SMT Device `TXD`; `Pin 8 (CTS)` taps Device `RTS`; `Pin 5` to `GND` |
| **Port 3** | `:4003` | `:968` | **Active MITM / Production Link 1** | Full RS-232 cable connected to Target SMT Device #1 |
| **Port 4** | `:4004` | `:969` | **Active MITM / Legacy Emulator 1** | Full RS-232 cable (Null-Modem) connected to Legacy Controller #1 |
| **Port 5** | `:4005` | `:970` | **Passive Tap 2A (`CTRL → DEV`)** | `Pin 2 (RXD)` taps Link 2 Controller `TXD` (if system has multiple serial channels) |
| **Port 6** | `:4006` | `:971` | **Passive Tap 2B (`DEV → CTRL`)** | `Pin 2 (RXD)` taps Link 2 Device `TXD` |
| **Port 7** | `:4007` | `:972` | **Production / Auxiliary Port 7** | Spare RS-232 control channel |
| **Port 8** | `:4008` | `:973` | **Loopback Self-Test / Spare Port 8** | Can bridge `P7 ⟷ P8` to test protocol framing before touching live machinery |

---

## 3. Using the Interactive 8-Port TUI (`tools/nport_tui.py`)

Launch the TUI pointed at your NPort 5610-8-DT IP address (or pass `--demo` to test offline with simulated SMT traffic):

```bash
# Connect to live NPort 5610-8-DT
./tools/nport_tui.py 192.168.127.254

# Launch in offline simulation mode
./tools/nport_tui.py --demo
```

### Interactive TUI Keybindings

| Key | Action | Protocol Used |
| :--- | :--- | :--- |
| **`1`–`8`** or **`↑`/`↓`** | Select active serial port (`Port 1` through `Port 8`) | Local UI |
| **`c`** | Connect / Disconnect raw TCP Data stream on selected port | `TCP :4001–4008` |
| **`b`** | Cycle Baud Rate (`1200` → `2400` → ... → `230400`) on selected port | `ASPP :966–973` (`0x10`) |
| **`f`** | Cycle UART Framing (`8N1`, `8E1`, `8O1`, `7E1`, `7O1`, `8N2`, `8M1`, `8S1`) | `ASPP :966–973` (`0x10`) |
| **`d`** | Toggle physical **`DTR`** output pin (`ON` / `OFF`) | `ASPP :966–973` (`0x12`) |
| **`r`** | Toggle physical **`RTS`** output pin (`ON` / `OFF`) | `ASPP :966–973` (`0x12`) |
| **`x`** | Flush hardware UART TX/RX FIFOs on selected port | `ASPP :966–973` (`0x14`) |
| **`k`** | Transmit a `250 ms` RS-232 `BREAK` pulse on selected port | `ASPP :966–973` (`0x15`/`0x21`) |
| **`t`** | Start **Passive Dual-RX Tap** on adjacent port pair (`P1+P2`, `P3+P4`, `P5+P6`, `P7+P8`) | `TCP :4001–4008` |
| **`m`** | Start **Active MITM Bridge** on adjacent port pair (`P1⟷P2`, `P3⟷P4`, `P5⟷P6`, `P7⟷P8`) | `TCP :4001–4008` |
| **`i`** | **Inject / Transmit Frame** (enter ASCII e.g. `\x0201POLL\x03` or Hex e.g. `hex:02 30 31 03`) | `TCP :4001–4008` |
| **`s`** | Run **ASPP Auto-Baud Scanner** on selected port and auto-lock highest-scoring baud rate | `ASPP` + `TCP Data` |
| **`p`** | Probe all 8 ports (`:4001–4008`) and refresh `CTS` / `DSR` / `DCD` hardware input states | `ASPP :966–973` (`0x13`) |
| **`u`** | Broadcast **Moxa UDP 4800 Discovery** to find NPort units on the LAN | `UDP :4800` |
| **`l`** | Toggle live structured **`.jsonl` Packet Capture Recording** | Local Disk |
| **`g`** | Clear on-screen frame buffer | Local UI |
| **`q`** | Disconnect cleanly and exit TUI | — |
