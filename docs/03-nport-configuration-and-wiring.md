# Moxa NPort 5450 Configuration, Wiring & Reverse-Engineering Playbook

This project uses the **Moxa NPort 5450** (4-port RS-232/422/485 serial device server with DB9 Male connectors). Having four independent, multi-interface ports on a single device is ideal for reverse-engineering and modernising the legacy SMT control system:

* **Ports 1 & 2 (`:4001` & `:4002`):** Dedicated **Passive Dual-RX Sniffer** across the live legacy RS-232 link.
* **Ports 3 & 4 (`:4003` & `:4004`):** Available simultaneously for a **second RS-232 link**, or pre-wired as the **New Linux Controller Output / Active MITM Bridge** so you can switch between legacy and modern control without re-soldering or re-configuring your tap cables.

---

## 1. NPort 5450 Hardware Specifics & Multi-Interface Warning

Unlike the RS-232-only NPort 5410, each port on the **NPort 5450** is software-selectable between **RS-232**, **RS-422**, **4-wire RS-485**, and **2-wire RS-485**.

> [!IMPORTANT]
> **Verify Interface = RS-232 Before Connecting:**
> In the NPort 5450 Web Console (under **Serial Settings → Port 1–4 → Interface**) or via the top-panel LCM screen, ensure all four ports are explicitly set to **`RS-232`**.
> If a port is left in `RS-422` or `RS-485` mode, Pin 2 on the DB9 connector becomes a driven differential `TxD+(B)` output instead of an `RXD` input!

### NPort 5450 DB9 Male Pinout (Across Modes)

| DB9 Male Pin | **RS-232 Mode (Required)** | RS-422 / 4-Wire RS-485 Mode | 2-Wire RS-485 Mode | Passive Tap Role (in RS-232 Mode) |
| :--- | :--- | :--- | :--- | :--- |
| **Pin 1** | `DCD` (Input) | `TxD-(A)` | — | Optional tap for control line monitoring |
| **Pin 2** | **`RXD` (Input)** | `TxD+(B)` | — | **Connect to tapped Legacy `TXD` line** |
| **Pin 3** | `TXD` (Output) | `RxD+(B)` | `Data+(B)` | **Leave disconnected (NC) on Passive Tap ports** |
| **Pin 4** | `DTR` (Output) | `RxD-(A)` | `Data-(A)` | Leave disconnected (NC) on Passive Tap ports |
| **Pin 5** | **`GND` (Signal Ground)** | `GND` | `GND` | **Connect to shared Legacy `GND` (Pin 5)** |
| **Pin 6** | `DSR` (Input) | — | — | Optional tap for Legacy `DTR` monitoring |
| **Pin 7** | `RTS` (Output) | — | — | Leave disconnected (NC) on Passive Tap ports |
| **Pin 8** | `CTS` (Input) | — | — | Optional tap for Legacy `RTS` monitoring |
| **Pin 9** | `RI` (Input) | — | — | Not used |

### Top-Panel LED Verification on the NPort 5450
The NPort 5450 has dual-colour **Tx/Rx LEDs** for Ports 1–4:
* **Orange / Amber blinking (`Rx`):** Serial bytes are arriving into the NPort's `RXD` (Pin 2).
* **Green blinking (`Tx`):** The NPort is transmitting out of `TXD` (Pin 3).
* When wired as a **Passive Dual-RX Tap** on Ports 1 and 2, you should see **Orange/Amber blinking** on both **Port 1** (when the Legacy Controller transmits) and **Port 2** (when the SMT Device replies), and **zero Green LED activity**.

---

## 2. Recommended 4-Port Allocation on the NPort 5450

| NPort 5450 Port | Data TCP Port | ASPP Cmd Port | Assigned Role | Wiring Summary |
| :--- | :--- | :--- | :--- | :--- |
| **Port 1** | `4001` | `966` | **Sniffer Channel A (`CTRL → DEV`)** | `Pin 2 (RXD)` taps Legacy Controller `TXD`; `Pin 8 (CTS)` optionally taps Controller `RTS`; `Pin 5` to `GND` |
| **Port 2** | `4002` | `967` | **Sniffer Channel B (`DEV → CTRL`)** | `Pin 2 (RXD)` taps SMT Device `TXD`; `Pin 8 (CTS)` optionally taps Device `RTS`; `Pin 5` to `GND` |
| **Port 3** | `4003` | `968` | **New Linux Control / MITM Port A** | Full RS-232 cable (`Pins 2, 3, 5, 7, 8`) ready to connect to Target SMT Device during active testing |
| **Port 4** | `4004` | `969` | **Auxiliary / Emulator Port B** | Full RS-232 cable (with Null-Modem adapter) ready to connect to Legacy Controller to emulate the SMT Device |

### Passive Dual-RX Tap Diagram (NPort 5450 Ports 1 & 2)

```text
Legacy Controller                Passive Y-Tap                Target SMT Device
┌───────────────┐                                             ┌───────────────┐
│      TXD (3) ●┼──────────────┬─────────────────────────────►│ RXD           │
│      RXD (2) ◄┼──────┬───────┼──────────────────────────────┼─● TXD         │
│      GND (5) ●┼──┬───┼───────┼──────────────────────────────┼─● GND         │
│  RTS/CTS/DTR ─┼──┼───┼───────┼──────────────────────────────┼─► Pass-through│
└───────────────┘  │   │       │                              └───────────────┘
                   │   │       └──────────────┐
                   │   └──────────────┐       │
                   ▼                  ▼       ▼
             ┌───────────┬──────────────┬──────────────┐
             │  GND (5)  │Port 2 RXD (2)│Port 1 RXD (2)│
             │  Shared   │ (DEV → CTRL) │ (CTRL → DEV) │
             └───────────┴──────────────┴──────────────┘
                    Moxa NPort 5450 (Ports 1 & 2)
                           │              │
                     TCP :4002      TCP :4001
                           ▼              ▼
                   Linux Workstation (serial_tap_logger.py)
```

> [!TIP]
> **Monitoring Hardware Handshaking Lines (`RTS` / `DTR`) Passively:**
> If you suspect the legacy controller toggles `RTS` or `DTR` to wake up or reset the SMT device, you can wire:
> * Legacy Controller `RTS` (Pin 7) → NPort Port 1 `CTS` (Pin 8)
> * Legacy Controller `DTR` (Pin 4) → NPort Port 1 `DSR` (Pin 6)
> * SMT Device `CTS`/`RTS` → NPort Port 2 `CTS` (Pin 8)
> Because `CTS` (Pin 8) and `DSR` (Pin 6) on the NPort 5450 are high-impedance **inputs**, tapping them will not load the legacy lines, and [`tools/nport_probe.py --watch-lines`](../tools/nport_probe.py) can poll their live states over ASPP Command Ports `966` and `967`!

---

## 3. Exact NPort 5450 Web Console Configuration Checklist

Log into the NPort 5450 Web UI (default IP `192.168.127.254`, default credentials `admin` / `moxa` on newer firmware) and configure **Ports 1–4**:

### A. Operating Settings (for Ports 1–4)
| Parameter | Setting | Reason |
| :--- | :--- | :--- |
| **Operation Mode** | **`TCP Server Mode`** | Exposes raw TCP sockets on `4001`–`4004` and ASPP Command Ports on `966`–`969`. |
| **TCP Alive Check Time** | **`1 min`** | Detects disconnected clients quickly. |
| **Inactivity Time** | **`0 ms`** | Never auto-disconnect idle sniffing or control sessions. |
| **Max Connection** | **`2`** | Allows the production control service AND `serial_tap_logger.py` to connect to `:4001` simultaneously. |
| **Ignore Jammed IP** | **`Yes`** | Ensures a paused diagnostic terminal on Connection 2 never blocks Connection 1. |
| **Allow Driver Control** | **`Yes`** | Allows `nport_probe.py` (or RFC 2217 / ASPP commands) to adjust baud rate and query line states via ports `966`–`969`. |
| **Packing Length** | **`0`** | Disable fixed-size block buffering. |
| **Delimiter 1 / 2** | **`Disable`** (initially) | Keep disabled until protocol delimiters are proven. |
| **Force Transmit** | **`1 ms` or `2 ms`** | Flushes received serial bytes over Ethernet as soon as 1–2 ms of line silence occurs. |

### B. Serial Settings (for Ports 1–4)
| Parameter | Setting | Reason |
| :--- | :--- | :--- |
| **Interface** | **`RS-232`** | **Mandatory on NPort 5450** so Pin 2 is `RXD` and Pin 3 is `TXD`. |
| **Baud Rate** | `9600` (or match legacy) | Can be auto-scanned on the fly using `tools/nport_probe.py --scan-baud`. |
| **Data Bits / Stop Bits / Parity** | `8`, `1`, `None` | Standard 8N1 baseline. |
| **FIFO** | **`Disable`** (for ≤19200 baud) | Prevents the 5450's internal UART FIFO from holding up to 16 bytes before raising an interrupt. |
| **Flow Control** | **`None`** | Mandatory for Passive Tap ports (`1` & `2`) so the NPort never waits for `CTS` to forward data. |
