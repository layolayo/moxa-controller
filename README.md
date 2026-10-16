# SMT Control System Modernisation (`smt-control-system`)

This repository contains the architectural documentation, reverse-engineering methodology, and diagnostic capture tooling for modernising the legacy RS-232 SMT control system into a Linux-based Ethernet-connected architecture using Moxa serial device servers.

---

## Repository Structure

* [`docs/01-moxa-linux-architecture.md`](docs/01-moxa-linux-architecture.md) — Comprehensive guide to interfacing a Linux application with an Ethernet-connected Moxa serial device (Direct TCP/UDP Socket Mode, RFC 2217, Moxa `npreal2` Real TTY driver, and `socat` user-space PTY bridges).
* [`docs/02-rs232-sniffing-and-protocol-analysis.md`](docs/02-rs232-sniffing-and-protocol-analysis.md) — Engineering handbook for non-intrusively tapping, capturing, and reverse-engineering bidirectional RS-232 serial traffic between two legacy devices.
* [`tools/serial_tap_logger.py`](tools/serial_tap_logger.py) — Dual-channel RS-232 tap logger supporting both Moxa TCP Server sockets and local `/dev/tty*` interfaces, with microsecond timestamping, automatic inter-frame gap detection, hex/ASCII side-by-side inspection, and JSONL structured logging.

---

## Modernisation Roadmap

1. **Phase 1: Electrical & Physical Layer Discovery**
   * Verify DE-9 / DB-25 pinouts, voltage levels (±3 V to ±15 V), hardware handshaking lines (RTS/CTS, DTR/DSR), and framing parameters (baud rate, data bits, parity, stop bits).
2. **Phase 2: Passive Line Tapping & Traffic Capture**
   * Insert a passive dual-RX RS-232 tap cable between the legacy controller and target equipment, feeding two receive channels on a Moxa NPort or dual USB-to-RS232 interface.
   * Record correlated stimulus-response sessions using [`tools/serial_tap_logger.py`](tools/serial_tap_logger.py).
3. **Phase 3: Protocol Reverse-Engineering**
   * Analyse frame boundaries, command opcodes, status registers, keep-alive polling loops, and checksum/CRC algorithms.
4. **Phase 4: Active Proxy & Emulation**
   * Transition from passive listening to a software Man-in-the-Middle (MITM) bridge to validate decoded packet structures and state machines.
5. **Phase 5: Native Linux Control Application**
   * Replace the legacy controller with the modern Linux application communicating directly over Ethernet to the Moxa NPort.
