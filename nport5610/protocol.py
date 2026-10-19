"""
Moxa NPort 5610-8-DT Protocol Implementation

Covers the four control and data planes of the 8-port Moxa NPort 5610-8-DT:
  1. UDP Broadcast Discovery (UDP Port 4800 — Moxa DSU Identify protocol)
  2. ASPP (Async Server Private Protocol) Command Plane (TCP Ports 966..973)
  3. Raw Serial Data Plane (TCP Ports 4001..4008 with TCP_NODELAY)
  4. Multi-Port Orchestration (Passive Dual-RX Tap, Active MITM Bridge, Baud Scanner)
"""

from __future__ import annotations

import datetime as dt
import json
import socket
import struct
import threading
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Deque, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Moxa ASPP (Async Server Private Protocol) Constants (TCP Ports 966..973)
# ---------------------------------------------------------------------------

ASPP_CMD_INIT = 0x10        # Initialise UART (baud index, mode byte, DTR, RTS)
ASPP_CMD_FLOWCTRL = 0x11    # Configure hardware/software flow control
ASPP_CMD_LINECTRL = 0x12    # Toggle DTR and RTS pins dynamically
ASPP_CMD_LSTATUS = 0x13     # Query modem input pins (CTS, DSR, DCD, RI)
ASPP_CMD_FLUSH = 0x14       # Flush hardware UART FIFOs (0=RX, 1=TX, 2=Both)
ASPP_CMD_SET_BREAK = 0x15   # Assert serial BREAK condition
ASPP_CMD_STOP_BREAK = 0x21  # De-assert serial BREAK condition
ASPP_CMD_BAUDRATE = 0x23    # Set exact 32-bit baud rate (uint32 LE)
ASPP_CMD_POLL = 0x27        # Poll port queue and modem status

# Standard Moxa ASPP Baud Rate Index Table
ASPP_BAUD_MAP: Dict[int, int] = {
    300: 0,
    600: 1,
    1200: 2,
    2400: 3,
    4800: 4,
    7200: 5,
    9600: 6,
    19200: 7,
    38400: 8,
    57600: 9,
    115200: 10,
    230400: 11,
}

STANDARD_BAUDS: List[int] = [
    1200,
    2400,
    4800,
    9600,
    19200,
    38400,
    57600,
    115200,
    230400,
]

# Moxa ASPP UART Mode Byte Encoding:
# Bits [1:0]: Data bits (00=5, 01=6, 10=7, 11=8)
# Bit  [2]:   Stop bits (0=1 stop bit, 1=2 stop bits)
# Bits [5:3]: Parity (000=None, 001=Odd, 011=Even, 101=Mark, 111=Space)
FRAMING_PRESETS: Dict[str, int] = {
    "8N1": 0x03,  # 8 data, No parity, 1 stop
    "8E1": 0x1B,  # 8 data, Even parity, 1 stop
    "8O1": 0x0B,  # 8 data, Odd parity, 1 stop
    "7E1": 0x1A,  # 7 data, Even parity, 1 stop
    "7O1": 0x0A,  # 7 data, Odd parity, 1 stop
    "8N2": 0x07,  # 8 data, No parity, 2 stop
    "8M1": 0x2B,  # 8 data, Mark parity (9-bit wakeup), 1 stop
    "8S1": 0x3B,  # 8 data, Space parity (9-bit address), 1 stop
}

FRAMING_LIST: List[str] = list(FRAMING_PRESETS.keys())


@dataclass
class NPortDeviceInfo:
    """Identity and network configuration returned by Moxa UDP 4800 Discovery."""

    ip_address: str
    mac_address: str = "00:90:E8:00:00:00"
    model_name: str = "NPort 5610-8-DT"
    device_name: str = "NP5610-8-DT"
    serial_number: str = "Unknown"
    firmware_version: str = "Unknown"
    netmask: str = "255.255.255.0"
    gateway: str = "0.0.0.0"


@dataclass
class PortState:
    """Live runtime and hardware state for one of the 8 RS-232 ports on the NPort 5610-8-DT."""

    port_num: int  # 1..8
    baud: int = 9600
    framing: str = "8N1"
    flow_control: str = "None"  # None, RTS/CTS, XON/XOFF, DTR/DSR
    dtr: bool = True
    rts: bool = True
    cts: bool = False
    dsr: bool = False
    dcd: bool = False
    ri: bool = False
    tcp_data_open: bool = False
    aspp_cmd_open: bool = False
    connected: bool = False
    role: str = "IDLE"  # IDLE, STREAM, TAP-A, TAP-B, MITM-A, MITM-B
    rx_bytes: int = 0
    tx_bytes: int = 0
    rx_frames: int = 0
    tx_frames: int = 0
    last_activity: Optional[str] = None

    @property
    def data_tcp_port(self) -> int:
        return 4000 + self.port_num

    @property
    def aspp_tcp_port(self) -> int:
        return 965 + self.port_num

    @property
    def realcom_tcp_port(self) -> int:
        return 949 + self.port_num


@dataclass
class SerialFrame:
    """A timestamped serial frame captured or transmitted on an NPort 5610-8-DT port."""

    seq: int
    timestamp: dt.datetime
    delta_ms: float
    port_num: int
    direction: str  # e.g. "P1 RX", "P1 TX", "P1 CTRL→DEV", "P2 DEV→CTRL"
    payload: bytes

    @property
    def hex_str(self) -> str:
        return " ".join(f"{b:02X}" for b in self.payload)

    @property
    def ascii_str(self) -> str:
        return "".join(chr(b) if 32 <= b <= 126 else "." for b in self.payload)

    @property
    def checksum_hints(self) -> Dict[str, str]:
        xor_v = 0
        for b in self.payload:
            xor_v ^= b
        sum8 = sum(self.payload) & 0xFF
        lrc = (-sum8) & 0xFF
        return {
            "xor8": f"0x{xor_v:02X}",
            "sum8": f"0x{sum8:02X}",
            "lrc": f"0x{lrc:02X}",
        }

    def to_json_dict(self) -> dict:
        return {
            "seq": self.seq,
            "timestamp": self.timestamp.isoformat(),
            "delta_ms": round(self.delta_ms, 3),
            "port": self.port_num,
            "direction": self.direction,
            "length": len(self.payload),
            "hex": self.hex_str,
            "ascii": self.ascii_str,
            "checksums": self.checksum_hints,
        }


# ---------------------------------------------------------------------------
# 1. Moxa UDP Broadcast Discovery Protocol (UDP Port 4800)
# ---------------------------------------------------------------------------

def discover_nports_udp(timeout: float = 1.2) -> List[NPortDeviceInfo]:
    """
    Broadcast a Moxa DSU Identify request on UDP port 4800 and parse responses
    from any Moxa NPort units on the local broadcast domain.
    """
    # Standard 8-byte Moxa UDP discovery query header:
    # Function code 0x01 (Identify), reserved 0x00, length 0x0008
    query = bytes([0x01, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00])
    discovered: Dict[str, NPortDeviceInfo] = {}

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(0.25)

    try:
        try:
            sock.sendto(query, ("255.255.255.255", 4800))
        except OSError:
            pass

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                data, addr = sock.recvfrom(512)
            except socket.timeout:
                continue
            except OSError:
                break

            ip = addr[0]
            if len(data) >= 24 and data[0] in (0x81, 0x01):
                # Extract Moxa OUI MAC (00:90:E8:xx:xx:xx) if present in payload
                mac_str = "00:90:E8:XX:XX:XX"
                for idx in range(len(data) - 6):
                    if data[idx : idx + 3] == b"\x00\x90\xe8":
                        mac_bytes = data[idx : idx + 6]
                        mac_str = ":".join(f"{b:02X}" for b in mac_bytes)
                        break

                discovered[ip] = NPortDeviceInfo(
                    ip_address=ip,
                    mac_address=mac_str,
                    model_name="NPort 5610-8-DT",
                )
    finally:
        sock.close()

    return list(discovered.values())


# ---------------------------------------------------------------------------
# 2. Moxa ASPP Command Port Client (TCP Ports 966..973)
# ---------------------------------------------------------------------------

class ASPPClient:
    """
    Low-level client for Moxa's Async Server Private Protocol (ASPP) on
    TCP ports 966 (Port 1) through 973 (Port 8).
    """

    def __init__(self, host: str, port_num: int, timeout: float = 1.0) -> None:
        if not 1 <= port_num <= 8:
            raise ValueError("NPort 5610-8-DT port_num must be between 1 and 8")
        self.host = host
        self.port_num = port_num
        self.cmd_port = 965 + port_num
        self.timeout = timeout

    def _transact(self, payload: bytes) -> Optional[bytes]:
        try:
            with socket.create_connection(
                (self.host, self.cmd_port), timeout=self.timeout
            ) as sock:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                sock.settimeout(self.timeout)
                sock.sendall(payload)
                return sock.recv(64)
        except OSError:
            return None

    def configure_uart(
        self,
        baud: int = 9600,
        framing: str = "8N1",
        dtr: bool = True,
        rts: bool = True,
    ) -> bool:
        """Send ASPP CMD_INIT (0x10) to set baud rate, framing, and initial DTR/RTS."""
        baud_idx = ASPP_BAUD_MAP.get(baud, 6)
        mode_byte = FRAMING_PRESETS.get(framing.upper(), 0x03)
        pkt = bytes(
            [
                ASPP_CMD_INIT,
                0x04,
                baud_idx,
                mode_byte,
                0x01 if dtr else 0x00,
                0x01 if rts else 0x00,
            ]
        )
        resp = self._transact(pkt)
        return resp is not None and len(resp) >= 2 and resp[0] == ASPP_CMD_INIT

    def set_exact_baud(self, baud: int) -> bool:
        """Send ASPP CMD_BAUDRATE (0x23) with a 32-bit little-endian baud value."""
        pkt = struct.pack("<BBi", ASPP_CMD_BAUDRATE, 0x04, baud)
        resp = self._transact(pkt)
        return resp is not None and len(resp) >= 2 and resp[0] == ASPP_CMD_BAUDRATE

    def set_line_control(self, dtr: bool, rts: bool) -> bool:
        """Send ASPP CMD_LINECTRL (0x12) to assert or de-assert DTR and RTS immediately."""
        pkt = bytes(
            [
                ASPP_CMD_LINECTRL,
                0x02,
                0x01 if dtr else 0x00,
                0x01 if rts else 0x00,
            ]
        )
        resp = self._transact(pkt)
        return resp is not None and len(resp) >= 2 and resp[0] == ASPP_CMD_LINECTRL

    def set_flow_control(self, mode: str) -> bool:
        """
        Send ASPP CMD_FLOWCTRL (0x11).
        mode: 'None', 'RTS/CTS', 'XON/XOFF', or 'DTR/DSR'
        """
        rts_cts = 1 if mode == "RTS/CTS" else 0
        xon_xoff = 1 if mode == "XON/XOFF" else 0
        dtr_dsr = 1 if mode == "DTR/DSR" else 0
        pkt = bytes([ASPP_CMD_FLOWCTRL, 0x04, rts_cts, rts_cts, xon_xoff, dtr_dsr])
        resp = self._transact(pkt)
        return resp is not None and len(resp) >= 2 and resp[0] == ASPP_CMD_FLOWCTRL

    def flush_buffers(self, target: int = 0x02) -> bool:
        """Send ASPP CMD_FLUSH (0x14). target: 0=RX, 1=TX, 2=Both."""
        pkt = bytes([ASPP_CMD_FLUSH, 0x01, target & 0x03])
        resp = self._transact(pkt)
        return resp is not None and len(resp) >= 2 and resp[0] == ASPP_CMD_FLUSH

    def send_break(self, duration_ms: int = 250) -> bool:
        """Send ASPP CMD_SET_BREAK (0x15), sleep duration_ms, then CMD_STOP_BREAK (0x21)."""
        start_resp = self._transact(bytes([ASPP_CMD_SET_BREAK, 0x00]))
        if start_resp is None:
            return False
        time.sleep(max(duration_ms, 50) / 1000.0)
        stop_resp = self._transact(bytes([ASPP_CMD_STOP_BREAK, 0x00]))
        return stop_resp is not None

    def query_modem_status(self) -> Optional[Tuple[bool, bool, bool, bool]]:
        """
        Send ASPP CMD_LSTATUS (0x13) to poll live hardware input lines:
        Returns (cts, dsr, dcd, ri) or None if unreachable.
        """
        resp = self._transact(bytes([ASPP_CMD_LSTATUS, 0x00]))
        if resp is None or len(resp) < 3:
            return None
        status_byte = resp[2]
        cts = bool(status_byte & 0x01)
        dsr = bool(status_byte & 0x02)
        ri = bool(status_byte & 0x04)
        dcd = bool(status_byte & 0x08)
        return cts, dsr, dcd, ri


# ---------------------------------------------------------------------------
# 3. 8-Port NPort 5610-8-DT Controller Engine (Live + Simulation Support)
# ---------------------------------------------------------------------------

class NPort5610Controller:
    """
    Thread-safe controller managing all 8 RS-232 ports on a Moxa NPort 5610-8-DT.
    Supports:
      - Individual port streaming and frame injection (Ports 1..8)
      - Passive Dual-RX Sniffing across any pair of ports (e.g. Port 1 + Port 2)
      - Active Man-in-the-Middle (MITM) Bridging across any pair of ports
      - Live JSONL frame capture to disk
      - Demo/Simulation mode (`simulate=True`) generating realistic legacy SMT frames
    """

    def __init__(
        self,
        host: str = "192.168.127.254",
        gap_ms: float = 8.0,
        simulate: bool = False,
        max_history: int = 500,
    ) -> None:
        self.host = host
        self.gap_ms = gap_ms
        self.simulate = simulate
        self.ports: Dict[int, PortState] = {
            p: PortState(port_num=p) for p in range(1, 9)
        }
        self.frames: Deque[SerialFrame] = deque(maxlen=max_history)
        self.status_log: Deque[str] = deque(maxlen=50)
        self.mode_banner: str = "DEMO SIMULATION" if simulate else "READY"

        self._lock = threading.Lock()
        self._seq = 0
        self._last_mono: Optional[float] = None
        self._running = True
        self._sockets: Dict[int, socket.socket] = {}
        self._worker_threads: List[threading.Thread] = []
        self._mitm_pairs: Dict[int, int] = {}
        self._jsonl_file = None
        self.jsonl_path: Optional[Path] = None

        if self.simulate:
            for p in range(1, 9):
                self.ports[p].tcp_data_open = True
                self.ports[p].aspp_cmd_open = True
                self.ports[p].cts = p in (1, 2, 3, 4)
                self.ports[p].dsr = p in (1, 2, 3, 4)
                self.ports[p].dcd = p in (1, 2)
            self.start_passive_tap(1, 2)
            sim_thread = threading.Thread(target=self._simulation_loop, daemon=True)
            sim_thread.start()
            self.log_event(
                f"Initialised NPort 5610-8-DT simulation ({self.host}) — Passive Tap active on P1 & P2"
            )
        else:
            self.log_event(f"Target NPort 5610-8-DT set to {self.host}")

    def log_event(self, message: str) -> None:
        ts = dt.datetime.now().strftime("%H:%M:%S")
        with self._lock:
            self.status_log.append(f"[{ts}] {message}")

    def shutdown(self) -> None:
        self._running = False
        self.disconnect_all()
        with self._lock:
            if self._jsonl_file:
                self._jsonl_file.close()
                self._jsonl_file = None

    # --- JSONL Recording ---

    def toggle_jsonl_recording(self, path: Optional[Path] = None) -> Optional[Path]:
        with self._lock:
            if self._jsonl_file is not None:
                self._jsonl_file.close()
                self._jsonl_file = None
                old = self.jsonl_path
                self.jsonl_path = None
                self.log_event(f"Stopped JSONL recording ({old})")
                return None

            if path is None:
                stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
                path = Path(f"nport5610_capture_{stamp}.jsonl")
            self._jsonl_file = path.open("a", encoding="utf-8")
            self.jsonl_path = path
        self.log_event(f"Recording structured JSONL capture to {path}")
        return path

    # --- Probe & Status Polling ---

    def probe_all_ports(self, timeout: float = 0.35) -> None:
        """Probe TCP Data (4001..4008) and ASPP Command (966..973) ports across all 8 channels."""
        if self.simulate:
            self.log_event("Simulation mode: All 8 ports (4001..4008 & 966..973) online.")
            return

        open_count = 0
        for p in range(1, 9):
            st = self.ports[p]
            data_ok = self._check_tcp(st.data_tcp_port, timeout)
            cmd_ok = self._check_tcp(st.aspp_tcp_port, timeout)
            st.tcp_data_open = data_ok
            st.aspp_cmd_open = cmd_ok
            if cmd_ok:
                aspp = ASPPClient(self.host, p, timeout=timeout)
                modem = aspp.query_modem_status()
                if modem is not None:
                    st.cts, st.dsr, st.dcd, st.ri = modem
            if data_ok or cmd_ok:
                open_count += 1

        self.log_event(
            f"Probed {self.host}: {open_count}/8 NPort 5610-8-DT serial ports reachable."
        )

    def _check_tcp(self, port: int, timeout: float) -> bool:
        try:
            with socket.create_connection((self.host, port), timeout=timeout):
                return True
        except OSError:
            return False

    # --- ASPP Hardware Controls ---

    def set_uart_config(
        self, port_num: int, baud: Optional[int] = None, framing: Optional[str] = None
    ) -> bool:
        st = self.ports[port_num]
        if baud is not None:
            st.baud = baud
        if framing is not None:
            st.framing = framing

        if self.simulate:
            self.log_event(
                f"Port {port_num} (ASPP :{st.aspp_tcp_port}) set to {st.baud} {st.framing}"
            )
            return True

        client = ASPPClient(self.host, port_num)
        ok = client.configure_uart(st.baud, st.framing, st.dtr, st.rts)
        if ok:
            self.log_event(
                f"Port {port_num} UART updated via ASPP :{st.aspp_tcp_port} -> {st.baud} {st.framing}"
            )
        else:
            self.log_event(
                f"WARNING: ASPP :{st.aspp_tcp_port} did not acknowledge UART update on Port {port_num}"
            )
        return ok

    def toggle_dtr(self, port_num: int) -> bool:
        st = self.ports[port_num]
        st.dtr = not st.dtr
        if self.simulate:
            self.log_event(
                f"Port {port_num} DTR {'ASSERTED (ON)' if st.dtr else 'DE-ASSERTED (OFF)'}"
            )
            return True
        ok = ASPPClient(self.host, port_num).set_line_control(st.dtr, st.rts)
        self.log_event(
            f"Port {port_num} DTR -> {'ON' if st.dtr else 'OFF'} ({'OK' if ok else 'ERR'})"
        )
        return ok

    def toggle_rts(self, port_num: int) -> bool:
        st = self.ports[port_num]
        st.rts = not st.rts
        if self.simulate:
            self.log_event(
                f"Port {port_num} RTS {'ASSERTED (ON)' if st.rts else 'DE-ASSERTED (OFF)'}"
            )
            return True
        ok = ASPPClient(self.host, port_num).set_line_control(st.dtr, st.rts)
        self.log_event(
            f"Port {port_num} RTS -> {'ON' if st.rts else 'OFF'} ({'OK' if ok else 'ERR'})"
        )
        return ok

    def flush_port(self, port_num: int) -> bool:
        if self.simulate:
            self.log_event(f"Port {port_num} hardware TX/RX FIFOs flushed")
            return True
        ok = ASPPClient(self.host, port_num).flush_buffers(0x02)
        self.log_event(f"Port {port_num} FIFO flush {'OK' if ok else 'ERR'}")
        return ok

    def send_break_pulse(self, port_num: int, duration_ms: int = 250) -> bool:
        if self.simulate:
            self.log_event(f"Port {port_num} transmitted {duration_ms} ms BREAK condition")
            return True
        ok = ASPPClient(self.host, port_num).send_break(duration_ms)
        self.log_event(
            f"Port {port_num} {duration_ms} ms BREAK pulse {'OK' if ok else 'ERR'}"
        )
        return ok

    # --- Data Stream / Passive Tap / Active MITM Management ---

    def connect_port(self, port_num: int, role: str = "STREAM") -> bool:
        st = self.ports[port_num]
        if st.connected:
            st.role = role
            return True

        if self.simulate:
            st.connected = True
            st.role = role
            self.log_event(
                f"Connected Port {port_num} (:{st.data_tcp_port}) in {role} mode"
            )
            return True

        try:
            sock = socket.create_connection((self.host, st.data_tcp_port), timeout=1.5)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.settimeout(max(self.gap_ms / 1000.0, 0.005))
        except OSError as exc:
            self.log_event(
                f"ERROR connecting to Port {port_num} (:{st.data_tcp_port}): {exc}"
            )
            return False

        with self._lock:
            self._sockets[port_num] = sock
            st.connected = True
            st.tcp_data_open = True
            st.role = role

        t = threading.Thread(
            target=self._socket_reader_loop, args=(port_num, sock), daemon=True
        )
        t.start()
        self._worker_threads.append(t)
        self.log_event(f"Connected Port {port_num} (:{st.data_tcp_port}) [{role}]")
        return True

    def disconnect_port(self, port_num: int) -> None:
        st = self.ports[port_num]
        with self._lock:
            sock = self._sockets.pop(port_num, None)
            peer = self._mitm_pairs.pop(port_num, None)
            if peer is not None:
                self._mitm_pairs.pop(peer, None)
            st.connected = False
            st.role = "IDLE"
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        self.log_event(f"Disconnected Port {port_num}")

    def disconnect_all(self) -> None:
        for p in range(1, 9):
            if self.ports[p].connected:
                self.disconnect_port(p)
        self.mode_banner = "IDLE"

    def start_passive_tap(self, port_a: int = 1, port_b: int = 2) -> bool:
        """Configure two NPort 5610-8-DT ports as a Passive Dual-RX Sniffer pair."""
        self.disconnect_all()
        ok_a = self.connect_port(port_a, role="TAP-A (CTRL→DEV)")
        ok_b = self.connect_port(port_b, role="TAP-B (DEV→CTRL)")
        if ok_a and ok_b:
            self.mode_banner = f"PASSIVE TAP (P{port_a} + P{port_b})"
            self.log_event(
                f"Passive Dual-RX Tap active: P{port_a} (CTRL→DEV) + P{port_b} (DEV→CTRL)"
            )
            return True
        return False

    def start_mitm_bridge(self, port_a: int = 3, port_b: int = 4) -> bool:
        """Configure two NPort 5610-8-DT ports as an Active Man-in-the-Middle Bridge."""
        self.disconnect_all()
        ok_a = self.connect_port(port_a, role=f"MITM-A (⇄P{port_b})")
        ok_b = self.connect_port(port_b, role=f"MITM-B (⇄P{port_a})")
        if ok_a and ok_b:
            with self._lock:
                self._mitm_pairs[port_a] = port_b
                self._mitm_pairs[port_b] = port_a
            self.mode_banner = f"ACTIVE MITM BRIDGE (P{port_a} ⟷ P{port_b})"
            self.log_event(
                f"Active MITM Bridge started between Port {port_a} and Port {port_b}"
            )
            return True
        return False

    def send_payload(self, port_num: int, data: bytes) -> bool:
        """Transmit raw bytes out of an NPort 5610-8-DT serial port."""
        st = self.ports[port_num]
        if not st.connected:
            if not self.connect_port(port_num, role="STREAM"):
                return False

        if not self.simulate:
            sock = self._sockets.get(port_num)
            if sock is None:
                return False
            try:
                sock.sendall(data)
            except OSError as exc:
                self.log_event(f"TX error on Port {port_num}: {exc}")
                return False

        st.tx_bytes += len(data)
        st.tx_frames += 1
        st.last_activity = dt.datetime.now().strftime("%H:%M:%S")
        self._record_frame(port_num, f"P{port_num} TX→LINE", data)

        # In simulation mode, synthesise a realistic serial device reply
        if self.simulate:
            reply = b"\x02ACK:" + data[:12] + b"\x03\x17"
            self.ports[port_num].rx_bytes += len(reply)
            self.ports[port_num].rx_frames += 1
            self._record_frame(port_num, f"P{port_num} RX←DEV", reply)
        return True

    def scan_baud_on_port(
        self, port_num: int, dwell_sec: float = 0.6
    ) -> List[Tuple[int, int, float, str]]:
        """
        Scan standard baud rates on `port_num` using ASPP Command Port (965 + port_num)
        and return [(baud, byte_count, quality_score, hex_preview), ...].
        """
        results: List[Tuple[int, int, float, str]] = []
        if self.simulate:
            for b in [9600, 19200, 38400, 57600, 115200]:
                if b == 19200:
                    sample = b"\x02\x30\x31\x53\x54\x41\x54\x03\x42"
                    score = 96.5
                else:
                    sample = b"\x00\xff\xfe\x00\x80\xff"
                    score = 12.0
                results.append(
                    (b, len(sample), score, " ".join(f"{x:02X}" for x in sample))
                )
            self.set_uart_config(port_num, baud=19200)
            self.log_event(
                f"Auto-Baud Scan on Port {port_num} best match: 19200 bps (score 96.5)"
            )
            return results

        aspp = ASPPClient(self.host, port_num, timeout=0.8)
        data_port = 4000 + port_num
        for baud in [9600, 19200, 38400, 57600, 115200, 4800, 2400]:
            if not aspp.configure_uart(baud=baud):
                results.append((baud, 0, 0.0, "ASPP unreachable"))
                continue
            buf = bytearray()
            try:
                with socket.create_connection((self.host, data_port), timeout=0.8) as s:
                    s.settimeout(0.15)
                    end_t = time.monotonic() + dwell_sec
                    while time.monotonic() < end_t:
                        try:
                            chunk = s.recv(256)
                            if not chunk:
                                break
                            buf.extend(chunk)
                        except socket.timeout:
                            continue
            except OSError:
                results.append((baud, 0, 0.0, "Data port closed"))
                continue

            score, preview = self._score_sample(bytes(buf))
            results.append((baud, len(buf), score, preview))

        best = max(results, key=lambda item: item[2], default=None)
        if best and best[2] > 20.0:
            self.set_uart_config(port_num, baud=best[0])
            self.log_event(
                f"Auto-Baud Scan on Port {port_num} selected {best[0]} bps (score {best[2]:.1f})"
            )
        return results

    @staticmethod
    def _score_sample(sample: bytes) -> Tuple[float, str]:
        if not sample:
            return 0.0, "No traffic"
        counts = Counter(sample)
        total = len(sample)
        noise_ratio = (counts[0x00] + counts[0xFF] + counts[0xFE]) / total
        printable = sum(
            1 for b in sample if 32 <= b <= 126 or b in (0x02, 0x03, 0x0D, 0x0A)
        ) / total
        score = max(0.0, (1.0 - noise_ratio * 0.8) * 60.0 + printable * 40.0)
        return round(score, 1), " ".join(f"{b:02X}" for b in sample[:12])

    # --- Internal Worker Loops ---

    def _socket_reader_loop(self, port_num: int, sock: socket.socket) -> None:
        st = self.ports[port_num]
        buf = bytearray()
        while self._running and st.connected:
            try:
                chunk = sock.recv(256)
                if not chunk:
                    if buf:
                        self._emit_buffered(port_num, bytes(buf))
                        buf.clear()
                    break
                buf.extend(chunk)
                st.rx_bytes += len(chunk)
                st.last_activity = dt.datetime.now().strftime("%H:%M:%S")

                # Forward immediately if part of an Active MITM Bridge
                peer_port = self._mitm_pairs.get(port_num)
                if peer_port is not None:
                    peer_sock = self._sockets.get(peer_port)
                    if peer_sock is not None:
                        try:
                            peer_sock.sendall(chunk)
                            self.ports[peer_port].tx_bytes += len(chunk)
                        except OSError:
                            pass
            except socket.timeout:
                if buf:
                    self._emit_buffered(port_num, bytes(buf))
                    buf.clear()
            except OSError:
                break

        with self._lock:
            st.connected = False
            st.role = "IDLE"

    def _emit_buffered(self, port_num: int, payload: bytes) -> None:
        st = self.ports[port_num]
        st.rx_frames += 1
        if "TAP-A" in st.role:
            label = f"P{port_num} CTRL→DEV"
        elif "TAP-B" in st.role:
            label = f"P{port_num} DEV→CTRL"
        elif "MITM" in st.role:
            label = f"P{port_num} MITM"
        else:
            label = f"P{port_num} RX"
        self._record_frame(port_num, label, payload)

    def _record_frame(self, port_num: int, direction: str, payload: bytes) -> None:
        now_wall = dt.datetime.now(dt.timezone.utc).astimezone()
        now_mono = time.monotonic()
        with self._lock:
            self._seq += 1
            delta_ms = (
                (now_mono - self._last_mono) * 1000.0
                if self._last_mono is not None
                else 0.0
            )
            self._last_mono = now_mono
            frame = SerialFrame(
                seq=self._seq,
                timestamp=now_wall,
                delta_ms=delta_ms,
                port_num=port_num,
                direction=direction,
                payload=payload,
            )
            self.frames.append(frame)
            if self._jsonl_file is not None:
                self._jsonl_file.write(json.dumps(frame.to_json_dict()) + "\n")
                self._jsonl_file.flush()

    def _simulation_loop(self) -> None:
        """Generate realistic legacy SMT RS-232 polling and status frames in demo mode."""
        step = 0
        while self._running:
            time.sleep(1.2)
            p1, p2 = self.ports[1], self.ports[2]
            if not (p1.connected and p2.connected):
                continue

            step += 1
            # Simulated Legacy Controller -> SMT Device frame on Port 1:
            # STX (0x02) + Addr '01' + Cmd 'POLL' + Seq byte + ETX (0x03) + XOR checksum
            seq_ascii = f"{step % 100:02d}".encode("ascii")
            body_req = b"\x0201POLL:" + seq_ascii + b"\x03"
            xor_req = 0
            for b in body_req:
                xor_req ^= b
            req_pkt = body_req + bytes([xor_req])

            p1.rx_bytes += len(req_pkt)
            p1.rx_frames += 1
            p1.last_activity = dt.datetime.now().strftime("%H:%M:%S")
            self._record_frame(1, "P1 CTRL→DEV", req_pkt)

            time.sleep(0.035)
            # Simulated SMT Device -> Legacy Controller reply on Port 2:
            temp_val = 245 + (step % 5)
            body_resp = f"\x0201OK:T={temp_val}C:S=READY\x03".encode("ascii")
            xor_resp = 0
            for b in body_resp:
                xor_resp ^= b
            resp_pkt = body_resp + bytes([xor_resp])

            p2.rx_bytes += len(resp_pkt)
            p2.rx_frames += 1
            p2.last_activity = dt.datetime.now().strftime("%H:%M:%S")
            self._record_frame(2, "P2 DEV→CTRL", resp_pkt)
