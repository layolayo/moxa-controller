#!/usr/bin/env python3
"""
Moxa NPort Network Probe & ASPP Baud-Rate Auto-Scanner

Features:
  1. Port & Mode Discovery (`--check`):
     Probes a Moxa NPort IP address to identify active TCP Server data ports (4001+),
     ASPP command ports (966+), Real COM ports (950+), and web console status.
  2. Automatic Baud-Rate Scanner (`--scan-baud`):
     Uses the Moxa ASPP Command Port (TCP 966 + port_index) to dynamically step the NPort
     UART through standard baud rates (1200 to 115200), samples live serial traffic on
     the corresponding TCP Data Port (4001 + port_index), and ranks candidate baud rates
     by framing consistency and entropy.
"""

from __future__ import annotations

import argparse
import socket
import time
from collections import Counter
from typing import Dict, List, Tuple


# Moxa ASPP (Async Server Private Protocol) baud rate index table
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


def check_tcp_port(host: str, port: int, timeout: float = 0.8) -> bool:
    """Return True if a TCP connection succeeds to host:port."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def probe_nport(host: str, max_ports: int = 8) -> None:
    """Scan common Moxa NPort 5610-8-DT management, Real COM, and TCP Server ports."""
    print(f"[*] Probing Moxa NPort 5610-8-DT at {host} ...")
    mgmt_ports = [
        (80, "HTTP Web Console"),
        (443, "HTTPS Web Console"),
        (23, "Telnet Console"),
        (22, "SSH Console"),
    ]
    for port, desc in mgmt_ports:
        status = "OPEN" if check_tcp_port(host, port) else "closed"
        print(f"    Management Port {port:5d} ({desc:<20}): {status}")

    print("\n[*] Checking Serial Channel Ports (TCP Server vs Real COM):")
    for idx in range(max_ports):
        port_num = idx + 1
        data_port = 4001 + idx
        cmd_port = 966 + idx
        realcom_data = 950 + idx

        data_open = check_tcp_port(host, data_port)
        cmd_open = check_tcp_port(host, cmd_port)
        rcom_open = check_tcp_port(host, realcom_data)

        if data_open or cmd_open or rcom_open:
            mode = (
                "TCP Server Mode"
                if data_open
                else ("Real COM Mode" if rcom_open else "Custom/Filtered")
            )
            print(
                f"    Serial Port {port_num}: {mode:<16} | "
                f"Data({data_port})={'OPEN' if data_open else 'closed'} | "
                f"Cmd({cmd_port})={'OPEN' if cmd_open else 'closed'} | "
                f"RealCOM({realcom_data})={'OPEN' if rcom_open else 'closed'}"
            )
        else:
            print(f"    Serial Port {port_num}: No active TCP listeners detected")


def aspp_set_uart(host: str, cmd_port: int, baud: int, mode_byte: int = 0x03) -> bool:
    """
    Send Moxa ASPP `IOCTL` command (0x10) to dynamically set baud rate and framing.
    mode_byte=0x03 corresponds to 8 data bits, No parity, 1 stop bit (8N1).
    """
    baud_idx = ASPP_BAUD_MAP.get(baud)
    if baud_idx is None:
        raise ValueError(f"Unsupported ASPP baud rate: {baud}")

    # ASPP Command 0x10 (Set Port Settings): [0x10, len=4, baud_idx, mode_byte, dtr=1, rts=1]
    packet = bytes([0x10, 0x04, baud_idx, mode_byte, 0x01, 0x01])
    try:
        with socket.create_connection((host, cmd_port), timeout=1.5) as sock:
            sock.sendall(packet)
            sock.settimeout(1.0)
            resp = sock.recv(16)
            return len(resp) >= 2 and resp[0] == 0x10
    except OSError:
        return False


def score_serial_sample(sample: bytes) -> Tuple[float, str]:
    """
    Heuristic quality score for captured bytes at a candidate baud rate.
    Wrong baud rates typically produce abundant 0x00, 0xFF, 0xFE, 0x80 framing noise.
    """
    if not sample:
        return 0.0, "No bytes received"

    counts = Counter(sample)
    total = len(sample)
    null_ff_ratio = (counts[0x00] + counts[0xFF] + counts[0xFE]) / total
    printable_ratio = sum(1 for b in sample if 32 <= b <= 126 or b in (0x0D, 0x0A, 0x09)) / total

    # Reward structured binary or printable ASCII, penalise heavy break/framing noise (0x00/0xFF)
    score = (1.0 - (null_ff_ratio * 0.8)) * 60.0 + (printable_ratio * 40.0)
    preview_hex = " ".join(f"{b:02X}" for b in sample[:16])
    return round(max(score, 0.0), 1), preview_hex


def scan_baud_rates(host: str, serial_port: int, dwell_sec: float) -> None:
    """Step an NPort serial channel through standard baud rates and score live traffic."""
    idx = serial_port - 1
    data_port = 4001 + idx
    cmd_port = 966 + idx
    candidates: List[int] = [9600, 19200, 38400, 57600, 115200, 4800, 2400, 1200]

    print(
        f"[*] Scanning baud rates on {host} Serial Port {serial_port} "
        f"(Data :{data_port}, ASPP Cmd :{cmd_port}, Dwell: {dwell_sec:.1f}s)..."
    )
    print("-" * 92)
    print(f"{'Baud':>8} | {'Bytes':>6} | {'Score':>6} | {'Sample Hex (first 16 bytes)'}")
    print("-" * 92)

    for baud in candidates:
        ok = aspp_set_uart(host, cmd_port, baud)
        if not ok:
            print(f"{baud:8d} |   ERR  |    0.0 | Could not set baud via ASPP port {cmd_port}")
            continue

        buf = bytearray()
        try:
            with socket.create_connection((host, data_port), timeout=1.5) as sock:
                sock.settimeout(0.25)
                deadline = time.monotonic() + dwell_sec
                while time.monotonic() < deadline:
                    try:
                        chunk = sock.recv(256)
                        if not chunk:
                            break
                        buf.extend(chunk)
                    except socket.timeout:
                        continue
        except OSError as exc:
            print(f"{baud:8d} |   ERR  |    0.0 | Data port error: {exc}")
            continue

        score, preview = score_serial_sample(bytes(buf))
        print(f"{baud:8d} | {len(buf):6d} | {score:6.1f} | {preview}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Moxa NPort network probe and ASPP baud-rate auto-scanner."
    )
    parser.add_argument("host", help="Moxa NPort IP address (e.g. 192.168.127.254)")
    parser.add_argument(
        "--port",
        type=int,
        default=1,
        help="NPort serial port number (1-based, default: 1)",
    )
    parser.add_argument(
        "--scan-baud",
        action="store_true",
        help="Auto-scan standard baud rates via Moxa ASPP command port (966+)",
    )
    parser.add_argument(
        "--dwell",
        type=float,
        default=3.0,
        help="Seconds to listen per baud rate during --scan-baud (default: 3.0s)",
    )
    args = parser.parse_args()

    if args.scan_baud:
        scan_baud_rates(args.host, args.port, args.dwell)
    else:
        probe_nport(args.host)


if __name__ == "__main__":
    main()
