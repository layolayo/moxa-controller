#!/usr/bin/env python3
"""
SMT Control System — Dual-Channel RS-232 Tap & MITM Protocol Logger

Supports:
  1. Networked Moxa NPort TCP Server endpoints (e.g. tcp://192.168.127.254:4001)
  2. Local Linux serial devices (e.g. /dev/ttyUSB0, /dev/ttyr00) via pyserial

Modes:
  - Passive Tap Mode (default): Listens on Channel A (CTRL -> DEV) and Channel B (DEV -> CTRL)
    simultaneously, framing packets by configurable inter-byte silence gap (--gap-ms),
    displaying colourised Hex + ASCII dumps, and writing structured JSONL logs.
  - Active MITM Mode (--mitm): Bridges bytes bidirectionally between Channel A and Channel B
    whilst recording the full conversation.
"""

from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import json
import socket
import sys
import time
from pathlib import Path
from typing import Optional, Tuple


ANSI_RESET = "\033[0m"
ANSI_CYAN = "\033[96m"
ANSI_YELLOW = "\033[93m"
ANSI_DIM = "\033[2m"


def format_hex_ascii(payload: bytes) -> Tuple[str, str]:
    """Return space-separated uppercase hex string and printable ASCII string."""
    hex_str = " ".join(f"{b:02X}" for b in payload)
    ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in payload)
    return hex_str, ascii_str


def calc_simple_checksums(payload: bytes) -> dict:
    """Compute common 8-bit checksum candidates to aid protocol analysis."""
    xor_val = 0
    for b in payload:
        xor_val ^= b
    sum8 = sum(payload) & 0xFF
    twos_comp = (-sum8) & 0xFF
    return {
        "xor8": f"0x{xor_val:02X}",
        "sum8": f"0x{sum8:02X}",
        "lrc_2s": f"0x{twos_comp:02X}",
    }


async def open_endpoint(
    endpoint: str, baudrate: int
) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Open either a tcp://host:port socket or a local serial port as asyncio streams."""
    if endpoint.startswith("tcp://"):
        host_port = endpoint[len("tcp://") :]
        host, port_str = host_port.rsplit(":", 1)
        reader, writer = await asyncio.open_connection(host, int(port_str))
        sock: Optional[socket.socket] = writer.get_extra_info("socket")
        if sock is not None:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return reader, writer

    try:
        import serial_asyncio  # type: ignore
    except ImportError as exc:
        raise RuntimeError(
            f"Local serial endpoint '{endpoint}' requires 'pyserial-asyncio'. "
            "Install via: pip install pyserial pyserial-asyncio (or use tcp://host:port for Moxa)."
        ) from exc

    return await serial_asyncio.open_serial_connection(url=endpoint, baudrate=baudrate)


class FrameLogger:
    """Formats and records framed serial packets with microsecond timestamps and deltas."""

    def __init__(self, jsonl_path: Optional[Path], use_colour: bool = True) -> None:
        self.jsonl_path = jsonl_path
        self.use_colour = use_colour
        self.last_frame_mono: Optional[float] = None
        self.seq = 0
        self._file = jsonl_path.open("a", encoding="utf-8") if jsonl_path else None

    def close(self) -> None:
        if self._file:
            self._file.close()

    def record_frame(
        self,
        direction: str,
        label: str,
        payload: bytes,
        start_wall: dt.datetime,
        start_mono: float,
    ) -> None:
        self.seq += 1
        delta_ms = (
            (start_mono - self.last_frame_mono) * 1000.0
            if self.last_frame_mono is not None
            else 0.0
        )
        self.last_frame_mono = start_mono

        hex_str, ascii_str = format_hex_ascii(payload)
        ts_str = start_wall.strftime("%H:%M:%S.%f")

        colour = (
            (ANSI_CYAN if direction == "A" else ANSI_YELLOW)
            if self.use_colour
            else ""
        )
        reset = ANSI_RESET if self.use_colour else ""
        dim = ANSI_DIM if self.use_colour else ""

        print(
            f"{dim}[{ts_str} +{delta_ms:8.3f} ms]{reset} "
            f"{colour}{label:<12}{reset} "
            f"({len(payload):3d} B) | {colour}{hex_str:<47}{reset} | {ascii_str}"
        )
        sys.stdout.flush()

        if self._file:
            entry = {
                "seq": self.seq,
                "timestamp": start_wall.isoformat(),
                "delta_ms": round(delta_ms, 3),
                "direction": label,
                "length": len(payload),
                "hex": hex_str,
                "ascii": ascii_str,
                "checksum_hints": calc_simple_checksums(payload),
            }
            self._file.write(json.dumps(entry) + "\n")
            self._file.flush()


async def pump_channel(
    direction: str,
    label: str,
    reader: asyncio.StreamReader,
    peer_writer: Optional[asyncio.StreamWriter],
    gap_seconds: float,
    logger: FrameLogger,
) -> None:
    """Read bytes from a channel, optionally forward in MITM mode, and emit frames on silence gap."""
    buffer = bytearray()
    frame_start_wall: Optional[dt.datetime] = None
    frame_start_mono: float = 0.0

    while True:
        try:
            timeout = gap_seconds if buffer else None
            chunk = await asyncio.wait_for(reader.read(256), timeout=timeout)
            if not chunk:
                if buffer and frame_start_wall is not None:
                    logger.record_frame(
                        direction, label, bytes(buffer), frame_start_wall, frame_start_mono
                    )
                print(f"[!] Endpoint {label} closed connection.", file=sys.stderr)
                break

            now_wall = dt.datetime.now(dt.timezone.utc).astimezone()
            now_mono = time.monotonic()

            if not buffer:
                frame_start_wall = now_wall
                frame_start_mono = now_mono

            buffer.extend(chunk)

            if peer_writer is not None:
                peer_writer.write(chunk)
                await peer_writer.drain()

        except asyncio.TimeoutError:
            if buffer and frame_start_wall is not None:
                logger.record_frame(
                    direction, label, bytes(buffer), frame_start_wall, frame_start_mono
                )
                buffer.clear()
                frame_start_wall = None


async def run_sniffer(args: argparse.Namespace) -> None:
    print(f"[*] Initialising Channel A ({args.label_a}): {args.port_a}")
    reader_a, writer_a = await open_endpoint(args.port_a, args.baud)

    print(f"[*] Initialising Channel B ({args.label_b}): {args.port_b}")
    reader_b, writer_b = await open_endpoint(args.port_b, args.baud)

    mode_str = "ACTIVE MITM BRIDGE" if args.mitm else "PASSIVE DUAL-RX TAP"
    print(
        f"[*] Mode: {mode_str} | Silence Gap: {args.gap_ms:.1f} ms | Baud: {args.baud}"
    )
    if args.output:
        print(f"[*] Writing structured JSONL capture to: {args.output}")
    print("-" * 100)

    logger = FrameLogger(Path(args.output) if args.output else None, not args.no_colour)
    gap_sec = args.gap_ms / 1000.0

    try:
        await asyncio.gather(
            pump_channel(
                "A",
                args.label_a,
                reader_a,
                writer_b if args.mitm else None,
                gap_sec,
                logger,
            ),
            pump_channel(
                "B",
                args.label_b,
                reader_b,
                writer_a if args.mitm else None,
                gap_sec,
                logger,
            ),
        )
    finally:
        logger.close()
        writer_a.close()
        writer_b.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Dual-channel RS-232 passive tap and MITM logger for Moxa TCP Server or local TTYs."
    )
    parser.add_argument(
        "--port-a",
        required=True,
        help="Channel A endpoint, e.g. tcp://192.168.127.254:4001 or /dev/ttyUSB0",
    )
    parser.add_argument(
        "--port-b",
        required=True,
        help="Channel B endpoint, e.g. tcp://192.168.127.254:4002 or /dev/ttyUSB1",
    )
    parser.add_argument(
        "--baud",
        type=int,
        default=9600,
        help="Baud rate for local TTY endpoints (default: 9600)",
    )
    parser.add_argument(
        "--gap-ms",
        type=float,
        default=10.0,
        help="Inter-frame silence threshold in milliseconds (default: 10.0 ms)",
    )
    parser.add_argument(
        "--label-a",
        default="CTRL → DEV",
        help="Display label for Channel A (default: 'CTRL → DEV')",
    )
    parser.add_argument(
        "--label-b",
        default="DEV → CTRL",
        help="Display label for Channel B (default: 'DEV → CTRL')",
    )
    parser.add_argument(
        "--mitm",
        action="store_true",
        help="Enable active Man-in-the-Middle forwarding between Port A and Port B",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Optional path to write structured JSONL packet capture file",
    )
    parser.add_argument(
        "--no-colour",
        action="store_true",
        help="Disable ANSI terminal colours",
    )
    return parser.parse_args()


if __name__ == "__main__":
    try:
        asyncio.run(run_sniffer(parse_args()))
    except KeyboardInterrupt:
        print("\n[*] Capture stopped by user.")
