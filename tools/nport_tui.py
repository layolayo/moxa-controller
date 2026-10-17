#!/usr/bin/env python3
"""
Moxa NPort 5610-8-DT — Interactive 8-Port Terminal User Interface (TUI)

Provides full hardware control, monitoring, passive dual-RX tapping, active MITM
bridging, auto-baud scanning, and frame injection across all 8 RS-232 ports of a
Moxa NPort 5610-8-DT over Ethernet (TCP Data 4001..4008, ASPP Command 966..973,
and UDP Discovery 4800).

Usage:
  # Connect to a live Moxa NPort 5610-8-DT:
  ./tools/nport_tui.py 192.168.127.254

  # Run in interactive Demo / Simulation mode (with simulated legacy SMT traffic):
  ./tools/nport_tui.py --demo

  # Print a non-interactive 8-port status & protocol snapshot:
  ./tools/nport_tui.py --demo --snapshot
"""

from __future__ import annotations

import argparse
import curses
import sys
from pathlib import Path
from typing import Optional

# Ensure repository root is importable when invoked as ./tools/nport_tui.py
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from nport5610.protocol import (  # noqa: E402
    FRAMING_LIST,
    STANDARD_BAUDS,
    NPort5610Controller,
    discover_nports_udp,
)


def parse_user_payload(raw_input: str) -> bytes:
    """
    Parse user input string into bytes:
      - If prefixed with 'hex:' (e.g. 'hex:02 30 31 03'), parses hexadecimal bytes.
      - Otherwise interprets standard escape sequences (\\r, \\n, \\x02, \\x03) and ASCII.
    """
    text = raw_input.strip()
    if text.lower().startswith("hex:"):
        hex_part = text[4:].replace(",", " ").replace("0x", "")
        return bytes.fromhex(hex_part)
    return text.encode("utf-8").decode("unicode_escape").encode("latin1")


def pair_for_port(port_num: int) -> tuple[int, int]:
    """Return natural adjacent port pair (1,2), (3,4), (5,6), or (7,8)."""
    base = ((port_num - 1) // 2) * 2 + 1
    return base, base + 1


def draw_safe(
    win: "curses._CursesWindow", y: int, x: int, text: str, attr: int = 0
) -> None:
    """Safely draw a string clipped to window dimensions without raising curses.error."""
    max_y, max_x = win.getmaxyx()
    if y < 0 or y >= max_y or x < 0 or x >= max_x:
        return
    avail = max_x - x - 1
    if avail <= 0:
        return
    try:
        win.addstr(y, x, text[:avail], attr)
    except curses.error:
        pass


def prompt_line(
    stdscr: "curses._CursesWindow", prompt_text: str
) -> Optional[str]:
    """Display a modal bottom-line input prompt and return entered string."""
    max_y, max_x = stdscr.getmaxyx()
    curses.echo()
    curses.curs_set(1)
    stdscr.nodelay(False)
    try:
        stdscr.move(max_y - 1, 0)
        stdscr.clrtoeol()
        draw_safe(stdscr, max_y - 1, 0, prompt_text, curses.A_BOLD)
        stdscr.refresh()
        raw = stdscr.getstr(
            max_y - 1, min(len(prompt_text), max_x - 2), max(max_x - len(prompt_text) - 2, 1)
        )
        return raw.decode("utf-8", errors="replace").strip()
    except KeyboardInterrupt:
        return None
    finally:
        curses.noecho()
        curses.curs_set(0)
        stdscr.nodelay(True)


def run_curses_tui(stdscr: "curses._CursesWindow", ctrl: NPort5610Controller) -> None:
    curses.curs_set(0)
    stdscr.nodelay(True)
    stdscr.keypad(True)

    has_colours = curses.has_colors()
    if has_colours:
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_CYAN, -1)     # Headers / Channel A
        curses.init_pair(2, curses.COLOR_YELLOW, -1)   # Channel B / Warnings
        curses.init_pair(3, curses.COLOR_GREEN, -1)    # Active / Online / ON
        curses.init_pair(4, curses.COLOR_RED, -1)      # Recording / Alert
        curses.init_pair(5, curses.COLOR_MAGENTA, -1)  # TX / Injected
        curses.init_pair(6, curses.COLOR_WHITE, curses.COLOR_BLUE)  # Top banner

    c_cyan = curses.color_pair(1) if has_colours else 0
    c_yellow = curses.color_pair(2) if has_colours else 0
    c_green = curses.color_pair(3) if has_colours else 0
    c_red = curses.color_pair(4) if has_colours else 0
    c_magenta = curses.color_pair(5) if has_colours else 0
    c_banner = (curses.color_pair(6) | curses.A_BOLD) if has_colours else curses.A_REVERSE

    selected_port = 1

    while True:
        stdscr.erase()
        max_y, max_x = stdscr.getmaxyx()

        # 1. Top Title Banner
        rec_tag = (
            f" ● REC: {ctrl.jsonl_path.name} "
            if ctrl.jsonl_path is not None
            else " ○ REC: OFF "
        )
        header = (
            f" MOXA NPort 5610-8-DT Control Console | Host: {ctrl.host} "
            f"| Mode: {ctrl.mode_banner} | Gap: {ctrl.gap_ms:.1f}ms |{rec_tag}"
        )
        draw_safe(stdscr, 0, 0, header.ljust(max_x), c_banner)

        # 2. 8-Port Status Table (Lines 2..11)
        draw_safe(
            stdscr,
            1,
            1,
            "PORT   DATA    ASPP   ROLE              UART        OUT(DTR/RTS)  IN(CTS/DSR/DCD)     RX(F/B)       TX(F/B)",
            c_cyan | curses.A_BOLD,
        )
        for p in range(1, 9):
            st = ctrl.ports[p]
            row_y = 1 + p
            is_sel = p == selected_port
            prefix = "▶" if is_sel else " "
            uart_str = f"{st.baud:>6} {st.framing}"
            out_pins = f"DTR:{'1' if st.dtr else '0'} RTS:{'1' if st.rts else '0'}"
            in_pins = (
                f"CTS:{'1' if st.cts else '0'} "
                f"DSR:{'1' if st.dsr else '0'} "
                f"DCD:{'1' if st.dcd else '0'}"
            )
            rx_stat = f"{st.rx_frames:4d}/{st.rx_bytes:6d}B"
            tx_stat = f"{st.tx_frames:4d}/{st.tx_bytes:6d}B"

            line = (
                f"{prefix} P{p}  :{st.data_tcp_port:<5d} :{st.aspp_tcp_port:<4d}  "
                f"{st.role:<16}  {uart_str:<10}  {out_pins:<12}  {in_pins:<16}  "
                f"{rx_stat:<12}  {tx_stat:<12}"
            )
            row_attr = curses.A_REVERSE if is_sel else (c_green if st.connected else 0)
            draw_safe(stdscr, row_y, 1, line, row_attr)

        # 3. Command & Keybinding Bar (Lines 11..13)
        pa, pb = pair_for_port(selected_port)
        draw_safe(stdscr, 10, 1, "─" * (max_x - 2), c_cyan)
        keys_line1 = (
            f"[1-8/↑↓] Select P{selected_port}  [c] Connect/Disc  [b] Baud  [f] Framing  "
            f"[d] Toggle DTR  [r] Toggle RTS  [x] Flush FIFO  [k] Send BREAK"
        )
        keys_line2 = (
            f"[t] Passive Tap (P{pa}+P{pb})  [m] Active MITM (P{pa}⟷P{pb})  "
            f"[i] Inject TX  [s] Auto-Baud Scan  [p] Probe 8 Ports  [u] UDP Scan  [l] JSONL Rec  [q] Quit"
        )
        draw_safe(stdscr, 11, 1, keys_line1, curses.A_BOLD)
        draw_safe(stdscr, 12, 1, keys_line2, c_yellow)
        draw_safe(stdscr, 13, 1, "─" * (max_x - 2), c_cyan)

        # 4. Live Framed Serial Packet Inspector (Lines 14 .. max_y - 4)
        draw_safe(
            stdscr,
            14,
            1,
            "SEQ   TIMESTAMP        +DELTA(ms)  SOURCE          LEN   HEX PAYLOAD                                    ASCII             CHECKSUMS (XOR/LRC)",
            c_cyan | curses.A_BOLD,
        )
        frame_rows = max(max_y - 19, 1)
        visible_frames = list(ctrl.frames)[-frame_rows:]
        for idx, fr in enumerate(visible_frames):
            y = 15 + idx
            ts_s = fr.timestamp.strftime("%H:%M:%S.%f")[:-3]
            cs = fr.checksum_hints
            cs_str = f"X:{cs['xor8']} L:{cs['lrc']}"
            row_text = (
                f"#{fr.seq:<4d} {ts_s}  +{fr.delta_ms:8.2f}  "
                f"{fr.direction:<14}  {len(fr.payload):3d}B  "
                f"{fr.hex_str[:45]:<45}  {fr.ascii_str[:16]:<16}  {cs_str}"
            )
            if "CTRL→DEV" in fr.direction or "P1" in fr.direction:
                f_attr = c_cyan
            elif "DEV→CTRL" in fr.direction or "P2" in fr.direction:
                f_attr = c_yellow
            elif "TX" in fr.direction:
                f_attr = c_magenta
            else:
                f_attr = c_green
            draw_safe(stdscr, y, 1, row_text, f_attr)

        # 5. Bottom Event Status Log (Last 3 lines)
        draw_safe(stdscr, max_y - 4, 1, "─" * (max_x - 2), c_cyan)
        recent_logs = list(ctrl.status_log)[-3:]
        for idx, entry in enumerate(recent_logs):
            draw_safe(
                stdscr,
                max_y - 3 + idx,
                1,
                entry,
                c_red if "ERROR" in entry or "WARNING" in entry else 0,
            )

        stdscr.refresh()

        # Input handling (50 ms tick)
        curses.napms(50)
        ch = stdscr.getch()
        if ch == -1:
            continue

        if ch in (ord("q"), ord("Q")):
            break
        elif ord("1") <= ch <= ord("8"):
            selected_port = ch - ord("0")
        elif ch == curses.KEY_UP:
            selected_port = 8 if selected_port == 1 else selected_port - 1
        elif ch == curses.KEY_DOWN:
            selected_port = 1 if selected_port == 8 else selected_port + 1
        elif ch in (ord("c"), ord("C")):
            st = ctrl.ports[selected_port]
            if st.connected:
                ctrl.disconnect_port(selected_port)
            else:
                ctrl.connect_port(selected_port, role="STREAM")
        elif ch in (ord("b"), ord("B")):
            st = ctrl.ports[selected_port]
            cur_idx = (
                STANDARD_BAUDS.index(st.baud) if st.baud in STANDARD_BAUDS else 3
            )
            next_baud = STANDARD_BAUDS[(cur_idx + 1) % len(STANDARD_BAUDS)]
            ctrl.set_uart_config(selected_port, baud=next_baud)
        elif ch in (ord("f"), ord("F")):
            st = ctrl.ports[selected_port]
            cur_idx = (
                FRAMING_LIST.index(st.framing) if st.framing in FRAMING_LIST else 0
            )
            next_framing = FRAMING_LIST[(cur_idx + 1) % len(FRAMING_LIST)]
            ctrl.set_uart_config(selected_port, framing=next_framing)
        elif ch in (ord("d"), ord("D")):
            ctrl.toggle_dtr(selected_port)
        elif ch in (ord("r"), ord("R")):
            ctrl.toggle_rts(selected_port)
        elif ch in (ord("x"), ord("X")):
            ctrl.flush_port(selected_port)
        elif ch in (ord("k"), ord("K")):
            ctrl.send_break_pulse(selected_port, duration_ms=250)
        elif ch in (ord("t"), ord("T")):
            pa, pb = pair_for_port(selected_port)
            ctrl.start_passive_tap(pa, pb)
        elif ch in (ord("m"), ord("M")):
            pa, pb = pair_for_port(selected_port)
            ctrl.start_mitm_bridge(pa, pb)
        elif ch in (ord("p"), ord("P")):
            ctrl.probe_all_ports()
        elif ch in (ord("s"), ord("S")):
            ctrl.log_event(f"Running ASPP Auto-Baud scan on Port {selected_port}...")
            stdscr.refresh()
            ctrl.scan_baud_on_port(selected_port)
        elif ch in (ord("u"), ord("U")):
            ctrl.log_event("Broadcasting UDP 4800 discovery query...")
            stdscr.refresh()
            units = discover_nports_udp(timeout=1.0)
            if units:
                for u in units:
                    ctrl.log_event(
                        f"Discovered {u.model_name} at {u.ip_address} (MAC {u.mac_address})"
                    )
            else:
                ctrl.log_event("UDP 4800 scan finished: no remote units responded on LAN")
        elif ch in (ord("l"), ord("L")):
            ctrl.toggle_jsonl_recording()
        elif ch in (ord("g"), ord("G")):
            ctrl.frames.clear()
            ctrl.log_event("Cleared packet capture display buffer")
        elif ch in (ord("i"), ord("I")):
            user_str = prompt_line(
                stdscr,
                f"Inject on Port {selected_port} (ASCII or 'hex:02 30 31 03'): ",
            )
            if user_str:
                try:
                    payload = parse_user_payload(user_str)
                    ctrl.send_payload(selected_port, payload)
                except ValueError as exc:
                    ctrl.log_event(f"Invalid payload format: {exc}")


def print_snapshot(ctrl: NPort5610Controller) -> None:
    """Render a clean text summary of all 8 ports and recent frames for CLI verification."""
    print(
        f"=== MOXA NPort 5610-8-DT Snapshot | Host: {ctrl.host} | Mode: {ctrl.mode_banner} ==="
    )
    print(
        "PORT  DATA    ASPP   ROLE              UART        OUT(DTR/RTS)  IN(CTS/DSR/DCD)   RX(F/B)      TX(F/B)"
    )
    print("-" * 106)
    for p in range(1, 9):
        st = ctrl.ports[p]
        print(
            f"P{p}   :{st.data_tcp_port:<5d} :{st.aspp_tcp_port:<4d}  "
            f"{st.role:<16}  {st.baud:>6} {st.framing}  "
            f"DTR:{int(st.dtr)} RTS:{int(st.rts)}   "
            f"CTS:{int(st.cts)} DSR:{int(st.dsr)} DCD:{int(st.dcd)}    "
            f"{st.rx_frames:3d}/{st.rx_bytes:5d}B   {st.tx_frames:3d}/{st.tx_bytes:5d}B"
        )
    print("-" * 106)
    for fr in list(ctrl.frames)[-6:]:
        cs = fr.checksum_hints
        print(
            f"#{fr.seq:<3d} [{fr.timestamp.strftime('%H:%M:%S.%f')[:-3]} +{fr.delta_ms:6.2f}ms] "
            f"{fr.direction:<14} ({len(fr.payload):2d}B) | {fr.hex_str:<40} | {fr.ascii_str:<16} | XOR:{cs['xor8']} LRC:{cs['lrc']}"
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Interactive 8-Port TUI Controller & Sniffer for Moxa NPort 5610-8-DT"
    )
    parser.add_argument(
        "host",
        nargs="?",
        default="192.168.127.254",
        help="Moxa NPort 5610-8-DT IP address (default: 192.168.127.254)",
    )
    parser.add_argument(
        "--gap-ms",
        type=float,
        default=8.0,
        help="Inter-frame silence gap in milliseconds (default: 8.0 ms)",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run with simulated 8-port NPort 5610-8-DT and synthetic SMT RS-232 traffic",
    )
    parser.add_argument(
        "--snapshot",
        action="store_true",
        help="Capture a brief snapshot and print 8-port status table to stdout without curses",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    ctrl = NPort5610Controller(
        host=args.host, gap_ms=args.gap_ms, simulate=args.demo
    )
    try:
        if not args.demo:
            ctrl.probe_all_ports()
        if args.snapshot:
            if args.demo:
                import time

                time.sleep(1.4)
            print_snapshot(ctrl)
            return
        curses.wrapper(run_curses_tui, ctrl)
    finally:
        ctrl.shutdown()


if __name__ == "__main__":
    main()
