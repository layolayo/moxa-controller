#!/usr/bin/env python3
"""
Live USB-Serial (/dev/ttyUSB0) Hex + ASCII + Timestamp Monitor & Transmitter.
Usage:
    python3 scripts/watch_usb_serial.py [/dev/ttyUSB0] [BAUD]
Example:
    python3 scripts/watch_usb_serial.py /dev/ttyUSB0 38400
"""

import datetime
import os
import select
import sys
import termios
import tty

BAUD_MAP = {
    1200: termios.B1200,
    2400: termios.B2400,
    4800: termios.B4800,
    9600: termios.B9600,
    19200: termios.B19200,
    38400: termios.B38400,
    57600: termios.B57600,
    115200: termios.B115200,
    230400: termios.B230400,
}


def configure_serial(fd: int, baud: int) -> None:
    attrs = termios.tcgetattr(fd)
    speed = BAUD_MAP.get(baud, termios.B38400)
    # 8N1, raw mode, no flow control
    attrs[0] = 0  # iflag
    attrs[1] = 0  # oflag
    attrs[2] = termios.CS8 | termios.CREAD | termios.CLOCAL  # cflag
    attrs[3] = 0  # lflag
    attrs[4] = speed  # ispeed
    attrs[5] = speed  # ospeed
    attrs[6][termios.VMIN] = 1
    attrs[6][termios.VTIME] = 0
    termios.tcsetattr(fd, termios.TCSANOW, attrs)


def main() -> None:
    dev = sys.argv[1] if len(sys.argv) > 1 else "/dev/ttyUSB0"
    baud = int(sys.argv[2]) if len(sys.argv) > 2 else 38400

    try:
        fd = os.open(dev, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    except PermissionError:
        print(f"Permission denied opening {dev}.")
        print(f"Run with sudo, or unlock permissions once with:")
        print(f"  sudo chmod 666 {dev} && sudo usermod -aG uucp $USER")
        sys.exit(1)

    configure_serial(fd, baud)
    print(f"=== Watching {dev} @ {baud} 8N1 (Ctrl+C to quit) ===")
    print("Type any text and press Enter to transmit over USB-Serial.\n")

    rx_buf = bytearray()
    last_rx = None

    try:
        while True:
            rlist, _, _ = select.select([fd, sys.stdin], [], [], 0.02)
            now = datetime.datetime.now()

            if fd in rlist:
                chunk = os.read(fd, 1024)
                if chunk:
                    rx_buf.extend(chunk)
                    last_rx = now

            # Flush frame after 20 ms inter-frame gap
            if rx_buf and last_rx and (now - last_rx).total_seconds() >= 0.02:
                ts = now.strftime("%H:%M:%S.%f")[:-3]
                hex_str = " ".join(f"{b:02X}" for b in rx_buf)
                ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in rx_buf)
                print(f"[{ts}] RX ({len(rx_buf):3d} B) | {hex_str:<48} | {ascii_str}")
                rx_buf.clear()

            if sys.stdin in rlist:
                line = sys.stdin.readline()
                if line:
                    payload = line.rstrip("\r\n").encode("utf-8") + b"\r\n"
                    os.write(fd, payload)
                    ts = now.strftime("%H:%M:%S.%f")[:-3]
                    hex_str = " ".join(f"{b:02X}" for b in payload)
                    print(f"[{ts}] TX ({len(payload):3d} B) | {hex_str}")
    except KeyboardInterrupt:
        print("\nClosed serial monitor.")
    finally:
        os.close(fd)


if __name__ == "__main__":
    main()
