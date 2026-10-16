# Interfacing a Linux Application with a Moxa Ethernet-to-Serial Device

When developing a Linux application to communicate with an Ethernet-connected Moxa serial device (such as a **Moxa NPort** serial device server or an **MGate** protocol gateway), you do not need to invent a custom transport protocol. Moxa devices support three primary operating architectures, ranging from direct network sockets to transparent virtual serial ports.

---

## 1. Direct Socket Mode (TCP Server / TCP Client / UDP) — *Recommended for New Applications*

In this mode, the Moxa device acts as a transparent bridge between an Ethernet socket and the physical RS-232/422/485 port. Serial parameters (baud rate, parity, data bits, stop bits, flow control) are pre-configured via the Moxa device's web interface, Telnet/SSH console, or configuration utility.

* **How it works:** You configure the Moxa serial port to **TCP Server Mode** (listening on a specific TCP port, typically `4001` for Port 1, `4002` for Port 2, etc., plus an optional command port at `966`). Every byte sent to that TCP socket is transmitted directly out of the physical serial port, and every byte received on the serial pin is streamed back over the TCP connection.
* **Moxa Packet Framing Options (Crucial for Serial Protocols):**
  * **Packing Length:** Buffer up to N bytes before sending an Ethernet frame.
  * **Delimiter 1 / 2:** Immediately flush the Ethernet buffer when a specific byte (e.g. `0x0D` CR or `0x03` ETX) is seen.
  * **Force Transmit Time:** Flush the buffer after N milliseconds of serial silence (ideal for binary protocols like Modbus RTU that rely on inter-frame silence gaps).
* **Linux Development:** Your application opens a standard POSIX TCP socket (`socket()`, `connect()`, `send()`, `recv()`) to `<moxa-ip>:4001` with `TCP_NODELAY` enabled to prevent Nagle's algorithm from coalescing small control frames.
* **Advantages:**
  * Zero kernel drivers or root dependencies on the Linux host.
  * Works cleanly inside Docker containers, across routed VLANs, and across Linux kernel upgrades.
* **Limitations:**
  * Cannot dynamically change baud rate or toggle hardware control lines (RTS/CTS/DTR) in-band without issuing out-of-band control commands.

---

## 2. RFC 2217 Mode (Telnet COM Port Control Option) — *Standardised Serial-over-IP*

If your application requires network-based communication *plus* the ability to dynamically set baud rates, parity, or monitor/toggle hardware flow-control lines (DTR/RTS/DCD) at runtime, **RFC 2217** is the open industry-standard protocol supported by Moxa NPort devices.

* **How it works:** Wraps the serial byte stream with Telnet-style negotiation packets to control the remote UART registers over TCP.
* **Linux Development:**
  * **Directly in Python (`pyserial`):** Native support for `rfc2217://` URLs without installing kernel drivers:
    ```python
    import serial

    with serial.serial_for_url("rfc2217://192.168.127.254:4001", baudrate=9600, timeout=1.0) as ser:
        ser.dtr = True
        ser.write(b"\x02STATUS\x03")
        reply = ser.read(64)
    ```
  * **Directly in C/C++ / Go / Rust:** Can be used via `ser2net` or standard RFC 2217 client libraries.

---

## 3. Moxa Real TTY Mode (`npreal2`) — *Proprietary Virtual TTY Kernel Driver*

Moxa provides its own proprietary protocol (**Real COM Mode**) and an accompanying Linux kernel driver called **`npreal2`** (Real TTY).

* **How it works:** The driver creates local character device nodes (`/dev/ttyr00`, `/dev/ttyr01`, etc.) in Linux. Under the hood, a background daemon (`mxcfmat` / `npreal2d`) communicates with the Moxa NPort over two TCP ports per serial channel (typically TCP `950` for data and TCP `966` for UART control and `ioctl` commands).
* **Linux Development:** Your Linux application uses standard POSIX `termios` calls (`open("/dev/ttyr00", ...)`, `tcgetattr()`, `tcsetattr()`, `ioctl()`) exactly as if the device were plugged into a local onboard RS-232 port or USB-to-serial adapter.
* **Advantages:**
  * 100% transparent to legacy or closed-source Linux binaries that strictly require a `/dev/tty*` device node and issue `termios` `ioctl` calls.
* **Limitations:**
  * Requires compiling the `npreal2` kernel module against your running Linux kernel headers (which can break after rolling kernel updates until Moxa updates their driver package).

---

## 4. User-Space Virtual TTY (`socat` or `tty0tty`) — *Driverless `/dev/tty` Alternative*

If you are running or testing an application that expects a `/dev/tty*` path, does not need dynamic baud-rate switching, and you wish to avoid compiling Moxa's `npreal2` kernel driver:

* Configure the Moxa device in **TCP Server Mode** (port `4001`).
* Run `socat` on Linux (typically supervised by a `systemd` service) to expose the TCP socket as a local pseudo-terminal:
  ```bash
  socat pty,link=/tmp/ttyMoxa0,rawer,echo=0,waitslave tcp:192.168.127.254:4001,nodelay
  ```
* Point your Linux application at `/tmp/ttyMoxa0`.

---

## 5. Application-Layer Serial Protocols (Payloads)

Because a Moxa NPort handles the **transport** layer (bridging Ethernet to RS-232/422/485), the message framing inside the byte stream depends on the target equipment:

* **Modbus RTU / Modbus ASCII:** Common on industrial controllers. With an NPort in TCP Server mode, use **Modbus RTU-over-TCP** (`libmodbus` or `pymodbus` with `ModbusRtuFramer`). If using a **Moxa MGate**, the gateway can translate **Modbus TCP** to **Modbus RTU** in hardware.
* **SCPI / ASCII Line Protocols:** Human-readable commands terminated by `CR` (`0x0D`), `LF` (`0x0A`), or `CRLF` (`0x0D 0x0A`).
* **Framed Binary Control Protocols:** Addressed packets with start/end markers (such as `STX` `0x02` / `ETX` `0x03`, or `DLE` byte-stuffing), command opcodes, payload lengths, and trailing LRC/XOR/CRC checksums.

---

## Summary Decision Matrix

| Scenario | Recommended Moxa Mode | Linux Implementation |
| :--- | :--- | :--- |
| **New Linux application** (fixed serial settings) | **TCP Server Mode** | Standard POSIX TCP socket (`<ip>:4001` with `TCP_NODELAY`) |
| **New Linux application** (needs runtime baud/RTS/DTR control) | **RFC 2217 Mode** | RFC 2217 client (`pyserial` `rfc2217://` or equivalent) |
| **Legacy binary requiring `/dev/tty*` & `termios` ioctls** | **Real COM Mode** | Moxa `npreal2` Linux kernel driver (`/dev/ttyr00`) |
| **Application requiring `/dev/tty*` without kernel modules** | **TCP Server Mode** | `socat` PTY bridge (`/tmp/ttyMoxa0`) |
