"""
Moxa NPort 5610-8-DT Protocol & Control Package

Provides:
  - UDP Broadcast Discovery (Port 4800)
  - ASPP (Async Server Private Protocol) Hardware UART Control (TCP Ports 966-973)
  - Raw TCP Data Streaming, Passive Dual-RX Tapping, and Active MITM Bridging (TCP Ports 4001-4008)
  - Loopback Simulation Backend for offline testing and demonstration
"""

from .protocol import (
    ASPP_BAUD_MAP,
    FRAMING_PRESETS,
    ASPPClient,
    NPort5610Controller,
    NPortDeviceInfo,
    PortState,
    SerialFrame,
    discover_nports_udp,
)

__all__ = [
    "ASPP_BAUD_MAP",
    "FRAMING_PRESETS",
    "ASPPClient",
    "NPort5610Controller",
    "NPortDeviceInfo",
    "PortState",
    "SerialFrame",
    "discover_nports_udp",
]
