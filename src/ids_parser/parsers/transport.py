"""Dispatch packets to supported transport-layer parsers."""

from __future__ import annotations

from typing import Any

from scapy.layers.inet import TCP, UDP

from .payload import empty_payload
from .tcp import parse_tcp
from .udp import parse_udp


def parse_transport(
    packet: Any,
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    """Parse a supported transport layer without relying on port numbers."""

    if not hasattr(packet, "haslayer"):
        return None, empty_payload()
    if packet.haslayer(TCP):
        return parse_tcp(packet)
    if packet.haslayer(UDP):
        return parse_udp(packet)
    return None, empty_payload()
