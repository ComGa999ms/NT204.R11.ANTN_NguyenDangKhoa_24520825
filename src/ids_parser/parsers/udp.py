"""UDP header and payload parser."""

from __future__ import annotations

from typing import Any

from scapy.layers.inet import UDP

from .payload import normalize_payload


def parse_udp(packet: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    udp_layer = packet.getlayer(UDP)
    payload_bytes = bytes(udp_layer.payload)
    udp_length = int(udp_layer.len) if udp_layer.len is not None else 8 + len(payload_bytes)

    transport = {
        "protocol": "UDP",
        "source_port": int(udp_layer.sport),
        "destination_port": int(udp_layer.dport),
        "length": udp_length,
        "checksum": None if udp_layer.chksum is None else int(udp_layer.chksum),
        "payload_length": len(payload_bytes),
    }
    return transport, normalize_payload(payload_bytes)

