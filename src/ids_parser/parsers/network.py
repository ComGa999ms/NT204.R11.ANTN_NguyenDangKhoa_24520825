"""Network-layer protocol parsers."""

from __future__ import annotations

from typing import Any

from scapy.layers.inet import IP


def _header_length(ip_layer: IP) -> int:
    if ip_layer.ihl is not None:
        return int(ip_layer.ihl) * 4

    header = ip_layer.copy()
    header.remove_payload()
    return len(bytes(header))


def _total_length(ip_layer: IP) -> int:
    if ip_layer.len is not None:
        return int(ip_layer.len)
    return len(bytes(ip_layer))


def parse_ipv4(packet: Any) -> dict[str, Any] | None:
    """Return normalized IPv4 fields, or ``None`` for non-IPv4 packets."""

    if not hasattr(packet, "haslayer") or not packet.haslayer(IP):
        return None

    ip_layer = packet.getlayer(IP)
    flag_bits = int(ip_layer.flags)
    tos = int(ip_layer.tos)

    return {
        "protocol": "IPv4",
        "version": int(ip_layer.version),
        "source_ip": str(ip_layer.src),
        "destination_ip": str(ip_layer.dst),
        "header_length": _header_length(ip_layer),
        "total_length": _total_length(ip_layer),
        "identification": int(ip_layer.id),
        "dscp": tos >> 2,
        "ecn": tos & 0b11,
        "flags": {
            "reserved": bool(flag_bits & 0b100),
            "dont_fragment": bool(flag_bits & 0b010),
            "more_fragments": bool(flag_bits & 0b001),
        },
        "fragment_offset": int(ip_layer.frag),
        "ttl": int(ip_layer.ttl),
        "transport_protocol_number": int(ip_layer.proto),
        "checksum": None if ip_layer.chksum is None else int(ip_layer.chksum),
        "options": [str(option) for option in ip_layer.options],
    }
