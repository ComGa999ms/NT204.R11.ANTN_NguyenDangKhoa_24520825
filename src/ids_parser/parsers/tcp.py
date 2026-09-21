"""TCP header and payload parser."""

from __future__ import annotations

from typing import Any

from scapy.layers.inet import TCP

from .payload import normalize_payload


TCP_FLAG_MASKS = {
    "ns": 0x100,
    "cwr": 0x080,
    "ece": 0x040,
    "urg": 0x020,
    "ack": 0x010,
    "psh": 0x008,
    "rst": 0x004,
    "syn": 0x002,
    "fin": 0x001,
}


def _json_safe(value: Any) -> Any:
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def _tcp_header_length(tcp_layer: TCP) -> int:
    if tcp_layer.dataofs is not None:
        return int(tcp_layer.dataofs) * 4
    header = tcp_layer.copy()
    header.remove_payload()
    return len(bytes(header))


def parse_tcp(packet: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    tcp_layer = packet.getlayer(TCP)
    payload_bytes = bytes(tcp_layer.payload)
    flag_bits = int(tcp_layer.flags)

    transport = {
        "protocol": "TCP",
        "source_port": int(tcp_layer.sport),
        "destination_port": int(tcp_layer.dport),
        "sequence_number": int(tcp_layer.seq),
        "acknowledgment_number": int(tcp_layer.ack),
        "header_length": _tcp_header_length(tcp_layer),
        "flags": {
            name: bool(flag_bits & mask) for name, mask in TCP_FLAG_MASKS.items()
        },
        "flag_string": str(tcp_layer.flags),
        "window_size": int(tcp_layer.window),
        "checksum": None if tcp_layer.chksum is None else int(tcp_layer.chksum),
        "urgent_pointer": int(tcp_layer.urgptr),
        "options": [
            {"name": str(name), "value": _json_safe(value)}
            for name, value in tcp_layer.options
        ],
        "payload_length": len(payload_bytes),
    }
    return transport, normalize_payload(payload_bytes)

