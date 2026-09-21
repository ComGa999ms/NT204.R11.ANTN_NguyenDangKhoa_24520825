from __future__ import annotations

from scapy.layers.inet import IP, UDP
from scapy.packet import Raw

from ids_parser.parsers.udp import parse_udp


def rebuild_ipv4(packet: IP) -> IP:
    return IP(bytes(packet))


def test_parse_udp_extracts_header_and_payload() -> None:
    packet = rebuild_ipv4(
        IP(src="203.0.113.1", dst="203.0.113.2")
        / UDP(sport=53000, dport=53)
        / Raw(b"query")
    )

    transport, payload = parse_udp(packet)

    assert transport["protocol"] == "UDP"
    assert transport["source_port"] == 53000
    assert transport["destination_port"] == 53
    assert transport["length"] == 13
    assert transport["payload_length"] == 5
    assert isinstance(transport["checksum"], int)
    assert payload == {"length": 5, "encoding": "utf-8", "data": "query"}

