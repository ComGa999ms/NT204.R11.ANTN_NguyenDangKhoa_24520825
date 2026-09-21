from __future__ import annotations

from scapy.layers.inet import ICMP, IP

from ids_parser.parsers.transport import parse_transport


def test_parse_transport_returns_empty_result_for_unsupported_protocol() -> None:
    packet = IP(bytes(IP() / ICMP()))

    transport, payload = parse_transport(packet)

    assert transport is None
    assert payload == {"length": 0, "encoding": None, "data": None}

