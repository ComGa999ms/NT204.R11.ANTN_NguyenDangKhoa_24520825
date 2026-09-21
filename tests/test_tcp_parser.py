from __future__ import annotations

import json

import pytest
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

from ids_parser.parsers.tcp import parse_tcp


def rebuild_ipv4(packet: IP) -> IP:
    return IP(bytes(packet))


def test_parse_tcp_extracts_flags_options_and_text_payload() -> None:
    packet = rebuild_ipv4(
        IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(
            sport=49152,
            dport=8080,
            seq=100,
            ack=201,
            flags="SA",
            window=8192,
            options=[("MSS", 1460), ("SAckOK", b"")],
        )
        / Raw(b"hello")
    )

    transport, payload = parse_tcp(packet)

    assert transport["protocol"] == "TCP"
    assert transport["source_port"] == 49152
    assert transport["destination_port"] == 8080
    assert transport["sequence_number"] == 100
    assert transport["acknowledgment_number"] == 201
    assert transport["header_length"] == 28
    assert transport["flags"]["syn"] is True
    assert transport["flags"]["ack"] is True
    assert transport["flags"]["fin"] is False
    assert transport["window_size"] == 8192
    assert transport["payload_length"] == 5
    assert payload == {"length": 5, "encoding": "utf-8", "data": "hello"}
    json.dumps(transport)


def test_parse_tcp_preserves_binary_payload_as_hex() -> None:
    packet = rebuild_ipv4(IP() / TCP() / Raw(b"\xff\x00\x80"))

    transport, payload = parse_tcp(packet)

    assert transport["payload_length"] == 3
    assert payload == {"length": 3, "encoding": "hex", "data": "ff0080"}


@pytest.mark.parametrize(
    ("raw_flags", "expected_syn", "expected_ack"),
    [
        ("S", True, False),
        ("SA", True, True),
        ("A", False, True),
    ],
    ids=["syn", "syn-ack", "ack"],
)
def test_parse_tcp_handshake_flags(
    raw_flags: str, expected_syn: bool, expected_ack: bool
) -> None:
    packet = rebuild_ipv4(IP() / TCP(flags=raw_flags))

    transport, _ = parse_tcp(packet)

    assert transport["flags"]["syn"] is expected_syn
    assert transport["flags"]["ack"] is expected_ack
    assert transport["flags"]["fin"] is False
    assert transport["flags"]["rst"] is False

